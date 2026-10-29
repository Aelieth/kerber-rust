// MIT: `krb5int_decode_tgs_rep` (decode_kdc.c:64-67)
//! TGS-REP without PA-FX-FAST accepted as MIT does; `KRB5_ERR_FAST_REQUIRED` ignored.

use std::time::Instant;

use krb5_asn1::{decode, encode};
use krb5_config::Krb5Conf;
use krb5_crypto::{
    EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt_enc_data, encrypt, krb_fx_cf2,
};
use krb5_types::{
    ApOptions, ApReq, Authenticator, Checksum, EncKdcRepPart, EncryptedData, EncryptionKey,
    KdcOptions, KdcReq, KdcReqBody, KerberosTime, PaData, PrincipalName, TgsRep, TgsReq, Ticket,
    flag_bit, ku, pa,
};

use crate::as_ex::AsOutcome;
use crate::ccache::CcacheCred;
use crate::error::Error;
use crate::preauth::{
    apply_strengthen, fx_fast_padata_over, unwrap_fast_rep_checked, verify_fast_finished,
};

use crate::trace;
use crate::transport::{KdcAddr, SendKind, sendto_kdc};

// MIT: `KRB5_REFERRAL_MAXHOPS` (k5-int.h)
const REFERRAL_MAX_HOPS: usize = 10;

#[derive(Clone, Debug)]
pub struct TgsOutcome {
    pub ticket: Ticket,
    pub enc_part: EncKdcRepPart,
    pub session_key: ProtocolKey,
    pub crealm: krb5_types::Realm,
    pub cname: PrincipalName,
}

// MIT: `krb5_tkt_creds_init` (get_creds.c:1107-1113)
// MIT: `make_request_for_service` (get_creds.c:358-363)
#[derive(Clone, Default)]
pub struct TgsCredsOptions {
    pub canonicalize: bool,
    pub forwardable: bool,
    pub enctype: Option<i32>,
    pub second_ticket: Option<Ticket>,
    #[cfg(feature = "test-hooks")]
    pub no_transit_check: bool,
    // MIT: `begin` (lib/krb5/krb/get_creds.c:1074-1083)
    pub referral_realm: bool,
    // MIT: `get_cached_tgt` (lib/krb5/krb/get_creds.c:759-793)
    pub cached_creds: Vec<CcacheCred>,
}

impl std::fmt::Debug for TgsCredsOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("TgsCredsOptions");
        s.field("canonicalize", &self.canonicalize);
        s.field("forwardable", &self.forwardable);
        s.field("enctype", &self.enctype);
        s.field("second_ticket", &self.second_ticket);
        #[cfg(feature = "test-hooks")]
        s.field("no_transit_check", &self.no_transit_check);
        s.field("referral_realm", &self.referral_realm);
        s.field("cached_creds", &self.cached_creds.len());
        s.finish()
    }
}

pub fn tgs_exchange(
    profile: &Krb5Conf,
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
) -> Result<TgsOutcome, Error> {
    Ok(tgs_exchange_path(profile, kdc, tgt, sname, realm, &TgsCredsOptions::default())?.0)
}

/// Gate-only: MIT clients never send a foreign body.realm.
#[cfg(feature = "test-hooks")]
pub fn tgs_exchange_once(
    profile: &Krb5Conf,
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
    disable_transited_check: bool,
    renew: bool,
) -> Result<TgsOutcome, Error> {
    let opts = tgs_request_options(
        tgt,
        KdcOptions::none()
            .with_bit(flag_bit::CANONICALIZE, true)
            .with_bit(flag_bit::DISABLE_TRANSITED_CHECK, disable_transited_check)
            .with_bit(flag_bit::RENEW, renew),
    );
    tgs_once(profile, kdc, tgt, TgsRequest::new(sname, realm, opts))
}

#[allow(clippy::needless_pass_by_value)]
pub fn tgs_exchange_path(
    profile: &Krb5Conf,
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
    opts: &TgsCredsOptions,
) -> Result<(TgsOutcome, Vec<AsOutcome>), Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let _g = krb5_log::enter_correlation(correlation_id.clone());
    let started = Instant::now();
    let result = tgs_inner(profile, kdc, tgt, &sname, realm, opts);
    let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    match &result {
        Ok(_) => tracing::debug!(
            event = krb5_log::events::PROTOCOL_TGS,
            correlation_id,
            component = "krb5-protocol",
            duration_us,
            outcome = "ok",
        ),
        Err(e) => tracing::error!(
            event = krb5_log::events::PROTOCOL_TGS,
            correlation_id,
            component = "krb5-protocol",
            duration_us,
            outcome = "error",
            error = %e,
        ),
    }
    result
}

pub fn tgs_forward(
    profile: &Krb5Conf,
    kdc: &KdcAddr,
    tgt: &AsOutcome,
) -> Result<TgsOutcome, Error> {
    let realm = String::from_utf8_lossy(tgt.crealm.as_bytes()).into_owned();
    let sname = PrincipalName::try_new(PrincipalName::NT_SRV_INST, ["krbtgt", realm.as_str()])
        .map_err(|e| Error::ReplyMismatch(e.to_string()))?;
    let opts = tgs_forward_options(&tgt.enc_part.flags, true);
    tgs_once(
        profile,
        kdc,
        tgt,
        TgsRequest::new(sname, &realm, opts).via_tkt_ext(),
    )
}

// MIT: `get_new_creds` (val_renew.c:47-74)
pub fn tgs_renew(profile: &Krb5Conf, kdc: &KdcAddr, tgt: &AsOutcome) -> Result<TgsOutcome, Error> {
    let realm = String::from_utf8_lossy(tgt.ticket.realm.as_bytes()).into_owned();
    let sname = tgt.ticket.sname.clone();
    let opts = tgs_renew_options(&tgt.enc_part.flags);
    tgs_once(
        profile,
        kdc,
        tgt,
        TgsRequest::new(sname, &realm, opts).via_tkt_ext(),
    )
}

// MIT: `KDC_TKT_COMMON_MASK` (krb5.hin:1659-1659)
fn tkt_common_from_flags(flags: &krb5_types::TicketFlags) -> KdcOptions {
    let mut opts = KdcOptions::none();
    for bit in [
        flag_bit::FORWARDABLE,
        flag_bit::PROXIABLE,
        flag_bit::MAY_POSTDATE,
        flag_bit::RENEWABLE,
    ] {
        if flags.bit(bit) {
            opts = opts.with_bit(bit, true);
        }
    }
    opts
}

#[must_use]
pub fn tgs_renew_options(flags: &krb5_types::TicketFlags) -> KdcOptions {
    tkt_common_from_flags(flags).with_bit(flag_bit::RENEW, true)
}

// MIT: `krb5_get_self_cred_from_kdc` (s4u_creds.c:517-567)
/// 130 filled after the TGS subkey exists (ku 26).
// MIT: `make_tgs_outer_padata` (fast.c:227-250)
/// S4U padata repeated in FAST outer padata: KDC may not read FAST.
pub fn tgs_s4u(
    profile: &Krb5Conf,
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
    for_user: &PrincipalName,
    for_realm: &str,
) -> Result<TgsOutcome, Error> {
    let opts = tgs_request_options(
        tgt,
        KdcOptions::none().with_bit(flag_bit::CANONICALIZE, true),
    );
    let mut req = TgsRequest::new(sname, realm, opts).via_tkt_ext();
    req.s4u = Some((for_user, for_realm));
    tgs_once(profile, kdc, tgt, req)
}

pub fn tgs_u2u(
    profile: &Krb5Conf,
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
    stkt: Ticket,
) -> Result<TgsOutcome, Error> {
    let opts = tgs_request_options(
        tgt,
        KdcOptions::none()
            .with_bit(flag_bit::CANONICALIZE, true)
            .with_bit(flag_bit::ENC_TKT_IN_SKEY, true),
    );
    let mut req = TgsRequest::new(sname, realm, opts);
    req.additional_tickets = Some(vec![stkt]);
    tgs_once(profile, kdc, tgt, req)
}

// MIT: `make_request` (get_creds.c:286-292)
fn tgs_request_options(tgt: &AsOutcome, extra: KdcOptions) -> KdcOptions {
    let common = tkt_common_from_flags(&tgt.enc_part.flags);
    let mut opts = extra;
    for bit in 0..32 {
        if common.bit(bit) {
            opts = opts.with_bit(bit, true);
        }
    }
    opts
}

fn tgs_service_extra(opts: &TgsCredsOptions) -> KdcOptions {
    KdcOptions::none()
        .with_bit(flag_bit::CANONICALIZE, opts.canonicalize)
        .with_bit(flag_bit::FORWARDABLE, opts.forwardable)
        .with_bit(flag_bit::ENC_TKT_IN_SKEY, opts.second_ticket.is_some())
}

fn tgs_inner(
    profile: &Krb5Conf,
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: &PrincipalName,
    realm: &str,
    creds_opts: &TgsCredsOptions,
) -> Result<(TgsOutcome, Vec<AsOutcome>), Error> {
    let start = tgt_served_realm(tgt);
    let mut cur_kdc = kdc.clone();
    let mut cur_tgt = tgt.clone();
    let mut path = Vec::new();
    if tgt_served_realm(&cur_tgt) != realm {
        let (dest, hops) = get_dest_tgt(profile, kdc, &cur_tgt, realm, creds_opts)?;
        cur_tgt = dest;
        path = hops;
        cur_kdc = kdc_for_realm(profile, &tgt_served_realm(&cur_tgt), kdc)?;
    }
    let mut seen = vec![start.clone()];
    for _ in 0..REFERRAL_MAX_HOPS {
        let served = tgt_served_realm(&cur_tgt);
        let step = tgs_service_once(
            profile,
            &cur_kdc,
            &cur_tgt,
            ServiceHop {
                sname,
                served: &served,
                extra: service_extra(creds_opts, &cur_tgt, realm),
                request_realm: realm,
                referral_count: seen.len(),
                creds_opts,
            },
        )?;
        let out = match step {
            ServiceStep::Reply(out) => *out,
            ServiceStep::Fallback(fallback) => {
                return tgs_fallback_realm(
                    profile, &cur_kdc, &cur_tgt, sname, &fallback, creds_opts, path,
                );
            }
        };
        if step_referrals(sname, &served, &out)? == ReferralStep::Again {
            let out = service_non_referral_request(
                profile,
                &cur_kdc,
                &cur_tgt,
                sname,
                &served,
                service_extra(creds_opts, &cur_tgt, realm),
                creds_opts,
            )?;
            // MIT: `complete` (lib/krb5/krb/get_creds.c:451-470)
            trace::tkt_creds_complete(trace::Princ::new(
                &out.enc_part.sname,
                out.enc_part.srealm.as_bytes(),
            ));
            return Ok((out, path));
        }
        match chase_step(&start, &mut seen, sname, &served, &out)? {
            TgsHop::Done => {
                // MIT: `complete` (lib/krb5/krb/get_creds.c:451-470)
                trace::tkt_creds_complete(trace::Princ::new(
                    &out.enc_part.sname,
                    out.enc_part.srealm.as_bytes(),
                ));
                return Ok((out, path));
            }
            TgsHop::Referral(foreign) => {
                // MIT: `step_referrals` (lib/krb5/krb/get_creds.c:561-634)
                trace::tkt_creds_referral(trace::Princ::new(
                    &out.ticket.sname,
                    out.ticket.realm.as_bytes(),
                ));
                cur_kdc = kdc_for_realm(profile, &foreign, kdc)?;
                cur_tgt = tgs_as_tgt(&cur_tgt, out);
            }
        }
    }
    Err(Error::Referral)
}

fn service_extra(creds_opts: &TgsCredsOptions, tgt: &AsOutcome, realm: &str) -> KdcOptions {
    let extra = tgs_service_extra(creds_opts);
    #[cfg(feature = "test-hooks")]
    let extra = extra.with_bit(
        flag_bit::DISABLE_TRANSITED_CHECK,
        creds_opts.no_transit_check && tgt.ticket.sname.is_krbtgt_for(realm),
    );
    #[cfg(not(feature = "test-hooks"))]
    let _ = (tgt, realm);
    extra
}

// MIT: `try_fallback` (lib/krb5/krb/get_creds.c:534-542)
/// Server realm is the fallback; its TGT comes first.
// MIT: `step_non_referral` (lib/krb5/krb/get_creds.c:483-487)
fn tgs_fallback_realm(
    profile: &Krb5Conf,
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: &PrincipalName,
    realm: &str,
    creds_opts: &TgsCredsOptions,
    mut path: Vec<AsOutcome>,
) -> Result<(TgsOutcome, Vec<AsOutcome>), Error> {
    trace::tkt_creds_fallback(realm.as_bytes());
    let (dest, hops) = get_dest_tgt(profile, kdc, tgt, realm, creds_opts)?;
    path.extend(hops);
    let served = tgt_served_realm(&dest);
    let dest_kdc = kdc_for_realm(profile, &served, kdc)?;
    let extra = service_extra(creds_opts, &dest, realm);
    trace::tkt_creds_service_req(trace::Princ::new(sname, realm.as_bytes()), false);
    let req = service_request(
        sname,
        &served,
        tgs_request_options(&dest, extra),
        creds_opts,
    );
    let out = tgs_once(profile, &dest_kdc, &dest, req)?;
    trace::tkt_creds_complete(trace::Princ::new(
        &out.enc_part.sname,
        out.enc_part.srealm.as_bytes(),
    ));
    Ok((out, path))
}

fn tgt_served_realm(tgt: &AsOutcome) -> String {
    referral_hop_realm(&tgt.ticket.sname)
        .unwrap_or_else(|| String::from_utf8_lossy(tgt.ticket.realm.as_bytes()).into_owned())
}

fn get_dest_tgt(
    profile: &Krb5Conf,
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    dest: &str,
    creds_opts: &TgsCredsOptions,
) -> Result<(AsOutcome, Vec<AsOutcome>), Error> {
    let start = tgt_served_realm(tgt);
    let path = krb5_config::client_realm_path(&profile.capaths, &start, dest);
    let mut seen = vec![start.clone()];
    let mut cached = Vec::new();
    let mut cur_kdc = kdc.clone();
    let mut cur_tgt = tgt.clone();
    let mut next = dest.to_owned();
    let now = krb5_types::unix_now();
    let mut offpath = false;
    let mut offpath_count = 0usize;
    let mut visited: Vec<String> = Vec::new();
    for _ in 0..REFERRAL_MAX_HOPS {
        let served = tgt_served_realm(&cur_tgt);
        if served == dest {
            return Ok((cur_tgt, cached));
        }
        if !offpath {
            // MIT: `get_tgt_request` (lib/krb5/krb/get_creds.c:890-914)
            let cred = cached_tgt(
                &creds_opts.cached_creds,
                &cur_tgt.cname,
                cur_tgt.crealm.as_bytes(),
                &next,
                now,
                &crate::as_ex::conf_etypes(profile, true),
            )?;
            if let Some(cred) = cred {
                trace::tkt_creds_cached_intermediate_tgt(
                    trace::Princ::new(&cred.client.1, cred.client.0.as_bytes()),
                    trace::Princ::new(&cred.server.1, cred.server.0.as_bytes()),
                );
                cur_tgt = tgt_from_cached(&cur_tgt, cred)?;
                let got = tgt_served_realm(&cur_tgt);
                if got == dest {
                    return Ok((cur_tgt, cached));
                }
                cur_kdc = kdc_for_realm(profile, &got, kdc)?;
                dest.clone_into(&mut next);
                continue;
            }
        }
        let hop = PrincipalName::try_new(PrincipalName::NT_SRV_INST, ["krbtgt", next.as_str()])
            .map_err(|e| Error::ReplyMismatch(e.to_string()))?;
        // MIT: `make_request_for_tgt` (get_creds.c:341-343)
        let opts = tgs_request_options(&cur_tgt, KdcOptions::none());
        trace::tkt_creds_tgt_req(
            trace::Princ::new(&hop, served.as_bytes()),
            trace::Princ::new(&cur_tgt.ticket.sname, cur_tgt.ticket.realm.as_bytes()),
        );
        match tgs_once(
            profile,
            &cur_kdc,
            &cur_tgt,
            TgsRequest::new(hop.clone(), &served, opts),
        ) {
            Ok(out) => {
                if offpath {
                    // MIT: `step_get_tgt_offpath` (lib/krb5/krb/get_creds.c:681-717)
                    authenticate_srealm(&out)?;
                    let Some(got) = referral_hop_realm(&out.ticket.sname) else {
                        return Err(Error::ReplyMismatch("off-path reply was not a TGT".into()));
                    };
                    if visited.iter().any(|r| r == &got) {
                        return Err(Error::Referral);
                    }
                    visited.push(got.clone());
                    cur_tgt = tgs_as_tgt(&cur_tgt, out);
                    if got == dest {
                        trace::tkt_creds_target_tgt_offpath(trace::Princ::new(
                            &cur_tgt.ticket.sname,
                            cur_tgt.ticket.realm.as_bytes(),
                        ));
                        return Ok((cur_tgt, cached));
                    }
                    if offpath_count >= REFERRAL_MAX_HOPS {
                        return Err(Error::ReplyMismatch("off-path chase gave up".into()));
                    }
                    offpath_count += 1;
                    cur_kdc = kdc_for_realm(profile, &got, kdc)?;
                    dest.clone_into(&mut next);
                    continue;
                }
                if let Some(realm) = referral_hop_realm(&out.ticket.sname)
                    && tgt_is_off_path(&path, &served, &start, &realm)
                {
                    // MIT: `step_get_tgt` (lib/krb5/krb/get_creds.c:966-971)
                    // MIT: `begin_get_tgt_offpath` (lib/krb5/krb/get_creds.c:721-726)
                    authenticate_srealm(&out)?;
                    trace::tkt_creds_offpath(realm.as_bytes());
                    visited.push(realm.clone());
                    offpath = true;
                    offpath_count = 1;
                    cur_tgt = tgs_as_tgt(&cur_tgt, out);
                    cur_kdc = kdc_for_realm(profile, &realm, kdc)?;
                    dest.clone_into(&mut next);
                    continue;
                }
                chase_step(&start, &mut seen, &hop, &served, &out)?;
                if let Some(realm) = referral_hop_realm(&out.ticket.sname) {
                    visited.push(realm);
                }
                if asked_for_hop(&hop, &out) {
                    cached.push(tgs_as_tgt(&cur_tgt, out.clone()));
                }
                cur_tgt = tgs_as_tgt(&cur_tgt, out);
                // MIT: `step_get_tgt` (lib/krb5/krb/get_creds.c:938-976)
                let got = tgt_served_realm(&cur_tgt);
                if got == dest {
                    trace::tkt_creds_target_tgt(trace::Princ::new(
                        &cur_tgt.ticket.sname,
                        cur_tgt.ticket.realm.as_bytes(),
                    ));
                } else {
                    trace::tkt_creds_advance(got.as_bytes());
                }
                cur_kdc = kdc_for_realm(profile, &got, kdc)?;
                dest.clone_into(&mut next);
            }
            Err(e @ Error::KrbError { .. }) if offpath => return Err(e),
            Err(e @ Error::KrbError { .. }) => match closer_hop(&path, &served, &next) {
                Some(c) => {
                    trace::tkt_creds_closer_realm(c.as_bytes());
                    next = c.to_owned();
                }
                None => return Err(e),
            },
            Err(e) => return Err(e),
        }
    }
    Err(Error::Referral)
}

// MIT: `get_cached_tgt` (lib/krb5/krb/get_creds.c:759-793)
// MIT: `krb5_cc_retrieve_cred_seq` (lib/krb5/ccache/cc_retr.c:195-250)
pub fn cached_tgt<'a>(
    creds: &'a [CcacheCred],
    client: &PrincipalName,
    client_realm: &[u8],
    realm: &str,
    now: u32,
    ktypes: &[i32],
) -> Result<Option<&'a CcacheCred>, Error> {
    let mut best: Option<(usize, &'a CcacheCred)> = None;
    let mut named = false;
    for c in creds {
        if c.is_config()
            || c.is_removed()
            || c.client.1.name_string != client.name_string
            || c.client.0.as_bytes() != client_realm
            || !c.server.1.is_krbtgt_for(realm)
            || c.endtime < now
        {
            continue;
        }
        named = true;
        let Some(rank) = ktypes.iter().position(|k| *k == i32::from(c.key.etype)) else {
            continue;
        };
        if c.session_key().is_err() {
            continue;
        }
        if best.is_none_or(|(prev, _)| rank < prev) {
            best = Some((rank, c));
        }
    }
    if let Some((_, cred)) = best {
        return Ok(Some(cred));
    }
    if named {
        return Err(Error::CcNotKtype);
    }
    Ok(None)
}

fn tgt_from_cached(prev: &AsOutcome, cred: &CcacheCred) -> Result<AsOutcome, Error> {
    let ticket = decode::<Ticket>(&cred.ticket).map_err(|e| Error::Asn1(e.to_string()))?;
    let session = cred
        .session_key()
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let end = KerberosTime::from_unix_seconds(cred.endtime);
    Ok(AsOutcome {
        ticket,
        enc_part: krb5_types::EncKdcRepPart {
            key: krb5_types::EncryptionKey {
                keytype: session.etype().to_iana(),
                keyvalue: session.as_bytes().to_vec().into(),
            },
            last_req: Vec::new(),
            nonce: 0,
            key_expiration: None,
            flags: krb5_types::TicketFlags::from_u32(cred.ticket_flags),
            authtime: KerberosTime::from_unix_seconds(cred.authtime),
            starttime: (cred.starttime > 0)
                .then(|| KerberosTime::from_unix_seconds(cred.starttime)),
            endtime: end,
            renew_till: (cred.renew_till > 0)
                .then(|| KerberosTime::from_unix_seconds(cred.renew_till)),
            srealm: cred.server.0.clone(),
            sname: cred.server.1.clone(),
            caddr: None,
            encrypted_pa_data: None,
        },
        client_key: prev.client_key.clone(),
        session_key: session,
        cname: cred.client.1.clone(),
        crealm: cred.client.0.clone(),
        fast_avail: prev.fast_avail,
        used_fast: prev.used_fast,
        pa_type: prev.pa_type,
        pa_config: None,
        time_offset: prev.time_offset,
    })
}

// MIT: `find_realm_in_path` (lib/krb5/krb/get_creds.c:871-882)
fn tgt_is_off_path(path: &[String], cur: &str, start: &str, realm: &str) -> bool {
    let rest = path
        .iter()
        .position(|r| r == cur)
        .map_or(&[][..], |i| &path[i + 1..]);
    !rest.iter().any(|r| r == realm) && realm != start
}

fn closer_hop<'a>(path: &'a [String], cur: &str, next: &str) -> Option<&'a str> {
    let ni = path.iter().position(|r| r == next)?;
    if ni == 0 {
        return None;
    }
    let c = path[ni - 1].as_str();
    (c != cur).then_some(c)
}

fn tgs_as_tgt(prev: &AsOutcome, out: TgsOutcome) -> AsOutcome {
    AsOutcome {
        ticket: out.ticket,
        enc_part: out.enc_part,
        client_key: prev.client_key.clone(),
        session_key: out.session_key,
        cname: prev.cname.clone(),
        crealm: prev.crealm.clone(),
        fast_avail: prev.fast_avail,
        used_fast: prev.used_fast,
        pa_type: prev.pa_type,
        pa_config: None,
        time_offset: prev.time_offset,
    }
}

// MIT: `check_reply_server` (lib/krb5/krb/gc_via_tkt.c:104-136)
fn check_reply_server(
    requested: &PrincipalName,
    requested_realm: &[u8],
    ticket: &PrincipalName,
    ticket_realm: &[u8],
    enc: &PrincipalName,
    enc_realm: &[u8],
    canonicalize: bool,
) -> Result<(), Error> {
    if requested.name_string == ticket.name_string && requested_realm == ticket_realm {
        return Ok(());
    }
    if canonicalize {
        trace::check_reply_server_differs(
            trace::Princ::new(requested, requested_realm),
            trace::Princ::new(enc, enc_realm),
        );
        return Ok(());
    }
    if !(requested.is_krbtgt() && ticket.is_krbtgt()) {
        return Err(Error::ReplyMismatch(format!(
            "TGS-REP sname mismatch requested={} ticket={}",
            requested.components_joined(),
            ticket.components_joined()
        )));
    }
    Ok(())
}

// MIT: `krb5int_fast_process_response` (fast.c:548-551)
/// FAST padata present: finished crealm and cname replace the reply's before the compare.
fn tgs_fast_reply_key(
    armor_key: &ProtocolKey,
    sub: &ProtocolKey,
    inner: &mut krb5_types::KdcRep,
    nonce: u32,
) -> Result<(ProtocolKey, Vec<PaData>), Error> {
    // MIT: `decrypt_fast_reply` (lib/krb5/krb/fast.c:359-415)
    trace::fast_decode();
    let has_fast = inner
        .padata
        .as_ref()
        .is_some_and(|v| v.iter().any(|p| p.padata_type == pa::FX_FAST));
    if !has_fast {
        return Ok((sub.clone(), inner.padata.clone().unwrap_or_default()));
    }
    let fast = unwrap_fast_rep_checked(armor_key, &inner.padata, nonce)?;
    let finished = fast.finished.as_ref().ok_or_else(|| {
        Error::ReplyMismatch("FAST response missing finish message in KDC reply".into())
    })?;
    verify_fast_finished(armor_key, &inner.ticket, finished)?;
    inner.crealm = finished.crealm.clone();
    inner.cname = finished.cname.clone();
    let sk = fast
        .strengthen_key
        .as_ref()
        .ok_or_else(|| Error::ReplyMismatch("FAST TGS reply missing strengthen-key".into()))?;
    tracing::debug!(
        event = krb5_log::events::CLIENT_TGS,
        component = "krb5-protocol",
        outcome = "ok",
        fast_strengthen = true,
    );
    let reply_key = apply_strengthen(sk, sub)?;
    // MIT: `krb5int_fast_reply_key` (lib/krb5/krb/fast.c:570-592)
    // The strengthened key is traced as a hash.
    trace::fast_reply_key((&reply_key).into());
    Ok((reply_key, fast.padata))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TgsHop {
    Done,
    Referral(String),
}

fn asked_for_hop(requested: &PrincipalName, out: &TgsOutcome) -> bool {
    out.ticket.sname == *requested || out.enc_part.sname == *requested
}

fn chase_step(
    start: &str,
    seen: &mut Vec<String>,
    requested: &PrincipalName,
    hop_realm: &str,
    out: &TgsOutcome,
) -> Result<TgsHop, Error> {
    match tgs_hop_decision(requested, hop_realm, out)? {
        TgsHop::Done => Ok(TgsHop::Done),
        TgsHop::Referral(foreign) => {
            if foreign == start {
                return Err(Error::ReplyMismatch(
                    "referred back to the start realm".into(),
                ));
            }
            if seen.iter().any(|r| r == &foreign) {
                return Err(Error::Referral);
            }
            seen.push(foreign.clone());
            Ok(TgsHop::Referral(foreign))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReferralStep {
    Chase,
    Again,
}

// MIT: `step_referrals` (lib/krb5/krb/get_creds.c:572-598)
// MIT: `begin_non_referral` (lib/krb5/krb/get_creds.c:492-496)
fn step_referrals(
    requested: &PrincipalName,
    hop_realm: &str,
    out: &TgsOutcome,
) -> Result<ReferralStep, Error> {
    authenticate_srealm(out)?;
    let server = &out.ticket.sname;
    if server.name_string == requested.name_string
        || out.enc_part.sname.name_string == requested.name_string
    {
        return Ok(ReferralStep::Chase);
    }
    if !server.is_krbtgt() {
        trace::tkt_creds_non_tgt(trace::Princ::new(server, out.ticket.realm.as_bytes()));
        return Ok(ReferralStep::Again);
    }
    let foreign = referral_hop_realm(server).ok_or(Error::Referral)?;
    if foreign == hop_realm {
        trace::tkt_creds_same_realm_tgt(foreign.as_bytes());
        return Ok(ReferralStep::Again);
    }
    Ok(ReferralStep::Chase)
}

pub(crate) fn tgs_hop_decision(
    requested: &PrincipalName,
    hop_realm: &str,
    out: &TgsOutcome,
) -> Result<TgsHop, Error> {
    authenticate_srealm(out)?;
    if out.ticket.sname.is_krbtgt() && out.ticket.sname != *requested {
        let foreign = referral_hop_realm(&out.ticket.sname).ok_or(Error::Referral)?;
        if foreign.is_empty() || foreign == hop_realm {
            return Err(Error::Referral);
        }
        return Ok(TgsHop::Referral(foreign));
    }
    Ok(TgsHop::Done)
}

#[must_use]
pub fn referral_hop_realm(sname: &PrincipalName) -> Option<String> {
    if !sname.is_krbtgt() {
        return None;
    }
    sname
        .name_string
        .get(1)
        .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
}

fn authenticate_srealm(out: &TgsOutcome) -> Result<(), Error> {
    if out.enc_part.srealm.as_bytes() != out.ticket.realm.as_bytes() {
        return Err(Error::ReplyMismatch(
            "TGS-REP srealm does not match ticket realm".into(),
        ));
    }
    Ok(())
}

fn kdc_for_realm(profile: &Krb5Conf, realm: &str, fallback: &KdcAddr) -> Result<KdcAddr, Error> {
    if krb5_config::handed_matches(realm, &fallback.host, fallback.port) {
        return Ok(fallback.clone());
    }
    let found = match profile.kdcs_for_traced(realm, &mut crate::trace::dns_srv) {
        Ok(list) => list,
        Err(krb5_config::Error::InvalidArgument) => return Err(Error::InvalidArgument),
        Err(_) => Vec::new(),
    };
    let Some(ep) = found.first() else {
        krb5_config::clear_handed();
        return Ok(fallback.clone());
    };
    let addr = KdcAddr {
        host: ep.host.clone(),
        port: ep.port,
    };
    krb5_config::hand_kdcs(realm, found);
    Ok(addr)
}

struct TgsRequest<'a> {
    sname: PrincipalName,
    realm: &'a str,
    kdc_options: KdcOptions,
    extra_padata: Vec<PaData>,
    additional_tickets: Option<Vec<Ticket>>,
    s4u: Option<(&'a PrincipalName, &'a str)>,
    enctype: Option<i32>,
    via_tkt_ext: bool,
}

impl<'a> TgsRequest<'a> {
    fn new(sname: PrincipalName, realm: &'a str, kdc_options: KdcOptions) -> Self {
        Self {
            sname,
            realm,
            kdc_options,
            extra_padata: Vec::new(),
            additional_tickets: None,
            s4u: None,
            enctype: None,
            via_tkt_ext: false,
        }
    }

    fn via_tkt_ext(mut self) -> Self {
        self.via_tkt_ext = true;
        self
    }
}

// MIT: `krb5_get_cred_via_tkt_ext` (lib/krb5/krb/gc_via_tkt.c:342-413)
// MIT: `get_creds_from_tgs_reply` (lib/krb5/krb/get_creds.c:381-410)
fn tgs_once(
    profile: &Krb5Conf,
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    req: TgsRequest<'_>,
) -> Result<TgsOutcome, Error> {
    let ext = req.via_tkt_ext;
    if ext {
        trace::get_cred_via_tkt_ext(
            trace::Princ::new(&req.sname, req.realm.as_bytes()),
            trace::Princ::new(&tgt.ticket.sname, tgt.ticket.realm.as_bytes()),
            req.kdc_options.bit(flag_bit::CANONICALIZE),
        );
    }
    let tracing = trace::enabled();
    let result = tgs_round_trip(profile, kdc, tgt, req);
    if !tracing {
        return result;
    }
    let kerr = match &result {
        Ok(_) => Some((0, None)),
        Err(e) => tgs_kerr(e, ext),
    };
    if let Some((code, msg)) = kerr {
        if ext {
            trace::get_cred_via_tkt_ext_return(code, msg.as_deref());
        } else {
            trace::tkt_creds_response_code(code, msg.as_deref());
        }
    }
    result
}

// MIT: `krb5int_process_tgs_reply` (lib/krb5/krb/gc_via_tkt.c:195-216)
fn tgs_kerr(e: &Error, ext: bool) -> Option<(i64, Option<String>)> {
    Some(match e {
        Error::KrbError { code, text } => {
            let text = text.as_ref().filter(|t| !t.is_empty());
            let msg = match (*code, text) {
                (krb5_types::err::GENERIC, Some(t)) => {
                    Some(format!("KDC returned error string: {t}"))
                }
                (krb5_types::err::S_PRINCIPAL_UNKNOWN, Some(t)) => Some(t.clone()),
                _ => None,
            };
            (trace::kdc_code(*code), msg)
        }
        Error::Io { .. } if !ext => return None,
        Error::Io { .. } | Error::Referral => (trace::KRB5_KDC_UNREACH, None),
        Error::Crypto(_) => (trace::kdc_code(krb5_types::err::BAD_INTEGRITY), None),
        // MIT: `KRB5DES_BAD_KEYPAR` (krb5_err.et:251-251)
        Error::DesBadParity => (trace::ERROR_TABLE_BASE_KRB5 + 186, None),
        Error::DesWeakKey => (trace::ERROR_TABLE_BASE_KRB5 + 187, None),
        Error::KdcReplySkew => (trace::KRB5_KDCREP_SKEW, None),
        Error::UnexpectedPdu => (trace::kdc_code(krb5_types::err::MSG_TYPE), None),
        _ => (trace::KRB5_KDCREP_MODIFIED, None),
    })
}

// MIT: `k5_make_tgs_req` (send_tgs.c:155-160)
fn tgs_round_trip(
    profile: &Krb5Conf,
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    req: TgsRequest<'_>,
) -> Result<TgsOutcome, Error> {
    let TgsRequest {
        sname,
        realm,
        kdc_options,
        extra_padata,
        additional_tickets: extra_tickets,
        s4u,
        enctype,
        via_tkt_ext,
    } = req;
    let nonce = random_nonce31()?;
    let till = KerberosTime(tgt.enc_part.endtime.0);
    let etypes = enctype.map_or_else(|| crate::as_ex::conf_etypes(profile, true), |e| vec![e]);

    let requested = sname.clone();
    let s4u2proxy = kdc_options.bit(flag_bit::CNAME_IN_ADDL_TKT);
    let body = KdcReqBody {
        kdc_options: kdc_options.clone(),
        cname: None,
        realm: krb5_types::try_ascii(realm).map_err(|e| Error::ReplyMismatch(e.to_string()))?,
        sname: Some(sname),
        from: None,
        till: till.clone(),
        rtime: None,
        nonce,
        etype: etypes,
        addresses: None,
        enc_authorization_data: None,
        additional_tickets: extra_tickets,
    };
    let body_der = encode(&body)?;
    let cksum_usage = KeyUsage::new(ku::TGS_REQ_AUTH_CKSUM)?;
    let mic = checksum(&tgt.session_key, cksum_usage, &body_der)?;
    // MIT: `tgs_construct_ap_req` (lib/krb5/krb/send_tgs.c:82-82)
    let (now, usec) = crate::ap_req::stamped(tgt.time_offset);
    let sent = now.clone();
    let sub = ProtocolKey::random(tgt.session_key.etype())?;
    trace::send_tgs_subkey((&sub).into());
    trace::send_tgs_etypes(&body.etype);
    let mut extra = extra_padata;
    let mut req_s4u = None;
    if let Some((user, urealm)) = s4u {
        let pa130 = crate::pa_s4u_x509_user(&sub, user.clone(), urealm, nonce)?;
        req_s4u = Some(
            decode::<krb5_types::s4u::PaS4uX509User>(pa130.padata_value.as_ref())
                .map_err(|e| Error::Asn1(e.to_string()))?,
        );
        extra.splice(
            0..0,
            [
                pa130,
                crate::pa_for_user(&tgt.session_key, user.clone(), urealm)?,
            ],
        );
    }
    let armor_key = krb_fx_cf2(&sub, &tgt.session_key, b"subkeyarmor", b"ticketarmor")?;
    let authenticator = Authenticator {
        authenticator_vno: Authenticator::VNO,
        crealm: tgt.crealm.clone(),
        cname: tgt.cname.clone(),
        cksum: Some(Checksum {
            cksumtype: tgt.session_key.etype().checksum_type(),
            checksum: mic.into(),
        }),
        cusec: usec,
        ctime: now,
        subkey: Some(EncryptionKey {
            keytype: sub.etype().to_iana(),
            keyvalue: sub.as_bytes().to_vec().into(),
        }),
        seq_number: None,
        authorization_data: None,
    };
    let auth_der = encode(&authenticator)?;
    let auth_usage = KeyUsage::new(ku::TGS_REQ_AUTHENTICATOR)?;
    let auth_cipher = encrypt(&tgt.session_key, auth_usage, &auth_der)?;
    let ap_req = ApReq {
        pvno: ApReq::PVNO,
        msg_type: ApReq::MSG_TYPE,
        ap_options: ApOptions::none(),
        ticket: tgt.ticket.clone(),
        authenticator: EncryptedData {
            etype: tgt.session_key.etype().to_iana(),
            kvno: None,
            cipher: auth_cipher.into(),
        },
    };
    let ap_raw = encode(&ap_req)?;
    let mut padata = vec![PaData {
        padata_type: pa::TGS_REQ,
        padata_value: ap_raw.clone().into(),
    }];
    trace::fast_encode();
    padata.push(fx_fast_padata_over(
        None,
        &armor_key,
        &ap_raw,
        &body,
        extra.clone(),
        &krb5_types::fast::fast_options_none(),
    )?);
    padata.extend(extra);
    let tgs = TgsReq(KdcReq {
        pvno: KdcReq::PVNO,
        msg_type: KdcReq::MSG_TGS_REQ,
        padata: Some(padata),
        req_body: body,
    });
    let wire = encode(&tgs)?;
    let reply = sendto_kdc(profile, kdc, realm, &wire, SendKind::Tgs)?;
    if reply.is_empty() {
        return Err(Error::TruncatedReply);
    }
    if reply[0] == 0x7e {
        let outer: krb5_types::KrbError = decode(&reply)?;
        if via_tkt_ext
            && trace::enabled()
            && outer
                .e_data
                .as_ref()
                .is_some_and(|ed| decode::<Vec<PaData>>(ed.as_ref()).is_ok())
        {
            trace::fast_decode();
        }
        let e = crate::as_ex::fast_error_material(&armor_key, &outer, nonce)?.err;
        let text = e
            .e_text
            .as_ref()
            .and_then(|s| std::str::from_utf8(s.as_bytes()).ok())
            .map(str::to_owned);
        let text = match text {
            Some(t) if e.error_code == krb5_types::err::S_PRINCIPAL_UNKNOWN && !t.is_empty() => {
                let server = e
                    .sname
                    .unparse_with_realm(&String::from_utf8_lossy(e.realm.as_bytes()));
                Some(format!("Server {server} not found in Kerberos database"))
            }
            text => text,
        };
        return Err(Error::KrbError {
            code: e.error_code,
            text,
        });
    }
    if reply[0] != 0x6d {
        return Err(Error::UnexpectedPdu);
    }
    let TgsRep(mut inner) = decode::<TgsRep>(&reply)?;
    let (reply_key, fast_padata) = tgs_fast_reply_key(&armor_key, &sub, &mut inner, nonce)?;
    let enc_usage = ku::TGS_REP_ENC_PART_SUBKEY;
    let usage = KeyUsage::new(enc_usage)?;
    let plain = zeroize::Zeroizing::new(decrypt_enc_data(
        &reply_key,
        usage,
        inner.enc_part.etype,
        inner.enc_part.cipher.as_ref(),
    )?);
    // MIT: `krb5_kdc_rep_decrypt_proc` (kdc_rep_dc.c:69-69)
    let mut enc_part =
        krb5_asn1::decode_enc_kdc_rep_part(&plain).map_err(|e| Error::Asn1(e.to_string()))?;
    if enc_part.nonce != nonce {
        return Err(Error::NonceMismatch);
    }
    enc_part.flags = tgs_strip_ok_as_delegate(
        tgt_is_local_realm(tgt),
        tgt.enc_part.flags.bit(flag_bit::OK_AS_DELEGATE),
        enc_part.flags,
    );
    let request_realm =
        krb5_types::try_ascii(realm).map_err(|e| Error::ReplyMismatch(e.to_string()))?;
    tgs_reply_client_ok(
        &tgt.cname,
        &tgt.crealm,
        &inner.cname,
        &inner.crealm,
        &inner.ticket.sname,
        &requested,
        &request_realm,
        req_s4u.is_some(),
        s4u2proxy,
    )?;
    if let Some(req) = req_s4u.as_ref() {
        crate::verify_s4u2self_reply(
            &sub,
            req,
            Some(&fast_padata),
            enc_part.encrypted_pa_data.as_deref(),
        )?;
    }
    tgs_reply_server_consistent(
        &inner.ticket.sname,
        &inner.ticket.realm,
        &enc_part.sname,
        &enc_part.srealm,
    )?;
    // RENEW, VALIDATE skip times check: wire till old; renewal may outlive it.
    if !kdc_options.bit(flag_bit::RENEW) && !kdc_options.bit(flag_bit::VALIDATE) {
        tgs_reply_req_times(&enc_part, &till, None, None, &kdc_options)?;
    }
    // MIT: `krb5int_process_tgs_reply` (lib/krb5/krb/gc_via_tkt.c:302-306)
    // No starttime is ever requested, so the reply's must be within skew.
    let start = enc_part.starttime.as_ref().unwrap_or(&enc_part.authtime);
    if (i64::from(start.unix_seconds()) - i64::from(sent.unix_seconds())).abs()
        > i64::from(profile.clockskew)
    {
        return Err(Error::KdcReplySkew);
    }
    check_reply_server(
        &requested,
        realm.as_bytes(),
        &inner.ticket.sname,
        inner.ticket.realm.as_bytes(),
        &enc_part.sname,
        enc_part.srealm.as_bytes(),
        kdc_options.bit(flag_bit::CANONICALIZE),
    )?;
    let session_etype = EncryptionType::known(enc_part.key.keytype)?;
    let session_key = ProtocolKey::from_bytes(session_etype, enc_part.key.keyvalue.as_ref())?;
    // MIT: `kdcrep2creds` (lib/krb5/krb/gc_via_tkt.c:36-94)
    // Traced after checks: client, server, session key, as hashes.
    trace::tgs_reply(
        trace::Princ::new(&inner.cname, inner.crealm.as_bytes()),
        trace::Princ::new(&enc_part.sname, enc_part.srealm.as_bytes()),
        (&enc_part.key).into(),
    );
    Ok(TgsOutcome {
        ticket: inner.ticket,
        enc_part,
        session_key,
        crealm: inner.crealm,
        cname: inner.cname,
    })
}

fn random_nonce31() -> Result<u32, Error> {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).map_err(|e| Error::transport_msg(e.to_string()))?;
    let n = u32::from_be_bytes(b) & 0x7fff_ffff;
    Ok(if n == 0 { 1 } else { n })
}

// MIT: `get_proxy_cred_from_kdc` (s4u_creds.c:1013-1031)
pub fn tgs_s4u2proxy(
    profile: &Krb5Conf,
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    target: PrincipalName,
    realm: &str,
    evidence: Ticket,
) -> Result<TgsOutcome, Error> {
    let opts = tgs_request_options(
        tgt,
        KdcOptions::none()
            .with_bit(flag_bit::CNAME_IN_ADDL_TKT, true)
            .with_bit(flag_bit::CANONICALIZE, true),
    );
    let mut req = TgsRequest::new(target, realm, opts).via_tkt_ext();
    req.extra_padata = vec![crate::pa_pac_options(true)?];
    req.additional_tickets = Some(vec![evidence]);
    tgs_once(profile, kdc, tgt, req)
}

pub fn tgs_validate(
    profile: &Krb5Conf,
    kdc: &KdcAddr,
    tgt: &AsOutcome,
) -> Result<TgsOutcome, Error> {
    let realm = String::from_utf8_lossy(tgt.ticket.realm.as_bytes()).into_owned();
    let sname = tgt.ticket.sname.clone();
    let opts = tgs_validate_options(&tgt.enc_part.flags);
    tgs_once(
        profile,
        kdc,
        tgt,
        TgsRequest::new(sname, &realm, opts).via_tkt_ext(),
    )
}

#[must_use]
pub fn tgs_validate_options(flags: &krb5_types::TicketFlags) -> KdcOptions {
    tkt_common_from_flags(flags).with_bit(flag_bit::VALIDATE, true)
}

fn princ_eq(
    name_a: &PrincipalName,
    realm_a: &krb5_types::Realm,
    name_b: &PrincipalName,
    realm_b: &krb5_types::Realm,
) -> bool {
    name_a.name_string == name_b.name_string && realm_a.as_bytes() == realm_b.as_bytes()
}

#[expect(clippy::too_many_arguments, reason = "name and realm stay separate")]
/// Reply client equal to requested server: KDC ignored PA-FOR-USER.
pub fn tgs_reply_client_ok(
    tgt_cname: &PrincipalName,
    tgt_crealm: &krb5_types::Realm,
    reply_cname: &PrincipalName,
    reply_crealm: &krb5_types::Realm,
    reply_sname: &PrincipalName,
    requested: &PrincipalName,
    request_realm: &krb5_types::Realm,
    s4u2self: bool,
    s4u2proxy: bool,
) -> Result<(), Error> {
    if s4u2self && !reply_sname.is_krbtgt() {
        if princ_eq(reply_cname, reply_crealm, requested, request_realm) {
            return Err(Error::KrbError {
                code: krb5_types::err::PADATA_TYPE_NOSUPP,
                text: None,
            });
        }
        return Ok(());
    }
    if (!s4u2proxy || reply_sname.is_krbtgt())
        && !princ_eq(reply_cname, reply_crealm, tgt_cname, tgt_crealm)
    {
        return Err(Error::ReplyMismatch(
            "TGS-REP client does not match TGT client".into(),
        ));
    }
    Ok(())
}

// MIT: `check_reply_server` (gc_via_tkt.c:108-110)
pub fn tgs_reply_server_consistent(
    ticket_sname: &PrincipalName,
    ticket_realm: &krb5_types::Realm,
    enc_sname: &PrincipalName,
    enc_srealm: &krb5_types::Realm,
) -> Result<(), Error> {
    if !princ_eq(ticket_sname, ticket_realm, enc_sname, enc_srealm) {
        return Err(Error::ReplyMismatch(
            "TGS-REP ticket server does not match enc-part server".into(),
        ));
    }
    Ok(())
}

pub fn tgs_reply_req_times(
    enc: &EncKdcRepPart,
    till: &KerberosTime,
    rtime: Option<&KerberosTime>,
    from: Option<&KerberosTime>,
    opts: &KdcOptions,
) -> Result<(), Error> {
    let start = enc.starttime.as_ref().unwrap_or(&enc.authtime);
    if opts.bit(flag_bit::POSTDATED)
        && let Some(from) = from
        && from.unix_seconds() != 0
        && from.unix_seconds() != start.unix_seconds()
    {
        return Err(Error::ReplyMismatch(
            "TGS-REP starttime != request from".into(),
        ));
    }
    if till.unix_seconds() != 0 && enc.endtime.unix_seconds() > till.unix_seconds() {
        return Err(Error::ReplyMismatch(
            "TGS-REP endtime after request till".into(),
        ));
    }
    if opts.bit(flag_bit::RENEWABLE)
        && let Some(rtime) = rtime
        && rtime.unix_seconds() != 0
        && enc
            .renew_till
            .as_ref()
            .is_some_and(|rt| rt.unix_seconds() > rtime.unix_seconds())
    {
        return Err(Error::ReplyMismatch(
            "TGS-REP renew-till after request rtime".into(),
        ));
    }
    if opts.bit(flag_bit::RENEWABLE_OK)
        && enc.flags.renewable()
        && till.unix_seconds() != 0
        && enc
            .renew_till
            .as_ref()
            .is_some_and(|rt| rt.unix_seconds() > till.unix_seconds())
    {
        return Err(Error::ReplyMismatch(
            "TGS-REP renew-till after request till".into(),
        ));
    }
    Ok(())
}

// MIT: `tgt_is_local_realm` (gc_via_tkt.c:139-147)
fn tgt_is_local_realm(tgt: &AsOutcome) -> bool {
    let crealm = String::from_utf8_lossy(tgt.crealm.as_bytes());
    tgt.ticket.sname.is_krbtgt_for(crealm.as_ref())
        && tgt.ticket.realm.as_bytes() == tgt.crealm.as_bytes()
}

#[must_use]
// MIT: `krb5int_process_tgs_reply` (gc_via_tkt.c:247-252)
/// Dropped when a foreign TGT lacks ok-as-delegate.
pub fn tgs_strip_ok_as_delegate(
    tgt_local_realm: bool,
    tgt_ok_as_delegate: bool,
    flags: krb5_types::TicketFlags,
) -> krb5_types::TicketFlags {
    if !tgt_local_realm && !tgt_ok_as_delegate {
        flags.with_bit(flag_bit::OK_AS_DELEGATE, false)
    } else {
        flags
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TgsFallback {
    KeepError,
    NonReferral,
    HostRealmUnknown,
    HostRealm,
}

#[must_use]
pub fn tgs_try_fallback(
    referral_count: usize,
    specified_realm: bool,
    ncomps: usize,
) -> TgsFallback {
    if referral_count > 1 {
        return TgsFallback::KeepError;
    }
    if specified_realm {
        return TgsFallback::NonReferral;
    }
    if ncomps < 2 {
        return TgsFallback::HostRealmUnknown;
    }
    TgsFallback::HostRealm
}

#[must_use]
pub fn tgs_non_referral_options(opts: KdcOptions) -> KdcOptions {
    opts.with_bit(flag_bit::CANONICALIZE, false)
}

enum ServiceStep {
    Reply(Box<TgsOutcome>),
    Fallback(String),
}

fn fallback_realm(profile: &Krb5Conf, sname: &PrincipalName) -> Option<String> {
    let host = sname.name_string.get(1)?;
    krb5_config::fallback_host_realm_traced(
        profile,
        &String::from_utf8_lossy(host.as_bytes()),
        &mut crate::trace::dns_srv,
    )
}

fn service_request<'a>(
    sname: &PrincipalName,
    served: &'a str,
    kdc_options: KdcOptions,
    creds_opts: &TgsCredsOptions,
) -> TgsRequest<'a> {
    let mut req = TgsRequest::new(sname.clone(), served, kdc_options);
    req.additional_tickets = creds_opts.second_ticket.clone().map(|t| vec![t]);
    req.enctype = creds_opts.enctype;
    req
}

struct ServiceHop<'a> {
    sname: &'a PrincipalName,
    served: &'a str,
    extra: KdcOptions,
    request_realm: &'a str,
    referral_count: usize,
    creds_opts: &'a TgsCredsOptions,
}

fn service_non_referral_request(
    profile: &Krb5Conf,
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: &PrincipalName,
    served: &str,
    extra: KdcOptions,
    creds_opts: &TgsCredsOptions,
) -> Result<TgsOutcome, Error> {
    trace::tkt_creds_service_req(trace::Princ::new(sname, served.as_bytes()), false);
    tgs_once(
        profile,
        kdc,
        tgt,
        service_request(sname, served, tgs_request_options(tgt, extra), creds_opts),
    )
}

fn tgs_service_once(
    profile: &Krb5Conf,
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    hop: ServiceHop<'_>,
) -> Result<ServiceStep, Error> {
    let ServiceHop {
        sname,
        served,
        extra,
        request_realm,
        referral_count,
        creds_opts,
    } = hop;
    let referral = tgs_request_options(tgt, extra.clone().with_bit(flag_bit::CANONICALIZE, true));
    let server = trace::Princ::new(sname, served.as_bytes());
    trace::tkt_creds_service_req(server, true);
    let non_referral = || {
        service_non_referral_request(profile, kdc, tgt, sname, served, extra, creds_opts)
            .map(|out| ServiceStep::Reply(Box::new(out)))
    };
    match tgs_once(
        profile,
        kdc,
        tgt,
        service_request(sname, served, referral, creds_opts),
    ) {
        Ok(out) => Ok(ServiceStep::Reply(Box::new(out))),
        // MIT: `step_referrals` (lib/krb5/krb/get_creds.c:566-570)
        // Any failure but an unreachable KDC.
        Err(e) if !matches!(e, Error::Io { .. }) => match tgs_try_fallback(
            referral_count,
            !request_realm.is_empty() && !creds_opts.referral_realm,
            sname.name_string.len(),
        ) {
            TgsFallback::NonReferral => non_referral(),
            TgsFallback::HostRealmUnknown => Err(Error::ReplyMismatch("host realm unknown".into())),
            TgsFallback::HostRealm => match fallback_realm(profile, sname) {
                Some(r) if r == request_realm => non_referral(),
                Some(r) => Ok(ServiceStep::Fallback(r)),
                None => Err(e),
            },
            TgsFallback::KeepError => Err(e),
        },
        Err(e) => Err(e),
    }
}

// MIT: `krb5_fwd_tgt_creds` (fwd_tgt.c:147-153)
#[must_use]
// MIT: `krb5_fwd_tgt_creds` (fwd_tgt.c:152-153)
pub fn tgs_forward_options(flags: &krb5_types::TicketFlags, forwardable: bool) -> KdcOptions {
    let mut opts = tkt_common_from_flags(flags).with_bit(flag_bit::FORWARDED, true);
    if !forwardable {
        opts = opts.with_bit(flag_bit::FORWARDABLE, false);
    }
    opts
}
