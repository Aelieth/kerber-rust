//! TGS-REQ / TGS-REP using an existing TGT.
// MIT: `krb5int_decode_tgs_rep` (decode_kdc.c:64-67)
//! a TGS-REP without PA-FX-FAST is accepted the same way, its `KRB5_ERR_FAST_REQUIRED` ignored.

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
    /// An S4U2Proxy caller checks it against the evidence ticket's client.
    pub cname: PrincipalName,
}

// MIT: `krb5_tkt_creds_init` (get_creds.c:1107-1113)
// MIT: `make_request_for_service` (get_creds.c:358-363)
#[derive(Clone, Debug, Default)]
pub struct TgsCredsOptions {
    /// `KRB5_GC_CANONICALIZE` (`kvno -C`): `canonicalize` on the non-referral retry too.
    pub canonicalize: bool,
    pub forwardable: bool,
    pub enctype: Option<i32>,
    pub second_ticket: Option<Ticket>,
    /// Gate-only: the flag is set only on the service-realm krbtgt hop.
    #[cfg(feature = "test-hooks")]
    pub no_transit_check: bool,
    // MIT: `begin` (lib/krb5/krb/get_creds.c:1074-1083)
    /// a server in the referral realm is asked for in the start realm, as a referral request.
    pub referral_realm: bool,
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

#[allow(clippy::needless_pass_by_value)] // `tgt` is cloned into the path-TGT vec
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
        Ok(_) => tracing::info!(
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
    let sname = PrincipalName::krbtgt(&realm);
    let opts = tgs_forward_options(&tgt.enc_part.flags, true);
    tgs_once(
        profile,
        kdc,
        tgt,
        TgsRequest::new(sname, &realm, opts).via_tkt_ext(),
    )
}

// MIT: `get_new_creds` (val_renew.c:47-74)
/// the cached credential is presented to ask for its server again, with its common flags.
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
/// `0x54800000` = FORWARDABLE | PROXIABLE | MAY_POSTDATE | RENEWABLE.
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
/// 130 is filled after the TGS subkey exists (ku 26).
// MIT: `make_tgs_outer_padata` (fast.c:227-250)
/// FAST outer padata duplicates both.
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
/// Options add the TGT's forwardable, proxiable, postdate, and renewable flags.
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
        let (dest, hops) = get_dest_tgt(profile, kdc, &cur_tgt, realm)?;
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
        match chase_step(&start, &mut seen, sname, &served, &out)? {
            TgsHop::Done => {
                // MIT: `complete` (lib/krb5/krb/get_creds.c:451-470)
                // the service's credential.
                trace::tkt_creds_complete(trace::Princ::new(
                    &out.enc_part.sname,
                    out.enc_part.srealm.as_bytes(),
                ));
                return Ok((out, path));
            }
            TgsHop::Referral(foreign) => {
                // MIT: `step_referrals` (lib/krb5/krb/get_creds.c:561-634)
                // a referral TGT is followed to its realm.
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
/// The server realm is the fallback, and its TGT is obtained first.
// MIT: `step_non_referral` (lib/krb5/krb/get_creds.c:483-487)
/// a non-referral request's error is the result; its reply completes.
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
    let (dest, hops) = get_dest_tgt(profile, kdc, tgt, realm)?;
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
) -> Result<(AsOutcome, Vec<AsOutcome>), Error> {
    let start = tgt_served_realm(tgt);
    let path = krb5_config::client_realm_path(&profile.capaths, &start, dest);
    let mut seen = vec![start.clone()];
    let mut cached = Vec::new();
    let mut cur_kdc = kdc.clone();
    let mut cur_tgt = tgt.clone();
    let mut next = dest.to_owned();
    for _ in 0..REFERRAL_MAX_HOPS {
        let served = tgt_served_realm(&cur_tgt);
        if served == dest {
            return Ok((cur_tgt, cached));
        }
        let hop = PrincipalName::try_new(PrincipalName::NT_SRV_INST, ["krbtgt", next.as_str()])
            .map_err(|e| Error::ReplyMismatch(e.to_string()))?;
        // MIT: `make_request_for_tgt` (get_creds.c:341-343)
        // a TGT request has no extra options.
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
                chase_step(&start, &mut seen, &hop, &served, &out)?;
                if asked_for_hop(&hop, &out) {
                    cached.push(tgs_as_tgt(&cur_tgt, out.clone()));
                }
                cur_tgt = tgs_as_tgt(&cur_tgt, out);
                // MIT: `step_get_tgt` (lib/krb5/krb/get_creds.c:938-976)
                // a TGT for the target realm ends the walk; another advances it.
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

fn tgs_sname_matches(
    requested: &PrincipalName,
    ticket: &PrincipalName,
    enc: &PrincipalName,
) -> bool {
    ticket.name_string == requested.name_string
        || enc.name_string == requested.name_string
        || (ticket.is_krbtgt() && requested.components_joined() != ticket.components_joined())
}

// MIT: `krb5int_fast_process_response` (fast.c:548-551)
/// When armed, the finished client replaces crealm and cname before the compare.
fn tgs_fast_reply_key(
    armor_key: &ProtocolKey,
    sub: &ProtocolKey,
    inner: &mut krb5_types::KdcRep,
    nonce: u32,
) -> Result<(ProtocolKey, Vec<PaData>), Error> {
    // MIT: `decrypt_fast_reply` (lib/krb5/krb/fast.c:359-415)
    // every TGS reply is traced as decoded, as a TGS request always has its armor key.
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
    tracing::info!(
        event = krb5_log::events::CLIENT_TGS,
        component = "krb5-protocol",
        outcome = "ok",
        fast_strengthen = true,
    );
    let reply_key = apply_strengthen(sk, sub)?;
    // MIT: `krb5int_fast_reply_key` (lib/krb5/krb/fast.c:570-592)
    // the strengthened key is traced as a hash.
    trace::fast_reply_key((&reply_key).into());
    Ok((reply_key, fast.padata))
}

fn tgs_sname_ok(
    requested: &PrincipalName,
    ticket: &PrincipalName,
    enc: &PrincipalName,
) -> Result<(), Error> {
    if tgs_sname_matches(requested, ticket, enc) {
        Ok(())
    } else {
        Err(Error::ReplyMismatch(format!(
            "TGS-REP sname mismatch requested={} ticket={}",
            requested.components_joined(),
            ticket.components_joined()
        )))
    }
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
                return Err(Error::ReplyMismatch("referral loop".into()));
            }
            seen.push(foreign.clone());
            Ok(TgsHop::Referral(foreign))
        }
    }
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
/// A generic KDC error keeps its e-text; an unknown server is named in the text.
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
        Error::Io { .. } => (trace::KRB5_KDC_UNREACH, None),
        Error::Crypto(_) => (trace::kdc_code(krb5_types::err::BAD_INTEGRITY), None),
        // MIT: `KRB5DES_BAD_KEYPAR` (krb5_err.et:251-251)
        // the code a des3 key with bad parity gives the request.
        Error::DesBadParity => (trace::ERROR_TABLE_BASE_KRB5 + 186, None),
        Error::DesWeakKey => (trace::ERROR_TABLE_BASE_KRB5 + 187, None),
        Error::UnexpectedPdu => (trace::kdc_code(krb5_types::err::MSG_TYPE), None),
        _ => (trace::KRB5_KDCREP_MODIFIED, None),
    })
}

// MIT: `k5_make_tgs_req` (send_tgs.c:155-160)
/// `till` is the TGT's end time, and no `rtime` is asked for.
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
    let plain = decrypt_enc_data(
        &reply_key,
        usage,
        inner.enc_part.etype,
        inner.enc_part.cipher.as_ref(),
    )?;
    // MIT: `krb5_kdc_rep_decrypt_proc` (kdc_rep_dc.c:69-69)
    // decodes the TGS-REP enc-part with `decode_krb5_enc_kdc_rep_part` (APPLICATION 26 then 25 then untagged).
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
    // VALIDATE. The wire `till` is still the old TGT endtime; a renewed ticket may outlive it.
    if !kdc_options.bit(flag_bit::RENEW) && !kdc_options.bit(flag_bit::VALIDATE) {
        tgs_reply_req_times(&enc_part, &till, None, None, &kdc_options)?;
    }
    if kdc_options.bit(flag_bit::CANONICALIZE)
        && (inner.ticket.sname.name_string != requested.name_string
            || inner.ticket.realm.as_bytes() != realm.as_bytes())
        && tgs_sname_matches(&requested, &inner.ticket.sname, &enc_part.sname)
    {
        trace::check_reply_server_differs(
            trace::Princ::new(&requested, realm.as_bytes()),
            trace::Princ::new(&inner.ticket.sname, inner.ticket.realm.as_bytes()),
        );
    }
    tgs_sname_ok(&requested, &inner.ticket.sname, &enc_part.sname)?;
    let session_etype = EncryptionType::known(enc_part.key.keytype)?;
    let session_key = ProtocolKey::from_bytes(session_etype, enc_part.key.keyvalue.as_ref())?;
    // MIT: `kdcrep2creds` (lib/krb5/krb/gc_via_tkt.c:36-94)
    // a reply that passed its checks is traced with its client, its server and its session key as a hash.
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
/// A reply client equal to the requested server means the KDC ignored PA-FOR-USER.
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
/// ticket server equals enc-part server (name and realm; name-type ignored).
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

/// A time of 0 is unspecified and is not checked.
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
/// true when the TGT is `krbtgt/CREALM@CREALM` for the client's realm.
fn tgt_is_local_realm(tgt: &AsOutcome) -> bool {
    let crealm = String::from_utf8_lossy(tgt.crealm.as_bytes());
    tgt.ticket.sname.is_krbtgt_for(crealm.as_ref())
        && tgt.ticket.realm.as_bytes() == tgt.crealm.as_bytes()
}

#[must_use]
// MIT: `krb5int_process_tgs_reply` (gc_via_tkt.c:247-252)
/// ok-as-delegate is dropped when a foreign TGT lacks it.
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

/// A referral adds canonicalize; the retry sends the caller's options alone.
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
        trace::tkt_creds_service_req(server, false);
        let req = service_request(sname, served, tgs_request_options(tgt, extra), creds_opts);
        tgs_once(profile, kdc, tgt, req).map(|out| ServiceStep::Reply(Box::new(out)))
    };
    match tgs_once(
        profile,
        kdc,
        tgt,
        service_request(sname, served, referral, creds_opts),
    ) {
        Ok(out) => Ok(ServiceStep::Reply(Box::new(out))),
        Err(e @ Error::KrbError { .. }) => match tgs_try_fallback(
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
/// `flags2options | KDC_OPT_FORWARDED`.
#[must_use]
// MIT: `krb5_fwd_tgt_creds` (fwd_tgt.c:152-153)
/// `forwardable == false` clears `FORWARDABLE`.
pub fn tgs_forward_options(flags: &krb5_types::TicketFlags, forwardable: bool) -> KdcOptions {
    let mut opts = tkt_common_from_flags(flags).with_bit(flag_bit::FORWARDED, true);
    if !forwardable {
        opts = opts.with_bit(flag_bit::FORWARDABLE, false);
    }
    opts
}

#[cfg(test)]
mod tests {
    use krb5_crypto::{EncryptionType, ProtocolKey};
    use krb5_types::{
        EncKdcRepPart, EncryptedData, EncryptionKey, OctetString, PrincipalName, Ticket,
        TicketFlags, ascii,
    };

    use super::*;

    fn session() -> ProtocolKey {
        ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[7u8; 32]).unwrap()
    }

    fn outcome(ticket_realm: &str, sname: PrincipalName, srealm: &str) -> TgsOutcome {
        let t = KerberosTime::now();
        TgsOutcome {
            ticket: Ticket {
                tkt_vno: Ticket::VNO,
                realm: ascii(ticket_realm),
                sname: sname.clone(),
                enc_part: EncryptedData {
                    etype: 18,
                    kvno: Some(1),
                    cipher: OctetString::from(vec![0u8; 16]),
                },
            },
            enc_part: EncKdcRepPart {
                key: EncryptionKey {
                    keytype: 18,
                    keyvalue: OctetString::from(vec![7u8; 32]),
                },
                last_req: vec![],
                nonce: 1,
                key_expiration: None,
                flags: TicketFlags::none(),
                authtime: t.clone(),
                starttime: None,
                endtime: t,
                renew_till: None,
                srealm: ascii(srealm),
                sname,
                caddr: None,
                encrypted_pa_data: None,
            },
            session_key: session(),
            crealm: ascii("KERBER.TEST"),
            cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        }
    }

    #[test]
    fn hop_two_uses_foreign_realm() {
        let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc.other.test"]);
        let krbtgt = PrincipalName::krbtgt("OTHER.TEST");
        let out = outcome("OTHER.TEST", krbtgt, "OTHER.TEST");
        match tgs_hop_decision(&host, "KERBER.TEST", &out).unwrap() {
            TgsHop::Referral(r) => assert_eq!(r, "OTHER.TEST"),
            TgsHop::Done => panic!("expected referral hop"),
        }
    }

    #[test]
    fn hop_rejects_mismatched_srealm() {
        let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc"]);
        let krbtgt = PrincipalName::krbtgt("OTHER.TEST");
        let out = outcome("OTHER.TEST", krbtgt, "EVIL.TEST");
        let err = tgs_hop_decision(&host, "KERBER.TEST", &out).unwrap_err();
        assert!(matches!(err, Error::ReplyMismatch(_)));
    }

    #[test]
    fn hop_rejects_same_realm_referral() {
        let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc"]);
        let krbtgt = PrincipalName::krbtgt("KERBER.TEST");
        let out = outcome("KERBER.TEST", krbtgt, "KERBER.TEST");
        let err = tgs_hop_decision(&host, "KERBER.TEST", &out).unwrap_err();
        assert!(matches!(err, Error::Referral));
    }

    #[test]
    fn hop_done_for_service_ticket() {
        let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc"]);
        let out = outcome("KERBER.TEST", host.clone(), "KERBER.TEST");
        assert_eq!(
            tgs_hop_decision(&host, "KERBER.TEST", &out).unwrap(),
            TgsHop::Done
        );
    }

    #[test]
    fn tgs_sname_ignores_name_type_rejects_wrong_components() {
        let asked = PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            ["host", "testhost.kerber.test"],
        );
        let heimdal =
            PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "testhost.kerber.test"]);
        assert!(tgs_sname_matches(&asked, &heimdal, &heimdal));
        let other = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "other.kerber.test"]);
        assert!(!tgs_sname_matches(&asked, &other, &other));
        let krbtgt = PrincipalName::krbtgt("OTHER.TEST");
        assert!(tgs_sname_matches(&asked, &krbtgt, &krbtgt));
        tgs_sname_ok(&asked, &krbtgt, &krbtgt).unwrap();
        let want_c = PrincipalName::krbtgt("C.TEST");
        let got_b = PrincipalName::krbtgt("B.TEST");
        assert!(tgs_sname_matches(&want_c, &got_b, &got_b));
        tgs_sname_ok(&want_c, &got_b, &got_b).unwrap();
    }

    #[test]
    fn tgs_sname_flat_krbtgt_is_reply_mismatch() {
        let two = PrincipalName::krbtgt("KERBER.TEST");
        let flat = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["krbtgt/KERBER.TEST"]);
        assert_eq!(two.components_joined(), flat.components_joined());
        assert!(matches!(
            tgs_sname_ok(&two, &flat, &flat),
            Err(Error::ReplyMismatch(_))
        ));
        assert!(matches!(
            tgs_sname_ok(&flat, &two, &two),
            Err(Error::ReplyMismatch(_))
        ));
    }

    fn as_tgt(instance: &str) -> AsOutcome {
        let out = outcome(instance, PrincipalName::krbtgt(instance), instance);
        AsOutcome {
            ticket: out.ticket,
            enc_part: out.enc_part,
            client_key: session(),
            session_key: session(),
            cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
            crealm: ascii(instance),
            fast_avail: false,
            used_fast: false,
            pa_type: None,
            pa_config: None,
            time_offset: 0,
        }
    }

    #[test]
    fn served_realm_is_krbtgt_instance() {
        let a = as_tgt("A.TEST");
        assert_eq!(tgt_served_realm(&a), "A.TEST");
        let mut x = as_tgt("C.TEST");
        x.ticket.sname = PrincipalName::krbtgt("C.TEST");
        x.ticket.realm = ascii("B.TEST");
        assert_eq!(tgt_served_realm(&x), "C.TEST");
    }

    fn tgt_with_flags(mit_flags: u32) -> AsOutcome {
        let out = outcome(
            "KERBER.TEST",
            PrincipalName::krbtgt("KERBER.TEST"),
            "KERBER.TEST",
        );
        AsOutcome {
            ticket: out.ticket,
            enc_part: EncKdcRepPart {
                flags: TicketFlags::from_u32(mit_flags),
                ..out.enc_part
            },
            client_key: session(),
            session_key: session(),
            cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
            crealm: ascii("KERBER.TEST"),
            fast_avail: false,
            used_fast: false,
            pa_type: None,
            pa_config: None,
            time_offset: 0,
        }
    }

    #[test]
    fn tgs_options_are_flags2opts_of_the_tgt() {
        const FRIA: u32 = 0x40e1_0000;
        let canon = KdcOptions::none().with_bit(flag_bit::CANONICALIZE, true);
        let service = |flags| tgs_request_options(&tgt_with_flags(flags), canon.clone()).to_u32();
        assert_eq!(service(FRIA), 0x4081_0000);
        assert_eq!(service(0x4061_0000), 0x4001_0000);
        assert_eq!(service(0x00e1_0000), 0x0081_0000);
        let u2u = canon.clone().with_bit(flag_bit::ENC_TKT_IN_SKEY, true);
        assert_eq!(
            tgs_request_options(&tgt_with_flags(FRIA), u2u).to_u32(),
            0x4081_0008
        );
        let proxiable = tgs_request_options(&tgt_with_flags(0x5000_0000), KdcOptions::none());
        assert_eq!(proxiable.to_u32(), 0x5000_0000);
        let tgt_hop = tgs_request_options(&tgt_with_flags(FRIA), KdcOptions::none());
        assert_eq!(tgt_hop.to_u32(), 0x4080_0000);
        let opts = TgsCredsOptions {
            canonicalize: true,
            ..TgsCredsOptions::default()
        };
        assert_eq!(tgs_service_extra(&opts).to_u32(), 0x0001_0000);
    }

    #[test]
    fn chase_step_repeated_realm_is_reply_mismatch() {
        let want = PrincipalName::krbtgt("C.TEST");
        let again = PrincipalName::krbtgt("B.TEST");
        let out = outcome("B.TEST", again, "B.TEST");
        let mut seen = vec!["A.TEST".into(), "B.TEST".into()];
        let err = chase_step("A.TEST", &mut seen, &want, "C.TEST", &out).unwrap_err();
        match err {
            Error::ReplyMismatch(s) => assert!(s.contains("referral loop"), "{s}"),
            other => panic!("expected ReplyMismatch referral loop, got {other:?}"),
        }
    }

    #[test]
    fn chase_step_asked_for_hop_is_cached() {
        let want = PrincipalName::krbtgt("C.TEST");
        let got_c = outcome("C.TEST", want.clone(), "B.TEST");
        assert!(asked_for_hop(&want, &got_c));
        let got_b = outcome("B.TEST", PrincipalName::krbtgt("B.TEST"), "A.TEST");
        assert!(!asked_for_hop(&want, &got_b));
    }
}
