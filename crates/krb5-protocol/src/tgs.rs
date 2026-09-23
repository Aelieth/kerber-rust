//! TGS-REQ / TGS-REP using an existing TGT.

use std::collections::BTreeMap;
use std::time::Instant;

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, checksum, decrypt, encrypt, krb_fx_cf2};
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

use crate::transport::{KdcAddr, exchange};

/// MIT `KRB5_REFERRAL_MAXHOPS` (`k5-int.h`).
const REFERRAL_MAX_HOPS: usize = 10;

/// Successful TGS exchange.
#[derive(Clone, Debug)]
pub struct TgsOutcome {
    /// Service ticket.
    pub ticket: Ticket,
    /// Decrypted EncKDCRepPart.
    pub enc_part: EncKdcRepPart,
    /// Session key for the service.
    pub session_key: ProtocolKey,
}

/// Request a service ticket with a TGT from [`AsOutcome`].
///
/// # Errors
///
/// Returns transport, crypto, or `KRB-ERROR` failures.
pub fn tgs_exchange(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
) -> Result<TgsOutcome, Error> {
    tgs_exchange_ex(kdc, tgt, sname, realm, false)
}

/// Like [`tgs_exchange`], with `DISABLE_TRANSITED_CHECK` on the hop whose
/// presented TGT is `krbtgt/{realm}` (the service realm). Referral hops
/// omit the bit so a default MIT KDC does not POLICY the first hop.
///
/// # Errors
///
/// Returns transport, crypto, or `KRB-ERROR` failures.
#[allow(clippy::needless_pass_by_value)]
pub fn tgs_exchange_ex(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
    disable_transited_check: bool,
) -> Result<TgsOutcome, Error> {
    Ok(tgs_exchange_path(kdc, tgt, sname, realm, disable_transited_check)?.0)
}

/// One TGS-REQ; `realm` is `body.realm`. No capaths/referral chase.
///
/// Gate-only (`krb5-kvno --body-realm`): MIT clients never send a foreign
/// `body.realm`.
///
/// # Errors
///
/// Transport, crypto, or `KRB-ERROR` failures.
#[allow(clippy::needless_pass_by_value)]
pub fn tgs_exchange_once(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
    disable_transited_check: bool,
    renew: bool,
) -> Result<TgsOutcome, Error> {
    let mut opts = tgs_kdc_options(tgt);
    if disable_transited_check {
        opts = opts.with_bit(flag_bit::DISABLE_TRANSITED_CHECK, true);
    }
    if renew {
        opts = opts.with_bit(flag_bit::RENEW, true);
    }
    tgs_once(kdc, tgt, sname, realm, opts, &[], None, None)
}

/// Like [`tgs_exchange_ex`], also returning asked-for path TGTs to cache.
///
/// # Errors
///
/// Returns transport, crypto, or `KRB-ERROR` failures.
#[allow(clippy::needless_pass_by_value)] // `tgt` is cloned into the path-TGT vec
pub fn tgs_exchange_path(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
    disable_transited_check: bool,
) -> Result<(TgsOutcome, Vec<AsOutcome>), Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let _g = krb5_log::enter_correlation(correlation_id.clone());
    let started = Instant::now();
    let result = tgs_inner(kdc, tgt, &sname, realm, disable_transited_check);
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

/// TGS-REQ with `FORWARDED` for `krb5_fwd_tgt_creds`.
///
/// # Errors
///
/// Transport, crypto, or `KRB-ERROR` failures.
pub fn tgs_forward(kdc: &KdcAddr, tgt: &AsOutcome) -> Result<TgsOutcome, Error> {
    let realm = String::from_utf8_lossy(tgt.crealm.as_bytes()).into_owned();
    let sname = PrincipalName::krbtgt(&realm);
    let opts = tgs_forward_options(&tgt.enc_part.flags, true);
    tgs_once(kdc, tgt, sname, &realm, opts, &[], None, None)
}

/// TGS-REQ with KDC option `renew` for `kinit -R`.
///
/// # Errors
///
/// Transport, crypto, or `KRB-ERROR` failures.
pub fn tgs_renew(kdc: &KdcAddr, tgt: &AsOutcome) -> Result<TgsOutcome, Error> {
    let realm = String::from_utf8_lossy(tgt.crealm.as_bytes()).into_owned();
    let sname = PrincipalName::krbtgt(&realm);
    tgs_once(
        kdc,
        tgt,
        sname,
        &realm,
        tgs_renew_options(&tgt.enc_part.flags),
        &[],
        None,
        None,
    )
}

/// MIT `KDC_TKT_COMMON_MASK` (`krb5.hin:1659` = `0x54800000`):
/// FORWARDABLE | PROXIABLE | MAY_POSTDATE | RENEWABLE.
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

/// MIT `val_renew.c:62-67` `get_new_creds`: `KDC_OPT_RENEW` plus
/// `old_creds.ticket_flags & KDC_TKT_COMMON_MASK`. No `CANONICALIZE`
/// (`get_creds.c` sets that only on the referral walk).
#[must_use]
pub fn tgs_renew_options(flags: &krb5_types::TicketFlags) -> KdcOptions {
    tkt_common_from_flags(flags).with_bit(flag_bit::RENEW, true)
}

/// TGS-REQ with PA-S4U-X509-USER (130) and PA-FOR-USER (129) like MIT
/// `krb5_get_self_cred_from_kdc` (`s4u_creds.c:517-567`). 130 is filled
/// after the TGS subkey exists (ku 26). FAST outer padata duplicates
/// both (`fast.c:227-250`). The KDC enforces that `sname` is the TGT
/// client; this helper does not.
///
/// # Errors
///
/// Transport, crypto, or `KRB-ERROR` failures.
pub fn tgs_s4u(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
    for_user: &PrincipalName,
    for_realm: &str,
) -> Result<TgsOutcome, Error> {
    tgs_once(
        kdc,
        tgt,
        sname,
        realm,
        tgs_kdc_options(tgt),
        &[],
        None,
        Some((for_user, for_realm)),
    )
}

/// One TGS-REQ with `ENC_TKT_IN_SKEY` and `stkt` as the second ticket.
///
/// Gate-only (`krb5-kvno --u2u`).
///
/// # Errors
///
/// Transport, crypto, or `KRB-ERROR` failures.
pub fn tgs_u2u(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
    stkt: Ticket,
) -> Result<TgsOutcome, Error> {
    let opts = tgs_kdc_options(tgt).with_bit(flag_bit::ENC_TKT_IN_SKEY, true);
    tgs_once(kdc, tgt, sname, realm, opts, &[], Some(vec![stkt]), None)
}

/// MIT `krb5_get_credentials`: copy F/P from the TGT into TGS-REQ options.
fn tgs_kdc_options(tgt: &AsOutcome) -> KdcOptions {
    let mut opts = KdcOptions::forwardable().with_bit(flag_bit::CANONICALIZE, true);
    if tgt.enc_part.flags.proxiable() {
        opts = opts.with_bit(flag_bit::PROXIABLE, true);
    }
    opts
}

fn tgs_inner(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: &PrincipalName,
    realm: &str,
    disable_transited_check: bool,
) -> Result<(TgsOutcome, Vec<AsOutcome>), Error> {
    let capaths = krb5_config::load_krb5_conf()
        .map(|c| c.capaths)
        .unwrap_or_default();
    let start = tgt_served_realm(tgt);
    let mut cur_kdc = kdc.clone();
    let mut cur_tgt = tgt.clone();
    let mut path = Vec::new();
    if tgt_served_realm(&cur_tgt) != realm {
        let (dest, hops) = get_dest_tgt(kdc, &cur_tgt, realm, &capaths)?;
        cur_tgt = dest;
        path = hops;
        cur_kdc = kdc_for_realm(&tgt_served_realm(&cur_tgt), kdc);
    }
    let mut seen = vec![start.clone()];
    for _ in 0..REFERRAL_MAX_HOPS {
        let served = tgt_served_realm(&cur_tgt);
        let mut opts = tgs_kdc_options(&cur_tgt);
        if disable_transited_check && cur_tgt.ticket.sname.is_krbtgt_for(realm) {
            opts = opts.with_bit(flag_bit::DISABLE_TRANSITED_CHECK, true);
        }
        let out = tgs_service_once(&cur_kdc, &cur_tgt, sname, &served, opts, realm, seen.len())?;
        match chase_step(&start, &mut seen, sname, &served, &out)? {
            TgsHop::Done => return Ok((out, path)),
            TgsHop::Referral(foreign) => {
                cur_kdc = kdc_for_realm(&foreign, kdc);
                cur_tgt = tgs_as_tgt(&cur_tgt, out);
            }
        }
    }
    Err(Error::Referral)
}

/// Realm this TGT is accepted at (MIT `cur_tgt->server` instance).
fn tgt_served_realm(tgt: &AsOutcome) -> String {
    referral_hop_realm(&tgt.ticket.sname)
        .unwrap_or_else(|| String::from_utf8_lossy(tgt.ticket.realm.as_bytes()).into_owned())
}

/// Ask the current TGT's realm for `krbtgt/<next>` until we hold the dest TGT.
///
/// MIT `get_tgt_request` / `step_get_tgt`: dest first, then closer hops
/// along `k5_client_realm_path`. Each TGS-REQ `body.realm` is the current
/// TGT's realm (`make_request_for_tgt`).
fn get_dest_tgt(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    dest: &str,
    capaths: &BTreeMap<String, BTreeMap<String, Vec<String>>>,
) -> Result<(AsOutcome, Vec<AsOutcome>), Error> {
    let start = tgt_served_realm(tgt);
    let path = krb5_config::client_realm_path(capaths, &start, dest);
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
        match tgs_once(
            &cur_kdc,
            &cur_tgt,
            hop.clone(),
            &served,
            tgs_kdc_options(&cur_tgt),
            &[],
            None,
            None,
        ) {
            Ok(out) => {
                chase_step(&start, &mut seen, &hop, &served, &out)?;
                if asked_for_hop(&hop, &out) {
                    cached.push(tgs_as_tgt(&cur_tgt, out.clone()));
                }
                cur_tgt = tgs_as_tgt(&cur_tgt, out);
                cur_kdc = kdc_for_realm(&tgt_served_realm(&cur_tgt), kdc);
                dest.clone_into(&mut next);
            }
            Err(e @ Error::KrbError { .. }) => match closer_hop(&path, &served, &next) {
                Some(c) => next = c.to_owned(),
                None => return Err(e),
            },
            Err(e) => return Err(e),
        }
    }
    Err(Error::Referral)
}

/// Previous realm on `path` toward `next`. `None` when that is `cur`.
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
    }
}

/// RFC 4120 name-type is a hint. Heimdal canonicalize may return NT-SRV-HST
/// for a host principal requested as NT-PRINCIPAL. A krbtgt reply that is
/// not the requested name is a referral or closer-hop TGT (`step_get_tgt`).
fn tgs_sname_matches(
    requested: &PrincipalName,
    ticket: &PrincipalName,
    enc: &PrincipalName,
) -> bool {
    ticket.name_string == requested.name_string
        || enc.name_string == requested.name_string
        || (ticket.is_krbtgt() && requested.components_joined() != ticket.components_joined())
}

/// MIT `decode_kdc.c:64-67`: missing PA-FX-FAST is `KRB5_ERR_FAST_REQUIRED`
/// then ignored. A present FAST envelope still requires finished + strengthen.
/// The returned padata is FAST-inner when armed (`fast.c` swap), else the
/// TGS-REP list — `verify_s4u2self_reply` reads 130 from here. When armed the
/// reply's `crealm` / `cname` are replaced by the finished message's client
/// (`fast.c:548-551`) before `process_tgs_reply` compares them.
fn tgs_fast_reply_key(
    armor_key: &ProtocolKey,
    sub: &ProtocolKey,
    inner: &mut krb5_types::KdcRep,
    nonce: u32,
) -> Result<(ProtocolKey, Vec<PaData>), Error> {
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
        event = "client.tgs",
        component = "krb5-protocol",
        outcome = "ok",
        fast_strengthen = true,
    );
    Ok((apply_strengthen(sk, sub)?, fast.padata))
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

/// One TGS-REQ hop: stay, chase a referral, or reject a bad srealm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TgsHop {
    /// `out` is the requested service ticket.
    Done,
    /// Chase `krbtgt/FOREIGN`; next `body.realm` is this string.
    Referral(String),
}

fn asked_for_hop(requested: &PrincipalName, out: &TgsOutcome) -> bool {
    out.ticket.sname == *requested || out.enc_part.sname == *requested
}

/// Per-chase hop: start-realm bounce and repeated realm are ReplyMismatch.
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

/// Authenticate `srealm` then decide whether this TGS-REP is a referral hop.
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

/// Next TGS-REQ `realm` after a referral TGT `krbtgt/FOREIGN`.
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

fn kdc_for_realm(realm: &str, fallback: &KdcAddr) -> KdcAddr {
    krb5_config::discover_kdc(realm).map_or_else(
        || fallback.clone(),
        |ep| KdcAddr {
            host: ep.host,
            port: ep.port,
        },
    )
}

#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
fn tgs_once(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
    kdc_options: KdcOptions,
    extra_padata: &[PaData],
    extra_tickets: Option<Vec<Ticket>>,
    s4u: Option<(&PrincipalName, &str)>,
) -> Result<TgsOutcome, Error> {
    let nonce = random_nonce31()?;
    let till = KerberosTime(tgt.enc_part.endtime.0);
    let etypes = crate::as_ex::conf_etypes(true);

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
    let now = KerberosTime::now();
    let usec = now.0.timestamp_subsec_micros() % 1_000_000;
    let mut raw = vec![0u8; tgt.session_key.etype().key_len()];
    getrandom::getrandom(&mut raw).map_err(|e| Error::transport_msg(e.to_string()))?;
    let sub = ProtocolKey::from_bytes(tgt.session_key.etype(), &raw)?;
    let mut extra = extra_padata.to_vec();
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
        cusec: krb5_types::Microseconds::from_subsec_micros(usec),
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
    // FAST armor AP-REQ uses key-usage 11; PA-TGS-REQ uses usage 7. MIT
    // FIND_FAST fails if the armor AP-REQ is the TGS authenticator.
    let ap_raw = encode(&ap_req)?;
    let mut padata = vec![PaData {
        padata_type: pa::TGS_REQ,
        padata_value: ap_raw.clone().into(),
    }];
    padata.push(fx_fast_padata_over(
        None,
        &armor_key,
        &ap_raw,
        &body,
        extra.clone(),
        &krb5_types::fast::fast_options_none(),
    )?);
    // MIT `make_tgs_outer_padata` (`fast.c:227-250`): outer FAST TGS
    // duplicates inner padata (S4U 130/129) after PA-FX-FAST.
    padata.extend(extra);
    let tgs = TgsReq(KdcReq {
        pvno: KdcReq::PVNO,
        msg_type: KdcReq::MSG_TGS_REQ,
        padata: Some(padata),
        req_body: body,
    });
    let wire = encode(&tgs)?;
    let reply = exchange(kdc, &wire)?;
    if reply.is_empty() {
        return Err(Error::TruncatedReply);
    }
    if reply[0] == 0x7e {
        let outer: krb5_types::KrbError = decode(&reply)?;
        // MIT `gc_via_tkt.c:190-194`: `krb5int_fast_process_error` under the
        // armor key — the authenticated FX-ERROR inside PA-FX-FAST replaces
        // the outer error; an envelope that is missing or does not unwrap
        // leaves the outer error as the (fatal) answer. Same rule as the AS
        // path (`as_ex.rs` `fast_error_material`).
        let e = crate::as_ex::fast_error_material(&armor_key, &outer, nonce)?.err;
        let text = e
            .e_text
            .as_ref()
            .and_then(|s| std::str::from_utf8(s.as_bytes()).ok())
            .map(str::to_owned);
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
    let plain = decrypt(&reply_key, usage, inner.enc_part.cipher.as_ref())?;
    // MIT `kdc_rep_dc.c:69` decodes the TGS-REP enc-part with
    // `decode_krb5_enc_kdc_rep_part` (APPLICATION 26 then 25 then untagged).
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
    // MIT `val_renew.c` `get_valrenewed_creds` zeros `in_creds.times`, so
    // `process_tgs_reply` skips the till/rtime/from bounds on RENEW and
    // VALIDATE. The wire `till` is still the old TGT endtime; a renewed
    // ticket may outlive it.
    if !kdc_options.bit(flag_bit::RENEW) && !kdc_options.bit(flag_bit::VALIDATE) {
        tgs_reply_req_times(&enc_part, &till, None, None, &kdc_options)?;
    }
    tgs_sname_ok(&requested, &inner.ticket.sname, &enc_part.sname)?;
    let session_etype = EncryptionType::known(enc_part.key.keytype)?;
    let session_key = ProtocolKey::from_bytes(session_etype, enc_part.key.keyvalue.as_ref())?;
    Ok(TgsOutcome {
        ticket: inner.ticket,
        enc_part,
        session_key,
    })
}

fn random_nonce31() -> Result<u32, Error> {
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).map_err(|e| Error::transport_msg(e.to_string()))?;
    let n = u32::from_be_bytes(b) & 0x7fff_ffff;
    Ok(if n == 0 { 1 } else { n })
}

/// S4U2Proxy TGS-REQ: `CNAME_IN_ADDL_TKT`, the evidence ticket, and
/// PA-PAC-OPTIONS RBCD (`s4u_creds.c:1013-1031` `k5_get_proxy_cred_from_kdc`).
/// FAST outer padata duplicates 167 (`fast.c:227-250`).
///
/// # Errors
///
/// Transport, crypto, or `KRB-ERROR` failures.
pub fn tgs_s4u2proxy(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    target: PrincipalName,
    realm: &str,
    evidence: Ticket,
) -> Result<TgsOutcome, Error> {
    let opts = tgs_kdc_options(tgt).with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let pac = crate::pa_pac_options(true)?;
    tgs_once(
        kdc,
        tgt,
        target,
        realm,
        opts,
        &[pac],
        Some(vec![evidence]),
        None,
    )
}

/// TGS-REQ with KDC option `validate` for `kinit -v`.
///
/// # Errors
///
/// Transport, crypto, or `KRB-ERROR` failures.
pub fn tgs_validate(kdc: &KdcAddr, tgt: &AsOutcome) -> Result<TgsOutcome, Error> {
    let realm = String::from_utf8_lossy(tgt.crealm.as_bytes()).into_owned();
    let sname = PrincipalName::krbtgt(&realm);
    tgs_once(
        kdc,
        tgt,
        sname,
        &realm,
        tgs_validate_options(&tgt.enc_part.flags),
        &[],
        None,
        None,
    )
}

/// MIT `val_renew.c:62-67` `get_new_creds`: `KDC_OPT_VALIDATE` plus
/// `old_creds.ticket_flags & KDC_TKT_COMMON_MASK`.
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

/// MIT `gc_via_tkt.c:257-270` `krb5int_process_tgs_reply` client half.
///
/// S4U2Self final hop: reply client == requested server means the KDC
/// ignored PA-FOR-USER (`KRB5KDC_ERR_PADATA_TYPE_NOSUPP`). Otherwise,
/// unless this is a final S4U2Proxy hop, reply client must match the
/// TGT client (`KRB5_KDCREP_MODIFIED`). Name-type is ignored
/// (`krb5_principal_compare`).
///
/// # Errors
///
/// [`Error::ReplyMismatch`] for either MIT status.
#[allow(clippy::too_many_arguments)]
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
            return Err(Error::ReplyMismatch("TGS-REP S4U2Self unsupported".into()));
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

/// MIT `gc_via_tkt.c:108-110` `check_reply_server`: ticket server equals
/// enc-part server (name and realm; name-type ignored).
///
/// # Errors
///
/// [`Error::ReplyMismatch`] (`KRB5_KDCREP_MODIFIED`).
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

/// MIT `gc_via_tkt.c:278-297` request-time half of `process_tgs_reply`.
///
/// `till`/`rtime`/`from` of 0 are unspecified. Reply `endtime` after
/// `till`, `renew_till` after `rtime` (RENEWABLE) or after `till`
/// (RENEWABLE_OK + issued RENEWABLE), or POSTDATED `from` ≠ starttime,
/// is `KRB5_KDCREP_MODIFIED`. `tgs_once` skips this on RENEW/VALIDATE
/// (`val_renew.c` zeros `in_creds.times`). Starttime skew is not
/// applied here: MIT uses the per-context timestamp that `kdc_timesync`
/// adjusts, and this crate has no `krb5_context`.
///
/// # Errors
///
/// [`Error::ReplyMismatch`] (`KRB5_KDCREP_MODIFIED`).
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

/// MIT `gc_via_tkt.c:139-147` `tgt_is_local_realm`.
fn tgt_is_local_realm(tgt: &AsOutcome) -> bool {
    let crealm = String::from_utf8_lossy(tgt.crealm.as_bytes());
    tgt.ticket.sname.is_krbtgt_for(crealm.as_ref())
        && tgt.ticket.realm.as_bytes() == tgt.crealm.as_bytes()
}

/// MIT `gc_via_tkt.c:247-252`: drop `ok-as-delegate` from a foreign TGT
/// that itself lacks the flag.
#[must_use]
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

/// After the first referral-style TGS error, MIT `try_fallback`
/// (`get_creds.c:503-543`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TgsFallback {
    /// Later referral hop: keep the KDC error (`referral_count > 1`).
    KeepError,
    /// Specified server realm: retry without `CANONICALIZE`.
    NonReferral,
    /// Referral realm and fewer than two name components.
    HostRealmUnknown,
    /// Referral realm + hostname: MIT `krb5_get_fallback_host_realm` (B3).
    HostRealm,
}

/// Decide the MIT `try_fallback` arm. Host-realm DNS rewrite is not
/// applied here (`HostRealm` keeps the original error).
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

/// MIT `make_request_for_service(..., FALSE)`: drop `CANONICALIZE`.
#[must_use]
pub fn tgs_non_referral_options(opts: KdcOptions) -> KdcOptions {
    opts.with_bit(flag_bit::CANONICALIZE, false)
}

/// First referral TGS, then `try_fallback` on a KDC error.
fn tgs_service_once(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: &PrincipalName,
    served: &str,
    opts: KdcOptions,
    request_realm: &str,
    referral_count: usize,
) -> Result<TgsOutcome, Error> {
    match tgs_once(
        kdc,
        tgt,
        sname.clone(),
        served,
        opts.clone(),
        &[],
        None,
        None,
    ) {
        Ok(out) => Ok(out),
        Err(e @ Error::KrbError { .. }) => match tgs_try_fallback(
            referral_count,
            !request_realm.is_empty(),
            sname.name_string.len(),
        ) {
            TgsFallback::NonReferral => tgs_once(
                kdc,
                tgt,
                sname.clone(),
                served,
                tgs_non_referral_options(opts),
                &[],
                None,
                None,
            ),
            TgsFallback::HostRealmUnknown => Err(Error::ReplyMismatch("host realm unknown".into())),
            TgsFallback::KeepError | TgsFallback::HostRealm => Err(e),
        },
        Err(e) => Err(e),
    }
}

/// MIT `fwd_tgt.c:147-153` `flags2options | KDC_OPT_FORWARDED`.
/// `forwardable == false` clears `FORWARDABLE` like `fwd_tgt.c:152-153`.
#[must_use]
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

    #[test]
    fn closer_hop_dest_first_then_capaths() {
        let path = ["A.TEST".into(), "B.TEST".into(), "C.TEST".into()];
        assert_eq!(closer_hop(&path, "A.TEST", "C.TEST"), Some("B.TEST"));
        assert_eq!(closer_hop(&path, "A.TEST", "B.TEST"), None);
        assert_eq!(closer_hop(&path, "B.TEST", "C.TEST"), None);
        let direct = ["A.TEST".into(), "C.TEST".into()];
        assert_eq!(closer_hop(&direct, "A.TEST", "C.TEST"), None);
    }

    fn tgt_with_proxiable(on: bool) -> AsOutcome {
        let out = outcome(
            "KERBER.TEST",
            PrincipalName::krbtgt("KERBER.TEST"),
            "KERBER.TEST",
        );
        AsOutcome {
            ticket: out.ticket,
            enc_part: EncKdcRepPart {
                flags: TicketFlags::none().with_bit(flag_bit::PROXIABLE, on),
                ..out.enc_part
            },
            client_key: session(),
            session_key: session(),
            cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
            crealm: ascii("KERBER.TEST"),
            fast_avail: false,
            used_fast: false,
            pa_type: None,
        }
    }

    #[test]
    fn tgs_options_copy_proxiable_from_tgt() {
        let with_p = tgs_kdc_options(&tgt_with_proxiable(true));
        assert!(with_p.bit(flag_bit::PROXIABLE));
        assert!(with_p.bit(flag_bit::FORWARDABLE));
        let without = tgs_kdc_options(&tgt_with_proxiable(false));
        assert!(!without.bit(flag_bit::PROXIABLE));
    }

    #[test]
    fn chase_step_start_realm_referral_is_reply_mismatch() {
        let want = PrincipalName::krbtgt("C.TEST");
        let back = PrincipalName::krbtgt("A.TEST");
        let out = outcome("A.TEST", back, "A.TEST");
        let mut seen = vec!["A.TEST".into()];
        let err = chase_step("A.TEST", &mut seen, &want, "B.TEST", &out).unwrap_err();
        match err {
            Error::ReplyMismatch(s) => assert!(s.contains("start realm"), "{s}"),
            other => panic!("expected ReplyMismatch start realm, got {other:?}"),
        }
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
