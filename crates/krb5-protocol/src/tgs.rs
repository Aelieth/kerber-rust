//! TGS-REQ / TGS-REP using an existing TGT.
//!
//! Every request is FAST-armored with the subkey armor key. A reply that
//! carries PA-FX-FAST is not accepted until its finished checksum
//! verifies, and its reply key is the strengthened subkey. A reply
//! without PA-FX-FAST is accepted and decrypted under the subkey alone.
//! MIT `krb5int_decode_tgs_rep` (`decode_kdc.c:64-67`): a TGS-REP without PA-FX-FAST is
//! accepted the same way, its `KRB5_ERR_FAST_REQUIRED` ignored.

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
    /// The reply's client realm (`crealm`).
    pub crealm: krb5_types::Realm,
    /// The reply's client name (`cname`): an S4U2Proxy caller checks it against the evidence
    /// ticket's client.
    pub cname: PrincipalName,
}

/// What a `krb5_get_credentials` caller asks for beyond the server name: the `KRB5_GC_*` options
/// that become KDC options of the service requests, and the extras of `in_creds`.
/// MIT `krb5_tkt_creds_init` (`get_creds.c:1107-1113`): `KRB5_GC_CANONICALIZE`,
/// `KRB5_GC_FORWARDABLE` and `KRB5_GC_NO_TRANSIT_CHECK` are the requested KDC options.
/// MIT `make_request_for_service` (`get_creds.c:358-363`): service requests carry them, and a
/// second ticket adds `ENC_TKT_IN_SKEY`.
#[derive(Clone, Debug, Default)]
pub struct TgsCredsOptions {
    /// `KRB5_GC_CANONICALIZE` (`kvno -C`): `canonicalize` on the non-referral retry too.
    pub canonicalize: bool,
    /// `KRB5_GC_FORWARDABLE`.
    pub forwardable: bool,
    /// `in_creds.keyblock.enctype` (`kvno -e`): the one enctype the service requests ask for.
    pub enctype: Option<i32>,
    /// `in_creds.second_ticket` (`kvno --u2u`): sent with `ENC_TKT_IN_SKEY` on the service
    /// requests.
    pub second_ticket: Option<Ticket>,
    /// `KRB5_GC_NO_TRANSIT_CHECK`, a gate-only knob of a `test-hooks` build: the bit goes on the
    /// hop whose TGT is `krbtgt/<service realm>` only, so a default MIT KDC does not refuse the
    /// first hop.
    #[cfg(feature = "test-hooks")]
    pub no_transit_check: bool,
}

/// Request a service ticket with a TGT from [`AsOutcome`].
///
/// # Errors
///
/// [`Error::Io`] when a KDC cannot be reached or the nonce or subkey cannot be drawn;
/// [`Error::KrbError`] with the KDC's code when it refuses a request (the FX-ERROR's once the
/// FAST envelope unwraps, `PREAUTH_FAILED` when that holds none); [`Error::NonceMismatch`] for
/// another nonce; [`Error::ReplyMismatch`] when a reply fails a check against its request (FAST
/// finished message or strengthen key, client, server, times), `realm` is not a GeneralString,
/// or the referral chase returns to the start realm, loops, or finds no host realm;
/// [`Error::Referral`] when a referral names no new realm or the chase passes ten hops;
/// [`Error::TruncatedReply`] for an empty reply and [`Error::UnexpectedPdu`] for one that is
/// neither TGS-REP nor KRB-ERROR; [`Error::Asn1`] when a message does not encode or decode;
/// [`Error::Crypto`] when a checksum, encryption, decryption, or key derivation fails, or a key
/// in the reply is unusable.
pub fn tgs_exchange(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
) -> Result<TgsOutcome, Error> {
    Ok(tgs_exchange_path(kdc, tgt, sname, realm, &TgsCredsOptions::default())?.0)
}

/// One TGS-REQ; `realm` is `body.realm`. No capaths/referral chase.
///
/// Gate-only (`krb5-kvno --body-realm`, a `test-hooks` build): MIT clients never send a foreign
/// `body.realm`.
///
/// # Errors
///
/// [`Error::Io`] when the KDC cannot be reached or the nonce or subkey cannot be drawn;
/// [`Error::KrbError`] with the KDC's code when it refuses the request (the FX-ERROR's once the
/// FAST envelope unwraps, `PREAUTH_FAILED` when that holds none); [`Error::NonceMismatch`] for
/// another nonce; [`Error::ReplyMismatch`] when the reply fails a check against the request (FAST
/// finished message or strengthen key, client, server, or times unless `renew`) or `realm` is
/// not a GeneralString; [`Error::TruncatedReply`] for an empty reply and [`Error::UnexpectedPdu`]
/// for one that is neither TGS-REP nor KRB-ERROR; [`Error::Asn1`] when a message does not encode
/// or decode; [`Error::Crypto`] when a checksum, encryption, decryption, or key derivation fails,
/// or a key in the reply is unusable.
#[cfg(feature = "test-hooks")]
pub fn tgs_exchange_once(
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
    tgs_once(kdc, tgt, TgsRequest::new(sname, realm, opts))
}

/// Like [`tgs_exchange`], with the caller's [`TgsCredsOptions`], also returning the asked-for
/// path TGTs to cache.
///
/// # Errors
///
/// [`Error::Io`] when a KDC cannot be reached or the nonce or subkey cannot be drawn;
/// [`Error::KrbError`] with the KDC's code when it refuses a request (the FX-ERROR's once the
/// FAST envelope unwraps, `PREAUTH_FAILED` when that holds none); [`Error::NonceMismatch`] for
/// another nonce; [`Error::ReplyMismatch`] when a reply fails a check against its request (FAST
/// finished message or strengthen key, client, server, times), `realm` is not a GeneralString,
/// or the referral chase returns to the start realm, loops, or finds no host realm;
/// [`Error::Referral`] when a referral names no new realm or the chase passes ten hops;
/// [`Error::TruncatedReply`] for an empty reply and [`Error::UnexpectedPdu`] for one that is
/// neither TGS-REP nor KRB-ERROR; [`Error::Asn1`] when a message does not encode or decode;
/// [`Error::Crypto`] when a checksum, encryption, decryption, or key derivation fails, or a key
/// in the reply is unusable.
#[allow(clippy::needless_pass_by_value)] // `tgt` is cloned into the path-TGT vec
pub fn tgs_exchange_path(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
    opts: &TgsCredsOptions,
) -> Result<(TgsOutcome, Vec<AsOutcome>), Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let _g = krb5_log::enter_correlation(correlation_id.clone());
    let started = Instant::now();
    let result = tgs_inner(kdc, tgt, &sname, realm, opts);
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
/// [`Error::Io`] when the KDC cannot be reached or the nonce or subkey cannot be drawn;
/// [`Error::KrbError`] with the KDC's code when it refuses the request (the FX-ERROR's once the
/// FAST envelope unwraps, `PREAUTH_FAILED` when that holds none); [`Error::NonceMismatch`] for
/// another nonce; [`Error::ReplyMismatch`] when the reply fails a check against the request (FAST
/// finished message or strengthen key, client, server, or times) or the TGT's client realm is not
/// a GeneralString; [`Error::TruncatedReply`] for an empty reply and [`Error::UnexpectedPdu`] for
/// one that is neither TGS-REP nor KRB-ERROR; [`Error::Asn1`] when a message does not encode or
/// decode; [`Error::Crypto`] when a checksum, encryption, decryption, or key derivation fails, or
/// a key in the reply is unusable.
pub fn tgs_forward(kdc: &KdcAddr, tgt: &AsOutcome) -> Result<TgsOutcome, Error> {
    let realm = String::from_utf8_lossy(tgt.crealm.as_bytes()).into_owned();
    let sname = PrincipalName::krbtgt(&realm);
    let opts = tgs_forward_options(&tgt.enc_part.flags, true);
    tgs_once(kdc, tgt, TgsRequest::new(sname, &realm, opts))
}

/// TGS-REQ with KDC option `renew` for `kinit -R`: the presented ticket's own server, at its realm.
/// MIT `get_new_creds` (`val_renew.c:47-74`): the cached credential is presented to ask for its
/// server again, with its common flags.
///
/// # Errors
///
/// [`Error::Io`] when the KDC cannot be reached or the nonce or subkey cannot be drawn;
/// [`Error::KrbError`] with the KDC's code when it refuses the request (the FX-ERROR's once the
/// FAST envelope unwraps, `PREAUTH_FAILED` when that holds none); [`Error::NonceMismatch`] for
/// another nonce; [`Error::ReplyMismatch`] when the reply fails a check against the request (FAST
/// finished message or strengthen key, client, or server) or the TGT's client realm is not a
/// GeneralString; [`Error::TruncatedReply`] for an empty reply and [`Error::UnexpectedPdu`] for
/// one that is neither TGS-REP nor KRB-ERROR; [`Error::Asn1`] when a message does not encode or
/// decode; [`Error::Crypto`] when a checksum, encryption, decryption, or key derivation fails, or
/// a key in the reply is unusable.
pub fn tgs_renew(kdc: &KdcAddr, tgt: &AsOutcome) -> Result<TgsOutcome, Error> {
    let realm = String::from_utf8_lossy(tgt.ticket.realm.as_bytes()).into_owned();
    let sname = tgt.ticket.sname.clone();
    let opts = tgs_renew_options(&tgt.enc_part.flags);
    tgs_once(kdc, tgt, TgsRequest::new(sname, &realm, opts))
}

/// MIT `KDC_TKT_COMMON_MASK` (`krb5.hin:1659-1659`): `0x54800000` = FORWARDABLE | PROXIABLE |
/// MAY_POSTDATE | RENEWABLE.
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

/// MIT `get_new_creds` (`val_renew.c:62-67`): `KDC_OPT_RENEW` plus
/// `old_creds.ticket_flags & KDC_TKT_COMMON_MASK`. No `CANONICALIZE` (`get_creds.c` sets that
/// only on the referral walk).
#[must_use]
pub fn tgs_renew_options(flags: &krb5_types::TicketFlags) -> KdcOptions {
    tkt_common_from_flags(flags).with_bit(flag_bit::RENEW, true)
}

/// TGS-REQ with PA-S4U-X509-USER (130) and PA-FOR-USER (129) like MIT
/// `krb5_get_self_cred_from_kdc`.
/// MIT `krb5_get_self_cred_from_kdc` (`s4u_creds.c:517-567`): 130 is filled after the TGS
/// subkey exists (ku 26).
/// MIT `make_tgs_outer_padata` (`fast.c:227-250`): FAST outer padata duplicates both.
/// The KDC enforces that `sname` is the TGT client; this helper does not.
///
/// # Errors
///
/// [`Error::Io`] when the KDC cannot be reached or the nonce or subkey cannot be drawn;
/// [`Error::KrbError`] with the KDC's code when it refuses the request (the FX-ERROR's once the
/// FAST envelope unwraps, `PREAUTH_FAILED` when that holds none), or `INAPP_CKSUM` for an unkeyed
/// S4U reply checksum under a newer etype; [`Error::NonceMismatch`] for another nonce;
/// [`Error::ReplyMismatch`] when the reply fails a check against the request (FAST finished
/// message or strengthen key, client, server, times, the PA-S4U-X509-USER reply, or a KDC that
/// ignored PA-FOR-USER) or `realm` or `for_realm` is not a GeneralString;
/// [`Error::TruncatedReply`] for an empty reply and [`Error::UnexpectedPdu`] for one that is
/// neither TGS-REP nor KRB-ERROR; [`Error::Asn1`] when a message does not encode or decode;
/// [`Error::Crypto`] when a checksum, encryption, decryption, or key derivation fails, or a key
/// in the reply is unusable.
pub fn tgs_s4u(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: PrincipalName,
    realm: &str,
    for_user: &PrincipalName,
    for_realm: &str,
) -> Result<TgsOutcome, Error> {
    // MIT `krb5_get_self_cred_from_kdc` (`s4u_creds.c:559-562`): canonicalize plus the TGT's
    // common flags.
    let opts = tgs_request_options(
        tgt,
        KdcOptions::none().with_bit(flag_bit::CANONICALIZE, true),
    );
    let mut req = TgsRequest::new(sname, realm, opts);
    req.s4u = Some((for_user, for_realm));
    tgs_once(kdc, tgt, req)
}

/// One TGS-REQ for `sname` at `realm` with `ENC_TKT_IN_SKEY` and `stkt` as the second ticket,
/// with no referral chase: the gates' `krb5-kvno --u2u … --body-realm` request. `kvno --u2u` as
/// MIT's goes through [`tgs_exchange_path`] with [`TgsCredsOptions::second_ticket`].
///
/// # Errors
///
/// [`Error::Io`] when the KDC cannot be reached or the nonce or subkey cannot be drawn;
/// [`Error::KrbError`] with the KDC's code when it refuses the request (the FX-ERROR's once the
/// FAST envelope unwraps, `PREAUTH_FAILED` when that holds none); [`Error::NonceMismatch`] for
/// another nonce; [`Error::ReplyMismatch`] when the reply fails a check against the request (FAST
/// finished message or strengthen key, client, server, or times) or `realm` is not a
/// GeneralString; [`Error::TruncatedReply`] for an empty reply and [`Error::UnexpectedPdu`] for
/// one that is neither TGS-REP nor KRB-ERROR; [`Error::Asn1`] when a message does not encode or
/// decode; [`Error::Crypto`] when a checksum, encryption, decryption, or key derivation fails, or
/// a key in the reply is unusable.
pub fn tgs_u2u(
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
    tgs_once(kdc, tgt, req)
}

/// MIT `make_request` (`get_creds.c:286-292`): a request's KDC options are the caller's `extra`
/// plus `FLAGS2OPTS` of the TGT it presents, its forwardable, proxiable, may-postdate and
/// renewable flags (`KDC_TKT_COMMON_MASK`).
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

/// MIT `make_request_for_service` (`get_creds.c:358-363`): the extra options of a service request,
/// the caller's `KRB5_GC_*` ones and `ENC_TKT_IN_SKEY` for a second ticket; `canonicalize` is added
/// for a referral request.
fn tgs_service_extra(opts: &TgsCredsOptions) -> KdcOptions {
    KdcOptions::none()
        .with_bit(flag_bit::CANONICALIZE, opts.canonicalize)
        .with_bit(flag_bit::FORWARDABLE, opts.forwardable)
        .with_bit(flag_bit::ENC_TKT_IN_SKEY, opts.second_ticket.is_some())
}

fn tgs_inner(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    sname: &PrincipalName,
    realm: &str,
    creds_opts: &TgsCredsOptions,
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
        let extra = tgs_service_extra(creds_opts);
        #[cfg(feature = "test-hooks")]
        let extra = extra.with_bit(
            flag_bit::DISABLE_TRANSITED_CHECK,
            creds_opts.no_transit_check && cur_tgt.ticket.sname.is_krbtgt_for(realm),
        );
        let out = tgs_service_once(
            &cur_kdc,
            &cur_tgt,
            ServiceHop {
                sname,
                served: &served,
                extra,
                request_realm: realm,
                referral_count: seen.len(),
                creds_opts,
            },
        )?;
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
        // MIT `make_request_for_tgt` (`get_creds.c:341-343`): a TGT request has no extra options.
        let opts = tgs_request_options(&cur_tgt, KdcOptions::none());
        match tgs_once(
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

/// MIT `krb5int_decode_tgs_rep` (`decode_kdc.c:64-67`): missing PA-FX-FAST is
/// `KRB5_ERR_FAST_REQUIRED` then ignored. A present FAST envelope still requires finished +
/// strengthen. The returned padata is FAST-inner when armed (`fast.c` swap), else the TGS-REP
/// list — `verify_s4u2self_reply` reads 130 from here.
/// MIT `krb5int_fast_process_response` (`fast.c:548-551`): when armed, the reply's `crealm` /
/// `cname` are replaced by the finished message's client before `process_tgs_reply` compares
/// them.
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
        event = krb5_log::events::CLIENT_TGS,
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

/// One TGS-REQ as [`tgs_once`] sends it.
struct TgsRequest<'a> {
    sname: PrincipalName,
    /// `body.realm`.
    realm: &'a str,
    kdc_options: KdcOptions,
    extra_padata: Vec<PaData>,
    additional_tickets: Option<Vec<Ticket>>,
    /// S4U2Self user and realm (PA-S4U-X509-USER and PA-FOR-USER).
    s4u: Option<(&'a PrincipalName, &'a str)>,
    /// The one enctype asked for, else the configured TGS list.
    enctype: Option<i32>,
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
        }
    }
}

/// MIT `krb5int_fast_process_response` (`fast.c:534-550`): a FAST reply with no finished
/// message, or a finished checksum that fails, is not accepted. An outer error whose FAST
/// envelope does not unwrap stays the fatal answer, and nothing inside that envelope is trusted.
/// MIT `k5_make_tgs_req` (`send_tgs.c:155-160`): `till` is the TGT's end time, and no `rtime` is
/// asked for.
fn tgs_once(kdc: &KdcAddr, tgt: &AsOutcome, req: TgsRequest<'_>) -> Result<TgsOutcome, Error> {
    let TgsRequest {
        sname,
        realm,
        kdc_options,
        extra_padata,
        additional_tickets: extra_tickets,
        s4u,
        enctype,
    } = req;
    let nonce = random_nonce31()?;
    let till = KerberosTime(tgt.enc_part.endtime.0);
    let etypes = enctype.map_or_else(|| crate::as_ex::conf_etypes(true), |e| vec![e]);

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
        // MIT `krb5int_process_tgs_reply` (`gc_via_tkt.c:190-194`): `krb5int_fast_process_error`
        // under the armor key — the authenticated FX-ERROR inside PA-FX-FAST replaces the outer
        // error; an envelope that is missing or does not unwrap leaves the outer error as the
        // (fatal) answer. Same rule as the AS path (`as_ex.rs` `fast_error_material`).
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
    // MIT `krb5_kdc_rep_decrypt_proc` (`kdc_rep_dc.c:69-69`): decodes the TGS-REP enc-part with
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

/// S4U2Proxy TGS-REQ: `CNAME_IN_ADDL_TKT`, the evidence ticket, and PA-PAC-OPTIONS RBCD.
/// MIT `get_proxy_cred_from_kdc` (`s4u_creds.c:1013-1031`): the `k5_get_proxy_cred_from_kdc`
/// step that adds PA-PAC-OPTIONS RBCD and requests with `CNAME_IN_ADDL_TKT`.
/// MIT `make_tgs_outer_padata` (`fast.c:227-250`): FAST outer padata duplicates 167.
///
/// # Errors
///
/// [`Error::Io`] when the KDC cannot be reached or the nonce or subkey cannot be drawn;
/// [`Error::KrbError`] with the KDC's code when it refuses the request (the FX-ERROR's once the
/// FAST envelope unwraps, `PREAUTH_FAILED` when that holds none); [`Error::NonceMismatch`] for
/// another nonce; [`Error::ReplyMismatch`] when the reply fails a check against the request (FAST
/// finished message or strengthen key, client, server, or times) or `realm` is not a
/// GeneralString; [`Error::TruncatedReply`] for an empty reply and [`Error::UnexpectedPdu`] for
/// one that is neither TGS-REP nor KRB-ERROR; [`Error::Asn1`] when a message (PA-PAC-OPTIONS
/// included) does not encode or decode; [`Error::Crypto`] when a checksum, encryption,
/// decryption, or key derivation fails, or a key in the reply is unusable.
pub fn tgs_s4u2proxy(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    target: PrincipalName,
    realm: &str,
    evidence: Ticket,
) -> Result<TgsOutcome, Error> {
    // MIT `get_proxy_cred_from_kdc` (`s4u_creds.c:1027-1028`): canonicalize and
    // cname-in-addl-tkt plus the TGT's common flags.
    let opts = tgs_request_options(
        tgt,
        KdcOptions::none()
            .with_bit(flag_bit::CNAME_IN_ADDL_TKT, true)
            .with_bit(flag_bit::CANONICALIZE, true),
    );
    let mut req = TgsRequest::new(target, realm, opts);
    req.extra_padata = vec![crate::pa_pac_options(true)?];
    req.additional_tickets = Some(vec![evidence]);
    tgs_once(kdc, tgt, req)
}

/// TGS-REQ with KDC option `validate` for `kinit -v`: the presented ticket's own server, at its
/// realm.
///
/// # Errors
///
/// [`Error::Io`] when the KDC cannot be reached or the nonce or subkey cannot be drawn;
/// [`Error::KrbError`] with the KDC's code when it refuses the request (the FX-ERROR's once the
/// FAST envelope unwraps, `PREAUTH_FAILED` when that holds none); [`Error::NonceMismatch`] for
/// another nonce; [`Error::ReplyMismatch`] when the reply fails a check against the request (FAST
/// finished message or strengthen key, client, or server) or the TGT's client realm is not a
/// GeneralString; [`Error::TruncatedReply`] for an empty reply and [`Error::UnexpectedPdu`] for
/// one that is neither TGS-REP nor KRB-ERROR; [`Error::Asn1`] when a message does not encode or
/// decode; [`Error::Crypto`] when a checksum, encryption, decryption, or key derivation fails, or
/// a key in the reply is unusable.
pub fn tgs_validate(kdc: &KdcAddr, tgt: &AsOutcome) -> Result<TgsOutcome, Error> {
    let realm = String::from_utf8_lossy(tgt.ticket.realm.as_bytes()).into_owned();
    let sname = tgt.ticket.sname.clone();
    let opts = tgs_validate_options(&tgt.enc_part.flags);
    tgs_once(kdc, tgt, TgsRequest::new(sname, &realm, opts))
}

/// MIT `get_new_creds` (`val_renew.c:62-67`): `KDC_OPT_VALIDATE` plus
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

/// MIT `krb5int_process_tgs_reply` (`gc_via_tkt.c:257-270`): the client half of the TGS-REP checks.
///
/// S4U2Self final hop: reply client == requested server means the KDC
/// ignored PA-FOR-USER (`KRB5KDC_ERR_PADATA_TYPE_NOSUPP`). Otherwise,
/// unless this is a final S4U2Proxy hop, reply client must match the
/// TGT client (`KRB5_KDCREP_MODIFIED`). Name-type is ignored
/// (`krb5_principal_compare`).
///
/// # Errors
///
/// [`Error::ReplyMismatch`] when a final S4U2Self reply names the requested server as its client
/// (`KRB5KDC_ERR_PADATA_TYPE_NOSUPP`), or, on any hop but a final S4U2Self or S4U2Proxy one, the
/// reply client is not the TGT client (`KRB5_KDCREP_MODIFIED`).
#[expect(clippy::too_many_arguments, reason = "name and realm stay separate")]
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

/// MIT `check_reply_server` (`gc_via_tkt.c:108-110`): ticket server equals enc-part server
/// (name and realm; name-type ignored).
///
/// # Errors
///
/// [`Error::ReplyMismatch`] (`KRB5_KDCREP_MODIFIED`) when the ticket server and the enc-part
/// server differ in name or realm.
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

/// MIT `krb5int_process_tgs_reply` (`gc_via_tkt.c:278-297`): the request-time half of
/// `process_tgs_reply`.
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
/// [`Error::ReplyMismatch`] (`KRB5_KDCREP_MODIFIED`) when `endtime` is after `till`, `renew_till`
/// is after the bound `opts` set, or a POSTDATED starttime is not `from`.
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

/// MIT `tgt_is_local_realm` (`gc_via_tkt.c:139-147`): true when the TGT is
/// `krbtgt/CREALM@CREALM` for the client's realm.
fn tgt_is_local_realm(tgt: &AsOutcome) -> bool {
    let crealm = String::from_utf8_lossy(tgt.crealm.as_bytes());
    tgt.ticket.sname.is_krbtgt_for(crealm.as_ref())
        && tgt.ticket.realm.as_bytes() == tgt.crealm.as_bytes()
}

/// MIT `krb5int_process_tgs_reply` (`gc_via_tkt.c:247-252`): drop `ok-as-delegate` from a
/// foreign TGT that itself lacks the flag.
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

/// After the first referral-style TGS error, MIT `try_fallback`.
/// MIT `try_fallback` (`get_creds.c:503-543`): only an error from the first referral request
/// falls back, to a non-referral request or to the fallback host realm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TgsFallback {
    /// Later referral hop: keep the KDC error (`referral_count > 1`).
    KeepError,
    /// Specified server realm: retry without `CANONICALIZE`.
    NonReferral,
    /// Referral realm and fewer than two name components.
    HostRealmUnknown,
    /// Referral realm + hostname: MIT `krb5_get_fallback_host_realm`.
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

/// One service request of the referral walk, as [`tgs_service_once`] sends it.
struct ServiceHop<'a> {
    sname: &'a PrincipalName,
    /// Realm of the presented TGT (`body.realm`).
    served: &'a str,
    /// The caller's extra options ([`tgs_service_extra`]).
    extra: KdcOptions,
    /// Realm of the requested server; empty for a referral (host-based) name.
    request_realm: &'a str,
    referral_count: usize,
    creds_opts: &'a TgsCredsOptions,
}

/// First referral TGS, then `try_fallback` on a KDC error.
/// MIT `make_request_for_service` (`get_creds.c:365-367`): the referral request adds
/// `canonicalize` to the caller's options; the non-referral retry sends the caller's alone.
fn tgs_service_once(
    kdc: &KdcAddr,
    tgt: &AsOutcome,
    hop: ServiceHop<'_>,
) -> Result<TgsOutcome, Error> {
    let ServiceHop {
        sname,
        served,
        extra,
        request_realm,
        referral_count,
        creds_opts,
    } = hop;
    let request = |kdc_options: KdcOptions| {
        let mut req = TgsRequest::new(sname.clone(), served, kdc_options);
        req.additional_tickets = creds_opts.second_ticket.clone().map(|t| vec![t]);
        req.enctype = creds_opts.enctype;
        req
    };
    let referral = tgs_request_options(tgt, extra.clone().with_bit(flag_bit::CANONICALIZE, true));
    match tgs_once(kdc, tgt, request(referral)) {
        Ok(out) => Ok(out),
        Err(e @ Error::KrbError { .. }) => match tgs_try_fallback(
            referral_count,
            !request_realm.is_empty(),
            sname.name_string.len(),
        ) {
            TgsFallback::NonReferral => {
                tgs_once(kdc, tgt, request(tgs_request_options(tgt, extra)))
            }
            TgsFallback::HostRealmUnknown => Err(Error::ReplyMismatch("host realm unknown".into())),
            TgsFallback::KeepError | TgsFallback::HostRealm => Err(e),
        },
        Err(e) => Err(e),
    }
}

/// MIT `krb5_fwd_tgt_creds` (`fwd_tgt.c:147-153`): `flags2options | KDC_OPT_FORWARDED`.
/// MIT `krb5_fwd_tgt_creds` (`fwd_tgt.c:152-153`): `forwardable == false` clears `FORWARDABLE`.
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
        }
    }

    /// Live MIT 1.22.2 `kvno`: a FRIA TGT sends 0x40810000, an FIA
    /// one 0x40010000, an RIA one (`kinit -F`) 0x00810000; `--u2u` adds 0x08.
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
