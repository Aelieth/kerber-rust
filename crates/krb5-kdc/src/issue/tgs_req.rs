//! TGS-REQ (`do_tgs_req.c`): `gather_tgs_req_info`, `check_tgs_req`
//! (flags/times/kdcpolicy tail `:900-945`), `tgs_issue_ticket`,
//! referral / alternate TGS, and the second-ticket helpers.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt, krb_fx_cf2};
use krb5_protocol::{ReplayCache, ReplayKey};
use krb5_types::{
    EncTicketPart, EncryptedData, HostAddress, HostAddresses, KdcReqBody, KerberosTime,
    OctetString, PaData, PrincipalName, TgsRep, TgsReq, TicketFlags, TransitedEncoding, err,
    flag_bit, ku, pa,
};

use super::as_req::{ANONYMOUS_REALM, anonymous_principal_name};
use super::fast_util::{check_fast_options, fast_hides_client, wrap_as_fast};
use super::kdc_util::{
    HeaderTgt, attr, check_anon, decrypt_presented_tgt, find_server_key, get_ticket_flags,
    include_pac_for_reply, kdc_get_ticket_endtime, kdc_get_ticket_renewtime, kdc_req_body_der, ks,
    process_tgs_header, s4u2self_forwardable, select_session_keytype, utf8_realm,
};
use super::reply::{
    MintTicket, enc_rep_part, encode_enc_kdc_rep_part, mint_ticket, return_enc_padata,
};
use super::tgs_policy::{
    check_tgs_constraints_skeleton, check_tgs_policy_flags, check_tgs_s4u2self, check_tgs_u2u,
};
use crate::ad::{
    SecondTicket, check_indicators, check_s4u2proxy_policy, check_tgs_s4u2proxy,
    get_auth_indicators, handle_authdata, make_s4u2self_rep, process_s4u2self_req, rbcd_pac_client,
    update_delegation_info, with_status,
};
use crate::error::Error;
use crate::kdb::{PrincipalRead, lookup_principal_id};
use crate::plugins::{apply_policy_times, current_policy};
use crate::preauth::{FastOk, fast_finished, find_pa, proto, unwrap_fast_tgs, wrap_fast_rep};
use crate::status;
use crate::store::{
    KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_SVR, KDB_NO_AUTH_DATA_REQUIRED, Principal, random_key,
};

/// Issued TGS-REP plus the service session key.
#[derive(Debug)]
pub struct IssuedTgs {
    /// Wire TGS-REP.
    pub rep: TgsRep,
    /// Service session key.
    pub session_key: ProtocolKey,
}

/// Issue a TGS-REP for `req` using the TGT in PA-TGS-REQ.
///
/// # Errors
///
/// Bad authenticator, unknown server, or crypto/DER failures.
pub fn issue_tgs(store: &dyn PrincipalRead, req: &TgsReq) -> Result<IssuedTgs, Error> {
    issue_tgs_from(store, req, None, None)
}

pub(super) fn issue_tgs_from(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    raw: Option<&[u8]>,
    sender: Option<&HostAddress>,
) -> Result<IssuedTgs, Error> {
    let outer = &req.0.req_body;
    let encoded_body;
    let body_der: &[u8] = if let Some(slice) = raw.and_then(kdc_req_body_der) {
        slice
    } else {
        encoded_body = encode(outer)?;
        &encoded_body
    };
    // MIT kdc_process_tgs_req (PROCESS_TGS) before kdc_find_fast.
    if req.0.msg_type != krb5_types::KdcReq::MSG_TGS_REQ {
        return Err(proto(err::GENERIC, status::UNKNOWN_REASON));
    }
    let pa_tgs = extract_pa_tgs(req.0.padata.as_deref())
        .ok_or_else(|| proto(err::PADATA_TYPE_NOSUPP, status::PROCESS_TGS))?;
    let header = process_tgs_header(store, pa_tgs.as_ref(), body_der, sender)?;
    let tgs_fast = unwrap_fast_tgs(
        store,
        req.0.padata.as_deref(),
        pa_tgs.as_ref(),
        header.authenticator.subkey.as_ref(),
        &header.session,
    )?;
    let inner_owned: Option<KdcReqBody> = match tgs_fast.as_ref() {
        Some(f) => Some(decode(&f.inner_body)?),
        None => None,
    };
    let body = inner_owned.as_ref().unwrap_or(outer);
    issue_tgs_body(store, req, raw, body, tgs_fast.as_ref(), header)
        .map_err(|e| wrap_as_fast(store, tgs_fast.as_ref(), e, body))
}

/// MIT `gather_tgs_req_info` (`do_tgs_req.c:592`) carried state. Data only.
struct TgsGather<'a> {
    tgs_padata: Option<&'a [PaData]>,
    ap: krb5_types::ApReq,
    enc_tkt: EncTicketPart,
    tgt_session: ProtocolKey,
    authenticator: krb5_types::Authenticator,
    header_realm: String,
    renew: bool,
    validate: bool,
    sname: PrincipalName,
    req_realm: String,
    header_pac: Option<Vec<u8>>,
    server: Principal,
}

/// MIT `check_tgs_req` (`do_tgs_req.c:857`) carried state. Data only.
struct TgsChecked<'a> {
    tgs_padata: Option<&'a [PaData]>,
    ap: krb5_types::ApReq,
    enc_tkt: EncTicketPart,
    tgt_session: ProtocolKey,
    authenticator: krb5_types::Authenticator,
    renew: bool,
    validate: bool,
    sname: PrincipalName,
    server: Principal,
    auth_indicators: Vec<String>,
    s4u2self: bool,
    s4u_local: Option<Principal>,
    s4u_referral: bool,
    session_etype: EncryptionType,
    set_transited_flag: bool,
    stkt: Option<SecondTicket>,
    subject_authtime: KerberosTime,
    s4u2proxy: bool,
    is_crossrealm: bool,
    is_referral: bool,
    s4u_subject: Option<(PrincipalName, String)>,
    s4u_x509: Option<krb5_types::s4u::PaS4uX509User>,
    evidence_logon: Option<Vec<u8>>,
    subject_pac: Option<Vec<u8>>,
    ticket_cname: PrincipalName,
    ticket_crealm: String,
    tkt_key: ProtocolKey,
    tkt_kvno: u32,
    tkt_etype: EncryptionType,
    transited: TransitedEncoding,
}

/// MIT `compute_ticket_times` (`do_tgs_req.c:812`) carried state. Data only.
struct TgsTimes<'a> {
    tgs_padata: Option<&'a [PaData]>,
    ap: krb5_types::ApReq,
    enc_tkt: EncTicketPart,
    tgt_session: ProtocolKey,
    authenticator: krb5_types::Authenticator,
    renew: bool,
    validate: bool,
    sname: PrincipalName,
    server: Principal,
    auth_indicators: Vec<String>,
    s4u2self: bool,
    stkt: Option<SecondTicket>,
    s4u2proxy: bool,
    is_crossrealm: bool,
    is_referral: bool,
    s4u_subject: Option<(PrincipalName, String)>,
    s4u_x509: Option<krb5_types::s4u::PaS4uX509User>,
    evidence_logon: Option<Vec<u8>>,
    subject_pac: Option<Vec<u8>>,
    ticket_cname: PrincipalName,
    ticket_crealm: String,
    tkt_key: ProtocolKey,
    tkt_kvno: u32,
    tkt_etype: EncryptionType,
    transited: TransitedEncoding,
    session: ProtocolKey,
    authtime: KerberosTime,
    starttime: KerberosTime,
    end: KerberosTime,
    flags: TicketFlags,
    ticket_renew_till: Option<KerberosTime>,
}

fn issue_tgs_body(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    raw: Option<&[u8]>,
    body: &KdcReqBody,
    tgs_fast: Option<&FastOk>,
    header: HeaderTgt,
) -> Result<IssuedTgs, Error> {
    let g = gather_tgs_req_info(store, req, body, tgs_fast, header)?;
    let t = check_tgs_req(store, req, body, g)?;
    tgs_issue_ticket(store, req, raw, body, tgs_fast, t)
}

/// MIT `gather_tgs_req_info` through `search_sprinc` (`do_tgs_req.c:592-673`).
fn gather_tgs_req_info<'a>(
    store: &dyn PrincipalRead,
    req: &'a TgsReq,
    body: &KdcReqBody,
    tgs_fast: Option<&'a FastOk>,
    header: HeaderTgt,
) -> Result<TgsGather<'a>, Error> {
    if let Some(f) = tgs_fast {
        check_fast_options(&f.fast_options)?;
    }
    if body.kdc_options.unsupported_bits() != 0 {
        return Err(proto(err::BADOPTION, status::UNKNOWN_REASON));
    }
    let tgs_padata = if let Some(f) = tgs_fast {
        Some(f.inner_padata.as_slice())
    } else {
        req.0.padata.as_deref()
    };
    let HeaderTgt {
        ap,
        enc_tkt,
        tgt_key,
        session: tgt_session,
        authenticator,
        header_realm,
        header_server,
    } = header;
    let renew = body.kdc_options.bit(flag_bit::RENEW);
    let validate = body.kdc_options.bit(flag_bit::VALIDATE);
    if renew && validate {
        return Err(proto(err::BADOPTION, status::TICKET_NOT_RENEWABLE));
    }
    let rkey = ReplayKey {
        client: format!(
            "{}@{}",
            authenticator.cname.components_joined(),
            utf8_realm(&enc_tkt.crealm)?
        ),
        server: format!("krbtgt/{}@{}", store.realm(), store.realm()),
        ctime: authenticator.ctime.unix_seconds(),
        cusec: authenticator.cusec.get(),
        auth_hash: ReplayCache::hash_authenticator(ap.authenticator.cipher.as_ref()),
    };
    if store.tgs_replay().check_and_store(rkey) {
        return Err(proto(err::REPEAT, status::PROCESS_TGS));
    }
    let sname = body
        .sname
        .clone()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, status::NULL_SERVER))?;
    // MIT get_local_tgt requires krbtgt/<body.realm>@<body.realm> in the KDB
    // before search_sprinc. A single-realm KDC answers 60 GET_LOCAL_TGT.
    let req_realm = utf8_realm(&body.realm)?.to_owned();
    if req_realm != store.realm() {
        return Err(proto(err::GENERIC, status::GET_LOCAL_TGT));
    }
    let header_pac = crate::ad::get_verified_pac(
        store.policy(),
        &enc_tkt,
        &tgt_key,
        &header_server,
        store.fetch_krbtgt()?.as_ref(),
    )?;
    let server = search_sprinc(store, &sname, req_realm.as_str(), body)?;
    Ok(TgsGather {
        tgs_padata,
        ap,
        enc_tkt,
        tgt_session,
        authenticator,
        header_realm,
        renew,
        validate,
        sname,
        req_realm,
        header_pac,
        server,
    })
}

/// MIT `check_tgs_req` (`do_tgs_req.c:857`) plus gather's tail
/// (`do_tgs_req.c:692-804`: S4U2Self, `decrypt_2ndtkt`, `RBCD_PAC_PRINC`,
/// auth indicators, transited); Rust runs the constraints skeleton first.
fn check_tgs_req<'a>(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    body: &KdcReqBody,
    g: TgsGather<'a>,
) -> Result<TgsTimes<'a>, Error> {
    let TgsGather {
        tgs_padata,
        ap,
        enc_tkt,
        tgt_session,
        authenticator,
        header_realm,
        renew,
        validate,
        sname,
        req_realm,
        header_pac,
        mut server,
    } = g;
    check_tgs_constraints_skeleton(
        body,
        &ap.ticket.sname,
        header_realm.as_str(),
        &enc_tkt,
        &sname,
        req_realm.as_str(),
        renew,
        validate,
    )?;
    let header_client = store.fetch_name(&enc_tkt.cname)?;
    let mut s4u_local = None;
    let mut ticket_cname = enc_tkt.cname.clone();
    let mut ticket_crealm = utf8_realm(&enc_tkt.crealm)?.to_owned();
    let mut evidence_logon = None;
    let mut s4u2self = false;
    let mut s4u_x509 = None;
    let mut s4u_referral = false;
    let mut s4u2proxy = false;
    let mut s4u_subject: Option<(PrincipalName, String)> = None;
    let mut subject_authtime = enc_tkt.authtime.clone();
    let mut subject_pac = header_pac.clone();
    if let Some(s4u) = process_s4u2self_req(
        store,
        &tgt_session,
        authenticator.subkey.as_ref(),
        tgs_padata,
        body.nonce,
    )? {
        let header_cross = utf8_realm(&ap.ticket.realm)? != store.realm();
        let is_referral = tgs_issuing_referral(&sname, req_realm.as_str(), &server);
        let is_self = utf8_realm(&enc_tkt.crealm)? == store.realm()
            && header_client
                .as_ref()
                .is_some_and(|c| c.realm == server.realm && c.name == server.name);
        if !is_referral && !is_self {
            return Err(proto(
                err::BADMATCH,
                status::INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH,
            ));
        }
        check_tgs_s4u2self(
            store,
            body,
            &s4u,
            header_cross,
            is_referral,
            &enc_tkt,
            header_pac.as_deref(),
        )?;
        server.attributes &= !KDB_NO_AUTH_DATA_REQUIRED;
        if !is_referral {
            ticket_cname = s4u.user.clone();
            ticket_crealm.clone_from(&s4u.realm);
        }
        s4u_x509 = s4u.x509;
        s4u_referral = is_referral;
        s4u_local = s4u.local;
        s4u_subject = Some((s4u.user.clone(), s4u.realm.clone()));
        s4u2self = true;
    }
    let is_referral = tgs_issuing_referral(&sname, req_realm.as_str(), &server);
    let is_crossrealm = tgs_header_is_crossrealm(header_realm.as_str(), &server.realm);
    let local_tgt = store.fetch_krbtgt()?;
    let stkt = decrypt_2ndtkt(store, req, local_tgt.as_ref())?;
    // MIT check_tgs_lineage before U2U (`tgs_policy.c:704-710`).
    if utf8_realm(&enc_tkt.crealm)? == store.realm() && is_crossrealm && !s4u2self {
        return Err(proto(err::POLICY, status::INVALID_LINEAGE));
    }
    if body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY) {
        check_tgs_u2u(store, stkt.as_ref(), &server)?;
    }
    if body.kdc_options.bit(flag_bit::CNAME_IN_ADDL_TKT) {
        // MIT `kau_make_tkt_id(stkt)` with a missing additional ticket is
        // EINVAL (`kdc_audit.c:154-155`) → 60 `UNKNOWN_REASON` before
        // `check_tgs_s4u2proxy` (`do_tgs_req.c:731-733`).
        let Some(st) = stkt.as_ref() else {
            return Err(proto(err::GENERIC, status::UNKNOWN_REASON));
        };
        if is_crossrealm {
            let pac = st
                .pac
                .as_deref()
                .ok_or_else(|| proto(err::BADOPTION, status::RBCD_PAC_PRINC))?;
            let (cname, crealm) = rbcd_pac_client(pac)?;
            s4u_subject = Some((cname.clone(), crealm.clone()));
            // MIT `do_tgs_req.c:756-759`: S4U rewrite only on the final hop.
            if !is_referral {
                ticket_cname = cname;
                ticket_crealm = crealm;
            }
        }
        check_tgs_s4u2proxy(
            store,
            body,
            &enc_tkt,
            header_pac.as_deref(),
            Some(st),
            &server.realm,
            is_crossrealm,
            is_referral,
        )?;
        if !is_crossrealm {
            let crealm = utf8_realm(&st.part.crealm)?.to_owned();
            s4u_subject = Some((st.part.cname.clone(), crealm.clone()));
            if !is_referral {
                ticket_cname = st.part.cname.clone();
                ticket_crealm = crealm;
            }
        }
        subject_authtime = st.part.authtime.clone();
        subject_pac.clone_from(&st.pac);
        s4u2proxy = true;
    } else if !s4u2self {
        crate::ad::check_normal_tgs_pac(&enc_tkt, header_pac.as_deref(), &server, is_crossrealm)?;
        if let Some(logon) = header_pac.as_ref().and_then(|p| {
            let parsed = krb5_types::pac::Pac::parse(p).ok()?;
            parsed
                .unique_buffer(krb5_types::pac::PAC_LOGON_INFO)
                .ok()
                .flatten()
                .map(<[u8]>::to_vec)
        }) {
            evidence_logon = Some(if utf8_realm(&ap.ticket.realm)? == store.realm() {
                logon
            } else {
                crate::ad::filter_cross_realm_logon(&logon, store.domain_sid())?
            });
        }
    }
    // MIT check_tgs_policy after constraints (`do_tgs_req.c:872-882`).
    check_tgs_policy_flags(&server, body, ap.ticket.sname.is_krbtgt(), &enc_tkt)?;
    let local_tgt_key = local_tgt
        .as_ref()
        .and_then(|t| store.policy().first_current_key(t).ok())
        .ok_or_else(|| proto(err::GENERIC, status::GET_LOCAL_TGT))?;
    let mut auth_indicators = Vec::new();
    if !s4u2self {
        let subject = stkt.as_ref().map_or(&enc_tkt, |s| &s.part);
        let tgt = local_tgt
            .as_ref()
            .ok_or_else(|| proto(err::GENERIC, status::GET_LOCAL_TGT))?;
        auth_indicators = get_auth_indicators(store.policy(), subject, tgt, &local_tgt_key.key)?;
        check_indicators(&server, &auth_indicators)?;
    }
    if s4u2proxy {
        let st = stkt
            .as_ref()
            .ok_or_else(|| proto(err::GENERIC, status::UNKNOWN_REASON))?;
        check_s4u2proxy_policy(
            tgs_padata,
            &sname,
            &enc_tkt.cname,
            utf8_realm(&enc_tkt.crealm)?,
            &st.server,
            &server,
            is_crossrealm,
            is_referral,
        )?;
    }
    check_anon(store, &enc_tkt.cname, &server.name)?;
    let skip_transited = body.kdc_options.bit(flag_bit::DISABLE_TRANSITED_CHECK);
    let u2u = if body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY) {
        let st = stkt
            .as_ref()
            .ok_or_else(|| proto(err::BADOPTION, status::NO_2ND_TKT))?;
        let offered = get_2ndtkt_enctype(body, st)?;
        Some((u2u_from_stkt(st)?, offered))
    } else {
        None
    };
    let session_etype = match &u2u {
        Some((_, Some(et))) => *et,
        Some((_, None)) | None => select_session_keytype(&server, &body.etype, store.policy())?,
    };
    let (tkt_key, tkt_kvno, tkt_etype) = if let Some(((k, kv, et), _)) = u2u {
        (k, kv, et)
    } else {
        let skey = store
            .policy()
            .first_current_key(&server)
            .map_err(|_| proto(err::GENERIC, status::FINDING_SERVER_KEY))?;
        (skey.key.clone(), skey.kvno, skey.etype)
    };
    let mut transited = enc_tkt.transited.clone();
    let prev_hop = header_realm.as_str();
    let header_crealm = utf8_realm(&enc_tkt.crealm)?;
    let tkt_client_realm = if s4u2self || s4u2proxy {
        ticket_crealm.as_str()
    } else {
        header_crealm
    };
    // MIT do_tgs_req.c:787-788: keep header transited when header-server
    // realm equals tkt_client realm.
    if is_crossrealm && prev_hop != tkt_client_realm {
        if transited.tr_type != 1 {
            return Err(proto(err::TRTYPE_NOSUPP, status::VALIDATE_TRANSIT_TYPE));
        }
        transited = transited
            .append_realm(prev_hop, tkt_client_realm, req_realm.as_str())
            .map_err(|_| proto(err::ILL_CR_TKT, status::ADD_TO_TRANSITED_LIST))?;
    }
    let transit_checked = if tkt_client_realm == "WELLKNOWN:ANONYMOUS" {
        true
    } else {
        match transited.realms_for(tkt_client_realm, req_realm.as_str()) {
            Ok(h) => store
                .policy()
                .transit_allowed(tkt_client_realm, &req_realm, &h),
            Err(e) => crate::audit::unexpected_transit_false(
                e,
                tkt_client_realm,
                req_realm.as_str(),
                &transited,
            ),
        }
    };
    // MIT do_tgs_req: skip leaves T unset; default reject_bad_transit
    // then POLICY. RENEW/VALIDATE keep the header T (get_ticket_flags).
    let inherited_t = (renew || validate) && enc_tkt.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED);
    let set_transited_flag = !skip_transited && transit_checked;
    if !(inherited_t || set_transited_flag) && store.policy().reject_bad_transit {
        return Err(proto(err::POLICY, status::BAD_TRANSIT));
    }
    let c = TgsChecked {
        tgs_padata,
        ap,
        enc_tkt,
        tgt_session,
        authenticator,
        renew,
        validate,
        sname,
        server,
        auth_indicators,
        s4u2self,
        s4u_local,
        s4u_referral,
        session_etype,
        set_transited_flag,
        stkt,
        subject_authtime,
        s4u2proxy,
        is_crossrealm,
        is_referral,
        s4u_subject,
        s4u_x509,
        evidence_logon,
        subject_pac,
        ticket_cname,
        ticket_crealm,
        tkt_key,
        tkt_kvno,
        tkt_etype,
        transited,
    };
    tgs_flags_times_policy(store, body, c)
}

/// Flags, times, and kdcpolicy: MIT `get_ticket_flags` (`do_tgs_req.c:905`),
/// `compute_ticket_times` (`do_tgs_req.c:812` via `:907`),
/// `check_kdcpolicy_tgs` (`do_tgs_req.c:919`), `gen_session_key`
/// (`do_tgs_req.c:980`), and the S4U client fetch (`do_tgs_req.c:775`).
fn tgs_flags_times_policy<'a>(
    store: &dyn PrincipalRead,
    body: &KdcReqBody,
    c: TgsChecked<'a>,
) -> Result<TgsTimes<'a>, Error> {
    let TgsChecked {
        tgs_padata,
        ap,
        enc_tkt,
        tgt_session,
        authenticator,
        renew,
        validate,
        sname,
        server,
        auth_indicators,
        s4u2self,
        s4u_local,
        s4u_referral,
        session_etype,
        set_transited_flag,
        stkt,
        subject_authtime,
        s4u2proxy,
        is_crossrealm,
        is_referral,
        s4u_subject,
        s4u_x509,
        evidence_logon,
        subject_pac,
        ticket_cname,
        ticket_crealm,
        tkt_key,
        tkt_kvno,
        tkt_etype,
        transited,
    } = c;
    let session = random_key(session_etype)?;
    let now = KerberosTime::now();
    let subject_cname = stkt.as_ref().map_or(&enc_tkt.cname, |s| &s.part.cname);
    let subject_crealm = if let Some(st) = stkt.as_ref() {
        utf8_realm(&st.part.crealm)?
    } else {
        utf8_realm(&enc_tkt.crealm)?
    };
    let tgs_client = if s4u2self {
        s4u_local
    } else if attr(&server, KDB_NO_AUTH_DATA_REQUIRED) {
        None
    } else if subject_crealm == store.realm() {
        store.fetch_name(subject_cname)?
    } else {
        None
    };
    let authtime;
    let starttime;
    let mut end;
    let mut flags;
    let mut ticket_renew_till;
    if renew {
        if !enc_tkt.flags.renewable() {
            return Err(proto(err::BADOPTION, status::TICKET_NOT_RENEWABLE));
        }
        authtime = enc_tkt.authtime.clone();
        starttime = if body.kdc_options.bit(flag_bit::POSTDATED) {
            body.from
                .clone()
                .unwrap_or_else(|| KerberosTime::from_unix_seconds(0))
        } else {
            now.clone()
        };
        let old_start = enc_tkt
            .starttime
            .clone()
            .unwrap_or_else(|| enc_tkt.authtime.clone());
        let start_s = old_start.unix_seconds();
        let end_s = enc_tkt.endtime.unix_seconds();
        let mut hlife = i64::from(end_s.wrapping_sub(start_s).cast_signed());
        if end_s > start_s && hlife < 0 {
            hlife = i64::from(i32::MAX);
        }
        end = starttime
            .add_seconds(hlife)
            .unwrap_or_else(|_| starttime.clone());
        if let Some(till) = &enc_tkt.renew_till
            && till.unix_seconds() < end.unix_seconds()
        {
            end = till.clone();
        }
        flags = get_ticket_flags(
            &body.kdc_options,
            tgs_client.as_ref(),
            &server,
            Some(&enc_tkt.flags),
        );
        ticket_renew_till = kdc_get_ticket_renewtime(
            store,
            body,
            Some(&enc_tkt),
            tgs_client.as_ref(),
            &server,
            &mut flags,
            &starttime,
            &end,
        );
        if set_transited_flag {
            flags = flags.with_bit(flag_bit::TRANSITED_POLICY_CHECKED, true);
        }
    } else if validate {
        authtime = enc_tkt.authtime.clone();
        starttime = enc_tkt
            .starttime
            .clone()
            .unwrap_or_else(|| enc_tkt.authtime.clone());
        end = enc_tkt.endtime.clone();
        ticket_renew_till = enc_tkt.renew_till.clone();
        flags = get_ticket_flags(
            &body.kdc_options,
            tgs_client.as_ref(),
            &server,
            Some(&enc_tkt.flags),
        );
        if set_transited_flag {
            flags = flags.with_bit(flag_bit::TRANSITED_POLICY_CHECKED, true);
        }
    } else {
        authtime = subject_authtime.clone();
        starttime = if body.kdc_options.bit(flag_bit::POSTDATED) {
            body.from
                .clone()
                .unwrap_or_else(|| KerberosTime::from_unix_seconds(0))
        } else {
            now.clone()
        };
        end = kdc_get_ticket_endtime(
            store,
            &starttime,
            Some(&enc_tkt.endtime),
            &body.till,
            tgs_client.as_ref(),
            &server,
        )?;
        flags = get_ticket_flags(
            &body.kdc_options,
            tgs_client.as_ref(),
            &server,
            Some(&enc_tkt.flags),
        );
        if set_transited_flag {
            flags = flags.with_bit(flag_bit::TRANSITED_POLICY_CHECKED, true);
        }
        ticket_renew_till = kdc_get_ticket_renewtime(
            store,
            body,
            Some(&enc_tkt),
            tgs_client.as_ref(),
            &server,
            &mut flags,
            &starttime,
            &end,
        );
    }
    if s4u2self && !s4u_referral {
        flags = s4u2self_forwardable(&server, flags);
    }
    let tgs_adj = current_policy().check_tgs(store, &server.name, &auth_indicators)?;
    apply_policy_times(&now, &mut end, &mut ticket_renew_till, &tgs_adj);
    Ok(TgsTimes {
        tgs_padata,
        ap,
        enc_tkt,
        tgt_session,
        authenticator,
        renew,
        validate,
        sname,
        server,
        auth_indicators,
        s4u2self,
        stkt,
        s4u2proxy,
        is_crossrealm,
        is_referral,
        s4u_subject,
        s4u_x509,
        evidence_logon,
        subject_pac,
        ticket_cname,
        ticket_crealm,
        tkt_key,
        tkt_kvno,
        tkt_etype,
        transited,
        session,
        authtime,
        starttime,
        end,
        flags,
        ticket_renew_till,
    })
}

/// MIT `tgs_issue_ticket` (`do_tgs_req.c:956`); session-key generation
/// lives in `tgs_flags_times_policy`.
fn tgs_issue_ticket(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    raw: Option<&[u8]>,
    body: &KdcReqBody,
    tgs_fast: Option<&FastOk>,
    t: TgsTimes<'_>,
) -> Result<IssuedTgs, Error> {
    let TgsTimes {
        tgs_padata,
        ap,
        enc_tkt,
        tgt_session,
        authenticator,
        renew,
        validate,
        sname,
        server,
        auth_indicators,
        s4u2self,
        stkt,
        s4u2proxy,
        is_crossrealm,
        is_referral,
        s4u_subject,
        s4u_x509,
        evidence_logon,
        mut subject_pac,
        ticket_cname,
        ticket_crealm,
        tkt_key,
        tkt_kvno,
        tkt_etype,
        transited,
        session,
        authtime,
        starttime,
        end,
        flags,
        ticket_renew_till,
    } = t;
    let krbtgt_p = store
        .fetch_krbtgt()?
        .ok_or_else(|| proto(err::GENERIC, status::GET_LOCAL_TGT))?;
    let krbtgt_key = store
        .policy()
        .first_current_key(&krbtgt_p)
        .map_err(|_| proto(err::GENERIC, status::GET_LOCAL_TGT))?;
    // Referral TGT PAC 16/19/7 must be keyed with the inter-realm key
    // the foreign KDC holds (Windows TDO inbound), not the local krbtgt.
    let pac_kdc = crate::ad::pac_privsvr_key(
        &server,
        if server.name.is_krbtgt() && !server.name.is_krbtgt_for(store.realm()) {
            &tkt_key
        } else {
            &krbtgt_key.key
        },
    )?;
    let include_pac = include_pac_for_reply(
        store,
        &server,
        tgs_padata,
        false,
        subject_pac.is_some(),
        flags.bit(flag_bit::ANONYMOUS),
    );
    if s4u2proxy
        && !is_crossrealm
        && let (Some(raw), Some(st)) = (subject_pac.as_deref(), stkt.as_ref())
    {
        let hop = st.server.name.unparse_with_realm(&st.server.realm);
        // MIT `kdc_authdata.c:410-414`: `req->server`, not the referral TGT.
        subject_pac = Some(update_delegation_info(raw, &sname, &hop)?);
    }
    let client_key = if let Some(sub) = authenticator.subkey.as_ref() {
        let st = EncryptionType::from_iana(sub.keytype)
            .or_else(|_| EncryptionType::known(sub.keytype))?;
        ProtocolKey::from_bytes(st, sub.keyvalue.as_ref())?
    } else {
        tgt_session.clone()
    };
    // MIT `kdc_authdata.c:534-544`: S4U referral PAC client info is the
    // subject with realm; the final hop omits the realm.
    let s4u_client_info = if s4u2self || s4u2proxy {
        Some(if is_referral {
            match &s4u_subject {
                Some((n, r)) => format!("{}@{r}", n.components_joined()),
                None => ticket_cname.components_joined(),
            }
        } else {
            ticket_cname.components_joined()
        })
    } else {
        None
    };
    let extra_ad = handle_authdata(
        true,
        flags.bit(flag_bit::ANONYMOUS),
        body.enc_authorization_data.as_ref(),
        Some(&tgt_session),
        Some(&client_key),
        enc_tkt.authorization_data.as_ref(),
        Some(&session),
        Some((&krbtgt_p.name, store.realm())),
    )?;
    let ticket_sname = if renew || validate {
        ap.ticket.sname.clone()
    } else if is_referral {
        server.name.clone()
    } else {
        sname.clone()
    };
    let ticket = mint_ticket(MintTicket {
        service_key: &tkt_key,
        kvno: tkt_kvno,
        service_etype: tkt_etype,
        session: &session,
        srealm: store.realm(),
        sname: &ticket_sname,
        crealm: &ticket_crealm,
        cname: &ticket_cname,
        authtime: &authtime,
        endtime: &end,
        flags: flags.clone(),
        kdc_key: &pac_kdc,
        transited,
        renew_till: ticket_renew_till.clone(),
        store,
        include_pac,
        logon_override: evidence_logon.as_deref(),
        starttime: &starttime,
        subject_pac: if s4u2self {
            None
        } else {
            subject_pac.as_deref()
        },
        caddr: tgs_ticket_caddr(body, renew, validate, &enc_tkt),
        s4u_client_info: s4u_client_info.as_deref(),
        extra_ad,
        indicators: &auth_indicators,
        krbtgt: &krbtgt_p,
        krbtgt_key: &krbtgt_key.key,
        no_auth_data: attr(&server, KDB_NO_AUTH_DATA_REQUIRED),
    })?;
    let mut s4u_rep_pa = None;
    let mut s4u_enc_pa = None;
    if let Some(ref x509) = s4u_x509 {
        let (pa, enc) = make_s4u2self_rep(x509, &tgt_session, authenticator.subkey.as_ref())?;
        s4u_rep_pa = Some(pa);
        s4u_enc_pa = enc;
    }
    let (mut enc_key, enc_usage) = if let Some(sub) = authenticator.subkey {
        let st = EncryptionType::from_iana(sub.keytype)
            .or_else(|_| EncryptionType::known(sub.keytype))?;
        (
            ProtocolKey::from_bytes(st, sub.keyvalue.as_ref())?,
            ku::TGS_REP_ENC_PART_SUBKEY,
        )
    } else {
        (tgt_session.clone(), ku::TGS_REP_ENC_PART)
    };
    let mut strengthen = None;
    if tgs_fast.is_some() {
        let sk = random_key(enc_key.etype())?;
        enc_key = krb_fx_cf2(&sk, &enc_key, b"strengthenkey", b"replykey")?;
        strengthen = Some(sk);
    }
    let want_enc_pa = find_pa(req.0.padata.as_deref(), pa::REQ_ENC_PA_REP).is_some()
        || tgs_fast.is_some_and(|f| find_pa(Some(&f.inner_padata), pa::REQ_ENC_PA_REP).is_some());
    let enc_part = enc_rep_part(
        &session,
        tgs_fast.map_or(body.nonce, |f| f.nonce),
        &authtime,
        &starttime,
        &end,
        store.realm(),
        &ticket_sname,
        flags,
        ticket_renew_till,
        return_enc_padata(raw, tgs_padata, &enc_key, want_enc_pa, s4u_enc_pa)?,
        tgs_reply_caddr(body, renew, validate),
        None,
    )?;
    let enc_der = encode_enc_kdc_rep_part(enc_part)?;
    let usage = KeyUsage::new(enc_usage)?;
    let cipher = encrypt(&enc_key, usage, &enc_der)?;
    let padata = if let Some(f) = tgs_fast {
        let finished = fast_finished(&f.armor_key, &ticket, &ticket_cname, &ticket_crealm)?;
        let inner: Vec<PaData> = s4u_rep_pa.into_iter().collect();
        Some(vec![wrap_fast_rep(
            &f.armor_key,
            inner,
            strengthen.as_ref(),
            f.nonce,
            Some(finished),
        )?])
    } else {
        s4u_rep_pa.map(|p| vec![p])
    };
    let (rep_crealm, rep_cname) = if tgs_fast.is_some_and(|f| fast_hides_client(&f.fast_options)) {
        (ks(ANONYMOUS_REALM)?, anonymous_principal_name())
    } else {
        (ks(&ticket_crealm)?, ticket_cname)
    };
    let rep = TgsRep(krb5_types::KdcRep {
        pvno: krb5_types::KdcRep::PVNO,
        msg_type: krb5_types::KdcRep::MSG_TGS_REP,
        padata,
        crealm: rep_crealm,
        cname: rep_cname,
        ticket,
        enc_part: EncryptedData {
            etype: enc_key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
    });
    Ok(IssuedTgs {
        rep,
        session_key: session,
    })
}

/// MIT `get_2ndtkt_enctype` (`do_tgs_req.c:310-328`).
fn get_2ndtkt_enctype(
    body: &KdcReqBody,
    st: &SecondTicket,
) -> Result<Option<EncryptionType>, Error> {
    let n = st.part.key.keytype;
    let Ok(et) = EncryptionType::known(n) else {
        return Err(proto(err::ETYPE_NOSUPP, status::BAD_ETYPE_IN_2ND_TKT));
    };
    if body.etype.contains(&n) {
        Ok(Some(et))
    } else {
        Ok(None)
    }
}

/// MIT `decrypt_2ndtkt` (`do_tgs_req.c:257-307`).
fn decrypt_2ndtkt(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    local_tgt: Option<&Principal>,
) -> Result<Option<SecondTicket>, Error> {
    let body = &req.0.req_body;
    if !body.kdc_options.bit(flag_bit::CNAME_IN_ADDL_TKT)
        && !body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY)
    {
        return Ok(None);
    }
    let Some(extra) = body.additional_tickets.as_ref().and_then(|v| v.first()) else {
        return Ok(None);
    };
    let stkt_realm = utf8_realm(&extra.realm)?;
    let server = store
        .fetch(&lookup_principal_id(&extra.sname, stkt_realm))?
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, status::SECOND_TKT_SERVER))?;
    if attr(&server, KDB_DISALLOW_ALL_TIX) || attr(&server, KDB_DISALLOW_SVR) {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::SECOND_TKT_SERVER));
    }
    let Ok(tkt_etype) = EncryptionType::from_iana(extra.enc_part.etype)
        .or_else(|_| EncryptionType::known(extra.enc_part.etype))
    else {
        return Err(proto(err::GENERIC, status::SECOND_TKT_SERVER));
    };
    let kvno = extra.enc_part.kvno.unwrap_or(0);
    let (key, _) = find_server_key(store.policy(), &server, Some(tkt_etype), kvno)
        .map_err(|e| with_status(e, status::SECOND_TKT_SERVER))?;
    let usage = KeyUsage::new(ku::TICKET)?;
    let plain = decrypt(&key, usage, extra.enc_part.cipher.as_ref())
        .map_err(|_| proto(err::BAD_INTEGRITY, status::SECOND_TKT_DECRYPT))?;
    let part: EncTicketPart =
        decode(&plain).map_err(|_| proto(err::BAD_INTEGRITY, status::SECOND_TKT_DECRYPT))?;
    if extra.sname.is_krbtgt() {
        let pac = crate::ad::get_verified_pac(store.policy(), &part, &key, &server, None)
            .map_err(|e| with_status(e, status::SECOND_TKT_PAC))?;
        return Ok(Some(SecondTicket { part, server, pac }));
    }
    let Some(tgt) = local_tgt else {
        return Err(proto(err::GENERIC, status::GET_LOCAL_TGT));
    };
    let pac = crate::ad::get_verified_pac(store.policy(), &part, &key, &server, Some(tgt))
        .map_err(|e| with_status(e, status::SECOND_TKT_PAC))?;
    Ok(Some(SecondTicket { part, server, pac }))
}

fn u2u_from_stkt(st: &SecondTicket) -> Result<(ProtocolKey, u32, EncryptionType), Error> {
    let etype = EncryptionType::from_iana(st.part.key.keytype)
        .or_else(|_| EncryptionType::known(st.part.key.keytype))?;
    let key = ProtocolKey::from_bytes(etype, st.part.key.keyvalue.as_ref())?;
    Ok((key, 0, etype))
}

/// MIT `do_tgs_req.c:686`: header ticket server realm ≠ canonical server realm.
#[must_use]
pub fn tgs_header_is_crossrealm(header_server_realm: &str, sprinc_realm: &str) -> bool {
    header_server_realm != sprinc_realm
}

/// MIT `in_list` (`do_tgs_req.c:417-431`): space/comma-separated tokens.
fn in_list(list: &str, item: &str) -> bool {
    if list.is_empty() {
        return false;
    }
    list.split(|c: char| c.is_ascii_whitespace() || c == ',')
        .any(|t| t == item)
}

fn no_referral_option(body: &KdcReqBody) -> bool {
    body.kdc_options.bit(flag_bit::FORWARDED)
        || body.kdc_options.bit(flag_bit::PROXY)
        || body.kdc_options.bit(flag_bit::RENEW)
        || body.kdc_options.bit(flag_bit::VALIDATE)
        || body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY)
}

/// MIT `is_referral_req` (`do_tgs_req.c:438-477`).
fn is_referral_req(store: &dyn PrincipalRead, body: &KdcReqBody, sname: &PrincipalName) -> bool {
    if !body.kdc_options.bit(flag_bit::CANONICALIZE)
        || body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY)
        || sname.name_string.len() != 2
    {
        return false;
    }
    let stype = sname
        .name_string
        .first()
        .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
        .unwrap_or_default();
    let hostbased = store.policy().host_based_services.as_str();
    let no_ref = store.policy().no_host_referral.as_str();
    match sname.name_type {
        PrincipalName::NT_UNKNOWN => {
            if !in_list(hostbased, &stype) && !in_list(hostbased, "*") {
                return false;
            }
        }
        PrincipalName::NT_SRV_HST | PrincipalName::NT_SRV_INST => {}
        _ => return false,
    }
    !in_list(no_ref, &stype) && !in_list(no_ref, "*")
}

/// MIT `find_referral_tgs` (`do_tgs_req.c:483-523`).
fn find_referral_tgs(
    store: &dyn PrincipalRead,
    body: &KdcReqBody,
    sname: &PrincipalName,
    req_realm: &str,
) -> Result<PrincipalName, Error> {
    if !is_referral_req(store, body, sname) {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::LOOKING_UP_SERVER));
    }
    let host = sname
        .name_string
        .get(1)
        .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
        .unwrap_or_default();
    if !host.contains('.') || krb5_config::is_numeric_address(&host) {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::LOOKING_UP_SERVER));
    }
    let Some(other) = store.policy().realm_for_host(&host) else {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::LOOKING_UP_SERVER));
    };
    if other.is_empty() || other == req_realm {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::LOOKING_UP_SERVER));
    }
    Ok(PrincipalName::new(
        PrincipalName::NT_SRV_INST,
        ["krbtgt", other],
    ))
}

/// MIT `find_alternate_tgs` (`do_tgs_req.c:370-414`).
fn find_alternate_tgs(
    store: &dyn PrincipalRead,
    princ: &PrincipalName,
) -> Result<crate::store::Principal, Error> {
    let far = princ
        .name_string
        .get(1)
        .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
        .unwrap_or_default();
    let hops = crate::store::walk_realm_instances(&store.policy().capaths, store.realm(), &far);
    for inst in hops.iter().skip(1).rev() {
        let hop = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", inst.as_str()]);
        if let Some(p) = lookup_svc_princ(store, &hop)? {
            return Ok(p);
        }
    }
    Err(proto(err::S_PRINCIPAL_UNKNOWN, status::UNKNOWN_SERVER))
}

/// MIT `search_sprinc` (`do_tgs_req.c:541-581`).
fn search_sprinc(
    store: &dyn PrincipalRead,
    requested: &PrincipalName,
    req_realm: &str,
    body: &KdcReqBody,
) -> Result<crate::store::Principal, Error> {
    if let Some(p) = lookup_svc_princ(store, requested)? {
        return Ok(p);
    }
    if no_referral_option(body) {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::LOOKING_UP_SERVER));
    }
    let lookup = if requested.is_cross_tgs_principal(req_realm) {
        requested.clone()
    } else {
        let reftgs = find_referral_tgs(store, body, requested, req_realm)?;
        if let Some(p) = lookup_svc_princ(store, &reftgs)? {
            return Ok(p);
        }
        reftgs
    };
    find_alternate_tgs(store, &lookup)
}

/// MIT `do_tgs_req.c:680-682`: cross TGS **and** resolved ≠ requested.
fn tgs_issuing_referral(
    requested: &PrincipalName,
    req_realm: &str,
    resolved: &crate::store::Principal,
) -> bool {
    resolved.name.is_cross_tgs_principal(&resolved.realm)
        && !krb5_types::principal_compare(&resolved.name, &resolved.realm, requested, req_realm)
}

/// MIT `do_tgs_req.c:1012-1027`.
fn tgs_ticket_caddr(
    body: &KdcReqBody,
    renew: bool,
    validate: bool,
    header: &EncTicketPart,
) -> Option<HostAddresses> {
    if renew || validate {
        header.caddr.clone()
    } else if body.kdc_options.bit(flag_bit::FORWARDED) || body.kdc_options.bit(flag_bit::PROXY) {
        body.addresses.clone()
    } else {
        header.caddr.clone()
    }
}

fn tgs_reply_caddr(body: &KdcReqBody, renew: bool, validate: bool) -> Option<HostAddresses> {
    let rewrite =
        body.kdc_options.bit(flag_bit::FORWARDED) || body.kdc_options.bit(flag_bit::PROXY);
    if renew || validate || !rewrite {
        None
    } else {
        body.addresses.clone()
    }
}

pub(super) fn extract_pa_tgs(padata: Option<&[PaData]>) -> Option<&OctetString> {
    padata?.iter().find_map(|p| {
        if p.padata_type == pa::TGS_REQ {
            Some(&p.padata_value)
        } else {
            None
        }
    })
}

/// Header-ticket client for a TGS KRB-ERROR (`prepare_error_tgs`
/// `errpkt.client`): the presented ticket's client when it decrypts, else
/// `None` (MIT's `NULL`).
pub(super) fn tgs_header_client(store: &dyn PrincipalRead, req: &TgsReq) -> Option<PrincipalName> {
    let pa_tgs = extract_pa_tgs(req.0.padata.as_deref())?;
    let ap: krb5_types::ApReq = decode(pa_tgs.as_ref()).ok()?;
    // MIT kdc_process_tgs_req refuses USE_SESSION_KEY / MUTUAL_REQUIRED
    // before rd_req, so the error has no decrypted client.
    if ap.ap_options.use_session_key() || ap.ap_options.wants_mutual() {
        return None;
    }
    let etype = EncryptionType::from_iana(ap.ticket.enc_part.etype)
        .or_else(|_| EncryptionType::known(ap.ticket.enc_part.etype))
        .ok()?;
    let (enc_tkt, _, _, _) = decrypt_presented_tgt(store, &ap, etype).ok()?;
    Some(enc_tkt.cname)
}

/// MIT `db_get_svc_princ` (`do_tgs_req.c:525-538`): `CANTLOCK_DB` is 29
/// `SVC_UNAVAILABLE`, and **any** backend error (including CANTLOCK) sets
/// `LOOKING_UP_SERVER`. Other faults stay 7 `S_PRINCIPAL_UNKNOWN` with that
/// status (the previous wire code; MIT would send the remapped KDB code).
fn lookup_svc_princ(
    store: &dyn PrincipalRead,
    name: &PrincipalName,
) -> Result<Option<crate::store::Principal>, Error> {
    match store.fetch_name(name) {
        Ok(v) => Ok(v),
        Err(Error::Protocol {
            code,
            e_data,
            detail,
            ..
        }) if code == err::SVC_UNAVAILABLE => Err(Error::Protocol {
            code,
            text: Some(status::LOOKING_UP_SERVER.to_owned()),
            e_data,
            detail,
        }),
        Err(_) => Err(proto(err::S_PRINCIPAL_UNKNOWN, status::LOOKING_UP_SERVER)),
    }
}

#[cfg(test)]
mod a2_6_crossrealm {
    use super::tgs_header_is_crossrealm;

    #[test]
    fn is_crossrealm_is_header_realm_vs_server_realm() {
        assert!(!tgs_header_is_crossrealm("KERBER.TEST", "KERBER.TEST"));
        assert!(tgs_header_is_crossrealm("OTHER.TEST", "KERBER.TEST"));
        assert!(!tgs_header_is_crossrealm("OTHER.TEST", "OTHER.TEST"));
        assert!(tgs_header_is_crossrealm("KERBER.TEST", "OTHER.TEST"));
    }
}
