//! A TGS request: the header ticket, the server, and the reply.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt_enc_data, encrypt, krb_fx_cf2};
use krb5_types::{
    EncTicketPart, EncryptedData, HostAddress, HostAddresses, KdcReqBody, KerberosTime,
    OctetString, PaData, PrincipalName, TgsRep, TgsReq, TicketFlags, TransitedEncoding, err,
    flag_bit, ku, pa,
};

use super::as_req::{ANONYMOUS_REALM, anonymous_principal_name};
use super::fast_util::{fast_hides_client, wrap_as_fast};
use super::kdc_util::{
    E_BADMSGTYPE, E_KDB_NOENTRY, HeaderTgt, LocalTgt, attr, check_anon, decrypt_presented_tgt,
    find_server_key, get_local_tgt, get_ticket_flags, include_pac_for_reply,
    kdc_get_ticket_endtime, kdc_get_ticket_renewtime, kdc_req_body_der, ks, process_tgs_header,
    s4u2self_forwardable, select_session_keytype, utf8_realm,
};
use super::reply::{
    MintTicket, TicketPac, enc_rep_part, encode_enc_kdc_rep_part, mint_ticket, return_enc_padata,
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
use crate::plugins::enforce_kdcpolicy_tgs;
use crate::preauth::{
    FastOk, fast_finished, find_pa, proto, proto_d, unwrap_fast_tgs, wrap_fast_rep,
};
use crate::status;
use crate::store::{
    KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_SVR, KDB_NO_AUTH_DATA_REQUIRED, Principal, random_key,
};

#[derive(Debug)]
pub struct IssuedTgs {
    pub rep: TgsRep,
    pub session_key: ProtocolKey,
}

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
    if req.0.msg_type != krb5_types::KdcReq::MSG_TGS_REQ {
        return Err(proto_d(err::GENERIC, status::UNKNOWN_REASON, E_BADMSGTYPE));
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
    crate::audit::note_tgs_body(body);
    issue_tgs_body(store, req, raw, body, tgs_fast.as_ref(), header)
        .map_err(|e| wrap_as_fast(store, tgs_fast.as_ref(), e, body))
}

// MIT: `gather_tgs_req_info` (do_tgs_req.c:592-592)
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
    local_tgt: LocalTgt,
}

// MIT: `check_tgs_req` (do_tgs_req.c:857-857)
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
    transited: TransitedEncoding,
    req_realm: String,
    tkt_client_realm: String,
    local_tgt: LocalTgt,
}

// MIT: `compute_ticket_times` (do_tgs_req.c:812-812)
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
    s4u_user_local: bool,
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
    local_tgt: LocalTgt,
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

fn gather_tgs_req_info<'a>(
    store: &dyn PrincipalRead,
    req: &'a TgsReq,
    body: &KdcReqBody,
    tgs_fast: Option<&'a FastOk>,
    header: HeaderTgt,
) -> Result<TgsGather<'a>, Error> {
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
    let sname = body
        .sname
        .clone()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, status::NULL_SERVER))?;
    let req_realm = utf8_realm(&body.realm)?.to_owned();
    // A foreign request realm is 60, before the server lookup.
    if req_realm != store.realm() {
        return Err(proto_d(err::GENERIC, status::GET_LOCAL_TGT, E_KDB_NOENTRY));
    }
    let local_tgt = get_local_tgt(store, &header_server)?;
    let header_pac = crate::ad::get_verified_pac(
        store.policy(),
        &enc_tkt,
        &tgt_key,
        &header_server,
        &local_tgt.entry,
        &local_tgt.key,
    )?;
    // MIT: `gather_tgs_req_info` (do_tgs_req.c:667-673)
    crate::audit::note_tgs(|f| f.stage = crate::audit::SRVC_PRINC);
    let server = search_sprinc(store, &sname, req_realm.as_str(), body)?;
    crate::audit::note_tgs(|f| {
        f.sprinc = Some(server.name.unparse_with_realm_lossy(&server.realm));
    });
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
        local_tgt,
    })
}

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
        local_tgt,
    } = g;
    let now = KerberosTime::now();
    let mut ticket_cname = enc_tkt.cname.clone();
    let mut ticket_crealm = utf8_realm(&enc_tkt.crealm)?.to_owned();
    let mut evidence_logon = None;
    let mut s4u2proxy = false;
    let mut s4u_subject: Option<(PrincipalName, String)> = None;
    let mut subject_authtime = enc_tkt.authtime.clone();
    let mut subject_pac = header_pac.clone();
    let is_referral = tgs_issuing_referral(&sname, req_realm.as_str(), &server);
    let is_crossrealm = tgs_header_is_crossrealm(header_realm.as_str(), &server.realm);
    let s4u2self_req = process_s4u2self_req(
        store,
        &tgt_session,
        authenticator.subkey.as_ref(),
        tgs_padata,
        body.nonce,
    );
    // MIT: `gather_tgs_req_info` (do_tgs_req.c:693-716)
    crate::audit::note_tgs(|f| match &s4u2self_req {
        Ok(None) => {}
        Ok(Some(s4u)) => {
            f.protocol_transition = true;
            f.s4u_client = Some(s4u.user.unparse_with_realm_lossy(&s4u.realm));
            f.au_status = None;
            f.event("S4U2SELF", true);
        }
        Err(e) => {
            f.au_status = crate::audit::error_status(e);
            f.event("S4U2SELF", false);
        }
    });
    let s4u = s4u2self_req?;
    let s4u2self = s4u.is_some();
    if let Some(s4u) = &s4u {
        server.attributes &= !KDB_NO_AUTH_DATA_REQUIRED;
        if !is_referral {
            ticket_cname = s4u.user.clone();
            ticket_crealm.clone_from(&s4u.realm);
        }
        s4u_subject = Some((s4u.user.clone(), s4u.realm.clone()));
    }
    let stkt = decrypt_2ndtkt(store, req, &local_tgt)?;
    if body.kdc_options.bit(flag_bit::CNAME_IN_ADDL_TKT) {
        // MIT: `gather_tgs_req_info` (do_tgs_req.c:729-733)
        // MIT: `kau_make_tkt_id` (kdc_audit.c:154-155)
        crate::audit::note_tgs(|f| f.constrained_delegation = true);
        let Some(st) = stkt.as_ref() else {
            return Err(proto_d(
                err::GENERIC,
                status::UNKNOWN_REASON,
                "Invalid argument",
            ));
        };
        if is_crossrealm {
            // MIT: `gather_tgs_req_info` (do_tgs_req.c:737-743)
            let rbcd = st
                .pac
                .as_deref()
                .ok_or_else(|| proto(err::BADOPTION, status::RBCD_PAC_PRINC))
                .and_then(rbcd_pac_client);
            let (cname, crealm) = rbcd.inspect_err(|e| {
                crate::audit::note_tgs(|f| {
                    f.au_status = crate::audit::error_status(e);
                    f.event("S4U2PROXY", false);
                });
            })?;
            s4u_subject = Some((cname, crealm));
        } else {
            let crealm = utf8_realm(&st.part.crealm)?.to_owned();
            s4u_subject = Some((st.part.cname.clone(), crealm));
        }
        if !is_referral && let Some((cname, crealm)) = &s4u_subject {
            ticket_cname = cname.clone();
            ticket_crealm.clone_from(crealm);
        }
        crate::audit::note_tgs(|f| {
            f.s4u_client = s4u_subject
                .as_ref()
                .map(|(n, r)| n.unparse_with_realm_lossy(r));
        });
        subject_authtime = st.part.authtime.clone();
        subject_pac.clone_from(&st.pac);
        s4u2proxy = true;
    }
    // MIT: `gather_tgs_req_info` (do_tgs_req.c:759)
    crate::audit::note_tgs(|f| f.authtime = subject_authtime.unix_seconds());
    let mut auth_indicators = Vec::new();
    if !s4u2self {
        let subject = stkt.as_ref().map_or(&enc_tkt, |s| &s.part);
        auth_indicators = get_auth_indicators(
            store.policy(),
            subject,
            &local_tgt.entry,
            &local_tgt.key.key,
        )?;
    }
    let mut transited = enc_tkt.transited.clone();
    let prev_hop = header_realm.as_str();
    let tkt_client_realm = if s4u2self || s4u2proxy {
        ticket_crealm.clone()
    } else {
        utf8_realm(&enc_tkt.crealm)?.to_owned()
    };
    if is_crossrealm && prev_hop != tkt_client_realm {
        if transited.tr_type != 1 {
            return Err(proto(err::TRTYPE_NOSUPP, status::VALIDATE_TRANSIT_TYPE));
        }
        transited = transited
            .append_realm(prev_hop, &tkt_client_realm, req_realm.as_str())
            .map_err(|_| proto(err::ILL_CR_TKT, status::ADD_TO_TRANSITED_LIST))?;
    }
    // MIT: `check_tgs_req` (do_tgs_req.c:866-880)
    crate::audit::note_tgs(|f| f.stage = crate::audit::VALIDATE_POL);
    check_tgs_constraints_skeleton(
        body,
        &ap.ticket.sname,
        header_realm.as_str(),
        &enc_tkt,
        &sname,
        req_realm.as_str(),
        renew,
        validate,
        &now,
    )?;
    if let Some(s4u) = &s4u {
        // MIT: `check_tgs_s4u2self` (tgs_policy.c:262-275)
        let header_cross = utf8_realm(&ap.ticket.realm)? != store.realm();
        if !is_referral && !is_client_db_alias(store, &server, &enc_tkt) {
            return Err(proto(
                err::BADMATCH,
                status::INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH,
            ));
        }
        check_tgs_s4u2self(
            store,
            body,
            s4u,
            header_cross,
            is_referral,
            &enc_tkt,
            header_pac.as_deref(),
        )?;
    } else if utf8_realm(&enc_tkt.crealm)? == store.realm() && is_crossrealm {
        // MIT: `check_tgs_constraints` (tgs_policy.c:704-710)
        return Err(proto(err::POLICY, status::INVALID_LINEAGE));
    }
    if body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY) {
        check_tgs_u2u(store, stkt.as_ref(), &server)?;
    }
    if let (true, Some(st)) = (s4u2proxy, stkt.as_ref()) {
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
    } else if !s4u2self {
        crate::ad::check_normal_tgs_pac(&enc_tkt, header_pac.as_deref(), &server, is_crossrealm)?;
        evidence_logon = carried_logon(store, &ap, header_pac.as_deref())?;
    } else if s4u.as_ref().is_some_and(|s| s.local.is_none()) {
        evidence_logon = carried_logon(store, &ap, header_pac.as_deref())?;
    }
    // MIT: `check_tgs_req` (do_tgs_req.c:882-892)
    let proxy_refused = |e: Error| {
        if s4u2proxy {
            crate::audit::note_tgs(|f| {
                f.au_status = crate::audit::error_status(&e);
                f.event("S4U2PROXY", false);
            });
        }
        e
    };
    check_tgs_policy_flags(&server, body, ap.ticket.sname.is_krbtgt(), &enc_tkt)
        .map_err(proxy_refused)?;
    if s4u2proxy {
        let st = stkt
            .as_ref()
            .ok_or_else(|| proto(err::GENERIC, status::UNKNOWN_REASON))?;
        check_s4u2proxy_policy(
            store,
            tgs_padata,
            &sname,
            &enc_tkt.cname,
            utf8_realm(&enc_tkt.crealm)?,
            &st.server,
            &server,
            is_crossrealm,
            is_referral,
        )
        .map_err(proxy_refused)?;
    }
    check_anon(store, &enc_tkt.cname, &server.name).map_err(proxy_refused)?;
    // MIT: `check_tgs_req` (do_tgs_req.c:897-902)
    if !s4u2self {
        check_indicators(&server, &auth_indicators)?;
    }
    let (s4u_x509, s4u_local, s4u_referral) =
        s4u.map_or((None, None, false), |s| (s.x509, s.local, is_referral));
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
        transited,
        req_realm,
        tkt_client_realm,
        local_tgt,
    };
    tgs_flags_times_policy(store, body, c, &now)
}

// MIT: `check_tgs_req` (do_tgs_req.c:905-905)
// MIT: `compute_ticket_times` (do_tgs_req.c:812-812)
// MIT: `check_tgs_req` (do_tgs_req.c:919-919)
// MIT: `tgs_issue_ticket` (do_tgs_req.c:980-980)
// MIT: `gather_tgs_req_info` (do_tgs_req.c:775-775)
fn tgs_flags_times_policy<'a>(
    store: &dyn PrincipalRead,
    body: &KdcReqBody,
    c: TgsChecked<'a>,
    now: &KerberosTime,
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
        transited,
        req_realm,
        tkt_client_realm,
        local_tgt,
    } = c;
    let subject_cname = stkt.as_ref().map_or(&enc_tkt.cname, |s| &s.part.cname);
    let subject_crealm = if let Some(st) = stkt.as_ref() {
        utf8_realm(&st.part.crealm)?
    } else {
        utf8_realm(&enc_tkt.crealm)?
    };
    let s4u_user_local = s4u_local.is_some();
    let tgs_client = if s4u2self {
        s4u_local
    } else if attr(&server, KDB_NO_AUTH_DATA_REQUIRED) {
        None
    } else if subject_crealm == store.realm() {
        store.fetch_client(subject_cname).ok().flatten()
    } else {
        None
    };
    let authtime;
    let starttime;
    let mut end;
    let mut flags;
    let mut ticket_renew_till;
    if renew {
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
    enforce_kdcpolicy_tgs(
        store,
        body,
        &server,
        &enc_tkt,
        &auth_indicators,
        now,
        &mut end,
        &mut ticket_renew_till,
    )?;
    // MIT: `check_tgs_req` (kdc/do_tgs_req.c:924-939)
    let skip_transited = body.kdc_options.bit(flag_bit::DISABLE_TRANSITED_CHECK);
    let cprinc = enc_tkt
        .cname
        .unparse_with_realm_lossy(utf8_realm(&enc_tkt.crealm)?);
    let sprinc = server.name.unparse_with_realm_lossy(&server.realm);
    let transit_checked = if skip_transited {
        krb5_log::klog::syslog(krb5_log::klog::Severity::Info, "not checking transit path");
        false
    } else if tkt_client_realm == "WELLKNOWN:ANONYMOUS" {
        true
    } else {
        match transited.realms_for(&tkt_client_realm, req_realm.as_str()) {
            Ok(h) => {
                let allowed = krb5_types::transited::transit_allowed(
                    &store.policy().capaths,
                    &tkt_client_realm,
                    &req_realm,
                    &h,
                );
                if !allowed {
                    crate::audit::log_bad_transit(&cprinc, &sprinc, &transited);
                }
                allowed
            }
            Err(e) => crate::audit::unexpected_transit_false(
                e,
                &tkt_client_realm,
                req_realm.as_str(),
                &cprinc,
                &sprinc,
                &transited,
            ),
        }
    };
    // Skip: no transited flag; renew, validate keep the header's.
    let inherited_t = (renew || validate) && enc_tkt.flags.bit(flag_bit::TRANSITED_POLICY_CHECKED);
    let set_transited_flag = !skip_transited && transit_checked;
    if !(inherited_t || set_transited_flag) && store.policy().reject_bad_transit {
        return Err(proto(err::POLICY, status::BAD_TRANSIT));
    }
    if set_transited_flag {
        flags = flags.with_bit(flag_bit::TRANSITED_POLICY_CHECKED, true);
    }
    // Ours only: after all of MIT's checks.
    if body.kdc_options.unsupported_bits() != 0 {
        return Err(proto(err::BADOPTION, status::UNKNOWN_REASON));
    }
    if renew && validate {
        return Err(proto(err::BADOPTION, status::TICKET_NOT_RENEWABLE));
    }
    // MIT: `tgs_issue_ticket` (do_tgs_req.c:978-1006)
    crate::audit::note_tgs(|f| f.stage = crate::audit::ISSUE_TKT);
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
    let session = random_key(session_etype)?;
    // MIT: `rep_etypes2str` (kdc/kdc_util.c:1219-1226)
    crate::audit::note_tgs(|f| f.ses = Some(session_etype.to_iana()));
    let (tkt_key, tkt_kvno, tkt_etype) = if let Some(((k, kv, et), _)) = u2u {
        (k, kv, et)
    } else {
        let skey = store
            .policy()
            .first_current_key(&server)
            .map_err(|e| proto_d(err::GENERIC, status::FINDING_SERVER_KEY, e.message()))?;
        (skey.key.clone(), skey.kvno, skey.etype)
    };
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
        s4u_user_local,
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
        local_tgt,
    })
}

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
        s4u_user_local,
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
        local_tgt: LocalTgt {
            entry: krbtgt_p,
            key: krbtgt_key,
        },
    } = t;
    let include_pac = include_pac_for_reply(
        store,
        &server,
        tgs_padata,
        false,
        subject_pac.is_some(),
        flags.bit(flag_bit::ANONYMOUS),
    );
    // MIT: `gather_tgs_req_info` (do_tgs_req.c:692-695)
    // Local S4U2Self: that user's PAC; other requests carry the ticket's.
    let initial = s4u2self && s4u_user_local;
    let ad_data =
        include_pac && crate::ad::pac_has_ad_data(store.policy(), subject_pac.as_deref(), initial);
    // MIT: `handle_pac` (kdc_authdata.c:559-564)
    // An AD-shaped referral krbtgt is checksummed under its own key.
    let privsvr_tgt_key =
        if ad_data && server.name.is_krbtgt() && !server.name.is_krbtgt_for(store.realm()) {
            &tkt_key
        } else {
            &krbtgt_key.key
        };
    // MIT: `update_delegation_info` (kdc_authdata.c:410-422)
    let delegation_hop = if s4u2proxy && !is_crossrealm {
        stkt.as_ref()
            .map(|st| st.server.name.unparse_with_realm_lossy(&st.server.realm))
    } else {
        None
    };
    let client_key = if let Some(sub) = authenticator.subkey.as_ref() {
        let st = EncryptionType::from_iana(sub.keytype)
            .or_else(|_| EncryptionType::known(sub.keytype))?;
        ProtocolKey::from_bytes(st, sub.keyvalue.as_ref())?
    } else {
        tgt_session.clone()
    };
    let s4u_client_info = if s4u2self || s4u2proxy {
        Some(if is_referral {
            match &s4u_subject {
                Some((n, r)) => format!("{}@{r}", n.components_joined_lossy()),
                None => ticket_cname.components_joined_lossy(),
            }
        } else {
            ticket_cname.components_joined_lossy()
        })
    } else {
        None
    };
    let extra_ad = handle_authdata(
        store.policy(),
        true,
        flags.bit(flag_bit::ANONYMOUS),
        body.enc_authorization_data.as_ref(),
        Some(&tgt_session),
        Some(&client_key),
        enc_tkt.authorization_data.as_ref(),
        Some(&session),
        Some((&krbtgt_p.name, store.realm())),
    )
    .map_err(|e| crate::ad::authdata_failed("TGS_REQ", e))?;
    let ticket_sname = if renew || validate {
        ap.ticket.sname.clone()
    } else if is_referral {
        server.name.clone()
    } else {
        sname.clone()
    };
    let updated_pac = match (ad_data, delegation_hop.as_deref(), subject_pac.as_deref()) {
        (true, Some(hop), Some(raw)) => Some(
            update_delegation_info(raw, &sname, hop)
                .map_err(|e| crate::ad::authdata_failed("TGS_REQ", e))?,
        ),
        _ => None,
    };
    let pac = if !include_pac {
        None
    } else if ad_data {
        Some(TicketPac::Ad {
            logon_override: evidence_logon.as_deref(),
            subject_pac: if initial {
                None
            } else {
                updated_pac.as_deref().or(subject_pac.as_deref())
            },
            s4u_client_info: s4u_client_info.as_deref(),
            identity: if initial {
                s4u_subject.as_ref().map(|(n, r)| (n, r.as_str()))
            } else {
                None
            },
        })
    } else {
        Some(TicketPac::Mit(crate::ad::HandlePac {
            subject: subject_pac.as_deref(),
            s4u: s4u2self || s4u2proxy,
            issuing_referral: is_referral,
            delegation: delegation_hop.as_deref().map(|hop| (&sname, hop)),
            altcprinc: s4u_subject.as_ref().map(|(n, r)| (n, r.as_str())),
        }))
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
        server: &server,
        privsvr_tgt_key,
        transited,
        renew_till: ticket_renew_till.clone(),
        store,
        pac,
        starttime: &starttime,
        caddr: tgs_ticket_caddr(body, renew, validate, &enc_tkt),
        extra_ad,
        indicators: &auth_indicators,
        krbtgt: &krbtgt_p,
        krbtgt_key: &krbtgt_key.key,
        no_auth_data: attr(&server, KDB_NO_AUTH_DATA_REQUIRED),
        kind: "TGS_REQ",
    })?;
    // MIT: `tgs_issue_ticket` (do_tgs_req.c:1056-1063)
    crate::audit::note_tgs(|f| {
        if body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY) {
            f.event("U2U", true);
        }
        f.stage = crate::audit::ENCR_REP;
    });
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
    let cipher = crate::ad::crypto_at(encrypt(&enc_key, usage, &enc_der), status::UNKNOWN_REASON)?;
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

// MIT: `get_2ndtkt_enctype` (do_tgs_req.c:310-328)
/// Second-ticket enctype is the session enctype only if listed.
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

// MIT: `decrypt_2ndtkt` (do_tgs_req.c:257-307)
fn decrypt_2ndtkt(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    local_tgt: &LocalTgt,
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
    let server = lookup_principal_id(&extra.sname, stkt_realm)
        .map(|id| store.fetch(&id))
        .transpose()?
        .flatten()
        .ok_or_else(|| proto(err::S_PRINCIPAL_UNKNOWN, status::SECOND_TKT_SERVER))?;
    if attr(&server, KDB_DISALLOW_ALL_TIX) || attr(&server, KDB_DISALLOW_SVR) {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::SECOND_TKT_SERVER));
    }
    // MIT: `kdc_get_server_key` (kdc_util.c:397-398)
    let Ok(tkt_etype) = EncryptionType::from_iana(extra.enc_part.etype)
        .or_else(|_| EncryptionType::known(extra.enc_part.etype))
    else {
        let text = crate::store::KeyLookup::NoPermittedKey.message();
        return Err(proto_d(err::GENERIC, status::SECOND_TKT_SERVER, text));
    };
    let kvno = extra.enc_part.kvno.unwrap_or(0);
    let (key, _) = find_server_key(store.policy(), &server, Some(tkt_etype), kvno)
        .map_err(|e| with_status(e, status::SECOND_TKT_SERVER))?;
    let usage = KeyUsage::new(ku::TICKET)?;
    let plain = decrypt_enc_data(
        &key,
        usage,
        extra.enc_part.etype,
        extra.enc_part.cipher.as_ref(),
    )
    .map_err(|_| proto(err::BAD_INTEGRITY, status::SECOND_TKT_DECRYPT))?;
    let part: EncTicketPart =
        decode(&plain).map_err(|_| proto(err::BAD_INTEGRITY, status::SECOND_TKT_DECRYPT))?;
    let pac = crate::ad::get_verified_pac(
        store.policy(),
        &part,
        &key,
        &server,
        &local_tgt.entry,
        &local_tgt.key,
    )
    .map_err(|e| with_status(e, status::SECOND_TKT_PAC))?;
    Ok(Some(SecondTicket { part, server, pac }))
}

fn u2u_from_stkt(st: &SecondTicket) -> Result<(ProtocolKey, u32, EncryptionType), Error> {
    let etype = EncryptionType::from_iana(st.part.key.keytype)
        .or_else(|_| EncryptionType::known(st.part.key.keytype))?;
    let key = ProtocolKey::from_bytes(etype, st.part.key.keyvalue.as_ref())?;
    Ok((key, 0, etype))
}

#[must_use]
pub fn tgs_header_is_crossrealm(header_server_realm: &str, sprinc_realm: &str) -> bool {
    header_server_realm != sprinc_realm
}

// MIT: `in_list` (do_tgs_req.c:417-431)
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

// MIT: `is_referral_req` (do_tgs_req.c:438-477)
/// No canonicalize, user-to-user, or no-referral service: no referral.
fn is_referral_req(store: &dyn PrincipalRead, body: &KdcReqBody, sname: &PrincipalName) -> bool {
    if !body.kdc_options.bit(flag_bit::CANONICALIZE)
        || body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY)
        || sname.name_string.len() != 2
    {
        return false;
    }
    let Some(stype) = sname
        .name_string
        .first()
        .and_then(|s| std::str::from_utf8(s.as_bytes()).ok())
    else {
        return false;
    };
    let hostbased = store.policy().host_based_services.as_str();
    let no_ref = store.policy().no_host_referral.as_str();
    match sname.name_type {
        PrincipalName::NT_UNKNOWN => {
            if !in_list(hostbased, stype) && !in_list(hostbased, "*") {
                return false;
            }
        }
        PrincipalName::NT_SRV_HST | PrincipalName::NT_SRV_INST => {}
        _ => return false,
    }
    !in_list(no_ref, stype) && !in_list(no_ref, "*")
}

// MIT: `find_referral_tgs` (do_tgs_req.c:483-523)
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
        .and_then(|s| std::str::from_utf8(s.as_bytes()).ok());
    let Some(host) = host else {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::LOOKING_UP_SERVER));
    };
    if !host.contains('.') || krb5_config::is_numeric_address(host) {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::LOOKING_UP_SERVER));
    }
    let Some(other) = store.policy().realm_for_host(host) else {
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

// MIT: `find_alternate_tgs` (do_tgs_req.c:370-414)
fn find_alternate_tgs(
    store: &dyn PrincipalRead,
    princ: &PrincipalName,
) -> Result<crate::store::Principal, Error> {
    let far = princ
        .name_string
        .get(1)
        .and_then(|s| std::str::from_utf8(s.as_bytes()).ok());
    let Some(far) = far else {
        return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::UNKNOWN_SERVER));
    };
    let hops = krb5_types::transited::walk_realm_tree(&store.policy().capaths, store.realm(), far);
    for inst in hops.iter().skip(1).rev() {
        let Ok(hop) = PrincipalName::try_new(PrincipalName::NT_SRV_INST, ["krbtgt", inst.as_str()])
        else {
            return Err(proto(err::S_PRINCIPAL_UNKNOWN, status::UNKNOWN_SERVER));
        };
        if let Some(p) = lookup_svc_princ(store, &hop)? {
            return Ok(p);
        }
    }
    Err(proto(err::S_PRINCIPAL_UNKNOWN, status::UNKNOWN_SERVER))
}

// MIT: `is_client_db_alias` (kdc/kdc_util.c:1534-1549)
fn is_client_db_alias(
    store: &dyn PrincipalRead,
    server: &Principal,
    enc_tkt: &EncTicketPart,
) -> bool {
    let entry = match utf8_realm(&enc_tkt.crealm) {
        Ok(realm) if realm == store.realm() => store.fetch_client(&enc_tkt.cname),
        Ok(realm) => crate::kdb::lookup_principal_id(&enc_tkt.cname, realm)
            .map_or(Ok(None), |id| store.fetch(&id)),
        Err(_) => Ok(None),
    };
    matches!(entry, Ok(Some(e)) if e.realm == server.realm && e.name == server.name)
}

// MIT: `search_sprinc` (do_tgs_req.c:541-581)
/// Forward, proxy, renew, validate, and user-to-user are not referred.
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

fn tgs_issuing_referral(
    requested: &PrincipalName,
    req_realm: &str,
    resolved: &crate::store::Principal,
) -> bool {
    resolved.name.is_cross_tgs_principal(&resolved.realm)
        && !krb5_types::principal_compare(&resolved.name, &resolved.realm, requested, req_realm)
}

/// A foreign ticket's logon info is SID-filtered.
fn carried_logon(
    store: &dyn PrincipalRead,
    ap: &krb5_types::ApReq,
    subject_pac: Option<&[u8]>,
) -> Result<Option<Vec<u8>>, Error> {
    let Some(logon) = subject_pac.and_then(|p| {
        let parsed = krb5_types::pac::Pac::parse(p).ok()?;
        parsed
            .unique_buffer(krb5_types::pac::PAC_LOGON_INFO)
            .ok()
            .flatten()
            .map(<[u8]>::to_vec)
    }) else {
        return Ok(None);
    };
    if utf8_realm(&ap.ticket.realm)? == store.realm() {
        return Ok(Some(logon));
    }
    crate::ad::filter_cross_realm_logon(&logon, store.domain_sid()).map(Some)
}

// MIT: `tgs_issue_ticket` (do_tgs_req.c:1012-1027)
/// Renew, validate: header addresses; forward, proxy: the request's.
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

pub(super) fn tgs_header_client(store: &dyn PrincipalRead, req: &TgsReq) -> Option<PrincipalName> {
    let pa_tgs = extract_pa_tgs(req.0.padata.as_deref())?;
    let ap: krb5_types::ApReq = decode(pa_tgs.as_ref()).ok()?;
    // A session-key or mutual header names no client on the error.
    if ap.ap_options.use_session_key() || ap.ap_options.wants_mutual() {
        return None;
    }
    let etype = EncryptionType::from_iana(ap.ticket.enc_part.etype)
        .or_else(|_| EncryptionType::known(ap.ticket.enc_part.etype))
        .ok()?;
    let (enc_tkt, _, _, _) = decrypt_presented_tgt(store, &ap, etype).ok()?;
    Some(enc_tkt.cname)
}

// MIT: `db_get_svc_princ` (do_tgs_req.c:525-538)
// MIT: `search_sprinc` (do_tgs_req.c:573-578)
/// Code 29 is kept; other lookup faults are 7, both LOOKING_UP_SERVER.
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
