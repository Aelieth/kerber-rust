//! A′-2 item 8 S4U2Proxy constraint and policy statuses.
//! A′-2 R18: S4U2Proxy identity, PAC client info, cross-realm gather.
//! A′-2 R22: realm-aware RBCD ACL; create_host seeds no s4u_allowed_from.
//! Phase 5–8 protocol tests: kpasswd, FAST, SPAKE, PKINIT, PAC, S4U, U2U.
//!
//! These call shipped `issue_as` / `issue_tgs` / `PrincipalStore` entry
//! points from a bootstrapped realm. They fail if those paths are type-only.

use krb5_crypto::ProtocolKey;
use krb5_kdc::testrealm::{
    TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
    bootstrap_documented, documented_admin_id, documented_host,
};
use krb5_kdc::{
    Error, PacTicket, PrincipalStore, as_req, decrypt_ticket_part, pa_enc_timestamp,
    pac_from_ticket_part, sign_reply_pac, tgs_req, ticket_checksum_der, wrap_win2k_pac,
};

use krb5_protocol::pa_pac_options;
use krb5_testkit::{
    TgsReqBuilder, aes_key, attach_pac, evidence_for_user, expect_status, host_tgt, issue_tgt,
    issue_tgt_password, pref_etypes, reseal, reseal_incoming,
};
use krb5_types::pac::{
    PAC_CLIENT_INFO, PAC_DELEGATION_INFO, PAC_LOGON_INFO, Pac, PacBuffer, PacIdentity, RpcSid,
    client_info_buffer, parse_client_info, parse_delegation_info, parse_kerb_validation_info,
};
use krb5_types::{EncTicketPart, KdcOptions, PrincipalName, Ticket, err, flag_bit, pa};

fn proxy_req(
    store: &PrincipalStore,
    evidence: krb5_types::Ticket,
    dest: PrincipalName,
    opts: KdcOptions,
    nonce: u32,
) -> krb5_types::TgsReq {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_tgt = issue_tgt(store, TEST_USER, nonce);
    TgsReqBuilder::new(
        user_tgt.rep.0.ticket,
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        dest,
        TEST_REALM,
        nonce + 1,
    )
    .options(opts)
    .additional_tickets(Some(vec![evidence]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap()
}

fn cname_addl() -> KdcOptions {
    KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true)
}

#[test]
// oracle: differential-gate.sh s4u2proxy-no-2nd-tkt
fn s4u2proxy_no_2nd_tkt_is_unknown_reason() {
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, 8100);
    let req = TgsReqBuilder::new(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        8101,
    )
    .options(cname_addl())
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::GENERIC);
    assert_eq!(text.as_deref(), Some("UNKNOWN_REASON"));
}

#[test]
// oracle: differential-gate.sh s4u2proxy-tgs-target
fn s4u2proxy_tgs_target_is_policy() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store.allow_s4u_to(&user, "krbtgt/KERBER.TEST");
    let ev = evidence_for_user(&store, 8110);
    let tgt = PrincipalName::krbtgt(TEST_REALM);
    let req = proxy_req(&store, ev, tgt, cname_addl(), 8112);
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::POLICY);
    assert_eq!(text.as_deref(), Some("NOT_ALLOWED_TO_DELEGATE"));
}

#[test]
// oracle: differential-gate.sh s4u2proxy-evidence-mismatch
fn s4u2proxy_evidence_mismatch_is_server_nomatch() {
    let (store, _) = bootstrap_documented().unwrap();
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, 8120);
    let req = proxy_req(
        &store,
        admin_tgt.rep.0.ticket,
        documented_host(),
        cname_addl(),
        8122,
    );
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::SERVER_NOMATCH);
    assert_eq!(text.as_deref(), Some("EVIDENCE_TICKET_MISMATCH"));
}

#[test]
// oracle: differential-gate.sh s4u2proxy-no-header-pac
fn s4u2proxy_no_header_pac_is_tgt_revoked() {
    let (store, _) = bootstrap_documented().unwrap();
    let ev = evidence_for_user(&store, 8130);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, 8132);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &tgt.rep.0.ticket).unwrap();
    part.authorization_data = None;
    let der = krb5_asn1::encode(&part).unwrap();
    let usage = krb5_crypto::KeyUsage::new(krb5_types::ku::TICKET).unwrap();
    let mut tkt = tgt.rep.0.ticket.clone();
    tkt.enc_part.cipher = krb5_crypto::encrypt(&krbtgt.key, usage, &der)
        .unwrap()
        .into();
    let req = TgsReqBuilder::new(
        tkt,
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        8133,
    )
    .options(cname_addl())
    .additional_tickets(Some(vec![ev]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::TGT_REVOKED);
    assert_eq!(text.as_deref(), Some("S4U2PROXY_NO_HEADER_PAC"));
}

#[test]
// oracle: differential-gate.sh s4u2proxy-no-stkt-pac
fn s4u2proxy_no_stkt_pac_is_modified() {
    let (store, _) = bootstrap_documented().unwrap();
    let ev = evidence_for_user(&store, 8140);
    let user = store
        .get_name(&PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            [TEST_USER],
        ))
        .unwrap();
    let ukey = user.best_key().unwrap();
    let mut part = decrypt_ticket_part(&ukey.key, &ev).unwrap();
    part.authorization_data = None;
    let der = krb5_asn1::encode(&part).unwrap();
    let usage = krb5_crypto::KeyUsage::new(krb5_types::ku::TICKET).unwrap();
    let mut tkt = ev;
    tkt.enc_part.cipher = krb5_crypto::encrypt(&ukey.key, usage, &der).unwrap().into();
    let req = proxy_req(&store, tkt, documented_host(), cname_addl(), 8142);
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::MODIFIED);
    assert_eq!(text.as_deref(), Some("S4U2PROXY_NO_STKT_PAC"));
}

#[test]
// oracle: differential-gate.sh s4u2proxy-u2u-combo
fn s4u2proxy_u2u_combo_is_invalid_options() {
    let (store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    let hkey = store
        .get_name(&host)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let host_as = as_req(
        host.clone(),
        TEST_REALM,
        8150,
        Some(vec![pa_enc_timestamp(&hkey).unwrap()]),
    )
    .unwrap();
    let host_tgt = krb5_kdc::issue_as(&store, &host_as).unwrap();
    let opts = cname_addl().with_bit(flag_bit::ENC_TKT_IN_SKEY, true);
    let req = proxy_req(&store, host_tgt.rep.0.ticket, host, opts, 8152);
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("INVALID_S4U2PROXY_OPTIONS"));
}

#[test]
fn s4u2proxy_first_hop_adds_delegation_info() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store.allow_s4u_to(&user, &documented_host().components_joined());
    let ev = evidence_for_user(&store, 8160);
    let req = proxy_req(&store, ev, documented_host(), cname_addl(), 8162);
    let out = krb5_kdc::issue_tgs(&store, &req).expect("S4U2Proxy");
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let part = decrypt_ticket_part(&host.key, &out.rep.0.ticket).unwrap();
    let pac = Pac::parse(&pac_from_ticket_part(&part).unwrap()).unwrap();
    let buf = pac.unique_buffer(PAC_DELEGATION_INFO).unwrap().unwrap();
    let di = parse_delegation_info(buf).unwrap();
    assert_eq!(di.proxy_target, documented_host().unparse());
    assert_eq!(
        di.transited_services.last().unwrap(),
        &format!("{TEST_USER}@{TEST_REALM}")
    );
    assert_eq!(out.rep.0.cname.components_joined(), TEST_ADMIN);
}

const FOREIGN: &str = "OTHER.TEST";

const SUBJECT: &str = "alice";

const SUBJECT_REALM: &str = "ALICE.TEST";

fn attach_stkt_pac(
    server: &ProtocolKey,
    kdc: &ProtocolKey,
    part: &mut EncTicketPart,
    info_name: &str,
) {
    let stub = Pac::built(
        0,
        vec![PacBuffer::new(
            PAC_CLIENT_INFO,
            client_info_buffer(part.authtime.unix_seconds(), info_name),
        )],
    )
    .to_bytes();
    part.authorization_data = Some(wrap_win2k_pac(&[0]).unwrap());
    let der = ticket_checksum_der(part).unwrap();
    let ident = PacIdentity {
        sam: part.cname.components_joined(),
        realm: String::new(),
        domain_sid: RpcSid::nt_domain(1, 2, 3),
        rid: 1,
    };
    let pac = sign_reply_pac(
        &part.cname,
        part.authtime.unix_seconds(),
        &PacTicket {
            server,
            kdc,
            enc_tkt_der: &der,
            is_service_tkt: true,
        },
        &ident,
        None,
        Some(&stub),
    )
    .unwrap();
    part.authorization_data = Some(wrap_win2k_pac(&pac).unwrap());
}

fn attach_deleg_pac(key: &ProtocolKey, part: &mut EncTicketPart, info_name: &str, transited: &str) {
    let di = krb5_types::pac::S4uDelegationInfo {
        proxy_target: documented_host().unparse(),
        transited_services: vec![transited.to_owned()],
    };
    let stub = Pac::built(
        0,
        vec![
            PacBuffer::new(
                PAC_CLIENT_INFO,
                client_info_buffer(part.authtime.unix_seconds(), info_name),
            ),
            PacBuffer::new(
                PAC_DELEGATION_INFO,
                krb5_types::pac::delegation_info_buffer(&di),
            ),
        ],
    )
    .to_bytes();
    part.authorization_data = Some(wrap_win2k_pac(&[0]).unwrap());
    let der = ticket_checksum_der(part).unwrap();
    let ident = PacIdentity {
        sam: part.cname.components_joined(),
        realm: String::new(),
        domain_sid: RpcSid::nt_domain(1, 2, 3),
        rid: 1,
    };
    let pac = sign_reply_pac(
        &part.cname,
        part.authtime.unix_seconds(),
        &PacTicket {
            server: key,
            kdc: key,
            enc_tkt_der: &der,
            is_service_tkt: false,
        },
        &ident,
        None,
        Some(&stub),
    )
    .unwrap();
    part.authorization_data = Some(wrap_win2k_pac(&pac).unwrap());
}

fn cross_store() -> (PrincipalStore, ProtocolKey) {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let ir = aes_key(0x44);
    store
        .create_interrealm_key(&acl, &documented_admin_id(), FOREIGN, ir.clone())
        .unwrap();
    store.allow_s4u_from(
        &documented_host(),
        &documented_host().unparse_with_realm(FOREIGN),
    );
    (store, ir)
}

fn foreign_host_header(
    store: &PrincipalStore,
    ir: &ProtocolKey,
    nonce: u32,
) -> (Ticket, ProtocolKey) {
    let tgt = host_tgt(store, nonce);
    let local = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut part = decrypt_ticket_part(&local, &tgt.rep.0.ticket).unwrap();
    part.cname = documented_host();
    part.crealm = krb5_types::try_ascii(FOREIGN).unwrap();
    part.flags = part.flags.with_bit(flag_bit::FORWARDABLE, true);
    attach_pac(ir, &mut part, &documented_host().components_joined());
    (reseal_incoming(ir, &tgt, &part), tgt.session_key)
}

fn cross_evidence(
    store: &PrincipalStore,
    ir: &ProtocolKey,
    nonce: u32,
    crealm: &str,
    info_name: &str,
) -> Ticket {
    let tgt = host_tgt(store, nonce);
    let local = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut part = decrypt_ticket_part(&local, &tgt.rep.0.ticket).unwrap();
    part.cname = documented_host();
    part.crealm = krb5_types::try_ascii(crealm).unwrap();
    part.flags = part.flags.with_bit(flag_bit::FORWARDABLE, true);
    let hop = documented_host().unparse_with_realm(crealm);
    attach_deleg_pac(ir, &mut part, info_name, &hop);
    reseal_incoming(ir, &tgt, &part)
}

fn proxy_cross(
    header: Ticket,
    session: &ProtocolKey,
    evidence: Ticket,
    nonce: u32,
) -> krb5_types::TgsReq {
    let host = documented_host();
    TgsReqBuilder::new(
        header,
        session,
        FOREIGN,
        &host,
        host.clone(),
        TEST_REALM,
        nonce,
    )
    .options(cname_addl())
    .additional_tickets(Some(vec![evidence]))
    .padata(vec![pa_pac_options(true).unwrap()])
    .etypes(pref_etypes())
    .build()
    .unwrap()
}

#[test]
fn local_s4u2proxy_client_info_omits_realm() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    store.allow_s4u_to(&user, &documented_host().components_joined());
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = {
        let key = store
            .get_name(&admin)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let req = as_req(
            admin.clone(),
            TEST_REALM,
            18000,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&store, &req).unwrap()
    };
    let ev = krb5_kdc::issue_tgs(
        &store,
        &TgsReqBuilder::new(
            admin_tgt.rep.0.ticket.clone(),
            &admin_tgt.session_key,
            TEST_REALM,
            &admin,
            user.clone(),
            TEST_REALM,
            18001,
        )
        .options(KdcOptions::forwardable())
        .additional_tickets(None)
        .padata(vec![])
        .etypes(pref_etypes())
        .build()
        .unwrap(),
    )
    .unwrap()
    .rep
    .0
    .ticket;
    let user_tgt = {
        let key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let req = as_req(
            user.clone(),
            TEST_REALM,
            18002,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&store, &req).unwrap()
    };
    let out = krb5_kdc::issue_tgs(
        &store,
        &TgsReqBuilder::new(
            user_tgt.rep.0.ticket,
            &user_tgt.session_key,
            TEST_REALM,
            &user,
            documented_host(),
            TEST_REALM,
            18003,
        )
        .options(cname_addl())
        .additional_tickets(Some(vec![ev]))
        .padata(vec![])
        .etypes(pref_etypes())
        .build()
        .unwrap(),
    )
    .unwrap();
    let hostk = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let part = decrypt_ticket_part(&hostk.key, &out.rep.0.ticket).unwrap();
    assert_eq!(part.cname.components_joined(), TEST_ADMIN);
    let pac = Pac::parse(&pac_from_ticket_part(&part).unwrap()).unwrap();
    let (_, name) =
        parse_client_info(pac.unique_buffer(PAC_CLIENT_INFO).unwrap().unwrap()).unwrap();
    assert!(!name.contains('@'), "{name}");
    let di =
        parse_delegation_info(pac.unique_buffer(PAC_DELEGATION_INFO).unwrap().unwrap()).unwrap();
    assert_eq!(di.proxy_target, documented_host().unparse());
}

#[test]
fn cross_stkt_realm_mismatch_is_xrealm() {
    let (store, ir) = cross_store();
    let (header, session) = foreign_host_header(&store, &ir, 18100);
    let ev = cross_evidence(
        &store,
        &ir,
        18110,
        "THIRD.TEST",
        &format!("{SUBJECT}@{SUBJECT_REALM}"),
    );
    let (c, text) = expect_status(
        krb5_kdc::issue_tgs(&store, &proxy_cross(header, &session, ev, 18120)).unwrap_err(),
    );
    assert_eq!(c, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("XREALM_EVIDENCE_TICKET_MISMATCH"));
}

#[test]
fn cross_pac_without_realm_is_rbcd_pac_princ() {
    let (store, ir) = cross_store();
    let (header, session) = foreign_host_header(&store, &ir, 18200);
    let ev = cross_evidence(&store, &ir, 18210, FOREIGN, SUBJECT);
    let (c, text) = expect_status(
        krb5_kdc::issue_tgs(&store, &proxy_cross(header, &session, ev, 18220)).unwrap_err(),
    );
    assert_eq!(c, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("RBCD_PAC_PRINC"));
}

#[test]
fn cross_tkt_client_realm_is_transited() {
    let (store, ir) = cross_store();
    let (header, session) = foreign_host_header(&store, &ir, 18250);
    let ev = cross_evidence(
        &store,
        &ir,
        18260,
        FOREIGN,
        &format!("{SUBJECT}@{SUBJECT_REALM}"),
    );
    let (c, text) = expect_status(
        krb5_kdc::issue_tgs(&store, &proxy_cross(header, &session, ev, 18270)).unwrap_err(),
    );
    assert_eq!(c, err::POLICY);
    assert_eq!(text.as_deref(), Some("BAD_TRANSIT"));
}

#[test]
fn cross_issues_pac_client_and_realm() {
    let (mut store, ir) = cross_store();
    store.policy.reject_bad_transit = false;
    let (header, session) = foreign_host_header(&store, &ir, 18300);
    let ev = cross_evidence(
        &store,
        &ir,
        18310,
        FOREIGN,
        &format!("{SUBJECT}@{SUBJECT_REALM}"),
    );
    let out = krb5_kdc::issue_tgs(&store, &proxy_cross(header, &session, ev, 18320))
        .expect("cross S4U2Proxy");
    let hostk = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let part = decrypt_ticket_part(&hostk.key, &out.rep.0.ticket).unwrap();
    assert_eq!(part.cname.components_joined(), SUBJECT);
    assert_eq!(
        std::str::from_utf8(part.crealm.as_bytes()).unwrap(),
        SUBJECT_REALM
    );
    let pac = Pac::parse(&pac_from_ticket_part(&part).unwrap()).unwrap();
    let (_, name) =
        parse_client_info(pac.unique_buffer(PAC_CLIENT_INFO).unwrap().unwrap()).unwrap();
    assert_eq!(name, SUBJECT);
    let di =
        parse_delegation_info(pac.unique_buffer(PAC_DELEGATION_INFO).unwrap().unwrap()).unwrap();
    assert_eq!(di.proxy_target, documented_host().unparse());
}

fn extra_host() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "rbcd.kerber.test"])
}

fn attach_deleg_pac_a2_r22(
    key: &ProtocolKey,
    part: &mut EncTicketPart,
    info_name: &str,
    transited: &str,
    dest: &PrincipalName,
) {
    let di = krb5_types::pac::S4uDelegationInfo {
        proxy_target: dest.unparse(),
        transited_services: vec![transited.to_owned()],
    };
    let stub = Pac::built(
        0,
        vec![
            PacBuffer::new(
                PAC_CLIENT_INFO,
                client_info_buffer(part.authtime.unix_seconds(), info_name),
            ),
            PacBuffer::new(
                PAC_DELEGATION_INFO,
                krb5_types::pac::delegation_info_buffer(&di),
            ),
        ],
    )
    .to_bytes();
    part.authorization_data = Some(wrap_win2k_pac(&[0]).unwrap());
    let der = ticket_checksum_der(part).unwrap();
    let ident = PacIdentity {
        sam: part.cname.components_joined(),
        realm: String::new(),
        domain_sid: RpcSid::nt_domain(1, 2, 3),
        rid: 1,
    };
    let pac = sign_reply_pac(
        &part.cname,
        part.authtime.unix_seconds(),
        &PacTicket {
            server: key,
            kdc: key,
            enc_tkt_der: &der,
            is_service_tkt: false,
        },
        &ident,
        None,
        Some(&stub),
    )
    .unwrap();
    part.authorization_data = Some(wrap_win2k_pac(&pac).unwrap());
}

fn foreign_header(store: &PrincipalStore, ir: &ProtocolKey, nonce: u32) -> (Ticket, ProtocolKey) {
    let tgt = host_tgt(store, nonce);
    let local = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut part = decrypt_ticket_part(&local, &tgt.rep.0.ticket).unwrap();
    part.cname = documented_host();
    part.crealm = krb5_types::try_ascii(FOREIGN).unwrap();
    part.flags = part.flags.with_bit(flag_bit::FORWARDABLE, true);
    attach_pac(ir, &mut part, &documented_host().components_joined());
    (reseal_incoming(ir, &tgt, &part), tgt.session_key)
}

fn foreign_evidence(store: &PrincipalStore, ir: &ProtocolKey, nonce: u32) -> Ticket {
    let tgt = host_tgt(store, nonce);
    let local = store.krbtgt().unwrap().best_key().unwrap().key.clone();
    let mut part = decrypt_ticket_part(&local, &tgt.rep.0.ticket).unwrap();
    part.cname = documented_host();
    part.crealm = krb5_types::try_ascii(FOREIGN).unwrap();
    part.flags = part.flags.with_bit(flag_bit::FORWARDABLE, true);
    let hop = documented_host().unparse_with_realm(FOREIGN);
    attach_deleg_pac_a2_r22(
        ir,
        &mut part,
        &format!("{SUBJECT}@{SUBJECT_REALM}"),
        &hop,
        &extra_host(),
    );
    reseal_incoming(ir, &tgt, &part)
}

fn proxy_cross_a2_r22(
    header: Ticket,
    session: &ProtocolKey,
    evidence: Ticket,
    nonce: u32,
) -> krb5_types::TgsReq {
    let dest = extra_host();
    TgsReqBuilder::new(
        header,
        session,
        FOREIGN,
        &documented_host(),
        dest,
        TEST_REALM,
        nonce,
    )
    .options(cname_addl())
    .additional_tickets(Some(vec![evidence]))
    .padata(vec![pa_pac_options(true).unwrap()])
    .etypes(pref_etypes())
    .build()
    .unwrap()
}

fn store_with_ir() -> (PrincipalStore, ProtocolKey) {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let ir = aes_key(0x44);
    store
        .create_interrealm_key(&acl, &documented_admin_id(), FOREIGN, ir.clone())
        .unwrap();
    store
        .create_host(&acl, &documented_admin_id(), &extra_host())
        .unwrap();
    store.policy.reject_bad_transit = false;
    (store, ir)
}

#[test]
fn create_host_has_no_s4u_from() {
    let (store, _) = bootstrap_documented().unwrap();
    let host = store.get_name(&documented_host()).expect("host");
    assert!(host.s4u_allowed_from.is_empty());
}

#[test]
fn foreign_impersonator_vs_local_grant_is_not_allowed() {
    let (mut store, ir) = store_with_ir();
    store.allow_s4u_from(&extra_host(), &documented_host().components_joined());
    let (header, session) = foreign_header(&store, &ir, 22000);
    let ev = foreign_evidence(&store, &ir, 22010);
    let (c, text) = expect_status(
        krb5_kdc::issue_tgs(&store, &proxy_cross_a2_r22(header, &session, ev, 22020)).unwrap_err(),
    );
    assert_eq!(c, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("NOT_ALLOWED_TO_DELEGATE"));
}

#[test]
fn realm_qualified_foreign_grant_matches() {
    let (mut store, ir) = store_with_ir();
    store.allow_s4u_from(
        &extra_host(),
        &documented_host().unparse_with_realm(FOREIGN),
    );
    let (header, session) = foreign_header(&store, &ir, 22100);
    let ev = foreign_evidence(&store, &ir, 22110);
    krb5_kdc::issue_tgs(&store, &proxy_cross_a2_r22(header, &session, ev, 22120))
        .expect("realm-qualified RBCD");
}

#[test]
fn s4u2proxy_takes_cname_from_evidence() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    store.allow_s4u_to(&user, &documented_host().components_joined());
    let admin_tgt = issue_tgt_password(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 701);
    let evidence_tgs = tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        702,
    )
    .expect("evidence TGS-REQ");
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).expect("evidence");
    let user_tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 703);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let tgs = TgsReqBuilder::new(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        704,
    )
    .options(opts)
    .additional_tickets(Some(vec![evidence.rep.0.ticket.clone()]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .expect("S4U2Proxy TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("S4U2Proxy");
    assert_eq!(out.rep.0.cname.components_joined(), TEST_ADMIN);
    let host = store
        .get_name(&documented_host())
        .unwrap()
        .best_key()
        .unwrap();
    let part = decrypt_ticket_part(&host.key, &out.rep.0.ticket).expect("enc");
    assert_eq!(part.cname.components_joined(), TEST_ADMIN);
    let pac = pac_from_ticket_part(&part).expect("copied PAC");
    let parsed = krb5_types::pac::Pac::parse(&pac).expect("PAC");
    let logon =
        parse_kerb_validation_info(parsed.buffer(PAC_LOGON_INFO).expect("logon")).expect("NDR");
    assert_eq!(logon.user_id, store.get_name(&admin).unwrap().rid);
    assert_eq!(logon.effective_name.value, TEST_ADMIN);
}

#[test]
// oracle: differential-gate.sh s4u2proxy-not-forwardable
fn s4u2proxy_rejects_non_forwardable_evidence() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = issue_tgt_password(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 711);
    let evidence_tgs = TgsReqBuilder::new(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        712,
    )
    .options(KdcOptions::none())
    .additional_tickets(None)
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .expect("non-forwardable evidence TGS-REQ");
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).expect("evidence");
    let user_long = store.get_name(&user).unwrap().best_key().unwrap();
    let ev_part = decrypt_ticket_part(&user_long.key, &evidence.rep.0.ticket).expect("ev");
    assert!(
        !ev_part.flags.forwardable(),
        "fixture must be a non-forwardable evidence ticket"
    );
    let user_tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 713);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let tgs = TgsReqBuilder::new(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        714,
    )
    .options(opts)
    .additional_tickets(Some(vec![evidence.rep.0.ticket.clone()]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .expect("S4U2Proxy TGS-REQ");
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, text, .. }) => {
            assert_eq!(code, err::BADOPTION);
            assert_eq!(text.as_deref(), Some("EVIDENCE_TKT_NOT_FORWARDABLE"));
        }
        other => panic!("expected BADOPTION, got {other:?}"),
    }
}

#[test]
// oracle: differential-gate.sh s4u2proxy-header-pac
fn s4u2proxy_header_pac_mismatch_is_badoption() {
    let (store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    let tgt = host_tgt(&store, 8200);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &tgt.rep.0.ticket).unwrap();
    attach_pac(&krbtgt.key, &mut part, TEST_USER);
    let header = reseal(&tgt.rep.0.ticket, &part, &krbtgt.key);
    let ev = evidence_for_user(&store, 8202);
    let req = TgsReqBuilder::new(
        header,
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        8203,
    )
    .options(cname_addl())
    .additional_tickets(Some(vec![ev]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .unwrap();
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("S4U2PROXY_HEADER_PAC"));
}

#[test]
// oracle: differential-gate.sh s4u2proxy-local-stkt-pac
fn s4u2proxy_local_stkt_pac_mismatch_is_badoption() {
    let (store, _) = bootstrap_documented().unwrap();
    let ev = evidence_for_user(&store, 8210);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let ukey = store.get_name(&user).unwrap().best_key().unwrap();
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&ukey.key, &ev).unwrap();
    attach_stkt_pac(
        &ukey.key,
        &krbtgt.key,
        &mut part,
        &documented_host().components_joined(),
    );
    let tkt = reseal(&ev, &part, &ukey.key);
    let req = proxy_req(&store, tkt, documented_host(), cname_addl(), 8212);
    let (c, text) = expect_status(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::BADOPTION);
    assert_eq!(text.as_deref(), Some("S4U2PROXY_LOCAL_STKT_PAC"));
}

#[test]
fn s4u2proxy_rejects_malformed_pac_options() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = issue_tgt_password(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 721);
    let evidence_tgs = tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        722,
    )
    .expect("evidence TGS-REQ");
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).expect("evidence");
    let user_tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 723);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let bad = krb5_types::PaData {
        padata_type: pa::PAC_OPTIONS,
        padata_value: b"not-der".to_vec().into(),
    };
    let tgs = TgsReqBuilder::new(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        724,
    )
    .options(opts)
    .additional_tickets(Some(vec![evidence.rep.0.ticket.clone()]))
    .padata(vec![bad])
    .etypes(pref_etypes())
    .build()
    .expect("S4U2Proxy TGS-REQ");
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::BADOPTION),
        other => panic!("expected BADOPTION for malformed PA-PAC-OPTIONS, got {other:?}"),
    }
}

#[test]
fn s4u2proxy_classic_denied_without_allowed_to() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = issue_tgt_password(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 751);
    let evidence_tgs = tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        752,
    )
    .expect("evidence TGS-REQ");
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).expect("evidence");
    let user_tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 753);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let tgs = TgsReqBuilder::new(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        754,
    )
    .options(opts)
    .additional_tickets(Some(vec![evidence.rep.0.ticket.clone()]))
    .padata(Vec::new())
    .etypes(pref_etypes())
    .build()
    .expect("S4U2Proxy TGS-REQ");
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::BADOPTION),
        other => panic!("classic S4U2Proxy without allowed-to must deny, got {other:?}"),
    }
}

#[test]
fn s4u2proxy_honors_pac_options_rbcd() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = issue_tgt_password(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 731);
    let evidence_tgs = tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        732,
    )
    .expect("evidence TGS-REQ");
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).expect("evidence");
    let user_tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 733);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let tgs = TgsReqBuilder::new(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        734,
    )
    .options(opts)
    .additional_tickets(Some(vec![evidence.rep.0.ticket.clone()]))
    .padata(vec![pa_pac_options(true).expect("PA-PAC-OPTIONS")])
    .etypes(pref_etypes())
    .build()
    .expect("S4U2Proxy TGS-REQ");
    match krb5_kdc::issue_tgs(&store, &tgs) {
        Err(Error::Protocol { code, .. }) => assert_eq!(code, err::BADOPTION),
        other => panic!("RBCD without allow-list must deny, got {other:?}"),
    }
}

#[test]
fn s4u2proxy_rbcd_allowed_from_succeeds() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    store.allow_s4u_from(&documented_host(), &user.components_joined());
    let admin_tgt = issue_tgt_password(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 741);
    let evidence_tgs = tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user.clone(),
        TEST_REALM,
        742,
    )
    .expect("evidence TGS-REQ");
    let evidence = krb5_kdc::issue_tgs(&store, &evidence_tgs).expect("evidence");
    let user_tgt = issue_tgt_password(&store, TEST_USER, TEST_USER_PASSWORD, 743);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true);
    let tgs = TgsReqBuilder::new(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        744,
    )
    .options(opts)
    .additional_tickets(Some(vec![evidence.rep.0.ticket.clone()]))
    .padata(vec![pa_pac_options(true).expect("PA-PAC-OPTIONS")])
    .etypes(pref_etypes())
    .build()
    .expect("S4U2Proxy TGS-REQ");
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("RBCD allowed");
    assert_eq!(out.rep.0.cname.components_joined(), TEST_ADMIN);
}
