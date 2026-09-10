//! A′-2 item 8 S4U2Proxy constraint and policy statuses.

use krb5_kdc::{
    PrincipalStore, TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
    as_req, bootstrap_documented, decrypt_ticket_part, documented_host, pa_enc_timestamp,
    pac_from_ticket_part,
};
use krb5_protocol::{tgs_req, tgs_req_ex};
use krb5_types::pac::{PAC_DELEGATION_INFO, Pac, parse_delegation_info};
use krb5_types::{KdcOptions, PrincipalName, err, flag_bit};

fn pref_etypes() -> Vec<i32> {
    krb5_crypto::EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect()
}

fn issue_tgt(
    store: &PrincipalStore,
    name: &str,
    password: &[u8],
    nonce: u32,
) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    let key = store
        .get_name(&cname)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let _ = password;
    let req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn evidence_for_user(store: &PrincipalStore, nonce: u32) -> krb5_types::Ticket {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = issue_tgt(store, TEST_ADMIN, TEST_ADMIN_PASSWORD, nonce);
    let req = tgs_req(
        admin_tgt.rep.0.ticket.clone(),
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user,
        TEST_REALM,
        nonce + 1,
    )
    .unwrap();
    krb5_kdc::issue_tgs(store, &req).unwrap().rep.0.ticket
}

fn proxy_req(
    store: &PrincipalStore,
    evidence: krb5_types::Ticket,
    dest: PrincipalName,
    opts: KdcOptions,
    nonce: u32,
) -> krb5_types::TgsReq {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_tgt = issue_tgt(store, TEST_USER, TEST_USER_PASSWORD, nonce);
    tgs_req_ex(
        user_tgt.rep.0.ticket,
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        dest,
        TEST_REALM,
        nonce + 1,
        opts,
        Some(vec![evidence]),
        Vec::new(),
        pref_etypes(),
    )
    .unwrap()
}

fn code(e: krb5_kdc::Error) -> (i32, Option<String>) {
    match e {
        krb5_kdc::Error::Protocol { code, text, .. } => (code, text),
        other => panic!("{other:?}"),
    }
}

fn cname_addl() -> KdcOptions {
    KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true)
}

#[test]
fn s4u2proxy_no_2nd_tkt_is_unknown_reason() {
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 8100);
    let req = tgs_req_ex(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        8101,
        cname_addl(),
        None,
        Vec::new(),
        pref_etypes(),
    )
    .unwrap();
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::GENERIC);
    assert_eq!(text.as_deref(), Some("UNKNOWN_REASON"));
}

#[test]
fn s4u2proxy_tgs_target_is_policy() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store.allow_s4u_to(&user, "krbtgt/KERBER.TEST");
    let ev = evidence_for_user(&store, 8110);
    let tgt = PrincipalName::krbtgt(TEST_REALM);
    let req = proxy_req(&store, ev, tgt, cname_addl(), 8112);
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::POLICY);
    assert_eq!(text.as_deref(), Some("NOT_ALLOWED_TO_DELEGATE"));
}

#[test]
fn s4u2proxy_evidence_mismatch_is_server_nomatch() {
    let (store, _) = bootstrap_documented().unwrap();
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 8120);
    let req = proxy_req(
        &store,
        admin_tgt.rep.0.ticket,
        documented_host(),
        cname_addl(),
        8122,
    );
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::SERVER_NOMATCH);
    assert_eq!(text.as_deref(), Some("EVIDENCE_TICKET_MISMATCH"));
}

#[test]
fn s4u2proxy_no_header_pac_is_tgt_revoked() {
    let (store, _) = bootstrap_documented().unwrap();
    let ev = evidence_for_user(&store, 8130);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 8132);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &tgt.rep.0.ticket).unwrap();
    part.authorization_data = None;
    let der = krb5_asn1::encode(&part).unwrap();
    let usage = krb5_crypto::KeyUsage::new(krb5_types::ku::TICKET).unwrap();
    let mut tkt = tgt.rep.0.ticket.clone();
    tkt.enc_part.cipher = krb5_crypto::encrypt(&krbtgt.key, usage, &der)
        .unwrap()
        .into();
    let req = tgs_req_ex(
        tkt,
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        8133,
        cname_addl(),
        Some(vec![ev]),
        Vec::new(),
        pref_etypes(),
    )
    .unwrap();
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::TGT_REVOKED);
    assert_eq!(text.as_deref(), Some("S4U2PROXY_NO_HEADER_PAC"));
}

#[test]
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
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::MODIFIED);
    assert_eq!(text.as_deref(), Some("S4U2PROXY_NO_STKT_PAC"));
}

#[test]
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
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
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
