//! Item 8 statuses that fail at parent `63e0a50` (inject this file only).

use krb5_kdc::{
    PrincipalStore, TEST_ADMIN, TEST_REALM, TEST_USER, as_req, bootstrap_documented,
    decrypt_ticket_part, documented_host, pa_enc_timestamp,
};
use krb5_protocol::{tgs_req, tgs_req_ex};
use krb5_types::{KdcOptions, PrincipalName, err, flag_bit};

fn pref_etypes() -> Vec<i32> {
    krb5_crypto::EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect()
}

fn issue_tgt(store: &PrincipalStore, name: &str, nonce: u32) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    let key = store
        .get_name(&cname)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
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
    let admin_tgt = issue_tgt(store, TEST_ADMIN, nonce);
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

fn cname_addl() -> KdcOptions {
    KdcOptions::forwardable().with_bit(flag_bit::CNAME_IN_ADDL_TKT, true)
}

fn code(e: krb5_kdc::Error) -> (i32, Option<String>) {
    match e {
        krb5_kdc::Error::Protocol { code, text, .. } => (code, text),
        other => panic!("{other:?}"),
    }
}

#[test]
fn s4u2proxy_tgs_target_is_policy() {
    let (store, _) = bootstrap_documented().unwrap();
    let ev = evidence_for_user(&store, 8210);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, 8212);
    let req = tgs_req_ex(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        8213,
        cname_addl(),
        Some(vec![ev]),
        Vec::new(),
        pref_etypes(),
    )
    .unwrap();
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::POLICY);
    assert_eq!(text.as_deref(), Some("NOT_ALLOWED_TO_DELEGATE"));
}

#[test]
fn s4u2proxy_evidence_mismatch_is_server_nomatch() {
    let (store, _) = bootstrap_documented().unwrap();
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, 8220);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, 8222);
    let req = tgs_req_ex(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        8223,
        cname_addl(),
        Some(vec![admin_tgt.rep.0.ticket]),
        Vec::new(),
        pref_etypes(),
    )
    .unwrap();
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::SERVER_NOMATCH);
    assert_eq!(text.as_deref(), Some("EVIDENCE_TICKET_MISMATCH"));
}

#[test]
fn s4u2proxy_no_stkt_pac_is_modified() {
    let (store, _) = bootstrap_documented().unwrap();
    let ev = evidence_for_user(&store, 8230);
    let user_p = store
        .get_name(&PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            [TEST_USER],
        ))
        .unwrap();
    let ukey = user_p.best_key().unwrap();
    let mut part = decrypt_ticket_part(&ukey.key, &ev).unwrap();
    part.authorization_data = None;
    let der = krb5_asn1::encode(&part).unwrap();
    let usage = krb5_crypto::KeyUsage::new(krb5_types::ku::TICKET).unwrap();
    let mut tkt = ev;
    tkt.enc_part.cipher = krb5_crypto::encrypt(&ukey.key, usage, &der).unwrap().into();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, 8232);
    let req = tgs_req_ex(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        8233,
        cname_addl(),
        Some(vec![tkt]),
        Vec::new(),
        pref_etypes(),
    )
    .unwrap();
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::MODIFIED);
    assert_eq!(text.as_deref(), Some("S4U2PROXY_NO_STKT_PAC"));
}

#[test]
fn s4u2proxy_no_header_pac_is_tgt_revoked() {
    let (store, _) = bootstrap_documented().unwrap();
    let ev = evidence_for_user(&store, 8240);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, 8242);
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
        8243,
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
