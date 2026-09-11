//! Item 9 statuses that fail at parent `30e0192` (inject this file only).

use krb5_asn1::encode;
use krb5_crypto::{KeyUsage, encrypt};
use krb5_kdc::{
    PrincipalStore, TEST_ADMIN, TEST_REALM, TEST_USER, as_req, bootstrap_documented,
    decrypt_ticket_part, documented_host, pa_enc_timestamp,
};
use krb5_protocol::{tgs_req, tgs_req_ex};
use krb5_types::{KdcOptions, PrincipalName, err, flag_bit, ku};

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

fn issue_host_tgt(store: &PrincipalStore, nonce: u32) -> krb5_kdc::IssuedAs {
    let host = documented_host();
    let key = store
        .get_name(&host)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        host,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn u2u_opts() -> KdcOptions {
    KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true)
}

fn u2u_req(
    store: &PrincipalStore,
    dest: PrincipalName,
    extra: krb5_types::Ticket,
    nonce: u32,
) -> krb5_types::TgsReq {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(store, TEST_USER, nonce);
    tgs_req_ex(
        tgt.rep.0.ticket,
        &tgt.session_key,
        TEST_REALM,
        &user,
        dest,
        TEST_REALM,
        nonce + 1,
        u2u_opts(),
        Some(vec![extra]),
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

#[test]
fn u2u_admin_tgt_for_host_is_mismatch() {
    let (store, _) = bootstrap_documented().unwrap();
    let admin = issue_tgt(&store, TEST_ADMIN, 9220);
    let req = u2u_req(&store, documented_host(), admin.rep.0.ticket, 9221);
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::SERVER_NOMATCH);
    assert_eq!(text.as_deref(), Some("2ND_TKT_MISMATCH"));
}

#[test]
fn u2u_service_ticket_is_not_tgs() {
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let tgt = issue_tgt(&store, TEST_USER, 9210);
    let svc = tgs_req(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        9211,
    )
    .unwrap();
    let extra = krb5_kdc::issue_tgs(&store, &svc).unwrap().rep.0.ticket;
    let req = u2u_req(&store, documented_host(), extra, 9212);
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::POLICY);
    assert_eq!(text.as_deref(), Some("2ND_TKT_NOT_TGS"));
}

#[test]
fn u2u_bad_session_etype_is_etype_nosupp() {
    let (store, _) = bootstrap_documented().unwrap();
    let host = issue_host_tgt(&store, 9230);
    let krbtgt = store.krbtgt().unwrap().best_key().unwrap();
    let mut part = decrypt_ticket_part(&krbtgt.key, &host.rep.0.ticket).unwrap();
    part.key.keytype = 99;
    let der = encode(&part).unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let mut extra = host.rep.0.ticket.clone();
    extra.enc_part.cipher = encrypt(&krbtgt.key, usage, &der).unwrap().into();
    let req = u2u_req(&store, documented_host(), extra, 9231);
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::ETYPE_NOSUPP);
    assert_eq!(text.as_deref(), Some("BAD_ETYPE_IN_2ND_TKT"));
}

#[test]
fn u2u_dup_skey_disallowed_is_policy() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    let attrs = store.get_name(&host).unwrap().attributes | 0x0000_0020;
    store
        .apply_admin_fields(&host, Some(attrs), None, None, None, None, false, None)
        .unwrap();
    let extra = issue_host_tgt(&store, 9250).rep.0.ticket;
    let req = u2u_req(&store, host, extra, 9251);
    let (c, text) = code(krb5_kdc::issue_tgs(&store, &req).unwrap_err());
    assert_eq!(c, err::POLICY);
    assert_eq!(text.as_deref(), Some("DUP_SKEY DISALLOWED"));
}

#[test]
fn u2u_host_tgt_issues_kvno_none() {
    let (store, _) = bootstrap_documented().unwrap();
    let extra = issue_host_tgt(&store, 9260);
    let req = u2u_req(&store, documented_host(), extra.rep.0.ticket, 9261);
    let out = krb5_kdc::issue_tgs(&store, &req).unwrap();
    assert!(
        out.rep.0.ticket.enc_part.kvno.is_none(),
        "U2U ticket kvno must be omitted (MIT DEFOPTIONALZEROTYPE)"
    );
}
