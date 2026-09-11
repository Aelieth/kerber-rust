//! A′-3 item 11: `get_ticket_flags` + `check_tgs_opts` + deny_opts.

use krb5_asn1::decode;
use krb5_crypto::{EncryptionType, KeyUsage, decrypt};
use krb5_kdc::{
    Error, KDB_DISALLOW_POSTDATED, KDB_DISALLOW_RENEWABLE, KDB_OK_AS_DELEGATE, PrincipalStore,
    TEST_REALM, TEST_USER, bootstrap_documented, documented_host,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req_ex};
use krb5_types::{EncTicketPart, KdcOptions, PrincipalName, err, flag_bit, ku};

fn proto(err: &Error) -> (i32, Option<&str>) {
    match err {
        Error::Protocol { code, text, .. } => (*code, text.as_deref()),
        other => panic!("expected protocol error, got {other:?}"),
    }
}

fn user_as(store: &PrincipalStore, nonce: u32, bits: &[(usize, bool)]) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = store
        .get_name(&cname)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let mut req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    for (bit, on) in bits {
        req.0.req_body.kdc_options = req.0.req_body.kdc_options.with_bit(*bit, *on);
    }
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn or_attr(store: &mut PrincipalStore, name: &PrincipalName, bit: u32) {
    let a = store.get_name(name).unwrap().attributes | bit;
    store
        .apply_admin_fields(name, Some(a), None, None, None, None, false, None)
        .unwrap();
}

fn host_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedTgs) -> EncTicketPart {
    let host = documented_host();
    let key = store.get_name(&host).unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &key.key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    decode(&plain).unwrap()
}

fn tgt_part(store: &PrincipalStore, issued: &krb5_kdc::IssuedTgs) -> EncTicketPart {
    let key = store.krbtgt().unwrap().best_key().unwrap();
    let usage = KeyUsage::new(ku::TICKET).unwrap();
    let plain = decrypt(
        &key.key,
        usage,
        issued.rep.0.ticket.enc_part.cipher.as_ref(),
    )
    .unwrap();
    decode(&plain).unwrap()
}

fn cname() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

#[test]
fn tgs_postdate_without_may_postdate_is_tgt_not_postdatable() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 11001, &[]);
    let tgs = tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname(),
        documented_host(),
        TEST_REALM,
        11002,
        KdcOptions::forwardable().with_bit(flag_bit::MAY_POSTDATE, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(proto(&err), (err::BADOPTION, Some("TGT NOT POSTDATABLE")));
}

#[test]
fn tgs_renewable_against_disallow_is_non_renewable() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    let issued = user_as(&store, 11011, &[(flag_bit::RENEWABLE, true)]);
    or_attr(&mut store, &host, KDB_DISALLOW_RENEWABLE);
    let tgs = tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname(),
        host,
        TEST_REALM,
        11012,
        KdcOptions::forwardable().with_bit(flag_bit::RENEWABLE, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    assert_eq!(proto(&err), (err::POLICY, Some("NON-RENEWABLE TICKET")));
}

#[test]
fn tgs_forwarded_sets_forwarded() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 11021, &[]);
    let tgs = tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname(),
        PrincipalName::krbtgt(TEST_REALM),
        TEST_REALM,
        11022,
        KdcOptions::none().with_bit(flag_bit::FORWARDED, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    assert!(tgt_part(&store, &out).flags.bit(flag_bit::FORWARDED));
}

#[test]
fn tgs_proxy_sets_proxy() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 11031, &[(flag_bit::PROXIABLE, true)]);
    let host_req = tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname(),
        documented_host(),
        TEST_REALM,
        11032,
        KdcOptions::forwardable().with_bit(flag_bit::PROXIABLE, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let host_out = krb5_kdc::issue_tgs(&store, &host_req).unwrap();
    assert!(host_part(&store, &host_out).flags.proxiable());
    let proxy = tgs_req_ex(
        host_out.rep.0.ticket.clone(),
        &host_out.session_key,
        TEST_REALM,
        &cname(),
        documented_host(),
        TEST_REALM,
        11033,
        KdcOptions::none().with_bit(flag_bit::PROXY, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &proxy).unwrap();
    assert!(host_part(&store, &out).flags.bit(flag_bit::PROXY));
}

#[test]
fn tgs_postdated_is_invalid() {
    let (store, _) = bootstrap_documented().unwrap();
    let issued = user_as(&store, 11041, &[(flag_bit::MAY_POSTDATE, true)]);
    let tgs = tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname(),
        documented_host(),
        TEST_REALM,
        11042,
        KdcOptions::none()
            .with_bit(flag_bit::MAY_POSTDATE, true)
            .with_bit(flag_bit::POSTDATED, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let part = host_part(&store, &out);
    assert!(part.flags.bit(flag_bit::POSTDATED));
    assert!(part.flags.invalid());
}

#[test]
fn tgs_postdated_bit_alone_does_not_deny_postdate() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let host = documented_host();
    or_attr(&mut store, &host, KDB_DISALLOW_POSTDATED);
    let issued = user_as(&store, 11051, &[(flag_bit::MAY_POSTDATE, true)]);
    let tgs = tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname(),
        host,
        TEST_REALM,
        11052,
        KdcOptions::none().with_bit(flag_bit::POSTDATED, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).expect("deny_opts keys only on ALLOW_POSTDATE");
    assert!(host_part(&store, &out).flags.invalid());
}

#[test]
fn tgs_renew_skips_ok_as_delegate() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let krbtgt = PrincipalName::krbtgt(TEST_REALM);
    or_attr(&mut store, &krbtgt, KDB_OK_AS_DELEGATE);
    let issued = user_as(&store, 11061, &[(flag_bit::RENEWABLE, true)]);
    let tgs = tgs_req_ex(
        issued.rep.0.ticket.clone(),
        &issued.session_key,
        TEST_REALM,
        &cname(),
        krbtgt,
        TEST_REALM,
        11062,
        KdcOptions::forwardable()
            .with_bit(flag_bit::RENEWABLE, true)
            .with_bit(flag_bit::RENEW, true),
        None,
        Vec::new(),
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    assert!(!tgt_part(&store, &out).flags.bit(flag_bit::OK_AS_DELEGATE));
}
