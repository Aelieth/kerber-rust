//! R13: `u2u_session` statuses (`do_tgs_req.c:250-307`, `kdc_util.c:420-450`).

use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_kdc::{
    PrincipalStore, S2K_ITERS, TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER,
    TEST_USER_PASSWORD, as_req, bootstrap_documented, pa_enc_timestamp,
};
use krb5_protocol::tgs_req_ex;
use krb5_types::{KdcOptions, PrincipalName, err, flag_bit};

fn password_key(name: &str, password: &[u8]) -> ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        password,
        &cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap()
}

fn issue_tgt(
    store: &PrincipalStore,
    name: &str,
    password: &[u8],
    nonce: u32,
) -> krb5_kdc::IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    let key = password_key(name, password);
    let req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}

fn pref_etypes() -> Vec<i32> {
    EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect()
}

fn proto(err: &krb5_kdc::Error) -> (i32, Option<&str>) {
    match err {
        krb5_kdc::Error::Protocol { code, text, .. } => (*code, text.as_deref()),
        other => panic!("expected protocol error, got {other:?}"),
    }
}

fn u2u(store: &PrincipalStore, second: krb5_types::Ticket) -> krb5_kdc::Error {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_tgt = issue_tgt(store, TEST_USER, TEST_USER_PASSWORD, 813);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true);
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket,
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        user.clone(),
        TEST_REALM,
        814,
        opts,
        Some(vec![second]),
        Vec::new(),
        pref_etypes(),
    )
    .unwrap();
    krb5_kdc::issue_tgs(store, &tgs).unwrap_err()
}

#[test]
fn u2u_no_key_of_ticket_etype_is_2nd_tkt_server() {
    let (store, _) = bootstrap_documented().unwrap();
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 811);
    let mut second = admin_tgt.rep.0.ticket;
    second.enc_part.etype = EncryptionType::Camellia128CtsCmac.to_iana();
    let err = u2u(&store, second);
    let (code, text) = proto(&err);
    assert_eq!(code, err::GENERIC);
    assert_eq!(text, Some("2ND_TKT_SERVER"));
}

#[test]
fn u2u_unknown_etype_99_is_2nd_tkt_server() {
    let (store, _) = bootstrap_documented().unwrap();
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 812);
    let mut second = admin_tgt.rep.0.ticket;
    second.enc_part.etype = 99;
    let err = u2u(&store, second);
    let (code, text) = proto(&err);
    assert_eq!(code, err::GENERIC);
    assert_eq!(text, Some("2ND_TKT_SERVER"));
}

#[test]
fn u2u_corrupt_cipher_is_2nd_tkt_decrypt() {
    let (store, _) = bootstrap_documented().unwrap();
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 815);
    let mut second = admin_tgt.rep.0.ticket;
    let mut cipher = second.enc_part.cipher.as_ref().to_vec();
    if let Some(b) = cipher.last_mut() {
        *b ^= 1;
    }
    second.enc_part.cipher = cipher.into();
    let err = u2u(&store, second);
    let (code, text) = proto(&err);
    assert_eq!(code, err::BAD_INTEGRITY);
    assert_eq!(text, Some("2ND_TKT_DECRYPT"));
}
