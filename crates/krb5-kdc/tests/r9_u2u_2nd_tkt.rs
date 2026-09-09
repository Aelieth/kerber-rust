//! R9: U2U missing second-ticket server is 7 `2ND_TKT_SERVER`
//! (`do_tgs_req.c:280-289` via `kdc_get_server_key(stkt)`).

use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_kdc::{
    PrincipalStore, S2K_ITERS, TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER,
    TEST_USER_PASSWORD, as_req, bootstrap_documented, documented_host, pa_enc_timestamp,
};
use krb5_protocol::tgs_req_ex;
use krb5_types::{KdcOptions, PrincipalName, err, flag_bit};

fn password_key(name: &str, password: &[u8]) -> ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    let salt = cname.default_salt(TEST_REALM);
    string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        password,
        &salt,
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

#[test]
fn u2u_missing_second_ticket_server_is_2nd_tkt_server() {
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_tgt = issue_tgt(&store, TEST_USER, TEST_USER_PASSWORD, 741);
    let admin_tgt = issue_tgt(&store, TEST_ADMIN, TEST_ADMIN_PASSWORD, 742);
    let mut second = admin_tgt.rep.0.ticket.clone();
    // Outer sname does not exist; MIT `kdc_get_server_key` → 7 `2ND_TKT_SERVER`.
    second.sname = PrincipalName::new(PrincipalName::NT_SRV_INST, ["no-such-2ndtkt", TEST_REALM]);
    let opts = KdcOptions::forwardable().with_bit(flag_bit::ENC_TKT_IN_SKEY, true);
    let tgs = tgs_req_ex(
        user_tgt.rep.0.ticket.clone(),
        &user_tgt.session_key,
        TEST_REALM,
        &user,
        documented_host(),
        TEST_REALM,
        743,
        opts,
        Some(vec![second]),
        Vec::new(),
        pref_etypes(),
    )
    .unwrap();
    let err = krb5_kdc::issue_tgs(&store, &tgs).unwrap_err();
    let (code, text) = proto(&err);
    assert_eq!(code, err::S_PRINCIPAL_UNKNOWN);
    assert_eq!(text, Some("2ND_TKT_SERVER"));
}
