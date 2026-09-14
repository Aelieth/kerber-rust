//! Z1.3 kpasswd acceptor pins the changepw service (`schpw.c` / MIT
//! `krb5_rd_req` on the kadmin/changepw cred). Compiles at the parent
//! `d6ae0c1` and fails there: the listener passed `expected_server: None`, so a
//! ticket whose sname is anything else (here `host/x`) that still decrypts under
//! the changepw key was accepted and drove a password change. At HEAD the
//! sname mismatch is refused before the KRB-PRIV is ever read.

use krb5_admin::{encode_kpasswd_req, handle_kpasswd_rfc3244};
use krb5_asn1::encode;
use krb5_kdc::{TEST_REALM, TEST_USER, bootstrap_documented, documented_changepw, shared_dump};
use krb5_protocol::{ReplayCache, as_req_sname, build_ap_req, build_krb_priv, pa_enc_timestamp};
use krb5_types::PrincipalName;

#[test]
fn z1_kpasswd_host_ticket_under_changepw_key_is_refused() {
    krb5_config::isolate_test_krb5();
    let (store, acl) = bootstrap_documented().expect("bootstrap");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let user_key = store
        .get_name(&user)
        .expect("user")
        .best_key()
        .expect("key")
        .key
        .clone();
    let changepw = documented_changepw();
    let cpw_key = store
        .get_name(&changepw)
        .expect("changepw")
        .best_key()
        .expect("key")
        .key
        .clone();

    // A real INITIAL ticket for kadmin/changepw (encrypted under the changepw key).
    let as_out = krb5_kdc::issue_as(
        &store,
        &as_req_sname(
            user.clone(),
            TEST_REALM,
            0x2400_0001,
            Some(vec![pa_enc_timestamp(&user_key).expect("pa")]),
            documented_changepw(),
            krb5_crypto::EncryptionType::preferred()
                .iter()
                .map(|e| e.to_iana())
                .collect(),
        )
        .expect("as-req"),
    )
    .expect("AS for kadmin/changepw");

    let mut ap = build_ap_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &krb5_types::ascii(TEST_REALM),
        &user,
    )
    .expect("AP-REQ");
    // Forge only the cleartext sname: the ticket still decrypts under the
    // changepw key, but it now claims to be host/x, not kadmin/changepw.
    ap.ticket.sname = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x.kerber.test"]);
    let ap_der = encode(&ap).expect("encode ap");

    let priv_msg = build_krb_priv(&as_out.session_key, b"z1-forge-newpass-123").expect("priv");
    let req = encode_kpasswd_req(&ap_der, &encode(&priv_msg).expect("encode priv"));

    let shared = shared_dump(store);
    let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
        .expect("handler returns a datagram");
    // A refusal before processing is a framed KRB-ERROR: AP-REP length 0.
    // The parent accepted the host/x ticket and replied with a real AP-REP.
    let ap_len = u16::from_be_bytes([rep[4], rep[5]]);
    assert_eq!(
        ap_len, 0,
        "host/x ticket under the changepw key must be refused"
    );
}
