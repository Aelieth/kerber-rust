//! Z1.3 GSS acceptor kvno pinning (MIT `try_one_princ`, `rd_req_dec.c:325-347`).
//! A fully specified acceptor name fetches the keytab entry by the exact ticket
//! kvno; a key labelled M != N is not tried for a kvno-N ticket. The plain
//! `accept_sec_context` keeps MIT's wildcard/no-kvno iteration.

use krb5_gss::GssContext;
use krb5_kdc::{
    S2K_ITERS, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented,
    documented_admin_id, documented_host, pa_enc_timestamp, tgs_req,
};
use krb5_protocol::ReplayCache;
use krb5_types::{PrincipalName, ascii};

/// Build a real host/… GSS AP-REQ token and return it with the ticket-enc key
/// and its kvno.
fn host_token() -> (Vec<u8>, krb5_crypto::ProtocolKey, u32) {
    let (store, acl) = bootstrap_documented().expect("bootstrap");
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = krb5_crypto::string_to_key(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .expect("s2k");
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        0x2500_0001,
        Some(vec![pa_enc_timestamp(&key).expect("pa")]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).expect("AS");
    let tgs = tgs_req(
        as_out.rep.0.ticket,
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        0x2500_0002,
    )
    .expect("TGS-REQ");
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).expect("TGS");
    let (_init, token) = GssContext::init_sec_context(
        tgs_out.rep.0.ticket,
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        false,
        None,
        None,
    )
    .expect("init token");
    let kt = store
        .export_keytab(&acl, &documented_admin_id(), &documented_host())
        .expect("keytab");
    let ent = kt.entries.into_iter().next().expect("host key");
    (token, ent.key, ent.kvno)
}

#[test]
fn z1_gss_accept_kt_pins_ticket_kvno() {
    let (token, skey, kvno) = host_token();
    assert_eq!(kvno, 1);
    let host = documented_host();

    // Plain accept keeps MIT's no-kvno iteration: the ticket opens under the key
    // regardless of the (here mismatched) keytab label.
    GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&host),
        Some(TEST_REALM),
        &ReplayCache::new(),
    )
    .expect("plain accept ignores kvno labels");

    // With kvnos + a fully specified server, a key labelled kvno 2 is not tried
    // for the kvno-1 ticket (try_one_princ get_entry(kvno=1) finds nothing) —
    // MIT keytab_fetch_error: KRB5KRB_AP_ERR_BADKEYVER (44) "Cannot find key for
    // host/… kvno 1 in keytab".
    match GssContext::accept_sec_context_kt(
        &token,
        std::slice::from_ref(&skey),
        Some(&[2u32]),
        None,
        Some(&host),
        Some(TEST_REALM),
        &ReplayCache::new(),
    ) {
        Ok(_) => panic!("kt accept must pin the ticket kvno"),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("44") && msg.contains("Cannot find key for host/"),
                "expected MIT's BADKEYVER refusal, got {msg}"
            );
        }
    }
}

#[test]
fn z1_gss_accept_kt_matching_kvno_verifies() {
    let (token, skey, kvno) = host_token();
    let host = documented_host();
    GssContext::accept_sec_context_kt(
        &token,
        std::slice::from_ref(&skey),
        Some(&[kvno]),
        None,
        Some(&host),
        Some(TEST_REALM),
        &ReplayCache::new(),
    )
    .expect("matching kvno verifies");
}
