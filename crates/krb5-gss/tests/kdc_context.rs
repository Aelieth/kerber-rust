//! The acceptor on a KDC context (`krb5_gss::use_kdc_context`, MIT `krb5_gss_use_kdc_context`):
//! `permitted_enctypes` comes from the KDC profile first. The switch is process-wide, so this
//! test binary holds this one test alone.

use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_gss::{Error, GssContext};
use krb5_kdc::S2K_ITERS;
use krb5_kdc::testrealm::{
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, documented_host,
};
use krb5_protocol::{ReplayCache, as_req, pa_enc_timestamp, tgs_req};
use krb5_types::{PrincipalName, ascii};

/// A fresh initial token from the documented user to the documented host (an aes256-cts
/// ticket and session key), and the host's key.
fn host_token() -> (Vec<u8>, ProtocolKey) {
    let (store, _) = bootstrap_documented().unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let key = string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let req = as_req(
        cname.clone(),
        TEST_REALM,
        41,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&store, &req).unwrap();
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        TEST_REALM,
        &cname,
        documented_host(),
        TEST_REALM,
        42,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    assert_eq!(
        tgs_out.session_key.etype(),
        EncryptionType::Aes256CtsHmacSha196
    );
    let (_init, token) = GssContext::init_sec_context(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        true,
        None,
        None,
    )
    .unwrap();
    let host = store.get_name(&documented_host()).unwrap();
    (token, host.best_key().unwrap().key.clone())
}

fn accept(token: &[u8], skey: &ProtocolKey) -> Result<(), Error> {
    GssContext::accept_sec_context(
        token,
        std::slice::from_ref(skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    )
    .map(|_| ())
}

#[test]
fn a_kdc_context_reads_permitted_enctypes_from_the_kdc_profile_first() {
    krb5_config::isolate_test_krb5();
    let kdc = krb5_testkit::scratch_dir("p15a-gss-kdc-context").join("kdc.conf");
    std::fs::write(
        &kdc,
        "[libdefaults]\n    permitted_enctypes = aes128-cts-hmac-sha1-96\n",
    )
    .unwrap();
    krb5_config::set_test_kdc_profile(Some(kdc));
    let (token, skey) = host_token();
    assert!(
        accept(&token, &skey).is_ok(),
        "a plain context reads krb5.conf alone, which permits MIT's DEFAULT"
    );
    krb5_gss::use_kdc_context();
    let (token, skey) = host_token();
    let Err(Error::Inner(msg)) = accept(&token, &skey) else {
        panic!("a KDC context reads the KDC profile's aes128-only list first");
    };
    // MIT `krb5_decrypt_tkt_part` (`decrypt_tk.c:46-50`): the aes256 ticket is refused first.
    assert_eq!(msg, "Encryption type not permitted");
}
