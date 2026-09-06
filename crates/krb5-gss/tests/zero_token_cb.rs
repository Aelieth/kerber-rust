//! MIT `process_checksum`: all-zero token CB vs acceptor bindings.

use krb5_crypto::{EncryptionType, string_to_key};
use krb5_gss::{ChannelBindings, GssContext};
use krb5_kdc::{
    S2K_ITERS, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, as_req, bootstrap_documented,
    documented_host, pa_enc_timestamp, tgs_req,
};
use krb5_protocol::ReplayCache;
use krb5_types::{PrincipalName, ascii};

#[test]
fn accept_zero_token_cb_with_acceptor_cb_is_ok() {
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
        1,
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
        2,
    )
    .unwrap();
    let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
    let host = store.get_name(&documented_host()).unwrap();
    let skey = host.best_key().unwrap().key.clone();
    let (_init, token) = GssContext::init_sec_context(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        false,
        None,
        None,
    )
    .unwrap();
    let local = ChannelBindings {
        application_data: b"acceptor-only".to_vec(),
        ..ChannelBindings::default()
    };
    GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        Some(&local),
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
    )
    .expect("all-zero token CB is accepted when the acceptor has bindings");
}
