//! GSS init/accept whole-flow tests (public API).

use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_gss::{Error, GssContext, mit_shaped_wrap};
use krb5_kdc::S2K_ITERS;
use krb5_kdc::testrealm::{
    TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented, documented_host,
};
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};

use krb5_protocol::{AcceptorConfig, ReplayCache};
use krb5_types::{PrincipalName, ascii};

fn contexts() -> (GssContext, GssContext) {
    krb5_config::isolate_test_krb5();
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
    let (init, token) = GssContext::init_sec_context(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        krb5_gss::GSS_C_REPLAY | krb5_gss::GSS_C_SEQUENCE,
        None,
        None,
    )
    .unwrap();
    let host = store.get_name(&documented_host()).unwrap();
    let skey = &host.best_key().unwrap().key;
    let (acc, _) = GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
        &AcceptorConfig::default(),
    )
    .unwrap();
    (init, acc)
}

fn user_host() -> (
    krb5_kdc::IssuedAs,
    krb5_kdc::IssuedTgs,
    ProtocolKey,
    PrincipalName,
) {
    krb5_config::isolate_test_krb5();
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
    let host = store.get_name(&documented_host()).unwrap();
    let skey = host.best_key().unwrap().key.clone();
    (as_out, tgs_out, skey, cname)
}

#[test]
fn accept_same_token_twice_is_repeat() {
    let (_as_out, tgs_out, skey, cname) = user_host();
    let (_init, token) = GssContext::init_sec_context(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        krb5_gss::GSS_C_REPLAY | krb5_gss::GSS_C_SEQUENCE,
        None,
        None,
    )
    .unwrap();
    let rcache = ReplayCache::new();
    GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &rcache,
        &AcceptorConfig::default(),
    )
    .expect("first accept");
    match GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &rcache,
        &AcceptorConfig::default(),
    ) {
        Err(err) => {
            assert_eq!(err.to_string(), "KRB-ERROR 34: authenticator replay");
        }
        Ok(_) => panic!("replayed AP-REQ must be 34"),
    }
}

#[test]
fn garbage_mac_does_not_consume_seq() {
    let (mut init, mut acc) = contexts();
    let good = init.wrap(b"keep-seq").unwrap();
    let mut bad = good.clone();
    let last = bad.last_mut().expect("wrap token");
    *last ^= 0xff;
    assert!(acc.unwrap(&bad).is_err(), "garbage MAC must fail");
    assert_eq!(
        acc.unwrap(&good).unwrap(),
        b"keep-seq",
        "in-window seq must still accept a later good MAC"
    );
    let (mut init, mut acc) = contexts();
    let mic = init.get_mic(b"keep-seq").unwrap();
    let mut bad = mic.clone();
    let last = bad.last_mut().expect("mic token");
    *last ^= 0xff;
    assert!(matches!(
        acc.verify_mic(b"keep-seq", &bad),
        Err(Error::Integrity)
    ));
    acc.verify_mic(b"keep-seq", &mic).unwrap();
}

#[test]
fn mutual_ap_rep_decrypts_with_ticket_session() {
    let (_as_out, tgs_out, skey, cname) = user_host();
    let (mut init, token) = GssContext::init_sec_context(
        tgs_out.rep.0.ticket.clone(),
        &tgs_out.session_key,
        &ascii(TEST_REALM),
        &cname,
        krb5_gss::GSS_C_MUTUAL | krb5_gss::GSS_C_REPLAY | krb5_gss::GSS_C_SEQUENCE,
        None,
        None,
    )
    .unwrap();
    let (_acc, ap_rep) = GssContext::accept_sec_context(
        &token,
        std::slice::from_ref(&skey),
        None,
        Some(&documented_host()),
        Some(TEST_REALM),
        &ReplayCache::new(),
        &AcceptorConfig::default(),
    )
    .unwrap();
    let tok = ap_rep.expect("mutual AP-REP");
    init.process_ap_rep(&tok, &tgs_out.session_key).unwrap();
}

#[test]
fn wrap_mic_replay_inside_window_is_rejected() {
    let (mut init, mut acc) = contexts();
    let w = init.wrap(b"one").unwrap();
    acc.unwrap(&w).unwrap();
    // Gap inside the window is accepted (seq 0 then seq 2).
    let gap = mit_shaped_wrap(init.session_key(), true, 2, b"gap").unwrap();
    assert_eq!(acc.unwrap(&gap).unwrap(), b"gap");
    assert!(matches!(acc.unwrap(&w), Err(Error::Sequence)));
    let mic = init.get_mic(b"one").unwrap();
    acc.verify_mic(b"one", &mic).unwrap();
    assert!(matches!(acc.verify_mic(b"one", &mic), Err(Error::Sequence)));
}

#[test]
fn export_import_wrap_still_works() {
    let (mut init, acc) = contexts();
    let w = init.wrap(b"keep").unwrap();
    let tok = acc.export_sec_context().unwrap();
    let mut acc2 = GssContext::import_sec_context(&tok).unwrap();
    assert_eq!(acc2.unwrap(&w).unwrap(), b"keep");
    let w2 = init.wrap(b"again").unwrap();
    assert_eq!(acc2.unwrap(&w2).unwrap(), b"again");
    assert!(matches!(
        GssContext::import_sec_context(&tok[..8]),
        Err(Error::Truncated)
    ));
    assert!(matches!(
        GssContext::import_sec_context(b"XXXX"),
        Err(Error::Truncated)
    ));
}
