//! A′-4 item 19 HEAD-only: TestPolicy + profile `supported_enctypes`.

use krb5_kdc::{
    Error, KdcPolicy, TEST_ADMIN, TEST_ADMIN_PASSWORD, TEST_REALM, TEST_USER, TEST_USER_PASSWORD,
    TestPolicy, bootstrap_documented, clear_thread_policy, documented_admin_id, set_thread_policy,
};
use krb5_protocol::{as_req, pa_enc_timestamp};
use krb5_types::{PrincipalName, err};

fn proto(err: &Error) -> (i32, Option<&str>) {
    match err {
        Error::Protocol { code, text, .. } => (*code, text.as_deref()),
        other => panic!("expected protocol error, got {other:?}"),
    }
}

#[test]
fn a4_19_test_policy_fail_client_is_local_policy() {
    set_thread_policy(std::sync::Arc::new(TestPolicy));
    let (mut store, acl) = bootstrap_documented().unwrap();
    let fail = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["fail"]);
    store
        .create_password(&acl, &documented_admin_id(), &fail, b"fail-secret")
        .unwrap();
    let key = store
        .get_name(&fail)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        fail,
        TEST_REALM,
        1910,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let (code, text) = proto(&err);
    assert_eq!(code, err::POLICY);
    assert_eq!(text, Some("LOCAL_POLICY"));
    clear_thread_policy();
}

#[test]
fn a4_19_test_policy_foreign_indicator_is_local_policy() {
    set_thread_policy(std::sync::Arc::new(TestPolicy));
    let store = krb5_kdc::PrincipalStore::bootstrap(
        TEST_REALM,
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
    )
    .unwrap();
    // Inject a non-ONE_HOUR/SEVEN_HOURS indicator via the store client path:
    // TestPolicy sees indicators from AS only after preauth. Use the
    // thread policy against a password AS with a dummy indicator by
    // setting require-style indicators on the issue path through SPAKE
    // is heavier; the name-deny cell above is the live gate's twin.
    // Here we call check_as directly.
    let user = store
        .get_name(&PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            [TEST_USER],
        ))
        .unwrap()
        .clone();
    let err = TestPolicy
        .check_as(&store, &user, &["OTHER".into()])
        .unwrap_err();
    let (code, text) = proto(&err);
    assert_eq!(code, err::POLICY);
    assert_eq!(text, Some("LOCAL_POLICY"));
    clear_thread_policy();
}

#[test]
fn a4_19_test_policy_one_hour_rewrites_endtime() {
    set_thread_policy(std::sync::Arc::new(TestPolicy));
    let store = krb5_kdc::PrincipalStore::bootstrap(
        TEST_REALM,
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
    )
    .unwrap();
    let user = store
        .get_name(&PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            [TEST_USER],
        ))
        .unwrap()
        .clone();
    let adj = TestPolicy
        .check_as(&store, &user, &["ONE_HOUR".into()])
        .unwrap();
    assert_eq!(adj.lifetime, 3600);
    assert_eq!(adj.renew_lifetime, 7200);
    let tgs = TestPolicy
        .check_tgs(
            &store,
            &PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x"]),
            &["ONE_HOUR".into()],
        )
        .unwrap();
    assert_eq!(tgs.lifetime, 1800);
    assert_eq!(tgs.renew_lifetime, 3600);
    let seven = TestPolicy
        .check_as(&store, &user, &["SEVEN_HOURS".into()])
        .unwrap();
    assert_eq!(seven.lifetime, 7 * 3600);
    assert_eq!(seven.renew_lifetime, 14 * 3600);
    clear_thread_policy();
}

#[test]
fn a4_19_bootstrap_honours_supported_enctypes_order() {
    let kdc = krb5_config::KdcConf::parse(
        r"
[realms]
    KERBER.TEST = {
        supported_enctypes = aes256-cts-hmac-sha384-192:normal aes128-cts-hmac-sha256-128:normal aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    }
",
    )
    .unwrap();
    let store = krb5_kdc::PrincipalStore::bootstrap_with_kdc_conf(
        TEST_REALM,
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
        Some(&kdc),
    )
    .unwrap();
    let keys: Vec<i32> = store
        .get_name(&PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            [TEST_USER],
        ))
        .unwrap()
        .keys
        .iter()
        .map(|k| k.etype.to_iana())
        .collect();
    assert_eq!(keys, vec![20, 19, 18, 17]);
}
