//! Lockout stamp-0 and REQUIRES_PRE_AUTH fail-count clear
//! (`kdb5.c:1539-1545,1574-1576`, `lockout.c:181-190`).

use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_kdc::{
    Error, KDB_REQUIRES_PRE_AUTH, NamedPolicy, S2K_ITERS, TEST_REALM, TEST_USER,
    TEST_USER_PASSWORD, as_req, bootstrap_documented, dump_store, load_dump, pa_enc_timestamp,
};
use krb5_types::{PrincipalName, err};

fn user_key() -> ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let salt = cname.default_salt(TEST_REALM);
    string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        &salt,
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap()
}

fn lock_policy(name: &str, max_fail: u32) -> NamedPolicy {
    NamedPolicy {
        name: name.into(),
        min_length: 1,
        min_classes: 1,
        history: 0,
        max_fail,
        pw_failcnt_interval: 0,
        pw_lockout_duration: 0,
        pw_min_life: 0,
        pw_max_life: 0,
        allowed_keysalts: None,
    }
}

fn zero_last_failed(dump: &str, princ: &str) -> String {
    dump.lines()
        .map(|line| {
            if line.starts_with("princ\t") && line.contains(princ) {
                let mut f: Vec<&str> = line.split('\t').collect();
                f[13] = "0";
                f.join("\t")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn absent_unlock_tl_stamp_zero_does_not_lock_last_failed_zero() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store.put_policy(lock_policy("lock", 1));
    store
        .set_principal_policy(&user, Some("lock".into()))
        .unwrap();
    store.record_as_outcome(&user, false);
    let p = store.get_name(&user).unwrap();
    assert_eq!(store.fail_auth_of(p), 1);
    assert!(store.last_failed_of(p) > 0);
    let dumped = dump_store(&store, b"masterpassword").unwrap();
    let store = load_dump(
        &zero_last_failed(&dumped, "user@KERBER.TEST"),
        b"masterpassword",
    )
    .unwrap();
    let p = store.get_name(&user).unwrap();
    assert_eq!(store.last_failed_of(p), 0);
    assert_eq!(store.fail_auth_of(p), 1);
    let req = as_req(
        user,
        TEST_REALM,
        701,
        Some(vec![pa_enc_timestamp(&user_key()).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(&store, &req).expect("last_failed==0 is not locked (MIT stamp 0)");
}

#[test]
fn as_success_clears_failcount_only_with_requires_preauth() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .apply_admin_fields(&user, Some(0), None, None, None, None, false, None)
        .unwrap();
    store.record_as_outcome(&user, false);
    store.record_as_outcome(&user, true);
    let p = store.get_name(&user).unwrap();
    assert_eq!(store.fail_auth_of(p), 1);
    assert_eq!(store.last_success_of(p), 0);

    store
        .apply_admin_fields(
            &user,
            Some(KDB_REQUIRES_PRE_AUTH),
            None,
            None,
            None,
            None,
            false,
            None,
        )
        .unwrap();
    store.record_as_outcome(&user, false);
    let req = as_req(
        user.clone(),
        TEST_REALM,
        703,
        Some(vec![pa_enc_timestamp(&user_key()).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(&store, &req).unwrap();
    let p = store.get_name(&user).unwrap();
    assert_eq!(store.fail_auth_of(p), 0);
    assert!(store.last_success_of(p) > 0);
}

#[test]
fn last_failed_nonzero_without_unlock_tl_still_locks() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store.put_policy(lock_policy("lock", 1));
    store
        .set_principal_policy(&user, Some("lock".into()))
        .unwrap();
    store.record_as_outcome(&user, false);
    let req = as_req(
        user,
        TEST_REALM,
        704,
        Some(vec![pa_enc_timestamp(&user_key()).unwrap()]),
    )
    .unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::CLIENT_REVOKED);
            assert_eq!(text.as_deref(), Some("CLIENT LOCKED OUT"));
        }
        other => panic!("expected 18 CLIENT LOCKED OUT, got {other:?}"),
    }
}
