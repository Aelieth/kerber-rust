//! Store whole-flow tests (bootstrap + issue_as + public methods).

use krb5_crypto::EncryptionType;
use krb5_kdc::principals::kadmin_history;
use krb5_kdc::*;
use krb5_protocol::pa_enc_timestamp;
use krb5_types::PrincipalName;
use std::time::{SystemTime, UNIX_EPOCH};

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u32::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

fn wait_unix_past(target: u32) {
    let cap = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while unix_now() <= target {
        assert!(
            std::time::Instant::now() < cap,
            "unix seconds did not pass {target} within 10s"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[test]
fn spake_not_advertised_without_groups() {
    let (mut store, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    store.policy.spake_preauth_groups.clear();
    let req = krb5_protocol::as_req(
        PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            [krb5_kdc::testrealm::TEST_USER],
        ),
        krb5_kdc::testrealm::TEST_REALM,
        30003,
        None,
    )
    .unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    let krb5_kdc::Error::PreauthRequired { e_data } = err else {
        panic!("expected PreauthRequired, got {err:?}");
    };
    let method: krb5_types::MethodData = krb5_asn1::decode(&e_data).unwrap();
    assert!(
        method
            .iter()
            .all(|p| p.padata_type != krb5_types::pa::SPAKE),
        "empty spake_preauth_groups must omit 151: {method:?}"
    );
}

/// MIT `krb5_db_create_policy` starts a primary's update log over (settled live): a replica at
/// a serial from before the policy needs a full resync, and the principals changed after it are
/// each logged, one named like a policy included.
#[cfg(feature = "test-hooks")]
#[test]
fn a_policy_change_starts_the_update_log_over() {
    let (mut store, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    krb5_kdc::testrealm::map_memory_ulog(&mut store, 100, IpropRole::Primary).unwrap();
    let user = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    store.set_password(&user, b"Before-pw1").unwrap();
    let before = store.ulog_last().unwrap();
    assert_eq!(before.sno, 2);
    store.put_policy(NamedPolicy::new("ipol")).unwrap();
    let reset = store.ulog_last().unwrap();
    assert_eq!(reset.sno, 1, "the policy started the log over");
    assert_eq!(store.ulog_get_entries(before).status, IPROP_FULL_RESYNC);
    store
        .set_principal_policy(&user, Some("ipol".into()))
        .unwrap();
    let colliding = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["policy:svc"]);
    store
        .create_password(
            &acl,
            &krb5_kdc::testrealm::documented_admin_id(),
            &colliding,
            b"collide-pw",
        )
        .unwrap();
    let got = store.ulog_get_entries(reset);
    assert_eq!(got.status, IPROP_OK);
    let names: Vec<String> = got
        .updates
        .iter()
        .map(|u| walk_incr_update(u).unwrap().name)
        .collect();
    assert_eq!(names, ["user@KERBER.TEST", "policy:svc@KERBER.TEST"]);
}

#[test]
fn password_history_matches_mit_window() {
    let (mut store, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let user = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    store
        .put_policy(NamedPolicy {
            name: "h1".into(),
            min_length: 8,
            min_classes: 2,
            history: 1,
            max_fail: 0,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
            pw_min_life: 0,
            pw_max_life: 0,
            allowed_keysalts: None,
        })
        .unwrap();
    store
        .set_principal_policy(&user, Some("h1".into()))
        .unwrap();
    store.set_password(&user, b"Hist-pw0").unwrap();
    assert!(
        store.set_password(&user, b"Hist-pw0").is_err(),
        "current password is inside history=1"
    );
    store.set_password(&user, b"Hist-pw1").unwrap();
    store
        .set_password(&user, b"Hist-pw0")
        .expect("history=1 must allow A→B→A like MIT");

    store
        .put_policy(NamedPolicy {
            name: "h2".into(),
            min_length: 8,
            min_classes: 2,
            history: 2,
            max_fail: 0,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
            pw_min_life: 0,
            pw_max_life: 0,
            allowed_keysalts: None,
        })
        .unwrap();
    store
        .set_principal_policy(&user, Some("h2".into()))
        .unwrap();
    store.set_password(&user, b"Hist-seed1").unwrap();
    store.set_password(&user, b"Hist-seed2").unwrap();
    store.set_password(&user, b"Hist-pw0").unwrap();
    store.set_password(&user, b"Hist-pw1").unwrap();
    store.set_password(&user, b"Hist-pw2").unwrap();
    assert!(
        store.set_password(&user, b"Hist-pw1").is_err(),
        "history=2 must reject B after A→B→C (MIT)"
    );
    store
        .set_password(&user, b"Hist-pw0")
        .expect("history=2 must allow the N-boundary password A after A→B→C");
    let p = store.get_name(&user).unwrap();
    let mut kvnos: Vec<u32> = p.keys.iter().map(|k| k.kvno).collect();
    kvnos.sort_unstable();
    kvnos.dedup();
    assert_eq!(kvnos.len(), 1, "active keys are a single kvno");
    let mut hkv: Vec<u32> = p.key_history.iter().map(|k| k.kvno).collect();
    hkv.sort_unstable();
    hkv.dedup();
    assert!(
        hkv.len() <= 1,
        "history=2 stores N-1 old kvnos, got {hkv:?}"
    );
    let text = krb5_kdc::dump_store(&store, b"masterpassword").unwrap();
    assert!(
        !text.contains("\t19204\t"),
        "history lives in KRB5_TL_KADM_DATA, not the private 0x4B04: {text}"
    );
    assert_eq!(
        p.kadm.old_keys.len(),
        1,
        "history=2 stores one old password"
    );
    let again = krb5_kdc::load_dump(&text, b"masterpassword").unwrap();
    assert!(
        again.get_name(&kadmin_history()).is_some(),
        "kadmin/history was created on the first policy chpass and dumped"
    );
    let p2 = again.get_name(&user).unwrap();
    assert!(
        !p2.key_history.is_empty(),
        "KADM_DATA old_keys round-trip under the history key"
    );
    assert_eq!(p2.kadm, p.kadm);
}

#[test]
fn failed_as_stamps_last_failed() {
    use krb5_protocol::{as_req, pa_enc_timestamp_at};
    use krb5_types::KerberosTime;

    let (store, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let user = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    let p0 = store.get_name(&user).unwrap().clone();
    assert_eq!(store.last_failed_of(&p0), 0);
    assert_eq!(store.last_success_of(&p0), 0);
    let zeros = krb5_crypto::ProtocolKey::from_bytes(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        &[0u8; 32],
    )
    .unwrap();
    let ts = KerberosTime::now().add_seconds(1).unwrap();
    let bad = as_req(
        user.clone(),
        krb5_kdc::testrealm::TEST_REALM,
        1,
        Some(vec![pa_enc_timestamp_at(&zeros, &ts).unwrap()]),
    )
    .unwrap();
    assert!(krb5_kdc::issue_as(&store, &bad).is_err());
    let p1 = store.get_name(&user).unwrap().clone();
    let failed = store.last_failed_of(&p1);
    assert!(
        failed > 0,
        "failed AS must stamp overlay last_failed, got {failed}"
    );
    let key = p1.best_key().unwrap().key.clone();
    let good = as_req(
        user.clone(),
        krb5_kdc::testrealm::TEST_REALM,
        1,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(&store, &good).unwrap();
    let p2 = store.get_name(&user).unwrap().clone();
    let ok_at = store.last_success_of(&p2);
    assert!(
        ok_at >= failed,
        "success must stamp last_success ({ok_at}) at/after last_failed ({failed})"
    );
    assert_eq!(store.fail_auth_of(&p2), 0);
}

#[test]
fn lockout_duration_only_unlocks_after_sleep() {
    use krb5_protocol::{as_req, pa_enc_timestamp_at};
    use krb5_types::KerberosTime;

    let (mut store, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let user = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    store
        .put_policy(NamedPolicy {
            name: "dur".into(),
            min_length: 0,
            min_classes: 0,
            history: 0,
            max_fail: 1,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 1,
            pw_min_life: 0,
            pw_max_life: 0,
            allowed_keysalts: None,
        })
        .unwrap();
    store
        .set_principal_policy(&user, Some("dur".into()))
        .unwrap();
    let key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let good = as_req(
        user.clone(),
        krb5_kdc::testrealm::TEST_REALM,
        1,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let zeros = krb5_crypto::ProtocolKey::from_bytes(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        &[0u8; 32],
    )
    .unwrap();
    let mut skew = 0i64;
    let mut bad_as = || {
        skew += 1;
        let ts = KerberosTime::now().add_seconds(skew).unwrap();
        as_req(
            user.clone(),
            krb5_kdc::testrealm::TEST_REALM,
            1,
            Some(vec![pa_enc_timestamp_at(&zeros, &ts).unwrap()]),
        )
        .unwrap()
    };
    let revoked = |e: &Error| matches!(e, Error::Protocol { code, .. } if *code == krb5_types::err::CLIENT_REVOKED);
    assert!(krb5_kdc::issue_as(&store, &bad_as()).is_err());
    let locked = krb5_kdc::issue_as(&store, &bad_as()).unwrap_err();
    assert!(revoked(&locked), "max_fail 1 must lock on the next AS");
    wait_unix_past(unix_now());
    krb5_kdc::issue_as(&store, &good)
        .expect("elapsed lockout duration with interval=0 must unlock");
}

/// MIT 1.22.2's KDC, settled live: past the failure count interval a failure counts from one
/// again (`maxfailure 2`: fail, wait, fail is one failure, not a lock), but the interval never
/// ends a lock (`maxfailure 1`, no lockout duration: the first failure locks for good).
#[test]
fn lockout_interval_resets_the_count_but_never_a_lock() {
    use krb5_protocol::{as_req, pa_enc_timestamp_at};
    use krb5_types::KerberosTime;

    let (mut store, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let user = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    let policy = |name: &str, max_fail: u32| NamedPolicy {
        name: name.into(),
        min_length: 0,
        min_classes: 0,
        history: 0,
        max_fail,
        pw_failcnt_interval: 1,
        pw_lockout_duration: 0,
        pw_min_life: 0,
        pw_max_life: 0,
        allowed_keysalts: None,
    };
    store.put_policy(policy("intv2", 2)).unwrap();
    store.put_policy(policy("intv1", 1)).unwrap();
    store
        .set_principal_policy(&user, Some("intv2".into()))
        .unwrap();
    let key = store
        .get_name(&user)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let good = as_req(
        user.clone(),
        krb5_kdc::testrealm::TEST_REALM,
        1,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let zeros = krb5_crypto::ProtocolKey::from_bytes(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        &[0u8; 32],
    )
    .unwrap();
    let mut skew = 0i64;
    let mut bad_as = || {
        skew += 1;
        let ts = KerberosTime::now().add_seconds(skew).unwrap();
        as_req(
            user.clone(),
            krb5_kdc::testrealm::TEST_REALM,
            1,
            Some(vec![pa_enc_timestamp_at(&zeros, &ts).unwrap()]),
        )
        .unwrap()
    };
    let revoked = |e: &Error| matches!(e, Error::Protocol { code, .. } if *code == krb5_types::err::CLIENT_REVOKED);
    assert!(krb5_kdc::issue_as(&store, &bad_as()).is_err());
    wait_unix_past(unix_now() + 1);
    let second = krb5_kdc::issue_as(&store, &bad_as()).unwrap_err();
    assert!(!revoked(&second), "past the interval: {second:?}");
    assert_eq!(store.fail_auth_of(store.get_name(&user).unwrap()), 1);
    krb5_kdc::issue_as(&store, &good).expect("one failure of two allowed");

    store
        .set_principal_policy(&user, Some("intv1".into()))
        .unwrap();
    assert!(krb5_kdc::issue_as(&store, &bad_as()).is_err());
    wait_unix_past(unix_now() + 1);
    let locked = krb5_kdc::issue_as(&store, &bad_as()).unwrap_err();
    assert!(
        revoked(&locked),
        "the interval does not end a lock: {locked:?}"
    );
    assert!(revoked(&krb5_kdc::issue_as(&store, &good).unwrap_err()));
}

/// MIT `ulog_replay` skips an update that is not committed without moving to the next, so the
/// batch ends there: the updates before it apply and are kept, none after it.
#[cfg(feature = "test-hooks")]
#[test]
fn an_update_not_committed_ends_the_replay() {
    let (mut master, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let (mut slave, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    krb5_kdc::testrealm::map_memory_ulog(&mut master, 1000, IpropRole::Primary).unwrap();
    let mkey = krb5_kdc::testrealm::map_memory_ulog(&mut slave, 1000, IpropRole::Replica).unwrap();
    let actor = krb5_kdc::testrealm::documented_admin_id();
    let sno0 = master.ulog_last().unwrap();
    let names = ["first", "uncommitted", "after"];
    for n in names {
        let p = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [n]);
        master
            .create_password(&acl, &actor, &p, b"replay-secret")
            .unwrap();
    }
    let mut updates: Vec<IpropUpdate> = master
        .ulog_get_entries(sno0)
        .updates
        .iter()
        .map(|u| decode_incr_update(u, Some(&mkey)).unwrap().0)
        .collect();
    assert!(
        updates.iter().all(|u| u.commit),
        "a primary's entries are committed"
    );
    updates[1].commit = false;
    slave.ulog().unwrap().set_last(sno0).unwrap();
    slave.apply_updates(&updates).unwrap();
    let has = |n: &str| {
        slave
            .get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, [n]))
            .is_some()
    };
    assert_eq!(names.map(has), [true, false, false]);
    assert_eq!(slave.ulog_last().unwrap().sno, sno0.sno + 1);
}

#[test]
fn admin_unlock_clears_failcount_lockout() {
    use krb5_protocol::as_req;
    use krb5_types::err;
    let (mut store, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let user = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    store
        .put_policy(NamedPolicy {
            name: "lock".into(),
            min_length: 1,
            min_classes: 1,
            history: 0,
            max_fail: 1,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
            pw_min_life: 0,
            pw_max_life: 0,
            allowed_keysalts: None,
        })
        .unwrap();
    store
        .set_principal_policy(&user, Some("lock".into()))
        .unwrap();
    let wrong =
        krb5_crypto::ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0u8; 32])
            .unwrap();
    let bad = as_req(
        user.clone(),
        krb5_kdc::testrealm::TEST_REALM,
        501,
        Some(vec![pa_enc_timestamp(&wrong).unwrap()]),
    )
    .unwrap();
    assert!(krb5_kdc::issue_as(&store, &bad).is_err());
    let key = store
        .get_name(&user)
        .unwrap()
        .key_for(EncryptionType::Aes256CtsHmacSha196)
        .unwrap()
        .key
        .clone();
    let req = as_req(
        user.clone(),
        krb5_kdc::testrealm::TEST_REALM,
        502,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let err = krb5_kdc::issue_as(&store, &req).unwrap_err();
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::CLIENT_REVOKED);
            assert_eq!(text.as_deref(), Some("LOCKED_OUT"));
        }
        other => panic!("expected 18 LOCKED_OUT, got {other:?}"),
    }
    store.admin_unlock(&user).unwrap();
    krb5_kdc::issue_as(&store, &req).expect("unlocked");
    let p = store.get_name(&user).unwrap();
    assert!(
        p.tl_data
            .iter()
            .any(|t| t.ty == TL_LAST_ADMIN_UNLOCK && t.contents.len() == 4),
        "dump-visible 1792"
    );
}
