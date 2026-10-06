//! Store whole-flow tests (bootstrap + issue_as + public methods).

use krb5_crypto::EncryptionType;
use krb5_kdc::principals::kadmin_history;
use krb5_kdc::*;
use krb5_protocol::pa_enc_timestamp;
use krb5_types::PrincipalName;
use krb5_types::pac::RpcSid;
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
fn pw_expiration_on_modify_is_last_pwd_change_plus_max_life() {
    let (mut store, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let user = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    let mut pol = NamedPolicy::new("life");
    pol.pw_max_life = 3600;
    store.put_policy(pol);
    store.set_last_pwd_unix(&user, 1_000_000).unwrap();
    store
        .apply_admin_fields(
            &user,
            krb5_kdc::AdminFields {
                attributes: None,
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: Some("life".into()),
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    let after = store.get_name(&user).unwrap();
    assert_eq!(after.pw_expire, 1_000_000 + 3600);
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

#[test]
fn bootstrap_sid_rid_are_real_not_dummy() {
    let (store, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    assert_ne!(
        store.domain_sid().to_sddl(),
        RpcSid::dummy_domain().to_sddl()
    );
    assert_eq!(store.krbtgt().unwrap().rid, RID_KRBTGT);
    let user = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    assert_eq!(store.get_name(&user).unwrap().rid, RID_FIRST_USER);
    let ident = store.pac_identity(&user, store.realm());
    assert_eq!(ident.rid, RID_FIRST_USER);
    assert_eq!(
        ident.client_sid().to_sddl(),
        store.domain_sid().with_rid(RID_FIRST_USER).to_sddl()
    );
}

#[test]
fn rename_keeps_rid_and_keys() {
    let (mut store, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let actor = krb5_kdc::testrealm::documented_admin_id();
    let old = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["renamefrom"]);
    let new = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["renameto"]);
    store
        .create_password(&acl, &actor, &old, b"rename-secret")
        .unwrap();
    let before = store.get_name(&old).unwrap();
    let rid = before.rid;
    let keys: Vec<(i32, u32, Vec<u8>)> = before
        .keys
        .iter()
        .map(|k| (k.etype.to_iana(), k.kvno, k.key.as_bytes().to_vec()))
        .collect();
    assert_ne!(rid, 0);
    store.rename(&acl, &actor, &old, &new).unwrap();
    assert!(store.get_name(&old).is_none());
    let after = store.get_name(&new).unwrap();
    assert_eq!(after.rid, rid);
    let after_keys: Vec<(i32, u32, Vec<u8>)> = after
        .keys
        .iter()
        .map(|k| (k.etype.to_iana(), k.kvno, k.key.as_bytes().to_vec()))
        .collect();
    assert_eq!(after_keys, keys);
    let add_only = Acl::parse("admin@KERBER.TEST a\n").expect("acl");
    store
        .create_password(&acl, &actor, &old, b"rename-secret")
        .unwrap();
    assert!(store.rename(&add_only, &actor, &old, &new).is_err());
}

#[test]
fn named_policy_pwqual_and_lockout() {
    use krb5_protocol::{as_req, pa_enc_timestamp_at};
    use krb5_types::KerberosTime;

    let (mut store, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let user = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    store.put_policy(NamedPolicy {
        name: "strict".into(),
        min_length: 8,
        min_classes: 2,
        history: 1,
        max_fail: 3,
        pw_failcnt_interval: 0,
        pw_lockout_duration: 0,
        pw_min_life: 0,
        pw_max_life: 0,
        allowed_keysalts: None,
    });
    store
        .set_principal_policy(&user, Some("strict".into()))
        .unwrap();
    assert!(store.check_password_quality(&user, b"short").is_err());
    assert!(store.set_password(&user, b"short").is_err());
    store.set_password(&user, b"Longer1x").unwrap();
    assert!(
        store.set_password(&user, b"Longer1x").is_err(),
        "history must reject reuse of the current password"
    );
    let n_kvno = {
        let p = store.get_name(&user).unwrap();
        let mut v: Vec<u32> = p.keys.iter().map(|k| k.kvno).collect();
        v.sort_unstable();
        v.dedup();
        v.len()
    };
    assert_eq!(n_kvno, 1, "keepold=false: one active kvno");

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
    assert!(krb5_kdc::issue_as(&store, &bad_as()).is_err());
    krb5_kdc::issue_as(&store, &good).expect("success must reset fail count");
    assert!(krb5_kdc::issue_as(&store, &bad_as()).is_err());
    let second = krb5_kdc::issue_as(&store, &bad_as()).unwrap_err();
    assert!(
        !revoked(&second),
        "second fail after success must not lock (count was reset): {second:?}"
    );
    assert!(krb5_kdc::issue_as(&store, &bad_as()).is_err());
    let locked = krb5_kdc::issue_as(&store, &bad_as()).unwrap_err();
    assert!(revoked(&locked), "expected CLIENT_REVOKED, got {locked:?}");
}

#[test]
fn pwqual_counts_five_mit_classes() {
    let (mut store, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let user = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    store.put_policy(NamedPolicy {
        name: "five".into(),
        min_length: 8,
        min_classes: 5,
        history: 0,
        max_fail: 0,
        pw_failcnt_interval: 0,
        pw_lockout_duration: 0,
        pw_min_life: 0,
        pw_max_life: 0,
        allowed_keysalts: None,
    });
    store
        .set_principal_policy(&user, Some("five".into()))
        .unwrap();
    assert!(
        store.check_password_quality(&user, b"Aa1!aaaa").is_err(),
        "lower+upper+digit+punct is 4 classes"
    );
    assert!(
        store.check_password_quality(&user, b"Aa1!aaa ").is_ok(),
        "space is MIT class other (5th)"
    );
}

/// MIT `krb5_db_put_principal` converts each update, its keys wrapped under the master key,
/// before the put: `kdb5_util load -update` prepares the log before its database write, so with
/// no master key nothing is written and nothing is logged, and with one the prepared updates are
/// appended only once the write is made.
#[cfg(feature = "test-hooks")]
#[test]
fn load_update_prepares_the_log_before_the_database_is_written() {
    let (loaded, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let (mut keyless, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    assert!(keyless.iprop_master_key().is_none());
    keyless.set_ulog(Ulog::memory(64).unwrap(), IpropRole::Primary);
    let before = keyless.ulog_last().unwrap();
    update_store(&mut keyless, &loaded, &[]);
    assert!(keyless.prepare_log().is_err());
    assert_eq!(keyless.ulog_last(), Some(before));
    let (mut keyed, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    krb5_kdc::testrealm::map_memory_ulog(&mut keyed, 64, IpropRole::Primary).unwrap();
    let start = keyed.ulog_last().unwrap();
    update_store(&mut keyed, &loaded, &[]);
    let prepared = keyed.prepare_log().unwrap();
    assert_eq!(
        keyed.ulog_last(),
        Some(start),
        "nothing is logged before the write"
    );
    keyed
        .write_logged(prepared, || Ok::<(), Error>(()))
        .unwrap();
    let puts = u32::try_from(loaded.ids().len()).unwrap();
    assert_eq!(keyed.ulog_last().unwrap().sno, start.sno + puts);
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
    store.put_policy(NamedPolicy::new("ipol"));
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
fn kadmin_history_is_created_before_a_rejected_quality_chpass() {
    // MIT kadm5_chpass_principal_3 fetches the history key (creating
    // kadmin/history) before passwd_check, so a chpass rejected for a
    // short password still leaves kadmin/history created.
    let (mut store, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let user = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    let mut pol = NamedPolicy::new("minlen");
    pol.min_length = 8;
    pol.history = 2;
    store.put_policy(pol);
    store
        .set_principal_policy(&user, Some("minlen".into()))
        .unwrap();
    let hist = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "history"]);
    assert!(
        store.get_name(&hist).is_none(),
        "kadmin/history not created until the first policy chpass"
    );
    assert!(
        store.set_password(&user, b"short").is_err(),
        "a too-short password is rejected"
    );
    assert!(
        store.get_name(&hist).is_some(),
        "kadmin/history is created before the quality check (MIT order)"
    );
}

#[test]
fn password_history_matches_mit_window() {
    let (mut store, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let user = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    store.put_policy(NamedPolicy {
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
    });
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

    store.put_policy(NamedPolicy {
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
    });
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
    store.put_policy(NamedPolicy {
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
    });
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
    store.put_policy(policy("intv2", 2));
    store.put_policy(policy("intv1", 1));
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

#[cfg(feature = "test-hooks")]
#[test]
fn serial_ulog_delta_then_issue_as() {
    use krb5_protocol::as_req;

    let (mut master, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let (mut slave, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    krb5_kdc::testrealm::map_memory_ulog(&mut master, 1000, IpropRole::Primary).unwrap();
    let mkey = krb5_kdc::testrealm::map_memory_ulog(&mut slave, 1000, IpropRole::Replica).unwrap();
    let actor = krb5_kdc::testrealm::documented_admin_id();
    let sno0 = master.ulog_last().unwrap();
    assert_eq!(sno0.sno, 1, "a new log holds the dummy entry at serial 1");
    assert_eq!(
        master.ulog_get_entries(UlogLast::default()).status,
        IPROP_FULL_RESYNC
    );
    assert_eq!(master.ulog_get_entries(sno0).status, IPROP_NIL);
    // A replica ahead of the master (rollback) must full-resync, not NIL.
    let ahead = UlogLast {
        sno: sno0.sno + 100,
        ..sno0
    };
    assert_eq!(
        master.ulog_get_entries(ahead).status,
        IPROP_FULL_RESYNC,
        "a replica serial past the master's must resync"
    );

    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["iproped"]);
    master
        .create_password(&acl, &actor, &extra, b"iprop-secret")
        .unwrap();
    let sno1 = master.ulog_last().unwrap();
    assert_eq!(sno1.sno, sno0.sno + 1, "one create is one entry");
    let got = master.ulog_get_entries(sno0);
    assert_eq!(got.status, IPROP_OK);
    assert_eq!(got.last, sno1);
    let updates: Vec<IpropUpdate> = got
        .updates
        .iter()
        .map(|u| decode_incr_update(u, Some(&mkey)).unwrap().0)
        .collect();
    assert_eq!(updates.len(), 1);
    assert!(updates[0].name.contains("iproped") && !updates[0].deleted);

    // The replica stands where a full resync left it, then applies and keeps the update.
    slave.ulog().unwrap().set_last(sno0).unwrap();
    slave.apply_updates(&updates).unwrap();
    assert!(slave.get_name(&extra).is_some());
    assert_eq!(slave.ulog_last(), Some(sno1));
    let key = slave
        .get_name(&extra)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        extra,
        krb5_kdc::testrealm::TEST_REALM,
        11,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(&slave, &req).expect("slave must issue after serial-delta");
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
fn apply_updates_assigns_rid_so_replica_pac_is_not_first_user() {
    use krb5_kdc::{decrypt_ticket_part, pac_from_ticket_part};
    use krb5_protocol::as_req;
    use krb5_protocol::pa_enc_timestamp;
    use krb5_types::pac::{PAC_LOGON_INFO, Pac, parse_kerb_validation_info};

    let (mut master, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let (mut slave, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    // AD data: the realm has an AD identity (kdc.conf `domain_sid`), so its PACs are AD-shaped.
    slave.policy.ad_identity = true;
    let actor = krb5_kdc::testrealm::documented_admin_id();
    let user = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    let user_rid = slave.get_name(&user).unwrap().rid;
    assert_eq!(user_rid, RID_FIRST_USER);

    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["iproped"]);
    master
        .create_password(&acl, &actor, &extra, b"iprop-secret")
        .unwrap();
    let mut incr = master.get_name(&extra).unwrap().clone();
    incr.rid = 0;
    incr.tl_data.retain(|t| t.ty != krb5_kdc::TL_KERBER_SID);
    slave
        .apply_updates(&[IpropUpdate {
            sno: slave.serial().saturating_add(1),
            time: 1,
            name: incr.id(),
            deleted: false,
            commit: true,
            vals: conv_2logentry(&incr, ULOG_ADD_ATTRS),
            raw: Vec::new(),
        }])
        .unwrap();

    let got = slave.get_name(&extra).unwrap().clone();
    assert_ne!(got.rid, 0, "incremental apply must allocate a RID");
    assert_ne!(got.rid, RID_FIRST_USER);
    assert_ne!(got.rid, user_rid);

    let key = got.best_key().unwrap().key.clone();
    let req = as_req(
        extra.clone(),
        krb5_kdc::testrealm::TEST_REALM,
        21,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let as_out = krb5_kdc::issue_as(&slave, &req).expect("replica AS");
    let tgt = slave.krbtgt().unwrap().best_key().unwrap();
    let part = decrypt_ticket_part(&tgt.key, &as_out.rep.0.ticket).expect("enc");
    let pac = pac_from_ticket_part(&part).expect("PAC");
    let parsed = Pac::parse(&pac).expect("PAC");
    let logon =
        parse_kerb_validation_info(parsed.buffer(PAC_LOGON_INFO).expect("logon")).expect("NDR");
    assert_eq!(logon.user_id, got.rid);
    assert_ne!(logon.user_id, RID_FIRST_USER);
}

#[test]
fn apply_updates_keeps_what_an_update_does_not_carry() {
    let (mut store, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let actor = krb5_kdc::testrealm::documented_admin_id();
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["keyless"]);
    store
        .create_password(&acl, &actor, &extra, b"keyless-secret")
        .unwrap();
    store.set_string(&extra, "note", Some("keep-me")).unwrap();
    let before = store.get_name(&extra).unwrap().clone();
    assert!(!before.keys.is_empty());
    let mut changed = before.clone();
    changed.max_life = 4 * 3600;
    let sno = store.serial().saturating_add(1);
    store
        .apply_updates(&[IpropUpdate {
            sno,
            time: 1,
            name: before.id(),
            deleted: false,
            commit: true,
            vals: conv_2logentry(&changed, attr_bit(AT_MAX_LIFE) | attr_bit(AT_PRINC)),
            raw: Vec::new(),
        }])
        .unwrap();
    let after = store.get_name(&extra).unwrap();
    assert_eq!(after.max_life, 4 * 3600);
    assert_eq!(after.keys.len(), before.keys.len());
    assert_eq!(after.keys[0].key.as_bytes(), before.keys[0].key.as_bytes());
    assert_eq!(after.string_attrs, before.string_attrs);
    assert_eq!(after.key_history.len(), before.key_history.len());
    assert_eq!(after.tl_data, before.tl_data);
    assert_eq!(after.attributes, before.attributes);
}

/// Each change is one entry, a rename MIT's three (settled live): the put of the new name with
/// every attribute, the delete of the old one, then the put that records the modification.
#[cfg(feature = "test-hooks")]
#[test]
fn ulog_records_delete_rename_chrand() {
    let (mut store, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let mkey = krb5_kdc::testrealm::map_memory_ulog(&mut store, 100, IpropRole::Primary).unwrap();
    let actor = krb5_kdc::testrealm::documented_admin_id();
    let a = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["ulogdel"]);
    let b = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["ulogren"]);
    let since = |store: &PrincipalStore, last: UlogLast| -> Vec<IncrLayout> {
        store
            .ulog_get_entries(last)
            .updates
            .iter()
            .map(|u| walk_incr_update(u).unwrap())
            .collect()
    };
    store
        .create_password(&acl, &actor, &a, b"ulog-secret")
        .unwrap();
    let after_create = store.ulog_last().unwrap();
    store.delete(&acl, &actor, &a).unwrap();
    let del = since(&store, after_create);
    assert_eq!(
        del.iter()
            .map(|l| (l.name.as_str(), l.deleted))
            .collect::<Vec<_>>(),
        [("ulogdel@KERBER.TEST", true)]
    );
    assert_eq!(del[0].nvals, 0, "a delete carries no values");
    store
        .create_password(&acl, &actor, &a, b"ulog-secret")
        .unwrap();
    let after_recreate = store.ulog_last().unwrap();
    store.rename(&acl, &actor, &a, &b).unwrap();
    let ren = since(&store, after_recreate);
    assert_eq!(
        ren.iter()
            .map(|l| (l.name.as_str(), l.deleted))
            .collect::<Vec<_>>(),
        [
            ("ulogren@KERBER.TEST", false),
            ("ulogdel@KERBER.TEST", true),
            ("ulogren@KERBER.TEST", false),
        ]
    );
    // The first put is a new principal's, every attribute; the last records the modification.
    let every = attr_bit(AT_ATTRFLAGS) | attr_bit(AT_KEYDATA) | attr_bit(AT_LEN);
    assert_eq!(ren[0].attrs & every, every, "{:#x}", ren[0].attrs);
    assert_eq!(ren[1].attrs, 0);
    assert_ne!(ren[2].attrs & attr_bit(AT_PRINC), 0);
    assert_eq!(ren[2].attrs & attr_bit(AT_KEYDATA), 0);
    let user = PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        [krb5_kdc::testrealm::TEST_USER],
    );
    let after_ren = store.ulog_last().unwrap();
    store.chrand(&user).unwrap();
    let ch = since(&store, after_ren);
    assert_eq!(ch.len(), 1);
    assert_ne!(
        ch[0].attrs & attr_bit(AT_KEYDATA),
        0,
        "chrand carries the keys"
    );
    let after_ch = store.ulog_last().unwrap();
    store.set_status(&user, true, 0).unwrap();
    let got = store.ulog_get_entries(after_ch);
    let (status, _) = decode_incr_update(&got.updates[0], Some(&mkey)).unwrap();
    assert!(
        status
            .vals
            .iter()
            .any(|v| matches!(v, KdbeVal::AttrFlags(f) if f & KDB_DISALLOW_ALL_TIX != 0)),
        "set_status must be logged with its flags: {status:?}"
    );
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
    store.put_policy(NamedPolicy {
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
    });
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
