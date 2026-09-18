//! Store whole-flow tests (bootstrap + issue_as + public methods).

use krb5_crypto::EncryptionType;
use krb5_kdc::*;
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
    let cap = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while unix_now() <= target {
        assert!(
            std::time::Instant::now() < cap,
            "unix seconds did not pass {target} within 2s"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

#[test]
fn pw_expiration_on_modify_is_last_pwd_change_plus_max_life() {
    let (mut store, _) = krb5_kdc::bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
    let mut pol = NamedPolicy::new("life");
    pol.pw_max_life = 3600;
    store.put_policy(pol);
    store.set_last_pwd_unix(&user, 1_000_000);
    store
        .apply_admin_fields(
            &user,
            None,
            None,
            None,
            None,
            Some("life".into()),
            false,
            None,
        )
        .unwrap();
    let after = store.get_name(&user).unwrap();
    assert_eq!(after.pw_expire, 1_000_000 + 3600);
}

#[test]
fn spake_not_advertised_without_groups() {
    let (mut store, _) = krb5_kdc::bootstrap_documented().unwrap();
    store.policy.spake_preauth_groups.clear();
    let req = krb5_protocol::as_req(
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]),
        krb5_kdc::TEST_REALM,
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
    let (store, _) = krb5_kdc::bootstrap_documented().unwrap();
    assert_ne!(
        store.domain_sid().to_sddl(),
        RpcSid::dummy_domain().to_sddl()
    );
    assert_eq!(store.krbtgt().unwrap().rid, RID_KRBTGT);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
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
    let (mut store, acl) = krb5_kdc::bootstrap_documented().unwrap();
    let actor = krb5_kdc::documented_admin_id();
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

    let (mut store, _) = krb5_kdc::bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
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
        krb5_kdc::TEST_REALM,
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
            krb5_kdc::TEST_REALM,
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
    let (mut store, _) = krb5_kdc::bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
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

#[test]
fn iprop_get_ships_principals_only_like_ulog_get_entries() {
    let (mut store, _) = krb5_kdc::bootstrap_documented().unwrap();
    let before = store.serial();
    store.put_policy(NamedPolicy::new("ipol"));
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
    store
        .set_principal_policy(&user, Some("ipol".into()))
        .unwrap();
    store.set_password(&user, b"Ipol-pw1").unwrap();
    // A principal literally named `policy:svc` must still ship (its id
    // carries @REALM; only the marker `policy:ipol` is filtered).
    let acl = Acl::allow_admin(krb5_kdc::documented_admin_id()).unwrap();
    let colliding = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["policy:svc"]);
    store
        .create_password(
            &acl,
            &krb5_kdc::documented_admin_id(),
            &colliding,
            b"collide-pw",
        )
        .unwrap();
    let (status, last, entries) = store.iprop_get(before);
    assert_eq!(status, IPROP_OK);
    assert_eq!(
        last,
        store.serial(),
        "the policy marker still advances the serial"
    );
    assert!(!entries.is_empty());
    // The bare marker `policy:ipol` (no @) is filtered; the principal
    // `policy:svc@REALM` is not.
    assert!(
        entries
            .iter()
            .all(|e| !e.name.starts_with("policy:") || e.name.contains('@'))
    );
    assert!(
        entries.iter().any(|e| e.name.starts_with("policy:svc@")),
        "a principal named policy:svc must not be filtered: {entries:?}"
    );
    assert!(
        entries
            .iter()
            .any(|e| e.name.starts_with("kadmin/history@"))
    );
    assert!(entries.iter().any(|e| e.name.starts_with("user@")));
}

#[test]
fn kadmin_history_is_created_before_a_rejected_quality_chpass() {
    // MIT kadm5_chpass_principal_3 fetches the history key (creating
    // kadmin/history) before passwd_check, so a chpass rejected for a
    // short password still leaves kadmin/history created.
    let (mut store, _) = krb5_kdc::bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
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
    let (mut store, _) = krb5_kdc::bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
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
        again.get_name(&krb5_kdc::documented_history()).is_some(),
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

    let (store, _) = krb5_kdc::bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
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
        krb5_kdc::TEST_REALM,
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
        krb5_kdc::TEST_REALM,
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

    let (mut store, _) = krb5_kdc::bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
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
        krb5_kdc::TEST_REALM,
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
            krb5_kdc::TEST_REALM,
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

#[test]
fn lockout_interval_only_resets_fail_count() {
    use krb5_protocol::{as_req, pa_enc_timestamp_at};
    use krb5_types::KerberosTime;

    let (mut store, _) = krb5_kdc::bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
    store.put_policy(NamedPolicy {
        name: "intv".into(),
        min_length: 0,
        min_classes: 0,
        history: 0,
        max_fail: 1,
        pw_failcnt_interval: 1,
        pw_lockout_duration: 0,
        pw_min_life: 0,
        pw_max_life: 0,
        allowed_keysalts: None,
    });
    store
        .set_principal_policy(&user, Some("intv".into()))
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
            krb5_kdc::TEST_REALM,
            1,
            Some(vec![pa_enc_timestamp_at(&zeros, &ts).unwrap()]),
        )
        .unwrap()
    };
    let revoked = |e: &Error| matches!(e, Error::Protocol { code, .. } if *code == krb5_types::err::CLIENT_REVOKED);
    assert!(krb5_kdc::issue_as(&store, &bad_as()).is_err());
    wait_unix_past(unix_now());
    let second = krb5_kdc::issue_as(&store, &bad_as()).unwrap_err();
    assert!(
        !revoked(&second),
        "elapsed failcnt interval with duration=0 must not lock: {second:?}"
    );
}

#[test]
fn serial_ulog_delta_then_issue_as() {
    use krb5_protocol::as_req;

    let (mut master, acl) = krb5_kdc::bootstrap_documented().unwrap();
    let (mut slave, _) = krb5_kdc::bootstrap_documented().unwrap();
    let actor = krb5_kdc::documented_admin_id();
    let sno0 = master.serial();
    assert!(
        sno0 > 0,
        "bootstrap mutations must advance serial (not mtime-only)"
    );
    assert_eq!(master.iprop_get(0).0, IPROP_FULL_RESYNC);
    assert_eq!(master.iprop_get(sno0).0, IPROP_NIL);
    // A replica ahead of the master (rollback) must full-resync, not NIL.
    assert_eq!(
        master.iprop_get(sno0 + 100).0,
        IPROP_FULL_RESYNC,
        "a replica serial past the master's must resync"
    );

    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["iproped"]);
    master
        .create_password(&acl, &actor, &extra, b"iprop-secret")
        .unwrap();
    let sno1 = master.serial();
    assert!(sno1 > sno0);
    let (st, last, entries) = master.iprop_get(sno0);
    assert_eq!(st, IPROP_OK);
    assert_eq!(last, sno1);
    assert!(
        entries
            .iter()
            .any(|e| e.name.contains("iproped") && !e.deleted),
        "ulog must record the create: {entries:?}"
    );

    slave.apply_updates(&entries);
    assert!(slave.get_name(&extra).is_some());
    assert_eq!(slave.serial(), sno1);
    let key = slave
        .get_name(&extra)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        extra,
        krb5_kdc::TEST_REALM,
        11,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(&slave, &req).expect("slave must issue after serial-delta");
}

#[test]
fn apply_updates_assigns_rid_so_replica_pac_is_not_first_user() {
    use krb5_kdc::{decrypt_ticket_part, pa_enc_timestamp, pac_from_ticket_part};
    use krb5_protocol::as_req;
    use krb5_types::pac::{PAC_LOGON_INFO, Pac, parse_kerb_validation_info};

    let (mut master, acl) = krb5_kdc::bootstrap_documented().unwrap();
    let (mut slave, _) = krb5_kdc::bootstrap_documented().unwrap();
    let actor = krb5_kdc::documented_admin_id();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
    let user_rid = slave.get_name(&user).unwrap().rid;
    assert_eq!(user_rid, RID_FIRST_USER);

    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["iproped"]);
    master
        .create_password(&acl, &actor, &extra, b"iprop-secret")
        .unwrap();
    let mut incr = master.get_name(&extra).unwrap().clone();
    incr.rid = 0;
    incr.tl_data.retain(|t| t.ty != krb5_kdc::TL_KERBER_SID);
    slave.apply_updates(&[UlogEntry {
        sno: slave.serial().saturating_add(1),
        time: 1,
        name: incr.id(),
        deleted: false,
        princ: Some(incr),
    }]);

    let got = slave.get_name(&extra).unwrap().clone();
    assert_ne!(got.rid, 0, "incremental apply must allocate a RID");
    assert_ne!(got.rid, RID_FIRST_USER);
    assert_ne!(got.rid, user_rid);

    let key = got.best_key().unwrap().key.clone();
    let req = as_req(
        extra.clone(),
        krb5_kdc::TEST_REALM,
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
fn apply_updates_keeps_keys_on_keyless_incremental() {
    let (mut store, acl) = krb5_kdc::bootstrap_documented().unwrap();
    let actor = krb5_kdc::documented_admin_id();
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["keyless"]);
    store
        .create_password(&acl, &actor, &extra, b"keyless-secret")
        .unwrap();
    store.set_string(&extra, "note", Some("keep-me")).unwrap();
    let before = store.get_name(&extra).unwrap().clone();
    assert!(!before.keys.is_empty());
    let mut incr = before.clone();
    incr.keys.clear();
    incr.key_history.clear();
    incr.string_attrs.clear();
    incr.tl_data.clear();
    incr.pw_policy = None;
    let sno = store.serial().saturating_add(1);
    store.apply_updates(&[UlogEntry {
        sno,
        time: 1,
        name: before.id(),
        deleted: false,
        princ: Some(incr),
    }]);
    let after = store.get_name(&extra).unwrap();
    assert_eq!(after.keys.len(), before.keys.len());
    assert_eq!(after.keys[0].key.as_bytes(), before.keys[0].key.as_bytes());
    assert_eq!(after.string_attrs, before.string_attrs);
    assert_eq!(after.key_history.len(), before.key_history.len());
}

#[test]
fn ulog_records_delete_rename_chrand() {
    let (mut store, acl) = krb5_kdc::bootstrap_documented().unwrap();
    let actor = krb5_kdc::documented_admin_id();
    let a = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["ulogdel"]);
    let b = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["ulogren"]);
    store
        .create_password(&acl, &actor, &a, b"ulog-secret")
        .unwrap();
    let after_create = store.serial();
    store.delete(&acl, &actor, &a).unwrap();
    let del = store.updates_after(after_create);
    assert!(
        del.iter().any(|e| e.name.contains("ulogdel") && e.deleted),
        "delete must be ulogged: {del:?}"
    );
    store
        .create_password(&acl, &actor, &a, b"ulog-secret")
        .unwrap();
    let after_recreate = store.serial();
    store.rename(&acl, &actor, &a, &b).unwrap();
    let ren = store.updates_after(after_recreate);
    assert!(
        ren.iter().any(|e| e.name.contains("ulogdel") && e.deleted)
            && ren
                .iter()
                .any(|e| e.name.contains("ulogren") && !e.deleted && e.princ.is_some()),
        "rename must ulog delete+add: {ren:?}"
    );
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
    let after_ren = store.serial();
    store.chrand(&user).unwrap();
    let ch = store.updates_after(after_ren);
    assert!(
        ch.iter()
            .any(|e| e.name.contains(krb5_kdc::TEST_USER) && e.princ.is_some()),
        "chrand must be ulogged: {ch:?}"
    );
    store.set_status(&user, true, 0).unwrap();
    assert!(
        store
            .ulog()
            .iter()
            .any(|e| e.name.contains(krb5_kdc::TEST_USER)
                && e.princ.as_ref().is_some_and(|p| p.locked)),
        "set_status must be ulogged"
    );
}

#[test]
fn admin_unlock_clears_failcount_lockout() {
    use krb5_protocol::as_req;
    use krb5_types::err;
    let (mut store, _) = krb5_kdc::bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
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
    store.record_as_outcome(&user, false);
    let key = store
        .get_name(&user)
        .unwrap()
        .key_for(EncryptionType::Aes256CtsHmacSha196)
        .unwrap()
        .key
        .clone();
    let req = as_req(
        user.clone(),
        krb5_kdc::TEST_REALM,
        502,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
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
