//! Persist round-trip and UDP listener adversarial tests.
//! Z6.4: `kdb_put_entry` stamps `KRB5_TL_MOD_PRINC` with
//! `handle->current_caller` (`server_kdb.c:376-377`), not a hard-coded
//! `kadmin/admin@REALM`. Compiles at the parent: `create_password` already
//! takes `actor`, but `stamp_admin_tl` ignored it.
//! Z7.2 (c): `kdb5_util create` stamps `db_creation@REALM`
//! (`kdb5_create.c:114-133`). Compiles at the parent: bootstrap and
//! `tl_mod_princ_name` exist; the parent hard-codes `kadmin/admin@REALM`.
//! Z8.3: `kadm5_create` stamps `kadmin/admin` and `kadmin/changepw`
//! `kdb5_util@REALM` (`kadm5_create.c:100`). Compiles at the parent:
//! bootstrap and `tl_mod_princ_name` exist; the parent restamps them
//! `db_creation@` via `apply_admin_fields`.
//! Z8 leftover: `kadm5_purgekeys` → `kdb_put_entry` stamps
//! `current_caller` (`server_kdb.c:376-377`). Compiles at the parent:
//! `purgekeys` and `tl_mod_princ_name` exist; the parent does not stamp.
//! Z8 leftover: `kadm5_set_string` → `kdb_put_entry` stamps
//! `current_caller` (`svr_principal.c:2022-2043`). Compiles at the
//! parent: `set_string` and `tl_mod_princ_name` exist; the parent
//! writes the attr and does not stamp.

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, decrypt, string_to_key};
use krb5_kdc::{
    Acl, S2K_ITERS, TEST_REALM, TEST_USER, TEST_USER_PASSWORD, TL_MOD_PRINC, as_req,
    bootstrap_documented, documented_admin_id, documented_changepw, documented_kadmin,
    handle_request, load_store, pa_enc_timestamp, save_store, tl_mod_princ_name,
};
use krb5_testkit::scratch_dir;
use krb5_types::{AsRep, PrincipalName, ku};

#[test]
fn persist_survives_restart_without_key_regen() {
    let dir = scratch_dir("krb5-persist");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, _) = bootstrap_documented().unwrap();
    let krbtgt_before = store
        .krbtgt()
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .as_bytes()
        .to_vec();
    save_store(&store, &db, &stash).unwrap();
    let header = std::fs::read(&db).unwrap();
    assert!(
        header.starts_with(b"kdb5_util load_dump version 7"),
        "live db must be dump version 7, got {}",
        String::from_utf8_lossy(&header[..header.len().min(40)])
    );
    assert!(!header.starts_with(b"KDB3"));
    let loaded = load_store(&db, &stash).unwrap();
    let krbtgt_after = loaded
        .krbtgt()
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .as_bytes()
        .to_vec();
    assert_eq!(krbtgt_before, krbtgt_after);
    assert_ne!(
        loaded.domain_sid().to_sddl(),
        krb5_types::pac::RpcSid::dummy_domain().to_sddl()
    );
    assert_eq!(loaded.domain_sid().to_sddl(), store.domain_sid().to_sddl());
    let user = krb5_types::PrincipalName::new(krb5_types::PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    assert_eq!(
        loaded.get_name(&user).unwrap().rid,
        store.get_name(&user).unwrap().rid
    );
    assert_eq!(loaded.krbtgt().unwrap().rid, krb5_kdc::RID_KRBTGT);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn persist_ulog_survives_reload() {
    let dir = scratch_dir("krb5-ulog");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (mut store, acl) = bootstrap_documented().unwrap();
    store.persist_paths = Some((db.clone(), stash.clone()));
    save_store(&store, &db, &stash).unwrap();
    let extra = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "ulog.kerber.test"]);
    store
        .create_host(&acl, &documented_admin_id(), &extra)
        .unwrap();
    let sno = store.serial();
    assert!(sno > 0);
    let before = store.ulog();
    assert!(
        before.iter().any(|e| e.name.contains("ulog.kerber.test")),
        "ulog must record the create: {before:?}"
    );
    let loaded = load_store(&db, &stash).unwrap();
    assert_eq!(loaded.serial(), sno);
    let after = loaded.ulog();
    assert!(
        after
            .iter()
            .any(|e| e.name.contains("ulog.kerber.test") && e.princ.is_some()),
        "reloaded ulog must keep extra: {after:?}"
    );
    let delta = loaded.updates_after(sno.saturating_sub(1));
    assert!(
        !delta.is_empty(),
        "replica poll after restart must stay incremental"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn persist_writes_db_and_stash_mode_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch_dir("krb5-persist-0600");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, _) = bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let db_mode = std::fs::metadata(&db).unwrap().permissions().mode() & 0o777;
    let stash_mode = std::fs::metadata(&stash).unwrap().permissions().mode() & 0o777;
    assert_eq!(db_mode, 0o600, "db must be 0600");
    assert_eq!(stash_mode, 0o600, "stash must be 0600");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reload_if_stale_sees_kadmin_create() {
    let dir = scratch_dir("krb5-reload");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (mut writer, acl) = bootstrap_documented().unwrap();
    save_store(&writer, &db, &stash).unwrap();
    let mut reader = load_store(&db, &stash).unwrap();
    reader.policy.allow_rc4 = true;
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["extra"]);
    writer.persist_paths = Some((db.clone(), stash.clone()));
    writer
        .create_password(&acl, &documented_admin_id(), &extra, b"extra-secret")
        .unwrap();
    reader.reload_if_stale().unwrap();
    assert!(
        reader.get_name(&extra).is_some(),
        "KDC must pick up kadmind create from the shared db"
    );
    assert!(
        reader.policy.allow_rc4,
        "kdc.conf allow_rc4 must survive dump reload"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reload_if_stale_keeps_lockout_and_pa_replay() {
    use krb5_kdc::{NamedPolicy, TEST_USER};
    use krb5_protocol::ReplayKey;

    let dir = scratch_dir("krb5-reload-overlay");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (mut writer, acl) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    writer.put_policy(NamedPolicy {
        name: "lock".into(),
        min_length: 0,
        min_classes: 0,
        history: 0,
        max_fail: 3,
        pw_failcnt_interval: 0,
        pw_lockout_duration: 0,
        pw_min_life: 0,
        pw_max_life: 0,
        allowed_keysalts: None,
    });
    writer
        .set_principal_policy(&user, Some("lock".into()))
        .unwrap();
    save_store(&writer, &db, &stash).unwrap();
    let mut reader = load_store(&db, &stash).unwrap();
    let before = reader.get_name(&user).unwrap();
    assert_eq!(reader.max_fail_for(before), 3);
    reader.record_as_outcome(&user, false);
    reader.record_as_outcome(&user, false);
    let after_fail = reader.get_name(&user).unwrap();
    assert_eq!(reader.fail_auth_of(after_fail), 2);
    let rk = ReplayKey {
        client: format!("{TEST_USER}@{TEST_REALM}"),
        server: format!("krbtgt/{TEST_REALM}@{TEST_REALM}"),
        ctime: 1,
        cusec: 2,
        auth_hash: [7u8; 20],
    };
    assert!(
        !reader.pa_replay().check_and_store(rk.clone()),
        "first PA must insert"
    );
    writer.persist_paths = Some((db.clone(), stash.clone()));
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["unrelated"]);
    writer
        .create_password(&acl, &documented_admin_id(), &extra, b"unrelated-secret")
        .unwrap();
    reader.reload_if_stale().unwrap();
    assert!(reader.get_name(&extra).is_some(), "reload must see extra");
    let after = reader.get_name(&user).unwrap();
    assert_eq!(
        reader.fail_auth_of(after),
        2,
        "lockout overlay must survive reload_if_stale"
    );
    assert!(
        reader.pa_replay().check_and_store(rk),
        "PA replay cache must survive reload_if_stale"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn persist_paths_saves_password_lock_and_expiry() {
    let dir = scratch_dir("krb5-persist-status");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, acl) = bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let mut store = load_store(&db, &stash).unwrap();
    assert!(
        store.persist_paths.is_some(),
        "load_store must wire persist_paths so mutations save"
    );
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let kvno_before = store
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    store
        .change_password(&acl, &documented_admin_id(), &user, b"rotated-secret")
        .unwrap();
    store.set_status(&user, true, 1_700_000_123).unwrap();
    let loaded = load_store(&db, &stash).unwrap();
    let p = loaded.get_name(&user).unwrap();
    let kvno_after = p.keys.iter().map(|k| k.kvno).max().unwrap();
    assert!(
        kvno_after > kvno_before,
        "change_password must persist a kvno bump via save_if_configured"
    );
    assert!(p.locked, "locked must round-trip through dump v7");
    assert_eq!(p.pw_expire, 1_700_000_123);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn persist_dump_v7_issues_as_with_string_to_key() {
    let dir = scratch_dir("krb5-persist-as");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, _) = bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let raw = std::fs::read(&db).unwrap();
    assert!(raw.starts_with(b"kdb5_util load_dump version 7"));
    assert!(!raw.starts_with(b"KDB3"));
    let loaded = load_store(&db, &stash).unwrap();
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let salt = cname.default_salt(TEST_REALM);
    let key = string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        &salt,
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let req = as_req(
        cname,
        TEST_REALM,
        77,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let rep = handle_request(&loaded, &encode(&req).unwrap()).unwrap();
    assert_eq!(rep.first().copied(), Some(0x6b));
    let as_rep: AsRep = decode(&rep).unwrap();
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&key, usage, as_rep.0.enc_part.cipher.as_ref()).unwrap();
    let _ = krb5_asn1::decode_enc_kdc_rep_part(&plain).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn persist_legacy_kdb3_still_loads_sid() {
    use krb5_kdc::save_store_legacy_kdb3;

    let dir = scratch_dir("krb5-persist-kdb3");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, _) = bootstrap_documented().unwrap();
    let sid = store.domain_sid().to_sddl();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let rid = store.get_name(&user).unwrap().rid;
    save_store_legacy_kdb3(&store, &db, &stash).unwrap();
    let raw = std::fs::read(&db).unwrap();
    assert!(raw.starts_with(b"KDB3"));
    let loaded = load_store(&db, &stash).unwrap();
    assert_eq!(loaded.domain_sid().to_sddl(), sid);
    assert_eq!(loaded.get_name(&user).unwrap().rid, rid);
    assert_ne!(sid, krb5_types::pac::RpcSid::dummy_domain().to_sddl());
    let cname = user;
    let salt = cname.default_salt(TEST_REALM);
    let key = string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        TEST_USER_PASSWORD,
        &salt,
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .unwrap();
    let req = as_req(
        cname,
        TEST_REALM,
        78,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let rep = handle_request(&loaded, &encode(&req).unwrap()).unwrap();
    assert_eq!(rep.first().copied(), Some(0x6b));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stash_is_keytab_format_and_reads_back_the_master() {
    // MIT krb5_def_store_mkey_list writes a FILE keytab with one K/M@REALM
    // entry; klist -k / kdb5_util read it. The Rust stash matches (etype/kvno
    // embedded, so load is a single decrypt, not a blind etype trial).
    let dir = scratch_dir("krb5-stash-kt");
    let db = dir.join("principal");
    let stash = dir.join(".k5.KERBER.TEST");
    let (store, _) = bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let bytes = std::fs::read(&stash).unwrap();
    assert_eq!(&bytes[..2], &[0x05, 0x02], "keytab v2 magic");
    let kt = krb5_protocol::Keytab::parse(&bytes).unwrap();
    let km = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["K", "M"]);
    let entry = kt.entries.iter().find(|e| e.name == km).expect("K/M entry");
    assert_eq!(entry.realm.as_bytes(), TEST_REALM.as_bytes());
    assert_eq!(entry.kvno, 1);
    assert!(matches!(
        entry.key.etype(),
        EncryptionType::Aes256CtsHmacSha384192 | EncryptionType::Aes256CtsHmacSha196
    ));
    let krbtgt = store
        .krbtgt()
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .as_bytes()
        .to_vec();
    let loaded = load_store(&db, &stash).unwrap();
    assert_eq!(
        loaded.krbtgt().unwrap().best_key().unwrap().key.as_bytes(),
        krbtgt.as_slice()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn legacy_raw_stash_loads_then_is_rewritten_as_keytab() {
    let dir = scratch_dir("krb5-stash-raw");
    let db = dir.join("principal");
    let stash = dir.join(".k5.KERBER.TEST");
    let (store, _) = bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    // Derive the legacy raw stash from the keytab the save just wrote (the bare
    // master-key bytes with no keytab framing).
    let kt = krb5_protocol::Keytab::parse(&std::fs::read(&stash).unwrap()).unwrap();
    let km = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["K", "M"]);
    let master = kt.entries.iter().find(|e| e.name == km).unwrap();
    std::fs::write(&stash, master.key.as_bytes()).unwrap();
    assert_ne!(&std::fs::read(&stash).unwrap()[..2], &[0x05, 0x02]);
    // A raw stash still loads (krb5_db_def_fetch_mkey fallback).
    let loaded = load_store(&db, &stash).unwrap();
    // Saving rewrites it in keytab format.
    save_store(&loaded, &db, &stash).unwrap();
    let bytes = std::fs::read(&stash).unwrap();
    assert_eq!(&bytes[..2], &[0x05, 0x02], "raw stash rewritten as keytab");
    load_store(&db, &stash).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

fn tl_mod_name(p: &krb5_kdc::Principal) -> Option<String> {
    let t = p.tl_data.iter().find(|t| t.ty == TL_MOD_PRINC)?;
    let bytes = t.contents.get(4..)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8(bytes[..end].to_vec()).ok()
}

#[test]
fn create_stamps_the_authenticated_caller() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let actor = "joe/admin@KERBER.TEST";
    let acl = Acl::allow_admin(actor).unwrap();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["z64u"]);
    store
        .create_password(&acl, actor, &name, b"z64-secret")
        .unwrap();
    let p = store.get_name(&name).expect("created");
    assert_eq!(
        tl_mod_name(p).as_deref(),
        Some(actor),
        "TL_MOD_PRINC must be current_caller, not kadmin/admin (got {:?}); documented admin is {}",
        tl_mod_name(p),
        documented_admin_id()
    );
    assert_ne!(
        tl_mod_name(p).as_deref(),
        Some("kadmin/admin@KERBER.TEST"),
        "must not hard-code the kadmind acceptor"
    );
}

#[test]
fn bootstrap_krbtgt_is_stamped_db_creation() {
    let (store, _) = bootstrap_documented().unwrap();
    let tgt = PrincipalName::krbtgt(TEST_REALM);
    let p = store.get_name(&tgt).expect("krbtgt");
    let got = tl_mod_princ_name(&p.tl_data);
    assert_eq!(
        got.as_deref(),
        Some("db_creation@KERBER.TEST"),
        "kdb5_util create stamps db_creation@REALM (got {got:?})"
    );
}

#[test]
fn bootstrap_kadmin_services_are_stamped_kdb5_util() {
    let (store, _) = bootstrap_documented().unwrap();
    for (label, name) in [
        ("kadmin/admin", documented_kadmin()),
        ("kadmin/changepw", documented_changepw()),
    ] {
        let p = store.get_name(&name).unwrap_or_else(|| panic!("{label}"));
        let got = tl_mod_princ_name(&p.tl_data);
        assert_eq!(
            got.as_deref(),
            Some("kdb5_util@KERBER.TEST"),
            "{label} kadm5_create.c:100 stamps kdb5_util@REALM (got {got:?})"
        );
    }
    let tgt = PrincipalName::krbtgt(TEST_REALM);
    let p = store.get_name(&tgt).expect("krbtgt");
    assert_eq!(
        tl_mod_princ_name(&p.tl_data).as_deref(),
        Some("db_creation@KERBER.TEST"),
        "kdb5_create.c:114-133 still stamps krbtgt db_creation@"
    );
}

#[test]
fn purgekeys_stamps_the_mod_actor() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["z8pk"]);
    store
        .create_password(&acl, &documented_admin_id(), &extra, b"z8pk-secret")
        .unwrap();
    let before = store.get_name(&extra).expect("created");
    assert_eq!(
        tl_mod_princ_name(&before.tl_data).as_deref(),
        Some("admin@KERBER.TEST"),
        "create stamps the session actor"
    );
    store.purgekeys(&extra, -1).unwrap();
    let after = store.get_name(&extra).expect("still there");
    assert_eq!(
        tl_mod_princ_name(&after.tl_data).as_deref(),
        Some("db_creation@KERBER.TEST"),
        "kdb_put_entry stamps current_caller (default_mod_actor without a handle)"
    );
}

#[test]
fn setstr_stamps_the_mod_actor() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["z8str"]);
    store
        .create_password(&acl, &documented_admin_id(), &extra, b"z8str-secret")
        .unwrap();
    let before = store.get_name(&extra).expect("created");
    assert_eq!(
        tl_mod_princ_name(&before.tl_data).as_deref(),
        Some("admin@KERBER.TEST"),
        "create stamps the session actor"
    );
    store.set_string(&extra, "note", Some("leftover")).unwrap();
    let after = store.get_name(&extra).expect("still there");
    assert_eq!(
        tl_mod_princ_name(&after.tl_data).as_deref(),
        Some("db_creation@KERBER.TEST"),
        "kdb_put_entry stamps current_caller (default_mod_actor without a handle)"
    );
}
