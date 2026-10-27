//! Persist round-trip and UDP listener adversarial tests, and the modifier each write
//! stamps.
// MIT: `kdb_put_entry` (server_kdb.c:376-377)
//! the put stamps `KRB5_TL_MOD_PRINC` with
//! `handle->current_caller`, not a hard-coded `kadmin/admin@REALM`, so the actor a create
//! names is the stamp.
//! `kdb5_util create` stamps `db_creation@REALM`.
// MIT: `db_creator_entries` (kdb5_create.c:114-115)
//! the stamp's one name component is
//! `db_creation`.
// MIT: `db_create_princ` (kdb5_create.c:127-133)
//! the `db_creation` principal that
//! `add_principal` stamps as the modifier of each principal `kdb5_util create` writes.
//! `kadm5_create` stamps `kadmin/admin` and `kadmin/changepw` with `kdb5_util@REALM`.
// MIT: `kadm5_create_magic_princs` (kadm5_create.c:100-100)
//! the kadm5 handle is opened
//! with `progname` as the client name, so its `current_caller` is `kdb5_util@REALM`.
//! `kadm5_purgekeys` goes through `kdb_put_entry`, which stamps `current_caller`.
// MIT: `kdb_put_entry` (server_kdb.c:376-377)
//! the put stamps the modifier as
//! `handle->current_caller`.
//! `kadm5_set_string` goes through `kdb_put_entry` too, so it stamps `current_caller`.
// MIT: `kadm5_set_string` (svr_principal.c:2022-2043)
//! the string is stored through
//! `kdb_put_entry`.

use krb5_crypto::EncryptionType;
use krb5_kdc::principals::{kadmin_admin, kadmin_changepw};
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented, documented_admin_id};
use krb5_kdc::{Acl, TL_MOD_PRINC, load_store, save_store, tl_mod_princ_name};

use krb5_testkit::scratch_dir;
use krb5_types::PrincipalName;

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

/// MIT `ulog_replay`: a put that fails ends the replay and reinitializes the replica's log, so
/// its next request is a full resync. Here the replica's database may not be written.
#[cfg(feature = "test-hooks")]
#[cfg(unix)]
#[test]
fn a_replica_whose_database_write_fails_starts_its_log_over() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = scratch_dir("krb5-replay-write");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (mut master, acl) = bootstrap_documented().unwrap();
    let mkey = krb5_kdc::testrealm::map_memory_ulog(&mut master, 100, krb5_kdc::IpropRole::Primary)
        .unwrap();
    let start = master.ulog_last().unwrap();
    let extra = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "replay.kerber.test"]);
    master
        .create_host(&acl, &documented_admin_id(), &extra)
        .unwrap();
    let updates: Vec<krb5_kdc::IpropUpdate> = master
        .ulog_get_entries(start)
        .updates
        .iter()
        .map(|u| krb5_kdc::decode_incr_update(u, Some(&mkey)).unwrap().0)
        .collect();
    let (mut replica, _) = bootstrap_documented().unwrap();
    replica.persist_paths = Some((db.clone(), stash.clone()));
    save_store(&replica, &db, &stash).unwrap();
    replica.set_ulog(
        krb5_kdc::Ulog::memory(100).unwrap(),
        krb5_kdc::IpropRole::Replica,
    );
    replica.ulog().unwrap().set_last(start).unwrap();
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o400)).unwrap();
    let written = replica.change(|s| s.apply_updates(&updates));
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(written.is_err(), "{written:?}");
    let hdr = replica.ulog().unwrap().header_now().unwrap();
    assert_eq!((hdr.num, hdr.first_sno, hdr.last_sno), (1, 1, 1));
    assert!(replica.get_name(&extra).is_none());
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

/// The keytab rewrite of a legacy raw stash is optional: a stash the writer may only read
/// still serves the save, and stays as it was.
#[cfg(unix)]
#[test]
fn legacy_raw_stash_the_writer_may_not_write_is_kept() {
    use std::os::unix::fs::PermissionsExt as _;
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let dir = scratch_dir("krb5-stash-raw-ro");
    let db = dir.join("principal");
    let stash = dir.join(".k5.KERBER.TEST");
    let (store, _) = bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let kt = krb5_protocol::Keytab::parse(&std::fs::read(&stash).unwrap()).unwrap();
    let raw = kt.entries[0].key.as_bytes().to_vec();
    std::fs::write(&stash, &raw).unwrap();
    std::fs::set_permissions(&stash, std::fs::Permissions::from_mode(0o400)).unwrap();
    let loaded = load_store(&db, &stash).unwrap();
    save_store(&loaded, &db, &stash).unwrap();
    assert_eq!(
        std::fs::read(&stash).unwrap(),
        raw,
        "the raw stash is left alone"
    );
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
        ("kadmin/admin", kadmin_admin()),
        ("kadmin/changepw", kadmin_changepw()),
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
