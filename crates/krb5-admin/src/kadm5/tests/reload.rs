//! kadm5 reload tests (private-bound; regrouped in place).

use super::*;

#[test]
fn chpass_reload_keeps_concurrent_local_create() {
    use krb5_kdc::{load_store, save_store};
    let dir = krb5_testkit::scratch_dir("n7-chpass");
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let mut local = load_store(&db, &stash).unwrap();
    let kadmind = load_store(&db, &stash).unwrap();
    let n7 = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["n7local"]);
    {
        let mut sess =
            AdminSession::local(&mut local, &acl, krb5_kdc::testrealm::documented_admin_id());
        sess.create_password(&n7, b"n7-secret").unwrap();
    }
    let shared = krb5_kdc::shared_dump(kadmind);
    let actor = krb5_kdc::testrealm::documented_admin_id();
    let out = dispatch_kadm5(
        &shared,
        &acl,
        &actor,
        CHPASS_PRINCIPAL,
        &chpass_args("user@KERBER.TEST", "n7-changed"),
    )
    .unwrap();
    assert_eq!(ret_code(&out), 0, "chpass user");
    let loaded = load_store(&db, &stash).unwrap();
    assert!(
        loaded.get_name(&n7).is_some(),
        "local addprinc must survive remote cpw"
    );
    assert!(
        loaded
            .get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
            .is_some()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn extract_reload_sees_local_cpw() {
    use krb5_kdc::{load_store, save_store};
    let dir = krb5_testkit::scratch_dir("o3-extract");
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let mut local = load_store(&db, &stash).unwrap();
    let kadmind = load_store(&db, &stash).unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let before = local
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    {
        let mut sess =
            AdminSession::local(&mut local, &acl, krb5_kdc::testrealm::documented_admin_id());
        sess.change_password(&user, b"o3-new-secret").unwrap();
    }
    let after = local
        .get_name(&user)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .max()
        .unwrap();
    assert!(after > before, "cpw must bump kvno");
    let shared = krb5_kdc::shared_dump(kadmind);
    let actor = krb5_kdc::testrealm::documented_admin_id();
    let out = dispatch_kadm5(
        &shared,
        &acl,
        &actor,
        EXTRACT_KEYS,
        &extract_args("user@KERBER.TEST", 0),
    )
    .unwrap();
    assert_eq!(ret_code(&out), 0, "extract");
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), API_V2);
    assert_eq!(r.u32().unwrap(), 0);
    let n = r.u32().unwrap();
    assert!(n > 0);
    let kvno = r.u32().unwrap();
    assert_eq!(kvno, after, "EXTRACT_KEYS must reload after local cpw");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A database kadmind may not write refuses each change before it is made, with MIT's
/// KRB5_KDB_CANTLOCK_DB, and keeps nothing of it in memory; the checks MIT makes before its lock
/// (an existing name, a missing one) still answer first.
#[test]
fn readonly_database_refuses_changes_before_making_them() {
    use std::os::unix::fs::PermissionsExt as _;

    use krb5_kdc::{load_store, save_store};
    if nix::unistd::geteuid().is_root() {
        // root may write a 0400 file, so there is no refusal to observe.
        return;
    }
    let dir = krb5_testkit::scratch_dir("ro-db");
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let shared = krb5_kdc::shared_dump(load_store(&db, &stash).unwrap());
    let actor = krb5_kdc::testrealm::documented_admin_id();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let snapshot = |s: &SharedStore| {
        let g = s.read().unwrap();
        let p = g.get_name(&user).unwrap();
        (p.attributes, p.keys.iter().map(|k| k.kvno).max())
    };
    let before = snapshot(&shared);
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o400)).unwrap();
    let call = |proc: u32, args: &[u8]| {
        ret_code(&dispatch_kadm5(&shared, &acl, &actor, proc, args).unwrap())
    };
    assert_eq!(
        call(
            CREATE_PRINCIPAL,
            &create_rec("ro1@KERBER.TEST", "ro-secret-1")
        ),
        KRB5_KDB_CANTLOCK_DB
    );
    let ro1 = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["ro1"]);
    assert!(shared.read().unwrap().get_name(&ro1).is_none());
    assert_eq!(
        call(
            CREATE_PRINCIPAL,
            &create_rec("user@KERBER.TEST", "x-secret")
        ),
        KADM5_DUP
    );
    assert_eq!(
        call(MODIFY_PRINCIPAL, &modify_args("user@KERBER.TEST")),
        KRB5_KDB_CANTLOCK_DB
    );
    assert_eq!(
        call(
            CHPASS_PRINCIPAL,
            &chpass_args("user@KERBER.TEST", "ro-changed-1")
        ),
        KRB5_KDB_CANTLOCK_DB
    );
    assert_eq!(
        call(DELETE_PRINCIPAL, &encode_named("user@KERBER.TEST")),
        KRB5_KDB_CANTLOCK_DB
    );
    assert_eq!(
        call(DELETE_PRINCIPAL, &encode_named("nosuch@KERBER.TEST")),
        KADM5_UNK_PRINC
    );
    assert_eq!(snapshot(&shared), before);
    std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        call(GET_PRINCIPAL, &getprinc_args("ro1@KERBER.TEST")),
        KADM5_UNK_PRINC
    );
    assert_eq!(
        call(
            CREATE_PRINCIPAL,
            &create_rec("ro1@KERBER.TEST", "ro-secret-1")
        ),
        0
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A password change under a policy creates `kadmin/history` before its quality check and saves
/// it on its own, as MIT's `create_hist` commits it (two update-log entries): a change refused for
/// quality leaves it in the database, and one naming a keysalt the policy refuses is refused
/// first and creates nothing.
#[test]
fn failed_chpass_keeps_the_history_principal() {
    use krb5_kdc::{load_store, save_store};
    let dir = krb5_testkit::scratch_dir("hist-commit");
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (mut store, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let actor = krb5_kdc::testrealm::documented_admin_id();
    for (pol, user, keysalts) in [
        ("kspol", "ku", Some("aes256-cts-hmac-sha1-96:normal")),
        ("hpol", "hu", None),
    ] {
        let mut p = krb5_kdc::NamedPolicy::new(pol);
        p.min_length = 8;
        p.history = 2;
        p.allowed_keysalts = keysalts.map(str::to_owned);
        store.put_policy(p);
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [user]);
        store
            .create_password(&acl, &actor, &name, b"hist-initial-secret")
            .unwrap();
        store.set_principal_policy(&name, Some(pol.into())).unwrap();
    }
    save_store(&store, &db, &stash).unwrap();
    let kadmind = krb5_kdc::shared_dump(load_store(&db, &stash).unwrap());
    let call = |proc: u32, args: &[u8]| {
        ret_code(&dispatch_kadm5(&kadmind, &acl, &actor, proc, args).unwrap())
    };
    let hist = krb5_kdc::principals::kadmin_history();
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("ku@KERBER.TEST"));
    w.u32(0);
    w.u32(1);
    w.u32(17);
    w.u32(0);
    w.nullstring(Some("sh"));
    assert_eq!(call(CHPASS_PRINCIPAL3, &w.b), KADM5_BAD_KEYSALTS);
    assert!(load_store(&db, &stash).unwrap().get_name(&hist).is_none());
    assert_eq!(
        call(CHPASS_PRINCIPAL, &chpass_args("hu@KERBER.TEST", "sh")),
        KADM5_PASS_Q_TOOSHORT
    );
    assert_eq!(
        call(GET_PRINCIPAL, &getprinc_args("kadmin/history@KERBER.TEST")),
        0
    );
    let on_disk = load_store(&db, &stash).unwrap();
    let kvnos: Vec<u32> = on_disk
        .get_name(&hist)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .collect();
    assert_eq!(kvnos, [2]);
    let logged = on_disk
        .ulog()
        .iter()
        .filter(|e| e.name == "kadmin/history@KERBER.TEST")
        .count();
    assert_eq!(logged, 2, "create_hist's create and its randkey");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A change whose save did not happen is undone: the store goes back to what the database holds.
#[test]
fn failed_change_is_undone_from_the_database() {
    use krb5_kdc::{load_store, save_store};
    let dir = krb5_testkit::scratch_dir("undo-db");
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let mut g = load_store(&db, &stash).unwrap();
    let persist = g.persist_paths.take();
    let lost = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["unsaved"]);
    {
        let mut sess =
            AdminSession::local(&mut g, &acl, krb5_kdc::testrealm::documented_admin_id());
        sess.create_password(&lost, b"unsaved-secret").unwrap();
    }
    assert!(g.get_name(&lost).is_some());
    g.persist_paths = persist;
    undo_failed_update(&mut g);
    assert!(g.get_name(&lost).is_none());
    assert!(
        g.get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
            .is_some()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// What another process (kadmin.local) saved after kadmind loaded the database is what kadmind
/// lists and answers, and a change kadmind makes afterwards keeps it.
#[test]
fn reads_see_another_process_and_writes_keep_its_change() {
    use krb5_kdc::{load_store, save_store};
    let dir = krb5_testkit::scratch_dir("stale-reads");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let kadmind = krb5_kdc::shared_dump(load_store(&db, &stash).unwrap());
    let actor = krb5_kdc::testrealm::documented_admin_id();
    let call = |proc: u32, args: &[u8]| dispatch_kadm5(&kadmind, &acl, &actor, proc, args).unwrap();
    let has = |out: &[u8], name: &str| out.windows(name.len()).any(|w| w == name.as_bytes());
    assert!(!has(&call(GET_PRINCS, &list_args()), "fresh@KERBER.TEST"));
    let fresh = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["fresh"]);
    {
        let mut local = load_store(&db, &stash).unwrap();
        let mut sess = AdminSession::local(&mut local, &acl, actor.clone());
        sess.create_password(&fresh, b"fresh-secret").unwrap();
        sess.add_policy("freshpol");
    }
    assert!(has(&call(GET_PRINCS, &list_args()), "fresh@KERBER.TEST"));
    assert!(has(&call(GET_POLS, &list_args()), "freshpol"));
    assert_eq!(ret_code(&call(GET_POLICY, &encode_named("freshpol"))), 0);
    assert_eq!(
        ret_code(&call(
            CREATE_PRINCIPAL,
            &create_rec("froma", "froma-secret")
        )),
        0
    );
    let on_disk = load_store(&db, &stash).unwrap();
    assert!(on_disk.get_name(&fresh).is_some());
    assert!(on_disk.policies().contains_key("freshpol"));
    assert!(
        on_disk
            .get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["froma"]))
            .is_some()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
