//! Admin whole-flow tests moved from `src/lib.rs`.
//! (b): local `ktadd` rotate and `modprinc -unlock` stamp the
//! session princstr (`svr_principal.c:685,1490` → `server_kdb.c:376-377`).
//! Compiles at the parent: `AdminSession::ktadd_local` / `admin_unlock`
//! already exist; the parent uses `default_mod_actor` on rotate and does
//! not stamp unlock.

#[path = "common/mod.rs"]
mod common;
use common::*;

use krb5_admin::{AdminSession, *};
use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented, documented_admin_id};
use krb5_kdc::{Acl, KDB_LOCKDOWN_KEYS, tl_mod_princ_name};

use krb5_types::PrincipalName;

#[test]
fn ktadd_local_lockdown_rotates_and_extracts() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let extra = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "lockee.kerber.test"]);
    {
        let mut admin = AdminSession::local(&mut store, &acl, documented_admin_id());
        admin.create_randkey(&extra).unwrap();
        admin
            .modify_attributes(&extra, Some(KDB_LOCKDOWN_KEYS))
            .unwrap();
    }
    assert_eq!(
        store
            .export_keytab(&acl, &documented_admin_id(), &extra)
            .unwrap_err(),
        krb5_kdc::Error::AclDenied
    );
    let before = max_kvno(&store, &extra);
    let mut written = None;
    {
        let mut admin = AdminSession::local(&mut store, &acl, documented_admin_id());
        admin
            .ktadd_local(&extra, true, |kt| {
                written = Some(kt.entries.len());
                Ok(())
            })
            .unwrap();
    }
    assert!(written.unwrap() >= 1);
    assert!(max_kvno(&store, &extra) > before);
}

#[test]
fn ktadd_local_write_fail_does_not_persist_rotation() {
    use krb5_kdc::{load_store, save_store};
    let dir = std::env::temp_dir().join(format!(
        "ktadd-atomic-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (mut store, acl) = bootstrap_documented().unwrap();
    let extra = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "atomic.kerber.test"]);
    {
        let mut admin = AdminSession::local(&mut store, &acl, documented_admin_id());
        admin.create_randkey(&extra).unwrap();
    }
    save_store(&store, &db, &stash).unwrap();
    store.persist_paths = Some((db.clone(), stash.clone()));
    let before = max_kvno(&store, &extra);
    {
        let mut admin = AdminSession::local(&mut store, &acl, documented_admin_id());
        let err = admin
            .ktadd_local(&extra, true, |_| Err("disk full".into()))
            .unwrap_err();
        assert!(matches!(err, Error::Inner(_)));
    }
    assert_eq!(max_kvno(&store, &extra), before);
    let reloaded = load_store(&db, &stash).unwrap();
    assert_eq!(max_kvno(&reloaded, &extra), before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn setstr_reload_keeps_concurrent_create() {
    use krb5_kdc::{load_store, save_store};
    let dir = std::env::temp_dir().join(format!(
        "setstr-race-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, acl) = bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let mut local = load_store(&db, &stash).unwrap();
    let mut kadmind = load_store(&db, &stash).unwrap();
    kadmind.persist_paths = Some((db.clone(), stash.clone()));
    local.persist_paths = Some((db.clone(), stash.clone()));
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["m5extra"]);
    kadmind
        .create_password(&acl, &documented_admin_id(), &extra, b"m5-secret")
        .unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    {
        let mut sess = AdminSession::local(&mut local, &acl, documented_admin_id());
        sess.set_string_attr(&user, "m5k", "m5v").unwrap();
    }
    let loaded = load_store(&db, &stash).unwrap();
    assert!(loaded.get_name(&extra).is_some());
    assert!(loaded.get_name(&user).is_some());
    let attrs = loaded.get_strings(&user).unwrap();
    assert!(
        attrs.iter().any(|(k, v)| k == "m5k" && v == "m5v"),
        "setstr must persist m5k=m5v: {attrs:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ktadd_local_krbtgt_rotates_like_mit() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let tgt = PrincipalName::krbtgt(krb5_kdc::testrealm::TEST_REALM);
    store
        .apply_admin_fields(
            &tgt,
            krb5_kdc::AdminFields {
                attributes: Some(KDB_LOCKDOWN_KEYS),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    let before = max_kvno(&store, &tgt);
    let mut n = 0;
    {
        let mut admin = AdminSession::local(&mut store, &acl, documented_admin_id());
        admin
            .ktadd_local(&tgt, true, |kt| {
                n = kt.entries.len();
                Ok(())
            })
            .unwrap();
    }
    assert!(n >= 1);
    assert!(max_kvno(&store, &tgt) > before);
}

fn n(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

#[test]
fn ktadd_local_stamps_the_session_actor() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let actor = "root/admin@KERBER.TEST";
    let acl = Acl::allow_admin(actor).unwrap();
    let name = n("z72kt");
    {
        let mut sess = AdminSession::local(&mut store, &acl, actor);
        sess.create_randkey(&name).unwrap();
        sess.ktadd_local(&name, true, |_| Ok(())).unwrap();
    }
    let p = store.get_name(&name).expect("ktadd target");
    let got = tl_mod_princ_name(&p.tl_data);
    assert_eq!(
        got.as_deref(),
        Some(actor),
        "ktadd rotate must stamp the session actor, not default_mod_actor (got {got:?})"
    );
}

#[test]
fn admin_unlock_stamps_the_session_actor() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let creator = "joe/admin@KERBER.TEST";
    let actor = "root/admin@KERBER.TEST";
    let acl = Acl::parse(&format!("{creator} *\n{actor} *\n")).unwrap();
    let name = n("z72ul");
    {
        let mut sess = AdminSession::local(&mut store, &acl, creator);
        sess.create_password(&name, b"z72-unlock-secret").unwrap();
    }
    {
        let mut sess = AdminSession::local(&mut store, &acl, actor);
        sess.admin_unlock(&name).unwrap();
    }
    let p = store.get_name(&name).expect("unlocked");
    let got = tl_mod_princ_name(&p.tl_data);
    assert_eq!(
        got.as_deref(),
        Some(actor),
        "unlock must stamp the session actor (got {got:?}; realm {TEST_REALM})"
    );
}
