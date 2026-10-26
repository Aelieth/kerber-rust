//! kadm5 reload tests (private-bound; regrouped in place).

use super::*;

#[cfg(feature = "test-hooks")]
fn gprinc_lockout(out: &[u8]) -> (u32, u32, u32) {
    let mut r = XdrR::new(out);
    assert_eq!(r.u32().unwrap(), API_V2);
    assert_eq!(r.u32().unwrap(), 0);
    let _ = r.nullstring().unwrap();
    for _ in 0..4 {
        r.u32().unwrap();
    }
    assert_eq!(r.u32().unwrap(), 0);
    let _ = r.nullstring().unwrap();
    for _ in 0..4 {
        r.u32().unwrap();
    }
    let _ = r.nullstring().unwrap();
    for _ in 0..2 {
        r.u32().unwrap();
    }
    (r.u32().unwrap(), r.u32().unwrap(), r.u32().unwrap())
}

#[cfg(feature = "test-hooks")]
#[test]
fn getprinc_shows_the_lockout_attributes_the_kdc_recorded_since_kadmind_read() {
    use krb5_kdc::{load_store, save_store};
    let dir = krb5_testkit::scratch_dir("kadmind-lockout");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let shared = krb5_kdc::shared_dump(load_store(&db, &stash).unwrap());
    let kdc = load_store(&db, &stash).unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    kdc.record_as_outcome(&user, false);
    kdc.record_as_outcome(&user, false);
    let actor = krb5_kdc::testrealm::documented_admin_id();
    let out = dispatch_kadm5(
        &shared,
        &acl,
        &actor,
        GET_PRINCIPAL,
        &getprinc_args("user@KERBER.TEST"),
    )
    .unwrap();
    let (last_success, last_failed, fail_auth_count) = gprinc_lockout(&out);
    assert_eq!((last_success, fail_auth_count), (0, 2));
    assert!(last_failed > 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_modify_is_one_write() {
    use std::os::unix::fs::MetadataExt as _;

    use krb5_kdc::{load_store, save_store};
    let dir = krb5_testkit::scratch_dir("modify-once");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let shared = krb5_kdc::shared_dump(load_store(&db, &stash).unwrap());
    let actor = krb5_kdc::testrealm::documented_admin_id();
    let ok = krb5_kdc::suffixed(&db, krb5_kdc::SUFFIX_LOCK);
    let future = std::time::SystemTime::now() + std::time::Duration::from_secs(100_000);
    std::fs::File::options()
        .write(true)
        .open(&ok)
        .unwrap()
        .set_modified(future)
        .unwrap();
    let set = std::fs::metadata(&ok).unwrap().mtime();
    let mut args = modify_args("user@KERBER.TEST");
    let n = args.len();
    args[n - 4..].copy_from_slice(&(KADM5_ATTRIBUTES | KADM5_MAX_LIFE | KADM5_KVNO).to_be_bytes());
    let out = dispatch_kadm5(&shared, &acl, &actor, MODIFY_PRINCIPAL, &args).unwrap();
    assert_eq!(ret_code(&out), 0);
    assert_eq!(std::fs::metadata(&ok).unwrap().mtime(), set + 1);
    let _ = std::fs::remove_dir_all(&dir);
}

fn overtaken_policy_call(
    kadmind: &SharedStore,
    acl: &Acl,
    local: &mut krb5_kdc::PrincipalStore,
    call: (u32, Vec<u8>),
    other: impl FnOnce(&mut krb5_kdc::PrincipalStore) -> Result<(), krb5_kdc::Error>,
) -> u32 {
    let (held, _) = local.read_hold().unwrap().unwrap();
    let (store, acl, actor) = (
        std::sync::Arc::clone(kadmind),
        acl.clone(),
        krb5_kdc::testrealm::documented_admin_id(),
    );
    let (proc, args) = call;
    let kadmind_call = std::thread::spawn(move || {
        ret_code(&dispatch_kadm5(&store, &acl, &actor, proc, &args).unwrap())
    });
    while kadmind.try_read().is_ok() {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    std::thread::sleep(std::time::Duration::from_millis(100));
    local.change(other).unwrap().unwrap();
    drop(held);
    kadmind_call.join().unwrap()
}

#[test]
fn a_policy_write_overtaken_after_kadminds_look_gets_mits_locked_answer() {
    use krb5_kdc::{load_store, save_store};
    let dir = krb5_testkit::scratch_dir("policy-race");
    let (db, stash) = (dir.join("principal"), dir.join("stash"));
    let (store, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let kadmind = krb5_kdc::shared_dump(load_store(&db, &stash).unwrap());
    let mut local = load_store(&db, &stash).unwrap();
    let life = |name: &str, secs: u32| {
        let mut p = krb5_kdc::NamedPolicy::new(name);
        p.pw_max_life = secs;
        p
    };
    let create = encode_cpol(
        API_V2,
        &life("racepol", 3600),
        KADM5_POLICY | KADM5_PW_MAX_LIFE,
    );
    let code = overtaken_policy_call(&kadmind, &acl, &mut local, (CREATE_POLICY, create), |s| {
        s.put_policy(life("racepol", 7200))
    });
    assert_eq!(code, OSA_ADB_DUP);
    let on_disk = load_store(&db, &stash).unwrap();
    assert_eq!(on_disk.policies().get("racepol").unwrap().pw_max_life, 7200);
    local
        .change(|s| s.put_policy(life("racepol2", 0)))
        .unwrap()
        .unwrap();
    let modify = encode_cpol(API_V2, &life("racepol2", 10800), KADM5_PW_MAX_LIFE);
    let code = overtaken_policy_call(&kadmind, &acl, &mut local, (MODIFY_POLICY, modify), |s| {
        s.delete_policy("racepol2")
    });
    assert_eq!(code, OSA_ADB_NOENT);
    assert!(
        !load_store(&db, &stash)
            .unwrap()
            .policies()
            .contains_key("racepol2")
    );
    let _ = std::fs::remove_dir_all(&dir);
}
