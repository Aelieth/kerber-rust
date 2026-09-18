//! kadm5 reload tests (private-bound; regrouped in place).

use super::*;

#[test]
fn chpass_reload_keeps_concurrent_local_create() {
    use krb5_kdc::{load_store, save_store};
    let dir = std::env::temp_dir().join(format!(
        "n7-chpass-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, acl) = krb5_kdc::bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let mut local = load_store(&db, &stash).unwrap();
    let kadmind = load_store(&db, &stash).unwrap();
    let n7 = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["n7local"]);
    {
        let mut sess = AdminSession::local(&mut local, &acl, krb5_kdc::documented_admin_id());
        sess.create_password(&n7, b"n7-secret").unwrap();
    }
    let shared = krb5_kdc::shared_dump(kadmind);
    let actor = krb5_kdc::documented_admin_id();
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
    let dir = std::env::temp_dir().join(format!(
        "o3-extract-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, acl) = krb5_kdc::bootstrap_documented().unwrap();
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
        let mut sess = AdminSession::local(&mut local, &acl, krb5_kdc::documented_admin_id());
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
    let actor = krb5_kdc::documented_admin_id();
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
