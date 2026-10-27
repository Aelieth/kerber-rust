//! Gating tests: ACL allow/deny, AS/TGS issue, AP-REQ verify negatives.
//! Request-realm ACL text and `mylex` YYEOF leftover (`42x` → 42 s).

#[path = "common/mod.rs"]
mod common;

use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented, documented_admin_id, documented_host};
use krb5_kdc::{Acl, AdminOp, Error, KDB_LOCKDOWN_KEYS, acl_for_store, default_acl_path};

use krb5_testkit::scratch_dir;
use krb5_types::PrincipalName;

#[test]
fn export_keytab_lockdown_is_denied() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .apply_admin_fields(
            &documented_host(),
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
        .expect("lockdown");
    let err = store
        .export_keytab(&acl, &documented_admin_id(), &documented_host())
        .unwrap_err();
    assert_eq!(err, Error::AclDenied);
}

#[test]
fn export_keytab_local_bypasses_lockdown() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let tgt = PrincipalName::krbtgt(TEST_REALM);
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
        .expect("lockdown krbtgt");
    let err = store
        .export_keytab(&acl, &documented_admin_id(), &tgt)
        .unwrap_err();
    assert_eq!(err, Error::AclDenied);
    let kt = store
        .export_keytab_local(&tgt)
        .expect("local --export-krbtgt-keytab");
    assert!(!kt.entries.is_empty());
    assert_eq!(kt.entries[0].name.components_joined(), "krbtgt/KERBER.TEST");
}

#[test]
fn acl_parse_kadm5_style() {
    let acl = Acl::parse("admin@KERBER.TEST *\nuser@KERBER.TEST i\n# comment\n").expect("acl");
    assert!(
        acl.check("admin@KERBER.TEST", AdminOp::Create, None)
            .is_ok()
    );
    assert!(
        acl.check("admin@KERBER.TEST", AdminOp::Modify, None)
            .is_ok()
    );
    assert!(
        acl.check("admin@KERBER.TEST", AdminOp::SetKey, None)
            .is_ok()
    );
    assert!(
        acl.check("admin@KERBER.TEST", AdminOp::Inquire, None)
            .is_ok()
    );
    assert_eq!(
        acl.check("admin@KERBER.TEST", AdminOp::Extract, None)
            .unwrap_err(),
        Error::AclDenied,
        "MIT * / x does not grant extract"
    );
    assert_eq!(
        acl.check("user@KERBER.TEST", AdminOp::Ktadd, None)
            .unwrap_err(),
        Error::AclDenied
    );
    assert!(
        acl.check("user@KERBER.TEST", AdminOp::Inquire, None)
            .is_ok()
    );
    assert_eq!(
        acl.check("user@KERBER.TEST", AdminOp::Create, None)
            .unwrap_err(),
        Error::AclDenied
    );
    assert_eq!(
        acl.check("user@KERBER.TEST", AdminOp::Modify, None)
            .unwrap_err(),
        Error::AclDenied
    );
    let with_e = Acl::parse("admin@KERBER.TEST *e\n").expect("acl");
    assert!(
        with_e
            .check("admin@KERBER.TEST", AdminOp::Extract, None)
            .is_ok()
    );
}

#[test]
fn acl_target_pattern_scopes_add_and_delete() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    // MIT match_data: `*` is a whole component; `user*` is a literal
    // (settled live). `*@REALM` matches user2, not svc/x.
    let acl = Acl::parse("scoped@KERBER.TEST ad *@KERBER.TEST\n").expect("acl");
    let actor = "scoped@KERBER.TEST";
    let user2 = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user2"]);
    let svc = PrincipalName::new(PrincipalName::NT_SRV_INST, ["svc", "x"]);
    store
        .create_password(&acl, actor, &user2, b"user2-secret")
        .expect("user2 in scope");
    let err = store
        .create_password(&acl, actor, &svc, b"svc-secret")
        .unwrap_err();
    assert_eq!(err, Error::AclDenied);
    store
        .delete(&acl, actor, &user2)
        .expect("delete user2 in scope");
}

#[test]
fn kadmind_acl_follows_store_realm_or_acl_file() {
    let none = acl_for_store("PROD.KERBER.TEST", None).expect("self-only");
    assert_eq!(
        none.check("admin@PROD.KERBER.TEST", AdminOp::Create, None)
            .unwrap_err(),
        Error::AclDenied
    );
    assert_eq!(
        none.check(
            "kiprop/testhost.prod.kerber.test@PROD.KERBER.TEST",
            AdminOp::Propagate,
            None,
        )
        .unwrap_err(),
        Error::AclDenied
    );

    let dir = scratch_dir("kadmind-acl");
    let path = dir.join("kadm5.acl");
    std::fs::write(
        &path,
        "admin@PROD.KERBER.TEST *\noperator@PROD.KERBER.TEST i\n",
    )
    .unwrap();
    let file = acl_for_store("PROD.KERBER.TEST", Some(&path)).expect("file acl");
    assert!(
        file.check("admin@PROD.KERBER.TEST", AdminOp::Create, None)
            .is_ok()
    );
    assert!(
        file.check("operator@PROD.KERBER.TEST", AdminOp::Inquire, None)
            .is_ok()
    );
    assert_eq!(
        file.check("admin@KERBER.TEST", AdminOp::Create, None)
            .unwrap_err(),
        Error::AclDenied
    );
    assert_eq!(
        file.check("operator@PROD.KERBER.TEST", AdminOp::Create, None)
            .unwrap_err(),
        Error::AclDenied
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn acl_default_path_is_kdc_dir_kadm5_acl() {
    let p = default_acl_path(std::path::Path::new("/var/lib/krb5kdc"));
    assert_eq!(p, std::path::PathBuf::from("/var/lib/krb5kdc/kadm5.acl"));
}

/// MIT `load_acl_file` reads the file with `fgets`, bytes as they are: a Latin-1 comment is a
/// comment, and an ACL path that is a directory opens with no line in it.
#[test]
fn acl_file_is_read_as_bytes() {
    let dir = scratch_dir("acl-bytes");
    let path = dir.join("kadm5.acl");
    std::fs::write(&path, b"# caf\xe9\n*/admin@KERBER.TEST *\n").unwrap();
    let acl = acl_for_store("KERBER.TEST", Some(&path)).expect("a Latin-1 comment");
    assert!(
        acl.check("admin/admin@KERBER.TEST", AdminOp::Create, None)
            .is_ok()
    );
    let none = acl_for_store("KERBER.TEST", Some(&dir)).expect("a directory");
    assert_eq!(
        none.check("admin/admin@KERBER.TEST", AdminOp::Create, None)
            .unwrap_err(),
        Error::AclDenied
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn acl_none_is_self_only_for_embed() {
    let acl = Acl::none();
    assert_eq!(
        acl.check("admin@KERBER.TEST", AdminOp::Create, None)
            .unwrap_err(),
        Error::AclDenied
    );
    assert_eq!(
        acl_for_store("KERBER.TEST", Some(std::path::Path::new("")))
            .expect("empty")
            .check("admin@KERBER.TEST", AdminOp::Create, None)
            .unwrap_err(),
        Error::AclDenied
    );
}

#[test]
fn acl_file_without_admin_is_not_replaced() {
    let dir = scratch_dir("kadmind-acl-nofallback");
    let path = dir.join("kadm5.acl");
    std::fs::write(&path, "operator@PROD.KERBER.TEST *\n").unwrap();
    let acl = acl_for_store("PROD.KERBER.TEST", Some(&path)).expect("file as-is");
    assert!(
        acl.check("operator@PROD.KERBER.TEST", AdminOp::Create, None)
            .is_ok()
    );
    assert_eq!(
        acl.check("admin@PROD.KERBER.TEST", AdminOp::Create, None)
            .unwrap_err(),
        Error::AclDenied
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn acl_default_realm_applies() {
    let dir = scratch_dir("kadmind-acl-realm");
    let path = dir.join("kadm5.acl");
    std::fs::write(&path, "admin *\noperator@PROD.KERBER.TEST i\n").unwrap();
    let acl = acl_for_store("PROD.KERBER.TEST", Some(&path)).expect("realm default");
    assert!(
        acl.check("admin@PROD.KERBER.TEST", AdminOp::Create, None)
            .is_ok()
    );
    assert!(
        acl.check("operator@PROD.KERBER.TEST", AdminOp::Inquire, None)
            .is_ok()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
