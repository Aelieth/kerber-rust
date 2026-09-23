//! Gating tests: ACL allow/deny, AS/TGS issue, AP-REQ verify negatives.
//! Request-realm ACL text and `mylex` YYEOF leftover (`42x` → 42 s).

#[path = "common/mod.rs"]
mod common;

use krb5_crypto::EncryptionType;
use krb5_kdc::testrealm::{
    TEST_REALM, TEST_USER, bootstrap_documented, documented_admin_id, documented_host,
};
use krb5_kdc::{Acl, AdminOp, Error, KDB_LOCKDOWN_KEYS, acl_for_store, default_acl_path};

use krb5_protocol::Keytab;
use krb5_testkit::scratch_dir;
use krb5_types::{PrincipalName, deltat};

#[test]
fn acl_allow_admin_create_and_ktadd() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let extra = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "extra.kerber.test"]);
    store
        .create_host(&acl, &documented_admin_id(), &extra)
        .expect("admin create");
    let kt = store
        .export_keytab(&acl, &documented_admin_id(), &extra)
        .expect("admin ktadd");
    let bytes = kt.to_bytes();
    assert_eq!(&bytes[..2], &[0x05, 0x02]);
    let parsed = Keytab::parse(&bytes).expect("keytab v2");
    assert_eq!(
        parsed.entries.len(),
        4,
        "host randkeys include etypes 17–20"
    );
    assert!(
        parsed
            .entries
            .iter()
            .any(|e| e.key.etype() == EncryptionType::Aes256CtsHmacSha384192)
    );
    assert_eq!(
        parsed.entries[0].name.components_joined(),
        "host/extra.kerber.test"
    );
}

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
fn acl_deny_non_admin_create_delete_ktadd() {
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    let user = format!("{TEST_USER}@{TEST_REALM}");
    let extra = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "denied.kerber.test"]);
    let err = store.create_host(&acl, &user, &extra).unwrap_err();
    assert_eq!(err, Error::AclDenied);
    let err = store
        .export_keytab(&acl, &user, &documented_host())
        .unwrap_err();
    assert_eq!(err, Error::AclDenied);
    let err = store.delete(&acl, &user, &documented_host()).unwrap_err();
    assert_eq!(err, Error::AclDenied);
    assert!(acl.check(&user, AdminOp::Create, None).is_err());
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
fn acl_target_backreference_matches_own_instance() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let acl = Acl::parse("*/admin@KERBER.TEST * */*1@KERBER.TEST\n").expect("acl");
    let actor = "joe/admin@KERBER.TEST";
    let own = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "joe"]);
    let other = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "other"]);
    store.create_host(&acl, actor, &own).expect("own instance");
    assert_eq!(
        store.create_host(&acl, actor, &other).unwrap_err(),
        Error::AclDenied
    );
}

#[test]
fn acl_rename_needs_delete_on_src_and_add_on_dest_without_restrictions() {
    let (mut store, admin_acl) = bootstrap_documented().expect("bootstrap");
    let admin = documented_admin_id();
    let user2 = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user2"]);
    store
        .create_password(&admin_acl, &admin, &user2, b"user2-secret")
        .unwrap();
    let acl = Acl::parse("scoped@KERBER.TEST ad *@KERBER.TEST\n").expect("acl");
    let actor = "scoped@KERBER.TEST";
    let svc = PrincipalName::new(PrincipalName::NT_SRV_INST, ["svc", "y"]);
    assert_eq!(
        store.rename(&acl, actor, &user2, &svc).unwrap_err(),
        Error::AclDenied
    );
    let user3 = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user3"]);
    store
        .rename(&acl, actor, &user2, &user3)
        .expect("user3 in scope");
}

#[test]
fn acl_target_star_is_any() {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    let acl = Acl::parse("admin@KERBER.TEST a *\n").expect("acl");
    let actor = "admin@KERBER.TEST";
    let svc = PrincipalName::new(PrincipalName::NT_SRV_INST, ["svc", "any"]);
    store
        .create_host(&acl, actor, &svc)
        .expect("* target is any");
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

#[test]
fn acl_unknown_op_letter_includes_line_and_aborting() {
    let dir = scratch_dir("acl-az");
    let path = dir.join("kadm5.acl");
    std::fs::write(&path, "bad@KERBER.TEST aZ\n").unwrap();
    let err = acl_for_store("KERBER.TEST", Some(&path)).expect_err("aZ");
    let msg = err.to_string();
    assert!(
        msg.contains("Unrecognized ACL operation 'Z' in bad@KERBER.TEST aZ"),
        "{msg}"
    );
    assert!(
        msg.contains("syntax error at line 1 <bad@KERBER...>"),
        "{msg}"
    );
    assert!(
        msg.contains("while initializing ACL file, aborting"),
        "{msg}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn acl_missing_default_file_refuses_start() {
    let path = std::path::Path::new("/no/such/kadm5.acl");
    let err = acl_for_store("KERBER.TEST", Some(path)).expect_err("missing");
    let msg = err.to_string();
    assert!(
        msg.contains("Cannot open /no/such/kadm5.acl: No such file or directory while initializing ACL file, aborting"),
        "{msg}"
    );
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

#[test]
fn documented_kadm5_acl_file_shape() {
    let text = include_str!("../../../harness/kadm5.acl");
    let acl = Acl::parse(text).expect("acl");
    assert!(
        acl.check("admin@KERBER.TEST", AdminOp::Create, None)
            .is_ok()
    );
    assert!(
        acl.check("foo/admin@KERBER.TEST", AdminOp::Create, None)
            .is_ok()
    );
    assert!(
        acl.check(
            "kiprop/testhost.kerber.test@KERBER.TEST",
            AdminOp::Propagate,
            None,
        )
        .is_ok()
    );
    assert_eq!(
        acl.check("user@KERBER.TEST", AdminOp::Create, None)
            .unwrap_err(),
        Error::AclDenied
    );
}

#[test]
fn parse_42x_is_forty_two_seconds() {
    assert_eq!(deltat::parse("42x"), Ok(42));
    assert!(deltat::parse("3dd").is_err());
}

#[test]
fn acl_unknown_op_letter_includes_line() {
    let err = Acl::parse("bad@KERBER.TEST aZ\n").unwrap_err();
    assert!(
        err.to_string()
            .contains("Unrecognized ACL operation 'Z' in bad@KERBER.TEST aZ"),
        "{err}"
    );
}
