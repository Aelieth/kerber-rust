//! Admin whole-flow tests moved from `src/lib.rs`.

#[path = "common/mod.rs"]
mod common;

use krb5_admin::*;
use krb5_kdc::AdminOp;
use krb5_kdc::testrealm::{bootstrap_documented, documented_admin_id, documented_host};

use krb5_types::PrincipalName;

#[test]
fn kadmind_enforces_acl() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let mut admin = AdminSession::local(&mut store, &acl, documented_admin_id());
    let extra = PrincipalName::new(
        PrincipalName::NT_SRV_HST,
        ["host", "admin-extra.kerber.test"],
    );
    admin.create_password(&extra, b"secret-pass").unwrap();
    let kt = admin.ktadd(&extra).unwrap();
    assert_eq!(&kt.to_bytes()[..2], &[0x05, 0x02]);
}

#[test]
fn kadmind_denies_user() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let mut user = AdminSession::local(&mut store, &acl, "user@KERBER.TEST");
    let extra = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "nope.kerber.test"]);
    assert_eq!(
        user.create_password(&extra, b"x").unwrap_err(),
        Error::AclDenied
    );
    assert_eq!(
        user.ktadd(&documented_host()).unwrap_err(),
        Error::AclDenied
    );
}

#[test]
fn load_acl_file_missing_is_error() {
    let path = krb5_testkit::scratch_dir("krb5-acl-missing").join("acl");
    let _ = std::fs::remove_file(&path);
    assert!(load_acl_file("admin@KERBER.TEST", Some(&path)).is_err());
    let acl = load_acl_file("admin@KERBER.TEST", None).unwrap();
    assert!(
        acl.check("admin@KERBER.TEST", AdminOp::Create, None)
            .is_ok()
    );
}

#[test]
fn load_acl_file_reads_bytes() {
    let path = krb5_testkit::scratch_dir("krb5-acl-bytes").join("acl");
    std::fs::write(&path, b"# caf\xe9\nadmin@KERBER.TEST *\n").unwrap();
    let acl = load_acl_file("other@KERBER.TEST", Some(&path)).unwrap();
    assert!(
        acl.check("admin@KERBER.TEST", AdminOp::Create, None)
            .is_ok()
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn load_acl_file_parses_readable() {
    let path = krb5_testkit::scratch_dir("krb5-acl-ok").join("acl");
    std::fs::write(&path, "admin@KERBER.TEST *\n").unwrap();
    let acl = load_acl_file("other@KERBER.TEST", Some(&path)).unwrap();
    assert!(
        acl.check("admin@KERBER.TEST", AdminOp::Create, None)
            .is_ok()
    );
    let _ = std::fs::remove_file(&path);
}
