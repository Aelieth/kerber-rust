//! Admin whole-flow tests moved from `src/lib.rs`.

#[path = "common/mod.rs"]
mod common;

use krb5_admin::*;
use krb5_kdc::AdminOp;

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
