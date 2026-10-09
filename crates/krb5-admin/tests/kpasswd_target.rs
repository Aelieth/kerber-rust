//! `KRB5_KPASSWD_TARGET` is an input of the gates' `kpasswd` only.

use std::process::{Command, Stdio};

use krb5_testkit::scratch_dir;

/// MIT 1.22.2's `kpasswd` has no set-password target and reads no such variable. A target that is
/// no principal name stops a `test-hooks` `kpasswd` first; a release one never reads it and gets
/// as far as the KDC lookup.
#[test]
fn only_a_test_hooks_kpasswd_reads_a_target() {
    let conf = scratch_dir("kpasswd-target").join("krb5.conf");
    std::fs::write(&conf, "[libdefaults]\n    default_realm = X.TEST\n").expect("krb5.conf");
    let out = Command::new(env!("CARGO_BIN_EXE_krb5-kpasswd"))
        .arg("user@X.TEST")
        .env("KRB5_CONFIG", &conf)
        .env("KRB5_KPASSWD_TARGET", "no-realm")
        .env_remove("KRB5_PASSWORD")
        .env_remove("KRB5CCNAME")
        .stdin(Stdio::null())
        .output()
        .expect("run krb5-kpasswd");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert_eq!(
        err.contains("parsing KRB5_KPASSWD_TARGET"),
        cfg!(feature = "test-hooks"),
        "{err}"
    );
    if cfg!(not(feature = "test-hooks")) {
        assert!(err.contains("Cannot find KDC for requested realm"), "{err}");
    }
}
