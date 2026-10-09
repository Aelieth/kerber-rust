//! `kpasswd`'s own line for a profile `krb5_init_context` refuses.

use std::process::{Command, Stdio};

use krb5_testkit::scratch_dir;

/// MIT `main` (`kpasswd.c:70-74`): `kpasswd: <error_message> initializing kerberos library`.
/// Live MIT 1.22.2: that line and exit 1 for an include that does not open and for a relation
/// with no value.
#[test]
fn a_profile_krb5_init_context_refuses_is_mit_s_line() {
    let dir = scratch_dir("kpasswd-init");
    let include = dir.join("include.conf");
    std::fs::write(
        &include,
        format!("include {}\n", dir.join("nope.conf").display()),
    )
    .expect("krb5.conf");
    let bare = dir.join("bare.conf");
    std::fs::write(
        &bare,
        "[libdefaults]\n    kcm_socket =\n    default_realm = X.TEST\n",
    )
    .expect("krb5.conf");
    let exe = env!("CARGO_BIN_EXE_krb5-kpasswd");
    for (conf, text) in [
        (&include, "Included profile file could not be read"),
        (&bare, "Improper format of Kerberos configuration file"),
    ] {
        let out = Command::new(exe)
            .arg("user@X.TEST")
            .env("KRB5_CONFIG", conf)
            .stdin(Stdio::null())
            .output()
            .expect("run krb5-kpasswd");
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            format!("{exe}: {text} initializing kerberos library\n")
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}
