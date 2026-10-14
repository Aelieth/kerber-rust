//! A profile the context init refuses stops each tool before anything else, with that tool's MIT
//! line.

use std::process::{Command, Stdio};

use krb5_testkit::scratch_dir;

/// Live MIT 1.22.2: a relation with no value whose next line is no `{` refuses the profile, and
/// each tool stops with its own line for the failed init and exit 1.
/// MIT `os_init_paths` (`init_os_ctx.c:403-408`): a missing `{` is `KRB5_CONFIG_BADFORMAT`.
/// MIT `main` (`kdc/main.c:917-921`): krb5kdc prints `while initializing krb5`
/// MIT `main` (`kdb5_util.c:214-218`): kdb5_util prints `while initializing Kerberos code`
#[test]
fn a_refused_profile_stops_the_tool_with_its_mit_line() {
    let dir = scratch_dir("profile-refused");
    let conf = dir.join("krb5.conf");
    std::fs::write(
        &conf,
        "[libdefaults]\n    kcm_socket =\n    default_realm = X.TEST\n",
    )
    .expect("krb5.conf");
    let tools: &[(&str, &[&str], &str)] = &[
        (
            env!("CARGO_BIN_EXE_krb5-kdc"),
            &["-n"][..],
            "while initializing krb5",
        ),
        (
            env!("CARGO_BIN_EXE_krb5-kdb"),
            &["list_mkeys"][..],
            "while initializing Kerberos code",
        ),
    ];
    for &(exe, args, context) in tools {
        let out = Command::new(exe)
            .args(args)
            .env("KRB5_CONFIG", &conf)
            .env("KRB5_KDC_PROFILE", dir.join("no-kdc.conf"))
            .env_remove("KRB5_KDC_CONF")
            .stdin(Stdio::null())
            .output()
            .expect("run the tool");
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{exe}: {err}");
        let name =
            if exe.ends_with("kadmind") || exe.ends_with("kdb") || exe.ends_with("kadmin-local") {
                exe.rsplit('/').next().unwrap_or(exe)
            } else {
                exe
            };
        let name = if exe.ends_with("kadmin-local") {
            "kadmin.local"
        } else {
            name
        };
        assert_eq!(
            err,
            format!("{name}: Improper format of Kerberos configuration file {context}\n"),
            "{exe}"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}
