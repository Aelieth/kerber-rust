//! A profile the context init refuses stops each tool before anything else, with that tool's MIT
//! line.

use std::process::{Command, Stdio};

use krb5_testkit::scratch_dir;

/// Live MIT 1.22.2: a relation with no value whose next line is no `{` refuses the profile, and
/// each tool stops with its own line for the failed init and exit 1.
/// MIT `os_init_paths` (`init_os_ctx.c:403-408`): a missing `{` is `KRB5_CONFIG_BADFORMAT`.
/// MIT `main` (`ovsec_kadmd.c:437-442`): kadmind prints `while initializing context, aborting`
/// MIT `kadmin_startup` (`kadmin.c:309-313`): kadmin.local prints `while initializing krb5 library`
/// MIT `main` (`kprop.c:101-105`): kprop prints `while initializing krb5`
/// MIT `parse_args` (`kpropd.c:1056-1062`): kpropd prints `while initializing krb5`
/// MIT `main` (`ktutil.c:49-53`): ktutil prints `while initializing krb5`
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
            env!("CARGO_BIN_EXE_krb5-kadmind"),
            &["-nofork"][..],
            "while initializing context, aborting",
        ),
        (
            env!("CARGO_BIN_EXE_krb5-kadmin-local"),
            &["-q", "listprincs"][..],
            "while initializing krb5 library",
        ),
        (
            env!("CARGO_BIN_EXE_krb5-kprop"),
            &["replica.x.test"][..],
            "while initializing krb5",
        ),
        (
            env!("CARGO_BIN_EXE_krb5-kpropd"),
            &["-S"][..],
            "while initializing krb5",
        ),
        (
            env!("CARGO_BIN_EXE_krb5-ktutil"),
            &[][..],
            "while initializing krb5",
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
