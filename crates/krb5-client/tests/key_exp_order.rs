//! W1-Z Z1b.2: `kinit`'s expired-password flow runs in MIT's order
//! (`lib/krb5/krb/gic_pwd.c:205-240`): a typed `KDC_ERR_KEY_EXP` → the
//! `kadmin/changepw` AS *first*, with the password just typed → only then the
//! `Enter new password` prompts. So a wrong password on an expired principal
//! is the password failure and never prompts (`kinit.c:785-790` "Password
//! incorrect while getting initial credentials"), and a changepw AS that
//! fails for any other reason is that error, unprompted. Drives the shipped
//! `krb5-kinit` against an in-process KDC. Compiles at `59c363b`
//! (parent-red): the parent prompted for the new password before any
//! changepw AS and matched the KDC error by text.

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use krb5_kdc::principals::kadmin_changepw;
use krb5_kdc::{
    KDB_REQUIRES_PRE_AUTH, KDB_REQUIRES_PWCHANGE, PrincipalStore, TEST_REALM, TEST_USER,
    bootstrap_documented,
};

use krb5_testkit::scratch_dir;
use krb5_types::PrincipalName;

/// Serve `store` on UDP and TCP at one ephemeral port; returns `host:port`.
fn serve(store: PrincipalStore) -> String {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).unwrap();
    let store = Arc::new(store);
    let s_udp = store.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 16384];
        while let Ok((n, src)) = udp.recv_from(&mut buf) {
            if let Ok(reply) = krb5_kdc::handle_request(&*s_udp, &buf[..n]) {
                let _ = udp.send_to(&reply, src);
            }
        }
    });
    thread::spawn(move || {
        for conn in tcp.incoming() {
            let Ok(mut conn) = conn else { break };
            let store = store.clone();
            thread::spawn(move || {
                let mut len = [0u8; 4];
                if conn.read_exact(&mut len).is_err() {
                    return;
                }
                let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
                if conn.read_exact(&mut req).is_err() {
                    return;
                }
                if let Ok(reply) = krb5_kdc::handle_request(&*store, &req) {
                    let n = u32::try_from(reply.len()).unwrap();
                    let _ = conn.write_all(&n.to_be_bytes());
                    let _ = conn.write_all(&reply);
                }
            });
        }
    });
    format!("127.0.0.1:{}", addr.port())
}

/// `user` set `+needchange` (`KDB_REQUIRES_PWCHANGE`): every AS but the one
/// for `kadmin/changepw` is KEY_EXP 23 "REQUIRED PWCHANGE"
/// (`kdc_util.c:762-766`).
fn expired_user_store() -> PrincipalStore {
    let (mut store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let attrs = store.get_name(&user).unwrap().attributes | KDB_REQUIRES_PWCHANGE;
    store
        .apply_admin_fields(&user, Some(attrs), None, None, None, None, false, None)
        .unwrap();
    store
}

/// Run `krb5-kinit KDC user@KERBER.TEST` with `password` from the
/// environment and `stdin` on hand for any new-password prompt; returns
/// (exit code, stdout + stderr — prompts and banners go to stdout like
/// `krb5_prompter_posix`, errors to stderr).
fn kinit(kdc: &str, password: &str, stdin: &str) -> (Option<i32>, String) {
    let dir = scratch_dir("z1b-kinit");
    let conf = dir.join("krb5.conf");
    std::fs::write(
        &conf,
        "[libdefaults]\n    default_realm = KERBER.TEST\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n",
    )
    .unwrap();
    let cc = dir.join("cc");
    let mut child = Command::new(env!("CARGO_BIN_EXE_krb5-kinit"))
        .args([kdc, &format!("{TEST_USER}@{TEST_REALM}")])
        .arg("-c")
        .arg(&cc)
        .env("KRB5_CONFIG", &conf)
        .env("KRB5_PASSWORD", password)
        .env_remove("KRB5_NEW_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let mut err = String::from_utf8_lossy(&out.stdout).into_owned();
    err.push_str(&String::from_utf8_lossy(&out.stderr));
    eprintln!("krb5-kinit rc={:?} output:\n{err}", out.status.code());
    (out.status.code(), err)
}

#[test]
fn wrong_password_on_an_expired_principal_is_password_incorrect_and_never_prompts() {
    let kdc = serve(expired_user_store());
    let (code, err) = kinit(&kdc, "not-the-password", "new-pw\nnew-pw\n");
    assert_eq!(code, Some(1), "stderr: {err}");
    assert!(
        !err.contains("Enter new password"),
        "prompted for a new password before the changepw AS: {err}"
    );
    assert!(
        err.contains("Password incorrect while getting initial credentials"),
        "kinit.c:785-790 text missing: {err}"
    );
}

#[test]
fn changepw_as_failure_is_reported_before_any_prompt() {
    // No kadmin/changepw principal: the changepw AS is S_PRINCIPAL_UNKNOWN
    // (7) with the *right* password — reported as such, never prompted.
    let mut store = expired_user_store();
    store.remove_in(&kadmin_changepw(), TEST_REALM).unwrap();
    let kdc = serve(store);
    let (code, err) = kinit(&kdc, "userpassword", "new-pw\nnew-pw\n");
    assert_eq!(code, Some(1), "stderr: {err}");
    assert!(
        !err.contains("Enter new password"),
        "prompted before the changepw AS: {err}"
    );
    assert!(
        err.contains("KRB-ERROR 7"),
        "changepw AS error missing: {err}"
    );
}

#[test]
fn wrong_password_without_preauth_is_bad_integrity_password_incorrect() {
    // MIT's harness principals carry no REQUIRES_PRE_AUTH: the changepw AS
    // with a wrong password is answered with an AS-REP the client cannot
    // verify — `krb5_kdc_rep_decrypt_proc` → `KRB5KRB_AP_ERR_BAD_INTEGRITY`
    // (31), which `kinit.c:787` also reports as `Password incorrect`.
    let mut store = expired_user_store();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let attrs = store.get_name(&user).unwrap().attributes & !KDB_REQUIRES_PRE_AUTH;
    store
        .apply_admin_fields(&user, Some(attrs), None, None, None, None, false, None)
        .unwrap();
    let kdc = serve(store);
    let (code, err) = kinit(&kdc, "not-the-password", "new-pw\nnew-pw\n");
    assert_eq!(code, Some(1), "stderr: {err}");
    assert!(!err.contains("Enter new password"), "prompted: {err}");
    assert!(
        err.contains("Password incorrect while getting initial credentials"),
        "BAD_INTEGRITY must read as Password incorrect: {err}"
    );
    // The tracing event trail still names the crypto failure; the user
    // line must not.
    assert!(
        !err.lines()
            .any(|l| l.starts_with("kinit:") && l.contains("integrity check failed")),
        "raw crypto text leaked to the user: {err}"
    );
}
