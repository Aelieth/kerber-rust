//! `kinit`'s expired-password flow runs in MIT's order.
//! MIT `krb5_get_init_creds_password` (`lib/krb5/krb/gic_pwd.c:205-240`): a typed
//! `KDC_ERR_KEY_EXP` → the `kadmin/changepw` AS *first*, with the password just typed → only
//! then the `Enter new password` prompts. So a wrong password on an expired principal is the
//! password failure and never prompts, and a changepw AS that fails for any other reason is
//! that error, unprompted.
//! MIT `k5_kinit` (`kinit.c:785-790`): that password failure is "Password incorrect while
//! getting initial credentials".
//! Drives the shipped `krb5-kinit` against an in-process KDC: no new-password prompt comes
//! before the changepw AS, and the KDC error is matched by its code, not its text.
//! The password prompt itself comes only once a KDC reply needs the key, so an unknown client is
//! reported unprompted, and `-S` asks the AS for that service.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use krb5_kdc::principals::kadmin_changepw;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented};
use krb5_kdc::{KDB_REQUIRES_PRE_AUTH, KDB_REQUIRES_PWCHANGE, PrincipalStore};

use krb5_testkit::scratch_dir;
use krb5_types::PrincipalName;

/// Serve `store` on UDP and TCP at one ephemeral port; returns `host:port`.
fn serve(store: PrincipalStore) -> String {
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    udp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let addr = udp.local_addr().unwrap();
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

/// `user` set `+needchange` (`KDB_REQUIRES_PWCHANGE`).
/// MIT `validate_as_request` (`kdc_util.c:762-766`): every AS but the one for
/// `kadmin/changepw` is KEY_EXP 23 "REQUIRED PWCHANGE".
fn expired_user_store() -> PrincipalStore {
    let (mut store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let attrs = store.get_name(&user).unwrap().attributes | KDB_REQUIRES_PWCHANGE;
    store
        .apply_admin_fields(
            &user,
            krb5_kdc::AdminFields {
                attributes: Some(attrs),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    store
}

/// Run `krb5-kinit -c cc user@KERBER.TEST` with the realm's KDC at `kdc` in its krb5.conf,
/// `password` on the first line of stdin and `stdin` after it for any new-password prompt;
/// returns (exit code, stdout + stderr — prompts and banners go to stdout like
/// `krb5_prompter_posix`, errors to stderr).
fn kinit(kdc: &str, password: &str, stdin: &str) -> (Option<i32>, String) {
    kinit_as(kdc, &format!("{TEST_USER}@{TEST_REALM}"), password, stdin)
}

/// [`kinit`] for `principal`.
fn kinit_as(kdc: &str, principal: &str, password: &str, stdin: &str) -> (Option<i32>, String) {
    let (code, out, _) = kinit_full(kdc, &[], principal, password, stdin);
    (code, out)
}

/// [`kinit_as`] with `extra` options before the principal; also returns the cache it wrote.
fn kinit_full(
    kdc: &str,
    extra: &[&str],
    principal: &str,
    password: &str,
    stdin: &str,
) -> (Option<i32>, String, Option<krb5_protocol::FileCcache>) {
    let dir = scratch_dir("z1b-kinit");
    let conf = dir.join("krb5.conf");
    std::fs::write(
        &conf,
        format!(
            "[libdefaults]\n    default_realm = KERBER.TEST\n    dns_lookup_kdc = false\n    \
             dns_lookup_realm = false\n[realms]\n    KERBER.TEST = {{\n        kdc = {kdc}\n    }}\n"
        ),
    )
    .unwrap();
    let cc = dir.join("cc");
    let mut child = Command::new(env!("CARGO_BIN_EXE_krb5-kinit"))
        .arg("-c")
        .arg(&cc)
        .args(extra)
        .arg(principal)
        .env("KRB5_CONFIG", &conf)
        .env_remove("KRB5_PASSWORD")
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
        .write_all(format!("{password}\n{stdin}").as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let cache = std::fs::read(&cc)
        .ok()
        .and_then(|b| krb5_protocol::FileCcache::parse(&b).ok());
    let _ = std::fs::remove_dir_all(&dir);
    let mut err = String::from_utf8_lossy(&out.stdout).into_owned();
    err.push_str(&String::from_utf8_lossy(&out.stderr));
    eprintln!("krb5-kinit rc={:?} output:\n{err}", out.status.code());
    (out.status.code(), err, cache)
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
        err.contains(
            "kinit: Server not found in Kerberos database while getting initial credentials"
        ),
        "changepw AS error missing: {err}"
    );
}

#[test]
fn wrong_password_without_preauth_is_bad_integrity_password_incorrect() {
    // MIT's harness principals carry no REQUIRES_PRE_AUTH: the changepw AS
    // with a wrong password is answered with an AS-REP the client cannot
    // verify — `krb5_kdc_rep_decrypt_proc` → `KRB5KRB_AP_ERR_BAD_INTEGRITY`
    // (31).
    // MIT `k5_kinit` (`kinit.c:787-787`): kinit also reports that error as `Password incorrect`.
    let mut store = expired_user_store();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let attrs = store.get_name(&user).unwrap().attributes & !KDB_REQUIRES_PRE_AUTH;
    store
        .apply_admin_fields(
            &user,
            krb5_kdc::AdminFields {
                attributes: Some(attrs),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
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

/// Live MIT 1.22.2 `kinit nosuch`: the KDC's error to the first
/// AS-REQ, and no password prompt.
/// MIT `encts_process` (`preauth_encts.c:75-75`): the password is read only to answer the KDC's
/// preauth hint.
#[test]
fn unknown_client_is_reported_without_a_password_prompt() {
    let (store, _) = bootstrap_documented().unwrap();
    let kdc = serve(store);
    let (code, out) = kinit_as(&kdc, &format!("nosuch@{TEST_REALM}"), "x", "");
    assert_eq!(code, Some(1), "output: {out}");
    assert!(
        !out.contains("Password for"),
        "prompted for an unknown client: {out}"
    );
    assert!(
        out.contains(
            "kinit: Client 'nosuch@KERBER.TEST' not found in Kerberos database while getting \
             initial credentials"
        ),
        "output: {out}"
    );
}

#[test]
fn the_password_is_read_once_when_preauth_needs_it() {
    let (store, _) = bootstrap_documented().unwrap();
    let kdc = serve(store);
    let (code, out) = kinit(&kdc, "userpassword", "");
    assert_eq!(code, Some(0), "output: {out}");
    let prompt = format!("Password for {TEST_USER}@{TEST_REALM}: ");
    assert_eq!(out.matches(&prompt).count(), 1, "output: {out}");
}

/// Live MIT 1.22.2 `kinit -S host/…@OTHER.TEST alice`: one AS-REQ for that service in the client's
/// realm, and the cache holds that ticket alone. (A `test-hooks` build keeps the gates' `-S`, a
/// TGS-REQ after the TGT.)
/// MIT `build_in_tkt_name` (`get_in_tkt.c:473-512`): the service's own realm is not used.
#[cfg(not(feature = "test-hooks"))]
#[test]
fn dash_s_asks_the_as_for_that_service() {
    let (store, _) = bootstrap_documented().unwrap();
    let kdc = serve(store);
    let (code, out, cache) = kinit_full(
        &kdc,
        &["-S", "host/testhost.kerber.test@OTHER.TEST"],
        &format!("{TEST_USER}@{TEST_REALM}"),
        "userpassword",
        "",
    );
    assert_eq!(code, Some(0), "output: {out}");
    let cache = cache.expect("kinit -S wrote no cache");
    let servers: Vec<String> = cache
        .list()
        .iter()
        .map(|c| {
            let realm = String::from_utf8_lossy(c.server.0.as_bytes()).into_owned();
            c.server.1.unparse_with_realm(&realm)
        })
        .collect();
    assert_eq!(servers, ["host/testhost.kerber.test@KERBER.TEST"]);
}
