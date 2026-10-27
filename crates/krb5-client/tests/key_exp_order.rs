use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use krb5_kdc::principals::kadmin_changepw;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented};
use krb5_kdc::{KDB_REQUIRES_PWCHANGE, PrincipalStore};

use krb5_testkit::scratch_dir;
use krb5_types::PrincipalName;

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

// MIT: `validate_as_request` (kdc_util.c:762-766)
// every AS but the one for
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

fn kinit(kdc: &str, password: &str, stdin: &str) -> (Option<i32>, String) {
    kinit_as(kdc, &format!("{TEST_USER}@{TEST_REALM}"), password, stdin)
}

fn kinit_as(kdc: &str, principal: &str, password: &str, stdin: &str) -> (Option<i32>, String) {
    let (code, out, _) = kinit_full(kdc, &[], principal, password, stdin);
    (code, out)
}

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
