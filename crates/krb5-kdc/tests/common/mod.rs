//! KDC-crate test glue. Cross-crate helpers live in `krb5-testkit`.

#![allow(dead_code)]

use krb5_crypto::ProtocolKey;
use krb5_kdc::testrealm::{TEST_USER, TEST_USER_PASSWORD};

use krb5_testkit::password_key;

/// `TEST_USER` string-to-key with the documented password.
///
/// Replaces `issue_acl_ap.rs`'s `client_key`.
pub fn client_key() -> ProtocolKey {
    password_key(TEST_USER, TEST_USER_PASSWORD)
}

/// The lines the KDC writes to its daemon log while `f` runs, each without its
/// `Mmm dd hh:mm:ss host prog[pid](severity): ` prefix. The log is the process's (a test runs in its
/// own process under nextest), so callers within one process take turns.
pub fn kdc_log<R>(f: impl FnOnce() -> R) -> (R, Vec<String>) {
    use std::sync::{Mutex, PoisonError};
    static TURN: Mutex<()> = Mutex::new(());
    let _turn = TURN.lock().unwrap_or_else(PoisonError::into_inner);
    let dir = krb5_testkit::scratch_dir("kdc-log");
    let path = dir.join("kdc.log");
    krb5_log::klog::init("krb5kdc", &[format!("FILE:{}", path.display())], false);
    let out = f();
    krb5_log::klog::close();
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    let lines = text
        .lines()
        .map(|l| l.split_once("): ").map_or(l, |(_, m)| m).to_owned())
        .collect();
    (out, lines)
}

/// The `preauth (<module>) verify failure: <message>` lines of a captured log, in order.
pub fn verify_failures(lines: &[String]) -> Vec<&str> {
    lines
        .iter()
        .map(String::as_str)
        .filter(|l| l.starts_with("preauth ("))
        .collect()
}

/// What a failed AS exchange wrote, in order: every verify-failure line as it stands, and the
/// `AS_REQ` line cut down to `AS_REQ <status word>, <its message>`, the message being what follows
/// `<client> for <server>, `.
pub fn failure_trace(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|l| {
            if l.starts_with("preauth (") {
                return Some(l.clone());
            }
            let rest = l.strip_prefix("AS_REQ (")?.split_once("}) ")?.1;
            let (_from, rest) = rest.split_once(": ")?;
            let (status, rest) = rest.split_once(": ")?;
            let (_names, tail) = rest.split_once(" for ")?.1.split_once(", ")?;
            Some(format!("AS_REQ {status}, {tail}"))
        })
        .collect()
}
