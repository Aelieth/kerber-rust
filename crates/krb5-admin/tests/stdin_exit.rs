//! Process-level stdin exit codes for `ktutil` / `kadmin.local`.

use std::io::Write;
use std::process::{Command, Stdio};

fn pipe_stdin(bin: &str, input: &[u8]) -> std::process::Output {
    let mut child = Command::new(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input)
        .expect("write");
    child.wait_with_output().expect("wait")
}

#[test]
fn ktutil_nope_then_q_exits_1() {
    let bin = env!("CARGO_BIN_EXE_krb5-ktutil");
    let out = pipe_stdin(bin, b"nope\nq\n");
    assert_eq!(
        out.status.code(),
        Some(1),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = pipe_stdin(bin, b"q\n");
    assert_eq!(out.status.code(), Some(0));
    let out = pipe_stdin(bin, b"q\nnope\n");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn kadmin_local_nope_then_q_exits_1() {
    let dir = std::env::temp_dir().join(format!(
        "kadmin-stdin-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, _) = krb5_kdc::bootstrap_documented().unwrap();
    krb5_kdc::save_store(&store, &db, &stash).unwrap();
    let bin = env!("CARGO_BIN_EXE_krb5-kadmin-local");
    let run = |input: &[u8]| {
        let mut child = Command::new(bin)
            .env("KRB5_KDC_DB", &db)
            .env("KRB5_KDC_STASH", &stash)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input)
            .expect("write");
        child.wait_with_output().expect("wait")
    };
    let out = run(b"nope\nq\n");
    assert_eq!(
        out.status.code(),
        Some(1),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run(b"q\n");
    assert_eq!(out.status.code(), Some(0));
    let out = run(b"q\nnope\n");
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&dir);
}
