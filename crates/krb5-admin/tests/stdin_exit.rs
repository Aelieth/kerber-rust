//! Process-level stdin exit codes for `ktutil` / `kadmin.local`.

use std::fs::File;
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
    let out = pipe_stdin(bin, b"\xff\nq\n");
    assert_eq!(
        out.status.code(),
        Some(1),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = pipe_stdin(bin, b"\xff\nnope\nq\n");
    assert_eq!(
        out.status.code(),
        Some(1),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("invalid utf-8") || err.contains("stream did not contain valid UTF-8"),
        "decode must continue: {err}"
    );
    assert!(
        err.contains("nope"),
        "continue after decode must run nope: {err}"
    );
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
    let out = run(b"\xff\nq\n");
    assert_eq!(
        out.status.code(),
        Some(1),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = run(b"\xff\nnope\nq\n");
    assert_eq!(
        out.status.code(),
        Some(1),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("invalid utf-8") || err.contains("stream did not contain valid UTF-8"),
        "decode must continue: {err}"
    );
    assert!(
        err.contains("nope"),
        "continue after decode must run nope: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn dir_stdin(bin: &str, envs: &[(&str, std::path::PathBuf)]) -> std::process::Output {
    let scratch = std::env::temp_dir().join(format!(
        "ktutil-dir-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    std::fs::create_dir_all(&scratch).unwrap();
    let file = File::open(&scratch).expect("open directory");
    let mut cmd = Command::new("timeout");
    cmd.args(["--kill-after=1s", "2", bin])
        .stdin(Stdio::from(file))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("timeout spawn");
    let _ = std::fs::remove_dir_all(&scratch);
    out
}

#[test]
fn ktutil_directory_stdin_terminates() {
    let bin = env!("CARGO_BIN_EXE_krb5-ktutil");
    let out = dir_stdin(bin, &[]);
    assert_ne!(
        out.status.code(),
        Some(124),
        "directory stdin spun: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_ne!(out.status.code(), Some(0));
    assert!(
        out.stderr.len() < 64 * 1024,
        "stderr {} bytes",
        out.stderr.len()
    );
}

#[test]
fn kadmin_local_directory_stdin_terminates() {
    let dir = std::env::temp_dir().join(format!(
        "kadmin-dirin-{}-{}",
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
    let out = dir_stdin(
        bin,
        &[
            ("KRB5_KDC_DB", db.clone()),
            ("KRB5_KDC_STASH", stash.clone()),
        ],
    );
    assert_ne!(
        out.status.code(),
        Some(124),
        "directory stdin spun: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_ne!(out.status.code(), Some(0));
    assert!(
        out.stderr.len() < 64 * 1024,
        "stderr {} bytes",
        out.stderr.len()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
