//! Env-gated raw PDU capture (`KERBER_CAPTURE_DIR`).
//!
//! Writes each request/reply at the Rust socket boundary so MIT 1.22.2
//! DER can be archived under `tests/traces/` with no packet sniffer.
//! Directory, first match: non-empty `KERBER_CAPTURE_DIR`, else
//! `${KERBER_SCRATCH}/traces`, else `${CARGO_TARGET_DIR}/traces`.
//! Empty `KERBER_CAPTURE_DIR` disables. Paths under `tests/traces`
//! are refused so a gate run cannot dirty the golden home; copy one
//! file in with `scripts/promote-trace.sh`.

/// Write `bytes` as `{label}-<nonce>.der` when a capture directory is set.
pub fn capture_pdu(label: &str, bytes: &[u8]) {
    let Some(dir) = capture_dir() else {
        return;
    };
    write_capture(&dir, label, bytes);
}

fn capture_dir() -> Option<String> {
    match std::env::var("KERBER_CAPTURE_DIR") {
        Ok(d) if d.is_empty() => return None,
        Ok(d) => return refuse_golden_home(d),
        Err(_) => {}
    }
    let base = std::env::var("KERBER_SCRATCH")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("CARGO_TARGET_DIR")
                .ok()
                .filter(|s| !s.is_empty())
        })?;
    refuse_golden_home(format!("{base}/traces"))
}

fn refuse_golden_home(dir: String) -> Option<String> {
    if is_golden_home(&dir) {
        return None;
    }
    Some(dir)
}

fn is_golden_home(dir: &str) -> bool {
    let norm = dir.replace('\\', "/");
    let parts: Vec<&str> = norm.split('/').collect();
    parts
        .windows(2)
        .any(|w| w[0] == "tests" && w[1] == "traces")
}

fn write_capture(dir: &str, label: &str, bytes: &[u8]) {
    let _ = std::fs::create_dir_all(dir);
    let mut n = [0u8; 4];
    if getrandom::getrandom(&mut n).is_err() {
        return;
    }
    let fname = format!("{label}-{:08x}.der", u32::from_be_bytes(n));
    let path = std::path::Path::new(dir).join(fname);
    let _ = std::fs::write(path, bytes);
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn unique_dir(prefix: &str) -> PathBuf {
        krb5_testkit::scratch_dir(prefix)
    }

    fn dir_count(dir: &Path) -> usize {
        std::fs::read_dir(dir).map_or(0, std::iter::Iterator::count)
    }

    fn spawn(name: &str, f: impl FnOnce(&mut Command)) -> bool {
        let Some(exe) = std::env::current_exe().ok() else {
            return false;
        };
        let mut cmd = Command::new(&exe);
        cmd.args([name, "--exact", "--nocapture"]);
        f(&mut cmd);
        cmd.status().is_ok_and(|s| s.success())
    }

    #[test]
    fn capture_writes_der_into_dir() {
        let dir = unique_dir("kerber-cap");
        let _ = std::fs::create_dir_all(&dir);
        super::write_capture(dir.to_str().unwrap_or("."), "test", b"\x6a\x03");
        let count = dir_count(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(count >= 1);
    }

    #[test]
    fn capture_pdu_honors_kerber_capture_dir() {
        if std::env::var("KERBER_CAPTURE_CHILD").ok().as_deref() == Some("1") {
            super::capture_pdu("test", b"\x6a\x03");
            return;
        }
        let dir = unique_dir("kerber-cap-env");
        let _ = std::fs::create_dir_all(&dir);
        let ok = spawn(
            "capture::tests::capture_pdu_honors_kerber_capture_dir",
            |cmd| {
                cmd.env("KERBER_CAPTURE_CHILD", "1")
                    .env("KERBER_CAPTURE_DIR", &dir);
            },
        );
        assert!(ok, "capture child");
        let count = dir_count(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            count >= 1,
            "shipped capture_pdu must write when KERBER_CAPTURE_DIR is set"
        );
    }

    #[test]
    fn capture_pdu_child() {
        if let Some("scratch" | "empty" | "golden") =
            std::env::var("KERBER_CAPTURE_CHILD").ok().as_deref()
        {
            super::capture_pdu("test", b"\x6a\x03");
        }
    }

    #[test]
    fn capture_pdu_defaults_under_kerber_scratch() {
        let scratch = unique_dir("kerber-cap-scratch");
        let _ = std::fs::create_dir_all(&scratch);
        let ok = spawn("capture::tests::capture_pdu_child", |cmd| {
            cmd.env("KERBER_CAPTURE_CHILD", "scratch")
                .env_remove("KERBER_CAPTURE_DIR")
                .env("KERBER_SCRATCH", &scratch)
                .env_remove("CARGO_TARGET_DIR");
        });
        assert!(ok, "scratch child");
        let count = dir_count(&scratch.join("traces"));
        let _ = std::fs::remove_dir_all(&scratch);
        assert!(
            count >= 1,
            "unset CAPTURE_DIR writes $KERBER_SCRATCH/traces"
        );
    }

    #[test]
    fn capture_pdu_empty_dir_disables() {
        let scratch = unique_dir("kerber-cap-empty");
        let _ = std::fs::create_dir_all(&scratch);
        let ok = spawn("capture::tests::capture_pdu_child", |cmd| {
            cmd.env("KERBER_CAPTURE_CHILD", "empty")
                .env("KERBER_CAPTURE_DIR", "")
                .env("KERBER_SCRATCH", &scratch);
        });
        assert!(ok, "empty child");
        let traces = scratch.join("traces");
        let wrote = traces.is_dir() && dir_count(&traces) > 0;
        let _ = std::fs::remove_dir_all(&scratch);
        assert!(!wrote, "empty KERBER_CAPTURE_DIR disables capture");
    }

    #[test]
    fn capture_pdu_refuses_tests_traces() {
        let root = unique_dir("kerber-cap-golden");
        let golden = root.join("tests").join("traces");
        let _ = std::fs::create_dir_all(&golden);
        let ok = spawn("capture::tests::capture_pdu_child", |cmd| {
            cmd.env("KERBER_CAPTURE_CHILD", "golden")
                .env("KERBER_CAPTURE_DIR", &golden);
        });
        assert!(ok, "golden child");
        let count = dir_count(&golden);
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(count, 0, "capture must refuse tests/traces");
    }

    #[test]
    fn is_golden_home_matches_nested_tests_traces() {
        assert!(super::is_golden_home("/x/tests/traces"));
        assert!(super::is_golden_home("/x/tests/traces/extra"));
        assert!(!super::is_golden_home("/x/target/traces"));
        assert!(!super::is_golden_home("/x/tests/other"));
    }
}
