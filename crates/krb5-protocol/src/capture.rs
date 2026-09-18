//! Env-gated raw PDU capture (`KERBER_CAPTURE_DIR`).
//!
//! Writes each request/reply at the Rust socket boundary so MIT 1.22.2
//! DER can be archived under `tests/traces/` with no packet sniffer.

/// Write `bytes` as `{label}-<nonce>.der` when `KERBER_CAPTURE_DIR` is set.
pub fn capture_pdu(label: &str, bytes: &[u8]) {
    let Ok(dir) = std::env::var("KERBER_CAPTURE_DIR") else {
        return;
    };
    if dir.is_empty() {
        return;
    }
    write_capture(&dir, label, bytes);
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
        if let Some("unset" | "empty") = std::env::var("KERBER_CAPTURE_CHILD").ok().as_deref() {
            super::capture_pdu("test", b"\x6a\x03");
        }
    }

    #[test]
    fn capture_pdu_unset_writes_nothing() {
        let scratch = unique_dir("kerber-cap-unset");
        let _ = std::fs::create_dir_all(&scratch);
        let ok = spawn("capture::tests::capture_pdu_child", |cmd| {
            cmd.env("KERBER_CAPTURE_CHILD", "unset")
                .env_remove("KERBER_CAPTURE_DIR")
                .env("KERBER_SCRATCH", &scratch)
                .env_remove("CARGO_TARGET_DIR");
        });
        assert!(ok, "unset child");
        let traces = scratch.join("traces");
        let wrote = traces.is_dir() && dir_count(&traces) > 0;
        let count = dir_count(&scratch);
        let _ = std::fs::remove_dir_all(&scratch);
        assert!(
            !wrote && count == 0,
            "unset KERBER_CAPTURE_DIR writes nothing"
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
}
