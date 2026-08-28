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
    use std::process::Command;

    fn unique_dir(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ))
    }

    #[test]
    fn capture_writes_der_into_dir() {
        let dir = unique_dir("kerber-cap");
        let _ = std::fs::create_dir_all(&dir);
        super::write_capture(dir.to_str().expect("utf8 temp"), "test", b"\x6a\x03");
        let count = std::fs::read_dir(&dir).map_or(0, std::iter::Iterator::count);
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
        let exe = std::env::current_exe().expect("test exe");
        let status = Command::new(&exe)
            .args([
                "capture::tests::capture_pdu_honors_kerber_capture_dir",
                "--exact",
                "--nocapture",
            ])
            .env("KERBER_CAPTURE_CHILD", "1")
            .env("KERBER_CAPTURE_DIR", &dir)
            .status()
            .expect("spawn capture child");
        assert!(status.success(), "capture child");
        let count = std::fs::read_dir(&dir).map_or(0, std::iter::Iterator::count);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            count >= 1,
            "shipped capture_pdu must write when KERBER_CAPTURE_DIR is set"
        );
    }
}
