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
    let _ = std::fs::create_dir_all(&dir);
    let mut n = [0u8; 4];
    if getrandom::getrandom(&mut n).is_err() {
        return;
    }
    let fname = format!("{label}-{:08x}.der", u32::from_be_bytes(n));
    let path = std::path::Path::new(&dir).join(fname);
    let _ = std::fs::write(path, bytes);
}

#[cfg(test)]
mod tests {
    #[test]
    fn capture_writes_der_when_env_set() {
        let dir = std::env::temp_dir().join(format!(
            "kerber-cap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::create_dir_all(&dir);
        std::env::set_var("KERBER_CAPTURE_DIR", &dir);
        super::capture_pdu("test", b"\x6a\x03");
        let count = std::fs::read_dir(&dir)
            .map(std::iter::Iterator::count)
            .unwrap_or(0);
        std::env::remove_var("KERBER_CAPTURE_DIR");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(count >= 1);
    }
}
