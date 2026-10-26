//! Raw PDU capture, in a test-hooks build only.
//! A release build writes nothing, as MIT's tools capture nothing.
//! Each PDU is written at the socket, with no packet sniffer.
//! The name is `{label}-<nonce>.der` when KERBER_CAPTURE_DIR is set.
pub fn capture_pdu(label: &str, bytes: &[u8]) {
    #[cfg(feature = "test-hooks")]
    {
        let Ok(dir) = std::env::var("KERBER_CAPTURE_DIR") else {
            return;
        };
        if dir.is_empty() {
            return;
        }
        write_capture(&dir, label, bytes);
    }
    #[cfg(not(feature = "test-hooks"))]
    let _ = (label, bytes);
}

#[cfg(feature = "test-hooks")]
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
