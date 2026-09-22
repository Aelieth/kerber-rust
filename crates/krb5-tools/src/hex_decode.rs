fn hex_decode(h: &str) -> Result<Vec<u8>, String> {
    let h = h.trim();
    if !h.len().is_multiple_of(2) || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("odd or non-hex".into());
    }
    let mut out = vec![0u8; h.len() / 2];
    for i in 0..out.len() {
        out[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}
