// Length-prefixed GSS tokens on a TCP stream.
// A length of 0 or above 1 MiB is refused. A short read is an error,
// not a partial token.

fn read_token(s: &mut std::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr)?;
    let n = usize::try_from(u32::from_be_bytes(hdr)).unwrap_or(usize::MAX);
    if n == 0 || n > 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad token length {n}"),
        ));
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_token(s: &mut std::net::TcpStream, tok: &[u8]) -> std::io::Result<()> {
    let n = u32::try_from(tok.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "token too large"))?;
    s.write_all(&n.to_be_bytes())?;
    s.write_all(tok)?;
    s.flush()
}
