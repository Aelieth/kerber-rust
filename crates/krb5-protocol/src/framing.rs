use std::io::{self, Write};

// MIT: `k5_write_messages` (lib/krb5/os/write_msg.c:39-70)
/// A lone length lets Nagle hold the message.
/// A message of 4 GiB or more is `InvalidInput`.
pub fn write_messages(w: &mut impl Write, messages: &[&[u8]]) -> io::Result<()> {
    let mut out = Vec::with_capacity(messages.iter().map(|m| 4 + m.len()).sum());
    for m in messages {
        let len = u32::try_from(m.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too long"))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(m);
    }
    w.write_all(&out)?;
    w.flush()
}
