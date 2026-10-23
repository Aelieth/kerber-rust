//! Length-prefixed messages, each call written with one write.

use std::io::{self, Write};

// MIT: `k5_write_messages` (lib/krb5/os/write_msg.c:39-70)
/// A lone length lets Nagle hold the message.
/// A message of 4 GiB or more is InvalidInput.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Writes(Vec<Vec<u8>>);

    impl Write for Writes {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.push(buf.to_vec());
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_message_and_its_length_are_one_write() {
        let mut w = Writes::default();
        write_messages(&mut w, &[b"reply"]).unwrap();
        assert_eq!(w.0, [b"\0\0\0\x05reply".to_vec()]);
        let mut w = Writes::default();
        write_messages(&mut w, &[b"KRB5_SENDAUTH_V1.0\0", b"kprop5_01\0"]).unwrap();
        assert_eq!(
            w.0,
            [b"\0\0\0\x13KRB5_SENDAUTH_V1.0\0\0\0\0\x0akprop5_01\0".to_vec()]
        );
        let mut w = Writes::default();
        write_messages(&mut w, &[b""]).unwrap();
        assert_eq!(w.0, [vec![0u8; 4]]);
    }
}
