//! Length-prefixed messages on a stream (RFC 4120 §7.2.2 TCP, RFC 3244 kpasswd over TCP,
//! kprop), each call written with one write.

use std::io::{self, Write};

/// Write `messages`, each behind its 4-byte big-endian length, with one write and a flush, so a
/// message and its length leave together: two writes put the 4-byte length in a segment of its
/// own, and Nagle then holds the message until the peer's delayed ACK (about 40 ms).
/// MIT `k5_write_messages` (`lib/krb5/os/write_msg.c:39-70`): the lengths and the messages go out
/// in one writev, "to avoid Nagle/DelayedAck problems".
///
/// # Errors
///
/// The error of the write or the flush; `InvalidInput` for a message of 4 GiB or more.
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

    /// The buffer of each `write` call.
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
