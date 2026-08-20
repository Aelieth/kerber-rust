//! RFC 3961 n-fold. Ported from MIT krb5 `krb5int_nfold` (1.22.2).

/// Expand `input` to exactly `out_len` octets using 1's-complement addition
/// of 13-bit rotations, as specified in RFC 3961 section 5.1.
///
/// `input` must be non-empty. `out_len` must be non-zero.
#[must_use]
pub fn nfold(input: &[u8], out_len: usize) -> Vec<u8> {
    assert!(!input.is_empty() && out_len > 0);
    let inbits = input.len();
    let outbits = out_len;

    let mut a = outbits;
    let mut b = inbits;
    while b != 0 {
        let c = b;
        b = a % b;
        a = c;
    }
    let lcm = outbits * inbits / a;

    let mut out = vec![0u8; outbits];
    let mut byte: u32 = 0;

    for i in (0..lcm).rev() {
        let msbit = {
            let inbits_bits = inbits << 3;
            ((inbits_bits - 1)
                + ((inbits_bits + 13) * (i / inbits))
                + ((inbits - (i % inbits)) << 3))
                % inbits_bits
        };

        byte += u32::from(
            (((u16::from(input[((inbits - 1) - (msbit >> 3)) % inbits]) << 8)
                | u16::from(input[(inbits - (msbit >> 3)) % inbits]))
                >> ((msbit & 7) + 1))
                & 0xff,
        );
        byte += u32::from(out[i % outbits]);
        out[i % outbits] = (byte & 0xff) as u8;
        byte >>= 8;
    }

    if byte != 0 {
        for i in (0..outbits).rev() {
            byte += u32::from(out[i]);
            out[i] = (byte & 0xff) as u8;
            byte >>= 8;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::nfold;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc3961_appendix_a1() {
        assert_eq!(nfold(b"012345", 8), hex("be072631276b1955"));
        assert_eq!(nfold(b"password", 7), hex("78a07b6caf85fa"));
        assert_eq!(
            nfold(b"Rough Consensus, and Running Code", 8),
            hex("bb6ed30870b7f0e0")
        );
        assert_eq!(
            nfold(b"password", 21),
            hex("59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e")
        );
        assert_eq!(
            nfold(b"MASSACHVSETTS INSTITVTE OF TECHNOLOGY", 24),
            hex("db3b0d8f0b061e603282b308a50841229ad798fab9540c1b")
        );
        assert_eq!(
            nfold(b"Q", 21),
            hex("518a54a215a8452a518a54a215a8452a518a54a215")
        );
        assert_eq!(
            nfold(b"ba", 21),
            hex("fb25d531ae8974499f52fd92ea9857c4ba24cf297e")
        );
        assert_eq!(nfold(b"kerberos", 8), hex("6b65726265726f73"));
        assert_eq!(
            nfold(b"kerberos", 16),
            hex("6b65726265726f737b9b5b2b93132b93")
        );
        assert_eq!(
            nfold(b"kerberos", 21),
            hex("8372c236344e5f1550cd0747e15d62ca7a5a3bcea4")
        );
        assert_eq!(
            nfold(b"kerberos", 32),
            hex(
                "6b65726265726f737b9b5b2b93132b935c9bdc dad95c9899c4cae4dee6d6cae4"
                    .replace(' ', "")
                    .as_str()
            )
        );
    }
}
