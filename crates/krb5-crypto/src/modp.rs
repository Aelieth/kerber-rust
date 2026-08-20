//! RFC 3526 Oakley MODP groups used by RFC 4556 PKINIT.

use std::sync::OnceLock;

use num_bigint::BigUint;
use zeroize::Zeroize;

use crate::error::Error;

/// RFC 3526 group 14 (2048-bit) and group 16 (4096-bit).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DhGroup {
    /// Human-readable name (`modp14` / `modp16`).
    pub name: &'static str,
    /// Prime size in bits.
    pub bits: u16,
    p_hex: &'static [u8],
}

/// Ephemeral DH key for PKINIT.
pub struct DhKeypair {
    /// Exponent (big-endian, not padded).
    pub secret: Vec<u8>,
    /// `y = g^x mod p`, big-endian, padded to `|p|`.
    pub public: Vec<u8>,
    /// DER `INTEGER` of `y` (RFC 4556 `DHPublicKey`).
    pub public_der: Vec<u8>,
}

impl Drop for DhKeypair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Oakley 2048-bit MODP group 14 (RFC 3526). RFC 4556 MUST.
pub const OAKLEY_2048: DhGroup = DhGroup {
    name: "modp14",
    bits: 2048,
    p_hex: b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
15728E5A8AACAA68FFFFFFFFFFFFFFFF",
};

/// Oakley 4096-bit MODP group 16 (RFC 3526). RFC 4556 SHOULD.
pub const OAKLEY_4096: DhGroup = DhGroup {
    name: "modp16",
    bits: 4096,
    p_hex: b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64\
ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B\
F12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31\
43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7\
88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA\
2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6\
287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED\
1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9\
93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199\
FFFFFFFFFFFFFFFF",
};

fn parse_p(hex: &'static [u8]) -> BigUint {
    // RFC 3526 MODP primes are compile-time constants; a parse failure is a
    // programming error in the hex tables above.
    #[allow(clippy::expect_used)]
    BigUint::parse_bytes(hex, 16).expect("RFC 3526 prime")
}

fn p2048() -> &'static BigUint {
    static P: OnceLock<BigUint> = OnceLock::new();
    P.get_or_init(|| parse_p(OAKLEY_2048.p_hex))
}

fn p4096() -> &'static BigUint {
    static P: OnceLock<BigUint> = OnceLock::new();
    P.get_or_init(|| parse_p(OAKLEY_4096.p_hex))
}

impl DhGroup {
    fn prime(&self) -> &'static BigUint {
        if self.bits == 2048 {
            p2048()
        } else {
            p4096()
        }
    }

    /// Length of the modulus in octets (padded DH secret / public).
    #[must_use]
    pub fn modulus_len(&self) -> usize {
        usize::from(self.bits / 8)
    }

    /// Modulus as an unsigned big-endian integer (no leading zeros).
    #[must_use]
    pub fn prime_bytes(&self) -> Vec<u8> {
        self.prime().to_bytes_be()
    }
}

/// Identify a well-known Oakley prime from a big-endian integer.
#[must_use]
pub fn dh_group_for_prime(p: &[u8]) -> Option<&'static DhGroup> {
    let n = BigUint::from_bytes_be(p);
    if n == *p2048() {
        Some(&OAKLEY_2048)
    } else if n == *p4096() {
        Some(&OAKLEY_4096)
    } else {
        None
    }
}

fn pad_be(n: &BigUint, len: usize) -> Vec<u8> {
    let mut out = n.to_bytes_be();
    if out.len() >= len {
        return out;
    }
    let mut padded = vec![0u8; len - out.len()];
    padded.append(&mut out);
    padded
}

/// DER `INTEGER` of an unsigned big-endian value.
#[must_use]
pub fn der_unsigned_integer(be: &[u8]) -> Vec<u8> {
    let mut n: Vec<u8> = be.iter().skip_while(|b| **b == 0).copied().collect();
    if n.is_empty() {
        n.push(0);
    }
    if n[0] & 0x80 != 0 {
        n.insert(0, 0);
    }
    let mut out = vec![0x02];
    if n.len() < 128 {
        out.push(u8::try_from(n.len()).unwrap_or(0));
    } else if n.len() < 256 {
        out.push(0x81);
        out.push(u8::try_from(n.len()).unwrap_or(0));
    } else {
        out.push(0x82);
        out.extend_from_slice(&(u16::try_from(n.len()).unwrap_or(u16::MAX)).to_be_bytes());
    }
    out.extend_from_slice(&n);
    out
}

/// Generate an ephemeral DH key for `group` (`g = 2`, 256- or 384-bit exponent).
///
/// # Errors
///
/// [`Error::Rng`] when the CSPRNG fails.
pub fn dh_generate(group: &DhGroup) -> Result<DhKeypair, Error> {
    let p = group.prime();
    let g = BigUint::from(2u8);
    let exp_len = if group.bits >= 4096 { 48 } else { 32 };
    let mut secret = vec![0u8; exp_len];
    for _ in 0..16 {
        getrandom::getrandom(&mut secret).map_err(|_| Error::Rng)?;
        if secret.iter().all(|b| *b == 0) {
            continue;
        }
        let x = BigUint::from_bytes_be(&secret);
        if x < BigUint::from(2u8) {
            continue;
        }
        let y = g.modpow(&x, p);
        let public = pad_be(&y, group.modulus_len());
        let public_der = der_unsigned_integer(&public);
        return Ok(DhKeypair {
            secret,
            public,
            public_der,
        });
    }
    Err(Error::Rng)
}

/// DH shared secret, padded to `|p|` (RFC 4556 octet-string of the modulus).
///
/// `peer_y` is a big-endian integer (leading zeros ignored).
///
/// # Errors
///
/// [`Error::Integrity`] when `peer_y` is out of range for a safe prime.
pub fn dh_shared(group: &DhGroup, secret: &[u8], peer_y: &[u8]) -> Result<Vec<u8>, Error> {
    let p = group.prime();
    let y = BigUint::from_bytes_be(peer_y);
    let one = BigUint::from(1u8);
    if y <= one || y >= p - &one {
        return Err(Error::Integrity);
    }
    let x = BigUint::from_bytes_be(secret);
    let z = y.modpow(&x, p);
    Ok(pad_be(&z, group.modulus_len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agree(group: &DhGroup) {
        let a = dh_generate(group).unwrap();
        let b = dh_generate(group).unwrap();
        let ab = dh_shared(group, &a.secret, &b.public).unwrap();
        let ba = dh_shared(group, &b.secret, &a.public).unwrap();
        assert_eq!(ab, ba);
        assert_eq!(ab.len(), group.modulus_len());
        assert_ne!(ab, vec![0u8; ab.len()]);
    }

    #[test]
    fn dh_agrees_modp14() {
        agree(&OAKLEY_2048);
    }

    #[test]
    fn dh_agrees_modp16() {
        agree(&OAKLEY_4096);
    }

    #[test]
    fn unknown_prime_is_rejected() {
        assert!(dh_group_for_prime(&[1, 2, 3]).is_none());
        let p = p2048().to_bytes_be();
        assert_eq!(dh_group_for_prime(&p).map(|g| g.bits), Some(2048));
        let q = p4096().to_bytes_be();
        assert_eq!(dh_group_for_prime(&q).map(|g| g.bits), Some(4096));
    }

    #[test]
    fn peer_one_is_rejected() {
        let a = dh_generate(&OAKLEY_2048).unwrap();
        assert!(dh_shared(&OAKLEY_2048, &a.secret, &[1]).is_err());
    }
}
