//! RFC 6113 KRB-FX-CF2 and P-256 ECDH used by FAST, SPAKE, and PKINIT.

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::Error;
use crate::etype::EncryptionType;
use crate::key::ProtocolKey;
use crate::prf::prf_plus;

/// KRB-FX-CF2(k1, k2, pepper1, pepper2) = random-to-key(PRF+(k1,p1) XOR PRF+(k2,p2)).
///
/// # Errors
///
/// PRF or key-length failures.
pub fn krb_fx_cf2(
    k1: &ProtocolKey,
    k2: &ProtocolKey,
    pepper1: &[u8],
    pepper2: &[u8],
) -> Result<ProtocolKey, Error> {
    let n = k1.etype().key_len();
    let mut a = prf_plus(k1, pepper1, n)?;
    let b = prf_plus(k2, pepper2, n)?;
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x ^= *y;
    }
    let key = ProtocolKey::from_bytes(k1.etype(), &a)?;
    a.zeroize();
    Ok(key)
}

/// Truncate or hash `bytes` to an etype-sized protocol key.
///
/// # Errors
///
/// [`Error::InvalidKeyLength`] should not occur after truncation.
pub fn key_from_shared(etype: EncryptionType, bytes: &[u8]) -> Result<ProtocolKey, Error> {
    let n = etype.key_len();
    if bytes.len() >= n {
        return ProtocolKey::from_bytes(etype, &bytes[..n]);
    }
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut buf = vec![0u8; n];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = out[i % out.len()];
    }
    ProtocolKey::from_bytes(etype, &buf)
}

/// P-256 ECDH: 32-byte scalar and 65-byte uncompressed public key.
pub struct P256Keypair {
    /// Scalar (secret).
    pub secret: [u8; 32],
    /// Uncompressed SEC1 public key.
    pub public: Vec<u8>,
}

/// Generate a P-256 keypair.
///
/// # Errors
///
/// [`Error::Rng`] when the CSPRNG fails or the scalar is invalid.
pub fn p256_generate() -> Result<P256Keypair, Error> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::elliptic_curve::PrimeField;
    use p256::{AffinePoint, ProjectivePoint};
    let scalar = random_scalar()?;
    let point = ProjectivePoint::GENERATOR * scalar;
    let enc = AffinePoint::from(point).to_encoded_point(false);
    let mut secret = [0u8; 32];
    secret.copy_from_slice(scalar.to_repr().as_ref());
    Ok(P256Keypair {
        secret,
        public: enc.as_bytes().to_vec(),
    })
}

/// ECDH shared secret (x-coordinate of scalar * peer).
///
/// # Errors
///
/// Invalid peer public key or scalar.
pub fn p256_shared(secret: &[u8; 32], peer_public: &[u8]) -> Result<[u8; 32], Error> {
    use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use p256::{AffinePoint, EncodedPoint, ProjectivePoint};
    let sc = scalar_from_bytes32(secret)?;
    let ep = EncodedPoint::from_bytes(peer_public).map_err(|_| Error::Integrity)?;
    let aff = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep))
        .ok_or(Error::Integrity)?;
    let shared = ProjectivePoint::from(aff) * sc;
    let out_pt = AffinePoint::from(shared).to_encoded_point(false);
    let bytes = out_pt.as_bytes();
    if bytes.len() < 33 {
        return Err(Error::Integrity);
    }
    // Uncompressed: 0x04 || x (32) || y (32)
    let mut x = [0u8; 32];
    x.copy_from_slice(&bytes[1..33]);
    Ok(x)
}

fn random_scalar() -> Result<p256::Scalar, Error> {
    let mut b = [0u8; 32];
    for _ in 0..16 {
        getrandom::getrandom(&mut b).map_err(|_| Error::Rng)?;
        b[0] &= 0x7f;
        if let Ok(s) = scalar_from_bytes32(&b) {
            return Ok(s);
        }
    }
    Err(Error::Rng)
}

fn scalar_from_bytes32(b: &[u8; 32]) -> Result<p256::Scalar, Error> {
    use p256::elliptic_curve::{ff::Field, PrimeField};
    let s = Option::<p256::Scalar>::from(p256::Scalar::from_repr((*b).into()))
        .ok_or(Error::Integrity)?;
    if bool::from(s.is_zero()) {
        return Err(Error::Integrity);
    }
    Ok(s)
}

/// SPAKE2-P256: password scalar `w`.
#[must_use]
pub fn spake_w(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"SPAKE2-P256-w");
    h.update(password);
    h.update(salt);
    let out = h.finalize();
    let mut w = [0u8; 32];
    w.copy_from_slice(&out);
    w[0] &= 0x7f;
    w
}

/// SPAKE2 public share: `secret*G + w*M` (client) or `+ w*N` (server).
///
/// # Errors
///
/// Invalid scalars.
pub fn spake_public(w: &[u8; 32], secret: &[u8; 32], server: bool) -> Result<Vec<u8>, Error> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::{AffinePoint, ProjectivePoint};
    let ws = scalar_from_bytes32(w)?;
    let xs = scalar_from_bytes32(secret)?;
    let mn = if server {
        hash_to_point(b"SPAKE2-P256-N")
    } else {
        hash_to_point(b"SPAKE2-P256-M")
    };
    let p = ProjectivePoint::GENERATOR * xs + mn * ws;
    Ok(AffinePoint::from(p)
        .to_encoded_point(false)
        .as_bytes()
        .to_vec())
}

/// SPAKE2 shared secret.
///
/// Client: `secret * (Y - w*N)`; server: `secret * (X - w*M)`.
///
/// # Errors
///
/// Invalid points or scalars.
pub fn spake_finish(
    w: &[u8; 32],
    secret: &[u8; 32],
    peer_public: &[u8],
    we_are_server: bool,
) -> Result<[u8; 32], Error> {
    use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
    use p256::{AffinePoint, EncodedPoint, ProjectivePoint};
    let ws = scalar_from_bytes32(w)?;
    let xs = scalar_from_bytes32(secret)?;
    let ep = EncodedPoint::from_bytes(peer_public).map_err(|_| Error::Integrity)?;
    let peer = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep))
        .ok_or(Error::Integrity)?;
    let mn = if we_are_server {
        hash_to_point(b"SPAKE2-P256-M")
    } else {
        hash_to_point(b"SPAKE2-P256-N")
    };
    let adjusted = ProjectivePoint::from(peer) - mn * ws;
    let shared = adjusted * xs;
    let enc = AffinePoint::from(shared).to_encoded_point(false);
    let b = enc.as_bytes();
    if b.len() < 33 {
        return Err(Error::Integrity);
    }
    let mut x = [0u8; 32];
    x.copy_from_slice(&b[1..33]);
    Ok(x)
}

fn hash_to_point(label: &[u8]) -> p256::ProjectivePoint {
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    use p256::{AffinePoint, EncodedPoint, ProjectivePoint};
    for ctr in 0u8..=255 {
        let mut h = Sha256::new();
        h.update(label);
        h.update([ctr]);
        let x = h.finalize();
        for tag in [0x02u8, 0x03] {
            let mut buf = [0u8; 33];
            buf[0] = tag;
            buf[1..].copy_from_slice(&x);
            if let Ok(ep) = EncodedPoint::from_bytes(buf) {
                if let Some(aff) = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep))
                {
                    return ProjectivePoint::from(aff);
                }
            }
        }
    }
    ProjectivePoint::GENERATOR
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::etype::EncryptionType;
    use crate::key::ProtocolKey;

    #[test]
    fn p256_ecdh_agrees() {
        let a = p256_generate().unwrap();
        let b = p256_generate().unwrap();
        let ab = p256_shared(&a.secret, &b.public).unwrap();
        let ba = p256_shared(&b.secret, &a.public).unwrap();
        assert_eq!(ab, ba);
    }

    #[test]
    fn spake_round_trip() {
        let w = spake_w(b"password", b"SALT");
        let client = p256_generate().unwrap();
        let server = p256_generate().unwrap();
        let x = spake_public(&w, &client.secret, false).unwrap();
        let y = spake_public(&w, &server.secret, true).unwrap();
        let c = spake_finish(&w, &client.secret, &y, false).unwrap();
        let s = spake_finish(&w, &server.secret, &x, true).unwrap();
        assert_eq!(c, s);
        let et = EncryptionType::Aes256CtsHmacSha196;
        let k1 = key_from_shared(et, &c).unwrap();
        let k2 = key_from_shared(et, &s).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn cf2_is_deterministic_and_order_sensitive() {
        let et = EncryptionType::Aes256CtsHmacSha196;
        let k1 = ProtocolKey::from_bytes(et, &[0x11u8; 32]).unwrap();
        let k2 = ProtocolKey::from_bytes(et, &[0x22u8; 32]).unwrap();
        let a = krb_fx_cf2(&k1, &k2, b"p1", b"p2").unwrap();
        let b = krb_fx_cf2(&k1, &k2, b"p1", b"p2").unwrap();
        let c = krb_fx_cf2(&k2, &k1, b"p1", b"p2").unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
    }
}
