//! RFC 6113 KRB-FX-CF2 and P-256 ECDH used by FAST, SPAKE, and PKINIT.
//!
//! CF2 is PRF+ of each key under its pepper, XOR, then random-to-key.
//! Both PRF+ outputs, and the buffer each key below is cut from, are wiped
//! on every return; the hash outputs on the stack are not.

use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256};
use zeroize::Zeroize;

use crate::error::Error;
use crate::etype::EncryptionType;
use crate::key::ProtocolKey;
use crate::prf::prf_plus;
use crate::wipe::Wiped;

/// KRB-FX-CF2(k1, k2, pepper1, pepper2) = random-to-key(PRF+(k1,p1) XOR PRF+(k2,p2)).
///
/// MIT `krb5_c_fx_cf2_simple` (`cf2.c:123-176`): each PRF+ is `k1`'s random-to-key input length, so des3 takes 21 octets.
///
/// # Errors
///
/// The refusals of [`prf`](crate::prf) for a des3-cbc-sha1 `k1` or `k2` MIT refuses; otherwise none:
/// both [`prf_plus`] calls ask for `k1`'s random-to-key input length, which is never 0 (the only
/// length it refuses), and the key is made from exactly that many octets.
pub fn krb_fx_cf2(
    k1: &ProtocolKey,
    k2: &ProtocolKey,
    pepper1: &[u8],
    pepper2: &[u8],
) -> Result<ProtocolKey, Error> {
    let n = k1.etype().keybytes();
    let mut a = Wiped(prf_plus(k1, pepper1, n)?);
    let b = Wiped(prf_plus(k2, pepper2, n)?);
    for (x, y) in a.iter_mut().zip(b.iter()) {
        *x ^= *y;
    }
    ProtocolKey::from_random(k1.etype(), &a)
}

/// P-256 ECDH: 32-byte scalar and 65-byte uncompressed public key.
///
/// The scalar is zeroized where the value lies when it drops. It is an inline array, so a copy
/// that a move of the value leaves, or that is taken out of it, is not wiped.
pub struct P256Keypair {
    /// Scalar (secret).
    pub secret: [u8; 32],
    /// Uncompressed SEC1 public key.
    pub public: Vec<u8>,
}

impl Drop for P256Keypair {
    fn drop(&mut self) {
        self.secret.zeroize();
        #[cfg(test)]
        let _ = crate::wipe::tests::DROPPED_SCALARS.try_with(|d| d.borrow_mut().push(self.secret));
    }
}

/// Generate a P-256 keypair.
///
/// # Errors
///
/// [`Error::Rng`] when the CSPRNG fails or the scalar is invalid.
pub fn p256_generate() -> Result<P256Keypair, Error> {
    use p256::elliptic_curve::PrimeField;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
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
/// [`Error::Integrity`] when `secret` is zero or not below the P-256 order, or `peer_public` is
/// not a SEC1 encoding of a curve point or is the identity.
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

/// ECDSA-SHA256 over `message` with a P-256 secret. Signature is DER `SEQUENCE { r, s }`.
///
/// # Errors
///
/// [`Error::Integrity`] when `secret` is zero or not below the P-256 order.
pub fn p256_ecdsa_sign(secret: &[u8; 32], message: &[u8]) -> Result<Vec<u8>, Error> {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    let sk = SigningKey::from_bytes(secret.into()).map_err(|_| Error::Integrity)?;
    let sig: Signature = sk.sign(message);
    Ok(sig.to_der().as_bytes().to_vec())
}

/// Verify ECDSA-SHA256 (`message` is hashed with SHA-256 by the verifier).
///
/// # Errors
///
/// [`Error::Integrity`] when `public` is not a SEC1 P-256 public key, `der_sig` is not a DER
/// ECDSA signature, or the signature does not verify over `message`.
pub fn p256_ecdsa_verify(public: &[u8], message: &[u8], der_sig: &[u8]) -> Result<(), Error> {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    let vk = VerifyingKey::from_sec1_bytes(public).map_err(|_| Error::Integrity)?;
    let sig = Signature::from_der(der_sig).map_err(|_| Error::Integrity)?;
    vk.verify(message, &sig).map_err(|_| Error::Integrity)
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
    use p256::elliptic_curve::{PrimeField, ff::Field};
    let s = Option::<p256::Scalar>::from(p256::Scalar::from_repr((*b).into()))
        .ok_or(Error::Integrity)?;
    if bool::from(s.is_zero()) {
        return Err(Error::Integrity);
    }
    Ok(s)
}

/// RFC 4556 `octetstring2key`: K-truncate of concatenated SHA-1(n || x), through the enctype's
/// random-to-key.
/// MIT `octetstring2key` (`plugins/preauth/pkinit/pkinit_crypto_openssl.c:2574-2646`): `keybytes` octets of the
/// stream go to `krb5_c_random_to_key`, so a des3 key is 21 octets spread over 24 with odd parity.
///
/// # Errors
///
/// None: the SHA-1 stream is cut to exactly `etype.keybytes()` octets, the length the
/// enctype's random-to-key requires.
pub fn octetstring2key(etype: EncryptionType, x: &[u8]) -> Result<ProtocolKey, Error> {
    let n = etype.keybytes();
    let mut buf = Wiped(Vec::with_capacity(n + 20));
    let mut i = 0u8;
    while buf.len() < n {
        let mut h = <Sha1 as Sha1Digest>::new();
        Sha1Digest::update(&mut h, [i]);
        Sha1Digest::update(&mut h, x);
        buf.extend_from_slice(&Sha1Digest::finalize(h));
        i = i.saturating_add(1);
        if i == 0 {
            break;
        }
    }
    buf.truncate(n);
    ProtocolKey::from_random(etype, &buf)
}

/// RFC 8636 PKINIT KDF: `SHA-256(counter || Z || OtherInfo)` K-truncated, through the enctype's
/// random-to-key.
///
/// `other_info` is the DER of RFC 8636 `OtherInfo` (or a test stand-in).
/// `Z` is the DH/ECDH shared secret. This is **not** RFC 4556 SHA-1
/// `octetstring2key`.
/// MIT `pkinit_kdf` (`plugins/preauth/pkinit/pkinit_crypto_openssl.c:2783-2868`): the SSKDF output is `keybytes`
/// octets, which go to `krb5_c_random_to_key`, so a des3 key is 21 octets spread over 24 with odd parity.
///
/// # Errors
///
/// None: the SHA-256 stream is cut to exactly `etype.keybytes()` octets, the length the
/// enctype's random-to-key requires.
pub fn pkinit_kdf_agile(
    etype: EncryptionType,
    shared: &[u8],
    other_info: &[u8],
) -> Result<ProtocolKey, Error> {
    let n = etype.keybytes();
    let mut buf = Wiped(Vec::with_capacity(n + 32));
    let mut counter = 1u32;
    while buf.len() < n {
        let mut h = Sha256::new();
        Sha2Digest::update(&mut h, counter.to_be_bytes());
        Sha2Digest::update(&mut h, shared);
        Sha2Digest::update(&mut h, other_info);
        buf.extend_from_slice(&Sha2Digest::finalize(h));
        counter = counter.saturating_add(1);
        if counter == 0 {
            break;
        }
    }
    buf.truncate(n);
    ProtocolKey::from_random(etype, &buf)
}

#[cfg(test)]
mod tests {
    use crate::etype::EncryptionType;

    #[test]
    fn arcfour_usage_9_is_9() {
        let k = crate::ops::string_to_key(EncryptionType::Rc4Hmac, b"password", b"", None).unwrap();
        let u9 = crate::etype::KeyUsage::new(9).unwrap();
        let u8 = crate::etype::KeyUsage::new(8).unwrap();
        let conf = [9u8; 8];
        let a = crate::weak::rc4_encrypt_with_conf(&k, u9, &conf, b"x").unwrap();
        let b = crate::weak::rc4_encrypt_with_conf(&k, u8, &conf, b"x").unwrap();
        assert_ne!(a, b, "enc_rc4.c:26 case 9 returns 9");
    }
}
