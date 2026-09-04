//! RFC 6113 KRB-FX-CF2 and P-256 ECDH used by FAST, SPAKE, and PKINIT.

use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256};
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
    let mut h = <Sha256 as Sha2Digest>::new();
    Sha2Digest::update(&mut h, bytes);
    let out = Sha2Digest::finalize(h);
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

/// ECDSA-SHA256 over `message` with a P-256 secret. Signature is DER `SEQUENCE { r, s }`.
///
/// # Errors
///
/// Invalid scalar or signing failure.
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
/// Invalid public key, signature, or verify failure.
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

/// RFC 4556 `octetstring2key`: K-truncate of concatenated SHA-1(n || x).
///
/// # Errors
///
/// Key-length failures.
pub fn octetstring2key(etype: EncryptionType, x: &[u8]) -> Result<ProtocolKey, Error> {
    let n = etype.key_len();
    let mut buf = Vec::with_capacity(n + 20);
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
    ProtocolKey::from_bytes(etype, &buf)
}

/// RFC 8636 PKINIT KDF: `SHA-256(counter || Z || OtherInfo)` K-truncated.
///
/// `other_info` is the DER of RFC 8636 `OtherInfo` (or a test stand-in).
/// `Z` is the DH/ECDH shared secret. This is **not** RFC 4556 SHA-1
/// `octetstring2key`.
///
/// # Errors
///
/// Key-length failures.
pub fn pkinit_kdf_agile(
    etype: EncryptionType,
    shared: &[u8],
    other_info: &[u8],
) -> Result<ProtocolKey, Error> {
    let n = etype.key_len();
    let mut buf = Vec::with_capacity(n + 32);
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
    ProtocolKey::from_bytes(etype, &buf)
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
    fn rfc8636_kdf_differs_from_octetstring2key() {
        let z = b"shared-secret-bytes-for-kdf";
        let other = b"other-info";
        let agile = pkinit_kdf_agile(EncryptionType::Aes256CtsHmacSha196, z, other).unwrap();
        let sha1 = octetstring2key(EncryptionType::Aes256CtsHmacSha196, z).unwrap();
        assert_ne!(agile.as_bytes(), sha1.as_bytes());
        let again = pkinit_kdf_agile(EncryptionType::Aes256CtsHmacSha196, z, other).unwrap();
        assert_eq!(agile.as_bytes(), again.as_bytes());
    }

    #[test]
    fn p256_ecdsa_sign_verify() {
        let kp = p256_generate().unwrap();
        let msg = b"pkinit-authpack";
        let sig = p256_ecdsa_sign(&kp.secret, msg).unwrap();
        p256_ecdsa_verify(&kp.public, msg, &sig).unwrap();
        assert!(p256_ecdsa_verify(&kp.public, b"other", &sig).is_err());
    }

    #[test]
    fn camellia_cts_cmac_round_trips() {
        let key = crate::ops::string_to_key(
            EncryptionType::Camellia256CtsCmac,
            b"password",
            b"SALT",
            None,
        )
        .unwrap();
        let usage = crate::etype::KeyUsage::new(2).unwrap();
        let c = crate::ops::encrypt(&key, usage, b"camellia-plain").unwrap();
        let p = crate::ops::decrypt(&key, usage, &c).unwrap();
        assert_eq!(p, b"camellia-plain");
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

    #[test]
    fn des3_s2k_round_trips() {
        let k = crate::ops::string_to_key(
            EncryptionType::Des3CbcSha1,
            b"password",
            b"ATHENA.MIT.EDUraeburn",
            None,
        )
        .unwrap();
        assert_eq!(k.as_bytes().len(), 24);
        let usage = crate::etype::KeyUsage::new(2).unwrap();
        let c = crate::ops::encrypt(&k, usage, b"des3pln!").unwrap();
        let p = crate::ops::decrypt(&k, usage, &c).unwrap();
        assert_eq!(&p[..8], b"des3pln!");
    }

    #[test]
    fn rc4_usage_3_matches_usage_8() {
        let k = crate::ops::string_to_key(EncryptionType::Rc4Hmac, b"password", b"", None).unwrap();
        let u3 = crate::etype::KeyUsage::new(3).unwrap();
        let u8 = crate::etype::KeyUsage::new(8).unwrap();
        let conf = [9u8; 8];
        let a = crate::weak::rc4_encrypt_with_conf(&k, u3, &conf, b"x").unwrap();
        let b = crate::weak::rc4_encrypt_with_conf(&k, u8, &conf, b"x").unwrap();
        assert_eq!(a, b);
    }

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

    #[test]
    fn camellia_ciphertext_differs_from_aes() {
        let cam = crate::ops::string_to_key(
            EncryptionType::Camellia128CtsCmac,
            b"password",
            b"SALT",
            None,
        )
        .unwrap();
        let aes = crate::ops::string_to_key(
            EncryptionType::Aes128CtsHmacSha196,
            b"password",
            b"SALT",
            None,
        )
        .unwrap();
        assert_ne!(cam.as_bytes(), aes.as_bytes());
    }
}
