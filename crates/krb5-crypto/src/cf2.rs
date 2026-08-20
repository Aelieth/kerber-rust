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
    let mut h = <Sha256 as Sha2Digest>::new();
    Sha2Digest::update(&mut h, b"SPAKE2-P256-w");
    Sha2Digest::update(&mut h, password);
    Sha2Digest::update(&mut h, salt);
    let out = Sha2Digest::finalize(h);
    let mut w = [0u8; 32];
    w.copy_from_slice(&out);
    w[0] &= 0x7f;
    w
}

/// SPAKE2 public share: `secret*G + w*M` (client) or `+ w*N` (server).
///
/// M and N are the draft-ietf-kitten-krb-spake-preauth P-256 seeds.
///
/// # Errors
///
/// Invalid scalars.
pub fn spake_public(w: &[u8; 32], secret: &[u8; 32], server: bool) -> Result<Vec<u8>, Error> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::{AffinePoint, ProjectivePoint};
    let ws = scalar_from_bytes32(w)?;
    let xs = scalar_from_bytes32(secret)?;
    let mn = if server { spake_n()? } else { spake_m()? };
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
        spake_m()?
    } else {
        spake_n()?
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

/// Compressed P-256 M from draft-ietf-kitten-krb-spake-preauth.
const SPAKE_M: [u8; 33] = [
    0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f,
];
/// Compressed P-256 N from draft-ietf-kitten-krb-spake-preauth.
const SPAKE_N: [u8; 33] = [
    0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49,
];

fn spake_m() -> Result<p256::ProjectivePoint, Error> {
    decode_compressed(&SPAKE_M)
}

fn spake_n() -> Result<p256::ProjectivePoint, Error> {
    decode_compressed(&SPAKE_N)
}

fn decode_compressed(bytes: &[u8; 33]) -> Result<p256::ProjectivePoint, Error> {
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    use p256::{AffinePoint, EncodedPoint, ProjectivePoint};
    let ep = EncodedPoint::from_bytes(bytes).map_err(|_| Error::Integrity)?;
    let aff = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep))
        .ok_or(Error::Integrity)?;
    Ok(ProjectivePoint::from(aff))
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
    fn p256_ecdsa_sign_verify() {
        let kp = p256_generate().unwrap();
        let msg = b"pkinit-authpack";
        let sig = p256_ecdsa_sign(&kp.secret, msg).unwrap();
        p256_ecdsa_verify(&kp.public, msg, &sig).unwrap();
        assert!(p256_ecdsa_verify(&kp.public, b"other", &sig).is_err());
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
