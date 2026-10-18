use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256};
use zeroize::Zeroize;

use crate::error::Error;
use crate::etype::EncryptionType;
use crate::key::ProtocolKey;
use crate::prf::prf_plus;
use crate::wipe::Wiped;

// MIT krb5_c_fx_cf2_simple; see docs/parity/b1-crypto-keys.md
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

pub struct P256Keypair {
    pub secret: [u8; 32],
    pub public: Vec<u8>,
}

impl Drop for P256Keypair {
    fn drop(&mut self) {
        self.secret.zeroize();
        #[cfg(test)]
        let _ = crate::wipe::tests::DROPPED_SCALARS.try_with(|d| d.borrow_mut().push(self.secret));
    }
}

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
    let mut x = [0u8; 32];
    x.copy_from_slice(&bytes[1..33]);
    Ok(x)
}

pub fn p256_ecdsa_sign(secret: &[u8; 32], message: &[u8]) -> Result<Vec<u8>, Error> {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    let sk = SigningKey::from_bytes(secret.into()).map_err(|_| Error::Integrity)?;
    let sig: Signature = sk.sign(message);
    Ok(sig.to_der().as_bytes().to_vec())
}

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

// MIT octetstring2key; see docs/parity/b1-crypto-keys.md
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

// MIT pkinit_kdf; see docs/parity/b1-crypto-keys.md
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
    use super::*;
    use crate::etype::EncryptionType;
    use crate::key::ProtocolKey;

    fn odd_parity(octets: &[u8]) -> bool {
        octets.iter().all(|b| b.count_ones() % 2 == 1)
    }

    // MIT krb5_c_random_to_key; see docs/parity/b1-crypto-keys.md
    #[test]
    fn the_pkinit_keys_of_des3_are_made_through_random_to_key() {
        use sha1::{Digest as _, Sha1};
        use sha2::Sha256;
        let z = b"a DH shared secret of some length, 32 octets+";
        let other = b"other-info";
        let mut stream = Vec::new();
        for i in 0u8..2 {
            let mut h = Sha1::new();
            h.update([i]);
            h.update(z);
            stream.extend_from_slice(&h.finalize());
        }
        let want = ProtocolKey::from_random(EncryptionType::Des3CbcSha1, &stream[..21]).unwrap();
        let got = octetstring2key(EncryptionType::Des3CbcSha1, z).unwrap();
        assert_eq!(got.as_bytes(), want.as_bytes());
        assert_eq!(got.as_bytes().len(), 24);
        assert!(odd_parity(got.as_bytes()), "{:02x?}", got.as_bytes());
        let mut h = Sha256::new();
        h.update(1u32.to_be_bytes());
        h.update(z);
        h.update(other);
        let block = h.finalize();
        let want = ProtocolKey::from_random(EncryptionType::Des3CbcSha1, &block[..21]).unwrap();
        let got = pkinit_kdf_agile(EncryptionType::Des3CbcSha1, z, other).unwrap();
        assert_eq!(got.as_bytes(), want.as_bytes());
        assert!(odd_parity(got.as_bytes()), "{:02x?}", got.as_bytes());
        let aes = octetstring2key(EncryptionType::Aes256CtsHmacSha196, z).unwrap();
        assert_eq!(aes.as_bytes().len(), 32);
        assert_eq!(&aes.as_bytes()[..20], &stream[..20]);
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
}
