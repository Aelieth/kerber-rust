//! MIT 1.22.2 SPAKE2 (draft-ietf-kitten-krb-spake-preauth) on P-256.

use sha2::{Digest as Sha2Digest, Sha256};
use zeroize::Zeroize;

use crate::error::Error;
use crate::key::ProtocolKey;
use crate::prf::prf_plus;
use crate::{krb_fx_cf2, p256_generate};

/// SPAKE group P-256 (IANA / MIT).
pub const SPAKE_GROUP_P256: i32 = 2;

/// Compressed P-256 M from the SPAKE IANA registry (MIT `iana.c`).
pub const SPAKE_M: [u8; 33] = [
    0x02, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2,
    0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1,
    0x2f,
];
/// Compressed P-256 N from the SPAKE IANA registry.
pub const SPAKE_N: [u8; 33] = [
    0x03, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77,
    0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b,
    0x49,
];

/// MIT `derive_wbytes`: PRF+(`ikey`, `"SPAKEsecret" || group-id`).
///
/// # Errors
///
/// PRF+ failures.
pub fn spake_wbytes(ikey: &ProtocolKey, group: i32) -> Result<Vec<u8>, Error> {
    let mut seed = b"SPAKEsecret".to_vec();
    seed.extend_from_slice(&group.to_be_bytes());
    prf_plus(ikey, &seed, 32)
}

/// IANA compressed M (33 octets).
#[must_use]
pub fn spake_m_bytes() -> &'static [u8] {
    &SPAKE_M
}

/// IANA compressed N (33 octets).
#[must_use]
pub fn spake_n_bytes() -> &'static [u8] {
    &SPAKE_N
}

/// Decode a compressed P-256 SPAKE element. Hostile input returns [`Error::Integrity`].
///
/// # Errors
///
/// Invalid encoding or a point not on the curve.
pub fn spake_decode_point(bytes: &[u8]) -> Result<(), Error> {
    decode_compressed(bytes).map(|_| ())
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

fn scalar_from_wbytes(wbytes: &[u8]) -> Result<p256::Scalar, Error> {
    use p256::U256;
    use p256::elliptic_curve::ff::Field;
    use p256::elliptic_curve::ops::Reduce;
    if wbytes.len() != 32 {
        return Err(Error::Integrity);
    }
    let n = U256::from_be_slice(wbytes);
    let s: p256::Scalar = Reduce::reduce(n);
    if bool::from(s.is_zero()) {
        return Err(Error::Integrity);
    }
    Ok(s)
}

fn decode_compressed(bytes: &[u8]) -> Result<p256::ProjectivePoint, Error> {
    use p256::elliptic_curve::sec1::FromEncodedPoint;
    use p256::{AffinePoint, EncodedPoint, ProjectivePoint};
    let ep = EncodedPoint::from_bytes(bytes).map_err(|_| Error::Integrity)?;
    let aff = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep))
        .ok_or(Error::Integrity)?;
    Ok(ProjectivePoint::from(aff))
}

fn encode_compressed(p: p256::ProjectivePoint) -> Vec<u8> {
    use p256::AffinePoint;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    AffinePoint::from(p)
        .to_encoded_point(true)
        .as_bytes()
        .to_vec()
}

fn spake_m() -> Result<p256::ProjectivePoint, Error> {
    decode_compressed(&SPAKE_M)
}

fn spake_n() -> Result<p256::ProjectivePoint, Error> {
    decode_compressed(&SPAKE_N)
}

/// SPAKE2 public share as a compressed P-256 point (MIT `elem_len` = 33).
///
/// KDC (`server`) computes `xG + wM`; client computes `yG + wN`.
///
/// # Errors
///
/// Invalid scalars.
pub fn spake_public(w: &[u8; 32], secret: &[u8; 32], server: bool) -> Result<Vec<u8>, Error> {
    spake_public_wbytes(w, secret, server)
}

/// Like [`spake_public`] with unreduced MIT `wbytes`.
///
/// # Errors
///
/// Invalid scalars.
pub fn spake_public_wbytes(
    wbytes: &[u8],
    secret: &[u8; 32],
    server: bool,
) -> Result<Vec<u8>, Error> {
    use p256::ProjectivePoint;
    let ws = scalar_from_wbytes(wbytes)?;
    let xs = scalar_from_bytes32(secret)?;
    // MIT: KDC uses M, client uses N.
    let mn = if server { spake_m()? } else { spake_n()? };
    Ok(encode_compressed(ProjectivePoint::GENERATOR * xs + mn * ws))
}

/// SPAKE2 shared element (compressed, 33 octets) matching MIT `group_result`.
///
/// KDC: `x(S - wN)`; client: `y(T - wM)`.
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
    let elem = spake_result_wbytes(w, secret, peer_public, we_are_server)?;
    let mut x = [0u8; 32];
    if elem.len() == 33 {
        x.copy_from_slice(&elem[1..]);
    } else if elem.len() == 32 {
        x.copy_from_slice(&elem);
    } else {
        return Err(Error::Integrity);
    }
    Ok(x)
}

/// Compressed SPAKE result (33 bytes) used as MIT `spakeresult`.
///
/// # Errors
///
/// Invalid points or scalars.
pub fn spake_result_wbytes(
    wbytes: &[u8],
    secret: &[u8; 32],
    peer_public: &[u8],
    we_are_server: bool,
) -> Result<Vec<u8>, Error> {
    let ws = scalar_from_wbytes(wbytes)?;
    let xs = scalar_from_bytes32(secret)?;
    let peer = decode_compressed(peer_public)?;
    // MIT: KDC subtracts N; client subtracts M.
    let mn = if we_are_server {
        spake_n()?
    } else {
        spake_m()?
    };
    Ok(encode_compressed((peer - mn * ws) * xs))
}

/// Transcript hash: `SHA-256(thash || data1 || data2)` (MIT `update_thash`).
#[must_use]
pub fn spake_thash_update(thash: &[u8], data1: &[u8], data2: &[u8]) -> [u8; 32] {
    let mut h = <Sha256 as Sha2Digest>::new();
    Sha2Digest::update(&mut h, thash);
    Sha2Digest::update(&mut h, data1);
    Sha2Digest::update(&mut h, data2);
    Sha2Digest::finalize(h).into()
}

/// MIT `derive_key`: K'[n] = CF2(ikey, "SPAKE", random-to-key(H), "keyderiv").
///
/// # Errors
///
/// PRF/CF2/key-length failures.
pub fn spake_derive_key(
    ikey: &ProtocolKey,
    group: i32,
    wbytes: &[u8],
    spakeresult: &[u8],
    thash: &[u8],
    der_req: &[u8],
    n: u32,
) -> Result<ProtocolKey, Error> {
    let seedlen = ikey.etype().key_len();
    let hashlen = 32usize;
    let nblocks = seedlen.div_ceil(hashlen);
    let mut seed = vec![0u8; nblocks * hashlen];
    for i in 0..nblocks {
        let bcount = u8::try_from(i + 1).unwrap_or(u8::MAX);
        let mut h = <Sha256 as Sha2Digest>::new();
        Sha2Digest::update(&mut h, b"SPAKEkey");
        Sha2Digest::update(&mut h, group.to_be_bytes());
        Sha2Digest::update(&mut h, ikey.etype().to_iana().to_be_bytes());
        Sha2Digest::update(&mut h, wbytes);
        Sha2Digest::update(&mut h, spakeresult);
        Sha2Digest::update(&mut h, thash);
        Sha2Digest::update(&mut h, der_req);
        Sha2Digest::update(&mut h, n.to_be_bytes());
        Sha2Digest::update(&mut h, [bcount]);
        let out = Sha2Digest::finalize(h);
        seed[i * hashlen..i * hashlen + hashlen].copy_from_slice(&out);
    }
    seed.truncate(seedlen);
    let hkey = ProtocolKey::from_bytes(ikey.etype(), &seed)?;
    seed.zeroize();
    krb_fx_cf2(ikey, &hkey, b"SPAKE", b"keyderiv")
}

/// Generate a KDC SPAKE keypair (compressed public, 32-byte secret).
///
/// # Errors
///
/// RNG or curve failures.
pub fn spake_kdc_keygen(wbytes: &[u8]) -> Result<([u8; 32], Vec<u8>), Error> {
    let kp = p256_generate()?;
    let pub_y = spake_public_wbytes(wbytes, &kp.secret, true)?;
    Ok((kp.secret, pub_y))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::etype::EncryptionType;
    use crate::ops::string_to_key;
    use crate::p256_generate;

    fn test_key() -> ProtocolKey {
        string_to_key(
            EncryptionType::Aes256CtsHmacSha196,
            b"userpassword",
            b"KERBER.TESTuser",
            Some(&4096u32.to_be_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn spake_compressed_agrees() {
        let ikey = test_key();
        let w = spake_wbytes(&ikey, SPAKE_GROUP_P256).unwrap();
        let client = p256_generate().unwrap();
        let server = p256_generate().unwrap();
        let x = spake_public_wbytes(&w, &client.secret, false).unwrap();
        let y = spake_public_wbytes(&w, &server.secret, true).unwrap();
        assert_eq!(x.len(), 33);
        assert_eq!(y.len(), 33);
        let c = spake_result_wbytes(&w, &client.secret, &y, false).unwrap();
        let s = spake_result_wbytes(&w, &server.secret, &x, true).unwrap();
        assert_eq!(c, s);
        assert_eq!(c.len(), 33);
    }

    #[test]
    fn spake_k0_uses_cf2_not_x_coordinate() {
        let ikey = test_key();
        let w = spake_wbytes(&ikey, SPAKE_GROUP_P256).unwrap();
        let client = p256_generate().unwrap();
        let server = p256_generate().unwrap();
        let x = spake_public_wbytes(&w, &client.secret, false).unwrap();
        let y = spake_public_wbytes(&w, &server.secret, true).unwrap();
        let result = spake_result_wbytes(&w, &server.secret, &x, true).unwrap();
        let thash = [0u8; 32];
        let der_req = b"fake-kdc-req-body";
        let k0 =
            spake_derive_key(&ikey, SPAKE_GROUP_P256, &w, &result, &thash, der_req, 0).unwrap();
        assert_ne!(k0.as_bytes(), &result[1..]);
        let k0b =
            spake_derive_key(&ikey, SPAKE_GROUP_P256, &w, &result, &thash, der_req, 0).unwrap();
        assert_eq!(k0.as_bytes(), k0b.as_bytes());
        let k1 =
            spake_derive_key(&ikey, SPAKE_GROUP_P256, &w, &result, &thash, der_req, 1).unwrap();
        assert_ne!(k0.as_bytes(), k1.as_bytes());
        let _ = y;
        let _ = client;
    }

    #[test]
    fn thash_starts_from_zeros() {
        let z = [0u8; 32];
        let a = spake_thash_update(&z, b"abc", b"def");
        let b = spake_thash_update(&z, b"abc", b"def");
        assert_eq!(a, b);
        let c = spake_thash_update(&z, b"abc", b"");
        assert_ne!(a, c);
    }
}
