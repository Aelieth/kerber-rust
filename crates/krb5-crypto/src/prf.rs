//! RFC 3961 §5.3 PRF and RFC 6113 PRF+.

use sha1::{Digest, Sha1};
use zeroize::Zeroize;

use crate::cts::{self, BLOCK};
use crate::derive::{dk_rfc3961, hmac_digest, kdf_hmac_sha2};
use crate::error::Error;
use crate::etype::EncryptionType;
use crate::key::ProtocolKey;

/// RFC 3961 / RFC 8009 pseudo-random function.
///
/// # Errors
///
/// Returns crypto failures from key derivation or the underlying HMAC/cipher.
pub fn prf(key: &ProtocolKey, input: &[u8]) -> Result<Vec<u8>, Error> {
    match key.etype() {
        EncryptionType::Aes128CtsHmacSha196
        | EncryptionType::Aes256CtsHmacSha196
        | EncryptionType::Des3CbcSha1 => prf_aes_sha1(key, input),
        EncryptionType::Camellia128CtsCmac | EncryptionType::Camellia256CtsCmac => {
            prf_camellia(key, input)
        }
        EncryptionType::Aes128CtsHmacSha256128 | EncryptionType::Aes256CtsHmacSha384192 => {
            prf_rfc8009(key, input)
        }
        EncryptionType::Rc4Hmac => {
            hmac_digest(EncryptionType::Aes128CtsHmacSha196, key.as_bytes(), input)
        }
    }
}

/// RFC 6113 PRF+: concatenate `PRF(K, i || S)` until `len` octets.
///
/// The counter is a single octet **prepended** to the seed (RFC 6113 §5.1,
/// not RFC 4402's append).
///
/// # Errors
///
/// Returns PRF failures or [`Error::InvalidParams`] when `len` is 0.
pub fn prf_plus(key: &ProtocolKey, seed: &[u8], len: usize) -> Result<Vec<u8>, Error> {
    if len == 0 {
        return Err(Error::InvalidParams);
    }
    let mut out = Vec::with_capacity(len);
    let mut i = 1u8;
    while out.len() < len {
        let mut input = Vec::with_capacity(1 + seed.len());
        input.push(i);
        input.extend_from_slice(seed);
        let block = prf(key, &input)?;
        input.zeroize();
        let need = (len - out.len()).min(block.len());
        out.extend_from_slice(&block[..need]);
        i = i.saturating_add(1);
        if i == 0 {
            break;
        }
    }
    if out.len() < len {
        return Err(Error::InvalidParams);
    }
    Ok(out)
}

fn prf_aes_sha1(key: &ProtocolKey, input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut hasher = Sha1::new();
    hasher.update(input);
    let tmp1 = hasher.finalize();
    // RFC 3961 §5.3 / MIT `prf_dk.c`: truncate the hash to the closest
    // multiple of the cipher block size, then encrypt.
    if key.etype() == EncryptionType::Des3CbcSha1 {
        let mut dk = crate::weak::dk_des3(key.as_bytes(), b"prf")?;
        let trunc = (tmp1.len() / 8) * 8;
        let c = crate::weak::des3_cbc_encrypt(&dk, [0u8; 8], &tmp1[..trunc])?;
        dk.zeroize();
        Ok(c)
    } else {
        let mut dk = dk_rfc3961(key.as_bytes(), b"prf")?;
        let trunc = (tmp1.len() / BLOCK) * BLOCK;
        let mut block = [0u8; BLOCK];
        block.copy_from_slice(&tmp1[..trunc]);
        let enc = cts::encrypt_block(&dk, &block)?;
        dk.zeroize();
        Ok(enc.to_vec())
    }
}

fn prf_camellia(key: &ProtocolKey, input: &[u8]) -> Result<Vec<u8>, Error> {
    // RFC 6803 §6: Kp = KDF-FEEDBACK-CMAC(protocol-key, "prf"); PRF = CMAC(Kp, octet-string).
    let mut kp = crate::weak::dk_camellia(key.as_bytes(), b"prf")?;
    let out = crate::weak::cmac_camellia(&kp, input)?;
    kp.zeroize();
    Ok(out)
}

fn prf_rfc8009(key: &ProtocolKey, input: &[u8]) -> Result<Vec<u8>, Error> {
    // RFC 8009 §5: PRF = KDF-HMAC-SHA2(key, "prf", octet-string, k)
    // with k = 256 (aes128-sha2) or 384 (aes256-sha2). The octet-string
    // is the KDF context; it is not pre-hashed.
    let k_bits = match key.etype() {
        EncryptionType::Aes128CtsHmacSha256128 => 256u32,
        EncryptionType::Aes256CtsHmacSha384192 => 384u32,
        _ => return Err(Error::UnsupportedEtype(key.etype().to_iana())),
    };
    kdf_hmac_sha2(key.etype(), key.as_bytes(), b"prf", Some(input), k_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::ProtocolKey;

    #[test]
    fn aes_sha1_prf_is_one_block() {
        let key =
            ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x11u8; 32]).unwrap();
        let out = prf(&key, b"seed").unwrap();
        assert_eq!(out.len(), 16, "AES-SHA1 PRF truncates to the AES block");
    }

    #[test]
    fn rfc8009_prf_is_full_hash() {
        let k128 =
            ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha256128, &[0x22u8; 16]).unwrap();
        assert_eq!(prf(&k128, b"x").unwrap().len(), 32);
        let k256 =
            ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha384192, &[0x33u8; 32]).unwrap();
        assert_eq!(prf(&k256, b"x").unwrap().len(), 48);
    }

    #[test]
    fn prf_plus_prepends_counter() {
        let key =
            ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x44u8; 32]).unwrap();
        let mut seed1 = vec![1u8];
        seed1.extend_from_slice(b"pepper");
        let first = prf(&key, &seed1).unwrap();
        let plus = prf_plus(&key, b"pepper", first.len()).unwrap();
        assert_eq!(plus, first);
        let mut appended = b"pepper".to_vec();
        appended.push(1);
        let wrong = prf(&key, &appended).unwrap();
        assert_ne!(plus, wrong, "counter must be prepended, not appended");
    }

    #[test]
    fn camellia_prf_uses_camellia_not_aes() {
        let bytes = [0x5au8; 16];
        let aes = ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &bytes).unwrap();
        let cam = ProtocolKey::from_bytes(EncryptionType::Camellia128CtsCmac, &bytes).unwrap();
        let a = prf(&aes, b"seed").unwrap();
        let c = prf(&cam, b"seed").unwrap();
        assert_eq!(a.len(), 16);
        assert_eq!(c.len(), 16);
        assert_ne!(
            a, c,
            "Camellia PRF must not share AES ECB with aes128-cts-hmac-sha1-96"
        );
    }
}
