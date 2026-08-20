//! RFC 3961 §5.3 PRF and RFC 4402 PRF+.

use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha384};
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
        | EncryptionType::Des3CbcSha1
        | EncryptionType::Camellia128CtsCmac
        | EncryptionType::Camellia256CtsCmac => prf_aes_sha1(key, input),
        EncryptionType::Aes128CtsHmacSha256128 | EncryptionType::Aes256CtsHmacSha384192 => {
            prf_rfc8009(key, input)
        }
        EncryptionType::Rc4Hmac => {
            hmac_digest(EncryptionType::Aes128CtsHmacSha196, key.as_bytes(), input)
        }
    }
}

/// RFC 4402 PRF+: concatenate `PRF(K, S | i)` until `len` octets.
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
        let mut input = Vec::with_capacity(seed.len() + 1);
        input.extend_from_slice(seed);
        input.push(i);
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
    let mut dk = dk_rfc3961(key.as_bytes(), b"prf")?;
    let out = if key.etype().key_len() == 24 {
        let mut padded = tmp1.to_vec();
        while padded.len() % 8 != 0 {
            padded.push(0);
        }
        let iv8 = [0u8; 8];
        crate::weak::des3_cbc_encrypt(&dk, iv8, &padded)
    } else {
        let iv = [0u8; BLOCK];
        cts::encrypt(&dk, &iv, &tmp1)
    };
    dk.zeroize();
    out
}

fn prf_rfc8009(key: &ProtocolKey, input: &[u8]) -> Result<Vec<u8>, Error> {
    let (hash_out, k_bits) = match key.etype() {
        EncryptionType::Aes128CtsHmacSha256128 => {
            let mut h = Sha256::new();
            h.update(input);
            (h.finalize().to_vec(), 128u32)
        }
        EncryptionType::Aes256CtsHmacSha384192 => {
            let mut h = Sha384::new();
            h.update(input);
            (h.finalize().to_vec(), 192u32)
        }
        _ => return Err(Error::UnsupportedEtype(key.etype().to_iana())),
    };
    kdf_hmac_sha2(key.etype(), key.as_bytes(), b"prf", Some(&hash_out), k_bits)
}
