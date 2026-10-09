//! RFC 3961 §5.3 PRF and RFC 6113 PRF+.
//!
//! PRF is one block for the key's etype. PRF+ concatenates blocks until
//! the requested length is met. It wipes each PRF output block on every
//! return, and each counter‖seed input once its block is made; the caller
//! owns the result.

use sha1::{Digest, Sha1};
use zeroize::{Zeroize, Zeroizing};

use crate::cts::{self, BLOCK};
use crate::derive::{dk_rfc3961, hmac_digest, kdf_hmac_sha2};
use crate::error::Error;
use crate::etype::EncryptionType;
use crate::key::ProtocolKey;
use crate::wipe::Wiped;

/// RFC 3961 / RFC 8009 pseudo-random function.
///
/// # Errors
///
/// None: no PRF step can fail on a [`ProtocolKey`], whose length always matches its etype.
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
/// [`Error::InvalidParams`] when `len` is 0.
pub fn prf_plus(key: &ProtocolKey, seed: &[u8], len: usize) -> Result<Vec<u8>, Error> {
    if len == 0 {
        return Err(Error::InvalidParams);
    }
    let mut out = Wiped(Vec::with_capacity(len));
    let mut i = 1u8;
    while out.len() < len {
        let mut input = Vec::with_capacity(1 + seed.len());
        input.push(i);
        input.extend_from_slice(seed);
        let block = Wiped(prf(key, &input)?);
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
    Ok(std::mem::take(&mut out.0))
}

/// MIT `krb5_c_derive_prfplus` (`cf2.c:82-121`): PRF+ of `keybytes`, then rand2key.
///
/// # Errors
///
/// None: PRF+ returns exactly `keybytes()` octets for `key`'s etype (never 0), so the des3
/// length check and [`ProtocolKey::from_bytes`] always pass.
pub fn derive_prfplus(key: &ProtocolKey, input: &[u8]) -> Result<ProtocolKey, Error> {
    derive_prfplus_enctype(key, input, key.etype())
}

/// MIT `krb5_c_derive_prfplus` with an explicit output enctype.
/// MIT `krb5_c_derive_prfplus` (`cf2.c:93-93`): the output enctype is the one given, or the
/// input key's when it is `ENCTYPE_NULL`.
///
/// # Errors
///
/// None: PRF+ returns exactly `enctype.keybytes()` octets (never 0), so the des3 length check
/// and [`ProtocolKey::from_bytes`] always pass.
pub fn derive_prfplus_enctype(
    key: &ProtocolKey,
    input: &[u8],
    enctype: EncryptionType,
) -> Result<ProtocolKey, Error> {
    let rnd = Wiped(prf_plus(key, input, enctype.keybytes())?);
    if enctype == EncryptionType::Des3CbcSha1 {
        if rnd.len() != 21 {
            return Err(Error::InvalidKeyLength);
        }
        let raw = Zeroizing::new(crate::weak::des3_random_to_key(&rnd));
        ProtocolKey::from_bytes(enctype, &*raw)
    } else {
        ProtocolKey::from_bytes(enctype, &rnd)
    }
}

fn prf_aes_sha1(key: &ProtocolKey, input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut hasher = Sha1::new();
    hasher.update(input);
    let tmp1 = hasher.finalize();
    // RFC 3961 §5.3 / MIT `prf_dk.c`: truncate the hash to the closest
    // multiple of the cipher block size, then encrypt.
    if key.etype() == EncryptionType::Des3CbcSha1 {
        let dk = Wiped(crate::weak::dk_des3(key.as_bytes(), b"prf")?);
        let trunc = (tmp1.len() / 8) * 8;
        crate::weak::des3_cbc_encrypt(&dk, [0u8; 8], &tmp1[..trunc])
    } else {
        let dk = Wiped(dk_rfc3961(key.as_bytes(), b"prf")?);
        let trunc = (tmp1.len() / BLOCK) * BLOCK;
        let mut block = [0u8; BLOCK];
        block.copy_from_slice(&tmp1[..trunc]);
        Ok(cts::encrypt_block(&dk, &block)?.to_vec())
    }
}

fn prf_camellia(key: &ProtocolKey, input: &[u8]) -> Result<Vec<u8>, Error> {
    // RFC 6803 §6: Kp = KDF-FEEDBACK-CMAC(protocol-key, "prf"); PRF = CMAC(Kp, octet-string).
    let kp = Wiped(crate::weak::dk_camellia(key.as_bytes(), b"prf")?);
    crate::weak::cmac_camellia(&kp, input)
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
        let derived = derive_prfplus(&key, b"pepper").unwrap();
        let direct = prf_plus(&key, b"pepper", key.etype().key_len()).unwrap();
        assert_eq!(derived.as_bytes(), direct.as_slice());
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
