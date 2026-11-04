use sha1::{Digest, Sha1};
use zeroize::{Zeroize, Zeroizing};

use crate::cts::{self, BLOCK};
use crate::derive::{dk_rfc3961, hmac_digest, kdf_hmac_sha2};
use crate::error::Error;
use crate::etype::EncryptionType;
use crate::key::ProtocolKey;
use crate::wipe::Wiped;

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

// MIT: `krb5_c_derive_prfplus` (lib/crypto/krb/cf2.c:81-121)
pub fn derive_prfplus(key: &ProtocolKey, input: &[u8]) -> Result<ProtocolKey, Error> {
    derive_prfplus_enctype(key, input, key.etype())
}

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
    let kp = Wiped(crate::weak::dk_camellia(key.as_bytes(), b"prf")?);
    crate::weak::cmac_camellia(&kp, input)
}

fn prf_rfc8009(key: &ProtocolKey, input: &[u8]) -> Result<Vec<u8>, Error> {
    let k_bits = match key.etype() {
        EncryptionType::Aes128CtsHmacSha256128 => 256u32,
        EncryptionType::Aes256CtsHmacSha384192 => 384u32,
        _ => return Err(Error::UnsupportedEtype(key.etype().to_iana())),
    };
    kdf_hmac_sha2(key.etype(), key.as_bytes(), b"prf", Some(input), k_bits)
}
