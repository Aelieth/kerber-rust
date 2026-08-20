//! RFC 3961 DK and RFC 8009 KDF-HMAC-SHA2.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha384};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::cts::{self, BLOCK};
use crate::error::Error;
use crate::etype::EncryptionType;
use crate::nfold::nfold;

/// RFC 3961 DR: encrypt the n-folded constant in a loop until `out_len` bytes
/// are produced. AES random-to-key is the identity, so DK = DR for these etypes.
pub(crate) fn dk_rfc3961(key: &[u8], constant: &[u8]) -> Result<Vec<u8>, Error> {
    let k = key.len();
    let folded = if constant.len() == BLOCK {
        constant.to_vec()
    } else {
        nfold(constant, BLOCK)?
    };
    let mut block = [0u8; BLOCK];
    block.copy_from_slice(&folded);
    let mut out = Vec::with_capacity(k);
    while out.len() < k {
        block = cts::encrypt_block(key, &block)?;
        let need = (k - out.len()).min(BLOCK);
        out.extend_from_slice(&block[..need]);
    }
    Ok(out)
}

/// RFC 8009 KDF-HMAC-SHA2. `k_bits` is L in SP 800-108 (output length in bits).
pub(crate) fn kdf_hmac_sha2(
    etype: EncryptionType,
    key: &[u8],
    label: &[u8],
    context: Option<&[u8]>,
    k_bits: u32,
) -> Result<Vec<u8>, Error> {
    let k_len = (k_bits / 8) as usize;
    let mut msg = Vec::with_capacity(4 + label.len() + 1 + context.map_or(0, <[u8]>::len) + 4);
    msg.extend_from_slice(&1u32.to_be_bytes());
    msg.extend_from_slice(label);
    msg.push(0x00);
    if let Some(ctx) = context {
        msg.extend_from_slice(ctx);
    }
    msg.extend_from_slice(&k_bits.to_be_bytes());

    let mut mac = hmac_digest(etype, key, &msg)?;
    if mac.len() > k_len {
        let mut tail = mac.split_off(k_len);
        tail.zeroize();
    }
    Ok(mac)
}

pub(crate) fn hmac_digest(
    etype: EncryptionType,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    match etype {
        EncryptionType::Aes128CtsHmacSha196 | EncryptionType::Aes256CtsHmacSha196 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        EncryptionType::Aes128CtsHmacSha256128 => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        EncryptionType::Aes256CtsHmacSha384192 => {
            let mut mac =
                Hmac::<Sha384>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        EncryptionType::Des3CbcSha1
        | EncryptionType::Rc4Hmac
        | EncryptionType::Camellia128CtsCmac
        | EncryptionType::Camellia256CtsCmac => Err(Error::UnsupportedEtype(etype.to_iana())),
    }
}

pub(crate) fn hmac_truncated(
    etype: EncryptionType,
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut mac = hmac_digest(etype, key, data)?;
    let n = etype.hmac_output_len();
    if mac.len() > n {
        let mut tail = mac.split_off(n);
        tail.zeroize();
    }
    Ok(mac)
}

pub(crate) fn mac_verify(got: &[u8], expected: &[u8]) -> Result<(), Error> {
    if got.len() != expected.len() || !bool::from(got.ct_eq(expected)) {
        return Err(Error::Integrity);
    }
    Ok(())
}

/// Three keys derived for one usage: Kc, Ke, Ki.
pub struct DerivedKeys {
    /// Checksum key.
    pub kc: Vec<u8>,
    /// Encryption key.
    pub ke: Vec<u8>,
    /// Integrity key.
    pub ki: Vec<u8>,
}

pub(crate) type UsageKeys = DerivedKeys;

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        self.kc.zeroize();
        self.ke.zeroize();
        self.ki.zeroize();
    }
}

/// Derive Kc, Ke, and Ki for `usage` from a protocol key (MIT t_derive KATs).
///
/// # Errors
///
/// Returns derivation failures.
pub fn derive_keys(
    key: &crate::key::ProtocolKey,
    usage: crate::etype::KeyUsage,
) -> Result<DerivedKeys, Error> {
    derive_usage_keys(key.etype(), key.as_bytes(), usage)
}

pub(crate) fn derive_usage_keys(
    etype: EncryptionType,
    base: &[u8],
    usage: crate::etype::KeyUsage,
) -> Result<UsageKeys, Error> {
    if etype.is_rfc8009() {
        let kc = kdf_hmac_sha2(
            etype,
            base,
            &usage.derivation_constant(0x99),
            None,
            (etype.mac_key_len() * 8) as u32,
        )?;
        let ke = kdf_hmac_sha2(
            etype,
            base,
            &usage.derivation_constant(0xAA),
            None,
            (etype.key_len() * 8) as u32,
        )?;
        let ki = kdf_hmac_sha2(
            etype,
            base,
            &usage.derivation_constant(0x55),
            None,
            (etype.mac_key_len() * 8) as u32,
        )?;
        Ok(UsageKeys { kc, ke, ki })
    } else {
        let kc = dk_rfc3961(base, &usage.derivation_constant(0x99))?;
        let ke = dk_rfc3961(base, &usage.derivation_constant(0xAA))?;
        let ki = dk_rfc3961(base, &usage.derivation_constant(0x55))?;
        Ok(UsageKeys { kc, ke, ki })
    }
}
