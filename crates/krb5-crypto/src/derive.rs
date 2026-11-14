use hmac::{Hmac, KeyInit, Mac};
use krb5_s2k::Sha2Kdf;
use sha1::Sha1;
use sha2::{Sha256, Sha384};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::Error;
use crate::etype::EncryptionType;
use crate::wipe::wipe;

pub(crate) fn bits_u32(nbytes: usize) -> u32 {
    u32::try_from(nbytes.saturating_mul(8)).unwrap_or(u32::MAX)
}

pub(crate) use krb5_s2k::dk_rfc3961;

pub(crate) fn kdf_hmac_sha2(
    etype: EncryptionType,
    key: &[u8],
    label: &[u8],
    context: Option<&[u8]>,
    k_bits: u32,
) -> Result<Vec<u8>, Error> {
    let hash = match etype {
        EncryptionType::Aes128CtsHmacSha256128 => Sha2Kdf::Sha256,
        EncryptionType::Aes256CtsHmacSha384192 => Sha2Kdf::Sha384,
        _ => return Err(Error::UnsupportedEtype(etype.to_iana())),
    };
    Ok(krb5_s2k::kdf_hmac_sha2(hash, key, label, context, k_bits)?)
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
        mac[n..].zeroize();
        mac.truncate(n);
    }
    Ok(mac)
}

pub(crate) fn mac_verify(got: &[u8], expected: &[u8]) -> Result<(), Error> {
    if got.len() != expected.len() || !bool::from(got.ct_eq(expected)) {
        return Err(Error::Integrity);
    }
    Ok(())
}

pub struct DerivedKeys {
    pub kc: Vec<u8>,
    pub ke: Vec<u8>,
    pub ki: Vec<u8>,
}

pub(crate) type UsageKeys = DerivedKeys;

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        wipe(&mut self.kc);
        wipe(&mut self.ke);
        wipe(&mut self.ki);
    }
}

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
            bits_u32(etype.mac_key_len()),
        )?;
        let ke = kdf_hmac_sha2(
            etype,
            base,
            &usage.derivation_constant(0xAA),
            None,
            bits_u32(etype.key_len()),
        )?;
        let ki = kdf_hmac_sha2(
            etype,
            base,
            &usage.derivation_constant(0x55),
            None,
            bits_u32(etype.mac_key_len()),
        )?;
        Ok(UsageKeys { kc, ke, ki })
    } else if etype.is_camellia() {
        let kc = crate::weak::dk_camellia(base, &usage.derivation_constant(0x99))?;
        let ke = crate::weak::dk_camellia(base, &usage.derivation_constant(0xAA))?;
        let ki = crate::weak::dk_camellia(base, &usage.derivation_constant(0x55))?;
        Ok(UsageKeys { kc, ke, ki })
    } else if etype == EncryptionType::Des3CbcSha1 {
        // MIT: `krb5int_derive_key` (lib/crypto/krb/derive.c:134-174)
        let kc = crate::weak::dk_des3(base, &usage.derivation_constant(0x99))?;
        let ke = crate::weak::dk_des3(base, &usage.derivation_constant(0xAA))?;
        let ki = crate::weak::dk_des3(base, &usage.derivation_constant(0x55))?;
        Ok(UsageKeys { kc, ke, ki })
    } else {
        let kc = dk_rfc3961(base, &usage.derivation_constant(0x99))?;
        let ke = dk_rfc3961(base, &usage.derivation_constant(0xAA))?;
        let ki = dk_rfc3961(base, &usage.derivation_constant(0x55))?;
        Ok(UsageKeys { kc, ke, ki })
    }
}
