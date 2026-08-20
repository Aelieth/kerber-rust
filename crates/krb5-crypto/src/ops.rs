//! Public RFC 3961 operations: string-to-key, encrypt, decrypt, checksum.

use std::time::Instant;

use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Sha256, Sha384};
use zeroize::Zeroize;

use crate::cts::{self, BLOCK};
use crate::derive::{self, derive_usage_keys, hmac_truncated, mac_verify};
use crate::error::Error;
use crate::etype::{EncryptionType, KeyUsage};
use crate::key::ProtocolKey;

/// Reject iteration counts above this. RFC 3962 test vectors use at most 1200;
/// RFC 8009 defaults to 32768. Zero (RFC 3962 = 2^32) is refused.
const MAX_ITERATIONS: u32 = 5_000_000;

fn parse_iterations(etype: EncryptionType, params: Option<&[u8]>) -> Result<u32, Error> {
    match params {
        None | Some([]) => Ok(etype.default_iterations()),
        Some(p) if p.len() == 4 => {
            let n = u32::from_be_bytes(p.try_into().map_err(|_| Error::InvalidParams)?);
            if n == 0 {
                return Err(Error::InvalidParams);
            }
            if n > MAX_ITERATIONS {
                return Err(Error::IterationLimit);
            }
            Ok(n)
        }
        Some(_) => Err(Error::InvalidParams),
    }
}

/// Derive a long-term key from a passphrase and salt.
///
/// `params` is the 4-octet big-endian iteration count, or `None` for the
/// etype default (4096 for RFC 3962, 32768 for RFC 8009).
///
/// # Errors
///
/// Returns [`Error::InvalidParams`] or [`Error::IterationLimit`] when the
/// iteration count cannot be used.
pub fn string_to_key(
    etype: EncryptionType,
    password: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
    params: Option<&[u8]>,
) -> Result<ProtocolKey, Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let started = Instant::now();
    let result = string_to_key_inner(etype, password.as_ref(), salt.as_ref(), params);
    emit(
        krb5_log::events::CRYPTO_STRING_TO_KEY,
        &correlation_id,
        etype,
        None,
        started,
        result.as_ref().err(),
    );
    result
}

fn string_to_key_inner(
    etype: EncryptionType,
    password: &[u8],
    salt: &[u8],
    params: Option<&[u8]>,
) -> Result<ProtocolKey, Error> {
    let iter = parse_iterations(etype, params)?;
    let key_len = etype.key_len();
    let mut tkey = vec![0u8; key_len];

    if etype.is_rfc8009() {
        let mut saltp = Vec::new();
        saltp.extend_from_slice(
            etype
                .enctype_name()
                .ok_or(Error::UnsupportedEtype(etype.to_iana()))?
                .as_bytes(),
        );
        saltp.push(0x00);
        saltp.extend_from_slice(salt);
        match etype {
            EncryptionType::Aes128CtsHmacSha256128 => {
                pbkdf2_hmac::<Sha256>(password, &saltp, iter, &mut tkey);
            }
            EncryptionType::Aes256CtsHmacSha384192 => {
                pbkdf2_hmac::<Sha384>(password, &saltp, iter, &mut tkey);
            }
            EncryptionType::Aes128CtsHmacSha196 | EncryptionType::Aes256CtsHmacSha196 => {
                return Err(Error::UnsupportedEtype(etype.to_iana()));
            }
        }
        let base = derive::kdf_hmac_sha2(etype, &tkey, b"kerberos", None, (key_len * 8) as u32)?;
        tkey.zeroize();
        ProtocolKey::from_bytes(etype, &base)
    } else {
        pbkdf2_hmac::<Sha1>(password, salt, iter, &mut tkey);
        let base = derive::dk_rfc3961(&tkey, b"kerberos")?;
        tkey.zeroize();
        ProtocolKey::from_bytes(etype, &base)
    }
}

/// Encrypt `plaintext` under `key` and `usage` with a random confounder.
///
/// # Errors
///
/// Returns [`Error::Rng`] when the CSPRNG fails, or key/etype errors.
pub fn encrypt(key: &ProtocolKey, usage: KeyUsage, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut conf = [0u8; BLOCK];
    getrandom::getrandom(&mut conf).map_err(|_| Error::Rng)?;
    encrypt_with_confounder(key, usage, &conf, plaintext)
}

/// Encrypt with a caller-supplied 16-octet confounder.
///
/// Required for known-answer tests (RFC 8009 Appendix A). Production
/// callers should use [`encrypt`], which draws the confounder from the OS
/// CSPRNG.
///
/// # Errors
///
/// Returns [`Error::InvalidConfounder`] when `confounder` is not 16 octets.
pub fn encrypt_with_confounder(
    key: &ProtocolKey,
    usage: KeyUsage,
    confounder: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let started = Instant::now();
    let result = encrypt_inner(key, usage, confounder, plaintext);
    emit(
        krb5_log::events::CRYPTO_ENCRYPT,
        &correlation_id,
        key.etype(),
        Some(usage),
        started,
        result.as_ref().err(),
    );
    result
}

fn encrypt_inner(
    key: &ProtocolKey,
    usage: KeyUsage,
    confounder: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    if confounder.len() != BLOCK {
        return Err(Error::InvalidConfounder);
    }
    let keys = derive_usage_keys(key.etype(), key.as_bytes(), usage)?;
    let iv = [0u8; BLOCK];
    let mut data = Vec::with_capacity(BLOCK + plaintext.len());
    data.extend_from_slice(confounder);
    data.extend_from_slice(plaintext);

    if key.etype().is_rfc8009() {
        let c = cts::encrypt(&keys.ke, &iv, &data)?;
        let mut hmac_input = Vec::with_capacity(BLOCK + c.len());
        hmac_input.extend_from_slice(&iv);
        hmac_input.extend_from_slice(&c);
        let h = hmac_truncated(key.etype(), &keys.ki, &hmac_input)?;
        let mut out = c;
        out.extend_from_slice(&h);
        Ok(out)
    } else {
        let c = cts::encrypt(&keys.ke, &iv, &data)?;
        let h = hmac_truncated(key.etype(), &keys.ki, &data)?;
        let mut out = c;
        out.extend_from_slice(&h);
        Ok(out)
    }
}

/// Decrypt `ciphertext` and return the plaintext with the confounder removed.
///
/// # Errors
///
/// Returns [`Error::Integrity`] or [`Error::CiphertextTooShort`] on failure.
/// The decrypted buffer is discarded when the HMAC does not match.
pub fn decrypt(key: &ProtocolKey, usage: KeyUsage, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let started = Instant::now();
    let result = decrypt_inner(key, usage, ciphertext);
    emit(
        krb5_log::events::CRYPTO_DECRYPT,
        &correlation_id,
        key.etype(),
        Some(usage),
        started,
        result.as_ref().err(),
    );
    result
}

fn decrypt_inner(key: &ProtocolKey, usage: KeyUsage, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let h = key.etype().hmac_output_len();
    if ciphertext.len() < BLOCK + h {
        return Err(Error::CiphertextTooShort);
    }
    let (c, mac) = ciphertext.split_at(ciphertext.len() - h);
    let keys = derive_usage_keys(key.etype(), key.as_bytes(), usage)?;
    let iv = [0u8; BLOCK];

    if key.etype().is_rfc8009() {
        let mut hmac_input = Vec::with_capacity(BLOCK + c.len());
        hmac_input.extend_from_slice(&iv);
        hmac_input.extend_from_slice(c);
        let expected = hmac_truncated(key.etype(), &keys.ki, &hmac_input)?;
        mac_verify(mac, &expected)?;
        let mut p = cts::decrypt(&keys.ke, &iv, c)?;
        if p.len() < BLOCK {
            return Err(Error::CiphertextTooShort);
        }
        let plain = p.split_off(BLOCK);
        Ok(plain)
    } else {
        let p = cts::decrypt(&keys.ke, &iv, c)?;
        let expected = hmac_truncated(key.etype(), &keys.ki, &p)?;
        mac_verify(mac, &expected)?;
        if p.len() < BLOCK {
            return Err(Error::CiphertextTooShort);
        }
        Ok(p[BLOCK..].to_vec())
    }
}

/// Keyed checksum (RFC 3961 `get_mic` / RFC 8009 section 6).
///
/// # Errors
///
/// Returns key-derivation errors.
pub fn checksum(key: &ProtocolKey, usage: KeyUsage, message: &[u8]) -> Result<Vec<u8>, Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let started = Instant::now();
    let result = checksum_inner(key, usage, message);
    emit(
        krb5_log::events::CRYPTO_CHECKSUM,
        &correlation_id,
        key.etype(),
        Some(usage),
        started,
        result.as_ref().err(),
    );
    result
}

fn checksum_inner(key: &ProtocolKey, usage: KeyUsage, message: &[u8]) -> Result<Vec<u8>, Error> {
    let keys = derive_usage_keys(key.etype(), key.as_bytes(), usage)?;
    hmac_truncated(key.etype(), &keys.kc, message)
}

fn emit(
    event: &'static str,
    correlation_id: &str,
    etype: EncryptionType,
    usage: Option<KeyUsage>,
    started: Instant,
    err: Option<&Error>,
) {
    let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    if let Some(e) = err {
        tracing::error!(
            event,
            correlation_id,
            component = "krb5-crypto",
            etype = etype.to_iana(),
            key_usage = usage.map(KeyUsage::get),
            duration_us,
            outcome = "error",
            error = %e,
        );
    } else {
        tracing::info!(
            event,
            correlation_id,
            component = "krb5-crypto",
            etype = etype.to_iana(),
            key_usage = usage.map(KeyUsage::get),
            duration_us,
            outcome = "ok",
        );
    }
}
