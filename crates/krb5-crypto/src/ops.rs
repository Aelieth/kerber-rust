//! Public RFC 3961 operations: string-to-key, encrypt, decrypt, checksum.

use std::time::Instant;

use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Sha256, Sha384};
use zeroize::{Zeroize, Zeroizing};

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
    let correlation_id = krb5_log::current_correlation_id();
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
            EncryptionType::Aes128CtsHmacSha196
            | EncryptionType::Aes256CtsHmacSha196
            | EncryptionType::Des3CbcSha1
            | EncryptionType::Rc4Hmac
            | EncryptionType::Camellia128CtsCmac
            | EncryptionType::Camellia256CtsCmac => {
                return Err(Error::UnsupportedEtype(etype.to_iana()));
            }
        }
        let mut base =
            derive::kdf_hmac_sha2(etype, &tkey, b"kerberos", None, derive::bits_u32(key_len))?;
        tkey.zeroize();
        let key = ProtocolKey::from_bytes(etype, &base);
        base.zeroize();
        key
    } else if etype == EncryptionType::Rc4Hmac {
        tkey.zeroize();
        crate::weak::rc4_string_to_key(password)
    } else if etype == EncryptionType::Des3CbcSha1 {
        tkey.zeroize();
        crate::weak::des3_string_to_key(password, salt)
    } else if etype.is_camellia() {
        let mut saltp = Vec::new();
        saltp.extend_from_slice(
            etype
                .enctype_name()
                .ok_or(Error::UnsupportedEtype(etype.to_iana()))?
                .as_bytes(),
        );
        saltp.push(0x00);
        saltp.extend_from_slice(salt);
        pbkdf2_hmac::<Sha1>(password, &saltp, iter, &mut tkey);
        let mut base = crate::weak::dk_camellia(&tkey, b"kerberos")?;
        tkey.zeroize();
        let key = ProtocolKey::from_bytes(etype, &base);
        base.zeroize();
        key
    } else {
        pbkdf2_hmac::<Sha1>(password, salt, iter, &mut tkey);
        let mut base = derive::dk_rfc3961(&tkey, b"kerberos")?;
        tkey.zeroize();
        let key = ProtocolKey::from_bytes(etype, &base);
        base.zeroize();
        key
    }
}

/// Cipher state carried between sequential encrypt/decrypt operations.
///
/// RFC 3961: the initial IV is all zeros. Subsequent operations may chain
/// the last ciphertext block. A hardcoded `[0; 16]` is used only as the
/// initial state, not for every message when a state object is passed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CipherState {
    /// Current initialization vector (AES block).
    pub iv: [u8; BLOCK],
}

impl Default for CipherState {
    fn default() -> Self {
        Self { iv: [0u8; BLOCK] }
    }
}

impl CipherState {
    /// Initial all-zero state.
    #[must_use]
    pub fn initial() -> Self {
        Self::default()
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

/// MIT KDB `key_data` framing: `int16_LE(key_length) ‖ RFC 3961 encrypt`.
///
/// The length prefix is **cleartext** (the 1.22.2 dump stores `20 00` /
/// `10 00` ahead of the ciphertext). The encrypted portion is the raw
/// protocol key under the master key with **usage 0** (ivec = NULL).
/// Protocol callers must keep using [`KeyUsage::new`], which still rejects 0.
///
/// # Errors
///
/// [`Error::InvalidKeyLength`] when `raw_key` is longer than u16, or encrypt
/// failures from the master-key etype.
pub fn kdb_encrypt_key(mkey: &ProtocolKey, raw_key: &[u8]) -> Result<Vec<u8>, Error> {
    let key_len = u16::try_from(raw_key.len()).map_err(|_| Error::InvalidKeyLength)?;
    let cipher = encrypt(mkey, KeyUsage::from_rfc(0), raw_key)?;
    let mut out = Vec::with_capacity(2 + cipher.len());
    out.extend_from_slice(&key_len.to_le_bytes());
    out.extend_from_slice(&cipher);
    Ok(out)
}

/// Inverse of [`kdb_encrypt_key`].
///
/// # Errors
///
/// Decrypt / integrity failures, or a length prefix that does not match the
/// decrypted key.
pub fn kdb_decrypt_key(mkey: &ProtocolKey, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < 2 {
        return Err(Error::CiphertextTooShort);
    }
    let key_len = usize::from(u16::from_le_bytes([ciphertext[0], ciphertext[1]]));
    let plain = decrypt(mkey, KeyUsage::from_rfc(0), &ciphertext[2..])?;
    if plain.len() != key_len {
        return Err(Error::InvalidKeyLength);
    }
    Ok(plain)
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
    let correlation_id = krb5_log::current_correlation_id();
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
    let mut state = CipherState::initial();
    encrypt_inner_state(key, usage, confounder, plaintext, &mut state)
}

/// Encrypt using a caller-managed cipher state (IV chaining).
///
/// # Errors
///
/// Same as [`encrypt`].
pub fn encrypt_with_state(
    key: &ProtocolKey,
    usage: KeyUsage,
    state: &mut CipherState,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut conf = [0u8; BLOCK];
    getrandom::getrandom(&mut conf).map_err(|_| Error::Rng)?;
    encrypt_inner_state(key, usage, &conf, plaintext, state)
}

fn encrypt_inner_state(
    key: &ProtocolKey,
    usage: KeyUsage,
    confounder: &[u8],
    plaintext: &[u8],
    state: &mut CipherState,
) -> Result<Vec<u8>, Error> {
    match key.etype() {
        EncryptionType::Rc4Hmac => {
            return crate::weak::rc4_encrypt_with_conf(
                key,
                usage,
                confounder
                    .get(..8)
                    .unwrap_or(&confounder[..confounder.len().min(8)]),
                plaintext,
            );
        }
        EncryptionType::Des3CbcSha1 => return crate::weak::des3_encrypt(key, usage, plaintext),
        EncryptionType::Camellia128CtsCmac | EncryptionType::Camellia256CtsCmac => {
            return crate::weak::camellia_encrypt_with_conf(key, usage, confounder, plaintext);
        }
        _ => {}
    }
    if confounder.len() != BLOCK {
        return Err(Error::InvalidConfounder);
    }
    let keys = derive_usage_keys(key.etype(), key.as_bytes(), usage)?;
    let iv = state.iv;
    let mut data = Vec::with_capacity(BLOCK + plaintext.len());
    data.extend_from_slice(confounder);
    data.extend_from_slice(plaintext);

    if key.etype().is_rfc8009() {
        let c = cts::encrypt(&keys.ke, &iv, &data)?;
        let mut hmac_input = Vec::with_capacity(BLOCK + c.len());
        hmac_input.extend_from_slice(&iv);
        hmac_input.extend_from_slice(&c);
        let h = hmac_truncated(key.etype(), &keys.ki, &hmac_input)?;
        update_iv(state, &c);
        let mut out = c;
        out.extend_from_slice(&h);
        Ok(out)
    } else {
        let c = cts::encrypt(&keys.ke, &iv, &data)?;
        let h = hmac_truncated(key.etype(), &keys.ki, &data)?;
        update_iv(state, &c);
        let mut out = c;
        out.extend_from_slice(&h);
        Ok(out)
    }
}

fn update_iv(state: &mut CipherState, ciphertext: &[u8]) {
    if ciphertext.len() >= BLOCK {
        let start = ciphertext.len() - BLOCK;
        state.iv.copy_from_slice(&ciphertext[start..]);
    }
}

/// Decrypt `ciphertext` and return the plaintext with the confounder removed.
///
/// # Errors
///
/// Returns [`Error::Integrity`] or [`Error::CiphertextTooShort`] on failure.
/// The decrypted buffer is discarded when the HMAC does not match.
pub fn decrypt(key: &ProtocolKey, usage: KeyUsage, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let correlation_id = krb5_log::current_correlation_id();
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
    let mut state = CipherState::initial();
    decrypt_inner_state(key, usage, ciphertext, &mut state)
}

/// Decrypt using a caller-managed cipher state (IV chaining).
///
/// # Errors
///
/// Same as [`decrypt`].
pub fn decrypt_with_state(
    key: &ProtocolKey,
    usage: KeyUsage,
    state: &mut CipherState,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    decrypt_inner_state(key, usage, ciphertext, state)
}

fn decrypt_inner_state(
    key: &ProtocolKey,
    usage: KeyUsage,
    ciphertext: &[u8],
    state: &mut CipherState,
) -> Result<Vec<u8>, Error> {
    match key.etype() {
        EncryptionType::Rc4Hmac => return crate::weak::rc4_decrypt(key, usage, ciphertext),
        EncryptionType::Des3CbcSha1 => return crate::weak::des3_decrypt(key, usage, ciphertext),
        EncryptionType::Camellia128CtsCmac | EncryptionType::Camellia256CtsCmac => {
            return crate::weak::camellia_decrypt(key, usage, ciphertext);
        }
        _ => {}
    }
    let h = key.etype().hmac_output_len();
    if ciphertext.len() < BLOCK + h {
        return Err(Error::CiphertextTooShort);
    }
    let (c, mac) = ciphertext.split_at(ciphertext.len() - h);
    let keys = derive_usage_keys(key.etype(), key.as_bytes(), usage)?;
    let iv = state.iv;

    if key.etype().is_rfc8009() {
        let mut hmac_input = Vec::with_capacity(BLOCK + c.len());
        hmac_input.extend_from_slice(&iv);
        hmac_input.extend_from_slice(c);
        let expected = hmac_truncated(key.etype(), &keys.ki, &hmac_input)?;
        mac_verify(mac, &expected)?;
        let mut p = cts::decrypt(&keys.ke, &iv, c)?;
        if p.len() < BLOCK {
            p.zeroize();
            return Err(Error::CiphertextTooShort);
        }
        update_iv(state, c);
        let conf = p.split_off(BLOCK);
        let mut z = Zeroizing::new(p);
        z.zeroize();
        Ok(conf)
    } else {
        let mut p = cts::decrypt(&keys.ke, &iv, c)?;
        let expected = hmac_truncated(key.etype(), &keys.ki, &p)?;
        if mac_verify(mac, &expected).is_err() {
            p.zeroize();
            return Err(Error::Integrity);
        }
        if p.len() < BLOCK {
            p.zeroize();
            return Err(Error::CiphertextTooShort);
        }
        update_iv(state, c);
        let plain = p[BLOCK..].to_vec();
        p.zeroize();
        Ok(plain)
    }
}

/// Truncated HMAC with the encryption integrity key (`Ki`), not `Kc`.
///
/// GSS wrap_iov `SIGN_ONLY` associated data is mixed into this MAC.
///
/// # Errors
///
/// Key-derivation failures.
pub fn integrity_mac(key: &ProtocolKey, usage: KeyUsage, message: &[u8]) -> Result<Vec<u8>, Error> {
    if !key.etype().is_aes() {
        return Err(Error::UnsupportedEtype(key.etype().to_iana()));
    }
    let keys = derive_usage_keys(key.etype(), key.as_bytes(), usage)?;
    hmac_truncated(key.etype(), &keys.ki, message)
}

/// AES-CTS decrypt of `cipher` with no HMAC (confounder, plaintext).
///
/// Caller must already have verified [`integrity_mac`].
///
/// # Errors
///
/// Short ciphertext, non-AES etype, or CTS failures.
pub fn decrypt_cts(
    key: &ProtocolKey,
    usage: KeyUsage,
    cipher: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if !key.etype().is_aes() {
        return Err(Error::UnsupportedEtype(key.etype().to_iana()));
    }
    if cipher.len() < BLOCK {
        return Err(Error::CiphertextTooShort);
    }
    let keys = derive_usage_keys(key.etype(), key.as_bytes(), usage)?;
    let iv = CipherState::initial().iv;
    let mut p = cts::decrypt(&keys.ke, &iv, cipher)?;
    if p.len() < BLOCK {
        p.zeroize();
        return Err(Error::CiphertextTooShort);
    }
    let plain = p[BLOCK..].to_vec();
    let conf = p[..BLOCK].to_vec();
    p.zeroize();
    Ok((conf, plain))
}

/// Keyed checksum (RFC 3961 `get_mic` / RFC 8009 section 6).
///
/// # Errors
///
/// Returns key-derivation errors.
pub fn checksum(key: &ProtocolKey, usage: KeyUsage, message: &[u8]) -> Result<Vec<u8>, Error> {
    let correlation_id = krb5_log::current_correlation_id();
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
    match key.etype() {
        EncryptionType::Rc4Hmac => {
            let mut k = hmac_md5_simple(key.as_bytes(), &usage.get().to_le_bytes())?;
            let out = hmac_md5_simple(&k, message)?;
            k.zeroize();
            Ok(out)
        }
        EncryptionType::Des3CbcSha1 => {
            let kc = derive::dk_rfc3961(key.as_bytes(), &usage.derivation_constant(0x99))?;
            crate::weak::hmac_sha1_export(&kc, message, 20)
        }
        EncryptionType::Camellia128CtsCmac | EncryptionType::Camellia256CtsCmac => {
            let kc = crate::weak::dk_camellia(key.as_bytes(), &usage.derivation_constant(0x99))?;
            crate::weak::cmac_camellia(&kc, message)
        }
        _ => {
            let keys = derive_usage_keys(key.etype(), key.as_bytes(), usage)?;
            hmac_truncated(key.etype(), &keys.kc, message)
        }
    }
}

fn hmac_md5_simple(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    use hmac::{Hmac, Mac};
    use md5::Md5;
    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// RFC 4757 HMAC-MD5-ARCFOUR (`-138`) / MD5-HMAC-ARCFOUR (`-137`).
///
/// MIT `checksum_hmac_md5.c:53-66`: `-138` signs with HMAC(key,
/// `"signaturekey\0"`); `-137` uses the raw key. Usage map is
/// `enc_rc4.c:17-35`.
///
/// # Errors
///
/// Key longer than the MD5 block, or HMAC setup failure.
pub fn hmac_md5_arcfour_checksum(
    key: &[u8],
    usage: u32,
    message: &[u8],
    ctype: i32,
) -> Result<Vec<u8>, Error> {
    use md5::{Digest, Md5};
    if key.len() > 64 {
        return Err(Error::InvalidKeyLength);
    }
    let mapped = crate::weak::arcfour_translate_usage(usage);
    let ksign = if ctype == -137 {
        None
    } else {
        Some(hmac_md5_simple(key, b"signaturekey\0")?)
    };
    let mac_key = ksign.as_deref().unwrap_or(key);
    let mut hasher = Md5::new();
    hasher.update(mapped.to_le_bytes());
    hasher.update(message);
    let hashval = hasher.finalize();
    hmac_md5_simple(mac_key, &hashval)
}

/// MIT `cksumtypes.c` `output_size`. Unknown types are `None`.
#[must_use]
pub fn checksum_output_size(cksumtype: i32) -> Option<usize> {
    match cksumtype {
        2 | 7 | 17..=19 | -137 | -138 => Some(16),
        9 | 12 | 14 => Some(20),
        15 | 16 => Some(12),
        20 => Some(24),
        _ => None,
    }
}

/// MIT `krb5int_unkeyed_checksum` (`cksumtypes.c` types 2, 7, 9, 14).
///
/// # Errors
///
/// [`Error::UnsupportedChecksum`] when `cksumtype` is not unkeyed.
pub fn unkeyed_checksum(cksumtype: i32, message: &[u8]) -> Result<Vec<u8>, Error> {
    match cksumtype {
        2 => {
            use md4::Digest;
            Ok(md4::Md4::digest(message).to_vec())
        }
        7 => {
            use md5::Digest;
            Ok(md5::Md5::digest(message).to_vec())
        }
        9 | 14 => {
            use sha1::Digest;
            Ok(sha1::Sha1::digest(message).to_vec())
        }
        _ => Err(Error::UnsupportedChecksum(cksumtype)),
    }
}

/// MIT `krb5_c_verify_checksum`: table lookup, length, then compute.
///
/// `cksumtype` 0 uses the key's mandatory type.
///
/// # Errors
///
/// Unknown type [`Error::UnsupportedChecksum`]; length
/// [`Error::BadChecksumSize`]; mismatch [`Error::Integrity`].
pub fn verify_checksum_type(
    key: &ProtocolKey,
    usage: KeyUsage,
    message: &[u8],
    cksumtype: i32,
    mac: &[u8],
) -> Result<(), Error> {
    let ctype = if cksumtype == 0 {
        key.etype().checksum_type()
    } else {
        cksumtype
    };
    let Some(want) = checksum_output_size(ctype) else {
        return Err(Error::UnsupportedChecksum(ctype));
    };
    if mac.len() != want {
        return Err(Error::BadChecksumSize);
    }
    if crate::etype::cksumtype_is_unkeyed(ctype) {
        let expected = unkeyed_checksum(ctype, message)?;
        return mac_verify(mac, &expected);
    }
    if !crate::etype::cksumtype_is_keyed(ctype) {
        return Err(Error::UnsupportedChecksum(ctype));
    }
    // MIT crypto_int.h:596-608 verify_key: keyed type with ctp->enc != NULL
    // requires ktp->enc == ctp->enc; ctp->enc == NULL (-138) accepts any key.
    if !keyed_cksum_accepts_key(ctype, key.etype()) {
        return Err(Error::UnsupportedChecksum(ctype));
    }
    let expected = keyed_checksum_for_type(key, usage, message, ctype)?;
    mac_verify(mac, &expected)
}

/// `krb5_c_is_keyed_cksum` then [`verify_checksum_type`] (`kdc_util.c:1244`, `pac.c:499`).
///
/// The keyed gate uses the declared type; `cksumtype` 0 is not keyed.
///
/// # Errors
///
/// [`Error::InappChecksum`] when the declared type is unkeyed; otherwise
/// the same as [`verify_checksum_type`].
pub fn verify_checksum_keyed(
    key: &ProtocolKey,
    usage: KeyUsage,
    message: &[u8],
    cksumtype: i32,
    mac: &[u8],
) -> Result<(), Error> {
    if !crate::etype::cksumtype_is_keyed(cksumtype) {
        return Err(Error::InappChecksum);
    }
    verify_checksum_type(key, usage, message, cksumtype, mac)
}

/// `krb5_c_valid_cksumtype` + coll-proof + keyed, then [`verify_checksum_type`]
/// (`rd_safe.c:66-74`).
///
/// # Errors
///
/// Unknown type [`Error::UnsupportedChecksum`]; not coll-proof or not
/// keyed [`Error::InappChecksum`]; otherwise [`verify_checksum_type`].
pub fn verify_checksum_collproof(
    key: &ProtocolKey,
    usage: KeyUsage,
    message: &[u8],
    cksumtype: i32,
    mac: &[u8],
) -> Result<(), Error> {
    if !crate::etype::cksumtype_is_known(cksumtype) {
        return Err(Error::UnsupportedChecksum(cksumtype));
    }
    if !crate::etype::cksumtype_is_coll_proof(cksumtype)
        || !crate::etype::cksumtype_is_keyed(cksumtype)
    {
        return Err(Error::InappChecksum);
    }
    verify_checksum_type(key, usage, message, cksumtype, mac)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EncProv {
    Aes128,
    Aes256,
    Des3,
    Arcfour,
    Camellia128,
    Camellia256,
}

fn cksum_enc(ctype: i32) -> Option<EncProv> {
    match ctype {
        15 | 19 => Some(EncProv::Aes128),
        16 | 20 => Some(EncProv::Aes256),
        12 => Some(EncProv::Des3),
        -137 => Some(EncProv::Arcfour),
        17 => Some(EncProv::Camellia128),
        18 => Some(EncProv::Camellia256),
        _ => None,
    }
}

fn key_enc(etype: EncryptionType) -> EncProv {
    match etype {
        EncryptionType::Aes128CtsHmacSha196 | EncryptionType::Aes128CtsHmacSha256128 => {
            EncProv::Aes128
        }
        EncryptionType::Aes256CtsHmacSha196 | EncryptionType::Aes256CtsHmacSha384192 => {
            EncProv::Aes256
        }
        EncryptionType::Des3CbcSha1 => EncProv::Des3,
        EncryptionType::Rc4Hmac => EncProv::Arcfour,
        EncryptionType::Camellia128CtsCmac => EncProv::Camellia128,
        EncryptionType::Camellia256CtsCmac => EncProv::Camellia256,
    }
}

fn keyed_cksum_accepts_key(ctype: i32, etype: EncryptionType) -> bool {
    match cksum_enc(ctype) {
        None => true,
        Some(p) => key_enc(etype) == p,
    }
}

fn cksumtype_compute_etype(ctype: i32) -> Result<EncryptionType, Error> {
    match ctype {
        15 => Ok(EncryptionType::Aes128CtsHmacSha196),
        16 => Ok(EncryptionType::Aes256CtsHmacSha196),
        19 => Ok(EncryptionType::Aes128CtsHmacSha256128),
        20 => Ok(EncryptionType::Aes256CtsHmacSha384192),
        12 => Ok(EncryptionType::Des3CbcSha1),
        17 => Ok(EncryptionType::Camellia128CtsCmac),
        18 => Ok(EncryptionType::Camellia256CtsCmac),
        -137 => Ok(EncryptionType::Rc4Hmac),
        _ => Err(Error::UnsupportedChecksum(ctype)),
    }
}

fn keyed_checksum_for_type(
    key: &ProtocolKey,
    usage: KeyUsage,
    message: &[u8],
    ctype: i32,
) -> Result<Vec<u8>, Error> {
    match ctype {
        -137 | -138 => hmac_md5_arcfour_checksum(key.as_bytes(), usage.get(), message, ctype),
        _ => {
            let etype = cksumtype_compute_etype(ctype)?;
            let tmp = ProtocolKey::from_bytes(etype, key.as_bytes())?;
            checksum_inner(&tmp, usage, message)
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use md5::{Digest, Md5};

    #[test]
    fn verify_checksum_type_md5_hmac_rc4_uses_raw_key() {
        let key = ProtocolKey::from_bytes(EncryptionType::Rc4Hmac, &[0x11u8; 16]).unwrap();
        let usage = KeyUsage::new(9).unwrap();
        let msg = b"kerber-rust-i2";
        let mut hasher = Md5::new();
        hasher.update(9u32.to_le_bytes());
        hasher.update(msg);
        let hashval = hasher.finalize();
        let expected = hmac_md5_simple(key.as_bytes(), &hashval).unwrap();
        verify_checksum_type(&key, usage, msg, -137, &expected).expect("raw-key -137");
    }

    #[test]
    fn verify_checksum_type_honours_declared_unkeyed() {
        let key =
            ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x42u8; 32]).unwrap();
        let usage = KeyUsage::new(15).unwrap();
        let msg = b"j2-declared-type";
        let mac = unkeyed_checksum(7, msg).unwrap();
        verify_checksum_type(&key, usage, msg, 7, &mac).expect("RSA-MD5 over AES key");
        assert!(matches!(
            verify_checksum_type(&key, usage, msg, 7, &mac[..15]),
            Err(Error::BadChecksumSize)
        ));
    }

    #[test]
    fn verify_checksum_keyed_rejects_unkeyed_declared() {
        let key =
            ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x42u8; 32]).unwrap();
        let usage = KeyUsage::new(17).unwrap();
        let msg = b"j2-keyed";
        let mac = unkeyed_checksum(7, msg).unwrap();
        assert!(matches!(
            verify_checksum_keyed(&key, usage, msg, 7, &mac),
            Err(Error::InappChecksum)
        ));
        assert!(matches!(
            verify_checksum_keyed(&key, usage, msg, 0, &mac),
            Err(Error::InappChecksum)
        ));
    }

    #[test]
    fn verify_checksum_collproof_rejects_unknown() {
        let key =
            ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x42u8; 32]).unwrap();
        let usage = KeyUsage::new(15).unwrap();
        assert!(matches!(
            verify_checksum_collproof(&key, usage, b"x", 1, b""),
            Err(Error::UnsupportedChecksum(1))
        ));
    }
}
