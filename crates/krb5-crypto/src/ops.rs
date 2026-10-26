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
use crate::wipe::Wiped;

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

// MIT: `krb5int_dk_string_to_key` (lib/crypto/krb/s2k_pbkdf2.c:33-101)
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

// MIT: `krb5_c_string_to_key_with_params` (lib/crypto/krb/string_to_key.c:39-79)
fn string_to_key_inner(
    etype: EncryptionType,
    password: &[u8],
    salt: &[u8],
    params: Option<&[u8]>,
) -> Result<ProtocolKey, Error> {
    let iter = parse_iterations(etype, params)?;
    let key_len = etype.key_len();
    let mut tkey = Wiped(vec![0u8; key_len]);

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
        let base = Wiped(derive::kdf_hmac_sha2(
            etype,
            &tkey,
            b"kerberos",
            None,
            derive::bits_u32(key_len),
        )?);
        ProtocolKey::from_bytes(etype, &base)
    } else if etype == EncryptionType::Rc4Hmac {
        crate::weak::rc4_string_to_key(password)
    } else if etype == EncryptionType::Des3CbcSha1 {
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
        let base = Wiped(crate::weak::dk_camellia(&tkey, b"kerberos")?);
        ProtocolKey::from_bytes(etype, &base)
    } else {
        pbkdf2_hmac::<Sha1>(password, salt, iter, &mut tkey);
        let base = Wiped(derive::dk_rfc3961(&tkey, b"kerberos")?);
        ProtocolKey::from_bytes(etype, &base)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CipherState {
    pub iv: [u8; BLOCK],
}

impl Default for CipherState {
    fn default() -> Self {
        Self { iv: [0u8; BLOCK] }
    }
}

impl CipherState {
    #[must_use]
    pub fn initial() -> Self {
        Self::default()
    }
}

pub fn encrypt(key: &ProtocolKey, usage: KeyUsage, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut conf = [0u8; BLOCK];
    getrandom::getrandom(&mut conf).map_err(|_| Error::Rng)?;
    encrypt_with_confounder(key, usage, &conf, plaintext)
}

pub fn kdb_encrypt_key(mkey: &ProtocolKey, raw_key: &[u8]) -> Result<Vec<u8>, Error> {
    let key_len = u16::try_from(raw_key.len()).map_err(|_| Error::InvalidKeyLength)?;
    let cipher = encrypt(mkey, KeyUsage::from_rfc(0), raw_key)?;
    let mut out = Vec::with_capacity(2 + cipher.len());
    out.extend_from_slice(&key_len.to_le_bytes());
    out.extend_from_slice(&cipher);
    Ok(out)
}

pub fn kdb_decrypt_key(mkey: &ProtocolKey, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if ciphertext.len() < 2 {
        return Err(Error::CiphertextTooShort);
    }
    let key_len = usize::from(u16::from_le_bytes([ciphertext[0], ciphertext[1]]));
    let plain = Zeroizing::new(decrypt(mkey, KeyUsage::from_rfc(0), &ciphertext[2..])?);
    if plain.len() != key_len {
        return Err(Error::InvalidKeyLength);
    }
    Ok(plain)
}

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

pub fn encrypt_with_confounder_and_state(
    key: &ProtocolKey,
    usage: KeyUsage,
    confounder: &[u8],
    state: &mut CipherState,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    encrypt_inner_state(key, usage, confounder, plaintext, state)
}

// MIT: `krb5int_dk_encrypt` (lib/crypto/krb/enc_dk_hmac.c:68-176)
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
            return crate::weak::camellia_encrypt_with_conf(
                key, usage, confounder, plaintext, state,
            );
        }
        _ => {}
    }
    if confounder.len() != BLOCK {
        return Err(Error::InvalidConfounder);
    }
    let keys = derive_usage_keys(key.etype(), key.as_bytes(), usage)?;
    let iv = state.iv;
    let mut data = Wiped(Vec::with_capacity(BLOCK + plaintext.len()));
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

pub(crate) fn update_iv(state: &mut CipherState, ciphertext: &[u8]) {
    let nblocks = ciphertext.len().div_ceil(BLOCK);
    if nblocks >= 2 {
        let start = (nblocks - 2) * BLOCK;
        state.iv.copy_from_slice(&ciphertext[start..start + BLOCK]);
    }
}

// MIT: `ENCTYPE_UNKNOWN` (include/krb5/krb5.hin:449-449)
pub const ENCTYPE_UNKNOWN: i32 = 0x01ff;

pub fn check_enc_data_etype(key: &ProtocolKey, etype: i32) -> Result<(), Error> {
    if etype != ENCTYPE_UNKNOWN && etype != key.etype().to_iana() {
        return Err(Error::BadEnctype(etype));
    }
    Ok(())
}

pub fn decrypt_enc_data(
    key: &ProtocolKey,
    usage: KeyUsage,
    etype: i32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    check_enc_data_etype(key, etype)?;
    decrypt(key, usage, ciphertext)
}

pub fn decrypt_enc_data_with_state(
    key: &ProtocolKey,
    usage: KeyUsage,
    state: &mut CipherState,
    etype: i32,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    check_enc_data_etype(key, etype)?;
    decrypt_with_state(key, usage, state, ciphertext)
}

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

pub fn decrypt_with_state(
    key: &ProtocolKey,
    usage: KeyUsage,
    state: &mut CipherState,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    decrypt_inner_state(key, usage, ciphertext, state)
}

// MIT: `krb5int_dk_decrypt` (lib/crypto/krb/enc_dk_hmac.c:178-269)
// MIT: `krb5int_etm_decrypt` (lib/crypto/krb/enc_etm.c:209-257)
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
            return crate::weak::camellia_decrypt(key, usage, ciphertext, state);
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
        update_iv(state, c);
        let expected = hmac_truncated(key.etype(), &keys.ki, &p)?;
        if mac_verify(mac, &expected).is_err() {
            p.zeroize();
            return Err(Error::Integrity);
        }
        if p.len() < BLOCK {
            p.zeroize();
            return Err(Error::CiphertextTooShort);
        }
        let plain = p[BLOCK..].to_vec();
        p.zeroize();
        Ok(plain)
    }
}

pub fn integrity_mac(key: &ProtocolKey, usage: KeyUsage, message: &[u8]) -> Result<Vec<u8>, Error> {
    if !key.etype().is_aes() {
        return Err(Error::UnsupportedEtype(key.etype().to_iana()));
    }
    let keys = derive_usage_keys(key.etype(), key.as_bytes(), usage)?;
    hmac_truncated(key.etype(), &keys.ki, message)
}

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

// MIT: `krb5int_dk_checksum` (lib/crypto/krb/checksum_dk_hmac.c:32-59)
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
            hmac_md5_arcfour_checksum(key.as_bytes(), usage.get(), message, -138)
        }
        EncryptionType::Des3CbcSha1 => {
            let kc = Wiped(crate::weak::dk_des3(
                key.as_bytes(),
                &usage.derivation_constant(0x99),
            )?);
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
    use hmac::{Hmac, KeyInit, Mac};
    use md5::Md5;
    let mut mac =
        <Hmac<Md5> as KeyInit>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

// MIT: `krb5int_hmacmd5_checksum` (lib/crypto/krb/checksum_hmac_md5.c:36-94)
// MIT: `krb5int_arcfour_translate_usage` (lib/crypto/krb/enc_rc4.c:16-35)
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
        Some(Zeroizing::new(hmac_md5_simple(key, b"signaturekey\0")?))
    };
    let mac_key = match &ksign {
        Some(k) => k.as_slice(),
        None => key,
    };
    let mut hasher = Md5::new();
    hasher.update(mapped.to_le_bytes());
    hasher.update(message);
    let hashval = hasher.finalize();
    hmac_md5_simple(mac_key, &hashval)
}

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

// MIT: `krb5int_unkeyed_checksum` (lib/crypto/krb/checksum_unkeyed.c:29-36)
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

// MIT: `krb5_c_verify_checksum` (lib/crypto/krb/verify_checksum.c:82-98)
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
    // MIT: `krb5_k_verify_checksum` (lib/crypto/krb/verify_checksum.c:30-80)
    if crate::etype::cksumtype_is_unkeyed(ctype) {
        if mac.len() != want {
            return Err(Error::BadChecksumSize);
        }
        let expected = unkeyed_checksum(ctype, message)?;
        return mac_verify(mac, &expected);
    }
    if !crate::etype::cksumtype_is_keyed(ctype) {
        return Err(Error::UnsupportedChecksum(ctype));
    }
    // MIT: `verify_key` (lib/crypto/krb/crypto_int.h:598-599)
    if !keyed_cksum_accepts_key(ctype, key.etype()) {
        return Err(Error::UnsupportedChecksum(ctype));
    }
    if mac.len() != want {
        return Err(Error::BadChecksumSize);
    }
    let expected = keyed_checksum_for_type(key, usage, message, ctype)?;
    mac_verify(mac, &expected)
}

// MIT: `verify_for_user_checksum` (kdc/kdc_util.c:1232-1302)
// MIT: `verify_checksum` (lib/krb5/krb/pac.c:478-515)
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

// MIT: `read_krbsafe` (lib/krb5/krb/rd_safe.c:37-125)
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
        tracing::debug!(
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

    // MIT: `krb5_c_decrypt` (lib/crypto/krb/decrypt.c:87-101)
    #[test]
    fn enc_data_etype_check_is_krb5_k_decrypts() {
        let key =
            ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x44u8; 32]).unwrap();
        let usage = KeyUsage::new(11).unwrap();
        let cipher = encrypt(&key, usage, b"hello").unwrap();
        for etype in [18, ENCTYPE_UNKNOWN] {
            assert_eq!(
                decrypt_enc_data(&key, usage, etype, &cipher).unwrap(),
                b"hello"
            );
        }
        for etype in [0, 17, 6] {
            assert_eq!(
                decrypt_enc_data(&key, usage, etype, &cipher),
                Err(Error::BadEnctype(etype))
            );
        }
        assert_eq!(
            decrypt_enc_data(&key, usage, 17, b"short"),
            Err(Error::BadEnctype(17))
        );
        let mut state = CipherState::initial();
        assert_eq!(
            decrypt_enc_data_with_state(&key, usage, &mut state, 17, &cipher),
            Err(Error::BadEnctype(17))
        );
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
}
