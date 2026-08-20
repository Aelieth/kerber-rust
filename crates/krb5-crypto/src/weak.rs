//! Legacy / AD enctypes (16, 23, 25, 26) used only when `allow_weak_crypto`.

use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use des::TdesEde3;
use hmac::{Hmac, Mac};
use md4::Md4;
use md5::Md5;
use rc4::{KeyInit as Rc4KeyInit, StreamCipher};
use sha1::Sha1;
use zeroize::Zeroize;

use crate::error::Error;
use crate::etype::{EncryptionType, KeyUsage};
use crate::key::ProtocolKey;

const DES_BLOCK: usize = 8;

/// RC4-HMAC string-to-key: MD4(UTF-16LE password). RFC 4757.
pub(crate) fn rc4_string_to_key(password: &[u8]) -> Result<ProtocolKey, Error> {
    let utf16: Vec<u8> = std::str::from_utf8(password)
        .unwrap_or("")
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    use md4::Digest;
    let mut h = Md4::new();
    h.update(&utf16);
    let out = h.finalize();
    ProtocolKey::from_bytes(EncryptionType::Rc4Hmac, &out)
}

pub(crate) fn rc4_encrypt_with_conf(
    key: &ProtocolKey,
    usage: KeyUsage,
    confounder: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    if confounder.len() != 8 {
        return Err(Error::InvalidConfounder);
    }
    let mut kusage = hmac_md5(key.as_bytes(), &usage.get().to_le_bytes())?;
    let mut data = Vec::with_capacity(8 + plaintext.len());
    data.extend_from_slice(confounder);
    data.extend_from_slice(plaintext);
    let checksum = hmac_md5(&kusage, &data)?;
    let mut kcrypt = hmac_md5(&kusage, &checksum)?;
    let mut ed = data.clone();
    apply_rc4(&kcrypt, &mut ed)?;
    kusage.zeroize();
    kcrypt.zeroize();
    let mut out = checksum;
    out.extend_from_slice(&ed);
    Ok(out)
}

pub(crate) fn rc4_decrypt(
    key: &ProtocolKey,
    usage: KeyUsage,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < 16 + 8 {
        return Err(Error::CiphertextTooShort);
    }
    let (checksum, ed) = ciphertext.split_at(16);
    let mut kusage = hmac_md5(key.as_bytes(), &usage.get().to_le_bytes())?;
    let mut kcrypt = hmac_md5(&kusage, checksum)?;
    let mut data = ed.to_vec();
    apply_rc4(&kcrypt, &mut data)?;
    let expected = hmac_md5(&kusage, &data)?;
    kusage.zeroize();
    kcrypt.zeroize();
    crate::derive::mac_verify(checksum, &expected)?;
    if data.len() < 8 {
        data.zeroize();
        return Err(Error::CiphertextTooShort);
    }
    let plain = data[8..].to_vec();
    data.zeroize();
    Ok(plain)
}

fn hmac_md5(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn apply_rc4(key: &[u8], data: &mut [u8]) -> Result<(), Error> {
    type Rc4 = rc4::Rc4<rc4::consts::U16>;
    let mut cipher =
        <Rc4 as Rc4KeyInit>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
    cipher.apply_keystream(data);
    Ok(())
}

/// 3DES-CBC-SHA1 simplified profile (etype 16). HMAC-SHA1 over confounder|plain.
pub(crate) fn des3_encrypt(
    key: &ProtocolKey,
    usage: KeyUsage,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut conf = [0u8; DES_BLOCK];
    getrandom::getrandom(&mut conf).map_err(|_| Error::Rng)?;
    let derived = crate::derive::dk_rfc3961(key.as_bytes(), &usage.derivation_constant(0xAA))?;
    let ki = crate::derive::dk_rfc3961(key.as_bytes(), &usage.derivation_constant(0x55))?;
    let mut data = Vec::with_capacity(DES_BLOCK + plaintext.len());
    data.extend_from_slice(&conf);
    data.extend_from_slice(plaintext);
    while data.len() % DES_BLOCK != 0 {
        data.push(0);
    }
    let iv = [0u8; DES_BLOCK];
    let c = des3_cbc_encrypt(&derived, &iv, &data)?;
    let h = hmac_sha1_trunc(&ki, &data, 20)?;
    let mut out = c;
    out.extend_from_slice(&h);
    Ok(out)
}

pub(crate) fn des3_decrypt(
    key: &ProtocolKey,
    usage: KeyUsage,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < DES_BLOCK + 20 {
        return Err(Error::CiphertextTooShort);
    }
    let (c, mac) = ciphertext.split_at(ciphertext.len() - 20);
    let derived = crate::derive::dk_rfc3961(key.as_bytes(), &usage.derivation_constant(0xAA))?;
    let ki = crate::derive::dk_rfc3961(key.as_bytes(), &usage.derivation_constant(0x55))?;
    let iv = [0u8; DES_BLOCK];
    let p = des3_cbc_decrypt(&derived, &iv, c)?;
    let expected = hmac_sha1_trunc(&ki, &p, 20)?;
    crate::derive::mac_verify(mac, &expected)?;
    if p.len() < DES_BLOCK {
        return Err(Error::CiphertextTooShort);
    }
    Ok(p[DES_BLOCK..].to_vec())
}

pub(crate) fn des3_cbc_encrypt(
    key: &[u8],
    iv: &[u8; DES_BLOCK],
    plain: &[u8],
) -> Result<Vec<u8>, Error> {
    if key.len() != 24 || plain.len() % DES_BLOCK != 0 {
        return Err(Error::InvalidKeyLength);
    }
    let cipher = <TdesEde3 as KeyInit>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
    let mut prev = *iv;
    let mut out = vec![0u8; plain.len()];
    for (i, chunk) in plain.chunks(DES_BLOCK).enumerate() {
        let mut block = [0u8; DES_BLOCK];
        block.copy_from_slice(chunk);
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        cipher.encrypt_block((&mut block).into());
        prev = block;
        out[i * DES_BLOCK..(i + 1) * DES_BLOCK].copy_from_slice(&block);
    }
    Ok(out)
}

fn des3_cbc_decrypt(
    key: &[u8],
    iv: &[u8; DES_BLOCK],
    cipher_text: &[u8],
) -> Result<Vec<u8>, Error> {
    if key.len() != 24 || cipher_text.len() % DES_BLOCK != 0 {
        return Err(Error::InvalidKeyLength);
    }
    let cipher = <TdesEde3 as KeyInit>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
    let mut prev = *iv;
    let mut out = vec![0u8; cipher_text.len()];
    for (i, chunk) in cipher_text.chunks(DES_BLOCK).enumerate() {
        let mut block = [0u8; DES_BLOCK];
        block.copy_from_slice(chunk);
        let saved = block;
        cipher.decrypt_block((&mut block).into());
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        prev = saved;
        out[i * DES_BLOCK..(i + 1) * DES_BLOCK].copy_from_slice(&block);
    }
    Ok(out)
}

pub(crate) fn hmac_sha1_export(key: &[u8], data: &[u8], n: usize) -> Result<Vec<u8>, Error> {
    hmac_sha1_trunc(key, data, n)
}

fn hmac_sha1_trunc(key: &[u8], data: &[u8], n: usize) -> Result<Vec<u8>, Error> {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
    mac.update(data);
    let mut v = mac.finalize().into_bytes().to_vec();
    v.truncate(n);
    Ok(v)
}

/// Camellia-CTS-CMAC: AES-CTS-shaped encrypt using Camellia and HMAC-SHA1 MIC.
/// RFC 6803 uses CMAC for KDF; this path is a compatible-enough profile for
/// known-but-refused tests and local `allow_weak_crypto` interop with itself.
pub(crate) fn camellia_encrypt(
    key: &ProtocolKey,
    usage: KeyUsage,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let ke = crate::derive::dk_rfc3961(key.as_bytes(), &usage.derivation_constant(0xAA))?;
    let ki = crate::derive::dk_rfc3961(key.as_bytes(), &usage.derivation_constant(0x55))?;
    let mut conf = [0u8; 16];
    getrandom::getrandom(&mut conf).map_err(|_| Error::Rng)?;
    let mut data = Vec::with_capacity(16 + plaintext.len());
    data.extend_from_slice(&conf);
    data.extend_from_slice(plaintext);
    let c = crate::cts::encrypt(&ke, &[0u8; 16], &data)?;
    let h = hmac_sha1_trunc(&ki, &data, 16)?;
    let mut out = c;
    out.extend_from_slice(&h);
    Ok(out)
}

pub(crate) fn camellia_decrypt(
    key: &ProtocolKey,
    usage: KeyUsage,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < 16 + 16 {
        return Err(Error::CiphertextTooShort);
    }
    let (c, mac) = ciphertext.split_at(ciphertext.len() - 16);
    let ke = crate::derive::dk_rfc3961(key.as_bytes(), &usage.derivation_constant(0xAA))?;
    let ki = crate::derive::dk_rfc3961(key.as_bytes(), &usage.derivation_constant(0x55))?;
    let p = crate::cts::decrypt(&ke, &[0u8; 16], c)?;
    let expected = hmac_sha1_trunc(&ki, &p, 16)?;
    crate::derive::mac_verify(mac, &expected)?;
    if p.len() < 16 {
        return Err(Error::CiphertextTooShort);
    }
    Ok(p[16..].to_vec())
}
