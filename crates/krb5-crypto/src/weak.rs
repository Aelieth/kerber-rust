//! Legacy / AD enctypes (16, 23, 25, 26) used only when `allow_weak_crypto`.

use des::TdesEde3;
use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
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
    let mut kusage = hmac_md5(key.as_bytes(), &rc4_usage(usage).to_le_bytes())?;
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
    let mut kusage = hmac_md5(key.as_bytes(), &rc4_usage(usage).to_le_bytes())?;
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

/// RFC 4757 usage translation (MIT `map_arcfour_gss`).
fn rc4_usage(usage: KeyUsage) -> u32 {
    match usage.get() {
        3 | 9 => 8,
        23 => 13,
        n => n,
    }
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
    let derived = dk_des3(key.as_bytes(), &usage.derivation_constant(0xAA))?;
    let ki = dk_des3(key.as_bytes(), &usage.derivation_constant(0x55))?;
    let mut data = Vec::with_capacity(DES_BLOCK + plaintext.len());
    data.extend_from_slice(&conf);
    data.extend_from_slice(plaintext);
    while data.len() % DES_BLOCK != 0 {
        data.push(0);
    }
    let iv = [0u8; DES_BLOCK];
    let c = des3_cbc_encrypt(&derived, iv, &data)?;
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
    let derived = dk_des3(key.as_bytes(), &usage.derivation_constant(0xAA))?;
    let ki = dk_des3(key.as_bytes(), &usage.derivation_constant(0x55))?;
    let iv = [0u8; DES_BLOCK];
    let p = des3_cbc_decrypt(&derived, iv, c)?;
    let expected = hmac_sha1_trunc(&ki, &p, 20)?;
    crate::derive::mac_verify(mac, &expected)?;
    if p.len() < DES_BLOCK {
        return Err(Error::CiphertextTooShort);
    }
    Ok(p[DES_BLOCK..].to_vec())
}

pub(crate) fn des3_cbc_encrypt(
    key: &[u8],
    iv: [u8; DES_BLOCK],
    plain: &[u8],
) -> Result<Vec<u8>, Error> {
    if key.len() != 24 || plain.len() % DES_BLOCK != 0 {
        return Err(Error::InvalidKeyLength);
    }
    let cipher = <TdesEde3 as KeyInit>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
    let mut prev = iv;
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

fn des3_cbc_decrypt(key: &[u8], iv: [u8; DES_BLOCK], cipher_text: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != 24 || cipher_text.len() % DES_BLOCK != 0 {
        return Err(Error::InvalidKeyLength);
    }
    let cipher = <TdesEde3 as KeyInit>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
    let mut prev = iv;
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

/// RFC 3961 §6.3 3DES string-to-key: n-fold to 168 bits, random-to-key, DK("kerberos").
pub(crate) fn des3_string_to_key(password: &[u8], salt: &[u8]) -> Result<ProtocolKey, Error> {
    let mut seed = Vec::with_capacity(password.len() + salt.len());
    seed.extend_from_slice(password);
    seed.extend_from_slice(salt);
    if seed.is_empty() {
        seed.push(0);
    }
    let mut raw21 = crate::nfold::nfold(&seed, 21)?;
    let mut raw = des3_random_to_key(&raw21);
    raw21.zeroize();
    let dk = dk_des3(&raw, b"kerberos")?;
    raw.zeroize();
    ProtocolKey::from_bytes(EncryptionType::Des3CbcSha1, &dk)
}

/// RFC 3961 §6.3.1 DES3random-to-key: three 56-bit groups, last output
/// byte collects input LSBs in reverse order, then odd parity (+ weak-key
/// correction as in §6.2).
fn des3_random_to_key(raw21: &[u8]) -> [u8; 24] {
    let mut out = [0u8; 24];
    for i in 0..3 {
        let p = &raw21[i * 7..i * 7 + 7];
        let k = &mut out[i * 8..i * 8 + 8];
        for (j, b) in p.iter().enumerate() {
            k[j] = b & 0xfe;
        }
        k[7] = (p[6] & 1) << 7
            | (p[5] & 1) << 6
            | (p[4] & 1) << 5
            | (p[3] & 1) << 4
            | (p[2] & 1) << 3
            | (p[1] & 1) << 2
            | (p[0] & 1) << 1;
        des_key_correction(k);
    }
    out
}

fn des_key_correction(key: &mut [u8]) {
    odd_parity(key);
    if des_is_weak(key) {
        key[7] ^= 0xf0;
        odd_parity(key);
    }
}

fn des_is_weak(key: &[u8]) -> bool {
    // DES weak and semi-weak keys (NIST), compared after parity is set.
    const WEAK: [[u8; 8]; 16] = [
        [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
        [0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe],
        [0xe0, 0xe0, 0xe0, 0xe0, 0xf1, 0xf1, 0xf1, 0xf1],
        [0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e],
        [0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe],
        [0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01],
        [0x1f, 0xe0, 0x1f, 0xe0, 0x0e, 0xf1, 0x0e, 0xf1],
        [0xe0, 0x1f, 0xe0, 0x1f, 0xf1, 0x0e, 0xf1, 0x0e],
        [0x01, 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1],
        [0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1, 0x01],
        [0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe],
        [0xfe, 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e],
        [0x01, 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e],
        [0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e, 0x01],
        [0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1, 0xfe],
        [0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1],
    ];
    WEAK.iter().any(|w| {
        w.iter()
            .zip(key.iter())
            .all(|(a, b)| (*a & 0xfe) == (*b & 0xfe))
    })
}

fn odd_parity(block: &mut [u8]) {
    for b in block {
        let mut x = *b & 0xfe;
        if x.count_ones() % 2 == 0 {
            x |= 1;
        }
        *b = x;
    }
}

/// RFC 3961 DR/DK for 3DES: DR to 168 bits, then [`des3_random_to_key`].
pub(crate) fn dk_des3(key: &[u8], constant: &[u8]) -> Result<Vec<u8>, Error> {
    let folded = crate::nfold::nfold(constant, DES_BLOCK)?;
    let mut block = [0u8; DES_BLOCK];
    block.copy_from_slice(&folded);
    let mut dr = Vec::with_capacity(24);
    while dr.len() < 21 {
        let c = des3_cbc_encrypt(key, [0u8; DES_BLOCK], &block)?;
        if c.len() != DES_BLOCK {
            return Err(Error::InvalidKeyLength);
        }
        block.copy_from_slice(&c);
        dr.extend_from_slice(&c);
    }
    dr.truncate(21);
    Ok(des3_random_to_key(&dr).to_vec())
}

pub(crate) fn camellia_encrypt_with_conf(
    key: &ProtocolKey,
    usage: KeyUsage,
    confounder: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    if confounder.len() != 16 {
        return Err(Error::InvalidConfounder);
    }
    let ke = dk_camellia(key.as_bytes(), &usage.derivation_constant(0xAA))?;
    let ki = dk_camellia(key.as_bytes(), &usage.derivation_constant(0x55))?;
    let mut data = Vec::with_capacity(16 + plaintext.len());
    data.extend_from_slice(confounder);
    data.extend_from_slice(plaintext);
    let c = crate::cts::camellia_encrypt(&ke, &[0u8; 16], &data)?;
    let h = cmac_camellia(&ki, &data)?;
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
    let ke = dk_camellia(key.as_bytes(), &usage.derivation_constant(0xAA))?;
    let ki = dk_camellia(key.as_bytes(), &usage.derivation_constant(0x55))?;
    let p = crate::cts::camellia_decrypt(&ke, &[0u8; 16], c)?;
    let expected = cmac_camellia(&ki, &p)?;
    crate::derive::mac_verify(mac, &expected)?;
    if p.len() < 16 {
        return Err(Error::CiphertextTooShort);
    }
    Ok(p[16..].to_vec())
}

/// RFC 6803 §3 KDF-FEEDBACK-CMAC. `key` is the protocol key (16 or 32 octets).
pub(crate) fn dk_camellia(key: &[u8], constant: &[u8]) -> Result<Vec<u8>, Error> {
    kdf_feedback_cmac(key, constant)
}

/// RFC 6803: `K(i) = CMAC(key, K(i-1) | i | constant | 0x00 | k)` with
/// `k` the output length in bits (big-endian 4 octets) and `i` a 4-octet
/// counter. Output is truncated to `key.len()` octets.
pub(crate) fn kdf_feedback_cmac(key: &[u8], constant: &[u8]) -> Result<Vec<u8>, Error> {
    let out_len = key.len();
    if out_len != 16 && out_len != 32 {
        return Err(Error::InvalidKeyLength);
    }
    let k_bits = u32::try_from(out_len.saturating_mul(8)).unwrap_or(u32::MAX);
    let n = out_len.div_ceil(16);
    let mut k_prev = vec![0u8; 16];
    let mut out = Vec::with_capacity(n * 16);
    for i in 1..=n {
        let i32 = u32::try_from(i).unwrap_or(u32::MAX);
        let mut input = Vec::with_capacity(16 + 4 + constant.len() + 1 + 4);
        input.extend_from_slice(&k_prev);
        input.extend_from_slice(&i32.to_be_bytes());
        input.extend_from_slice(constant);
        input.push(0x00);
        input.extend_from_slice(&k_bits.to_be_bytes());
        let ki = cmac_camellia(key, &input)?;
        k_prev.clone_from(&ki);
        out.extend_from_slice(&ki);
    }
    out.truncate(out_len);
    Ok(out)
}

pub(crate) fn cmac_camellia(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    use camellia::{Camellia128, Camellia256};
    use cmac::{Cmac, Mac};
    match key.len() {
        16 => {
            let mut mac = <Cmac<Camellia128> as Mac>::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        32 => {
            let mut mac = <Cmac<Camellia256> as Mac>::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        _ => Err(Error::InvalidKeyLength),
    }
}
