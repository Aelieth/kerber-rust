use des::TdesEde3;
use des::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use rc4::StreamCipher;
use sha1::Sha1;
use zeroize::{Zeroize, Zeroizing};

use crate::error::Error;
use crate::etype::{EncryptionType, KeyUsage};
use crate::key::ProtocolKey;
use crate::wipe::Wiped;

const DES_BLOCK: usize = 8;

pub(crate) fn rc4_string_to_key(password: &[u8]) -> Result<ProtocolKey, Error> {
    let text = std::str::from_utf8(password).unwrap_or("");
    let mut utf16 = Wiped(Vec::with_capacity(text.len() * 2));
    for unit in text.encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    let mut h = Md4::new();
    h.update(utf16.as_slice());
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
    let mut data = Wiped(Vec::with_capacity(8 + plaintext.len()));
    data.extend_from_slice(confounder);
    data.extend_from_slice(plaintext);
    let checksum = hmac_md5(&kusage, &data)?;
    let mut kcrypt = hmac_md5(&kusage, &checksum)?;
    let mut ed = Wiped((*data).clone());
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
    let mut mac =
        <Hmac<Md5> as KeyInit>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub(crate) fn arcfour_translate_usage(usage: u32) -> u32 {
    match usage {
        3 => 8,
        9 => 9,
        23 => 13,
        n => n,
    }
}

fn rc4_usage(usage: KeyUsage) -> u32 {
    arcfour_translate_usage(usage.get())
}

fn apply_rc4(key: &[u8], data: &mut [u8]) -> Result<(), Error> {
    if key.len() != 16 {
        return Err(Error::InvalidKeyLength);
    }
    let mut cipher =
        <rc4::Rc4 as KeyInit>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
    cipher.apply_keystream(data);
    Ok(())
}

pub(crate) fn des3_encrypt(
    key: &ProtocolKey,
    usage: KeyUsage,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut conf = [0u8; DES_BLOCK];
    getrandom::getrandom(&mut conf).map_err(|_| Error::Rng)?;
    let derived = dk_des3(key.as_bytes(), &usage.derivation_constant(0xAA))?;
    let ki = dk_des3(key.as_bytes(), &usage.derivation_constant(0x55))?;
    let span = DES_BLOCK + plaintext.len();
    let padded = span.div_ceil(DES_BLOCK) * DES_BLOCK;
    let mut data = Wiped(Vec::with_capacity(padded));
    data.extend_from_slice(&conf);
    data.extend_from_slice(plaintext);
    data.resize(padded, 0);
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

// MIT weak; see docs/parity/b1-crypto-keys.md
// MIT mit_des_is_weak_key; see docs/parity/b1-crypto-keys.md
const WEAK_DES_KEYS: [[u8; 8]; 16] = [
    [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
    [0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe],
    [0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e],
    [0xe0, 0xe0, 0xe0, 0xe0, 0xf1, 0xf1, 0xf1, 0xf1],
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

// MIT mit_des_check_key_parity; see docs/parity/b1-crypto-keys.md
fn des_check_key_parity(key: [u8; 8]) -> bool {
    key.iter().all(|b| b.count_ones() % 2 == 1)
}

fn des_is_weak_key(key: [u8; 8]) -> bool {
    WEAK_DES_KEYS.contains(&key)
}

fn des3_key_sched(key: &[u8]) -> Result<TdesEde3, Error> {
    let key24: &[u8; 24] = key.try_into().map_err(|_| Error::InvalidKeyLength)?;
    let (keys, _) = key24.as_chunks::<8>();
    for &k in keys {
        if !des_check_key_parity(k) {
            return Err(Error::DesBadParity);
        }
        if des_is_weak_key(k) {
            return Err(Error::DesWeakKey);
        }
    }
    <TdesEde3 as KeyInit>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)
}

pub(crate) fn des3_cbc_encrypt(
    key: &[u8],
    iv: [u8; DES_BLOCK],
    plain: &[u8],
) -> Result<Vec<u8>, Error> {
    if key.len() != 24 || !plain.len().is_multiple_of(DES_BLOCK) {
        return Err(Error::InvalidKeyLength);
    }
    let cipher = des3_key_sched(key)?;
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
    if key.len() != 24 || !cipher_text.len().is_multiple_of(DES_BLOCK) {
        return Err(Error::InvalidKeyLength);
    }
    let cipher = des3_key_sched(key)?;
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
    let mut mac =
        <Hmac<Sha1> as KeyInit>::new_from_slice(key).map_err(|_| Error::InvalidKeyLength)?;
    mac.update(data);
    let mut v = mac.finalize().into_bytes().to_vec();
    v.truncate(n);
    Ok(v)
}

pub(crate) fn des3_string_to_key(password: &[u8], salt: &[u8]) -> Result<ProtocolKey, Error> {
    let mut seed = Wiped(Vec::with_capacity((password.len() + salt.len()).max(1)));
    seed.extend_from_slice(password);
    seed.extend_from_slice(salt);
    if seed.is_empty() {
        seed.push(0);
    }
    let raw21 = Wiped(crate::nfold::nfold(&seed, 21)?);
    let raw = Zeroizing::new(des3_random_to_key(&raw21));
    let dk = Wiped(dk_des3(&*raw, b"kerberos")?);
    ProtocolKey::from_bytes(EncryptionType::Des3CbcSha1, &dk)
}

pub(crate) fn des3_random_to_key(raw21: &[u8]) -> [u8; 24] {
    debug_assert_eq!(raw21.len(), 21);
    let mut out = [0u8; 24];
    let (keys, _) = out.as_chunks_mut::<8>();
    let (sevens, _) = raw21.as_chunks::<7>();
    for (key, seven) in keys.iter_mut().zip(sevens) {
        key[..7].copy_from_slice(seven);
        eighth_byte(key);
        fixup_key_parity(key);
    }
    out
}

// MIT eighth_byte; see docs/parity/b1-crypto-keys.md
fn eighth_byte(b: &mut [u8; 8]) {
    b[7] = ((b[0] & 1) << 1)
        | ((b[1] & 1) << 2)
        | ((b[2] & 1) << 3)
        | ((b[3] & 1) << 4)
        | ((b[4] & 1) << 5)
        | ((b[5] & 1) << 6)
        | ((b[6] & 1) << 7);
}

// MIT k5_des_fixup_key_parity; see docs/parity/b1-crypto-keys.md
fn fixup_key_parity(key: &mut [u8; 8]) {
    for b in key {
        let mut x = *b & 0xfe;
        if x.count_ones().is_multiple_of(2) {
            x |= 1;
        }
        *b = x;
    }
}

pub(crate) fn dk_des3(key: &[u8], constant: &[u8]) -> Result<Vec<u8>, Error> {
    let folded = crate::nfold::nfold(constant, DES_BLOCK)?;
    let mut block = [0u8; DES_BLOCK];
    block.copy_from_slice(&folded);
    let mut dr = Wiped(Vec::with_capacity(24));
    while dr.len() < 21 {
        let c = Wiped(des3_cbc_encrypt(key, [0u8; DES_BLOCK], &block)?);
        if c.len() != DES_BLOCK {
            return Err(Error::InvalidKeyLength);
        }
        block.copy_from_slice(&c);
        dr.extend_from_slice(&c);
    }
    dr.truncate(21);
    let k = Zeroizing::new(des3_random_to_key(&dr));
    Ok(k.to_vec())
}

pub(crate) fn camellia_encrypt_with_conf(
    key: &ProtocolKey,
    usage: KeyUsage,
    confounder: &[u8],
    plaintext: &[u8],
    state: &mut crate::CipherState,
) -> Result<Vec<u8>, Error> {
    if confounder.len() != 16 {
        return Err(Error::InvalidConfounder);
    }
    let ke = dk_camellia(key.as_bytes(), &usage.derivation_constant(0xAA))?;
    let ki = dk_camellia(key.as_bytes(), &usage.derivation_constant(0x55))?;
    let mut data = Wiped(Vec::with_capacity(16 + plaintext.len()));
    data.extend_from_slice(confounder);
    data.extend_from_slice(plaintext);
    let c = crate::cts::camellia_encrypt(&ke, &state.iv, &data)?;
    let h = cmac_camellia(&ki, &data)?;
    crate::ops::update_iv(state, &c);
    let mut out = c;
    out.extend_from_slice(&h);
    Ok(out)
}

pub(crate) fn camellia_decrypt(
    key: &ProtocolKey,
    usage: KeyUsage,
    ciphertext: &[u8],
    state: &mut crate::CipherState,
) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < 16 + 16 {
        return Err(Error::CiphertextTooShort);
    }
    let (c, mac) = ciphertext.split_at(ciphertext.len() - 16);
    let ke = dk_camellia(key.as_bytes(), &usage.derivation_constant(0xAA))?;
    let ki = dk_camellia(key.as_bytes(), &usage.derivation_constant(0x55))?;
    let p = crate::cts::camellia_decrypt(&ke, &state.iv, c)?;
    // MIT krb5int_dk_cmac_decrypt; see docs/parity/b1-crypto-state.md
    crate::ops::update_iv(state, c);
    let expected = cmac_camellia(&ki, &p)?;
    crate::derive::mac_verify(mac, &expected)?;
    if p.len() < 16 {
        return Err(Error::CiphertextTooShort);
    }
    Ok(p[16..].to_vec())
}

pub(crate) fn dk_camellia(key: &[u8], constant: &[u8]) -> Result<Vec<u8>, Error> {
    kdf_feedback_cmac(key, constant)
}

pub(crate) fn kdf_feedback_cmac(key: &[u8], constant: &[u8]) -> Result<Vec<u8>, Error> {
    let out_len = key.len();
    if out_len != 16 && out_len != 32 {
        return Err(Error::InvalidKeyLength);
    }
    let k_bits = u32::try_from(out_len.saturating_mul(8)).unwrap_or(u32::MAX);
    let n = out_len.div_ceil(16);
    let mut k_prev = Wiped(vec![0u8; 16]);
    let mut out = Wiped(Vec::with_capacity(n * 16));
    for i in 1..=n {
        let i32 = u32::try_from(i).unwrap_or(u32::MAX);
        let mut input = Wiped(Vec::with_capacity(16 + 4 + constant.len() + 1 + 4));
        input.extend_from_slice(&k_prev);
        input.extend_from_slice(&i32.to_be_bytes());
        input.extend_from_slice(constant);
        input.push(0x00);
        input.extend_from_slice(&k_bits.to_be_bytes());
        let ki = Wiped(cmac_camellia(key, &input)?);
        k_prev.clone_from(&ki.0);
        out.extend_from_slice(&ki);
    }
    out.truncate(out_len);
    Ok(std::mem::take(&mut out.0))
}

pub(crate) fn cmac_camellia(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
    use camellia::{Camellia128, Camellia256};
    use cmac::{Cmac, Mac};
    match key.len() {
        16 => {
            let mut mac = <Cmac<Camellia128> as KeyInit>::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        32 => {
            let mut mac = <Cmac<Camellia256> as KeyInit>::new_from_slice(key)
                .map_err(|_| Error::InvalidKeyLength)?;
            mac.update(data);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        _ => Err(Error::InvalidKeyLength),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dk_des3_is_mits_t_derive_vectors() {
        fn hex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        let key = hex("850bb51358548cd05e86768c313e3bfef7511937dcf72c3e");
        for (constant, want) in [
            (0x99u8, "f78c496d16e6c2dae0e0b6c24057a84c0426aeef26fd6dce"),
            (0xaa, "5b5723d0b634cb684c3eba5264e9a70d52e683231ad3c4ce"),
            (0x55, "a77c94980e9b7345a81525c423a737ce67f4cd91b6b3da45"),
        ] {
            let got = dk_des3(&key, &[0, 0, 0, 2, constant]).unwrap();
            assert_eq!(got, hex(want), "constant {constant:#x}");
        }
    }
}
