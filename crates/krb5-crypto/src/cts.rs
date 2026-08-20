//! AES CBC-CS3 (RFC 3962 / NIST SP 800-38A addendum), matching MIT krb5 1.22.2.

use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128, Aes256,
};
use camellia::{Camellia128, Camellia256};

use crate::error::Error;

pub(crate) const BLOCK: usize = 16;

pub(crate) fn encrypt(key: &[u8], iv: &[u8; BLOCK], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    match key.len() {
        16 => encrypt_with(Aes128::new(GenericArray::from_slice(key)), iv, plaintext),
        32 => encrypt_with(Aes256::new(GenericArray::from_slice(key)), iv, plaintext),
        _ => Err(Error::InvalidKeyLength),
    }
}

pub(crate) fn decrypt(key: &[u8], iv: &[u8; BLOCK], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    match key.len() {
        16 => decrypt_with(Aes128::new(GenericArray::from_slice(key)), iv, ciphertext),
        32 => decrypt_with(Aes256::new(GenericArray::from_slice(key)), iv, ciphertext),
        _ => Err(Error::InvalidKeyLength),
    }
}

/// Single-block AES (ECB). Used by RFC 3961 DR.
pub(crate) fn encrypt_block(key: &[u8], block: &[u8; BLOCK]) -> Result<[u8; BLOCK], Error> {
    let mut out = *block;
    match key.len() {
        16 => {
            let cipher = Aes128::new(GenericArray::from_slice(key));
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut out));
        }
        32 => {
            let cipher = Aes256::new(GenericArray::from_slice(key));
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut out));
        }
        _ => return Err(Error::InvalidKeyLength),
    }
    Ok(out)
}

pub(crate) fn camellia_encrypt(
    key: &[u8],
    iv: &[u8; BLOCK],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    match key.len() {
        16 => encrypt_with(
            Camellia128::new(GenericArray::from_slice(key)),
            iv,
            plaintext,
        ),
        32 => encrypt_with(
            Camellia256::new(GenericArray::from_slice(key)),
            iv,
            plaintext,
        ),
        _ => Err(Error::InvalidKeyLength),
    }
}

pub(crate) fn camellia_decrypt(
    key: &[u8],
    iv: &[u8; BLOCK],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    match key.len() {
        16 => decrypt_with(
            Camellia128::new(GenericArray::from_slice(key)),
            iv,
            ciphertext,
        ),
        32 => decrypt_with(
            Camellia256::new(GenericArray::from_slice(key)),
            iv,
            ciphertext,
        ),
        _ => Err(Error::InvalidKeyLength),
    }
}

pub(crate) fn camellia_encrypt_block(
    key: &[u8],
    block: &[u8; BLOCK],
) -> Result<[u8; BLOCK], Error> {
    let mut out = *block;
    match key.len() {
        16 => {
            let cipher = Camellia128::new(GenericArray::from_slice(key));
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut out));
        }
        32 => {
            let cipher = Camellia256::new(GenericArray::from_slice(key));
            cipher.encrypt_block(GenericArray::from_mut_slice(&mut out));
        }
        _ => return Err(Error::InvalidKeyLength),
    }
    Ok(out)
}

fn xor_in_place(block: &mut [u8; BLOCK], mask: &[u8; BLOCK]) {
    for (b, m) in block.iter_mut().zip(mask) {
        *b ^= *m;
    }
}

fn encrypt_with<C: BlockEncrypt>(
    cipher: C,
    iv: &[u8; BLOCK],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    if plaintext.is_empty() {
        return Err(Error::CiphertextTooShort);
    }
    let nblocks = plaintext.len().div_ceil(BLOCK);
    if nblocks == 1 {
        // RFC 3962: a single block is AES (ECB), equivalent to CBC with IV = 0.
        let mut block = [0u8; BLOCK];
        block[..plaintext.len()].copy_from_slice(plaintext);
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
        let mut out = block.to_vec();
        out.truncate(plaintext.len());
        return Ok(out);
    }

    let mut prev = *iv;
    let mut out = vec![0u8; plaintext.len()];
    let full_prefix = (nblocks - 2) * BLOCK;

    for i in 0..nblocks - 2 {
        let mut block = [0u8; BLOCK];
        block.copy_from_slice(&plaintext[i * BLOCK..(i + 1) * BLOCK]);
        xor_in_place(&mut block, &prev);
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
        prev = block;
        out[i * BLOCK..(i + 1) * BLOCK].copy_from_slice(&block);
    }

    // Last two blocks: CBC-encrypt then write back swapped (MIT krb5int_aes_encrypt).
    let mut block_n2 = [0u8; BLOCK];
    let n2_len = plaintext.len() - full_prefix;
    let take_n2 = n2_len.min(BLOCK);
    block_n2[..take_n2].copy_from_slice(&plaintext[full_prefix..full_prefix + take_n2]);
    xor_in_place(&mut block_n2, &prev);
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut block_n2));
    prev = block_n2;

    let mut block_n1 = [0u8; BLOCK];
    let n1_off = full_prefix + BLOCK;
    if n1_off < plaintext.len() {
        block_n1[..plaintext.len() - n1_off].copy_from_slice(&plaintext[n1_off..]);
    }
    xor_in_place(&mut block_n1, &prev);
    cipher.encrypt_block(GenericArray::from_mut_slice(&mut block_n1));

    // Write C_n (full) then truncated C_{n-1}.
    let last_len = plaintext.len() - (nblocks - 1) * BLOCK;
    out[full_prefix..full_prefix + BLOCK].copy_from_slice(&block_n1);
    let n2_out_off = full_prefix + BLOCK;
    out[n2_out_off..].copy_from_slice(&block_n2[..last_len]);
    Ok(out)
}

fn decrypt_with<C: BlockDecrypt>(
    cipher: C,
    iv: &[u8; BLOCK],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    if ciphertext.is_empty() {
        return Err(Error::CiphertextTooShort);
    }
    let nblocks = ciphertext.len().div_ceil(BLOCK);
    if nblocks == 1 {
        let mut block = [0u8; BLOCK];
        block[..ciphertext.len()].copy_from_slice(ciphertext);
        cipher.decrypt_block(GenericArray::from_mut_slice(&mut block));
        let mut out = block.to_vec();
        out.truncate(ciphertext.len());
        return Ok(out);
    }

    let last_len = ciphertext.len() - (nblocks - 1) * BLOCK;
    let mut out = vec![0u8; ciphertext.len()];
    let mut prev = *iv;
    let full_prefix = (nblocks - 2) * BLOCK;

    for i in 0..nblocks - 2 {
        let mut block = [0u8; BLOCK];
        block.copy_from_slice(&ciphertext[i * BLOCK..(i + 1) * BLOCK]);
        let ccopy = block;
        cipher.decrypt_block(GenericArray::from_mut_slice(&mut block));
        xor_in_place(&mut block, &prev);
        prev = ccopy;
        out[i * BLOCK..(i + 1) * BLOCK].copy_from_slice(&block);
    }

    // blockN2 = next-to-last ciphertext (full AES block = CBC C_n)
    let mut block_n2 = [0u8; BLOCK];
    block_n2.copy_from_slice(&ciphertext[full_prefix..full_prefix + BLOCK]);
    // blockN1 = last ciphertext (possibly partial = stolen C_{n-1})
    let mut block_n1 = [0u8; BLOCK];
    block_n1[..last_len].copy_from_slice(&ciphertext[full_prefix + BLOCK..]);

    let dummy_iv = block_n1;
    let mut pn = block_n2;
    cipher.decrypt_block(GenericArray::from_mut_slice(&mut pn));
    xor_in_place(&mut pn, &dummy_iv);

    block_n1[last_len..].copy_from_slice(&pn[last_len..]);
    let mut pn1 = block_n1;
    cipher.decrypt_block(GenericArray::from_mut_slice(&mut pn1));
    xor_in_place(&mut pn1, &prev);

    out[full_prefix..full_prefix + BLOCK].copy_from_slice(&pn1);
    out[full_prefix + BLOCK..].copy_from_slice(&pn[..last_len]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 3962 Appendix B CBC-CS3 vectors (AES-128, IV = 0).
    #[test]
    fn rfc3962_cts_vectors() {
        let key = hex("636869636b656e207465726979616b69");
        let iv = [0u8; 16];
        let cases = [
            (
                "4920776f756c64206c696b652074686520",
                "c6353568f2bf8cb4d8a580362da7ff7f97",
            ),
            (
                "4920776f756c64206c696b65207468652047656e6572616c20476175277320",
                "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5",
            ),
            (
                "4920776f756c64206c696b65207468652047656e6572616c2047617527732043",
                "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584",
            ),
            (
                "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c",
                "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5",
            ),
            (
                "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20",
                "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8",
            ),
            (
                "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e",
                "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8",
            ),
        ];
        for (pt_hex, ct_hex) in cases {
            let pt = hex(pt_hex);
            let ct = hex(ct_hex);
            assert_eq!(encrypt(&key, &iv, &pt).unwrap(), ct, "encrypt {pt_hex}");
            assert_eq!(decrypt(&key, &iv, &ct).unwrap(), pt, "decrypt {pt_hex}");
        }
    }
}
