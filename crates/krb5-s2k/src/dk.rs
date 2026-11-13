use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use alloc::vec::Vec;

use crate::error::S2kError;
use crate::nfold::nfold;

const BLOCK: usize = 16;

// MIT: `k5_derive_random_rfc3961` (lib/crypto/builtin/kdf.c:141-188)
pub fn dk_rfc3961(key: &[u8], constant: &[u8]) -> Result<Vec<u8>, S2kError> {
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
        block = encrypt_block(key, &block)?;
        let need = (k - out.len()).min(BLOCK);
        out.extend_from_slice(&block[..need]);
    }
    Ok(out)
}

fn encrypt_block(key: &[u8], block: &[u8; BLOCK]) -> Result<[u8; BLOCK], S2kError> {
    let mut out = *block;
    match key.len() {
        16 => Aes128::new_from_slice(key)
            .map_err(|_| S2kError::InvalidKeyLength)?
            .encrypt_block((&mut out).into()),
        32 => Aes256::new_from_slice(key)
            .map_err(|_| S2kError::InvalidKeyLength)?
            .encrypt_block((&mut out).into()),
        _ => return Err(S2kError::InvalidKeyLength),
    }
    Ok(out)
}
