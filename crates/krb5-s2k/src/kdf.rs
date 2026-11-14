use alloc::vec::Vec;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384};
use zeroize::Zeroize;

use crate::error::S2kError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sha2Kdf {
    Sha256,
    Sha384,
}

macro_rules! hmac_bytes {
    ($d:ty, $key:expr, $data:expr) => {{
        let mut mac =
            <Hmac<$d> as KeyInit>::new_from_slice($key).map_err(|_| S2kError::InvalidKeyLength)?;
        mac.update($data);
        mac.finalize().into_bytes().to_vec()
    }};
}

// MIT: `k5_sp800_108_counter_hmac` (lib/crypto/builtin/kdf.c:33-73)
pub fn kdf_hmac_sha2(
    hash: Sha2Kdf,
    key: &[u8],
    label: &[u8],
    context: Option<&[u8]>,
    k_bits: u32,
) -> Result<Vec<u8>, S2kError> {
    let k_len = (k_bits / 8) as usize;
    let mut msg = Vec::with_capacity(4 + label.len() + 1 + context.map_or(0, <[u8]>::len) + 4);
    msg.extend_from_slice(&1u32.to_be_bytes());
    msg.extend_from_slice(label);
    msg.push(0x00);
    if let Some(ctx) = context {
        msg.extend_from_slice(ctx);
    }
    msg.extend_from_slice(&k_bits.to_be_bytes());

    let mut mac = match hash {
        Sha2Kdf::Sha256 => hmac_bytes!(Sha256, key, &msg),
        Sha2Kdf::Sha384 => hmac_bytes!(Sha384, key, &msg),
    };
    if mac.len() > k_len {
        mac[k_len..].zeroize();
        mac.truncate(k_len);
    }
    Ok(mac)
}
