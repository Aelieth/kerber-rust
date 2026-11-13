use alloc::vec;
use alloc::vec::Vec;
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Sha256, Sha384};
use zeroize::Zeroizing;

use crate::dk::dk_rfc3961;
use crate::error::S2kError;
use crate::kdf::{Sha2Kdf, kdf_hmac_sha2};

pub const MAX_ITERATIONS: u32 = 0x100_0000;

const AES128_SHA1: i32 = 17;
const AES256_SHA1: i32 = 18;
const AES128_SHA256: i32 = 19;
const AES256_SHA384: i32 = 20;

fn default_iterations(enctype: i32) -> Result<u32, S2kError> {
    match enctype {
        AES128_SHA1 | AES256_SHA1 => Ok(4_096),
        AES128_SHA256 | AES256_SHA384 => Ok(32_768),
        n => Err(S2kError::UnsupportedEtype(n)),
    }
}

// MIT: `pbkdf2_string_to_key` (lib/crypto/krb/s2k_pbkdf2.c:122-141)
pub fn string_to_key(
    enctype: i32,
    password: &[u8],
    salt: &[u8],
    params: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, S2kError> {
    let default = default_iterations(enctype)?;
    let iterations = match params {
        None => default,
        Some(p) => {
            let n = u32::from_be_bytes(p.try_into().map_err(|_| S2kError::BadParams)?);
            if n < default {
                return Err(S2kError::BadParams);
            }
            n
        }
    };
    if iterations >= MAX_ITERATIONS {
        return Err(S2kError::BadParams);
    }
    string_to_key_iter(enctype, password, salt, iterations)
}

// MIT: `pbkdf2_string_to_key` (lib/crypto/krb/s2k_pbkdf2.c:142-179)
pub fn string_to_key_iter(
    enctype: i32,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<Vec<u8>>, S2kError> {
    let (key_len, name, hash) = match enctype {
        AES128_SHA1 => (16, None, None),
        AES256_SHA1 => (32, None, None),
        AES128_SHA256 => (
            16,
            Some("aes128-cts-hmac-sha256-128"),
            Some(Sha2Kdf::Sha256),
        ),
        AES256_SHA384 => (
            32,
            Some("aes256-cts-hmac-sha384-192"),
            Some(Sha2Kdf::Sha384),
        ),
        n => return Err(S2kError::UnsupportedEtype(n)),
    };
    let mut tkey = Zeroizing::new(vec![0u8; key_len]);
    let Some((name, hash)) = name.zip(hash) else {
        pbkdf2_hmac::<Sha1>(password, salt, iterations, &mut tkey);
        return Ok(Zeroizing::new(dk_rfc3961(&tkey, b"kerberos")?));
    };
    let mut saltp = Vec::with_capacity(name.len() + 1 + salt.len());
    saltp.extend_from_slice(name.as_bytes());
    saltp.push(0x00);
    saltp.extend_from_slice(salt);
    match hash {
        Sha2Kdf::Sha256 => pbkdf2_hmac::<Sha256>(password, &saltp, iterations, &mut tkey),
        Sha2Kdf::Sha384 => pbkdf2_hmac::<Sha384>(password, &saltp, iterations, &mut tkey),
    }
    let bits = u32::try_from(key_len * 8).map_err(|_| S2kError::InvalidKeyLength)?;
    Ok(Zeroizing::new(kdf_hmac_sha2(
        hash,
        &tkey,
        b"kerberos",
        None,
        bits,
    )?))
}
