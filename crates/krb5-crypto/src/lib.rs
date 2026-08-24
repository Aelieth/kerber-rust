//! Kerberos V5 encryption types 17–20 (RFC 3961, 3962, 8009).
//!
//! This crate implements string-to-key, key-usage derivation, AES-CTS
//! encrypt/decrypt, and keyed checksums. Long-term key material is zeroized
//! on drop. There is no `unsafe` code.
//!
//! # Profiles
//!
//! * Etypes 17 and 18 use the RFC 3961 simplified profile (HMAC-SHA-1-96
//!   over confounder||plaintext, DK via n-fold).
//! * Etypes 19 and 20 use RFC 8009 (HMAC-SHA-2 over IV||ciphertext,
//!   SP 800-108 KDF).
//!
//! Key usage 0 is rejected by [`KeyUsage::new`]. MIT KDB `key_data` is the
//! documented exception (`kdb_encrypt_key` / `kdb_decrypt_key` use
//! [`KeyUsage::from_rfc`] with usage 0 plus a cleartext `int16_LE` length
//! prefix). PBKDF2 iteration count 0 (RFC 3962 = 2^32) is rejected as a
//! local DoS control.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod cf2;
mod derive;
mod error;
mod etype;
mod key;
mod modp;
mod nfold;
mod ops;
mod prf;
mod spake;
pub(crate) mod weak;

pub(crate) mod cts;

pub use cf2::{
    key_from_shared, krb_fx_cf2, octetstring2key, p256_ecdsa_sign, p256_ecdsa_verify,
    p256_generate, p256_shared, pkinit_kdf_agile, P256Keypair,
};
pub use derive::{derive_keys, DerivedKeys};
pub use error::Error;
pub use etype::{EncryptionType, KeyUsage};
pub use key::ProtocolKey;
pub use modp::{
    dh_generate, dh_group_for_prime, dh_shared, DhGroup, DhKeypair, OAKLEY_2048, OAKLEY_4096,
};
pub use ops::{
    checksum, decrypt, decrypt_with_state, encrypt, encrypt_with_confounder, encrypt_with_state,
    hmac_md5_arcfour_checksum, kdb_decrypt_key, kdb_encrypt_key, string_to_key, verify_checksum,
    CipherState,
};
pub use prf::{prf, prf_plus};
pub use spake::{
    spake_decode_point, spake_derive_key, spake_finish, spake_kdc_keygen, spake_m_bytes,
    spake_n_bytes, spake_public, spake_public_wbytes, spake_result_wbytes, spake_thash_update,
    spake_wbytes, SPAKE_GROUP_P256,
};
