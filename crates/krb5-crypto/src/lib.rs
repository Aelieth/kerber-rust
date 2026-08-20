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
//! Key usage 0 is rejected. PBKDF2 iteration count 0 (RFC 3962 = 2^32) is
//! rejected as a local DoS control.

#![forbid(unsafe_code)]

mod derive;
mod error;
mod etype;
mod key;
mod nfold;
mod ops;

pub(crate) mod cts;

pub use error::Error;
pub use etype::{EncryptionType, KeyUsage};
pub use key::ProtocolKey;
pub use ops::{checksum, decrypt, encrypt, encrypt_with_confounder, string_to_key};
