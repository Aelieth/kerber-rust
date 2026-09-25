//! Kerberos V5 encryption types (RFC 3961, 3962, 8009).
//!
//! Default profiles are etypes 17–20: string-to-key, key-usage derivation,
//! AES-CTS, and keyed checksums. Etypes 16, 23, 25, and 26 exist only when
//! `allow_weak_crypto` is set. SPAKE, MODP, CF2, and PRF+ sit beside those
//! profiles. Long-term key material is zeroized on drop. There is no
//! `unsafe` code.
//!
//! The public surface is the names this root re-exports. Weak etypes are
//! not part of the default profile.
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

//! Known answers and the logging schema. These examples do not talk to a KDC.
//!
//! RFC 3962 appendix B, AES-128, one iteration:
//!
//! ```
//! use krb5_crypto::{EncryptionType, string_to_key};
//! let key = string_to_key(
//!     EncryptionType::Aes128CtsHmacSha196,
//!     b"password",
//!     b"ATHENA.MIT.EDUraeburn",
//!     Some(&1u32.to_be_bytes()),
//! )?;
//! assert_eq!(
//!     key.as_bytes(),
//!     &[
//!         0x42, 0x26, 0x3c, 0x6e, 0x89, 0xf4, 0xfc, 0x28, 0xb8, 0xdf, 0x68, 0xee, 0x09, 0x79, 0x9f,
//!         0x15,
//!     ]
//! );
//! Ok::<(), krb5_crypto::Error>(())
//! ```
//!
//! RFC 3962 appendix B, AES-256, one iteration:
//!
//! ```
//! use krb5_crypto::{EncryptionType, string_to_key};
//! let key = string_to_key(
//!     EncryptionType::Aes256CtsHmacSha196,
//!     b"password",
//!     b"ATHENA.MIT.EDUraeburn",
//!     Some(&1u32.to_be_bytes()),
//! )?;
//! assert_eq!(
//!     key.as_bytes(),
//!     &[
//!         0xfe, 0x69, 0x7b, 0x52, 0xbc, 0x0d, 0x3c, 0xe1, 0x44, 0x32, 0xba, 0x03, 0x6a, 0x92, 0xe6,
//!         0x5b, 0xbb, 0x52, 0x28, 0x09, 0x90, 0xa2, 0xfa, 0x27, 0x88, 0x39, 0x98, 0xd7, 0x2a, 0xf3,
//!         0x01, 0x61,
//!     ]
//! );
//! Ok::<(), krb5_crypto::Error>(())
//! ```
//!
//! A JSON subscriber sees `event`, `correlation_id`, `component`, and
//! `outcome` on the string-to-key event the library emits:
//!
//! ```
//! use std::io::{self, Write};
//! use std::sync::{Arc, Mutex};
//!
//! use krb5_crypto::{EncryptionType, string_to_key};
//!
//! struct Mem(Arc<Mutex<Vec<u8>>>);
//!
//! impl Write for Mem {
//!     fn write(&mut self, data: &[u8]) -> io::Result<usize> {
//!         self.0
//!             .lock()
//!             .map_err(|_| io::Error::other("poison"))?
//!             .extend_from_slice(data);
//!         Ok(data.len())
//!     }
//!     fn flush(&mut self) -> io::Result<()> {
//!         Ok(())
//!     }
//! }
//!
//! let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
//! let writer = Arc::clone(&buf);
//! assert!(
//!     tracing_subscriber::fmt()
//!         .json()
//!         .with_ansi(false)
//!         .with_current_span(false)
//!         .with_max_level(tracing::Level::INFO)
//!         .with_writer(move || Mem(Arc::clone(&writer)))
//!         .try_init()
//!         .is_ok()
//! );
//!
//! let _ = string_to_key(
//!     EncryptionType::Aes128CtsHmacSha196,
//!     b"password",
//!     b"ATHENA.MIT.EDUraeburn",
//!     Some(&1u32.to_be_bytes()),
//! )?;
//! let text = String::from_utf8(buf.lock().expect("lock").clone()).expect("utf8");
//! fn string_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
//!     let pat = format!("\"{key}\":");
//!     let rest = line[line.find(&pat)? + pat.len()..].trim_start();
//!     let rest = rest.strip_prefix('"')?;
//!     Some(&rest[..rest.find('"')?])
//! }
//! let mut seen = std::collections::BTreeSet::new();
//! for line in text.lines() {
//!     if !line.starts_with('{') {
//!         continue;
//!     }
//!     for key in ["event", "correlation_id", "component", "outcome"] {
//!         assert!(string_field(line, key).is_some(), "{key} missing in {line}");
//!     }
//!     if let Some(event) = string_field(line, "event") {
//!         seen.insert(event.to_owned());
//!     }
//! }
//! assert!(
//!     seen.contains("crypto.string_to_key"),
//!     "library string-to-key did not emit"
//! );
//! assert!(!seen.is_empty());
//! Ok::<(), krb5_crypto::Error>(())
//! ```

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
    P256Keypair, key_from_shared, krb_fx_cf2, octetstring2key, p256_ecdsa_sign, p256_ecdsa_verify,
    p256_generate, p256_shared, pkinit_kdf_agile,
};
pub use derive::{DerivedKeys, derive_keys};
pub use error::Error;
pub use etype::{
    EncryptionType, KeyUsage, cksumtype_is_coll_proof, cksumtype_is_keyed, cksumtype_is_known,
    cksumtype_is_unkeyed, default_enctype_list, parse_enctype_list, parse_keysalt_list,
};
pub use key::ProtocolKey;
pub use modp::{
    DhGroup, DhKeypair, OAKLEY_2048, OAKLEY_4096, dh_generate, dh_group_for_prime, dh_shared,
};
pub use ops::{
    CipherState, checksum, checksum_output_size, decrypt, decrypt_cts, decrypt_with_state, encrypt,
    encrypt_with_confounder, encrypt_with_state, hmac_md5_arcfour_checksum, integrity_mac,
    kdb_decrypt_key, kdb_encrypt_key, string_to_key, unkeyed_checksum, verify_checksum_collproof,
    verify_checksum_keyed, verify_checksum_type,
};
pub use prf::{derive_prfplus, derive_prfplus_enctype, prf, prf_plus};
pub use spake::{
    SPAKE_GROUP_P256, spake_decode_point, spake_derive_key, spake_finish, spake_kdc_keygen,
    spake_m_bytes, spake_n_bytes, spake_public, spake_public_wbytes, spake_result_wbytes,
    spake_thash_update, spake_wbytes,
};
