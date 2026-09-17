//! Shared test helpers for kerber-rust.
//!
//! This crate is a `publish = false` **dev-dependency**. Product
//! `[dependencies]` must not take an edge on it.

#![forbid(unsafe_code)]

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_kdc::{IssuedAs, PrincipalStore, TEST_REALM, as_req, documented_host, pa_enc_timestamp};

/// IANA etype numbers in MIT `preferred()` order.
///
/// Replaces the local `pref_etypes` copies in `krb5-kdc` tests. The two
/// in-tree spellings (`EncryptionType::preferred` vs
/// `krb5_crypto::EncryptionType::preferred`) were the same body.
#[must_use]
pub fn pref_etypes() -> Vec<i32> {
    EncryptionType::preferred()
        .iter()
        .map(|e| e.to_iana())
        .collect()
}

/// AES-256 key of 32 repeated `seed` bytes.
///
/// Replaces the five identical `aes_key` copies in `krb5-kdc` tests.
///
/// # Panics
///
/// Panics if 32 bytes is not a valid AES-256 key length (it is).
#[must_use]
pub fn aes_key(seed: u8) -> ProtocolKey {
    ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[seed; 32]).expect("key")
}

/// AS-issued TGT for the documented POSIX host principal.
///
/// Replaces the five identical `host_tgt` copies in `krb5-kdc` tests.
///
/// # Panics
///
/// Panics if the documented host is missing from `store`, has no key,
/// timestamp preauth fails, or `issue_as` fails — the same unwraps the
/// local copies used.
#[must_use]
pub fn host_tgt(store: &PrincipalStore, nonce: u32) -> IssuedAs {
    let host = documented_host();
    let key = store
        .get_name(&host)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    let req = as_req(
        host,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    krb5_kdc::issue_as(store, &req).unwrap()
}
