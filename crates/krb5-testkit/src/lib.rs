//! Shared test helpers for kerber-rust.
//!
//! This crate is a `publish = false` **dev-dependency**. Product
//! `[dependencies]` must not take an edge on it.

#![forbid(unsafe_code)]

use krb5_crypto::EncryptionType;

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
