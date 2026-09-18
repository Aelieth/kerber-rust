//! Shared test helpers for kerber-rust.
//!
//! This crate is a `publish = false` **dev-dependency**. Product
//! `[dependencies]` must not take an edge on it.

#![forbid(unsafe_code)]

use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_kdc::{
    IssuedAs, PacTicket, PrincipalStore, S2K_ITERS, TEST_REALM, TEST_USER, as_req, documented_host,
    pa_enc_timestamp, sign_reply_pac, ticket_checksum_der, wrap_win2k_pac,
};
use krb5_types::EncTicketPart;
use krb5_types::PrincipalName;
use krb5_types::flag_bit;
use krb5_types::pac::{PAC_CLIENT_INFO, Pac, PacBuffer, PacIdentity, RpcSid, client_info_buffer};

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

/// AES-256 string-to-key of `password` with `name`'s default realm salt.
///
/// Replaces the eleven local `password_key` copies in `krb5-kdc` tests.
/// Those copies differed only in `unwrap` vs `expect("s2k")` and whether
/// the salt was bound to a local.
///
/// # Panics
///
/// Panics if string-to-key fails — the same expect/unwrap the copies used.
#[must_use]
pub fn password_key(name: &str, password: &[u8]) -> ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        password,
        cname.default_salt(TEST_REALM),
        Some(&S2K_ITERS.to_be_bytes()),
    )
    .expect("s2k")
}

/// Best long-term key for the NT_PRINCIPAL named `name`.
///
/// # Panics
///
/// Panics if `name` is missing from `store` or has no key.
#[must_use]
pub fn store_key(store: &PrincipalStore, name: &str) -> ProtocolKey {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    store
        .get_name(&cname)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone()
}

fn as_tgt(
    store: &PrincipalStore,
    name: &str,
    nonce: u32,
    key: &ProtocolKey,
    renewable: bool,
) -> IssuedAs {
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]);
    let mut req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(key).unwrap()]),
    )
    .unwrap();
    if renewable {
        req.0.req_body.kdc_options = req
            .0
            .req_body
            .kdc_options
            .with_bit(flag_bit::RENEWABLE, true);
        req.0.req_body.rtime = Some(req.0.req_body.till.add_hours(48).expect("rtime"));
    }
    krb5_kdc::issue_as(store, &req).unwrap()
}

/// AS-issued TGT for `name` using the store's best long-term key.
///
/// Replaces the store-key `issue_tgt` copies (unused-password and
/// `TEST_USER`-only signatures).
///
/// # Panics
///
/// Panics if the principal is missing, timestamp preauth fails, or
/// `issue_as` fails — the same unwraps the local copies used.
#[must_use]
pub fn issue_tgt(store: &PrincipalStore, name: &str, nonce: u32) -> IssuedAs {
    let key = store_key(store, name);
    as_tgt(store, name, nonce, &key, false)
}

/// AS-issued TGT for `name` using string-to-key of `password`.
///
/// Replaces the `password_key` `issue_tgt` copies (`unwrap` and
/// `expect("pa")`/`expect("AS")`).
///
/// # Panics
///
/// Panics if string-to-key, timestamp preauth, or `issue_as` fails.
#[must_use]
pub fn issue_tgt_password(
    store: &PrincipalStore,
    name: &str,
    password: &[u8],
    nonce: u32,
) -> IssuedAs {
    let key = password_key(name, password);
    as_tgt(store, name, nonce, &key, false)
}

/// Like [`issue_tgt`] but optionally sets RENEWABLE and `rtime` +48h.
///
/// Replaces `a2_r16.rs`'s four-argument `issue_tgt`.
///
/// # Panics
///
/// Same unwraps as [`issue_tgt`], plus `add_hours(48)` if `renewable`.
#[must_use]
pub fn issue_tgt_renewable(
    store: &PrincipalStore,
    name: &str,
    nonce: u32,
    renewable: bool,
) -> IssuedAs {
    let key = store_key(store, name);
    as_tgt(store, name, nonce, &key, renewable)
}

/// AS-issued TGT for `TEST_USER` using the store's best key.
///
/// Replaces the eight two-argument `user_as` copies (`PrincipalName`
/// inline vs a local `user()`/`cname()` helper).
///
/// # Panics
///
/// Same unwraps as [`issue_tgt`].
#[must_use]
pub fn user_as(store: &PrincipalStore, nonce: u32) -> IssuedAs {
    issue_tgt(store, TEST_USER, nonce)
}

/// Like [`user_as`] but applies `bits` to `kdc_options` before issue.
///
/// Replaces `a3_11.rs` and `a3_r26.rs`.
///
/// # Panics
///
/// Same unwraps as [`user_as`].
#[must_use]
pub fn user_as_bits(store: &PrincipalStore, nonce: u32, bits: &[(usize, bool)]) -> IssuedAs {
    let key = store_key(store, TEST_USER);
    let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut req = as_req(
        cname,
        TEST_REALM,
        nonce,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    for (bit, on) in bits {
        req.0.req_body.kdc_options = req.0.req_body.kdc_options.with_bit(*bit, *on);
    }
    krb5_kdc::issue_as(store, &req).unwrap()
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

/// Sign a Win2k PAC onto an existing ticket part using `key` as both
/// server and KDC key.
///
/// Replaces the four identical `attach_pac` copies in `krb5-kdc` tests.
///
/// # Panics
///
/// Panics if PAC wrap, ticket-checksum DER, or `sign_reply_pac` fails —
/// the same unwraps the local copies used.
pub fn attach_pac(key: &ProtocolKey, part: &mut EncTicketPart, info_name: &str) {
    let stub = Pac::built(
        0,
        vec![PacBuffer::new(
            PAC_CLIENT_INFO,
            client_info_buffer(part.authtime.unix_seconds(), info_name),
        )],
    )
    .to_bytes();
    part.authorization_data = Some(wrap_win2k_pac(&[0]).unwrap());
    let der = ticket_checksum_der(part).unwrap();
    let ident = PacIdentity {
        sam: part.cname.components_joined(),
        realm: String::new(),
        domain_sid: RpcSid::nt_domain(1, 2, 3),
        rid: 1,
    };
    let pac = sign_reply_pac(
        &part.cname,
        part.authtime.unix_seconds(),
        &PacTicket {
            server: key,
            kdc: key,
            enc_tkt_der: &der,
            is_service_tkt: false,
        },
        &ident,
        None,
        Some(&stub),
    )
    .unwrap();
    part.authorization_data = Some(wrap_win2k_pac(&pac).unwrap());
}
