//! Shared test helpers for kerber-rust.
//!
//! This crate is a `publish = false` **dev-dependency**. Product
//! `[dependencies]` must not take an edge on it.

#![forbid(unsafe_code)]

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_kdc::{
    IssuedAs, PacTicket, PrincipalStore, TEST_REALM, as_req, documented_host, pa_enc_timestamp,
    sign_reply_pac, ticket_checksum_der, wrap_win2k_pac,
};
use krb5_types::EncTicketPart;
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
