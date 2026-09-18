//! Shared test helpers for kerber-rust.
//!
//! This crate is a `publish = false` **dev-dependency**. Product
//! `[dependencies]` must not take an edge on it.

#![forbid(unsafe_code)]

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_kdc::{
    IssuedAs, PacTicket, PrincipalStore, S2K_ITERS, TEST_ADMIN, TEST_REALM, TEST_USER, as_req,
    documented_host, pa_enc_timestamp, sign_reply_pac, ticket_checksum_der, wrap_win2k_pac,
};
use krb5_protocol::{pa_for_user, tgs_req, tgs_req_ex};
use krb5_types::AuthorizationData;
use krb5_types::AuthorizationDataValue;
use krb5_types::EncTicketPart;
use krb5_types::KdcOptions;
use krb5_types::KrbError;
use krb5_types::PaData;
use krb5_types::PrincipalName;
use krb5_types::TgsReq;
use krb5_types::Ticket;
use krb5_types::flag_bit;
use krb5_types::pa;
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

/// Protocol error code + borrowed status text.
///
/// Replaces the local `proto` copies.
///
/// # Panics
///
/// Panics if `err` is not [`krb5_kdc::Error::Protocol`].
#[must_use]
pub fn status(err: &krb5_kdc::Error) -> (i32, Option<&str>) {
    match err {
        krb5_kdc::Error::Protocol { code, text, .. } => (*code, text.as_deref()),
        other => panic!("expected protocol error, got {other:?}"),
    }
}

/// Protocol error code + owned status text.
///
/// Replaces the local `code(Error)` copies. Those copies panic with
/// `{other:?}` (no "expected protocol error" prefix). Must not be
/// merged with [`status`]: borrowed vs owned text, and different
/// panic strings.
///
/// # Panics
///
/// Panics if `err` is not [`krb5_kdc::Error::Protocol`].
#[must_use]
pub fn expect_status(err: krb5_kdc::Error) -> (i32, Option<String>) {
    match err {
        krb5_kdc::Error::Protocol { code, text, .. } => (code, text),
        other => panic!("{other:?}"),
    }
}

/// Protocol code from a `Result`, or `None` if it is not a protocol error.
///
/// Replaces `pac_shape.rs`'s `code(&Result)`. Must not be merged with
/// [`expect_status`]: this returns `Option` and never panics.
#[must_use]
pub fn protocol_code(result: &Result<(), krb5_kdc::Error>) -> Option<i32> {
    match result {
        Err(krb5_kdc::Error::Protocol { code, .. }) => Some(*code),
        _ => None,
    }
}

/// Wire `KRB-ERROR` code + `e-text` (empty string when absent).
///
/// Replaces `a2_r19.rs`'s two-tuple `err_of`. Must not be merged with
/// [`err_of_cname`]: that site also returns the error `cname`.
///
/// # Panics
///
/// Panics if `bytes` is not a `KRB-ERROR` — the same unwrap the copy used.
#[must_use]
pub fn err_of(bytes: &[u8]) -> (i32, String) {
    let e: KrbError = decode(bytes).unwrap();
    let text = e
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok())
        .unwrap_or("")
        .to_owned();
    (e.error_code, text)
}

/// Wire `KRB-ERROR` code, `e-text`, and joined `cname`.
///
/// Replaces `a2_10_caddr.rs`'s three-tuple `err_of`.
///
/// # Panics
///
/// Same unwrap as [`err_of`].
#[must_use]
pub fn err_of_cname(bytes: &[u8]) -> (i32, String, Option<String>) {
    let e: KrbError = decode(bytes).unwrap();
    let text = e
        .e_text
        .as_ref()
        .and_then(|t| std::str::from_utf8(t.as_bytes()).ok())
        .unwrap_or("")
        .to_owned();
    let cname = e.cname.as_ref().map(PrincipalName::components_joined);
    (e.error_code, text, cname)
}

/// S4U TGS-REQ: header TGT, client = documented host, caller `sname` / padata / opts.
///
/// Replaces `a2_r17.rs`. Etypes are [`pref_etypes`].
///
/// # Panics
///
/// Panics if `tgs_req_ex` fails — the same unwrap the copy used.
#[must_use]
pub fn s4u_tgs(
    tgt: &IssuedAs,
    sname: PrincipalName,
    padata: Vec<PaData>,
    nonce: u32,
    opts: KdcOptions,
) -> TgsReq {
    let host = documented_host();
    tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        sname,
        TEST_REALM,
        nonce,
        opts,
        None,
        padata,
        pref_etypes(),
    )
    .unwrap()
}

/// S4U2Self TGS-REQ for the documented host with FORWARDABLE and caller padata.
///
/// Replaces `a2_7_s4u2self.rs`.
///
/// # Panics
///
/// Same unwrap as [`s4u_tgs`].
#[must_use]
pub fn s4u_self(tgt: &IssuedAs, padata: Vec<PaData>, nonce: u32) -> TgsReq {
    s4u_tgs(
        tgt,
        documented_host(),
        padata,
        nonce,
        KdcOptions::forwardable(),
    )
}

/// S4U2Self TGS-REQ impersonating `TEST_ADMIN` with a single AES-256 etype.
///
/// Replaces `a3_r27.rs`. Must not call [`s4u_tgs`]: that site's etype
/// list is AES-256 only, not [`pref_etypes`].
///
/// # Panics
///
/// Panics if `pa_for_user` or `tgs_req_ex` fails — the same unwraps
/// the copy used.
#[must_use]
pub fn s4u_admin(tgt: &IssuedAs, nonce: u32, opts: KdcOptions) -> TgsReq {
    let host = documented_host();
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let pa = pa_for_user(&tgt.session_key, admin, TEST_REALM).unwrap();
    tgs_req_ex(
        tgt.rep.0.ticket.clone(),
        &tgt.session_key,
        TEST_REALM,
        &host,
        host.clone(),
        TEST_REALM,
        nonce,
        opts,
        None,
        vec![pa],
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap()
}

/// Admin TGS for `TEST_USER` — S4U2Proxy evidence ticket.
///
/// Replaces the two `evidence_for_user` copies. `a2_8` already used
/// [`issue_tgt`]; `a4_18b` inlined the same store-key AS.
///
/// # Panics
///
/// Panics if the admin TGT, `tgs_req`, or `issue_tgs` fails — the
/// same unwraps the copies used.
#[must_use]
pub fn evidence_for_user(store: &PrincipalStore, nonce: u32) -> Ticket {
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
    let admin_tgt = issue_tgt(store, TEST_ADMIN, nonce);
    let req = tgs_req(
        admin_tgt.rep.0.ticket,
        &admin_tgt.session_key,
        TEST_REALM,
        &admin,
        user,
        TEST_REALM,
        nonce + 1,
    )
    .unwrap();
    krb5_kdc::issue_tgs(store, &req).unwrap().rep.0.ticket
}

/// IF-RELEVANT wrapper around inner authdata elements.
///
/// Replaces the three test copies (`a3_13`, `a3_r28`, `a3_r29`).
/// Product `ad.rs` stays `Result`-returning and is not this helper.
///
/// # Panics
///
/// Panics if DER encode fails — the same unwrap the copies used.
#[must_use]
pub fn wrap_if_relevant(inner: &[AuthorizationDataValue]) -> AuthorizationData {
    let wrapped = encode(&inner.to_vec()).unwrap();
    vec![AuthorizationDataValue {
        ad_type: pa::AD_IF_RELEVANT,
        ad_data: wrapped.into(),
    }]
}
