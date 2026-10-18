#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::cell::RefCell;
use std::fmt::Write as _;

#[cfg(unix)]
pub mod klog;

pub mod events {
    pub const CRYPTO_STRING_TO_KEY: &str = "crypto.string_to_key";
    pub const CRYPTO_ENCRYPT: &str = "crypto.encrypt";
    pub const CRYPTO_DECRYPT: &str = "crypto.decrypt";
    pub const CRYPTO_CHECKSUM: &str = "crypto.checksum";
    pub const ASN1_ENCODE: &str = "asn1.encode";
    pub const ASN1_DECODE: &str = "asn1.decode";
    pub const PROTOCOL_AS: &str = "protocol.as";
    pub const PROTOCOL_TGS: &str = "protocol.tgs";
    pub const PROTOCOL_KRB_ERROR: &str = "protocol.krb_error";
    pub const KDC_ISSUE: &str = "kdc.issue";
    pub const KDC_AUDIT: &str = "kdc.audit";
    pub const KDC_ACL: &str = "kdc.acl";
    pub const PROTOCOL_AP: &str = "protocol.ap";
    pub const KDC_LISTEN: &str = "kdc.listen";
    pub const KDC_TRANSPORT: &str = "kdc.transport";
    pub const PROTOCOL_TRANSPORT: &str = "protocol.transport";
    pub const ADMIN: &str = "admin";
    pub const CLIENT_TGS: &str = "client.tgs";
    pub const CLIENT_PKINIT: &str = "client.pkinit";
    pub const CLIENT_FAST: &str = "client.fast";
    pub const KDC_LOOKASIDE_FULL: &str = "kdc.lookaside.full";
    pub const KDC_PKINIT: &str = "kdc.pkinit";
    pub const KDC_AUTHDATA_MODULE: &str = "kdc.authdata.module";
    pub const PROTOCOL_SECRET_FILE: &str = "protocol.secret_file";
}

thread_local! {
    static CURRENT: RefCell<Option<String>> = const { RefCell::new(None) };
}

pub struct CorrelationGuard {
    prev: Option<String>,
}

impl Drop for CorrelationGuard {
    fn drop(&mut self) {
        CURRENT.with(|c| {
            *c.borrow_mut() = self.prev.take();
        });
    }
}

pub fn enter_correlation(id: impl Into<String>) -> CorrelationGuard {
    let id = id.into();
    CURRENT.with(|c| {
        let prev = c.replace(Some(id));
        CorrelationGuard { prev }
    })
}

#[must_use]
pub fn current_correlation_id() -> String {
    CURRENT.with(|c| c.borrow().clone().unwrap_or_else(|| "none".into()))
}

/// 32 lowercase hex characters; a timestamp mix if the CSPRNG fails.
#[must_use]
pub fn new_correlation_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        bytes[..8].copy_from_slice(&nanos.to_be_bytes()[..8]);
        bytes[8..].copy_from_slice(&nanos.to_le_bytes()[..8]);
    }
    let mut out = String::with_capacity(32);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}
