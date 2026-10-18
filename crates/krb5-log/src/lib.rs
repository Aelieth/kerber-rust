//! Structured log fields. The daemons' text log is [`klog`].

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::cell::RefCell;
use std::fmt::Write as _;

#[cfg(unix)]
pub mod klog;

/// Canonical `event` field values.
pub mod events {
    /// RFC 3961 string-to-key finished (success or failure).
    pub const CRYPTO_STRING_TO_KEY: &str = "crypto.string_to_key";
    /// RFC 3961 encrypt finished.
    pub const CRYPTO_ENCRYPT: &str = "crypto.encrypt";
    /// RFC 3961 decrypt finished.
    pub const CRYPTO_DECRYPT: &str = "crypto.decrypt";
    /// RFC 3961 keyed checksum finished.
    pub const CRYPTO_CHECKSUM: &str = "crypto.checksum";
    /// DER encode finished.
    pub const ASN1_ENCODE: &str = "asn1.encode";
    /// DER decode finished.
    pub const ASN1_DECODE: &str = "asn1.decode";
    /// AS-REQ sent or AS-REP processed.
    pub const PROTOCOL_AS: &str = "protocol.as";
    /// TGS-REQ sent or TGS-REP processed.
    pub const PROTOCOL_TGS: &str = "protocol.tgs";
    /// KDC returned KRB-ERROR.
    pub const PROTOCOL_KRB_ERROR: &str = "protocol.krb_error";
    /// KDC handled an AS or TGS request.
    pub const KDC_ISSUE: &str = "kdc.issue";
    /// KDC audit plugin record (`kdc_audit.c` / `j_dict.h` field names).
    pub const KDC_AUDIT: &str = "kdc.audit";
    /// Admin ACL decision.
    pub const KDC_ACL: &str = "kdc.acl";
    /// AP-REQ verified or rejected.
    pub const PROTOCOL_AP: &str = "protocol.ap";
    /// KDC UDP/TCP listener.
    pub const KDC_LISTEN: &str = "kdc.listen";
    /// KDC transport event (datagram/connection).
    pub const KDC_TRANSPORT: &str = "kdc.transport";
    /// Client transport (UDP/TCP exchange).
    pub const PROTOCOL_TRANSPORT: &str = "protocol.transport";
    /// Admin protocol (kadmind / kpasswd / kprop).
    pub const ADMIN: &str = "admin";
    /// Client TGS step: a FAST TGS reply that carried a strengthen key (`krb5-protocol`), or
    /// a failed service-ticket request after `kinit`'s AS (`krb5-client`).
    pub const CLIENT_TGS: &str = "client.tgs";
    /// Client PKINIT AS request that carries `PA-PK-AS-REQ`.
    pub const CLIENT_PKINIT: &str = "client.pkinit";
    /// Client FAST unwrap of the inner padata of a KDC error.
    pub const CLIENT_FAST: &str = "client.fast";
    /// KDC lookaside cache reached its byte cap (logged once).
    pub const KDC_LOOKASIDE_FULL: &str = "kdc.lookaside.full";
    /// KDC PKINIT preauth decision.
    pub const KDC_PKINIT: &str = "kdc.pkinit";
    /// A kdcauthdata module returned an error; the KDC logs it and runs the next module.
    pub const KDC_AUTHDATA_MODULE: &str = "kdc.authdata.module";
    /// A secret-file save could not keep the replaced file's owner or group.
    pub const PROTOCOL_SECRET_FILE: &str = "protocol.secret_file";
}

thread_local! {
    static CURRENT: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Restores the previous correlation ID when dropped.
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

/// Set this thread's correlation ID until the guard is dropped.
pub fn enter_correlation(id: impl Into<String>) -> CorrelationGuard {
    let id = id.into();
    CURRENT.with(|c| {
        let prev = c.replace(Some(id));
        CorrelationGuard { prev }
    })
}

/// This thread's correlation ID, or `"none"`.
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
