//! Structured logging schema for kerber-rust.
//!
//! Library crates emit [`tracing`] events using the field names in this
//! module. Applications and tests install a subscriber; this crate does not.
//!
//! # Event fields
//!
//! Every foundation event SHOULD include:
//!
//! | Field | Meaning |
//! | --- | --- |
//! | `event` | Stable name from [`events`] |
//! | `correlation_id` | Hex ID tying one operation together |
//! | `component` | Emitting crate (`krb5-crypto`, `krb5-asn1`, `harness`) |
//! | `outcome` | `"ok"` or `"error"` |
//!
//! Crypto operations also emit `etype` (IANA number), `key_usage`, and
//! `duration_us`. Failures emit `error` with the Display form of the error.
//! ASN.1 operations emit `pdu` (type name) and `byte_len`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::cell::RefCell;
use std::fmt::Write as _;

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
    /// MIT KDC harness process started.
    pub const HARNESS_START: &str = "harness.start";
    /// MIT KDC is accepting clients.
    pub const HARNESS_KDC_READY: &str = "harness.kdc.ready";
    /// In-harness `kinit` finished.
    pub const HARNESS_KINIT: &str = "harness.kinit";
    /// AS-REQ sent or AS-REP processed.
    pub const PROTOCOL_AS: &str = "protocol.as";
    /// TGS-REQ sent or TGS-REP processed.
    pub const PROTOCOL_TGS: &str = "protocol.tgs";
    /// KDC returned KRB-ERROR.
    pub const PROTOCOL_KRB_ERROR: &str = "protocol.krb_error";
    /// KDC handled an AS or TGS request.
    pub const KDC_ISSUE: &str = "kdc.issue";
    /// Admin ACL decision.
    pub const KDC_ACL: &str = "kdc.acl";
    /// AP-REQ verified or rejected.
    pub const PROTOCOL_AP: &str = "protocol.ap";
    /// AP-REP processed.
    pub const PROTOCOL_AP_REP: &str = "protocol.ap_rep";
    /// KDC UDP/TCP listener.
    pub const KDC_LISTEN: &str = "kdc.listen";
    /// KDC transport event (datagram/connection).
    pub const KDC_TRANSPORT: &str = "kdc.transport";
    /// Client transport (UDP/TCP exchange).
    pub const PROTOCOL_TRANSPORT: &str = "protocol.transport";
    /// GSS wrap/unwrap/MIC.
    pub const GSS: &str = "gss";
    /// Admin protocol (kadmind / kpasswd / kprop).
    pub const ADMIN: &str = "admin";
    /// Config / discovery.
    pub const CONFIG: &str = "config";
}

/// Tracing field name for the correlation ID.
pub const FIELD_CORRELATION_ID: &str = "correlation_id";
/// Tracing field name for the stable event name.
pub const FIELD_EVENT: &str = "event";
/// Tracing field name for the emitting component.
pub const FIELD_COMPONENT: &str = "component";
/// Tracing field name for IANA etype.
pub const FIELD_ETYPE: &str = "etype";
/// Tracing field name for RFC 3961 key usage.
pub const FIELD_KEY_USAGE: &str = "key_usage";
/// Tracing field name for duration in microseconds.
pub const FIELD_DURATION_US: &str = "duration_us";
/// Tracing field name for `"ok"` / `"error"`.
pub const FIELD_OUTCOME: &str = "outcome";
/// Tracing field name for an error Display string.
pub const FIELD_ERROR: &str = "error";
/// Tracing field name for the PDU type name.
pub const FIELD_PDU: &str = "pdu";
/// Tracing field name for encoded/decoded byte length.
pub const FIELD_BYTE_LEN: &str = "byte_len";

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

/// Set the parent correlation ID for this thread until the guard is dropped.
///
/// Crypto and ASN.1 log using [`current_correlation_id`] so one KDC exchange
/// keeps a single ID.
pub fn enter_correlation(id: impl Into<String>) -> CorrelationGuard {
    let id = id.into();
    CURRENT.with(|c| {
        let prev = c.replace(Some(id));
        CorrelationGuard { prev }
    })
}

/// Correlation ID for the current exchange, or `"none"` if unset.
///
/// Crypto and ASN.1 must not mint a new ID per operation.
#[must_use]
pub fn current_correlation_id() -> String {
    CURRENT.with(|c| c.borrow().clone().unwrap_or_else(|| "none".into()))
}

/// Allocate a 128-bit correlation ID encoded as 32 lowercase hex characters.
///
/// Uses the OS CSPRNG when available. If the CSPRNG fails, falls back to a
/// timestamp-derived value so logging still works; that fallback is not a
/// cryptographic identifier.
#[must_use]
pub fn new_correlation_id() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        bytes[..8].copy_from_slice(&nanos.to_be_bytes()[..8]);
        bytes[8..].copy_from_slice(&nanos.to_le_bytes()[..8]);
    }
    let mut out = String::with_capacity(32);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlation_id_is_32_hex_chars() {
        let id = new_correlation_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn parent_correlation_is_visible_until_guard_drops() {
        assert_eq!(current_correlation_id(), "none");
        let id = new_correlation_id();
        {
            let _g = enter_correlation(id.clone());
            assert_eq!(current_correlation_id(), id);
        }
        assert_eq!(current_correlation_id(), "none");
    }
}
