//! DER encode/decode for RFC 4120 core types.
//!
//! Encoding and decoding go through [`rasn`]'s DER codec. Truncated or
//! malformed encodings return [`Error`]; they never panic.

#![forbid(unsafe_code)]

use std::time::Instant;

use rasn::{Decode, Encode};

pub use krb5_types as types;
pub use krb5_types::{
    ApReq, AsRep, AsReq, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, EncryptedData, KdcRep, KdcReq,
    KerberosTime, KrbError, PrincipalName, Realm, TgsRep, TgsReq, Ticket,
};

/// Codec failure. Malformed and truncated input both surface here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// rasn refused to encode the value as DER.
    Encode(String),
    /// rasn refused to decode the bytes as DER of the requested type.
    Decode(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encode(s) => write!(f, "DER encode failed: {s}"),
            Self::Decode(s) => write!(f, "DER decode failed: {s}"),
        }
    }
}

impl std::error::Error for Error {}

/// DER-encode `value`.
///
/// # Errors
///
/// Returns [`Error::Encode`] when the value cannot be represented in DER.
pub fn encode<T: Encode>(value: &T) -> Result<Vec<u8>, Error> {
    encode_named(value, std::any::type_name::<T>())
}

/// DER-decode `bytes` as `T`.
///
/// # Errors
///
/// Returns [`Error::Decode`] on truncated or malformed encodings. Does not panic.
pub fn decode<T: Decode>(bytes: &[u8]) -> Result<T, Error> {
    decode_named(bytes, std::any::type_name::<T>())
}

/// Encode and immediately decode, used by tests and the consumer.
///
/// # Errors
///
/// Returns encode or decode errors. Successful results are not compared here.
pub fn round_trip<T: Encode + Decode>(value: &T) -> Result<T, Error> {
    let bytes = encode(value)?;
    decode(&bytes)
}

fn encode_named<T: Encode>(value: &T, pdu: &str) -> Result<Vec<u8>, Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let started = Instant::now();
    match rasn::der::encode(value) {
        Ok(bytes) => {
            emit(
                krb5_log::events::ASN1_ENCODE,
                &correlation_id,
                pdu,
                bytes.len(),
                started,
                None,
            );
            Ok(bytes)
        }
        Err(e) => {
            let err = Error::Encode(e.to_string());
            emit(
                krb5_log::events::ASN1_ENCODE,
                &correlation_id,
                pdu,
                0,
                started,
                Some(&err),
            );
            Err(err)
        }
    }
}

fn decode_named<T: Decode>(bytes: &[u8], pdu: &str) -> Result<T, Error> {
    let correlation_id = krb5_log::new_correlation_id();
    let started = Instant::now();
    match rasn::der::decode(bytes) {
        Ok(v) => {
            emit(
                krb5_log::events::ASN1_DECODE,
                &correlation_id,
                pdu,
                bytes.len(),
                started,
                None,
            );
            Ok(v)
        }
        Err(e) => {
            let err = Error::Decode(e.to_string());
            emit(
                krb5_log::events::ASN1_DECODE,
                &correlation_id,
                pdu,
                bytes.len(),
                started,
                Some(&err),
            );
            Err(err)
        }
    }
}

fn emit(
    event: &'static str,
    correlation_id: &str,
    pdu: &str,
    byte_len: usize,
    started: Instant,
    err: Option<&Error>,
) {
    let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    if let Some(e) = err {
        tracing::error!(
            event,
            correlation_id,
            component = "krb5-asn1",
            pdu,
            byte_len,
            duration_us,
            outcome = "error",
            error = %e,
        );
    } else {
        tracing::info!(
            event,
            correlation_id,
            component = "krb5-asn1",
            pdu,
            byte_len,
            duration_us,
            outcome = "ok",
        );
    }
}
