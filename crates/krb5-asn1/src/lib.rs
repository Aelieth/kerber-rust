#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::time::Instant;

use rasn::{Decode, Encode};

pub use krb5_types as types;
pub use krb5_types::{
    ApReq, AsRep, AsReq, EncAsRepPart, EncKdcRepPart, EncTgsRepPart, EncTicketPart, EncryptedData,
    KdcRep, KdcReq, KerberosTime, KrbError, PrincipalName, Realm, TgsRep, TgsReq, Ticket,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Encode(String),
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

pub fn encode<T: Encode>(value: &T) -> Result<Vec<u8>, Error> {
    encode_named(value, std::any::type_name::<T>())
}

/// Nonzero remainder decodes.
// MIT: `k5_asn1_full_decode` (lib/krb5/asn.1/asn1_encode.c:1567-1585)
pub fn decode<T: Decode>(bytes: &[u8]) -> Result<T, Error> {
    decode_named(bytes, std::any::type_name::<T>())
}

/// 26, then 25, untagged. A miss is silent.
// MIT: `decode_krb5_enc_kdc_rep_part` (lib/krb5/asn.1/asn1_k_encode.c:1135-1155)
pub fn decode_enc_kdc_rep_part(bytes: &[u8]) -> Result<EncKdcRepPart, Error> {
    if let Ok(EncTgsRepPart(part)) = rasn::der::decode(bytes) {
        return Ok(part);
    }
    if let Ok(EncAsRepPart(part)) = rasn::der::decode(bytes) {
        return Ok(part);
    }
    if let Ok(part) = rasn::der::decode(bytes) {
        return Ok(part);
    }
    Err(Error::Decode(format!(
        "enc-part der tag={:02x} len={}",
        bytes.first().copied().unwrap_or(0),
        bytes.len()
    )))
}

fn encode_named<T: Encode>(value: &T, pdu: &str) -> Result<Vec<u8>, Error> {
    let correlation_id = krb5_log::current_correlation_id();
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
    let correlation_id = krb5_log::current_correlation_id();
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
        tracing::debug!(
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
