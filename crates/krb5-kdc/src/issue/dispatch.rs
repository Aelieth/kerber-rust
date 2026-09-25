//! AS/TGS dispatch (`dispatch.c`, `net-server.c` drop): the UDP/TCP
//! payload switch, the empty-reply arms, and the KRB-ERROR log line.

use std::time::Instant;

use krb5_asn1::decode;
use krb5_types::{AsReq, HostAddress, TgsReq, err};

use super::reply::{as_reply, krb_error_log_fields, tgs_reply};
use crate::error::Error;
use crate::kdb::PrincipalRead;

/// Dispatch one UDP/TCP payload (AS-REQ or TGS-REQ) to the issue path.
///
/// Empty, undecodable, and unknown-tag datagrams yield an empty reply
/// (MIT `dispatch.c` + `net-server.c` drop). Other failures are a KRB-ERROR.
///
/// # Errors
///
/// Only store-programming failures that cannot be encoded as KRB-ERROR.
pub fn handle_request(store: &dyn PrincipalRead, raw: &[u8]) -> Result<Vec<u8>, Error> {
    handle_request_from(store, raw, None)
}

/// Like [`handle_request`], with the UDP/TCP peer for TGS `BADADDR`.
///
/// # Errors
///
/// A store failure that is not a KDC error.
pub fn handle_request_from(
    store: &dyn PrincipalRead,
    raw: &[u8],
    sender: Option<&HostAddress>,
) -> Result<Vec<u8>, Error> {
    let id = krb5_log::new_correlation_id();
    let _g = krb5_log::enter_correlation(id);
    let started = Instant::now();
    krb5_protocol::capture_pdu("kdc-req", raw);
    let result = handle_inner(store, raw, sender);
    if let Ok((bytes, _)) = &result {
        krb5_protocol::capture_pdu("kdc-rep", bytes);
    }
    let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    match result {
        Ok((bytes, detail)) => {
            if bytes.is_empty() {
                return Ok(bytes);
            }
            if bytes.starts_with(&[0x7e]) {
                let (code, mut e_text) = krb_error_log_fields(&bytes);
                if code == err::PREAUTH_REQUIRED && e_text.is_empty() {
                    e_text = "NEEDED_PREAUTH".into();
                }
                log_krb_error(duration_us, code, &e_text, detail.as_deref());
                crate::audit::log_failure(store, raw, sender, &bytes, code, &e_text);
            } else {
                tracing::info!(
                    event = krb5_log::events::KDC_ISSUE,
                    correlation_id = krb5_log::current_correlation_id(),
                    component = "krb5-kdc",
                    duration_us,
                    outcome = "ok",
                );
                crate::audit::log_success(store, raw, sender, &bytes);
            }
            Ok(bytes)
        }
        Err(e) => {
            tracing::error!(
                event = krb5_log::events::KDC_ISSUE,
                correlation_id = krb5_log::current_correlation_id(),
                component = "krb5-kdc",
                duration_us,
                outcome = "error",
                error = %e,
            );
            Err(e)
        }
    }
}

fn log_krb_error(duration_us: u64, code: i32, e_text: &str, detail: Option<&str>) {
    if let Some(d) = detail.filter(|s| !s.is_empty()) {
        tracing::info!(
            event = krb5_log::events::KDC_ISSUE,
            correlation_id = krb5_log::current_correlation_id(),
            component = "krb5-kdc",
            duration_us,
            outcome = "krb-error",
            code,
            e_text,
            detail = d,
        );
    } else {
        tracing::info!(
            event = krb5_log::events::KDC_ISSUE,
            correlation_id = krb5_log::current_correlation_id(),
            component = "krb5-kdc",
            duration_us,
            outcome = "krb-error",
            code,
            e_text,
        );
    }
}

fn handle_inner(
    store: &dyn PrincipalRead,
    raw: &[u8],
    sender: Option<&HostAddress>,
) -> Result<(Vec<u8>, Option<String>), Error> {
    // MIT dispatch.c:145-153: not AS/TGS or decode fail → no response.
    if raw.is_empty() {
        return Ok((Vec::new(), None));
    }
    match raw[0] {
        0x6a => match decode::<AsReq>(raw) {
            Ok(req) if req.0.pvno != krb5_types::KdcReq::PVNO => Ok((Vec::new(), None)),
            Ok(req) => as_reply(store, &req, raw),
            Err(_) => Ok((Vec::new(), None)),
        },
        0x6c => match decode::<TgsReq>(raw) {
            Ok(req) if req.0.pvno != krb5_types::KdcReq::PVNO => Ok((Vec::new(), None)),
            Ok(req) => tgs_reply(store, &req, raw, sender),
            Err(_) => Ok((Vec::new(), None)),
        },
        _ => Ok((Vec::new(), None)),
    }
}
