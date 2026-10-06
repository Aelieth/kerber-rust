//! AS/TGS dispatch (`dispatch.c`): the lookaside, the request's decode, AS or TGS processing, the
//! UDP reply size, and the KRB-ERROR log line; [`KdcDispatch`] is what the net-server loop calls.

use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Instant;

use krb5_asn1::decode;
use krb5_log::klog::Severity;
use krb5_types::{AsReq, HostAddress, TgsReq, err};

use super::reply::{as_reply, krb_error_log_fields, tgs_reply};
use crate::audit::{KdcAudit, restore_thread_audit, take_thread_audit};
use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::listen::{SharedStore, plain_store, read_store};
use crate::lookaside::{Check, Lookaside};
use crate::net_server::{Dispatch, Log, Reply};
use crate::plugins::{
    KdcAuthdata, KdcPolicy, KdcPreauth, restore_thread_authdata, restore_thread_policy,
    restore_thread_preauth, take_thread_authdata, take_thread_policy, take_thread_preauth,
};

/// Dispatch one UDP/TCP payload (AS-REQ or TGS-REQ) to the issue path.
///
/// A request MIT's dispatch refuses (empty, not an AS-REQ or TGS-REQ, one that does not decode,
/// a protocol version other than 5, no server name) yields an empty reply, as MIT sends none.
/// Other failures are a KRB-ERROR.
///
/// # Errors
///
/// [`Error::Asn1`] when an issued AS-REP or TGS-REP does not encode; every refusal is returned as
/// KRB-ERROR bytes instead.
pub fn handle_request(store: &dyn PrincipalRead, raw: &[u8]) -> Result<Vec<u8>, Error> {
    handle_request_from(store, raw, None)
}

/// Like [`handle_request`], with the UDP/TCP peer for TGS `BADADDR`.
///
/// # Errors
///
/// [`Error::Asn1`] when an issued AS-REP or TGS-REP does not encode; every refusal is returned as
/// KRB-ERROR bytes instead.
pub fn handle_request_from(
    store: &dyn PrincipalRead,
    raw: &[u8],
    sender: Option<&HostAddress>,
) -> Result<Vec<u8>, Error> {
    match process_logged(store, raw, sender)? {
        Processed::Reply(bytes) => Ok(bytes),
        Processed::Refused(_) => Ok(Vec::new()),
    }
}

/// What processing one request gave: reply bytes (empty for an AS-REQ a preauth module
/// discarded), or MIT's error text for a request its dispatch refuses before processing.
enum Processed {
    Reply(Vec<u8>),
    Refused(&'static str),
}

/// [`handle_inner`] under the request's correlation id, with its PDU captured and its outcome
/// logged.
fn process_logged(
    store: &dyn PrincipalRead,
    raw: &[u8],
    sender: Option<&HostAddress>,
) -> Result<Processed, Error> {
    let id = krb5_log::new_correlation_id();
    let _g = krb5_log::enter_correlation(id);
    let started = Instant::now();
    krb5_protocol::capture_pdu("kdc-req", raw);
    let result = handle_inner(store, raw, sender);
    if let Ok(Inner::Reply(bytes, _)) = &result {
        krb5_protocol::capture_pdu("kdc-rep", bytes);
    }
    let duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    match result {
        Ok(Inner::Refused(text)) => Ok(Processed::Refused(text)),
        Ok(Inner::Reply(bytes, detail)) => {
            if bytes.is_empty() {
                return Ok(Processed::Reply(bytes));
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
            Ok(Processed::Reply(bytes))
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

/// What [`handle_inner`] made of a request.
enum Inner {
    /// The reply and the log detail.
    Reply(Vec<u8>, Option<String>),
    /// MIT's error text for a request dispatch refuses.
    Refused(&'static str),
}

/// MIT `krb5int_is_app_tag` (`include/k5-int.h:1334-1336`): the first byte, its constructed bit cleared, is `0x40 | tag`.
fn is_app_tag(raw: &[u8], tag: u8) -> bool {
    raw.first().is_some_and(|b| b & !0x20 == 0x40 | tag)
}

/// MIT `dispatch` (`kdc/dispatch.c:145-170`): a TGS-REQ is tried first, then an AS-REQ, anything else is a message-type error; a request that does not decode, or whose server is not named, is refused before processing.
/// MIT `setup_server_realm` (`kdc/main.c:123-124`): a request with no server has no realm.
fn handle_inner(
    store: &dyn PrincipalRead,
    raw: &[u8],
    sender: Option<&HostAddress>,
) -> Result<Inner, Error> {
    if is_app_tag(raw, 12) {
        return match decode_kdc_req(raw, 12, decode::<TgsReq>) {
            Err(text) => Ok(Inner::Refused(text)),
            Ok(req) if req.0.req_body.sname.is_none() => Ok(Inner::Refused(WRONG_REALM)),
            Ok(req) => tgs_reply(store, &req, raw, sender).map(|(b, d)| Inner::Reply(b, d)),
        };
    }
    if is_app_tag(raw, 10) {
        return match decode_kdc_req(raw, 10, decode::<AsReq>) {
            Err(text) => Ok(Inner::Refused(text)),
            Ok(req) if req.0.req_body.sname.is_none() => Ok(Inner::Refused(WRONG_REALM)),
            Ok(req) => as_reply(store, &req, raw).map(|(b, d)| Inner::Reply(b, d)),
        };
    }
    Ok(Inner::Refused(MSG_TYPE))
}

/// MIT `KRB5KRB_AP_ERR_MSG_TYPE` (`lib/krb5/error_tables/krb5_err.et:83-83`): its text.
const MSG_TYPE: &str = "Invalid message type";
/// MIT `KRB5KDC_ERR_BAD_PVNO` (`lib/krb5/error_tables/krb5_err.et:44-44`): its text.
const BAD_PVNO: &str = "Requested protocol version not supported";
/// MIT `KRB5KDC_ERR_WRONG_REALM` (`lib/krb5/error_tables/krb5_err.et:112-112`): its text.
const WRONG_REALM: &str = "Realm not local to KDC";
/// MIT `KRB5KDC_ERR_DISCARD` (`lib/krb5/error_tables/k5e1_err.et:36-36`): its text.
const DISCARD: &str = "The KDC should discard this request";
/// MIT `ASN1_MISSING_FIELD` (`lib/krb5/error_tables/asn1_err.et:3-3`): its text.
const ASN1_MISSING_FIELD: &str = "ASN.1 structure is missing a required field";
/// MIT `ASN1_OVERFLOW` (`lib/krb5/error_tables/asn1_err.et:6-6`): its text.
const ASN1_OVERFLOW: &str = "ASN.1 value too large";
/// MIT `ASN1_OVERRUN` (`lib/krb5/error_tables/asn1_err.et:7-7`): its text.
const ASN1_OVERRUN: &str = "ASN.1 encoding ended unexpectedly";
/// MIT `ASN1_BAD_ID` (`lib/krb5/error_tables/asn1_err.et:8-8`): its text.
const ASN1_BAD_ID: &str = "ASN.1 identifier doesn't match expected value";
/// MIT `ASN1_BAD_LENGTH` (`lib/krb5/error_tables/asn1_err.et:9-9`): its text.
const ASN1_BAD_LENGTH: &str = "ASN.1 length doesn't match expected value";
/// MIT `ASN1_BAD_FORMAT` (`lib/krb5/error_tables/asn1_err.et:10-10`): its text.
const ASN1_BAD_FORMAT: &str = "ASN.1 badly-formatted encoding";
/// MIT `ASN1_PARSE_ERROR` (`lib/krb5/error_tables/asn1_err.et:11-11`): its text.
const ASN1_PARSE_ERROR: &str = "ASN.1 parse error";
/// MIT `ASN1_INDEF` (`lib/krb5/error_tables/asn1_err.et:13-13`): its text.
const ASN1_INDEF: &str = "ASN.1 indefinite encoding";

/// Decode a KDC-REQ under APPLICATION `app` with `full`, failing with the text of the error
/// MIT's decoder returns for the same bytes. The KDC-REQ's own fields (the tags, `pvno` 5,
/// `msg-type`, the PA-DATA list) are checked as MIT's decoder checks them, in its order; inside
/// the request body an element that runs past its parent is an overrun, and any other failure is
/// named by the class of the Rust decoder's failure.
fn decode_kdc_req<T>(
    raw: &[u8],
    app: u32,
    full: impl FnOnce(&[u8]) -> Result<T, krb5_asn1::Error>,
) -> Result<T, &'static str> {
    kdc_req_verdict(raw, app)?;
    full(raw).map_err(|e| {
        let body = get_tag(raw)
            .and_then(|t| inner(&t))
            .ok()
            .and_then(|s| last_field(s.contents));
        match body.map(framing) {
            Some(Err(text)) => text,
            _ => body_failure_text(&e.to_string()),
        }
    })
}

/// One DER element as MIT's `get_tag` reads it.
struct Tlv<'a> {
    class: u8,
    constructed: bool,
    tagnum: u32,
    contents: &'a [u8],
    rest: &'a [u8],
}

const UNIVERSAL: u8 = 0x00;
const APPLICATION: u8 = 0x40;
const CONTEXT: u8 = 0x80;
/// MIT `ASN1_TAGNUM_MAX` (`lib/krb5/asn.1/krbasn1.h:22-22`): the largest tag number, one below `INT_MAX`.
const TAGNUM_MAX: u32 = 0x7fff_fffe;

/// MIT `get_tag` (`lib/krb5/asn.1/asn1_encode.c:366-421`): an identifier and length that run past the input are an overrun, a tag number or length too large an overflow, and the indefinite length its own error.
fn get_tag(asn1: &[u8]) -> Result<Tlv<'_>, &'static str> {
    let (&o, mut p) = asn1.split_first().ok_or(ASN1_OVERRUN)?;
    let mut tagnum = u32::from(o & 0x1F);
    if o & 0x1F == 0x1F {
        tagnum = 0;
        loop {
            let (&b, q) = p.split_first().ok_or(ASN1_OVERRUN)?;
            p = q;
            if tagnum > TAGNUM_MAX >> 7 {
                return Err(ASN1_OVERFLOW);
            }
            tagnum = (tagnum << 7) | u32::from(b & 0x7F);
            if b & 0x80 == 0 {
                break;
            }
        }
        if tagnum > TAGNUM_MAX {
            return Err(ASN1_OVERFLOW);
        }
    }
    let (&l, p) = p.split_first().ok_or(ASN1_OVERRUN)?;
    let (clen, p) = if l & 0x80 == 0 {
        (usize::from(l), p)
    } else {
        let llen = usize::from(l & 0x7F);
        if llen > p.len() {
            return Err(ASN1_OVERRUN);
        }
        if llen > std::mem::size_of::<usize>() {
            return Err(ASN1_OVERFLOW);
        }
        if llen == 0 {
            return Err(ASN1_INDEF);
        }
        let clen = p[..llen]
            .iter()
            .fold(0usize, |c, &b| (c << 8) | usize::from(b));
        (clen, &p[llen..])
    };
    if clen > p.len() {
        return Err(ASN1_OVERRUN);
    }
    Ok(Tlv {
        class: o & 0xC0,
        constructed: o & 0x20 != 0,
        tagnum,
        contents: &p[..clen],
        rest: &p[clen..],
    })
}

/// MIT `check_atype_tag` (`lib/krb5/asn.1/asn1_encode.c:1097-1103`): an explicit tag matches by class, number and the constructed bit.
fn explicit(t: &Tlv<'_>, class: u8, tagnum: u32) -> bool {
    t.constructed && t.class == class && t.tagnum == tagnum
}

/// MIT `decode_atype` (`lib/krb5/asn.1/asn1_encode.c:1186-1201`): an explicit tag holds one element that fills it.
fn inner<'a>(t: &Tlv<'a>) -> Result<Tlv<'a>, &'static str> {
    let i = get_tag(t.contents)?;
    if !i.rest.is_empty() {
        return Err(ASN1_BAD_LENGTH);
    }
    Ok(i)
}

fn is_universal(t: &Tlv<'_>, constructed: bool, tagnum: u32) -> bool {
    t.class == UNIVERSAL && t.constructed == constructed && t.tagnum == tagnum
}

/// The KDC-REQ's fields and PA-DATA's, as MIT's decoder knows them.
#[derive(Clone, Copy)]
enum Kind {
    /// `krb5_version`: an INTEGER that must be 5.
    Pvno,
    /// An unsigned INTEGER of 32 bits (`msg-type`).
    Uint32,
    /// A signed INTEGER of 32 bits (`padata-type`).
    Int32,
    /// An OCTET STRING.
    Octets,
    /// The PA-DATA list.
    Padata,
    /// The request body: a SEQUENCE, whose fields are left to the full decode.
    Body,
}

struct Field {
    tagnum: u32,
    required: bool,
    kind: Kind,
}

/// MIT `kdc_req_fields` (`lib/krb5/asn.1/asn1_k_encode.c:789-792`): `pvno`, `msg-type`, optional `padata`, `req-body`.
const KDC_REQ: [Field; 4] = [
    Field {
        tagnum: 1,
        required: true,
        kind: Kind::Pvno,
    },
    Field {
        tagnum: 2,
        required: true,
        kind: Kind::Uint32,
    },
    Field {
        tagnum: 3,
        required: false,
        kind: Kind::Padata,
    },
    Field {
        tagnum: 4,
        required: true,
        kind: Kind::Body,
    },
];

/// RFC 4120 PA-DATA: `padata-type` [1] Int32, `padata-value` [2] OCTET STRING.
const PA_DATA: [Field; 2] = [
    Field {
        tagnum: 1,
        required: true,
        kind: Kind::Int32,
    },
    Field {
        tagnum: 2,
        required: true,
        kind: Kind::Octets,
    },
];

/// MIT `k5_asn1_full_decode` (`lib/krb5/asn.1/asn1_encode.c:1576-1584`): the outer tag, then its contents; bytes after it are not checked.
fn kdc_req_verdict(raw: &[u8], app: u32) -> Result<(), &'static str> {
    let t = get_tag(raw)?;
    if !explicit(&t, APPLICATION, app) {
        return Err(ASN1_BAD_ID);
    }
    let s = inner(&t)?;
    if !is_universal(&s, true, 16) {
        return Err(ASN1_BAD_ID);
    }
    decode_sequence(s.contents, &KDC_REQ)
}

/// MIT `decode_sequence` (`lib/krb5/asn.1/asn1_encode.c:1411-1446`): each element goes to the next field whose tag it carries, the fields it skips are omitted, a required one omitted is a missing field, and an element no field takes ends the sequence.
fn decode_sequence(mut p: &[u8], fields: &[Field]) -> Result<(), &'static str> {
    let mut i = 0;
    while i < fields.len() && !p.is_empty() {
        let t = get_tag(p)?;
        p = t.rest;
        while i < fields.len() && !explicit(&t, CONTEXT, fields[i].tagnum) {
            if fields[i].required {
                return Err(ASN1_MISSING_FIELD);
            }
            i += 1;
        }
        if i == fields.len() {
            break;
        }
        decode_field(fields[i].kind, &t)?;
        i += 1;
    }
    if fields[i..].iter().any(|f| f.required) {
        return Err(ASN1_MISSING_FIELD);
    }
    Ok(())
}

/// One explicitly tagged field.
/// MIT `k5_asn1_decode_int` (`lib/krb5/asn.1/asn1_encode.c:191-199`): an empty INTEGER is a bad length, one longer than eight bytes an overflow.
/// MIT `k5_asn1_decode_uint` (`lib/krb5/asn.1/asn1_encode.c:211-219`): a negative or too long unsigned INTEGER is an overflow.
/// MIT `decode_atype` (`lib/krb5/asn.1/asn1_encode.c:1229-1230`): `pvno` other than 5 is the immediate's error, `KRB5KDC_ERR_BAD_PVNO`.
fn decode_field(kind: Kind, t: &Tlv<'_>) -> Result<(), &'static str> {
    let v = inner(t)?;
    match kind {
        Kind::Pvno | Kind::Int32 => {
            let c = integer(&v)?;
            if c.len() > 8 {
                return Err(ASN1_OVERFLOW);
            }
            let start: i64 = if c[0] & 0x80 == 0 { 0 } else { -1 };
            let n = c.iter().fold(start, |n, &b| {
                n.wrapping_mul(256).wrapping_add(i64::from(b))
            });
            match kind {
                Kind::Pvno if n != 5 => Err(BAD_PVNO),
                Kind::Int32 if i32::try_from(n).is_err() => Err(ASN1_OVERFLOW),
                _ => Ok(()),
            }
        }
        Kind::Uint32 => {
            let c = integer(&v)?;
            if c[0] & 0x80 != 0 || c.len() > 8 + usize::from(c[0] == 0) {
                return Err(ASN1_OVERFLOW);
            }
            let n = c.iter().fold(0u128, |n, &b| (n << 8) | u128::from(b));
            if u32::try_from(n).is_err() {
                return Err(ASN1_OVERFLOW);
            }
            Ok(())
        }
        Kind::Octets => {
            if is_universal(&v, false, 4) {
                Ok(())
            } else {
                Err(ASN1_BAD_ID)
            }
        }
        Kind::Padata => {
            if !is_universal(&v, true, 16) {
                return Err(ASN1_BAD_ID);
            }
            // MIT `decode_sequence_of` (`lib/krb5/asn.1/asn1_encode.c:1468-1480`): each element is read, must be a SEQUENCE, and is decoded.
            let mut p = v.contents;
            while !p.is_empty() {
                let e = get_tag(p)?;
                p = e.rest;
                if !is_universal(&e, true, 16) {
                    return Err(ASN1_BAD_ID);
                }
                decode_sequence(e.contents, &PA_DATA)?;
            }
            Ok(())
        }
        Kind::Body => {
            if is_universal(&v, true, 16) {
                Ok(())
            } else {
                Err(ASN1_BAD_ID)
            }
        }
    }
}

/// An INTEGER's contents, as MIT's integer decoders take them.
fn integer<'a>(v: &Tlv<'a>) -> Result<&'a [u8], &'static str> {
    if !is_universal(v, false, 2) {
        return Err(ASN1_BAD_ID);
    }
    if v.contents.is_empty() {
        return Err(ASN1_BAD_LENGTH);
    }
    Ok(v.contents)
}

/// The contents of the last element of a KDC-REQ's SEQUENCE (its `req-body` SEQUENCE).
fn last_field(mut p: &[u8]) -> Option<&[u8]> {
    let mut last = None;
    while !p.is_empty() {
        let t = get_tag(p).ok()?;
        p = t.rest;
        last = Some(t.contents);
    }
    get_tag(last?).ok().map(|t| t.contents)
}

/// How deep [`framing`] looks: past the deepest element of a request body (a ticket's cipher in
/// `additional-tickets`, nine down), so a request built of nested tags cannot run it deep.
const FRAMING_DEPTH: u32 = 16;

/// Every element inside `p`, depth first to [`FRAMING_DEPTH`], read as MIT's `get_tag` reads it:
/// the error of the first that runs past the element holding it, or whose tag or length cannot
/// be read.
fn framing(p: &[u8]) -> Result<(), &'static str> {
    framing_at(p, 0)
}

fn framing_at(mut p: &[u8], depth: u32) -> Result<(), &'static str> {
    while !p.is_empty() {
        let t = get_tag(p)?;
        if t.constructed && depth < FRAMING_DEPTH {
            framing_at(t.contents, depth + 1)?;
        }
        p = t.rest;
    }
    Ok(())
}

/// The MIT error a failure inside a well-framed request body stands for, from the Rust decoder's
/// failure: a time that is not fifteen characters is a bad length and any other bad time a bad
/// format; a field missing or out of place is a missing field; a wrong type tag a bad identifier.
/// MIT `k5_asn1_decode_generaltime` (`lib/krb5/asn.1/asn1_encode.c:242-260`): a time must be fifteen characters, digits then `Z`.
fn body_failure_text(e: &str) -> &'static str {
    if let Some(time) = e
        .split("Invalid date string: ")
        .nth(1)
        .and_then(|t| t.split(" (Codec").next())
    {
        return if time.len() == 15 {
            ASN1_BAD_FORMAT
        } else {
            ASN1_BAD_LENGTH
        };
    }
    if e.contains("Expected Tag { class: Context")
        || e.contains("Missing field")
        || e.contains("Need more data")
        || e.contains("Unexpected EOF")
    {
        return ASN1_MISSING_FIELD;
    }
    if e.contains("Expected Tag {") {
        return ASN1_BAD_ID;
    }
    if e.contains(" bytes, actual length was ") {
        return ASN1_BAD_LENGTH;
    }
    if e.contains("larger than expected") {
        return ASN1_OVERFLOW;
    }
    if e.contains("Indefinite length") {
        return ASN1_INDEF;
    }
    ASN1_PARSE_ERROR
}

/// MIT `dispatch` (`kdc/dispatch.c:123-131`): the two lines a request found in the lookaside logs; MIT never fills in the address.
const RESENDING: &str = "DISPATCH: repeated (retransmitted?) request from [unknown address type], resending previous response";
const DROPPING: &str = "DISPATCH: repeated (retransmitted?) request from [unknown address type] during request processing, dropping repeated request";

/// The JSON twin of the resend line.
fn log_dispatch_resend() {
    tracing::info!(
        event = krb5_log::events::KDC_ISSUE,
        correlation_id = krb5_log::current_correlation_id(),
        component = "krb5-kdc",
        outcome = "retransmit",
        detail = "resending previous response",
    );
}

/// The JSON twin of the drop line.
fn log_dispatch_inflight_drop() {
    tracing::info!(
        event = krb5_log::events::KDC_ISSUE,
        correlation_id = krb5_log::current_correlation_id(),
        component = "krb5-kdc",
        outcome = "discard",
        detail = "dropping repeated request during processing",
    );
}

/// What a request's processing came to: MIT's `respond` code and response.
enum Done {
    /// Code 0 and a reply.
    Reply(Vec<u8>),
    /// A nonzero code, as its text; `discard` for `KRB5KDC_ERR_DISCARD`.
    Failed { text: String, discard: bool },
}

/// The KDC's side of the net-server loop: MIT's `dispatch`, `make_toolong_error` and reset, with
/// the lookaside the loop's alone (MIT's `kdc/replay.c` has no lock: one loop uses it).
pub(crate) struct KdcDispatch {
    store: SharedStore,
    lookaside: Lookaside,
    max_dgram_reply_size: usize,
    /// A request whose processing panics, for the containment unit.
    #[cfg(test)]
    pub(crate) panic_on: Option<Vec<u8>>,
}

impl KdcDispatch {
    /// The dispatcher for `store`, with an empty lookaside; a UDP reply longer than
    /// `max_dgram_reply_size` is replaced by `KRB_ERR_RESPONSE_TOO_BIG`.
    pub(crate) fn new(store: SharedStore, max_dgram_reply_size: usize) -> Self {
        Self {
            store,
            lookaside: Lookaside::new(),
            max_dgram_reply_size,
            #[cfg(test)]
            panic_on: None,
        }
    }

    /// MIT `finish_dispatch_cache` (`kdc/dispatch.c:77-83`): the in-progress mark goes unless the request was discarded, and a reply is cached.
    fn finish_dispatch_cache(&mut self, request: &[u8], is_tcp: bool, done: Done) -> Reply {
        match &done {
            Done::Failed { discard: true, .. } => {}
            Done::Reply(bytes) => self.lookaside.finish(request, Some(bytes)),
            Done::Failed { .. } => self.lookaside.finish(request, None),
        }
        self.finish_dispatch(is_tcp, done)
    }

    /// MIT `finish_dispatch` (`kdc/dispatch.c:54-66`): a UDP reply over `max_dgram_reply_size` is replaced by the response-too-big error, then the code and reply go back to the loop.
    ///
    /// Deviation: a reply resent from the lookaside that is too big for UDP is replaced by the
    /// realm's response-too-big error, where MIT's builds it from a realm it has not set yet.
    fn finish_dispatch(&self, is_tcp: bool, done: Done) -> Reply {
        match done {
            Done::Reply(bytes) if !is_tcp && bytes.len() > self.max_dgram_reply_size => {
                Reply::Send(plain_store(&self.store, |s| {
                    super::kdc_error_bytes(s, err::RESPONSE_TOO_BIG)
                }))
            }
            Done::Reply(bytes) => Reply::Send(bytes),
            Done::Failed { text, .. } => Reply::Failed(text),
        }
    }
}

/// What processing one fresh request through the issue path gave.
fn process(store: &dyn PrincipalRead, raw: &[u8], sender: &HostAddress) -> Done {
    match process_logged(store, raw, Some(sender)) {
        // MIT `finish_process_as_req` (`kdc/do_as_req.c:371-381`): a discard sends no error.
        Ok(Processed::Reply(bytes)) if bytes.is_empty() => Done::Failed {
            text: DISCARD.into(),
            discard: true,
        },
        Ok(Processed::Reply(bytes)) => Done::Reply(bytes),
        Ok(Processed::Refused(text)) => Done::Failed {
            text: text.into(),
            discard: false,
        },
        Err(e) => Done::Failed {
            text: e.to_string(),
            discard: false,
        },
    }
}

impl Dispatch for KdcDispatch {
    /// MIT `dispatch` (`kdc/dispatch.c:114-141`): a request in the lookaside is resent its reply, or dropped while it is being processed, each logged; any other is marked in progress and processed.
    ///
    /// A request whose processing panics is answered with nothing and its mark removed, where
    /// MIT's process would end.
    fn dispatch(
        &mut self,
        _local: SocketAddr,
        remote: SocketAddr,
        request: &[u8],
        is_tcp: bool,
        log: &mut dyn Log,
    ) -> Reply {
        match self.lookaside.check_or_mark(request) {
            Check::Hit(reply) => {
                log.syslog(Severity::Info, RESENDING);
                log_dispatch_resend();
                return self.finish_dispatch(is_tcp, Done::Reply(reply));
            }
            Check::InProgress => {
                log.syslog(Severity::Info, DROPPING);
                log_dispatch_inflight_drop();
                return self.finish_dispatch(
                    is_tcp,
                    Done::Failed {
                        text: DISCARD.into(),
                        discard: true,
                    },
                );
            }
            Check::Fresh => {}
        }
        crate::audit::set_client_port(u32::from(remote.port()));
        let sender = HostAddress::from_socket(remote);
        let store = &self.store;
        #[cfg(test)]
        let panics = self.panic_on.as_deref() == Some(request);
        let run = catch_unwind(AssertUnwindSafe(|| {
            #[cfg(test)]
            assert!(!panics, "a request set to panic");
            read_store(store, |s| process(s, request, &sender))
        }));
        let Ok(done) = run else {
            self.lookaside.finish(request, None);
            tracing::error!(
                event = krb5_log::events::KDC_TRANSPORT,
                correlation_id = krb5_log::current_correlation_id(),
                component = "krb5-kdc",
                outcome = "error",
                error = "request panic isolated",
            );
            return Reply::Nothing;
        };
        self.finish_dispatch_cache(request, is_tcp, done)
    }

    /// MIT `make_toolong_error` (`kdc/kdc_util.c:1882-1913`): `KRB_ERR_FIELD_TOOLONG` from the realm's TGS, with no client or text.
    fn make_toolong_error(&mut self) -> Result<Vec<u8>, String> {
        Ok(plain_store(&self.store, |s| {
            super::kdc_error_bytes(s, err::FIELD_TOOLONG)
        }))
    }
}

/// The plugin slots this thread set for itself (its kdcpolicy, kdcpreauth, kdcauthdata and
/// audit modules), off it while one loop serves every request on the thread, and put back when
/// the loop returns: modules that apply to all the KDC's requests are the process-wide ones, as
/// MIT's loaded modules are.
pub(crate) struct ThreadSlots {
    policy: Option<Arc<dyn KdcPolicy>>,
    preauth: Option<Vec<Arc<dyn KdcPreauth>>>,
    authdata: Option<Vec<Arc<dyn KdcAuthdata>>>,
    audit: Option<Arc<dyn KdcAudit>>,
}

impl ThreadSlots {
    /// Take this thread's slots off it until the result is dropped.
    pub(crate) fn take() -> Self {
        Self {
            policy: take_thread_policy(),
            preauth: take_thread_preauth(),
            authdata: take_thread_authdata(),
            audit: take_thread_audit(),
        }
    }
}

impl Drop for ThreadSlots {
    fn drop(&mut self) {
        restore_thread_policy(self.policy.take());
        restore_thread_preauth(self.preauth.take());
        restore_thread_authdata(self.authdata.take());
        restore_thread_audit(self.audit.take());
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use krb5_asn1::encode;
    use krb5_types::{KrbError, PrincipalName};

    use super::*;
    use crate::listen::shared_store;
    use crate::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented, documented_host};

    #[derive(Default)]
    struct Lines(Vec<(Severity, String)>);

    impl Log for Lines {
        fn syslog(&mut self, severity: Severity, msg: &str) {
            self.0.push((severity, msg.to_owned()));
        }
    }

    const NO_LINES: [(Severity, String); 0] = [];

    fn info(msg: &str) -> (Severity, String) {
        (Severity::Info, msg.to_owned())
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn kdc(max_dgram: usize) -> KdcDispatch {
        let (store, _) = bootstrap_documented().unwrap();
        KdcDispatch::new(shared_store(store), max_dgram)
    }

    fn local() -> SocketAddr {
        "127.0.0.1:88".parse().unwrap()
    }

    fn peer() -> SocketAddr {
        "127.0.0.1:4242".parse().unwrap()
    }

    /// An AS-REQ without preauth for a client the realm does not hold.
    fn nosuch(nonce: u32) -> Vec<u8> {
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["nosuch"]);
        encode(&krb5_protocol::as_req(cname, TEST_REALM, nonce, None).unwrap()).unwrap()
    }

    /// A KDC-REQ-BODY's tail after `cname`, as the settles built it: realm, sname, till,
    /// nonce 4242, etypes 18 and 17.
    const AS_REQ_BODY: &str = "6a8183308180a103020105a20302010aa4743072a00703050000000000a1133011a003020101a10a30081b066e6f73756368a20d1b0b534554544c452e54455354a320301ea003020102a11730151b066b72627467741b0b534554544c452e54455354a511180f32303337303931333032343830355aa704020210f7a8083006020112020111";

    /// Requests MIT 1.22.2's dispatch refused when settled live, byte for byte, each with the text
    /// MIT logged "- while dispatching (udp)".
    const REFUSED: [(&str, &str); 17] = [
        ("6e03020105", MSG_TYPE),
        ("3003020105", MSG_TYPE),
        (
            "6a8183308180a103020105a20302010aa4743072a00703050000000000a1133011a003020101a10a",
            ASN1_OVERRUN,
        ),
        ("6c053003020105", ASN1_MISSING_FIELD),
        (
            "6a8183308180a103020104a20302010aa4743072a00703050000000000a1133011a003020101a10a30081b066e6f73756368a20d1b0b534554544c452e54455354a320301ea003020102a11730151b066b72627467741b0b534554544c452e54455354a511180f32303337303931333032343830355aa704020210f7a8083006020112020111",
            BAD_PVNO,
        ),
        ("4a03020105", ASN1_BAD_ID),
        ("6a8030030201050000", ASN1_INDEF),
        ("6a053103020105", ASN1_BAD_ID),
        ("6a06300302010500", ASN1_BAD_LENGTH),
        ("6a043002a100", ASN1_OVERRUN),
        ("6a063004a1020400", ASN1_BAD_ID),
        ("6a073005a103020105", ASN1_MISSING_FIELD),
        ("6a073005a103020104", BAD_PVNO),
        ("6a153013a103020104a20302010aa4073005a003030100", BAD_PVNO),
        (
            "6a773075a103020105a20302010aa4693067a00703050000000000a1133011a003020101a10a30081b066e6f73756368a20d1b0b534554544c452e54455354a320301ea003020102a11730151b066b72627467741b0b534554544c452e54455354a506180432303337a70402021092a8083006020112020111",
            ASN1_BAD_LENGTH,
        ),
        (
            "6a60305ea103020105a20302010aa4523050a00703050000000000a1133011a003020101a10a30081b066e6f73756368a20d1b0b534554544c452e54455354a511180f32303337303931333032343830355aa70402021092a8083006020112020111",
            WRONG_REALM,
        ),
        (
            "6c60305ea103020105a20302010ca4523050a00703050000000000a1133011a003020101a10a30081b066e6f73756368a20d1b0b534554544c452e54455354a511180f32303337303931333032343830355aa70402021092a8083006020112020111",
            WRONG_REALM,
        ),
    ];

    /// Each request MIT refused is refused with MIT's text, with no DISPATCH line, and is not
    /// cached: sent again, it is refused again. The library entry point answers it with nothing.
    #[test]
    fn requests_dispatch_refuses_get_mits_texts() {
        let mut k = kdc(65_536);
        let mut log = Lines::default();
        for (h, text) in REFUSED {
            for _ in 0..2 {
                let r = k.dispatch(local(), peer(), &hex(h), false, &mut log);
                assert_eq!(r, Reply::Failed(text.into()), "{h}");
            }
        }
        assert_eq!(log.0, NO_LINES);
        let (store, _) = bootstrap_documented().unwrap();
        for (h, _) in REFUSED {
            assert_eq!(handle_request(&store, &hex(h)).unwrap(), Vec::<u8>::new());
        }
        // The well-formed request the settles built from the same parts is processed.
        let r = k.dispatch(local(), peer(), &hex(AS_REQ_BODY), false, &mut log);
        let Reply::Send(bytes) = r else {
            panic!("no reply: {r:?}")
        };
        let e: KrbError = krb5_asn1::decode(&bytes).unwrap();
        assert_eq!(e.error_code, err::C_PRINCIPAL_UNKNOWN);
    }

    /// The same request again, over UDP or TCP, is resent the first reply byte for byte, with
    /// MIT's line.
    #[test]
    fn a_repeat_is_resent_from_the_lookaside_with_mits_line() {
        let mut k = kdc(65_536);
        let mut log = Lines::default();
        let req = nosuch(7);
        let Reply::Send(first) = k.dispatch(local(), peer(), &req, false, &mut log) else {
            panic!("no first reply")
        };
        assert_eq!(log.0, NO_LINES);
        for is_tcp in [false, true] {
            let again = k.dispatch(local(), peer(), &req, is_tcp, &mut log);
            assert_eq!(again, Reply::Send(first.clone()));
        }
        assert_eq!(log.0, [info(RESENDING), info(RESENDING)]);
    }

    /// A repeat that finds its request still in progress (MIT's loop meets one while an AS-REQ
    /// waits on an asynchronous preauth module, settled live with OTP) is dropped with MIT's line
    /// and the discard code, and the mark stays.
    #[test]
    fn a_repeat_during_processing_is_dropped_with_mits_lines() {
        let mut k = kdc(65_536);
        let mut log = Lines::default();
        let req = nosuch(8);
        assert!(matches!(k.lookaside.check_or_mark(&req), Check::Fresh));
        for is_tcp in [false, true] {
            let r = k.dispatch(local(), peer(), &req, is_tcp, &mut log);
            assert_eq!(r, Reply::Failed(DISCARD.into()));
        }
        assert_eq!(log.0, [info(DROPPING), info(DROPPING)]);
        assert!(matches!(k.lookaside.check_or_mark(&req), Check::InProgress));
    }

    /// A discarded request keeps its in-progress mark, so its repeats are dropped while the
    /// lookaside holds it; any other outcome removes the mark.
    #[test]
    fn a_discard_keeps_its_mark_and_a_failure_does_not() {
        let mut k = kdc(65_536);
        let (a, b) = (nosuch(9), nosuch(10));
        for (req, discard) in [(&a, true), (&b, false)] {
            assert!(matches!(k.lookaside.check_or_mark(req), Check::Fresh));
            let text = if discard { DISCARD } else { MSG_TYPE };
            let done = Done::Failed {
                text: text.into(),
                discard,
            };
            assert_eq!(
                k.finish_dispatch_cache(req, false, done),
                Reply::Failed(text.into())
            );
        }
        assert!(matches!(k.lookaside.check_or_mark(&a), Check::InProgress));
        assert!(matches!(k.lookaside.check_or_mark(&b), Check::Fresh));
    }

    /// A request whose processing panics is answered with nothing and its mark removed, so the
    /// same request is processed when it comes again.
    #[test]
    fn a_panicking_request_is_contained_and_its_mark_removed() {
        let mut k = kdc(65_536);
        let mut log = Lines::default();
        let req = nosuch(11);
        k.panic_on = Some(req.clone());
        assert_eq!(
            k.dispatch(local(), peer(), &req, false, &mut log),
            Reply::Nothing
        );
        k.panic_on = None;
        let again = k.dispatch(local(), peer(), &req, false, &mut log);
        assert!(matches!(again, Reply::Send(_)), "{again:?}");
        assert_eq!(log.0, NO_LINES, "processed, not resent or dropped");
    }

    /// A reply too big for UDP goes out as RESPONSE_TOO_BIG, and the whole reply is cached, so
    /// the client's retry over TCP is resent it.
    #[test]
    fn a_reply_too_big_for_udp_is_response_too_big_and_cached_whole() {
        let mut k = kdc(10);
        let mut log = Lines::default();
        let req = nosuch(12);
        let Reply::Send(small) = k.dispatch(local(), peer(), &req, false, &mut log) else {
            panic!("no UDP reply")
        };
        let e: KrbError = krb5_asn1::decode(&small).unwrap();
        assert_eq!(e.error_code, err::RESPONSE_TOO_BIG);
        let Reply::Send(whole) = k.dispatch(local(), peer(), &req, true, &mut log) else {
            panic!("no TCP reply")
        };
        let e: KrbError = krb5_asn1::decode(&whole).unwrap();
        assert_eq!(e.error_code, err::C_PRINCIPAL_UNKNOWN);
        assert_eq!(log.0, [info(RESENDING)]);
    }

    /// FIELD_TOOLONG names the realm's TGS and carries no client or text, as MIT's (settled
    /// live: `krbtgt/R@R`, no e-text).
    #[test]
    fn field_toolong_is_mits_error() {
        let mut k = kdc(65_536);
        let e: KrbError = krb5_asn1::decode(&k.make_toolong_error().unwrap()).unwrap();
        assert_eq!(e.error_code, err::FIELD_TOOLONG);
        assert_eq!(std::str::from_utf8(e.realm.as_bytes()).unwrap(), TEST_REALM);
        assert_eq!(e.sname, PrincipalName::krbtgt(TEST_REALM));
        assert!(e.cname.is_none() && e.crealm.is_none() && e.e_text.is_none());
    }

    /// A replay the lookaside no longer holds is processed again: the AS-REQ with the same
    /// PA-ENC-TIMESTAMP and the TGS-REQ with the same authenticator each get a new ticket, where
    /// the lookaside resent the first reply while it held it.
    /// MIT `dispatch` (`kdc/dispatch.c:114-140`): only the lookaside answers a repeated request, so one it no longer holds is processed again.
    #[test]
    fn a_replay_the_lookaside_no_longer_holds_is_issued_again() {
        let (store, _) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let as_req = |nonce, padata| krb5_protocol::as_req(user.clone(), TEST_REALM, nonce, padata);
        let enc_ts = || Some(vec![krb5_protocol::pa_enc_timestamp(&key).unwrap()]);
        let as_bytes = encode(&as_req(71, enc_ts()).unwrap()).unwrap();
        let tgt = crate::issue_as(&store, &as_req(72, enc_ts()).unwrap()).unwrap();
        let tgs = krb5_protocol::tgs_req(
            tgt.rep.0.ticket.clone(),
            &tgt.session_key,
            TEST_REALM,
            &user,
            documented_host(),
            TEST_REALM,
            73,
        );
        let tgs_bytes = encode(&tgs.unwrap()).unwrap();
        let stale = Duration::from_millis(500);
        let mut k = KdcDispatch::new(shared_store(store), 65_536);
        k.lookaside = Lookaside::with_limits(crate::lookaside::MAX_SIZE, stale);
        let mut log = Lines::default();
        let mut send = |req: &[u8]| match k.dispatch(local(), peer(), req, true, &mut log) {
            Reply::Send(reply) => reply,
            other => panic!("no reply: {other:?}"),
        };
        let as_first = send(&as_bytes);
        assert_eq!(
            send(&as_bytes),
            as_first,
            "the lookaside resends the AS-REP"
        );
        let tgs_first = send(&tgs_bytes);
        assert_eq!(
            send(&tgs_bytes),
            tgs_first,
            "the lookaside resends the TGS-REP"
        );
        std::thread::sleep(stale + Duration::from_millis(100));
        // A later request's insert purges the stale entries, as MIT's does.
        send(&encode(&as_req(74, None).unwrap()).unwrap());
        let as_again = send(&as_bytes);
        assert_eq!(
            as_again.first(),
            Some(&0x6b),
            "the replayed AS-REQ issues an AS-REP"
        );
        assert_ne!(as_again, as_first, "a new AS-REP, not the cached one");
        let tgs_again = send(&tgs_bytes);
        assert_eq!(
            tgs_again.first(),
            Some(&0x6d),
            "the replayed TGS-REQ issues a TGS-REP"
        );
        assert_ne!(tgs_again, tgs_first, "a new TGS-REP, not the cached one");
    }

    /// A kdcpreauth module that offers nothing and claims nothing.
    struct NoPreauth;

    impl KdcPreauth for NoPreauth {
        fn name(&self) -> &'static str {
            "none"
        }
        fn pa_types(&self) -> &'static [i32] {
            &[]
        }
        fn advertise(
            &self,
            _store: &dyn crate::kdb::PrincipalRead,
            _client: &crate::store::Principal,
            _armor: bool,
            _requested: &[i32],
        ) -> Vec<krb5_types::PaData> {
            Vec::new()
        }
        fn process_as(
            &self,
            _rock: &crate::plugins::PreauthRock<'_>,
        ) -> Result<Option<crate::plugins::PreauthAction>, Error> {
            Ok(None)
        }
    }

    /// A kdcauthdata module that changes nothing.
    struct NoAuthdata;

    impl KdcAuthdata for NoAuthdata {
        fn name(&self) -> &'static str {
            "none"
        }
        fn handle(
            &self,
            _is_tgs: bool,
            _reply: &mut krb5_types::AuthorizationData,
            _session: Option<&krb5_crypto::ProtocolKey>,
            _issuer: Option<(&PrincipalName, &str)>,
        ) -> Result<(), Error> {
            Ok(())
        }
    }

    fn is_own<T: ?Sized>(slot: &[Arc<T>], own: &Arc<T>) -> bool {
        slot.iter().any(|m| Arc::ptr_eq(m, own))
    }

    /// All four slots come off the thread while a loop holds them and go back when it is done.
    #[test]
    fn thread_slots_come_off_and_go_back() {
        use crate::plugins::{authdata_modules, preauth_modules};

        let policy: Arc<dyn KdcPolicy> = Arc::new(crate::testrealm::TestPolicy);
        let audit: Arc<dyn KdcAudit> = Arc::new(crate::audit::JsonAudit);
        let preauth: Arc<dyn KdcPreauth> = Arc::new(NoPreauth);
        let authdata: Arc<dyn KdcAuthdata> = Arc::new(NoAuthdata);
        crate::plugins::set_thread_policy(Arc::clone(&policy));
        crate::audit::set_thread_audit(Arc::clone(&audit));
        crate::plugins::set_thread_preauth(vec![Arc::clone(&preauth)]);
        crate::plugins::set_thread_authdata(vec![Arc::clone(&authdata)]);
        {
            let _slots = ThreadSlots::take();
            assert!(!Arc::ptr_eq(&crate::plugins::current_policy(), &policy));
            assert!(!Arc::ptr_eq(&crate::audit::current_audit(), &audit));
            assert!(!is_own(&preauth_modules(), &preauth));
            assert!(!is_own(&authdata_modules(), &authdata));
        }
        assert!(Arc::ptr_eq(&crate::plugins::current_policy(), &policy));
        assert!(Arc::ptr_eq(&crate::audit::current_audit(), &audit));
        assert!(is_own(&preauth_modules(), &preauth));
        assert!(is_own(&authdata_modules(), &authdata));
        // A loop that ends by a panic puts the slots back as it unwinds.
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _slots = ThreadSlots::take();
            assert!(!is_own(&preauth_modules(), &preauth));
            panic!("the loop ends by a panic");
        }));
        assert!(unwound.is_err());
        assert!(Arc::ptr_eq(&crate::plugins::current_policy(), &policy));
        assert!(Arc::ptr_eq(&crate::audit::current_audit(), &audit));
        assert!(is_own(&preauth_modules(), &preauth));
        assert!(is_own(&authdata_modules(), &authdata));
        crate::plugins::clear_thread_policy();
        crate::audit::clear_thread_audit();
        crate::plugins::clear_thread_preauth();
        crate::plugins::clear_thread_authdata();
    }
}
