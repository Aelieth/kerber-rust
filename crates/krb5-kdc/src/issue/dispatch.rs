//! AS and TGS dispatch, the lookaside, and the UDP size cap.

use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Instant;

use krb5_asn1::decode;
use krb5_log::klog::Severity;
use krb5_types::{AsReq, HostAddress, TgsReq, err};

use super::reply::{as_reply, krb_error_log_fields, tgs_reply};
use crate::asn1_text::{
    APPLICATION, ASN1_BAD_FORMAT, ASN1_BAD_ID, ASN1_BAD_LENGTH, ASN1_INDEF, ASN1_MISSING_FIELD,
    ASN1_OVERFLOW, ASN1_PARSE_ERROR, CONTEXT, Tlv, UNIVERSAL, get_tag,
};
use crate::audit::{
    KdcAudit, restore_thread_audit, restore_thread_audits, take_thread_audit, take_thread_audits,
};
use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::listen::{SharedStore, plain_store, read_store};
use crate::lookaside::{Check, Lookaside};
use crate::net_server::{Dispatch, Log, Reply};
use crate::plugins::{
    KdcAuthdata, KdcPolicy, KdcPreauth, OtpVerifier, restore_thread_authdata,
    restore_thread_kdcpolicies, restore_thread_otp_verifiers, restore_thread_policy,
    restore_thread_preauth, take_thread_authdata, take_thread_kdcpolicies,
    take_thread_otp_verifiers, take_thread_policy, take_thread_preauth,
};

pub fn handle_request(store: &dyn PrincipalRead, raw: &[u8]) -> Result<Vec<u8>, Error> {
    handle_request_from(store, raw, None)
}

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

enum Processed {
    Reply(Vec<u8>),
    Refused(&'static str),
}

fn process_logged(
    store: &dyn PrincipalRead,
    raw: &[u8],
    sender: Option<&HostAddress>,
) -> Result<Processed, Error> {
    let id = krb5_log::new_correlation_id();
    let _g = krb5_log::enter_correlation(id);
    let _req = match crate::audit::begin_request() {
        Ok(req) => req,
        Err(e) => return Ok(audit_id_failure(store, raw, e)),
    };
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
                crate::audit::log_failure(
                    store,
                    raw,
                    sender,
                    &bytes,
                    code,
                    &e_text,
                    detail.as_deref(),
                );
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

fn audit_id_failure(store: &dyn PrincipalRead, raw: &[u8], e: getrandom::Error) -> Processed {
    tracing::error!(
        event = krb5_log::events::KDC_ISSUE,
        correlation_id = krb5_log::current_correlation_id(),
        component = "krb5-kdc",
        outcome = "error",
        error = %e,
        "cannot make the audit request id",
    );
    match raw.first() {
        // MIT: `prepare_error_tgs` (kdc/do_tgs_req.c:182)
        Some(&0x6c) => Processed::Reply(super::kdc_error_bytes(store, err::GENERIC)),
        // MIT: `process_packet_response` (lib/apputils/net-server.c:1096-1104)
        _ => Processed::Refused("audit id unavailable"),
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

enum Inner {
    Reply(Vec<u8>, Option<String>),
    Refused(&'static str),
}

// MIT: `krb5int_is_app_tag` (include/k5-int.h:1334-1336)
fn is_app_tag(raw: &[u8], tag: u8) -> bool {
    raw.first().is_some_and(|b| b & !0x20 == 0x40 | tag)
}

// MIT: `dispatch` (kdc/dispatch.c:145-170)
// MIT: `setup_server_realm` (kdc/main.c:123-124)
fn handle_inner(
    store: &dyn PrincipalRead,
    raw: &[u8],
    sender: Option<&HostAddress>,
) -> Result<Inner, Error> {
    // A TGS-REQ is tried before an AS-REQ; no server name is WRONG_REALM.
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

// MIT: `KRB5KRB_AP_ERR_MSG_TYPE` (lib/krb5/error_tables/krb5_err.et:83-83)
const MSG_TYPE: &str = "Invalid message type";
// MIT: `KRB5KDC_ERR_BAD_PVNO` (lib/krb5/error_tables/krb5_err.et:44-44)
const BAD_PVNO: &str = "Requested protocol version not supported";
// MIT: `KRB5KDC_ERR_WRONG_REALM` (lib/krb5/error_tables/krb5_err.et:112-112)
const WRONG_REALM: &str = "Realm not local to KDC";
// MIT: `KRB5KDC_ERR_DISCARD` (lib/krb5/error_tables/k5e1_err.et:36-36)
const DISCARD: &str = "The KDC should discard this request";

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

// MIT: `check_atype_tag` (lib/krb5/asn.1/asn1_encode.c:1097-1103)
fn explicit(t: &Tlv<'_>, class: u8, tagnum: u32) -> bool {
    t.constructed && t.class == class && t.tagnum == tagnum
}

// MIT: `decode_atype` (lib/krb5/asn.1/asn1_encode.c:1186-1201)
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

#[derive(Clone, Copy)]
enum Kind {
    Pvno,
    Uint32,
    Int32,
    Octets,
    Padata,
    Body,
}

struct Field {
    tagnum: u32,
    required: bool,
    kind: Kind,
}

// MIT: `kdc_req_fields` (lib/krb5/asn.1/asn1_k_encode.c:789-792)
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

// MIT: `k5_asn1_full_decode` (lib/krb5/asn.1/asn1_encode.c:1576-1584)
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

// MIT: `decode_sequence` (lib/krb5/asn.1/asn1_encode.c:1411-1446)
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

// MIT: `k5_asn1_decode_int` (lib/krb5/asn.1/asn1_encode.c:191-199)
// MIT: `k5_asn1_decode_uint` (lib/krb5/asn.1/asn1_encode.c:211-219)
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
            // MIT: `decode_sequence_of` (lib/krb5/asn.1/asn1_encode.c:1468-1480)
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

fn integer<'a>(v: &Tlv<'a>) -> Result<&'a [u8], &'static str> {
    if !is_universal(v, false, 2) {
        return Err(ASN1_BAD_ID);
    }
    if v.contents.is_empty() {
        return Err(ASN1_BAD_LENGTH);
    }
    Ok(v.contents)
}

fn last_field(mut p: &[u8]) -> Option<&[u8]> {
    let mut last = None;
    while !p.is_empty() {
        let t = get_tag(p).ok()?;
        p = t.rest;
        last = Some(t.contents);
    }
    get_tag(last?).ok().map(|t| t.contents)
}

/// Depth 16 is past a ticket cipher nine down, so nested tags stop.
const FRAMING_DEPTH: u32 = 16;

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

// MIT: `k5_asn1_decode_generaltime` (lib/krb5/asn.1/asn1_encode.c:242-260)
fn body_failure_text(e: &str) -> &'static str {
    if let Some(n) = e
        .split("KerberosTime is not YYYYMMDDhhmmssZ (")
        .nth(1)
        .and_then(|rest| rest.split(" octets)").next())
        .and_then(|n| n.parse::<usize>().ok())
    {
        return if n == 15 {
            ASN1_BAD_FORMAT
        } else {
            ASN1_BAD_LENGTH
        };
    }
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

// MIT: `dispatch` (kdc/dispatch.c:123-131)
const RESENDING: &str = "DISPATCH: repeated (retransmitted?) request from [unknown address type], resending previous response";
const DROPPING: &str = "DISPATCH: repeated (retransmitted?) request from [unknown address type] during request processing, dropping repeated request";

fn log_dispatch_resend() {
    tracing::info!(
        event = krb5_log::events::KDC_ISSUE,
        correlation_id = krb5_log::current_correlation_id(),
        component = "krb5-kdc",
        outcome = "retransmit",
        detail = "resending previous response",
    );
}

fn log_dispatch_inflight_drop() {
    tracing::info!(
        event = krb5_log::events::KDC_ISSUE,
        correlation_id = krb5_log::current_correlation_id(),
        component = "krb5-kdc",
        outcome = "discard",
        detail = "dropping repeated request during processing",
    );
}

enum Done {
    Reply(Vec<u8>),
    Failed { text: String, discard: bool },
}

pub(crate) struct KdcDispatch {
    store: SharedStore,
    lookaside: Lookaside,
    max_dgram_reply_size: usize,
    #[cfg(test)]
    pub(crate) panic_on: Option<Vec<u8>>,
}

impl KdcDispatch {
    pub(crate) fn new(store: SharedStore, max_dgram_reply_size: usize) -> Self {
        Self {
            store,
            lookaside: Lookaside::new(),
            max_dgram_reply_size,
            #[cfg(test)]
            panic_on: None,
        }
    }

    fn run_contained(&self, remote: SocketAddr, request: &[u8]) -> Option<Done> {
        crate::audit::set_client_port(u32::from(remote.port()));
        let sender = HostAddress::from_socket(remote);
        crate::plugins::set_request_peer(Some(sender.clone()));
        let store = &self.store;
        #[cfg(test)]
        let panics = self.panic_on.as_deref() == Some(request);
        let run = catch_unwind(AssertUnwindSafe(|| {
            #[cfg(test)]
            assert!(!panics, "a request set to panic");
            read_store(store, |s| process(s, request, &sender))
        }));
        crate::plugins::set_request_peer(None);
        run.ok()
    }

    fn dispatch_panic(&mut self, request: &[u8]) -> Reply {
        crate::plugins::set_otp_resume(None);
        drop(crate::plugins::take_otp_park());
        self.lookaside.finish(request, None);
        tracing::error!(
            event = krb5_log::events::KDC_TRANSPORT,
            correlation_id = krb5_log::current_correlation_id(),
            component = "krb5-kdc",
            outcome = "error",
            error = "request panic isolated",
        );
        Reply::Nothing
    }

    // MIT: `finish_dispatch_cache` (kdc/dispatch.c:77-83)
    fn finish_dispatch_cache(&mut self, request: &[u8], is_tcp: bool, done: Done) -> Reply {
        match &done {
            // An empty reply is a discard: it is not cached, and the mark stays.
            Done::Failed { discard: true, .. } => {}
            Done::Reply(bytes) => self.lookaside.finish(request, Some(bytes)),
            Done::Failed { .. } => self.lookaside.finish(request, None),
        }
        self.finish_dispatch(is_tcp, done)
    }

    // MIT: `finish_dispatch` (kdc/dispatch.c:54-66)
    fn finish_dispatch(&self, is_tcp: bool, done: Done) -> Reply {
        match done {
            // An oversized UDP reply, a resend included, is this realm's response-too-big.
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

fn process(store: &dyn PrincipalRead, raw: &[u8], sender: &HostAddress) -> Done {
    match process_logged(store, raw, Some(sender)) {
        // MIT: `finish_process_as_req` (kdc/do_as_req.c:371-381)
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
    // MIT: `dispatch` (kdc/dispatch.c:114-141)
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
        crate::plugins::set_otp_resume(None);
        drop(crate::plugins::take_otp_park());
        let Some(done) = self.run_contained(remote, request) else {
            return self.dispatch_panic(request);
        };
        // OTP verify pending: hold the lookaside mark; the loop resumes us.
        if crate::plugins::otp_park_pending() {
            return Reply::Parked;
        }
        self.finish_dispatch_cache(request, is_tcp, done)
    }

    // MIT: `finish_dispatch_cache` (kdc/dispatch.c:77-83)
    fn dispatch_resume(
        &mut self,
        _local: SocketAddr,
        remote: SocketAddr,
        request: &[u8],
        is_tcp: bool,
        _log: &mut dyn Log,
    ) -> Reply {
        let Some(done) = self.run_contained(remote, request) else {
            return self.dispatch_panic(request);
        };
        if crate::plugins::otp_park_pending() {
            return Reply::Parked;
        }
        crate::plugins::set_otp_resume(None);
        self.finish_dispatch_cache(request, is_tcp, done)
    }

    fn otp_wake_fd(&self) -> Option<OwnedFd> {
        read_store(&self.store, |s| {
            s.otp_runtime().and_then(|rt| rt.pool().wake_read_fd())
        })
    }

    // MIT: `make_toolong_error` (kdc/kdc_util.c:1882-1913)
    fn make_toolong_error(&mut self) -> Result<Vec<u8>, String> {
        Ok(plain_store(&self.store, |s| {
            super::kdc_error_bytes(s, err::FIELD_TOOLONG)
        }))
    }
}

pub(crate) struct ThreadSlots {
    policy: Option<Arc<dyn KdcPolicy>>,
    policies: Option<Vec<Arc<dyn KdcPolicy>>>,
    preauth: Option<Vec<Arc<dyn KdcPreauth>>>,
    authdata: Option<Vec<Arc<dyn KdcAuthdata>>>,
    otp: Option<Vec<Arc<dyn OtpVerifier>>>,
    audit: Option<Arc<dyn KdcAudit>>,
    audits: Option<Vec<Arc<dyn KdcAudit>>>,
}

impl ThreadSlots {
    pub(crate) fn take() -> Self {
        Self {
            policy: take_thread_policy(),
            policies: take_thread_kdcpolicies(),
            preauth: take_thread_preauth(),
            authdata: take_thread_authdata(),
            otp: take_thread_otp_verifiers(),
            audit: take_thread_audit(),
            audits: take_thread_audits(),
        }
    }
}

impl Drop for ThreadSlots {
    fn drop(&mut self) {
        restore_thread_policy(self.policy.take());
        restore_thread_kdcpolicies(self.policies.take());
        restore_thread_preauth(self.preauth.take());
        restore_thread_authdata(self.authdata.take());
        restore_thread_otp_verifiers(self.otp.take());
        restore_thread_audit(self.audit.take());
        restore_thread_audits(self.audits.take());
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use krb5_asn1::encode;
    use krb5_types::{KrbError, PrincipalName};

    use super::*;
    use crate::asn1_text::ASN1_OVERRUN;
    use crate::listen::shared_store;
    use crate::plugins::{OtpVerdict, OtpVerifyRequest};
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

    fn nosuch(nonce: u32) -> Vec<u8> {
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["nosuch"]);
        encode(&krb5_protocol::as_req(cname, TEST_REALM, nonce, None).unwrap()).unwrap()
    }

    const AS_REQ_BODY: &str = "6a8183308180a103020105a20302010aa4743072a00703050000000000a1133011a003020101a10a30081b066e6f73756368a20d1b0b534554544c452e54455354a320301ea003020102a11730151b066b72627467741b0b534554544c452e54455354a511180f32303337303931333032343830355aa704020210f7a8083006020112020111";

    /// Requests MIT 1.22.2's dispatch refused when settled live, byte for byte, each with the text MIT logged "- while dispatching (udp)".
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

    /// Each request MIT refused is refused with MIT's text, with no DISPATCH line, and is not cached: sent again, it is refused again. The library entry point answers it with nothing.
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
        let r = k.dispatch(local(), peer(), &hex(AS_REQ_BODY), false, &mut log);
        let Reply::Send(bytes) = r else {
            panic!("no reply: {r:?}")
        };
        let e: KrbError = krb5_asn1::decode(&bytes).unwrap();
        assert_eq!(e.error_code, err::C_PRINCIPAL_UNKNOWN);
    }

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

    /// A discarded request keeps its in-progress mark, so its repeats are dropped while the lookaside holds it; any other outcome removes the mark.
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

    /// A request whose processing panics is answered with nothing and its mark removed, so the same request is processed when it comes again.
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

    /// A reply too big for UDP goes out as RESPONSE_TOO_BIG, and the whole reply is cached, so the client's retry over TCP is resent it.
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

    #[test]
    fn field_toolong_is_mits_error() {
        let mut k = kdc(65_536);
        let e: KrbError = krb5_asn1::decode(&k.make_toolong_error().unwrap()).unwrap();
        assert_eq!(e.error_code, err::FIELD_TOOLONG);
        assert_eq!(std::str::from_utf8(e.realm.as_bytes()).unwrap(), TEST_REALM);
        assert_eq!(e.sname, PrincipalName::krbtgt(TEST_REALM));
        assert!(e.cname.is_none() && e.crealm.is_none() && e.e_text.is_none());
    }

    /// A replay the lookaside no longer holds is processed again: the AS-REQ with the same PA-ENC-TIMESTAMP and the TGS-REQ with the same authenticator each get a new ticket, where the lookaside resent the first reply while it held it.
    // MIT: `dispatch` (kdc/dispatch.c:114-140)
    /// only the lookaside answers a repeated request, so one it no longer holds is processed again.
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

    struct NoOtp;

    impl OtpVerifier for NoOtp {
        fn name(&self) -> &'static str {
            "none"
        }
        fn verify(&self, _req: &OtpVerifyRequest) -> OtpVerdict {
            OtpVerdict::Reject
        }
    }

    fn is_own<T: ?Sized>(slot: &[Arc<T>], own: &Arc<T>) -> bool {
        slot.iter().any(|m| Arc::ptr_eq(m, own))
    }

    #[test]
    fn thread_slots_come_off_and_go_back() {
        use crate::plugins::{authdata_modules, preauth_modules};

        let policy: Arc<dyn KdcPolicy> = Arc::new(crate::testrealm::TestPolicy);
        let audit: Arc<dyn KdcAudit> = Arc::new(crate::audit::JsonAudit);
        let preauth: Arc<dyn KdcPreauth> = Arc::new(NoPreauth);
        let authdata: Arc<dyn KdcAuthdata> = Arc::new(NoAuthdata);
        let otp: Arc<dyn OtpVerifier> = Arc::new(NoOtp);
        let own_otp = |v: &Arc<dyn OtpVerifier>| {
            crate::plugins::find_otp_verifier(v.name()).is_some_and(|f| Arc::ptr_eq(&f, v))
        };
        crate::plugins::set_thread_policy(Arc::clone(&policy));
        crate::audit::set_thread_audit(Arc::clone(&audit));
        crate::plugins::set_thread_preauth(vec![Arc::clone(&preauth)]);
        crate::plugins::set_thread_authdata(vec![Arc::clone(&authdata)]);
        crate::plugins::set_thread_otp_verifiers(vec![Arc::clone(&otp)]);
        {
            let _slots = ThreadSlots::take();
            assert!(!Arc::ptr_eq(&crate::plugins::current_policy(), &policy));
            assert!(!Arc::ptr_eq(&crate::audit::current_audit(), &audit));
            assert!(!is_own(&preauth_modules(), &preauth));
            assert!(!is_own(&authdata_modules(), &authdata));
            assert!(!own_otp(&otp));
        }
        assert!(Arc::ptr_eq(&crate::plugins::current_policy(), &policy));
        assert!(Arc::ptr_eq(&crate::audit::current_audit(), &audit));
        assert!(is_own(&preauth_modules(), &preauth));
        assert!(is_own(&authdata_modules(), &authdata));
        assert!(own_otp(&otp));
        // A loop that ends by a panic puts the slots back as it unwinds.
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _slots = ThreadSlots::take();
            assert!(!is_own(&preauth_modules(), &preauth));
            assert!(!own_otp(&otp));
            panic!("the loop ends by a panic");
        }));
        assert!(unwound.is_err());
        assert!(Arc::ptr_eq(&crate::plugins::current_policy(), &policy));
        assert!(Arc::ptr_eq(&crate::audit::current_audit(), &audit));
        assert!(is_own(&preauth_modules(), &preauth));
        assert!(is_own(&authdata_modules(), &authdata));
        assert!(own_otp(&otp));
        crate::plugins::clear_thread_policy();
        crate::audit::clear_thread_audit();
        crate::plugins::clear_thread_preauth();
        crate::plugins::clear_thread_authdata();
        crate::plugins::clear_thread_otp_verifiers();
    }
}
