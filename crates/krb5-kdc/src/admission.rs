//! The host's say over logins of the principals it owns (the host mark).

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use krb5_types::{EncTicketPart, HostAddress, KdcReqBody, PrincipalName, err};

use crate::error::Error;
use crate::kdb::PrincipalRead;
use crate::status;
use crate::store::Principal;

/// A KDC error code, and the e-text the client is sent with it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdcRefusal {
    pub code: i32,
    pub e_text: Option<String>,
}

/// Asked before pre-authentication, where MIT checks lockout.
#[derive(Debug)]
pub struct AsQuestion<'a> {
    /// The record the name resolved to: an alias gives its target.
    pub client: &'a Principal,
    pub requested: &'a PrincipalName,
    pub server: &'a Principal,
    pub peer: Option<&'a HostAddress>,
    pub now: u32,
    pub request: &'a KdcReqBody,
    pub s4u2self: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    EncTimestamp,
    EncChallenge,
    Spake,
    Pkinit,
    Otp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsReason {
    Issued,
    /// The mechanism ran and the secret was wrong, an OTP reject included.
    PreauthFailed,
    /// The mechanism could not decide: skew, an OTP timeout, no verifier, a cookie.
    PreauthNotCompleted,
    /// Pre-authentication passed or was not required, then the request was refused.
    PolicyRefused,
    /// MIT's checks of the entry before pre-authentication.
    EntryRefused,
    /// This module's own `check_as`.
    HostRefused,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsNotice {
    pub client: String,
    pub requested: String,
    pub peer: Option<HostAddress>,
    pub time: u32,
    /// The code sent, or 0.
    pub code: i32,
    pub reason: AsReason,
    pub mechanism: Option<Mechanism>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TgsKind {
    Normal,
    Renew,
    Validate,
    U2u,
    S4u2Self,
    S4u2Proxy,
}

#[derive(Clone, Copy, Debug)]
pub enum TgsClient<'a> {
    Found(&'a Principal),
    NoEntry,
    ReadFailed,
}

impl<'a> TgsClient<'a> {
    #[must_use]
    pub fn principal(self) -> Option<&'a Principal> {
        match self {
            Self::Found(p) => Some(p),
            Self::NoEntry | Self::ReadFailed => None,
        }
    }
}

#[derive(Debug)]
pub struct TgsQuestion<'a> {
    pub client: TgsClient<'a>,
    pub subject: &'a PrincipalName,
    pub server: &'a Principal,
    pub ticket: &'a EncTicketPart,
    pub request: &'a KdcReqBody,
    pub peer: Option<&'a HostAddress>,
    pub now: u32,
    pub kind: TgsKind,
}

/// `check_as` and `check_tgs` run under the store's read guard: answer from memory,
/// and never write the store from them. `as_notice` runs after that guard is released.
pub trait HostAdmission: Send + Sync {
    fn check_as(&self, q: &AsQuestion<'_>) -> Result<(), KdcRefusal>;
    fn as_notice(&self, n: AsNotice);
    fn check_tgs(&self, q: &TgsQuestion<'_>) -> Result<(), KdcRefusal>;
}

#[derive(Clone, Copy, Default)]
struct Attempt {
    mechanism: Option<Mechanism>,
    failed: Option<bool>,
    passed_preauth: bool,
    host_refused: bool,
}

type Queued = (Arc<dyn HostAdmission>, AsNotice);

thread_local! {
    static ATTEMPT: RefCell<Attempt> = RefCell::new(Attempt::default());
    static NOTICES: RefCell<Vec<Queued>> = const { RefCell::new(Vec::new()) };
}

fn attempt(f: impl FnOnce(&mut Attempt)) {
    ATTEMPT.with(|a| f(&mut a.borrow_mut()));
}

pub(crate) fn begin_attempt() {
    attempt(|a| *a = Attempt::default());
}

pub(crate) fn mechanism_of(module: &str) -> Option<Mechanism> {
    match module {
        "encrypted_timestamp" => Some(Mechanism::EncTimestamp),
        "encrypted_challenge" => Some(Mechanism::EncChallenge),
        "spake" => Some(Mechanism::Spake),
        "pkinit" => Some(Mechanism::Pkinit),
        "otp" => Some(Mechanism::Otp),
        _ => None,
    }
}

/// The OTP module's library code for a rejected token, before it is filtered to 24.
const KRB5_PREAUTH_FAILED: i32 = -1_765_328_174;

/// Before `filter_preauth_error` turns every code into 24.
pub(crate) fn note_preauth_failure(module: &str, raw: &Error) {
    let code = match raw {
        Error::Protocol { code, .. } | Error::PreauthModule { code, .. } => Some(*code),
        _ => None,
    };
    let wrong = matches!(
        code,
        Some(err::PREAUTH_FAILED | err::BAD_INTEGRITY | KRB5_PREAUTH_FAILED)
    );
    attempt(|a| {
        a.mechanism = mechanism_of(module).or(a.mechanism);
        a.failed = Some(wrong);
    });
}

pub(crate) fn note_preauth_ok(mechanism: Option<Mechanism>) {
    attempt(|a| a.mechanism = mechanism.or(a.mechanism));
}

pub(crate) fn note_passed_preauth() {
    attempt(|a| a.passed_preauth = true);
}

fn admission(store: &dyn PrincipalRead) -> Option<Arc<dyn HostAdmission>> {
    store.policy().plugins.host_admission()
}

static WARNED_NO_MODULE: AtomicBool = AtomicBool::new(false);

fn no_module(client: &Principal) -> Error {
    if !WARNED_NO_MODULE.swap(true, Ordering::Relaxed) {
        krb5_log::klog::syslog(
            krb5_log::klog::Severity::Err,
            &format!(
                "{} is owned by the host but no admission module is installed: refused",
                client.id()
            ),
        );
    }
    crate::preauth::proto(err::CLIENT_REVOKED, status::LOCKED_OUT)
}

fn refused(r: KdcRefusal) -> Error {
    Error::Protocol {
        code: r.code,
        text: r.e_text,
        e_data: None,
        detail: None,
    }
}

// MIT: `krb5_db_check_policy_as` (lib/kdb/kdb5.c:2657-2675)
/// A host-owned entry gets the host's verdict instead of the KDC's lockout check.
pub(crate) fn check_as_policy(
    store: &dyn PrincipalRead,
    client: &Principal,
    requested: &PrincipalName,
    server: &Principal,
    request: &KdcReqBody,
    now: u32,
    s4u2self: bool,
) -> Result<(), Error> {
    if !client.host_owned() {
        return crate::lockout::lockout_check_policy(store, client, now);
    }
    let Some(module) = admission(store) else {
        attempt(|a| a.host_refused = true);
        return Err(no_module(client));
    };
    let peer = crate::plugins::request_peer();
    let q = AsQuestion {
        client,
        requested,
        server,
        peer: peer.as_ref(),
        now,
        request,
        s4u2self,
    };
    module.check_as(&q).map_err(|r| {
        attempt(|a| a.host_refused = true);
        refused(r)
    })
}

/// Queued here; delivered once the request has let go of the store.
pub(crate) fn queue_notice<T>(
    store: &dyn PrincipalRead,
    client: &Principal,
    requested: &PrincipalName,
    time: u32,
    out: &Result<T, Error>,
) {
    let Some(module) = admission(store) else {
        return;
    };
    let code = crate::lockout::as_outcome(out);
    if matches!(
        code,
        err::PREAUTH_REQUIRED | err::MORE_PREAUTH_DATA_REQUIRED | err::DISCARD
    ) {
        return;
    }
    let a = ATTEMPT.with(|a| *a.borrow());
    let reason = match (out.is_ok(), a.host_refused, a.failed) {
        (true, ..) => AsReason::Issued,
        (false, true, _) => AsReason::HostRefused,
        (false, false, Some(true)) => AsReason::PreauthFailed,
        (false, false, Some(false)) => AsReason::PreauthNotCompleted,
        (false, false, None) if a.passed_preauth => AsReason::PolicyRefused,
        (false, false, None) => AsReason::EntryRefused,
    };
    let notice = AsNotice {
        client: client.id(),
        requested: requested.unparse_with_realm_lossy(&client.realm),
        peer: crate::plugins::request_peer(),
        time,
        code,
        reason,
        mechanism: a.mechanism,
    };
    NOTICES.with(|n| n.borrow_mut().push((module, notice)));
}

/// With no store guard held.
pub(crate) fn deliver_notices() {
    for (module, notice) in NOTICES.with(|n| std::mem::take(&mut *n.borrow_mut())) {
        module.as_notice(notice);
    }
}

pub(crate) fn drop_notices() {
    NOTICES.with(|n| n.borrow_mut().clear());
}

/// Stricter than MIT, whose TGS never looks at the client: only for host-owned subjects.
#[expect(
    clippy::too_many_arguments,
    reason = "the TGS request as the host sees it"
)]
pub(crate) fn check_tgs_policy(
    store: &dyn PrincipalRead,
    request: &KdcReqBody,
    server: &Principal,
    ticket: &EncTicketPart,
    subject: &PrincipalName,
    client: TgsClient<'_>,
    kind: TgsKind,
    now: u32,
) -> Result<(), Error> {
    let Some(module) = admission(store) else {
        return match client {
            TgsClient::Found(c) if c.host_owned() => Err(no_module(c)),
            _ => Ok(()),
        };
    };
    if client.principal().is_some_and(|c| !c.host_owned()) {
        return Ok(());
    }
    let peer = crate::plugins::request_peer();
    let q = TgsQuestion {
        client,
        subject,
        server,
        ticket,
        request,
        peer: peer.as_ref(),
        now,
        kind,
    };
    module.check_tgs(&q).map_err(refused)
}
