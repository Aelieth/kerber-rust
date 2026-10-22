//! The ISSUE tuple records the decision. It is not the reply.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use krb5_asn1::decode;
use krb5_crypto::EncryptionType;
use krb5_types::{
    AsRep, AsReq, EncTicketPart, HostAddress, KdcReqBody, PrincipalName, TgsRep, TgsReq, Ticket,
    TransitError, TransitedEncoding, err, flag_bit, pa,
};
use sha2::{Digest, Sha256};

use crate::decrypt_ticket_part;
use crate::kdb::{PrincipalRead, lookup_principal_id};
use crate::status;
use crate::store::Principal;

pub const AUTHN_REQ_CL: i32 = 1;
pub const SRVC_PRINC: i32 = 2;
pub const ENCR_REP: i32 = 5;

/// 32 with the C NUL, so the printable id is 31.
pub const REQID_LEN: usize = 32;
const REQID_CHARS: usize = REQID_LEN - 1;

const RAND_ALPHANUM: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const HEX_UP: &[u8; 16] = b"0123456789ABCDEF";

#[must_use]
/// SHA-256 of the ticket ciphertext, 64 uppercase hex digits.
pub fn make_tkt_id(ciphertext: &[u8]) -> String {
    let hash = Sha256::digest(ciphertext);
    let mut out = String::with_capacity(64);
    for b in hash {
        out.push(HEX_UP[usize::from(b >> 4)] as char);
        out.push(HEX_UP[usize::from(b & 0x0f)] as char);
    }
    out
}

#[must_use]
pub fn new_req_id() -> String {
    let mut bytes = [0u8; REQID_CHARS];
    let _ = getrandom::getrandom(&mut bytes);
    let mut out = String::with_capacity(REQID_CHARS);
    for b in bytes {
        out.push(RAND_ALPHANUM[usize::from(b) % RAND_ALPHANUM.len()] as char);
    }
    out
}

#[must_use]
pub fn enctype_name(etype: i32) -> String {
    match etype {
        6 => return "DEPRECATED:des3-cbc-raw".into(),
        24 => return "DEPRECATED:arcfour-hmac-exp".into(),
        _ => {}
    }
    if let Some(n) = cms_enctype_name(etype) {
        if EncryptionType::known(etype).is_ok() {
            return n.to_string();
        }
        return format!("UNSUPPORTED:{n}");
    }
    match EncryptionType::known(etype) {
        Ok(et) if et.is_deprecated() => format!("DEPRECATED:{}", et.to_mit_name()),
        Ok(et) => et.to_mit_name().to_string(),
        Err(_) => match des_enctype_name(etype) {
            Some(n) => format!("UNSUPPORTED:{n}"),
            None => "UNSUPPORTED:".to_string(),
        },
    }
}

#[must_use]
pub fn ktypes2str(etypes: &[i32]) -> String {
    let mut out = format!("{} etypes {{", etypes.len());
    for (i, et) in etypes.iter().copied().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{}({et})", enctype_name(et));
    }
    out.push('}');
    out
}

#[must_use]
pub fn rep_etypes2str(rep: i32, tkt: Option<i32>, ses: Option<i32>) -> String {
    let mut out = format!("etypes {{rep={}({rep})", enctype_name(rep));
    if let Some(t) = tkt {
        let _ = write!(out, ", tkt={}({t})", enctype_name(t));
    }
    if let Some(s) = ses {
        let _ = write!(out, ", ses={}({s})", enctype_name(s));
    }
    out.push('}');
    out
}

// MIT: `limit_string` (kdc/kdc_util.c:1120-1135)
/// A name of 128 bytes or more is cut so the rest of the line still fits.
fn limit_string(name: &str) -> String {
    if name.len() < 128 {
        return name.to_owned();
    }
    let mut end = 124;
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &name[..end])
}

#[must_use]
pub fn kdc_error_message(code: i32) -> String {
    let text = match code {
        0 => "No error",
        1 => "Client's entry in database has expired",
        2 => "Server's entry in database has expired",
        3 => "Requested protocol version not supported",
        4 => "Client's key is encrypted in an old master key",
        5 => "Server's key is encrypted in an old master key",
        6 => "Client not found in Kerberos database",
        7 => "Server not found in Kerberos database",
        8 => "Principal has multiple entries in Kerberos database",
        9 => "Client or server has a null key",
        10 => "Ticket is ineligible for postdating",
        11 => "Requested effective lifetime is negative or too short",
        12 => "KDC policy rejects request",
        13 => "KDC can't fulfill requested option",
        14 => "KDC has no support for encryption type",
        15 => "KDC has no support for checksum type",
        16 => "KDC has no support for padata type",
        17 => "KDC has no support for transited type",
        18 => "Client's credentials have been revoked",
        19 => "Credentials for server have been revoked",
        20 => "TGT has been revoked",
        21 => "Client not yet valid - try again later",
        22 => "Server not yet valid - try again later",
        23 => "Password has expired",
        24 => "Preauthentication failed",
        25 => "Additional pre-authentication required",
        26 => "Requested server and ticket don't match",
        27 => "Server principal valid for user2user only",
        28 => "KDC policy rejects transited path",
        29 => "A service is not available that is required to process the request",
        31 => "Decrypt integrity check failed",
        32 => "Ticket expired",
        33 => "Ticket not yet valid",
        34 => "Request is a replay",
        35 => "The ticket isn't for us",
        36 => "Ticket/authenticator don't match",
        37 => "Clock skew too great",
        38 => "Incorrect net address",
        39 => "Protocol version mismatch",
        40 => "Invalid message type",
        41 => "Message stream modified",
        42 => "Message out of order",
        43 => "Illegal cross-realm ticket",
        44 => "Key version is not available",
        45 => "Service key not available",
        46 => "Mutual authentication failed",
        47 => "Incorrect message direction",
        48 => "Alternative authentication method required",
        49 => "Incorrect sequence number in message",
        50 => "Inappropriate type of checksum in message",
        51 => "Policy rejects transited path",
        52 => "Response too big for UDP, retry with TCP",
        60 => "Generic error (see e-text)",
        61 => "Field is too long for this implementation",
        62 => "Client not trusted",
        63 => "KDC not trusted",
        64 => "Invalid signature",
        65 => "Key parameters not accepted",
        66 => "Certificate mismatch",
        67 => "No ticket granting ticket",
        68 => "Realm not local to KDC",
        69 => "User to user required",
        70 => "Can't verify certificate",
        71 => "Invalid certificate",
        72 => "Revoked certificate",
        73 => "Revocation status unknown",
        74 => "Revocation status unavailable",
        75 => "Client name mismatch",
        76 => "KDC name mismatch",
        77 => "Inconsistent key purpose",
        78 => "Digest in certificate not accepted",
        79 => "Checksum must be included",
        80 => "Digest in signed-data not accepted",
        81 => "Public key encryption not supported",
        85 => "The IAKERB proxy could not find a KDC",
        86 => "The KDC did not respond to the IAKERB proxy",
        90 => "Preauthentication expired",
        91 => "More preauthentication data is required",
        93 => "An unsupported critical FAST option was requested",
        100 => "No acceptable KDF offered",
        _ => return format!("KRB5 error code {code}"),
    };
    text.to_owned()
}

// MIT: `gather_tgs_req_info` (kdc/do_tgs_req.c:727-754)
/// An early TGS failure logs authtime 0; the subject ticket is not open yet.
fn tgs_failed_before_authtime(status: &str) -> bool {
    matches!(
        status,
        status::PROCESS_TGS
            | status::FIND_FAST
            | status::NULL_SERVER
            | status::GET_LOCAL_TGT
            | status::HEADER_PAC
            | status::LOOKING_UP_SERVER
            | status::UNKNOWN_SERVER
            | status::DECODE_PA_FOR_USER
            | status::DECODE_PA_S4U_X509_USER
            | status::INVALID_S4U2SELF_CHECKSUM
            | status::INVALID_S4U2SELF_REQUEST
            | status::LOOKING_UP_S4U2SELF_PRINCIPAL
            | status::UNKNOWN_S4U2SELF_PRINCIPAL
            | status::SECOND_TKT_SERVER
            | status::SECOND_TKT_DECRYPT
            | status::SECOND_TKT_PAC
            | status::RBCD_PAC_PRINC
    )
}

enum MitOutcome<'a> {
    Issue {
        authtime: u32,
        etypes: &'a str,
    },
    Fail {
        status: &'a str,
        code: i32,
        authtime: u32,
        emsg: &'a str,
    },
}

// MIT: `log_as_req` (kdc/kdc_log.c:57-97)
fn as_req_line(
    req_etypes: &str,
    from: &str,
    outcome: &MitOutcome<'_>,
    client: &str,
    server: &str,
) -> String {
    let (client, server) = (limit_string(client), limit_string(server));
    match outcome {
        MitOutcome::Issue { authtime, etypes } => format!(
            "AS_REQ ({req_etypes}) {from}: ISSUE: authtime {authtime}, {etypes}, {client} for {server}"
        ),
        MitOutcome::Fail {
            status, code, emsg, ..
        } => format!(
            "AS_REQ ({req_etypes}) {from}: {status}: {client} for {server}, {}",
            failure_emsg(*code, emsg)
        ),
    }
}

// MIT: `log_tgs_req` (kdc/kdc_log.c:117-173)
fn tgs_req_lines(
    req_etypes: &str,
    from: &str,
    outcome: &MitOutcome<'_>,
    client: &str,
    server: &str,
    s4u: Option<(&str, &str)>,
) -> Vec<String> {
    let (client, server) = (limit_string(client), limit_string(server));
    let line = match outcome {
        MitOutcome::Fail {
            status,
            code,
            authtime,
            ..
        // A server mismatch logs the second ticket's client, not the etypes.
        } if *code == err::SERVER_NOMATCH => {
            let alt = limit_string(s4u.map_or("<unknown>", |(_, c)| c));
            return vec![format!(
                "TGS_REQ {from}: {status}: authtime {authtime}, {client} for {server}, 2nd tkt client {alt}"
            )];
        }
        MitOutcome::Issue { authtime, etypes } => format!(
            "TGS_REQ ({req_etypes}) {from}: ISSUE: authtime {authtime}, {etypes}, {client} for {server}"
        ),
        MitOutcome::Fail {
            status,
            code,
            authtime,
            emsg,
        } => format!(
            "TGS_REQ ({req_etypes}) {from}: {status}: authtime {authtime},  {client} for {server}, {}",
            failure_emsg(*code, emsg)
        ),
    };
    let mut lines = vec![line];
    // The S4U client is a following line, not folded into the request line.
    if let Some((kind, s4u_client)) = s4u {
        lines.push(format!(
            "... {kind} s4u-client={}",
            limit_string(s4u_client)
        ));
    }
    lines
}

fn klog_as_req(req_etypes: &str, from: &str, outcome: &MitOutcome<'_>, client: &str, server: &str) {
    krb5_log::klog::syslog(
        krb5_log::klog::Severity::Info,
        &as_req_line(req_etypes, from, outcome, client, server),
    );
}

fn klog_tgs_req(
    req_etypes: &str,
    from: &str,
    outcome: &MitOutcome<'_>,
    client: &str,
    server: &str,
    s4u: Option<(&str, &str)>,
) {
    for line in tgs_req_lines(req_etypes, from, outcome, client, server, s4u) {
        krb5_log::klog::syslog(krb5_log::klog::Severity::Info, &line);
    }
}

pub trait KdcAudit: Send + Sync {
    fn name(&self) -> &'static str {
        ""
    }

    fn kdc_start(&self, success: bool) {
        let _ = success;
    }
    fn kdc_stop(&self, success: bool) {
        let _ = success;
    }
    fn as_req(&self, success: bool, state: &AuditState) {
        let _ = (success, state);
    }
    fn tgs_req(&self, success: bool, state: &AuditState) {
        let _ = (success, state);
    }
    fn s4u2self(&self, success: bool, state: &AuditState) {
        let _ = (success, state);
    }
    fn s4u2proxy(&self, success: bool, state: &AuditState) {
        let _ = (success, state);
    }
    fn u2u(&self, success: bool, state: &AuditState) {
        let _ = (success, state);
    }
}

#[derive(Clone, Debug, Default)]
pub struct AuditState {
    pub event_name: &'static str,
    pub stage: i32,
    pub tkt_out_id: Option<String>,
    pub(crate) tkt_in_id: Option<String>,
    pub req_id: String,
    pub(crate) cl_port: u32,
    pub cl_addr: Option<HostAddress>,
    pub status: Option<String>,
    pub(crate) req_client: Option<PrincipalName>,
    pub(crate) req_client_realm: Option<String>,
    pub(crate) req_server: Option<PrincipalName>,
    pub(crate) req_server_realm: Option<String>,
    pub kdc_options: u32,
    pub(crate) avail_etypes: Vec<i32>,
    pub(crate) tkt_renewed: i32,
    pub(crate) tkt_validated: i32,
}

pub struct JsonAudit;

impl KdcAudit for JsonAudit {
    fn name(&self) -> &'static str {
        "json"
    }

    fn kdc_start(&self, success: bool) {
        emit_trace_record(&start_stop_json("KDC_START", success));
    }
    fn kdc_stop(&self, success: bool) {
        emit_trace_record(&start_stop_json("KDC_STOP", success));
    }
    fn as_req(&self, success: bool, state: &AuditState) {
        emit_trace_record(&state.to_json(success));
    }
    fn tgs_req(&self, success: bool, state: &AuditState) {
        emit_trace_record(&state.to_json(success));
    }
    fn s4u2self(&self, success: bool, state: &AuditState) {
        emit_trace_record(&state.to_json(success));
    }
    fn s4u2proxy(&self, success: bool, state: &AuditState) {
        emit_trace_record(&state.to_json(success));
    }
    fn u2u(&self, success: bool, state: &AuditState) {
        emit_trace_record(&state.to_json(success));
    }
}

static AUDIT: Mutex<Option<Arc<dyn KdcAudit>>> = Mutex::new(None);
static NAMED_AUDITS: Mutex<Vec<Arc<dyn KdcAudit>>> = Mutex::new(Vec::new());

thread_local! {
    static THREAD_AUDIT: std::cell::RefCell<Option<Arc<dyn KdcAudit>>> =
        const { std::cell::RefCell::new(None) };
    static THREAD_AUDITS: std::cell::RefCell<Option<Vec<Arc<dyn KdcAudit>>>> =
        const { std::cell::RefCell::new(None) };
    static CL_PORT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static CUR_REQ_ID: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

pub fn set_audit(a: Arc<dyn KdcAudit>) {
    *AUDIT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(a);
}

pub fn set_thread_audit(a: Arc<dyn KdcAudit>) {
    THREAD_AUDIT.with(|t| *t.borrow_mut() = Some(a));
}

pub fn clear_thread_audit() {
    THREAD_AUDIT.with(|t| *t.borrow_mut() = None);
}

pub(crate) fn take_thread_audit() -> Option<Arc<dyn KdcAudit>> {
    THREAD_AUDIT.with(|t| t.borrow_mut().take())
}

pub(crate) fn restore_thread_audit(a: Option<Arc<dyn KdcAudit>>) {
    THREAD_AUDIT.with(|t| *t.borrow_mut() = a);
}

#[must_use]
pub fn current_audit() -> Arc<dyn KdcAudit> {
    if let Some(a) = THREAD_AUDIT.with(|t| t.borrow().clone()) {
        return a;
    }
    AUDIT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .unwrap_or_else(|| Arc::new(JsonAudit))
}

pub fn register_audit(module: Arc<dyn KdcAudit>) {
    NAMED_AUDITS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(module);
}

pub fn set_thread_audits(modules: Vec<Arc<dyn KdcAudit>>) {
    THREAD_AUDITS.with(|slot| *slot.borrow_mut() = Some(modules));
}

pub fn clear_thread_audits() {
    THREAD_AUDITS.with(|slot| *slot.borrow_mut() = None);
}

pub(crate) fn take_thread_audits() -> Option<Vec<Arc<dyn KdcAudit>>> {
    THREAD_AUDITS.with(|slot| slot.borrow_mut().take())
}

pub(crate) fn restore_thread_audits(modules: Option<Vec<Arc<dyn KdcAudit>>>) {
    THREAD_AUDITS.with(|slot| *slot.borrow_mut() = modules);
}

// MIT: `filter_enabled_modules` (lib/krb5/krb/plugin.c:271-299)
fn selected_audits(
    relations: &krb5_config::PluginRelations,
    modules: Vec<Arc<dyn KdcAudit>>,
) -> Vec<Arc<dyn KdcAudit>> {
    let names: Vec<&str> = modules.iter().map(|module| module.name()).collect();
    let kept = krb5_config::filter_plugin_modules(relations, &names);
    let mut left = modules;
    let mut out = Vec::new();
    for want in kept {
        if let Some(index) = left.iter().position(|module| module.name() == want) {
            out.push(left.remove(index));
        }
    }
    out
}

// MIT: `kau_as_req` (kdc/kdc_audit.c:260-272)
fn active_audits(store: &dyn PrincipalRead) -> Vec<Arc<dyn KdcAudit>> {
    if let Some(module) = THREAD_AUDIT.with(|slot| slot.borrow().clone()) {
        return vec![module];
    }
    if let Some(modules) = THREAD_AUDITS.with(|slot| slot.borrow().clone()) {
        return selected_audits(&store.policy().audit, modules);
    }
    if let Some(module) = AUDIT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
    {
        return vec![module];
    }
    let mut modules: Vec<Arc<dyn KdcAudit>> = vec![Arc::new(JsonAudit)];
    modules.extend(
        NAMED_AUDITS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone(),
    );
    selected_audits(&store.policy().audit, modules)
}

// MIT: `kau_as_req` (kdc/kdc_audit.c:260-272)
fn each_audit(store: &dyn PrincipalRead, mut call: impl FnMut(&dyn KdcAudit)) {
    for module in active_audits(store) {
        call(module.as_ref());
    }
}

// MIT: `kau_kdc_start` (kdc/kdc_audit.c:244-256)
/// Disabling json leaves no module, so nothing is recorded.
pub fn audit_kdc_start(store: &dyn PrincipalRead, success: bool) {
    each_audit(store, |module| module.kdc_start(success));
}

// MIT: `kau_kdc_stop` (kdc/kdc_audit.c:229-241)
pub fn audit_kdc_stop(store: &dyn PrincipalRead, success: bool) {
    each_audit(store, |module| module.kdc_stop(success));
}

pub(crate) fn set_client_port(port: u32) {
    CL_PORT.with(|c| c.set(port));
}

#[must_use]
pub(crate) fn client_port() -> u32 {
    CL_PORT.with(std::cell::Cell::get)
}

fn current_req_id() -> String {
    CUR_REQ_ID.with(|c| {
        if let Some(id) = c.borrow().as_ref() {
            return id.clone();
        }
        let id = new_req_id();
        *c.borrow_mut() = Some(id.clone());
        id
    })
}

fn clear_req_id() {
    CUR_REQ_ID.with(|c| *c.borrow_mut() = None);
}

// MIT: `process_as_req` (do_as_req.c:520-520)
fn seed_as_req(store: &dyn PrincipalRead, req: &AsReq, sender: Option<&HostAddress>) {
    clear_req_id();
    let mut state = base_state("AS_REQ", &req.0.req_body, sender);
    state.stage = AUTHN_REQ_CL;
    each_audit(store, |module| module.as_req(true, &state));
}

// MIT: `process_tgs_req` (do_tgs_req.c:1181-1184)
fn seed_tgs_req(store: &dyn PrincipalRead, req: &TgsReq, sender: Option<&HostAddress>) {
    clear_req_id();
    let mut state = base_state("TGS_REQ", &req.0.req_body, sender);
    state.stage = AUTHN_REQ_CL;
    state.tkt_in_id = tgs_header_tkt_id(req);
    each_audit(store, |module| module.tgs_req(true, &state));
}

fn tgs_fail_stage(e_text: &str) -> i32 {
    match e_text {
        status::LOOKING_UP_SERVER
        | status::UNKNOWN_SERVER
        | status::SERVER_NOT_FOUND
        | status::NULL_SERVER => SRVC_PRINC,
        _ => AUTHN_REQ_CL,
    }
}

// MIT: `armor_ap_request` (kdc/fast_util.c:57-58)
/// An empty k5_setmsg falls back to MIT's stock sentence.
fn failure_emsg(code: i32, setmsg: &str) -> String {
    if setmsg.is_empty() {
        kdc_error_message(code)
    } else {
        setmsg.to_owned()
    }
}

fn tgs_fail_emsg(code: i32) -> &'static str {
    if code == err::S_PRINCIPAL_UNKNOWN {
        "Server not found in Kerberos database"
    } else {
        ""
    }
}

/// MIT logs the first 125 bytes, then ...
fn transit_via(transited: &TransitedEncoding) -> (String, &'static str) {
    let raw = transited.contents.as_ref();
    let (shown, dots) = if raw.len() > 125 {
        (&raw[..125], "...")
    } else {
        (raw, "")
    };
    (String::from_utf8_lossy(shown).into_owned(), dots)
}

// MIT: `log_tgs_badtrans` (kdc/kdc_log.c:176-212)
#[must_use]
/// An unexpected transit error is logged, and the path stays unchecked.
pub fn unexpected_transit_false(
    err: TransitError,
    crealm: &str,
    srealm: &str,
    cname: &str,
    sname: &str,
    transited: &TransitedEncoding,
) -> bool {
    let (via, dots) = transit_via(transited);
    tracing::error!(
        event = krb5_log::events::KDC_ISSUE,
        correlation_id = krb5_log::current_correlation_id(),
        component = "krb5-kdc",
        outcome = "error",
        status = "UNEXPECTED_TRANSIT",
        client = crealm,
        server = srealm,
        via = %via,
        error = %err,
        "unexpected error checking transit from '{crealm}' to '{srealm}' via '{via}{dots}': {err}"
    );
    krb5_log::klog::syslog(
        krb5_log::klog::Severity::Err,
        &format!(
            "unexpected error checking transit from '{}' to '{}' via '{via}{dots}': {err}",
            limit_string(cname),
            limit_string(sname)
        ),
    );
    false
}

// MIT: `log_tgs_badtrans` (kdc/kdc_log.c:176-212)
/// A refused transit path is logged; the ticket stays unchecked.
pub fn log_bad_transit(cname: &str, sname: &str, transited: &TransitedEncoding) {
    let (via, dots) = transit_via(transited);
    krb5_log::klog::syslog(
        krb5_log::klog::Severity::Info,
        &format!(
            "bad realm transit path from '{}' to '{}' via '{via}{dots}'",
            limit_string(cname),
            limit_string(sname)
        ),
    );
}

pub fn log_success(
    store: &dyn PrincipalRead,
    raw: &[u8],
    sender: Option<&HostAddress>,
    bytes: &[u8],
) {
    if raw.is_empty() || bytes.is_empty() || bytes.starts_with(&[0x7e]) {
        return;
    }
    match raw.first().copied() {
        Some(0x6a) => {
            if let Ok(req) = decode::<AsReq>(raw) {
                as_success(store, &req, sender, bytes);
            }
        }
        Some(0x6c) => {
            if let Ok(req) = decode::<TgsReq>(raw) {
                tgs_success(store, &req, sender, bytes);
            }
        }
        _ => {}
    }
}

pub fn log_failure(
    store: &dyn PrincipalRead,
    raw: &[u8],
    sender: Option<&HostAddress>,
    _bytes: &[u8],
    code: i32,
    e_text: &str,
    detail: Option<&str>,
) {
    let emsg = detail.unwrap_or("");
    match raw.first().copied() {
        Some(0x6a) => {
            if let Ok(req) = decode::<AsReq>(raw) {
                as_failure(store, &req, sender, code, e_text, emsg);
            }
        }
        Some(0x6c) => {
            if let Ok(req) = decode::<TgsReq>(raw) {
                tgs_failure(store, &req, sender, code, e_text, emsg);
            }
        }
        _ => {}
    }
}

fn as_success(store: &dyn PrincipalRead, req: &AsReq, sender: Option<&HostAddress>, bytes: &[u8]) {
    let Ok(rep) = decode::<AsRep>(bytes) else {
        return;
    };
    seed_as_req(store, req, sender);
    let body = &req.0.req_body;
    let realm = realm_str(&body.realm);
    let client = opt_unparse(body.cname.as_ref(), &realm, "<unknown client>");
    let server = opt_unparse(body.sname.as_ref(), &realm, "<unknown server>");
    let ticket = &rep.0.ticket;
    let part = decrypt_issued(store, ticket);
    let ses = part.as_ref().map(|p| p.key.keytype);
    let authtime = part.as_ref().map_or(0, |p| p.authtime.unix_seconds());
    let etypes = rep_etypes2str(rep.0.enc_part.etype, Some(ticket.enc_part.etype), ses);
    let req_etypes = ktypes2str(&body.etype);
    let from = format_from(sender);
    emit_issue(
        "AS_REQ",
        &req_etypes,
        &from,
        "ISSUE",
        authtime,
        &etypes,
        &client,
        &server,
        None,
        false,
        "",
    );
    klog_as_req(
        &req_etypes,
        &from,
        &MitOutcome::Issue {
            authtime,
            etypes: &etypes,
        },
        &client,
        &server,
    );
    let mut state = base_state("AS_REQ", body, sender);
    state.stage = ENCR_REP;
    state.tkt_out_id = Some(make_tkt_id(ticket.enc_part.cipher.as_ref()));
    each_audit(store, |module| module.as_req(true, &state));
    clear_req_id();
}

fn as_failure(
    store: &dyn PrincipalRead,
    req: &AsReq,
    sender: Option<&HostAddress>,
    code: i32,
    e_text: &str,
    emsg: &str,
) {
    seed_as_req(store, req, sender);
    let body = &req.0.req_body;
    let realm = realm_str(&body.realm);
    let client = opt_unparse(body.cname.as_ref(), &realm, "<unknown client>");
    let server = opt_unparse(body.sname.as_ref(), &realm, "<unknown server>");
    let req_etypes = ktypes2str(&body.etype);
    let from = format_from(sender);
    let status = if e_text.is_empty() {
        "UNKNOWN_REASON"
    } else {
        e_text
    };
    emit_issue(
        "AS_REQ",
        &req_etypes,
        &from,
        status,
        0,
        "",
        &client,
        &server,
        None,
        false,
        emsg,
    );
    klog_as_req(
        &req_etypes,
        &from,
        &MitOutcome::Fail {
            status,
            code,
            authtime: 0,
            emsg,
        },
        &client,
        &server,
    );
    let mut state = base_state("AS_REQ", body, sender);
    state.stage = AUTHN_REQ_CL;
    state.status = Some(status.to_string());
    each_audit(store, |module| module.as_req(code == 0, &state));
    clear_req_id();
}

fn tgs_success(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    sender: Option<&HostAddress>,
    bytes: &[u8],
) {
    let Ok(rep) = decode::<TgsRep>(bytes) else {
        return;
    };
    seed_tgs_req(store, req, sender);
    let body = &req.0.req_body;
    let realm = realm_str(&body.realm);
    let client = tgs_client_name(store, req, &rep, &realm);
    let server = opt_unparse(body.sname.as_ref(), &realm, "<unknown server>");
    let ticket = &rep.0.ticket;
    let part = decrypt_issued(store, ticket);
    let ses = part.as_ref().map(|p| p.key.keytype);
    let authtime = part.as_ref().map_or(0, |p| p.authtime.unix_seconds());
    let etypes = rep_etypes2str(rep.0.enc_part.etype, Some(ticket.enc_part.etype), ses);
    let req_etypes = ktypes2str(&body.etype);
    let from = format_from(sender);
    let s4u = tgs_s4u_kind(req);
    emit_issue(
        "TGS_REQ",
        &req_etypes,
        &from,
        "ISSUE",
        authtime,
        &etypes,
        &client,
        &server,
        s4u.as_ref().map(|(k, c)| (*k, c.as_str())),
        false,
        "",
    );
    klog_tgs_req(
        &req_etypes,
        &from,
        &MitOutcome::Issue {
            authtime,
            etypes: &etypes,
        },
        &client,
        &server,
        s4u.as_ref().map(|(k, c)| (*k, c.as_str())),
    );
    let mut state = base_state("TGS_REQ", body, sender);
    state.stage = ENCR_REP;
    state.status = Some("ISSUE".into());
    state.tkt_out_id = Some(make_tkt_id(ticket.enc_part.cipher.as_ref()));
    state.tkt_in_id = tgs_header_tkt_id(req);
    // 1 if the bit is set, 2 if it is clear, 0 when unused.
    state.tkt_renewed = if body.kdc_options.bit(flag_bit::RENEW) {
        1
    } else {
        2
    };
    state.tkt_validated = if body.kdc_options.bit(flag_bit::VALIDATE) {
        1
    } else {
        2
    };
    each_audit(store, |audit| match s4u.as_ref().map(|(k, _)| *k) {
        Some("PROTOCOL-TRANSITION") => {
            let mut s4u_state = state.clone();
            s4u_state.event_name = "S4U2SELF";
            audit.s4u2self(true, &s4u_state);
        }
        Some("CONSTRAINED-DELEGATION") => {
            let mut s4u_state = state.clone();
            s4u_state.event_name = "S4U2PROXY";
            audit.s4u2proxy(true, &s4u_state);
        }
        _ if body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY) => {
            let mut s4u_state = state.clone();
            s4u_state.event_name = "U2U";
            audit.u2u(true, &s4u_state);
        }
        _ => {}
    });
    each_audit(store, |audit| audit.tgs_req(true, &state));
    clear_req_id();
}

fn tgs_failure(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    sender: Option<&HostAddress>,
    code: i32,
    e_text: &str,
    emsg: &str,
) {
    seed_tgs_req(store, req, sender);
    let body = &req.0.req_body;
    let realm = realm_str(&body.realm);
    let client = tgs_error_client(store, req, &realm);
    let server = opt_unparse(body.sname.as_ref(), &realm, "<unknown server>");
    let req_etypes = ktypes2str(&body.etype);
    let from = format_from(sender);
    let status = if e_text.is_empty() {
        status::UNKNOWN_REASON
    } else {
        e_text
    };
    let nomatch = code == err::SERVER_NOMATCH;
    let authtime = tgs_header_authtime(store, req);
    emit_issue(
        "TGS_REQ",
        &req_etypes,
        &from,
        status,
        authtime,
        "",
        &client,
        &server,
        None,
        nomatch,
        if emsg.is_empty() {
            tgs_fail_emsg(code)
        } else {
            emsg
        },
    );
    let early = tgs_failed_before_authtime(status);
    let s4u = (!early || status == status::RBCD_PAC_PRINC)
        .then(|| tgs_s4u_kind(req))
        .flatten();
    klog_tgs_req(
        &req_etypes,
        &from,
        &MitOutcome::Fail {
            status,
            code,
            authtime: if early { 0 } else { authtime },
            emsg,
        },
        &client,
        &server,
        s4u.as_ref().map(|(k, c)| (*k, c.as_str())),
    );
    let mut state = base_state("TGS_REQ", body, sender);
    state.stage = tgs_fail_stage(status);
    state.status = Some(status.to_string());
    state.tkt_in_id = tgs_header_tkt_id(req);
    each_audit(store, |audit| {
        match tgs_s4u_kind(req).as_ref().map(|(k, _)| *k) {
            Some("PROTOCOL-TRANSITION") => {
                let mut s4u_state = state.clone();
                s4u_state.event_name = "S4U2SELF";
                audit.s4u2self(false, &s4u_state);
            }
            Some("CONSTRAINED-DELEGATION") => {
                let mut s4u_state = state.clone();
                s4u_state.event_name = "S4U2PROXY";
                audit.s4u2proxy(false, &s4u_state);
            }
            _ if body.kdc_options.bit(flag_bit::ENC_TKT_IN_SKEY) => {
                let mut s4u_state = state.clone();
                s4u_state.event_name = "U2U";
                audit.u2u(false, &s4u_state);
            }
            _ => {}
        }
    });
    each_audit(store, |audit| audit.tgs_req(false, &state));
    clear_req_id();
}

#[expect(clippy::too_many_arguments, reason = "kau state, not a params struct")]
fn emit_issue(
    kind: &str,
    req_etypes: &str,
    from: &str,
    status: &str,
    authtime: u32,
    etypes: &str,
    client: &str,
    server: &str,
    s4u: Option<(&str, &str)>,
    server_nomatch: bool,
    emsg: &str,
) {
    if server_nomatch {
        tracing::info!(
            event = krb5_log::events::KDC_ISSUE,
            correlation_id = krb5_log::current_correlation_id(),
            component = "krb5-kdc",
            outcome = "krb-error",
            kind,
            from,
            status,
            authtime,
            client,
            server,
            nomatch = true,
            emsg,
        );
        return;
    }
    tracing::info!(
        event = krb5_log::events::KDC_ISSUE,
        correlation_id = krb5_log::current_correlation_id(),
        component = "krb5-kdc",
        outcome = if status == "ISSUE" { "ok" } else { "krb-error" },
        kind,
        req_etypes,
        from,
        status,
        authtime,
        etypes,
        client,
        server,
        emsg,
    );
    if let Some((kind, s4u_client)) = s4u {
        tracing::info!(
            event = krb5_log::events::KDC_ISSUE,
            correlation_id = krb5_log::current_correlation_id(),
            component = "krb5-kdc",
            outcome = "ok",
            s4u = kind,
            s4u_client,
        );
    }
}

fn base_state(
    event_name: &'static str,
    body: &KdcReqBody,
    sender: Option<&HostAddress>,
) -> AuditState {
    let realm = realm_str(&body.realm);
    AuditState {
        event_name,
        stage: AUTHN_REQ_CL,
        tkt_out_id: None,
        tkt_in_id: None,
        req_id: current_req_id(),
        cl_port: client_port(),
        cl_addr: sender.cloned(),
        status: None,
        req_client: body.cname.clone(),
        req_client_realm: body.cname.as_ref().map(|_| realm.clone()),
        req_server: body.sname.clone(),
        req_server_realm: body.sname.as_ref().map(|_| realm),
        kdc_options: body.kdc_options.to_u32(),
        avail_etypes: body.etype.iter().copied().filter(|e| *e > 0).collect(),
        tkt_renewed: 0,
        tkt_validated: 0,
    }
}

fn decrypt_issued(store: &dyn PrincipalRead, ticket: &Ticket) -> Option<EncTicketPart> {
    let realm = realm_str(&ticket.realm);
    let princ = store
        .fetch(&lookup_principal_id(&ticket.sname, &realm))
        .ok()
        .flatten()?;
    ticket_key(&princ, ticket.enc_part.etype, store.policy())
        .and_then(|k| decrypt_ticket_part(&k.key, ticket).ok())
}

fn ticket_key<'a>(
    princ: &'a Principal,
    etype: i32,
    policy: &crate::store::Policy,
) -> Option<&'a crate::store::KeyEntry> {
    let want = EncryptionType::known(etype).ok();
    policy
        .find_enctype(princ, want, 0)
        .ok()
        .or_else(|| policy.first_current_key(princ).ok())
}

fn tgs_header_tkt_id(req: &TgsReq) -> Option<String> {
    let pa = req
        .0
        .padata
        .as_ref()?
        .iter()
        .find(|p| p.padata_type == pa::TGS_REQ)?;
    let ap: krb5_types::ApReq = decode(pa.padata_value.as_ref()).ok()?;
    Some(make_tkt_id(ap.ticket.enc_part.cipher.as_ref()))
}

fn tgs_header_authtime(store: &dyn PrincipalRead, req: &TgsReq) -> u32 {
    header_enc_part(store, req).map_or(0, |p| p.authtime.unix_seconds())
}

// MIT: `kdc_get_server_key` (kdc/kdc_util.c:377-379)
/// The header ticket opens under its own server key, a cross-realm krbtgt included.
fn header_enc_part(store: &dyn PrincipalRead, req: &TgsReq) -> Option<EncTicketPart> {
    let pa = req
        .0
        .padata
        .as_ref()?
        .iter()
        .find(|p| p.padata_type == pa::TGS_REQ)?;
    let ap: krb5_types::ApReq = decode(pa.padata_value.as_ref()).ok()?;
    let etype = EncryptionType::known(ap.ticket.enc_part.etype).ok()?;
    crate::issue::decrypt_presented_tgt(store, &ap, etype)
        .ok()
        .map(|(part, _, _, _)| part)
}

fn tgs_client_name(store: &dyn PrincipalRead, req: &TgsReq, rep: &TgsRep, realm: &str) -> String {
    let reply = rep.0.cname.unparse_with_realm(&realm_str(&rep.0.crealm));
    if !reply.contains("WELLKNOWN/ANONYMOUS") {
        return reply;
    }
    tgs_error_client(store, req, realm)
}

fn tgs_error_client(store: &dyn PrincipalRead, req: &TgsReq, realm: &str) -> String {
    let Some(part) = header_enc_part(store, req) else {
        return "<unknown client>".into();
    };
    // MIT: `unparse_and_limit` (kdc/kdc_log.c:105-109)
    // The logged client uses the header ticket's realm.
    let crealm = realm_str(&part.crealm);
    let realm = if crealm.is_empty() {
        realm
    } else {
        crealm.as_str()
    };
    part.cname.unparse_with_realm(realm)
}

fn tgs_s4u_kind(req: &TgsReq) -> Option<(&'static str, String)> {
    let padata = req.0.padata.as_deref()?;
    let has_for_user = padata.iter().any(|p| p.padata_type == pa::FOR_USER);
    let has_x509 = padata.iter().any(|p| p.padata_type == pa::FOR_X509_USER);
    if has_for_user || has_x509 {
        return Some(("PROTOCOL-TRANSITION", s4u_user_unparse(padata)));
    }
    if padata.iter().any(|p| p.padata_type == pa::PAC_OPTIONS)
        && req
            .0
            .req_body
            .additional_tickets
            .as_ref()
            .is_some_and(|t| !t.is_empty())
    {
        return Some(("CONSTRAINED-DELEGATION", "<unknown>".into()));
    }
    None
}

fn s4u_user_unparse(padata: &[krb5_types::PaData]) -> String {
    for p in padata {
        if p.padata_type == pa::FOR_USER
            && let Ok(fu) = decode::<krb5_types::s4u::PaForUser>(p.padata_value.as_ref())
        {
            let realm = realm_str(&fu.user_realm);
            return fu.user_name.unparse_with_realm(&realm);
        }
    }
    "<unknown>".into()
}

fn opt_unparse(name: Option<&PrincipalName>, realm: &str, fallback: &str) -> String {
    name.map_or_else(|| fallback.into(), |n| n.unparse_with_realm(realm))
}

fn format_from(sender: Option<&HostAddress>) -> String {
    let Some(s) = sender else {
        return "<unknown>".into();
    };
    if s.addr_type == HostAddress::ADDRTYPE_INET && s.address.len() == 4 {
        return format!(
            "{}.{}.{}.{}",
            s.address[0], s.address[1], s.address[2], s.address[3]
        );
    }
    if s.addr_type == HostAddress::ADDRTYPE_INET6 && s.address.len() == 16 {
        let mut oct = [0u8; 16];
        oct.copy_from_slice(s.address.as_ref());
        return std::net::Ipv6Addr::from(oct).to_string();
    }
    "<unknown>".into()
}

fn realm_str(r: &krb5_types::Realm) -> String {
    String::from_utf8_lossy(r.as_bytes()).into_owned()
}

fn cms_enctype_name(etype: i32) -> Option<&'static str> {
    Some(match etype {
        9 => "id-dsa-with-sha1-CmsOID",
        10 => "md5WithRSAEncryption-CmsOID",
        11 => "sha-1WithRSAEncryption-CmsOID",
        12 => "rc2-cbc-EnvOID",
        13 => "rsaEncryption-EnvOID",
        14 => "id-RSAES-OAEP-EnvOID",
        15 => "des-ede3-cbc-EnvOID",
        _ => return None,
    })
}

fn des_enctype_name(etype: i32) -> Option<&'static str> {
    Some(match etype {
        1 => "des-cbc-crc",
        2 => "des-cbc-md4",
        3 => "des-cbc-md5",
        4 => "des-cbc-raw",
        8 => "des-hmac-sha1",
        _ => return None,
    })
}

fn emit_trace_record(record: &str) {
    tracing::info!(
        event = krb5_log::events::KDC_AUDIT,
        correlation_id = krb5_log::current_correlation_id(),
        component = "krb5-kdc",
        outcome = "ok",
        record,
    );
}

pub(crate) fn start_stop_json(name: &str, success: bool) -> String {
    format!(
        "{{\"event_name\":\"{name}\",\"event_success\":{}}}",
        if success { "true" } else { "false" }
    )
}

impl AuditState {
    pub(crate) fn to_json(&self, success: bool) -> String {
        let mut j = JsonObj::new();
        j.str("event_name", self.event_name);
        j.int("stage", i64::from(self.stage));
        j.bool("event_success", success);
        j.opt_str("tkt_in_id", self.tkt_in_id.as_deref());
        j.opt_str("tkt_out_id", self.tkt_out_id.as_deref());
        j.str("req_id", &self.req_id);
        j.int("fromport", i64::from(self.cl_port));
        if let Some(addr) = &self.cl_addr {
            j.raw("fromaddr", &addr_json(addr));
        }
        j.opt_str("kdc_status", self.status.as_deref());
        if let Some(c) = &self.req_client {
            j.raw(
                "req.client",
                &princ_json(c, self.req_client_realm.as_deref().unwrap_or("")),
            );
        }
        if let Some(s) = &self.req_server {
            j.raw(
                "req.server",
                &princ_json(s, self.req_server_realm.as_deref().unwrap_or("")),
            );
        }
        j.int("req.kdc_options", i64::from(self.kdc_options));
        if !self.avail_etypes.is_empty() {
            j.raw("req.avail_etypes", &int_array(&self.avail_etypes));
        }
        if self.tkt_renewed != 0 {
            j.int("tkt_renewed", i64::from(self.tkt_renewed));
        }
        if self.tkt_validated != 0 {
            j.int("tkt_validated", i64::from(self.tkt_validated));
        }
        j.finish()
    }
}

fn princ_json(name: &PrincipalName, realm: &str) -> String {
    let comps: Vec<String> = name
        .name_string
        .iter()
        .map(|s| json_escape(&String::from_utf8_lossy(s.as_bytes())))
        .collect();
    let mut arr = String::from("[");
    for (i, c) in comps.iter().enumerate() {
        if i > 0 {
            arr.push(',');
        }
        arr.push('"');
        arr.push_str(c);
        arr.push('"');
    }
    arr.push(']');
    format!(
        "{{\"components\":{arr},\"realm\":\"{}\",\"length\":{},\"type\":{}}}",
        json_escape(realm),
        name.name_string.len(),
        name.name_type
    )
}

fn addr_json(addr: &HostAddress) -> String {
    let mut j = JsonObj::new();
    j.int("type", i64::from(addr.addr_type));
    j.int(
        "length",
        i64::from(u32::try_from(addr.address.len()).unwrap_or(u32::MAX)),
    );
    if addr.addr_type == HostAddress::ADDRTYPE_INET || addr.addr_type == HostAddress::ADDRTYPE_INET6
    {
        let ips: Vec<i32> = addr.address.iter().map(|b| i32::from(*b)).collect();
        j.raw("ip", &int_array(&ips));
    }
    j.finish()
}

fn int_array(v: &[i32]) -> String {
    let mut s = String::from("[");
    for (i, n) in v.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "{n}");
    }
    s.push(']');
    s
}

struct JsonObj(String);

impl JsonObj {
    fn new() -> Self {
        Self("{".into())
    }
    fn comma(&mut self) {
        if !self.0.ends_with('{') {
            self.0.push(',');
        }
    }
    fn str(&mut self, k: &str, v: &str) {
        self.comma();
        let _ = write!(self.0, "\"{}\":\"{}\"", json_escape(k), json_escape(v));
    }
    fn opt_str(&mut self, k: &str, v: Option<&str>) {
        if let Some(v) = v {
            self.str(k, v);
        }
    }
    fn int(&mut self, k: &str, v: i64) {
        self.comma();
        let _ = write!(self.0, "\"{}\":{v}", json_escape(k));
    }
    fn bool(&mut self, k: &str, v: bool) {
        self.comma();
        let _ = write!(
            self.0,
            "\"{}\":{}",
            json_escape(k),
            if v { "true" } else { "false" }
        );
    }
    fn raw(&mut self, k: &str, json: &str) {
        self.comma();
        let _ = write!(self.0, "\"{}\":{json}", json_escape(k));
    }
    fn finish(self) -> String {
        let mut s = self.0;
        s.push('}');
        s
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn tkt_id_is_uppercase_sha256_of_ciphertext() {
        let id = make_tkt_id(b"cipher");
        assert_eq!(id.len(), 64);
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
        );
        assert_eq!(id, make_tkt_id(b"cipher"));
        assert_ne!(id, make_tkt_id(b"other"));
    }

    #[test]
    fn req_id_is_mit_random_string_len() {
        let id = new_req_id();
        assert_eq!(id.len(), REQID_CHARS);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn ktypes_and_rep_match_mit_format() {
        let k = ktypes2str(&[18, 17]);
        assert_eq!(
            k,
            "2 etypes {aes256-cts-hmac-sha1-96(18), aes128-cts-hmac-sha1-96(17)}"
        );
        let r = rep_etypes2str(20, Some(20), Some(18));
        assert_eq!(
            r,
            "etypes {rep=aes256-cts-hmac-sha384-192(20), tkt=aes256-cts-hmac-sha384-192(20), ses=aes256-cts-hmac-sha1-96(18)}"
        );
        assert!(enctype_name(16).starts_with("DEPRECATED:"));
        assert!(enctype_name(1).starts_with("UNSUPPORTED:"));
        assert_eq!(enctype_name(6), "DEPRECATED:des3-cbc-raw");
        assert_eq!(enctype_name(24), "DEPRECATED:arcfour-hmac-exp");
    }

    const KINIT_ETYPES: [i32; 8] = [18, 17, 20, 19, 16, 23, 25, 26];

    #[test]
    fn as_lines_match_mit_live() {
        let req = ktypes2str(&KINIT_ETYPES);
        let etypes = rep_etypes2str(18, Some(18), Some(18));
        assert_eq!(
            as_req_line(
                &req,
                "127.0.0.1",
                &MitOutcome::Issue {
                    authtime: 1_790_891_954,
                    etypes: &etypes
                },
                "alice@SETTLE.TEST",
                "krbtgt/SETTLE.TEST@SETTLE.TEST"
            ),
            "AS_REQ (8 etypes {aes256-cts-hmac-sha1-96(18), aes128-cts-hmac-sha1-96(17), \
             aes256-cts-hmac-sha384-192(20), aes128-cts-hmac-sha256-128(19), \
             DEPRECATED:des3-cbc-sha1(16), DEPRECATED:arcfour-hmac(23), camellia128-cts-cmac(25), \
             camellia256-cts-cmac(26)}) 127.0.0.1: ISSUE: authtime 1790891954, \
             etypes {rep=aes256-cts-hmac-sha1-96(18), tkt=aes256-cts-hmac-sha1-96(18), \
             ses=aes256-cts-hmac-sha1-96(18)}, alice@SETTLE.TEST for krbtgt/SETTLE.TEST@SETTLE.TEST"
        );
        assert_eq!(
            as_req_line(
                "6 etypes {aes256-cts-hmac-sha384-192(20)}",
                "192.168.177.22",
                &MitOutcome::Fail {
                    status: "NEEDED_PREAUTH",
                    code: err::PREAUTH_REQUIRED,
                    authtime: 0,
                    emsg: "",
                },
                "alice@KERBER.TEST",
                "krbtgt/KERBER.TEST@KERBER.TEST"
            ),
            "AS_REQ (6 etypes {aes256-cts-hmac-sha384-192(20)}) 192.168.177.22: NEEDED_PREAUTH: \
             alice@KERBER.TEST for krbtgt/KERBER.TEST@KERBER.TEST, Additional pre-authentication required"
        );
        assert!(
            as_req_line(
                "",
                "127.0.0.1",
                &MitOutcome::Fail {
                    status: "CLIENT_NOT_FOUND",
                    code: 6,
                    authtime: 0,
                    emsg: "",
                },
                "nosuch@SETTLE.TEST",
                "krbtgt/SETTLE.TEST@SETTLE.TEST"
            )
            .ends_with(": CLIENT_NOT_FOUND: nosuch@SETTLE.TEST for krbtgt/SETTLE.TEST@SETTLE.TEST, Client not found in Kerberos database")
        );
    }

    #[test]
    fn tgs_lines_match_mit_live() {
        let req = "1 etypes {aes256-cts-hmac-sha1-96(18)}";
        let etypes = rep_etypes2str(18, Some(18), Some(18));
        assert_eq!(
            tgs_req_lines(
                req,
                "127.0.0.1",
                &MitOutcome::Issue {
                    authtime: 1_790_891_954,
                    etypes: &etypes
                },
                "alice@SETTLE.TEST",
                "host/kdc.settle.test@SETTLE.TEST",
                None
            ),
            [format!(
                "TGS_REQ ({req}) 127.0.0.1: ISSUE: authtime 1790891954, {etypes}, \
                 alice@SETTLE.TEST for host/kdc.settle.test@SETTLE.TEST"
            )]
        );
        assert_eq!(
            tgs_req_lines(
                req,
                "127.0.0.1",
                &MitOutcome::Fail {
                    status: status::LOOKING_UP_SERVER,
                    code: err::S_PRINCIPAL_UNKNOWN,
                    authtime: 0,
                    emsg: "",
                },
                "alice@SETTLE.TEST",
                "nosuch/kdc.settle.test@SETTLE.TEST",
                None
            ),
            [format!(
                "TGS_REQ ({req}) 127.0.0.1: LOOKING_UP_SERVER: authtime 0,  alice@SETTLE.TEST \
                 for nosuch/kdc.settle.test@SETTLE.TEST, Server not found in Kerberos database"
            )]
        );
        assert!(tgs_failed_before_authtime(status::LOOKING_UP_SERVER));
        assert!(!tgs_failed_before_authtime(status::TKT_EXPIRED));
        let lines = tgs_req_lines(
            req,
            "::1",
            &MitOutcome::Issue {
                authtime: 1,
                etypes: &etypes,
            },
            "svc@R",
            "svc@R",
            Some(("PROTOCOL-TRANSITION", "user@R")),
        );
        assert_eq!(lines[1], "... PROTOCOL-TRANSITION s4u-client=user@R");
        assert_eq!(
            tgs_req_lines(
                req,
                "::1",
                &MitOutcome::Fail {
                    status: "2ND_TKT_MISMATCH",
                    code: err::SERVER_NOMATCH,
                    authtime: 5,
                    emsg: "ap-request armor for something other than the local TGS",
                },
                "a@R",
                "b@R",
                None
            ),
            ["TGS_REQ ::1: 2ND_TKT_MISMATCH: authtime 5, a@R for b@R, 2nd tkt client <unknown>"]
        );
    }

    #[test]
    fn long_names_and_error_texts_are_mits() {
        let long = "a".repeat(200);
        let cut = limit_string(&long);
        assert_eq!(cut.len(), 127);
        assert!(cut.ends_with("aaa..."));
        assert_eq!(limit_string("short@R"), "short@R");
        assert_eq!(kdc_error_message(24), "Preauthentication failed");
        assert_eq!(kdc_error_message(30), "KRB5 error code 30");
        assert_eq!(
            kdc_error_message(93),
            "An unsupported critical FAST option was requested"
        );
    }

    #[test]
    fn tkt_id_matches_independent_sha256() {
        let cipher = b"cipher";
        let hash = Sha256::digest(cipher);
        let mut expect = String::with_capacity(64);
        for b in hash {
            expect.push(HEX_UP[usize::from(b >> 4)] as char);
            expect.push(HEX_UP[usize::from(b & 0x0f)] as char);
        }
        assert_eq!(make_tkt_id(cipher), expect);
    }

    #[test]
    fn cross_realm_header_client_is_logged_with_its_own_realm() {
        use krb5_asn1::encode;
        use krb5_crypto::{KeyUsage, ProtocolKey, encrypt};
        use krb5_types::{
            ApOptions, ApReq, EncryptedData, EncryptionKey, KdcOptions, KdcReq, KdcReqBody,
            KerberosTime, PaData, Ticket, TicketFlags, TransitedEncoding, ku,
        };

        use crate::kdb::{MemoryStore, PrincipalWrite};
        use crate::store::{KeyEntry, PrincipalFields, random_key};

        const LOCAL: &str = "KERBER.TEST";
        const OTHER: &str = "AD.KERBER.TEST";
        const AUTHTIME: u32 = 1_790_893_601;

        fn header_req(
            ticket_realm: &str,
            key: &ProtocolKey,
            client: &str,
            client_realm: &str,
            authtime: u32,
        ) -> TgsReq {
            let etype = key.etype();
            let when = KerberosTime::from_unix_seconds(authtime);
            let end = when.add_hours(10).unwrap_or_else(|_| when.clone());
            let till = when.add_hours(1).unwrap_or_else(|_| when.clone());
            let part = EncTicketPart {
                flags: TicketFlags::none(),
                key: EncryptionKey {
                    keytype: etype.to_iana(),
                    keyvalue: key.as_bytes().to_vec().into(),
                },
                crealm: krb5_types::try_ascii(client_realm).unwrap(),
                cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, [client]),
                transited: TransitedEncoding {
                    tr_type: 1,
                    contents: Vec::<u8>::new().into(),
                },
                authtime: when,
                starttime: None,
                endtime: end,
                renew_till: None,
                caddr: None,
                authorization_data: None,
            };
            let usage = KeyUsage::new(ku::TICKET).unwrap();
            let cipher = encrypt(key, usage, &encode(&part).unwrap()).unwrap();
            let ticket = Ticket {
                tkt_vno: Ticket::VNO,
                realm: krb5_types::try_ascii(ticket_realm).unwrap(),
                sname: PrincipalName::krbtgt(LOCAL),
                enc_part: EncryptedData {
                    etype: etype.to_iana(),
                    kvno: Some(1),
                    cipher: cipher.into(),
                },
            };
            let ap = ApReq {
                pvno: ApReq::PVNO,
                msg_type: ApReq::MSG_TYPE,
                ap_options: ApOptions::none(),
                ticket,
                authenticator: EncryptedData {
                    etype: etype.to_iana(),
                    kvno: None,
                    cipher: vec![0u8].into(),
                },
            };
            TgsReq(KdcReq {
                pvno: KdcReq::PVNO,
                msg_type: KdcReq::MSG_TGS_REQ,
                padata: Some(vec![PaData {
                    padata_type: pa::TGS_REQ,
                    padata_value: encode(&ap).unwrap().into(),
                }]),
                req_body: KdcReqBody {
                    kdc_options: KdcOptions::none(),
                    cname: None,
                    realm: krb5_types::try_ascii(LOCAL).unwrap(),
                    sname: Some(PrincipalName::new(
                        PrincipalName::NT_SRV_HST,
                        ["host", "client2"],
                    )),
                    from: None,
                    till,
                    rtime: None,
                    nonce: 1,
                    etype: vec![20, 19, 18, 17, 26, 25],
                    addresses: None,
                    enc_authorization_data: None,
                    additional_tickets: None,
                },
            })
        }

        let etype = EncryptionType::Aes256CtsHmacSha196;
        let local_key = random_key(etype).unwrap();
        let cross_key = random_key(etype).unwrap();
        let fields = PrincipalFields {
            requires_preauth: false,
            max_life: 0,
            locked: false,
            pw_expire: 0,
        };
        let mut store = MemoryStore::new(LOCAL);
        store
            .put_principal(Principal::from_keys(
                PrincipalName::krbtgt(LOCAL),
                LOCAL.into(),
                vec![KeyEntry::new(etype, local_key.clone(), 1)],
                Vec::new(),
                fields,
            ))
            .unwrap();
        let req = header_req(OTHER, &cross_key, "kbruser", OTHER, AUTHTIME);
        assert_eq!(tgs_error_client(&store, &req, LOCAL), "<unknown client>");
        assert_eq!(tgs_header_authtime(&store, &req), 0);

        store
            .put_principal(Principal::from_keys(
                PrincipalName::krbtgt(LOCAL),
                OTHER.into(),
                vec![KeyEntry::new(etype, cross_key.clone(), 1)],
                Vec::new(),
                fields,
            ))
            .unwrap();
        assert_eq!(
            tgs_error_client(&store, &req, LOCAL),
            "kbruser@AD.KERBER.TEST"
        );
        assert_eq!(tgs_header_authtime(&store, &req), AUTHTIME);
        let local_req = header_req(LOCAL, &local_key, "alice", LOCAL, AUTHTIME);
        assert_eq!(
            tgs_error_client(&store, &local_req, LOCAL),
            "alice@KERBER.TEST"
        );

        let client = tgs_error_client(&store, &req, LOCAL);
        let line = tgs_req_lines(
            &ktypes2str(&[20, 19, 18, 17, 26, 25]),
            "192.168.177.22",
            &MitOutcome::Fail {
                status: status::LOOKING_UP_SERVER,
                code: err::S_PRINCIPAL_UNKNOWN,
                authtime: 0,
                emsg: "",
            },
            &client,
            "host/client2@KERBER.TEST",
            None,
        );
        assert_eq!(
            line[0],
            "TGS_REQ (6 etypes {aes256-cts-hmac-sha384-192(20), aes128-cts-hmac-sha256-128(19), \
             aes256-cts-hmac-sha1-96(18), aes128-cts-hmac-sha1-96(17), camellia256-cts-cmac(26), \
             camellia128-cts-cmac(25)}) 192.168.177.22: LOOKING_UP_SERVER: authtime 0,  \
             kbruser@AD.KERBER.TEST for host/client2@KERBER.TEST, Server not found in Kerberos database"
        );
    }

    #[test]
    fn failure_line_uses_the_k5_setmsg_text() {
        let msg = "Decrypt integrity check failed while handling ap-request armor";
        let as_line = as_req_line(
            "1 etypes {aes256-cts-hmac-sha1-96(18)}",
            "127.0.0.1",
            &MitOutcome::Fail {
                status: status::FIND_FAST,
                code: 31,
                authtime: 0,
                emsg: msg,
            },
            "alice@KERBER.TEST",
            "krbtgt/KERBER.TEST@KERBER.TEST",
        );
        assert!(as_line.ends_with(&format!(", {msg}")), "{as_line}");
        let plain = as_req_line(
            "1 etypes {aes256-cts-hmac-sha1-96(18)}",
            "127.0.0.1",
            &MitOutcome::Fail {
                status: status::FIND_FAST,
                code: 31,
                authtime: 0,
                emsg: "",
            },
            "alice@KERBER.TEST",
            "krbtgt/KERBER.TEST@KERBER.TEST",
        );
        assert!(
            plain.ends_with(", Decrypt integrity check failed"),
            "{plain}"
        );
        let tgs = tgs_req_lines(
            "1 etypes {aes256-cts-hmac-sha1-96(18)}",
            "127.0.0.1",
            &MitOutcome::Fail {
                status: status::FIND_FAST,
                code: 31,
                authtime: 0,
                emsg: msg,
            },
            "alice@KERBER.TEST",
            "host/client2@KERBER.TEST",
            None,
        );
        assert!(tgs[0].ends_with(&format!(", {msg}")), "{}", tgs[0]);
    }

    struct CountAudit {
        name: &'static str,
        hits: std::sync::atomic::AtomicU64,
    }

    impl KdcAudit for CountAudit {
        fn name(&self) -> &'static str {
            self.name
        }

        fn as_req(&self, _success: bool, _state: &AuditState) {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        fn kdc_start(&self, _success: bool) {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }

        fn kdc_stop(&self, _success: bool) {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    struct ClearAudits;

    impl Drop for ClearAudits {
        fn drop(&mut self) {
            clear_thread_audits();
            clear_thread_audit();
        }
    }

    #[test]
    fn named_audit_modules_all_run_and_disable_drops_one() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().unwrap();
        store.policy.audit = krb5_config::Krb5Conf::parse(
            "[plugins]\n    audit = {\n        disable = quiet\n    }\n",
        )
        .expect("stanza")
        .plugin_relations("audit");
        let loud = Arc::new(CountAudit {
            name: "loud",
            hits: std::sync::atomic::AtomicU64::new(0),
        });
        let quiet = Arc::new(CountAudit {
            name: "quiet",
            hits: std::sync::atomic::AtomicU64::new(0),
        });
        set_thread_audits(vec![
            Arc::clone(&loud) as Arc<dyn KdcAudit>,
            Arc::clone(&quiet) as Arc<dyn KdcAudit>,
        ]);
        let _guard = ClearAudits;
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::testrealm::TEST_USER]);
        let req =
            krb5_protocol::as_req(cname, crate::testrealm::TEST_REALM, 1, None).expect("as-req");
        as_failure(&store, &req, None, 24, "NEEDED_PREAUTH", "");
        assert_eq!(loud.hits.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(quiet.hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn enable_only_of_an_unknown_audit_keeps_nothing() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().unwrap();
        store.policy.audit = krb5_config::Krb5Conf::parse(
            "[plugins]\n    audit = {\n        enable_only = nosuch\n    }\n",
        )
        .expect("stanza")
        .plugin_relations("audit");
        let loud = Arc::new(CountAudit {
            name: "loud",
            hits: std::sync::atomic::AtomicU64::new(0),
        });
        set_thread_audits(vec![Arc::clone(&loud) as Arc<dyn KdcAudit>]);
        let _guard = ClearAudits;
        assert!(active_audits(&store).is_empty());
    }

    #[test]
    fn json_is_the_builtin_and_disable_drops_it() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().unwrap();
        let names: Vec<&str> = active_audits(&store)
            .iter()
            .map(|module| module.name())
            .collect();
        assert_eq!(names, ["json"]);
        store.policy.audit = krb5_config::Krb5Conf::parse(
            "[plugins]\n    audit = {\n        disable = json\n    }\n",
        )
        .expect("stanza")
        .plugin_relations("audit");
        assert!(active_audits(&store).is_empty());
    }

    #[test]
    fn disable_json_skips_kdc_start_and_kdc_stop() {
        let (mut store, _) = crate::testrealm::bootstrap_documented().unwrap();
        let json = Arc::new(CountAudit {
            name: "json",
            hits: std::sync::atomic::AtomicU64::new(0),
        });
        set_thread_audits(vec![Arc::clone(&json) as Arc<dyn KdcAudit>]);
        let _guard = ClearAudits;
        audit_kdc_start(&store, true);
        audit_kdc_stop(&store, true);
        assert_eq!(json.hits.load(std::sync::atomic::Ordering::SeqCst), 2);
        store.policy.audit = krb5_config::Krb5Conf::parse(
            "[plugins]\n    audit = {\n        disable = json\n    }\n",
        )
        .expect("stanza")
        .plugin_relations("audit");
        audit_kdc_start(&store, true);
        audit_kdc_stop(&store, true);
        assert_eq!(json.hits.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
