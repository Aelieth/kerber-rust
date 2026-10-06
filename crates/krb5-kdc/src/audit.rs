//! MIT `kdc_log.c` ISSUE tuple and `kdc_audit.c` plugin registry.
//!
//! The success and error paths emit the tuple and then call the plugin.
//! The tuple records the decision. It is not the reply.

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

/// Authenticate request and client (`audit_plugin.h`).
pub const AUTHN_REQ_CL: i32 = 1;
/// Determine service principal.
pub const SRVC_PRINC: i32 = 2;
/// Encrypt reply.
pub const ENCR_REP: i32 = 5;

/// MIT `REQID_LEN`: C buffer including the NUL that `krb5int_random_string`
/// writes, so the printable id is 31 alphanumeric characters.
pub const REQID_LEN: usize = 32;
const REQID_CHARS: usize = REQID_LEN - 1;

const RAND_ALPHANUM: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const HEX_UP: &[u8; 16] = b"0123456789ABCDEF";

/// SHA-256 of `ticket.enc_part.ciphertext` as 64 uppercase hex digits
/// (`kau_make_tkt_id`).
#[must_use]
pub fn make_tkt_id(ciphertext: &[u8]) -> String {
    let hash = Sha256::digest(ciphertext);
    let mut out = String::with_capacity(64);
    for b in hash {
        out.push(HEX_UP[usize::from(b >> 4)] as char);
        out.push(HEX_UP[usize::from(b & 0x0f)] as char);
    }
    out
}

/// MIT `krb5int_random_string` over a `REQID_LEN` buffer (31 chars + NUL).
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

/// MIT `kdc_util.c` `enctype_name` (short name + DEPRECATED/UNSUPPORTED).
#[must_use]
pub fn enctype_name(etype: i32) -> String {
    // MIT `etypes.c` lists these as `ETYPE_DEPRECATED` but Rust `known()`
    // does not implement them (`enctype_util.c` `krb5int_c_deprecated_enctype`).
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

/// MIT `ktypes2str`: `"%d etypes {%s(%ld), ...}"`.
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

/// MIT `rep_etypes2str`: `"etypes {rep=%s(%ld), tkt=%s(%ld), ses=%s(%ld)}"`.
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

/// A name for a log line: 128 bytes or more keep their first 124 and end in `...`.
/// MIT `limit_string` (`kdc/kdc_util.c:1120-1135`): long names are cut so they do not crowd out
/// the rest of the entry.
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

/// The message of a KDC error code: the texts of MIT's `lib/krb5/error_tables/krb5_err.et`, whose
/// unnamed slots read `KRB5 error code N`.
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

/// Whether a TGS failure with `status` happened before the subject ticket was known.
/// MIT `gather_tgs_req_info` (`kdc/do_tgs_req.c:727-754`): the logged authtime is set from the
/// subject ticket only here, so an earlier failure logs authtime 0.
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

/// How a request ended, for its MIT log line.
enum MitOutcome<'a> {
    /// A ticket was issued.
    Issue { authtime: u32, etypes: &'a str },
    /// A KRB-ERROR was sent.
    Fail {
        status: &'a str,
        code: i32,
        authtime: u32,
    },
}

/// The AS line for the `[logging]` destinations.
/// MIT `log_as_req` (`kdc/kdc_log.c:57-97`): `AS_REQ (etypes) from: ISSUE: authtime, reply etypes,
/// client for server`, or the status, the names and the error's message.
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
        MitOutcome::Fail { status, code, .. } => format!(
            "AS_REQ ({req_etypes}) {from}: {status}: {client} for {server}, {}",
            kdc_error_message(*code)
        ),
    }
}

/// The TGS line, and the S4U line after it, for the `[logging]` destinations.
/// MIT `log_tgs_req` (`kdc/kdc_log.c:117-173`): a server mismatch logs the second ticket's client
/// instead of the etypes; otherwise the line has the reply etypes on success and the error's
/// message on a failure, followed by `... PROTOCOL-TRANSITION` or `... CONSTRAINED-DELEGATION`
/// with the S4U client.
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
        } => format!(
            "TGS_REQ ({req_etypes}) {from}: {status}: authtime {authtime},  {client} for {server}, {}",
            kdc_error_message(*code)
        ),
    };
    let mut lines = vec![line];
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

/// KDC audit plugin (`kdc_audit.c` `kau_*`).
pub trait KdcAudit: Send + Sync {
    /// KDC process start.
    fn kdc_start(&self, success: bool) {
        let _ = success;
    }
    /// KDC process stop.
    fn kdc_stop(&self, success: bool) {
        let _ = success;
    }
    /// AS-REQ.
    fn as_req(&self, success: bool, state: &AuditState) {
        let _ = (success, state);
    }
    /// TGS-REQ.
    fn tgs_req(&self, success: bool, state: &AuditState) {
        let _ = (success, state);
    }
    /// S4U2Self.
    fn s4u2self(&self, success: bool, state: &AuditState) {
        let _ = (success, state);
    }
    /// S4U2Proxy.
    fn s4u2proxy(&self, success: bool, state: &AuditState) {
        let _ = (success, state);
    }
    /// User-to-user.
    fn u2u(&self, success: bool, state: &AuditState) {
        let _ = (success, state);
    }
}

/// MIT `krb5_audit_state` fields the JSON sink emits.
#[derive(Clone, Debug, Default)]
pub struct AuditState {
    /// `event_name` (`AS_REQ` / `TGS_REQ` / `S4U2SELF` / `S4U2PROXY` / `U2U`).
    pub event_name: &'static str,
    /// Processing step (`AUTHN_REQ_CL`…`ENCR_REP`).
    pub stage: i32,
    /// SHA-256 hex of the issued ticket ciphertext.
    pub tkt_out_id: Option<String>,
    /// SHA-256 hex of the header / evidence ticket ciphertext.
    pub(crate) tkt_in_id: Option<String>,
    /// 31-character alphanumeric request id.
    pub req_id: String,
    /// Client UDP/TCP port.
    pub(crate) cl_port: u32,
    /// Client address.
    pub cl_addr: Option<HostAddress>,
    /// KDC status word (`ISSUE`, `NEEDED_PREAUTH`, …). Omitted when empty.
    pub status: Option<String>,
    /// Requested client principal.
    pub(crate) req_client: Option<PrincipalName>,
    /// Requested client realm.
    pub(crate) req_client_realm: Option<String>,
    /// Requested server principal.
    pub(crate) req_server: Option<PrincipalName>,
    /// Requested server realm.
    pub(crate) req_server_realm: Option<String>,
    /// `KDCOptions` as MIT's packed integer.
    pub kdc_options: u32,
    /// Requested etypes (`req.avail_etypes`).
    pub(crate) avail_etypes: Vec<i32>,
    /// TGS RENEW bit was set (1) or not (2) on success; 0 when unused.
    pub(crate) tkt_renewed: i32,
    /// TGS VALIDATE bit was set (1) or not (2) on success; 0 when unused.
    pub(crate) tkt_validated: i32,
}

/// Built-in JSON sink: one `kdc.audit` tracing event per record.
pub struct JsonAudit;

impl KdcAudit for JsonAudit {
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

thread_local! {
    static THREAD_AUDIT: std::cell::RefCell<Option<Arc<dyn KdcAudit>>> =
        const { std::cell::RefCell::new(None) };
    static CL_PORT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    static CUR_REQ_ID: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

/// Install the process-wide audit module (KDC workers).
pub fn set_audit(a: Arc<dyn KdcAudit>) {
    *AUDIT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(a);
}

/// Install a thread-local module checked before the process-wide slot.
pub fn set_thread_audit(a: Arc<dyn KdcAudit>) {
    THREAD_AUDIT.with(|t| *t.borrow_mut() = Some(a));
}

/// Drop the thread-local module.
pub fn clear_thread_audit() {
    THREAD_AUDIT.with(|t| *t.borrow_mut() = None);
}

/// Take this thread's own module off it, leaving the process-wide slot in force on the thread.
pub(crate) fn take_thread_audit() -> Option<Arc<dyn KdcAudit>> {
    THREAD_AUDIT.with(|t| t.borrow_mut().take())
}

/// Put back what [`take_thread_audit`] took.
pub(crate) fn restore_thread_audit(a: Option<Arc<dyn KdcAudit>>) {
    THREAD_AUDIT.with(|t| *t.borrow_mut() = a);
}

/// Current audit module (default [`JsonAudit`]).
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

/// Peer port from the UDP/TCP listener (`kau_init_kdc_req` `cl_port`).
pub(crate) fn set_client_port(port: u32) {
    CL_PORT.with(|c| c.set(port));
}

/// Current peer port (0 when the caller is not the listener).
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

/// MIT `process_as_req` (`do_as_req.c:520-520`): seeds `kau_as_req(TRUE)` before a ticket exists.
fn seed_as_req(req: &AsReq, sender: Option<&HostAddress>) {
    clear_req_id();
    let mut state = base_state("AS_REQ", &req.0.req_body, sender);
    state.stage = AUTHN_REQ_CL;
    current_audit().as_req(true, &state);
}

/// MIT `process_tgs_req` (`do_tgs_req.c:1181-1184`): seeds `kau_tgs_req(TRUE)` at `AUTHN_REQ_CL`.
fn seed_tgs_req(req: &TgsReq, sender: Option<&HostAddress>) {
    clear_req_id();
    let mut state = base_state("TGS_REQ", &req.0.req_body, sender);
    state.stage = AUTHN_REQ_CL;
    state.tkt_in_id = tgs_header_tkt_id(req);
    current_audit().tgs_req(true, &state);
}

/// Unknown-server words after MIT `SRVC_PRINC`.
/// MIT `gather_tgs_req_info` (`do_tgs_req.c:667-667`): the audit stage becomes `SRVC_PRINC`
/// before the server principal is looked up.
fn tgs_fail_stage(e_text: &str) -> i32 {
    match e_text {
        status::LOOKING_UP_SERVER
        | status::UNKNOWN_SERVER
        | status::SERVER_NOT_FOUND
        | status::NULL_SERVER => SRVC_PRINC,
        _ => AUTHN_REQ_CL,
    }
}

fn tgs_fail_emsg(code: i32) -> &'static str {
    if code == err::S_PRINCIPAL_UNKNOWN {
        "Server not found in Kerberos database"
    } else {
        ""
    }
}

/// The transited contents as MIT logs them: the first 125 bytes, then `...` when cut.
fn transit_via(transited: &TransitedEncoding) -> (String, &'static str) {
    let raw = transited.contents.as_ref();
    let (shown, dots) = if raw.len() > 125 {
        (&raw[..125], "...")
    } else {
        (raw, "")
    };
    (String::from_utf8_lossy(shown).into_owned(), dots)
}

/// An error other than a refused path while checking the transited realms: logged, then the
/// path counts as unchecked. `crealm` / `srealm` are the realms checked, `cname` / `sname` the
/// request's client and server.
/// MIT `log_tgs_badtrans` (`kdc/kdc_log.c:176-212`): an unexpected error is logged at error
/// severity with the client and server names and the path.
#[must_use]
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

/// A transited path the realms do not allow: logged, and the ticket is not marked checked.
/// MIT `log_tgs_badtrans` (`kdc/kdc_log.c:176-212`): a refused path is logged at info with the
/// client and server names and the path.
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

/// AS/TGS success: MIT ISSUE tuple on `kdc.issue` plus the audit plugin.
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

/// AS/TGS KRB-ERROR: MIT fail tuple plus the audit plugin.
pub fn log_failure(
    store: &dyn PrincipalRead,
    raw: &[u8],
    sender: Option<&HostAddress>,
    _bytes: &[u8],
    code: i32,
    e_text: &str,
) {
    match raw.first().copied() {
        Some(0x6a) => {
            if let Ok(req) = decode::<AsReq>(raw) {
                as_failure(&req, sender, code, e_text);
            }
        }
        Some(0x6c) => {
            if let Ok(req) = decode::<TgsReq>(raw) {
                tgs_failure(store, &req, sender, code, e_text);
            }
        }
        _ => {}
    }
}

fn as_success(store: &dyn PrincipalRead, req: &AsReq, sender: Option<&HostAddress>, bytes: &[u8]) {
    let Ok(rep) = decode::<AsRep>(bytes) else {
        return;
    };
    seed_as_req(req, sender);
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
    current_audit().as_req(true, &state);
    clear_req_id();
}

fn as_failure(req: &AsReq, sender: Option<&HostAddress>, code: i32, e_text: &str) {
    seed_as_req(req, sender);
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
        "",
    );
    klog_as_req(
        &req_etypes,
        &from,
        &MitOutcome::Fail {
            status,
            code,
            authtime: 0,
        },
        &client,
        &server,
    );
    let mut state = base_state("AS_REQ", body, sender);
    state.stage = AUTHN_REQ_CL;
    state.status = Some(status.to_string());
    current_audit().as_req(code == 0, &state);
    clear_req_id();
}

/// MIT `log_tgs_req` (`kdc_log.c:132-135`): a missing client or server name is logged as
/// unknown, not omitted.
/// A body that does not decode as a TGS-REP is not logged as a success.
fn tgs_success(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    sender: Option<&HostAddress>,
    bytes: &[u8],
) {
    let Ok(rep) = decode::<TgsRep>(bytes) else {
        return;
    };
    seed_tgs_req(req, sender);
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
    let audit = current_audit();
    match s4u.as_ref().map(|(k, _)| *k) {
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
    }
    audit.tgs_req(true, &state);
    clear_req_id();
}

/// MIT `log_tgs_req` (`kdc_log.c:142-148`): a server-mismatch is not logged on the normal
/// status line.
/// An empty status is recorded as unknown rather than as a success.
fn tgs_failure(
    store: &dyn PrincipalRead,
    req: &TgsReq,
    sender: Option<&HostAddress>,
    code: i32,
    e_text: &str,
) {
    seed_tgs_req(req, sender);
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
        tgs_fail_emsg(code),
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
        },
        &client,
        &server,
        s4u.as_ref().map(|(k, c)| (*k, c.as_str())),
    );
    let mut state = base_state("TGS_REQ", body, sender);
    state.stage = tgs_fail_stage(status);
    state.status = Some(status.to_string());
    state.tkt_in_id = tgs_header_tkt_id(req);
    let audit = current_audit();
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
    audit.tgs_req(false, &state);
    clear_req_id();
}

/// MIT `log_as_req` (`kdc_log.c:76-83`): a null status is the issue line, and that line is
/// not the reply.
/// A missing client or server name is logged as unknown rather than omitted.
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
    let Some(pa) = req
        .0
        .padata
        .as_ref()
        .and_then(|p| p.iter().find(|x| x.padata_type == pa::TGS_REQ))
    else {
        return 0;
    };
    let Ok(ap) = decode::<krb5_types::ApReq>(pa.padata_value.as_ref()) else {
        return 0;
    };
    let Some(tgt) = store.fetch_krbtgt().ok().flatten() else {
        return 0;
    };
    let Some(key) = ticket_key(&tgt, ap.ticket.enc_part.etype, store.policy()) else {
        return 0;
    };
    decrypt_ticket_part(&key.key, &ap.ticket)
        .ok()
        .map_or(0, |p| p.authtime.unix_seconds())
}

fn tgs_client_name(store: &dyn PrincipalRead, req: &TgsReq, rep: &TgsRep, realm: &str) -> String {
    let reply = rep.0.cname.unparse_with_realm(&realm_str(&rep.0.crealm));
    if !reply.contains("WELLKNOWN/ANONYMOUS") {
        return reply;
    }
    tgs_error_client(store, req, realm)
}

fn tgs_error_client(store: &dyn PrincipalRead, req: &TgsReq, realm: &str) -> String {
    header_cname(store, req).map_or_else(
        || "<unknown client>".into(),
        |n| n.unparse_with_realm(realm),
    )
}

fn header_cname(store: &dyn PrincipalRead, req: &TgsReq) -> Option<PrincipalName> {
    let pa = req
        .0
        .padata
        .as_ref()?
        .iter()
        .find(|p| p.padata_type == pa::TGS_REQ)?;
    let ap: krb5_types::ApReq = decode(pa.padata_value.as_ref()).ok()?;
    let tgt = store.fetch_krbtgt().ok().flatten()?;
    let key = ticket_key(&tgt, ap.ticket.enc_part.etype, store.policy())?;
    Some(decrypt_ticket_part(&key.key, &ap.ticket).ok()?.cname)
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

    /// The etype list MIT 1.22.2 `kinit` sent in the live settle.
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
                    authtime: 0
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
                    authtime: 0
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
                    authtime: 0
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
                    authtime: 5
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
}
