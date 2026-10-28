use krb5_gss::GssContext;
use krb5_log::klog::{self, Severity};

use super::codes::{
    CHPASS_PRINCIPAL, CHPASS_PRINCIPAL3, CHRAND_PRINCIPAL, CHRAND_PRINCIPAL3, CREATE_ALIAS,
    CREATE_POLICY, CREATE_PRINCIPAL, CREATE_PRINCIPAL3, DELETE_POLICY, DELETE_PRINCIPAL, EINVAL,
    EXTRACT_KEYS, GET_POLICY, GET_POLS, GET_PRINCIPAL, GET_PRINCS, GET_PRIVS, GET_STRINGS,
    GSS_S_BAD_BINDINGS, GSS_S_DEFECTIVE_TOKEN, INIT, KADM5_AUTH_DELETE, KADM5_FAILURE,
    KADM5_UNK_PRINC, KRB5_KDB_ALIAS_UNSUPPORTED, KRB5_KDB_BAD_SALTTYPE, KRB5_KDB_CANTLOCK_DB,
    MODIFY_POLICY, MODIFY_PRINCIPAL, PURGEKEYS, RENAME_PRINCIPAL, SET_STRING, SETKEY_PRINCIPAL,
    SETKEY_PRINCIPAL3, SETKEY_PRINCIPAL4,
};
use super::dispatch::auth_code_for;
use super::xdr::XdrR;

pub(super) fn kadm5_op_name(proc: u32) -> Option<&'static str> {
    Some(match proc {
        CREATE_PRINCIPAL | CREATE_PRINCIPAL3 => "kadm5_create_principal",
        DELETE_PRINCIPAL => "kadm5_delete_principal",
        MODIFY_PRINCIPAL => "kadm5_modify_principal",
        RENAME_PRINCIPAL => "kadm5_rename_principal",
        GET_PRINCIPAL => "kadm5_get_principal",
        CHPASS_PRINCIPAL | CHPASS_PRINCIPAL3 => "kadm5_chpass_principal",
        CHRAND_PRINCIPAL | CHRAND_PRINCIPAL3 => "kadm5_randkey_principal",
        SETKEY_PRINCIPAL | SETKEY_PRINCIPAL3 | SETKEY_PRINCIPAL4 => "kadm5_setkey_principal",
        GET_PRINCS => "kadm5_get_principals",
        CREATE_POLICY => "kadm5_create_policy",
        DELETE_POLICY => "kadm5_delete_policy",
        MODIFY_POLICY => "kadm5_modify_policy",
        GET_POLICY => "kadm5_get_policy",
        GET_POLS => "kadm5_get_policies",
        GET_PRIVS => "kadm5_get_privs",
        PURGEKEYS => "kadm5_purgekeys",
        GET_STRINGS => "kadm5_get_strings",
        SET_STRING => "kadm5_mod_strings",
        EXTRACT_KEYS => "kadm5_get_principal_keys",
        CREATE_ALIAS => "kadm5_create_alias",
        _ => return None,
    })
}

fn fetches_principal_first(proc: u32) -> bool {
    matches!(
        proc,
        MODIFY_PRINCIPAL
            | GET_PRINCIPAL
            | CHPASS_PRINCIPAL
            | CHPASS_PRINCIPAL3
            | CHRAND_PRINCIPAL
            | CHRAND_PRINCIPAL3
            | SETKEY_PRINCIPAL
            | SETKEY_PRINCIPAL3
            | SETKEY_PRINCIPAL4
            | PURGEKEYS
            | GET_STRINGS
            | SET_STRING
            | EXTRACT_KEYS
    )
}

/// MIT texts; strerror for an errno.
pub(super) fn kadm5_error_text(code: u32) -> String {
    const OVK: [&str; 64] = [
        "Operation failed for unspecified reason",
        "Operation requires ``get'' privilege",
        "Operation requires ``add'' privilege",
        "Operation requires ``modify'' privilege",
        "Operation requires ``delete'' privilege",
        "Insufficient authorization for operation",
        "Database inconsistency detected",
        "Principal or policy already exists",
        "Communication failure with server",
        "No administration server found for realm",
        "Password history entry (kadmin/history) contains unsupported key type",
        "Connection to server not initialized",
        "Principal does not exist",
        "Policy does not exist",
        "Invalid field mask for operation",
        "Invalid number of character classes",
        "Invalid password length",
        "Illegal policy name",
        "Illegal principal name",
        "Invalid auxiliary attributes",
        "Invalid password history count",
        "Password minimum life is greater than password maximum life",
        "Password is too short",
        "Password does not contain enough character classes",
        "Password is in the password dictionary",
        "Cannot reuse password",
        "Current password's minimum life has not expired",
        "Policy is in use",
        "Connection to server already initialized",
        "Incorrect password",
        "Cannot change protected principal",
        "Programmer error!  Bad Admin server handle",
        "Programmer error!  Bad API structure version",
        "API structure version specified by application is no longer supported (to fix, recompile application against current KADM5 API header files and libraries)",
        "API structure version specified by application is unknown to libraries (to fix, obtain current KADM5 API header files and libraries and recompile application)",
        "Programmer error!  Bad API version",
        "API version specified by application is no longer supported by libraries (to fix, update application to adhere to current API version and recompile)",
        "API version specified by application is no longer supported by server (to fix, update application to adhere to current API version and recompile)",
        "API version specified by application is unknown to libraries (to fix, obtain current KADM5 API header files and libraries and recompile application)",
        "API version specified by application is unknown to server (to fix, obtain and install newest KADM5 Admin Server)",
        "Database error! Required KADM5 principal missing",
        "The salt type of the specified principal does not support renaming",
        "Illegal configuration parameter for remote KADM5 client",
        "Illegal configuration parameter for local KADM5 client",
        "Operation requires ``list'' privilege",
        "Operation requires ``change-password'' privilege",
        "GSS-API (or Kerberos) error",
        "Programmer error!  Illegal tagged data list type",
        "Required parameters in kdc.conf missing",
        "Bad krb5 admin server hostname",
        "Operation requires ``set-key'' privilege",
        "Multiple values for single or folded enctype",
        "Invalid enctype for setv4key",
        "Mismatched enctypes for setkey3",
        "Missing parameters in krb5.conf required for kadmin client",
        "XDR encoding error",
        "Cannot resolve network address for admin server in requested realm",
        "Unspecified password quality failure",
        "Invalid key/salt tuples",
        "Invalid multiple or duplicate kvnos in setkey operation",
        "Operation requires ``extract-keys'' privilege",
        "Principal keys are locked down",
        "Operation requires initial ticket",
        "Alias target must be within the same realm",
    ];
    if let Some(text) = code
        .checked_sub(KADM5_FAILURE)
        .and_then(|i| OVK.get(usize::try_from(i).ok()?))
    {
        return (*text).to_owned();
    }
    match code {
        KRB5_KDB_CANTLOCK_DB => "Insufficient access to lock database".to_owned(),
        KRB5_KDB_BAD_SALTTYPE => "Unsupported salt type".to_owned(),
        KRB5_KDB_ALIAS_UNSUPPORTED => "Operation unsupported on alias principal name".to_owned(),
        EINVAL => "Invalid argument".to_owned(),
        c if c < 4096 => i32::try_from(c).map_or_else(
            |_| format!("Unknown code {c}"),
            |n| klog::os_error_text(&std::io::Error::from_raw_os_error(n)),
        ),
        c => format!("Unknown code {c}"),
    }
}

/// Unlike MIT, a name cannot forge a line.
fn escape_log(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if !s.chars().any(char::is_control) {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let b = c as usize;
                out.push_str("\\x");
                out.push(HEX[(b >> 4) & 0xf] as char);
                out.push(HEX[b & 0xf] as char);
            }
            c => out.push(c),
        }
    }
    out
}

fn trunc_name(s: &str) -> String {
    if s.len() <= 125 {
        return escape_log(s);
    }
    let mut end = 125;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    escape_log(&format!("{}...", &s[..end]))
}

// MIT: `prime_arg` (stub_setup)
pub(super) fn kadm5_prime_arg(proc: u32, args: &[u8], client: &str) -> String {
    let mut r = XdrR::new(args);
    if r.u32().is_err() {
        return client.to_owned();
    }
    match proc {
        CREATE_PRINCIPAL | CREATE_PRINCIPAL3 | DELETE_PRINCIPAL | MODIFY_PRINCIPAL
        | GET_PRINCIPAL | CHPASS_PRINCIPAL | CHPASS_PRINCIPAL3 | CHRAND_PRINCIPAL
        | CHRAND_PRINCIPAL3 | SETKEY_PRINCIPAL | SETKEY_PRINCIPAL3 | SETKEY_PRINCIPAL4
        | PURGEKEYS | GET_STRINGS | SET_STRING | EXTRACT_KEYS | RENAME_PRINCIPAL | CREATE_ALIAS => {
            r.principal_realm().map_or_else(
                |_| client.to_owned(),
                |(p, realm)| p.unparse_with_realm(&realm),
            )
        }
        CREATE_POLICY | DELETE_POLICY | MODIFY_POLICY | GET_POLICY => r
            .nullstring()
            .ok()
            .flatten()
            .unwrap_or_else(|| "(null)".to_owned()),
        GET_PRINCS | GET_POLS => r
            .nullstring()
            .ok()
            .flatten()
            .unwrap_or_else(|| "*".to_owned()),
        _ => client.to_owned(),
    }
}

fn rename_targets(args: &[u8]) -> Option<(String, String)> {
    let mut r = XdrR::new(args);
    r.u32().ok()?;
    let (src, src_realm) = r.principal_realm().ok()?;
    let (dst, dst_realm) = r.principal_realm().ok()?;
    Some((
        src.unparse_with_realm(&src_realm),
        dst.unparse_with_realm(&dst_realm),
    ))
}

pub(super) struct Caller<'a> {
    pub(super) client: &'a str,
    pub(super) service: &'a str,
    pub(super) addr: &'a str,
    /// Flavor: RPCSEC_GSS 6, AUTH_GSSAPI 300001.
    pub(super) flavor: u32,
}

// MIT: `log_unauth` (kadmin/server/server_stubs.c:403-428)
// MIT: `log_done` (kadmin/server/server_stubs.c:430-459)
/// Request: op, target, result, then the tail.
// MIT: `init_2_svc` (kadmin/server/server_stubs.c:1617-1653)
pub(super) fn kadm5_log_lines(
    proc: u32,
    args: &[u8],
    who: &Caller<'_>,
    reply: &[u8],
) -> Vec<String> {
    let code = reply
        .get(4..8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_be_bytes);
    let client = trunc_name(who.client);
    let service = trunc_name(who.service);
    let addr = who.addr;
    let tail = format!("client={client}, service={service}, addr={addr}");
    if proc == INIT {
        let vers = XdrR::new(args).u32().unwrap_or(0) & !0x1234_5700;
        return vec![format!(
            "Request: kadm5_init, {client}, success, {tail}, vers={vers}, flavor={}",
            who.flavor
        )];
    }
    let Some(op) = kadm5_op_name(proc) else {
        return Vec::new();
    };
    if fetches_principal_first(proc) && code == KADM5_UNK_PRINC {
        return Vec::new();
    }
    let denied = code == auth_code_for(proc);
    let result = if code == 0 {
        "success".to_owned()
    } else {
        kadm5_error_text(code)
    };
    if proc == RENAME_PRINCIPAL {
        let (src, dst) = rename_targets(args).unwrap_or_default();
        let (src, dst) = (trunc_name(&src), trunc_name(&dst));
        let refused = denied || code == KADM5_AUTH_DELETE;
        let mut lines = Vec::new();
        if refused {
            lines.push(format!("Unauthorized request: {op}, {src}, {tail}"));
        }
        if refused || code == KADM5_UNK_PRINC {
            lines.push(format!(
                "Unauthorized request: {op}, {src} to {dst}, {tail}"
            ));
        } else {
            lines.push(format!("Request: {op}, {src} to {dst}, {result}, {tail}"));
        }
        return lines;
    }
    let target = trunc_name(&kadm5_prime_arg(proc, args, who.client));
    if denied {
        vec![format!("Unauthorized request: {op}, {target}, {tail}")]
    } else {
        vec![format!("Request: {op}, {target}, {result}, {tail}")]
    }
}

pub(super) fn kadm5_service_name(ctx: &GssContext) -> String {
    match (&ctx.acceptor, &ctx.ticket_realm) {
        (Some(a), Some(r)) => a.unparse_with_realm(r),
        _ => String::new(),
    }
}

pub(super) fn kadm5_log_op(proc: u32, args: &[u8], who: &Caller<'_>, reply: &[u8]) {
    for line in kadm5_log_lines(proc, args, who, reply) {
        emit(&line);
    }
}

fn emit(line: &str) {
    let unauthorized = line.starts_with("Unauthorized");
    crate::kadmind::admin_syslog_open(Severity::Notice, line);
    tracing::info!(
        event = krb5_log::events::ADMIN,
        component = "krb5-admin",
        outcome = if unauthorized { "unauthorized" } else { "done" },
        "{line}"
    );
}

fn iprop_tail(who: &Caller<'_>) -> String {
    format!(
        "client={}, service={}, addr={}",
        who.client, who.service, who.addr
    )
}

// MIT: `replystr` (kadmin/server/ipropd_svc.c:96-114)
fn iprop_reply_str(status: u32) -> &'static str {
    match status {
        krb5_kdc::IPROP_OK => "UPDATE_OK",
        krb5_kdc::IPROP_ERROR => "UPDATE_ERROR",
        krb5_kdc::IPROP_FULL_RESYNC => "UPDATE_FULL_RESYNC_NEEDED",
        3 => "UPDATE_BUSY",
        krb5_kdc::IPROP_NIL => "UPDATE_NIL",
        krb5_kdc::IPROP_PERM_DENIED => "UPDATE_PERM_DENIED",
        _ => "<UNKNOWN_CODE>",
    }
}

// MIT: `iprop_get_updates_1_svc` (kadmin/server/ipropd_svc.c:191-200)
// MIT: `ipropx_resync` (kadmin/server/ipropd_svc.c:311-320)
pub(super) fn iprop_log_unauth(whoami: &str, who: &Caller<'_>) {
    emit(&format!(
        "Unauthorized request: {whoami}, {}",
        iprop_tail(who)
    ));
}

// MIT: `iprop_get_updates_1_svc` (kadmin/server/ipropd_svc.c:202-230)
pub(super) fn iprop_log_updates(
    who: &Caller<'_>,
    incoming: u32,
    got: &krb5_kdc::UlogUpdates,
    err: Option<&str>,
) {
    let out = if got.status == krb5_kdc::IPROP_OK {
        got.last.sno.to_string()
    } else {
        "N/A".to_owned()
    };
    emit(&format!(
        "Request: iprop_get_updates_1, {}; Incoming SerialNo={incoming}; \
         Outgoing SerialNo={out}, {}, {}",
        iprop_reply_str(got.status),
        err.unwrap_or("success"),
        iprop_tail(who)
    ));
}

// MIT: `ipropx_resync` (kadmin/server/ipropd_svc.c:420-428)
pub(super) fn iprop_log_resync(who: &Caller<'_>, task: i32) {
    emit(&format!(
        "Request: iprop_full_resync_1, spawned resync process {task}, {}",
        iprop_tail(who)
    ));
}

// MIT: `log_miscerr` (kadmin/server/ovsec_kadmd.c:291-295)
pub(super) fn rpc_log_miscerr(addr: &str, error: &str) {
    crate::kadmind::admin_syslog(
        Severity::Notice,
        &format!("Miscellaneous RPC error: {addr}, {error}"),
    );
}

// MIT: `log_badverf` (kadmin/server/ovsec_kadmd.c:206-287)
/// Name from table (no 17), else number.
pub(super) fn rpc_log_badverf(proc: u32, client: Option<&str>, server: Option<&str>, addr: &str) {
    const NAMES: [&str; 24] = [
        "CREATE_PRINCIPAL",
        "DELETE_PRINCIPAL",
        "MODIFY_PRINCIPAL",
        "RENAME_PRINCIPAL",
        "GET_PRINCIPAL",
        "CHPASS_PRINCIPAL",
        "CHRAND_PRINCIPAL",
        "CREATE_POLICY",
        "DELETE_POLICY",
        "MODIFY_POLICY",
        "GET_POLICY",
        "GET_PRIVS",
        "INIT",
        "GET_PRINCS",
        "GET_POLS",
        "SETKEY_PRINCIPAL",
        "",
        "CREATE_PRINCIPAL3",
        "CHPASS_PRINCIPAL3",
        "CHRAND_PRINCIPAL3",
        "SETKEY_PRINCIPAL3",
        "PURGEKEYS",
        "GET_STRINGS",
        "SET_STRING",
    ];
    let procname = usize::try_from(proc)
        .ok()
        .and_then(|p| p.checked_sub(1))
        .and_then(|i| NAMES.get(i))
        .filter(|n| !n.is_empty())
        .map_or_else(|| proc.to_string(), |n| (*n).to_owned());
    let client = trunc_name(client.unwrap_or("(null)"));
    let server = trunc_name(server.unwrap_or("(null)"));
    crate::kadmind::admin_syslog(
        Severity::Notice,
        &format!(
            "WARNING! Forged/garbled request: {procname}, claimed client = {client}, server = \
             {server}, addr = {addr}"
        ),
    );
}

// MIT: `krb5_iprop_prog_1` (kadmin/server/ipropd_svc.c:542-548)
pub(super) fn rpc_log_flavor_refused(iprop: bool, addr: &str, flavor: u32) {
    let lead = if iprop {
        "authentication"
    } else {
        "Authentication"
    };
    crate::kadmind::admin_syslog(
        Severity::Err,
        &format!("{lead} attempt failed: {addr}, RPC authentication flavor {flavor}"),
    );
}

// MIT: `log_badauth` (kadmin/server/ovsec_kadmd.c:325-333)
/// Header, major, minor, footer.
// MIT: `displayMajor` (lib/gssapi/mechglue/g_dsp_status.c:192-231)
pub(super) fn rpc_log_badauth(addr: &str, major: u32, minor: &str) {
    let major = match major {
        GSS_S_BAD_BINDINGS => "Incorrect channel bindings were supplied",
        GSS_S_DEFECTIVE_TOKEN => "Invalid token was supplied",
        _ => "Unspecified GSS failure.  Minor code may provide more information",
    };
    for line in [
        format!("Authentication attempt failed: {addr}, GSS-API error strings are:"),
        format!("    {major}"),
        format!("    {minor}"),
        "   GSS-API error strings complete.".to_owned(),
    ] {
        crate::kadmind::admin_syslog(Severity::Notice, &line);
    }
}

pub(super) fn rpc_log_bad_service(service: &str) {
    crate::kadmind::admin_syslog(
        Severity::Err,
        &format!("bad service principal {}", trunc_name(service)),
    );
}

/// Unserved: before `svcerr_noproc`.
pub(super) fn rpc_log_bad_proc(iprop: bool, addr: &str, proc: u32) {
    let line = if iprop {
        format!("RPC unknown request: {proc} (krb5_iprop_prog_1)")
    } else {
        format!("Invalid KADM5 procedure number: {addr}, {proc}")
    };
    crate::kadmind::admin_syslog(Severity::Err, &line);
}
