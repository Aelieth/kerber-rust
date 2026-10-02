//! kadmind request logging (`kadmin/server/server_stubs.c` `log_done` / `log_unauth`, `prime_arg`,
//! `init_2_svc`): the `Request:` / `Unauthorized request:` lines with client, service and address,
//! one per procedure MIT logs, to the daemon log and the structured log.

use krb5_gss::GssContext;
use krb5_log::klog::{self, Severity};

use super::codes::{
    CHPASS_PRINCIPAL, CHPASS_PRINCIPAL3, CHRAND_PRINCIPAL, CHRAND_PRINCIPAL3, CREATE_ALIAS,
    CREATE_POLICY, CREATE_PRINCIPAL, CREATE_PRINCIPAL3, DELETE_POLICY, DELETE_PRINCIPAL, EINVAL,
    EXTRACT_KEYS, GET_POLICY, GET_POLS, GET_PRINCIPAL, GET_PRINCS, GET_PRIVS, GET_STRINGS, INIT,
    KADM5_AUTH_DELETE, KADM5_FAILURE, KADM5_UNK_PRINC, KRB5_KDB_ALIAS_UNSUPPORTED,
    KRB5_KDB_CANTLOCK_DB, MODIFY_POLICY, MODIFY_PRINCIPAL, PURGEKEYS, RENAME_PRINCIPAL, SET_STRING,
    SETKEY_PRINCIPAL, SETKEY_PRINCIPAL3, SETKEY_PRINCIPAL4,
};
use super::dispatch::auth_code_for;
use super::xdr::XdrR;

/// MIT `server_stubs.c` op name for the `Request:` / `Unauthorized request:` kadmind log lines;
/// `None` for the procedures MIT does not log this way (`kadm5_init` has its own line).
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

/// Whether the stub fetches the principal before anything else, so that a missing one ends the
/// request before any line is logged.
/// MIT `stub_setup` (`kadmin/server/server_stubs.c:293-298`): with `rec_out` the principal is
/// read first, and its error returns before the ACL check and the log.
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

/// The message of a kadm5 return code: MIT's `lib/kadm5/kadm_err.et` texts, the database errors
/// kadmind returns, and `strerror` for an errno.
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
        KRB5_KDB_ALIAS_UNSUPPORTED => "Operation unsupported on alias principal name".to_owned(),
        EINVAL => "Invalid argument".to_owned(),
        c if c < 4096 => i32::try_from(c).map_or_else(
            |_| format!("Unknown code {c}"),
            |n| klog::os_error_text(&std::io::Error::from_raw_os_error(n)),
        ),
        c => format!("Unknown code {c}"),
    }
}

/// A name for a log line: up to 125 bytes, then `...` when longer.
/// MIT `trunc_name` (`kadmin/server/misc.c:127-131`): names past `MAXPRINCLEN` are cut and
/// marked with dots.
fn trunc_name(s: &str) -> String {
    if s.len() <= 125 {
        return s.to_owned();
    }
    let mut end = 125;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

/// MIT `prime_arg` (`stub_setup`): the unparsed principal for a principal op, the policy name for
/// a policy op (`(null)` when there is none), the expression for a list (`*` when there is
/// none), and the client for `kadm5_get_privs`.
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

/// The rename's two principals, unparsed.
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

/// Who asked, and from where, for the request lines.
pub(super) struct Caller<'a> {
    /// The client principal.
    pub(super) client: &'a str,
    /// The kadmind service principal the client authenticated to.
    pub(super) service: &'a str,
    /// The client's address.
    pub(super) addr: &'a str,
    /// The RPC credential flavor (`RPCSEC_GSS` 6, `AUTH_GSSAPI` 300001).
    pub(super) flavor: u32,
}

/// The daemon log lines MIT writes for procedure `proc` with arguments `args` and `reply`.
/// MIT `log_unauth` (`kadmin/server/server_stubs.c:403-428`): the `Unauthorized request:` line
/// carries the op, target, client, service, and addr.
/// MIT `log_done` (`kadmin/server/server_stubs.c:430-459`): the `Request:` line carries the op,
/// target, result text, client, service, and addr.
/// MIT `rename_principal_2_svc` (`kadmin/server/server_stubs.c:671-747`): a rename names both
/// principals, and a refused one is logged once more with both.
/// MIT `init_2_svc` (`kadmin/server/server_stubs.c:1617-1653`): `kadm5_init` adds the API version
/// and the credential flavor.
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
        // Refused by the ACL or the source's lockdown: `log_unauth`, then the line naming both.
        // A missing source fails the lockdown lookup: only the line naming both.
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

/// The kadmind acceptor principal for the `service=` field (`kadmin/admin@REALM`).
pub(super) fn kadm5_service_name(ctx: &GssContext) -> String {
    match (&ctx.acceptor, &ctx.ticket_realm) {
        (Some(a), Some(r)) => a.unparse_with_realm(r),
        _ => String::new(),
    }
}

/// Log one kadmind request to the daemon log (notice) and the structured log.
pub(super) fn kadm5_log_op(proc: u32, args: &[u8], who: &Caller<'_>, reply: &[u8]) {
    for line in kadm5_log_lines(proc, args, who, reply) {
        let unauthorized = line.starts_with("Unauthorized");
        klog::syslog(Severity::Notice, &line);
        tracing::info!(
            event = krb5_log::events::ADMIN,
            component = "krb5-admin",
            outcome = if unauthorized { "unauthorized" } else { "done" },
            "{line}"
        );
    }
}
