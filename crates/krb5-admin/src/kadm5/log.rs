//! kadmind request logging (`server_stubs.c` `log_done` / `log_unauth`,
//! `prime_arg`): the `Request:` / `Unauthorized request:` lines with
//! client, service and address, one per procedure MIT logs.

use krb5_gss::GssContext;

use super::codes::{
    CHPASS_PRINCIPAL, CHPASS_PRINCIPAL3, CHRAND_PRINCIPAL, CHRAND_PRINCIPAL3, CREATE_ALIAS,
    CREATE_POLICY, CREATE_PRINCIPAL, CREATE_PRINCIPAL3, DELETE_POLICY, DELETE_PRINCIPAL,
    EXTRACT_KEYS, GET_POLICY, GET_POLS, GET_PRINCIPAL, GET_PRINCS, GET_PRIVS, GET_STRINGS,
    KADM5_AUTH_ADD, KADM5_AUTH_CHANGEPW, KADM5_AUTH_DELETE, KADM5_AUTH_EXTRACT, KADM5_AUTH_GET,
    KADM5_AUTH_INITIAL, KADM5_AUTH_INSUFFICIENT, KADM5_AUTH_LIST, KADM5_AUTH_MODIFY,
    KADM5_AUTH_SETKEY, MODIFY_POLICY, MODIFY_PRINCIPAL, PURGEKEYS, RENAME_PRINCIPAL, SET_STRING,
    SETKEY_PRINCIPAL, SETKEY_PRINCIPAL3, SETKEY_PRINCIPAL4,
};
use super::xdr::XdrR;

/// MIT `server_stubs.c` op name for the `Request:`/`Unauthorized request:`
/// kadmind log lines; `None` for the procs MIT does not log this way.
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

pub(super) fn kadm5_auth_denied(code: u32) -> bool {
    matches!(
        code,
        KADM5_AUTH_GET
            | KADM5_AUTH_ADD
            | KADM5_AUTH_MODIFY
            | KADM5_AUTH_DELETE
            | KADM5_AUTH_INSUFFICIENT
            | KADM5_AUTH_LIST
            | KADM5_AUTH_CHANGEPW
            | KADM5_AUTH_SETKEY
            | KADM5_AUTH_EXTRACT
            | KADM5_AUTH_INITIAL
    )
}

/// The kadmind acceptor principal for the `service=` field (`kadmin/admin@REALM`).
fn kadm5_service_name(ctx: &GssContext) -> String {
    match (&ctx.acceptor, &ctx.ticket_realm) {
        (Some(a), Some(r)) => a.unparse_with_realm(r),
        _ => String::new(),
    }
}

/// prime_arg (`stub_setup`): the unparsed principal for a principal op,
/// the policy/expression for a policy or list op, else the client.
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
            .unwrap_or_else(|| client.to_owned()),
        GET_PRINCS | GET_POLS => match r.nullstring() {
            Ok(Some(s)) if !s.is_empty() => s,
            _ => "*".to_owned(),
        },
        _ => client.to_owned(),
    }
}

/// The kadm5 result text for `log_done`; the full `com_err` table is not ported,
/// so a non-success, non-denial code logs a generic phrase (documented).
fn kadm5_result_text(code: u32) -> &'static str {
    if code == 0 {
        "success"
    } else {
        "operation failed"
    }
}

/// MIT `log_done` (`server_stubs.c:431-459`): then MIT `log_unauth` (`server_stubs.c:403-428`): `log_unauth` : one `Request:` or
/// `Unauthorized request:` line per kadmind operation with client/service/addr.
pub(super) fn kadm5_log_op(
    proc: u32,
    args: &[u8],
    client: &str,
    ctx: &GssContext,
    addr: &str,
    reply: &[u8],
) {
    let Some(op) = kadm5_op_name(proc) else {
        return;
    };
    let code = reply
        .get(4..8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_be_bytes);
    let target = kadm5_prime_arg(proc, args, client);
    let service = kadm5_service_name(ctx);
    if kadm5_auth_denied(code) {
        tracing::info!(
            event = krb5_log::events::ADMIN,
            component = "krb5-admin",
            outcome = "unauthorized",
            "Unauthorized request: {op}, {target}, client={client}, service={service}, addr={addr}"
        );
    } else {
        let result = kadm5_result_text(code);
        tracing::info!(
            event = krb5_log::events::ADMIN,
            component = "krb5-admin",
            outcome = "done",
            "Request: {op}, {target}, {result}, client={client}, service={service}, addr={addr}"
        );
    }
}
