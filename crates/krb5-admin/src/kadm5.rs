//! MIT kadm5 GSS-RPC (ONC RPC program 2112, version 2) on TCP 749.

mod acceptor;
mod auth;
pub(crate) mod auth_plugin;
mod codes;
mod dispatch;
mod glob;
mod iprop;
mod log;
mod policy;
mod principal;
mod rpc;
mod xdr;

#[cfg(test)]
mod tests;

pub use acceptor::{acceptor_names_served, kdb_rd_req};
pub use auth::{
    changepw_acceptor, check_auth_gssapi_names, check_iprop_rpcsec_auth, check_rpcsec_auth,
};
pub(crate) use codes::{
    KADM5_BAD_PASSWORD, KADM5_CANT_RESOLVE, KADM5_GSS_ERROR, KADM5_MISSING_KRB5_CONF_PARAMS,
    KADM5_RPC_ERROR, KADM5_SECURE_PRINC_MISSING,
};
pub use glob::glob_pattern_ok;
pub(crate) use glob::{glob_expand, glob_is_match, policies_matching, principals_matching};
pub use iprop::{IncrReply, IpropClient, RpcFailure};
pub(crate) use policy::{create_policy_local, modify_policy_local};
pub(crate) use rpc::Kadm5Conn;
pub use rpc::{
    Kadm5RpcSession, Programs, RpcCtx, RpcPeer, UnhandledRpc, kadm5_handle_rpc, serve_kadm5_conn,
};

/// The message of the kadm5 code `code` (`lib/kadm5/kadm_err.et`), as `error_message` gives it.
pub(crate) fn kadm5_error_message(code: u32) -> String {
    log::kadm5_error_text(code)
}

/// The daemon log text of a password change that failed with `e`: the message of the kadm5 code a `kadm5_chpass_principal` stub would return.
pub(crate) fn chpass_error_text(e: &crate::Error) -> String {
    log::kadm5_error_text(dispatch::kadm5_code(codes::CHPASS_PRINCIPAL, e))
}

/// The message of the kadm5 code a `kadm5_chpass_principal` stub would return for the database's error `e`, an errno's text included.
pub(crate) fn chpass_store_error_text(e: &krb5_kdc::Error) -> String {
    log::kadm5_error_text(dispatch::store_code(codes::CHPASS_PRINCIPAL, e))
}
