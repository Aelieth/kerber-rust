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

#[cfg(all(test, feature = "test-hooks"))]
mod tests;

pub use acceptor::{acceptor_names_served, kdb_rd_req};
pub use auth::{
    changepw_acceptor, check_auth_gssapi_names, check_iprop_rpcsec_auth, check_rpcsec_auth,
};
pub use auth_plugin::{Decision, Kadm5Auth, Kadm5AuthConfig};
pub(crate) use codes::{
    KADM5_BAD_PASSWORD, KADM5_CANT_RESOLVE, KADM5_GSS_ERROR, KADM5_MISSING_KRB5_CONF_PARAMS,
    KADM5_RPC_ERROR, KADM5_SECURE_PRINC_MISSING,
};
pub use glob::glob_pattern_ok;
pub(crate) use glob::{glob_expand, glob_is_match, policies_matching, principals_matching};
pub use iprop::{IncrReply, IpropClient, IpropResync, RpcFailure};
pub(crate) use policy::{create_policy_local, modify_policy_local};
pub(crate) use rpc::Kadm5Conn;
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub use rpc::serve_kadm5_conn;
pub use rpc::{Kadm5RpcSession, Programs, RpcCtx, RpcPeer, UnhandledRpc, kadm5_handle_rpc};

pub(crate) fn kadm5_error_message(code: u32) -> String {
    log::kadm5_error_text(code)
}

/// MIT chpass-stub text.
pub(crate) fn chpass_error_text(e: &crate::Error) -> String {
    log::kadm5_error_text(dispatch::kadm5_code(codes::CHPASS_PRINCIPAL, e))
}

/// Includes errno.
pub(crate) fn chpass_store_error_text(e: &krb5_kdc::Error) -> String {
    log::kadm5_error_text(dispatch::store_code(codes::CHPASS_PRINCIPAL, e))
}
