//! MIT kadm5 GSS-RPC (ONC RPC program 2112, version 2) on TCP 749.
//!
//! MIT 1.22.2 `kadmin` authenticates with AUTH_GSSAPI flavor 300001
//! (`auth_gssapi.h`), not RFC 2203 RPCSEC_GSS flavor 6. This is not a
//! full C ABI clone.
//!
//! One module per MIT source family: `codes` (constants), `xdr`, `rpc`
//! (framing and reply builders), `auth` (AUTH_GSSAPI, RPCSEC_GSS and the
//! acceptor checks), `iprop`, `dispatch` (the procedure switch),
//! `principal` and `policy` (argument and reply codecs), `glob`, `log`.
//! In-src tests stay under `tests/`.

mod auth;
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

pub use auth::{
    changepw_acceptor, check_auth_gssapi_names, check_iprop_rpcsec_auth, check_rpcsec_auth,
};
pub(crate) use dispatch::{lock_database, undo_failed_update};
pub use glob::glob_pattern_ok;
pub(crate) use glob::{glob_expand, glob_is_match};
pub use iprop::{IpropLast, IpropPull, iprop_fullresync, iprop_pull};
pub(crate) use policy::{create_policy_local, modify_policy_local};
pub use rpc::{Kadm5RpcError, Kadm5RpcSession, RpcCtx, kadm5_handle_rpc, serve_kadm5_conn};

/// The daemon log text of a password change that failed with `e`: the message of the kadm5
/// code a `kadm5_chpass_principal` stub would return.
pub(crate) fn chpass_error_text(e: &crate::Error) -> String {
    log::kadm5_error_text(dispatch::kadm5_code(codes::CHPASS_PRINCIPAL, e))
}
