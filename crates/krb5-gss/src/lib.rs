//! GSS-API Kerberos V5 mechanism (RFC 4121) and SPNEGO (RFC 4178).
//!
//! Interop with MIT `libgssapi_krb5` is out-of-process only. This crate
//! never links C libraries.
//!
//! One module per MIT source family: `context` (init/accept), `wrap`,
//! `mic`, `iov`, `export`, `spnego`, `deleg`, `oid`. In-src tests stay
//! under `tests`.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod context;
mod deleg;
mod export;
mod iov;
mod mic;
mod oid;
mod spnego;
mod wrap;

#[cfg(test)]
mod tests;

use krb5_crypto::ProtocolKey;
use krb5_protocol::ReplayCache;
use thiserror::Error;

/// GSS-API error.
#[derive(Debug, Error)]
pub enum Error {
    /// Protocol / crypto.
    #[error("{0}")]
    Inner(String),
    /// Integrity.
    #[error("gss integrity")]
    Integrity,
    /// Token too short.
    #[error("gss truncated")]
    Truncated,
    /// Sequence number replay or gap.
    #[error("gss sequence")]
    Sequence,
    /// Channel bindings mismatch.
    #[error("gss channel bindings")]
    ChannelBindings,
}

impl From<krb5_protocol::Error> for Error {
    fn from(e: krb5_protocol::Error) -> Self {
        Self::Inner(e.to_string())
    }
}

impl From<krb5_crypto::Error> for Error {
    fn from(e: krb5_crypto::Error) -> Self {
        Self::Inner(e.to_string())
    }
}

impl From<krb5_asn1::Error> for Error {
    fn from(e: krb5_asn1::Error) -> Self {
        Self::Inner(e.to_string())
    }
}

/// Established GSS context (initiator or acceptor).
pub struct GssContext {
    session: ProtocolKey,
    /// MIT CFX acceptor subkey from AP-REP (`FLAG_ACCEPTOR_SUBKEY`).
    acceptor_subkey: Option<ProtocolKey>,
    send_seq: u64,
    recv_seq: u64,
    recv_seen: bool,
    recv_window: std::collections::HashSet<u64>,
    initiator: bool,
    /// MIT libgssrpc INIT may spend GSS seq 0 on a discarded window MIC.
    rpcsec_init_window: bool,
    replay: ReplayCache,
    /// Authenticated client `name@REALM` (set on accept; initiator from cname).
    pub client: Option<String>,
    /// Delegated client from a 0x8003 KRB-CRED trailer (`GSS_C_DELEG_FLAG`).
    pub delegated: Option<String>,
    spnego_mech_list: Option<Vec<u8>>,
    lifetime_end: u32,
    gss_flags: u32,
    /// Ticket INITIAL flag (`gss_krb5_get_tkt_flags` / `TKT_FLG_INITIAL`).
    ticket_initial: bool,
    /// Ticket sname (`accept_sec_context` / CHANGEPW_SERVICE / kiprop).
    pub acceptor: Option<krb5_types::PrincipalName>,
    /// Ticket realm (`check_rpcsec_auth` / `check_iprop_rpcsec_auth`).
    pub ticket_realm: Option<String>,
    /// Ticket session for DCE third-leg `krb5_rd_rep_dce`.
    ap_rep_key: Option<ProtocolKey>,
    dce_style: bool,
}

pub use context::{ChannelBindings, InquireOk};
pub use deleg::DelegCred;
pub use iov::{IovBuf, IovType};
pub use oid::{
    GSS_C_CHANNEL_BOUND, GSS_C_CONF, GSS_C_DCE, GSS_C_DELEG, GSS_C_EXTENDED_ERROR, GSS_C_IDENTIFY,
    GSS_C_INTEG, GSS_C_MUTUAL, GSS_C_PROT_READY, GSS_C_REPLAY, GSS_C_SEQUENCE, GSS_C_TRANS,
    GSS_CHECKSUM_TYPE, KRB5_OID, SPNEGO_OID,
};
pub use spnego::{is_spnego, spnego_accept, spnego_accept_kt, spnego_init, spnego_inner};
pub use wrap::mit_shaped_wrap;
