//! GSS-API Kerberos V5 (RFC 4121) and SPNEGO (RFC 4178); never links C libraries.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod context;
mod deleg;
mod export;
mod iov;
mod mic;
mod oid;
mod seqstate;
mod spnego;
mod wrap;

#[cfg(all(test, feature = "test-hooks"))]
mod tests;

use krb5_crypto::ProtocolKey;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Inner(String),
    #[error("gss integrity")]
    Integrity,
    #[error("gss truncated")]
    Truncated,
    #[error("gss sequence")]
    Sequence,
    #[error("gss channel bindings")]
    ChannelBindings,
    #[error("{0}")]
    NotUs(String),
}

impl From<krb5_protocol::Error> for Error {
    fn from(e: krb5_protocol::Error) -> Self {
        match e {
            krb5_protocol::Error::KrbError { code, .. } if code == krb5_types::err::NOT_US => {
                Self::NotUs(e.to_string())
            }
            e => Self::Inner(e.to_string()),
        }
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

pub struct GssContext {
    session: ProtocolKey,
    acceptor_subkey: Option<ProtocolKey>,
    send_seq: u64,
    recv: seqstate::SeqState,
    initiator: bool,
    pub client: Option<String>,
    pub delegated: Option<String>,
    spnego_mech_list: Option<Vec<u8>>,
    lifetime_end: u32,
    acceptor_skew: i32,
    gss_flags: u32,
    ticket_initial: bool,
    pub acceptor: Option<krb5_types::PrincipalName>,
    pub ticket_realm: Option<String>,
    ap_rep_key: Option<ProtocolKey>,
    dce_style: bool,
    ap_req_time: Option<(krb5_types::KerberosTime, krb5_types::Microseconds)>,
}

pub use context::{ChannelBindings, InquireOk};
pub use deleg::DelegCred;
pub use iov::{IovBuf, IovType};
pub use oid::{
    GSS_C_AF_INET, GSS_C_CHANNEL_BOUND, GSS_C_CONF, GSS_C_DCE, GSS_C_DELEG, GSS_C_EXTENDED_ERROR,
    GSS_C_IDENTIFY, GSS_C_INTEG, GSS_C_MUTUAL, GSS_C_PROT_READY, GSS_C_REPLAY, GSS_C_SEQUENCE,
    GSS_C_TRANS, GSS_CHECKSUM_TYPE, KRB5_OID, SPNEGO_OID,
};
pub use spnego::{is_spnego, spnego_accept, spnego_accept_kt, spnego_init, spnego_inner};
pub use wrap::mit_shaped_wrap;
