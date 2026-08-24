//! Kerberos V5 AS, TGS, AP, SAFE/PRIV/CRED exchanges (RFC 4120).
//!
//! Transport is UDP with TCP fallback. Preauthentication uses
//! PA-ENC-TIMESTAMP and ETYPE-INFO2. Keytab and FILE ccache live here so
//! the KDC does not depend on the client crate. There is no C FFI.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod ap_rep;
mod ap_req;
mod as_ex;
mod builders;
mod capture;
mod ccache;
mod error;
mod keytab;
mod preauth;
mod replay;
mod safe_priv;
mod secret_file;
mod tgs;
mod transport;

pub use ap_rep::{build_ap_rep, verify_ap_rep};
pub use ap_req::{
    build_ap_req, build_ap_req_opts, build_ap_req_with_cksum, verify_ap_req, verify_ap_req_ex,
    ApVerifyOk, ApVerifyParams, DEFAULT_SKEW,
};
pub use as_ex::{as_exchange, AsOutcome, AsRequest};
pub use builders::{
    as_req, as_req_sname, pa_enc_timestamp, pa_enc_timestamp_at, tgs_req, tgs_req_ex,
};
pub use capture::capture_pdu;
pub use ccache::{parse_principal, realm, tgt_cred, CcacheCred, FileCcache};
pub use error::Error;
pub use keytab::{Keytab, KeytabEntry};
pub use preauth::{
    apply_strengthen, armor_key, attach_fast, build_fast_armor, fx_fast_padata, pa_for_user,
    pa_pac_options, pa_pk_as_req, pa_pk_as_req_agile, pa_pk_as_req_spki, pa_spake_response,
    pa_spake_support, pkinit_reply_key, pkinit_reply_key_agile, unwrap_fast_rep,
};
pub use replay::{ReplayCache, ReplayKey};
pub use safe_priv::{
    build_krb_cred, build_krb_priv, build_krb_priv_with_seq, build_krb_safe, unwrap_krb_cred,
    unwrap_krb_priv, unwrap_krb_priv_ex, unwrap_krb_safe,
};
pub use secret_file::write_secret_file;
pub use tgs::{referral_hop_realm, tgs_exchange, TgsOutcome};
pub use transport::{exchange, exchange_with_failover, KdcAddr, KDC_PORT};
