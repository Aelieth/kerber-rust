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
#[cfg(any(test, feature = "diff"))]
#[cfg_attr(not(feature = "diff"), allow(dead_code))]
mod diff;
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
    ApVerifyOk, ApVerifyParams, DEFAULT_SKEW, build_ap_req, build_ap_req_mutual_seq,
    build_ap_req_opts, build_ap_req_with_cksum, verify_ap_req, verify_ap_req_ex,
};
pub use as_ex::{AsOutcome, AsRequest, FastArmor, PkinitClient, as_exchange, as_exchange_key};
pub use builders::{
    as_req, as_req_sname, pa_enc_timestamp, pa_enc_timestamp_at, tgs_req, tgs_req_ex,
};
pub use capture::capture_pdu;
pub use ccache::{CcacheCred, FileCcache, parse_principal, parse_principal_ex, realm, tgt_cred};
#[cfg(feature = "diff")]
pub use diff::{
    CompareOk, DiffError, StableKrbError, StableRep, Whitelist, compare_krb_error,
    compare_preauth_e_data, compare_stable_rep, decode_enc_kdc_rep, stable_krb_error, stable_rep,
};
pub use error::Error;
pub use keytab::{Keytab, KeytabEntry};
pub use preauth::{
    apply_strengthen, armor_key, attach_fast, build_fast_armor, fx_fast_padata, pa_for_user,
    pa_pac_options, pa_pk_as_req, pa_pk_as_req_agile, pa_pk_as_req_cn, pa_pk_as_req_signed,
    pa_pk_as_req_spki, pa_spake_response, pa_spake_support, pkinit_reply_key,
    pkinit_reply_key_agile, unwrap_fast_rep,
};
pub use replay::{ReplayCache, ReplayKey};
pub use safe_priv::{
    build_krb_cred, build_krb_priv, build_krb_priv_chained, build_krb_priv_with_seq,
    build_krb_safe, build_krb_safe_ex, unwrap_krb_cred, unwrap_krb_priv, unwrap_krb_priv_chained,
    unwrap_krb_priv_ex, unwrap_krb_safe, unwrap_krb_safe_ex,
};
pub use secret_file::{destroy_secret_file, write_secret_file};
pub use tgs::{TgsOutcome, referral_hop_realm, tgs_exchange};
pub use transport::{KDC_PORT, KdcAddr, exchange, exchange_on_tcp, exchange_with_failover};

#[cfg(test)]
#[path = "../tests/diff_compare.rs"]
mod diff_compare;
