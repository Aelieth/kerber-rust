//! Minimal Kerberos V5 client: AS/TGS, MIT FILE ccache, keytab v2.
//!
//! `kinit` talks to a KDC over UDP/TCP 88, stores a TGT, and can request a
//! service ticket. There is no C FFI.

#![forbid(unsafe_code)]

pub mod ccache;
pub mod keytab;

use std::path::Path;

use krb5_protocol::{as_exchange, tgs_exchange, AsOutcome, AsRequest, KdcAddr, TgsOutcome};
use krb5_types::PrincipalName;
use zeroize::Zeroize;

pub use ccache::{parse_principal, realm, CcacheCred, FileCcache};
pub use keytab::{Keytab, KeytabEntry};
pub use krb5_protocol::{Error as ProtocolError, KDC_PORT};

/// Result of [`kinit`].
pub struct KinitResult {
    /// AS outcome (TGT + session key).
    pub as_out: AsOutcome,
    /// Optional TGS outcome.
    pub tgs_out: Option<TgsOutcome>,
}

/// Obtain a TGT from `kdc` for `principal` (`user@REALM`) and write a FILE
/// ccache. If `service` is `Some("host/foo")`, also run a TGS-REQ.
///
/// # Errors
///
/// Returns protocol or I/O errors. The password buffer is zeroized before
/// return.
pub fn kinit(
    kdc: &KdcAddr,
    principal: &str,
    password: &mut [u8],
    ccache_path: impl AsRef<Path>,
    service: Option<&str>,
) -> Result<KinitResult, Box<dyn std::error::Error + Send + Sync>> {
    let result = kinit_inner(kdc, principal, password, ccache_path.as_ref(), service);
    password.zeroize();
    result
}

fn kinit_inner(
    kdc: &KdcAddr,
    principal: &str,
    password: &[u8],
    ccache_path: &Path,
    service: Option<&str>,
) -> Result<KinitResult, Box<dyn std::error::Error + Send + Sync>> {
    let (cname, realm_s) = parse_principal(principal)?;
    let as_out = as_exchange(AsRequest {
        cname,
        realm: &realm_s,
        password,
        kdc,
    })?;
    let mut creds = vec![ccache::tgt_cred(
        &as_out.crealm,
        &as_out.cname,
        &as_out.ticket,
        &as_out.session_key,
        &as_out.enc_part,
    )?];
    let mut tgs_out = None;
    let mut tgs_err: Option<String> = None;
    if let Some(svc) = service {
        let parts: Vec<&str> = svc.split('/').collect();
        let sname = if parts.len() > 1 {
            PrincipalName::new(PrincipalName::NT_SRV_HST, parts)
        } else {
            PrincipalName::new(PrincipalName::NT_PRINCIPAL, parts)
        };
        match tgs_exchange(kdc, &as_out, sname, &realm_s) {
            Ok(tgs) => {
                creds.push(ccache::tgt_cred(
                    &as_out.crealm,
                    &as_out.cname,
                    &tgs.ticket,
                    &tgs.session_key,
                    &tgs.enc_part,
                )?);
                tgs_out = Some(tgs);
            }
            Err(e) => tgs_err = Some(e.to_string()),
        }
    }
    let cache = FileCcache {
        primary: (as_out.crealm.clone(), as_out.cname.clone()),
        creds,
    };
    cache.write_file(ccache_path)?;
    if let Some(e) = tgs_err {
        tracing::error!(
            event = "client.tgs",
            component = "krb5-client",
            outcome = "error",
            error = e.as_str(),
        );
    }
    Ok(KinitResult { as_out, tgs_out })
}
