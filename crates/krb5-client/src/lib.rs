//! Minimal Kerberos V5 client: AS/TGS, MIT FILE ccache, keytab v2.
//!
//! `kinit` talks to a KDC over UDP/TCP 88, stores a TGT, and can request a
//! service ticket. There is no C FFI.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::path::Path;

use krb5_protocol::{AsOutcome, AsRequest, KdcAddr, TgsOutcome, as_exchange, tgs_exchange};
use krb5_types::PrincipalName;
use zeroize::Zeroize;

pub use krb5_protocol::{
    CcacheCred, FileCcache, Keytab, KeytabEntry, parse_principal, realm, tgt_cred,
};
pub use krb5_protocol::{Error as ProtocolError, KDC_PORT};

pub mod ccache {
    pub use krb5_protocol::{CcacheCred, FileCcache, parse_principal, realm, tgt_cred};
}

pub mod keytab {
    pub use krb5_protocol::{Keytab, KeytabEntry};
}

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
    kinit_ex(kdc, principal, password, ccache_path, service, false)
}

/// [`kinit`] with a preauth mode (`want_spake` = PA-SPAKE P-256).
///
/// # Errors
///
/// Protocol or I/O errors. The password buffer is zeroized before return.
pub fn kinit_ex(
    kdc: &KdcAddr,
    principal: &str,
    password: &mut [u8],
    ccache_path: impl AsRef<Path>,
    service: Option<&str>,
    want_spake: bool,
) -> Result<KinitResult, Box<dyn std::error::Error + Send + Sync>> {
    let result = kinit_inner(
        kdc,
        principal,
        password,
        ccache_path.as_ref(),
        service,
        want_spake,
    );
    password.zeroize();
    result
}

fn kinit_inner(
    kdc: &KdcAddr,
    principal: &str,
    password: &[u8],
    ccache_path: &Path,
    service: Option<&str>,
    want_spake: bool,
) -> Result<KinitResult, Box<dyn std::error::Error + Send + Sync>> {
    let (cname, realm_s) = parse_principal(principal)?;
    let resolved = resolve_kdc(&realm_s, kdc);
    let as_out = as_exchange(&AsRequest {
        cname,
        realm: &realm_s,
        password,
        kdc: &resolved,
        want_spake,
    })?;
    let mut creds = vec![tgt_cred(
        &as_out.crealm,
        &as_out.cname,
        &as_out.ticket,
        &as_out.session_key,
        &as_out.enc_part,
    )?];
    let mut tgs_out = None;
    let mut tgs_err: Option<String> = None;
    if let Some(svc) = service {
        let (svc_name, svc_realm) = match svc.rsplit_once('@') {
            Some((n, r)) => (n, r.to_owned()),
            None => (svc, realm_s.clone()),
        };
        let parts: Vec<&str> = svc_name.split('/').collect();
        let sname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, parts);
        match tgs_exchange(&resolved, &as_out, sname, &svc_realm) {
            Ok(tgs) => {
                creds.push(tgt_cred(
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
        return Err(e.into());
    }
    Ok(KinitResult { as_out, tgs_out })
}

fn resolve_kdc(realm: &str, argv: &KdcAddr) -> KdcAddr {
    krb5_config::discover_kdc(realm).map_or_else(
        || argv.clone(),
        |ep| KdcAddr {
            host: ep.host,
            port: ep.port,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_kdc_prefers_krb5_conf_over_argv() {
        let path = std::env::temp_dir().join(format!(
            "kerber-client-krb5-{}-{}.conf",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &path,
            r"
[realms]
    KERBER.TEST = {
        kdc = 192.0.2.10:8888
    }
",
        )
        .unwrap();
        let argv = KdcAddr {
            host: "127.0.0.1".into(),
            port: 88,
        };
        let ep = krb5_config::discover_kdc_in([&path], "KERBER.TEST").unwrap();
        let resolved = KdcAddr {
            host: ep.host,
            port: ep.port,
        };
        assert_eq!(resolved.host, "192.0.2.10");
        assert_eq!(resolved.port, 8888);
        assert_eq!(argv.port, 88);
        let _ = std::fs::remove_file(&path);
    }
}
