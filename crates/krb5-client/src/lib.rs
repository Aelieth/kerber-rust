//! Minimal Kerberos V5 client: AS/TGS, MIT FILE ccache, keytab v2.
//!
//! `kinit` talks to a KDC over UDP/TCP 88, stores a TGT, and can request a
//! service ticket. There is no C FFI.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::path::Path;

use krb5_asn1::decode;
use krb5_config::CcSpec;
use krb5_protocol::{
    AsOutcome, AsRequest, FastArmor, KdcAddr, PkinitClient, TgsOutcome, as_exchange,
    dir_cache_path, memory_destroy, memory_retrieve, memory_store, parse_principal_ex,
    tgs_exchange,
};
use krb5_types::{PrincipalName, Ticket};
use zeroize::Zeroize;

pub use krb5_protocol::{
    CcacheCred, CcacheKeyblock, FileCcache, Keytab, KeytabEntry, parse_principal, realm, tgt_cred,
};
pub use krb5_protocol::{Error as ProtocolError, KDC_PORT};

pub mod ccache {
    pub use krb5_protocol::{
        CcacheCred, CcacheKeyblock, FileCcache, parse_principal, realm, tgt_cred,
    };
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
    kinit_ex(
        kdc,
        principal,
        password,
        ccache_path,
        service,
        false,
        None,
        None,
        None,
        false,
    )
}

/// [`kinit`] with a preauth mode (`want_spake` = PA-SPAKE P-256).
///
/// # Errors
///
/// Protocol or I/O errors. The password buffer is zeroized before return.
#[allow(clippy::too_many_arguments)]
pub fn kinit_ex(
    kdc: &KdcAddr,
    principal: &str,
    password: &mut [u8],
    ccache_path: impl AsRef<Path>,
    service: Option<&str>,
    want_spake: bool,
    armor_ccache: Option<&Path>,
    pkinit_identity: Option<&Path>,
    pkinit_anchors: Option<&Path>,
    enterprise: bool,
) -> Result<KinitResult, Box<dyn std::error::Error + Send + Sync>> {
    let result = kinit_to_spec(
        kdc,
        principal,
        password,
        &CcSpec::File(ccache_path.as_ref().to_path_buf()),
        service,
        want_spake,
        armor_ccache,
        pkinit_identity,
        pkinit_anchors,
        enterprise,
    );
    password.zeroize();
    result
}

/// [`kinit_ex`] storing into [`CcSpec`] (FILE, MEMORY, or DIR).
///
/// # Errors
///
/// Protocol or I/O errors. The password buffer is zeroized before return.
#[allow(clippy::too_many_arguments)]
pub fn kinit_to_spec(
    kdc: &KdcAddr,
    principal: &str,
    password: &mut [u8],
    spec: &CcSpec,
    service: Option<&str>,
    want_spake: bool,
    armor_ccache: Option<&Path>,
    pkinit_identity: Option<&Path>,
    pkinit_anchors: Option<&Path>,
    enterprise: bool,
) -> Result<KinitResult, Box<dyn std::error::Error + Send + Sync>> {
    let built = kinit_inner(
        kdc,
        principal,
        password,
        service,
        want_spake,
        armor_ccache,
        pkinit_identity,
        pkinit_anchors,
        enterprise,
    );
    let result = match built {
        Ok((r, cc)) => store_ccache(spec, cc).map(|()| r),
        Err(e) => Err(e),
    };
    password.zeroize();
    result
}

/// Load a FILE, MEMORY, or DIR cache.
///
/// # Errors
///
/// Missing cache or parse failure.
pub fn load_ccache(spec: &CcSpec) -> Result<FileCcache, Box<dyn std::error::Error + Send + Sync>> {
    match spec {
        CcSpec::File(p) => Ok(FileCcache::parse(&std::fs::read(p)?)?),
        CcSpec::Memory(n) => memory_retrieve(n).ok_or_else(|| "No credentials cache found".into()),
        CcSpec::Dir(r) => {
            let p = dir_cache_path(r)?;
            Ok(FileCcache::parse(&std::fs::read(p)?)?)
        }
    }
}

/// Write a cache to FILE, MEMORY, or DIR.
///
/// # Errors
///
/// I/O or DIR residual errors.
pub fn store_ccache(
    spec: &CcSpec,
    cc: FileCcache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match spec {
        CcSpec::File(p) => cc.write_file(p).map_err(Into::into),
        CcSpec::Memory(n) => {
            memory_store(n.clone(), cc);
            Ok(())
        }
        CcSpec::Dir(r) => {
            let p = dir_cache_path(r)?;
            cc.write_file(p).map_err(Into::into)
        }
    }
}

/// Destroy FILE, MEMORY, or DIR (primary/subsidiary FILE).
///
/// # Errors
///
/// Missing cache or I/O.
pub fn destroy_ccache(spec: &CcSpec) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match spec {
        CcSpec::File(p) => krb5_protocol::destroy_secret_file(p).map_err(Into::into),
        CcSpec::Memory(n) => {
            if memory_destroy(n) {
                Ok(())
            } else {
                Err("No credentials cache found".into())
            }
        }
        CcSpec::Dir(r) => {
            let p = dir_cache_path(r)?;
            krb5_protocol::destroy_secret_file(&p).map_err(Into::into)
        }
    }
}

fn load_fast_armor(path: &Path) -> Result<FastArmor, Box<dyn std::error::Error + Send + Sync>> {
    let bytes = std::fs::read(path)?;
    let cc = FileCcache::parse(&bytes)?;
    let cred = cc
        .creds
        .iter()
        .find(|c| !c.is_config() && c.server.1.components_joined().starts_with("krbtgt/"))
        .ok_or("armor ccache has no TGT")?;
    let ticket: Ticket = decode(&cred.ticket)?;
    Ok(FastArmor {
        ticket,
        session: cred.session_key()?,
        crealm: cred.client.0.clone(),
        cname: cred.client.1.clone(),
    })
}

fn strip_file_spec(s: &str) -> &str {
    s.strip_prefix("FILE:").unwrap_or(s)
}

fn load_pkinit(
    identity: &Path,
    anchors: &Path,
) -> Result<PkinitClient, Box<dyn std::error::Error + Send + Sync>> {
    let id = std::fs::read_to_string(identity)?;
    let (cert, key) = krb5_types::pkinit::parse_identity_pem(&id).ok_or("pkinit identity PEM")?;
    let anc = std::fs::read_to_string(anchors)?;
    let ca_cert = krb5_types::pkinit::parse_pem("CERTIFICATE", &anc).ok_or("pkinit anchors PEM")?;
    Ok(PkinitClient { cert, key, ca_cert })
}

fn pkinit_from_conf(realm: &str) -> (Option<std::path::PathBuf>, Option<std::path::PathBuf>) {
    for path in krb5_config::krb5_conf_paths() {
        let Ok(conf) = krb5_config::Krb5Conf::load_file(&path) else {
            continue;
        };
        let id = conf
            .pkinit_identities
            .get(realm)
            .and_then(|v| v.first())
            .map(|s| std::path::PathBuf::from(strip_file_spec(s)));
        let an = conf
            .pkinit_anchors
            .get(realm)
            .and_then(|v| v.first())
            .map(|s| std::path::PathBuf::from(strip_file_spec(s)));
        if id.is_some() || an.is_some() {
            return (id, an);
        }
    }
    (None, None)
}

#[allow(clippy::too_many_arguments)]
fn kinit_inner(
    kdc: &KdcAddr,
    principal: &str,
    password: &[u8],
    service: Option<&str>,
    want_spake: bool,
    armor_ccache: Option<&Path>,
    pkinit_identity: Option<&Path>,
    pkinit_anchors: Option<&Path>,
    enterprise: bool,
) -> Result<(KinitResult, FileCcache), Box<dyn std::error::Error + Send + Sync>> {
    let (cname, realm_s) = parse_principal_ex(principal, enterprise)?;
    let resolved = resolve_kdc(&realm_s, kdc);
    let armor = match armor_ccache {
        Some(p) => Some(load_fast_armor(p)?),
        None => None,
    };
    let (conf_id, conf_an) = if pkinit_identity.is_none() || pkinit_anchors.is_none() {
        pkinit_from_conf(&realm_s)
    } else {
        (None, None)
    };
    let id_path = pkinit_identity.map(Path::to_path_buf).or(conf_id);
    let an_path = pkinit_anchors.map(Path::to_path_buf).or(conf_an);
    let pkinit = match (id_path.as_deref(), an_path.as_deref()) {
        (Some(i), Some(a)) => Some(load_pkinit(i, a)?),
        (Some(_), None) | (None, Some(_)) => {
            return Err("pkinit requires identity and anchors".into());
        }
        (None, None) => None,
    };
    let as_out = as_exchange(&AsRequest {
        cname,
        realm: &realm_s,
        password,
        kdc: &resolved,
        want_spake,
        fast_armor: armor.as_ref(),
        pkinit: pkinit.as_ref(),
        canonicalize: enterprise,
        sname: None,
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
    let cache = FileCcache::new((as_out.crealm.clone(), as_out.cname.clone()), creds);
    if let Some(e) = tgs_err {
        tracing::error!(
            event = "client.tgs",
            component = "krb5-client",
            outcome = "error",
            error = e.as_str(),
        );
        return Err(e.into());
    }
    Ok((KinitResult { as_out, tgs_out }, cache))
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
