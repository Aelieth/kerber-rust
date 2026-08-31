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
    AsOutcome, AsRequest, AsTicketOpts, FastArmor, KdcAddr, PkinitClient, TgsOutcome, as_exchange,
    as_exchange_with_keys, dir_cache_path, dir_cache_path_for_store, memory_destroy,
    memory_retrieve, memory_store, parse_principal_ex, tgs_exchange, tgs_renew,
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

pub mod cli;

/// Flags for [`kinit_with`].
#[derive(Clone, Debug, Default)]
pub struct KinitParams<'a> {
    /// Optional TGS service (`-S` or positional).
    pub service: Option<&'a str>,
    /// PA-SPAKE.
    pub want_spake: bool,
    /// FAST armor ccache.
    pub armor_ccache: Option<&'a Path>,
    /// PKINIT identity PEM.
    pub pkinit_identity: Option<&'a Path>,
    /// PKINIT anchors PEM.
    pub pkinit_anchors: Option<&'a Path>,
    /// NT-ENTERPRISE.
    pub enterprise: bool,
    /// Keytab (`-k` / `-t`).
    pub keytab: Option<&'a Path>,
    /// AS ticket options.
    pub ticket: AsTicketOpts,
    /// `kinit -R`.
    pub renew: bool,
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
    let spec = CcSpec::File(ccache_path.as_ref().to_path_buf());
    let params = KinitParams {
        service,
        want_spake,
        armor_ccache,
        pkinit_identity,
        pkinit_anchors,
        enterprise,
        ..KinitParams::default()
    };
    kinit_with(kdc, principal, password, &spec, params)
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
    kinit_with(
        kdc,
        principal,
        password,
        spec,
        KinitParams {
            service,
            want_spake,
            armor_ccache,
            pkinit_identity,
            pkinit_anchors,
            enterprise,
            ..KinitParams::default()
        },
    )
}

/// [`kinit_to_spec`] with keytab, renewal, and ticket flags.
///
/// # Errors
///
/// Protocol or I/O errors. The password buffer is zeroized before return.
pub fn kinit_with(
    kdc: &KdcAddr,
    principal: &str,
    password: &mut [u8],
    spec: &CcSpec,
    params: KinitParams<'_>,
) -> Result<KinitResult, Box<dyn std::error::Error + Send + Sync>> {
    let built = kinit_inner(kdc, principal, password, spec, params);
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
            let p = dir_cache_path_for_store(r)?;
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

fn conf_default_realm() -> Option<String> {
    krb5_config::krb5_conf_paths().into_iter().find_map(|p| {
        krb5_config::Krb5Conf::load_file(&p)
            .ok()
            .and_then(|c| c.default_realm)
    })
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

fn kinit_inner(
    kdc: &KdcAddr,
    principal: &str,
    password: &[u8],
    spec: &CcSpec,
    params: KinitParams<'_>,
) -> Result<(KinitResult, FileCcache), Box<dyn std::error::Error + Send + Sync>> {
    let (cname, mut realm_s) = parse_principal_ex(principal, params.enterprise)?;
    if realm_s.is_empty() {
        realm_s = conf_default_realm().ok_or("Cannot find KDC for requested realm")?;
    }
    let resolved = resolve_kdc(&realm_s, kdc);
    if params.renew {
        return renew_inner(&resolved, spec);
    }
    let armor = match params.armor_ccache {
        Some(p) => Some(load_fast_armor(p)?),
        None => None,
    };
    let (conf_id, conf_an) = if params.pkinit_identity.is_none() || params.pkinit_anchors.is_none()
    {
        pkinit_from_conf(&realm_s)
    } else {
        (None, None)
    };
    let id_path = params.pkinit_identity.map(Path::to_path_buf).or(conf_id);
    let an_path = params.pkinit_anchors.map(Path::to_path_buf).or(conf_an);
    let pkinit = match (id_path.as_deref(), an_path.as_deref()) {
        (Some(i), Some(a)) => Some(load_pkinit(i, a)?),
        (Some(_), None) | (None, Some(_)) => {
            return Err("pkinit requires identity and anchors".into());
        }
        (None, None) => None,
    };
    let conf_e = krb5_protocol::conf_etypes(false);
    let req = AsRequest {
        cname: cname.clone(),
        realm: &realm_s,
        password,
        kdc: &resolved,
        want_spake: params.want_spake,
        fast_armor: armor.as_ref(),
        pkinit: pkinit.as_ref(),
        canonicalize: params.enterprise,
        sname: None,
        etypes: Some(&conf_e),
        ticket: params.ticket,
    };
    let as_out = if let Some(ktpath) = params.keytab {
        let kt = Keytab::parse(&std::fs::read(ktpath)?)?;
        let keys: Vec<_> = kt
            .entries
            .iter()
            .filter(|e| e.name == cname)
            .map(|e| e.key.clone())
            .collect();
        if keys.is_empty() {
            return Err("keytab has no matching principal".into());
        }
        as_exchange_with_keys(&req, &keys)?
    } else {
        as_exchange(&req)?
    };
    let mut creds = vec![tgt_cred(
        &as_out.crealm,
        &as_out.cname,
        &as_out.ticket,
        &as_out.session_key,
        &as_out.enc_part,
    )?];
    let mut tgs_out = None;
    let mut tgs_err: Option<String> = None;
    if let Some(svc) = params.service {
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

fn renew_inner(
    kdc: &KdcAddr,
    spec: &CcSpec,
) -> Result<(KinitResult, FileCcache), Box<dyn std::error::Error + Send + Sync>> {
    let mut cc = load_ccache(spec)?;
    let cred = cc
        .list()
        .into_iter()
        .find(|c| c.server.1.components_joined().starts_with("krbtgt/"))
        .ok_or("ccache has no TGT")?
        .clone();
    let tgt = outcome_from_cred(&cred)?;
    let tgs = tgs_renew(kdc, &tgt)?;
    let new_cred = tgt_cred(
        &tgt.crealm,
        &tgt.cname,
        &tgs.ticket,
        &tgs.session_key,
        &tgs.enc_part,
    )?;
    for c in &mut cc.creds {
        if c.server.1.components_joined().starts_with("krbtgt/") && !c.is_config() {
            *c = new_cred.clone();
            break;
        }
    }
    Ok((
        KinitResult {
            as_out: tgt,
            tgs_out: Some(tgs),
        },
        cc,
    ))
}

fn outcome_from_cred(
    cred: &CcacheCred,
) -> Result<AsOutcome, Box<dyn std::error::Error + Send + Sync>> {
    let session = cred.session_key()?;
    let ticket: Ticket = decode(&cred.ticket)?;
    Ok(AsOutcome {
        ticket,
        enc_part: krb5_types::EncKdcRepPart {
            key: krb5_types::EncryptionKey {
                keytype: session.etype().to_iana(),
                keyvalue: session.as_bytes().to_vec().into(),
            },
            last_req: Vec::new(),
            nonce: 0,
            key_expiration: None,
            flags: krb5_types::TicketFlags::from_u32(cred.ticket_flags),
            authtime: krb5_types::KerberosTime::from_unix_seconds(cred.authtime),
            starttime: Some(krb5_types::KerberosTime::from_unix_seconds(cred.starttime)),
            endtime: krb5_types::KerberosTime::from_unix_seconds(cred.endtime),
            renew_till: (cred.renew_till > 0)
                .then(|| krb5_types::KerberosTime::from_unix_seconds(cred.renew_till)),
            srealm: cred.server.0.clone(),
            sname: cred.server.1.clone(),
            caddr: None,
            encrypted_pa_data: None,
        },
        client_key: session.clone(),
        session_key: session,
        cname: cred.client.1.clone(),
        crealm: cred.client.0.clone(),
    })
}

/// Local IPv4 address for `kinit -a` (MIT ADDRTYPE_INET = 2).
#[must_use]
pub fn local_host_addresses() -> Option<krb5_types::HostAddresses> {
    use std::net::{SocketAddr, UdpSocket};
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    let SocketAddr::V4(v4) = sock.local_addr().ok()? else {
        return None;
    };
    Some(vec![krb5_types::HostAddress {
        addr_type: 2,
        address: v4.ip().octets().to_vec().into(),
    }])
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
