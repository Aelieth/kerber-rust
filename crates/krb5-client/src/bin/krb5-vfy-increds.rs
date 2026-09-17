//! MIT `t_vfy_increds`: verify the first non-config ccache cred against a keytab.
//!
//! Usage: `krb5-vfy-increds [-n] [server]`

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use krb5_client::load_ccache;
use krb5_config::{env_ktname, load_krb5_conf, resolve_ccspec};
use krb5_protocol::{
    KdcAddr, Keytab, parse_principal, realm, verify_init_creds, verify_init_creds_nofail,
};
use krb5_types::PrincipalName;

fn main() {
    if let Err(e) = run() {
        eprintln!("t_vfy_increds: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut opt_nofail = None;
    if args.first().is_some_and(|a| a == "-n") {
        opt_nofail = Some(true);
        args.remove(0);
    }
    let spec = resolve_ccspec(None)?;
    let cc = load_ccache(&spec).map_err(|e| e.to_string())?;
    let cred = cc
        .list()
        .into_iter()
        .next()
        .cloned()
        .ok_or_else(|| "ccache has no credentials".to_string())?;
    let conf = load_krb5_conf();
    let nofail = verify_init_creds_nofail(
        opt_nofail,
        conf.as_ref().is_some_and(|c| c.verify_ap_req_nofail),
    );
    let server = if let Some(raw) = args.first() {
        let (name, realm_s) = if raw.contains('@') {
            parse_principal(raw)?
        } else {
            let realm_s = conf
                .as_ref()
                .and_then(|c| c.default_realm.clone())
                .ok_or_else(|| "principal must be name@REALM".to_string())?;
            let (comps, _) = krb5_types::parse_name(raw, "").map_err(|e| e.to_string())?;
            (
                PrincipalName::try_new(krb5_types::infer_name_type(&comps), comps)
                    .map_err(|e| e.to_string())?,
                realm_s,
            )
        };
        Some((realm(&realm_s), name))
    } else {
        None
    };
    let kt_path = env_ktname().unwrap_or_else(|| PathBuf::from("/etc/krb5.keytab"));
    let keytab = fs::read(&kt_path).ok().and_then(|b| Keytab::parse(&b).ok());
    let crealm = String::from_utf8_lossy(cred.client.0.as_bytes()).into_owned();
    let addr = krb5_config::discover_kdc(&crealm).map_or_else(
        || KdcAddr::new("127.0.0.1"),
        |ep| KdcAddr {
            host: ep.host,
            port: ep.port,
        },
    );
    verify_init_creds(
        &cred,
        server.as_ref().map(|(r, n)| (r, n)),
        keytab.as_ref(),
        &addr,
        nofail,
    )
    .map_err(|e| e.to_string())
}
