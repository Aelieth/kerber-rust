#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::disallowed_methods,
    reason = "a program reads its profile and environment when it starts"
)]

use std::fs;
use std::path::PathBuf;

use krb5_client::load_ccache;
use krb5_config::{ClientContext, env_ktname, resolve_ccspec};
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
    let ctx = ClientContext::from_env().map_err(|e| e.to_string())?;
    let spec = resolve_ccspec(&ctx, None).map_err(|e| e.to_string())?;
    let cc = load_ccache(&ctx, &spec).map_err(|e| e.to_string())?;
    let cred = cc
        .list()
        .into_iter()
        .next()
        .cloned()
        .ok_or_else(|| "ccache has no credentials".to_string())?;
    let conf = &ctx.profile;
    let server = if let Some(raw) = args.first() {
        let (name, realm_s) = if raw.contains('@') {
            parse_principal(raw)?
        } else {
            let realm_s = conf
                .default_realm
                .clone()
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
    let nofail = verify_init_creds_nofail(opt_nofail, conf.verify_ap_req_nofail_for(&crealm));
    let found = match conf.kdcs_for(&crealm) {
        Ok(list) => list,
        Err(e @ krb5_config::Error::InvalidArgument) => return Err(e.to_string()),
        Err(_) => Vec::new(),
    };
    let addr = found.first().map_or_else(
        || KdcAddr::new("127.0.0.1"),
        |ep| KdcAddr {
            host: ep.host.clone(),
            port: ep.port,
        },
    );
    if !found.is_empty() {
        krb5_config::hand_kdcs(&crealm, found);
    }
    verify_init_creds(
        conf,
        &cred,
        server.as_ref().map(|(r, n)| (r, n)),
        keytab.as_ref(),
        &addr,
        nofail,
    )
    .map_err(|e| e.to_string())
}
