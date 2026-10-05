//! MIT-wire kprop sender (TCP 754) wrapping dump version 7.
//!
//! Usage: `krb5-kprop [-P port] [-s keytab] [-n host-instance] replica`
//!
//! Loads the database and stash [`krb5_config::KdcPaths`] resolves, issues a `host/<instance>`
//! ticket from that store, and calls [`krb5_admin::kprop_send_store`]. The dump's keys are
//! wrapped under the stash's master key, as MIT's kprop sends a dump of the database that stash
//! opens; with the `test-hooks` feature, `KRB5_MASTER_PASSWORD` names it instead when set.
//!
//! `KRB5_KPROP_KEYTAB` names the client keytab when `-s` does not: a kerber-rust extension
//! (MIT's kprop takes `-s` alone).

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpStream;
use std::path::{Path, PathBuf};

use krb5_admin::{KPROP_PORT, kprop_send_store, kprop_send_store_iprop};
use krb5_crypto::ProtocolKey;
use krb5_kdc::{PrincipalStore, issue_as, issue_tgs, load_store};
use krb5_log::klog::JsonLog;
use krb5_protocol::Keytab;
use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};
use krb5_types::PrincipalName;

fn main() {
    // The JSON log only where the KDC profile's `[logging] json` names a destination (MIT has
    // none).
    if let Some(json) = krb5_config::LogSpecs::load_json().and_then(|s| JsonLog::open("kprop", &s))
    {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_writer(json.make_writer())
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "krb5_admin=info,krb5_kdc=info".into()),
            )
            .try_init();
    }

    let mut port = KPROP_PORT;
    let mut keytab: Option<PathBuf> = std::env::var("KRB5_KPROP_KEYTAB").ok().map(PathBuf::from);
    let mut instance: Option<String> = None;
    let mut replica: Option<String> = None;
    let mut iprop = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-i" => iprop = true,
            "-P" => {
                let p = args.next().unwrap_or_else(|| need_arg("-P"));
                port = p.parse().unwrap_or_else(|_| {
                    eprintln!("krb5-kprop: bad port {p}");
                    std::process::exit(2);
                });
            }
            "-s" => {
                keytab = Some(PathBuf::from(args.next().unwrap_or_else(|| need_arg("-s"))));
            }
            "-n" => {
                instance = Some(args.next().unwrap_or_else(|| need_arg("-n")));
            }
            flag if flag.starts_with('-') => {
                eprintln!("krb5-kprop: unknown flag {flag}");
                usage();
            }
            other => replica = Some(other.to_owned()),
        }
    }
    let Some(replica) = replica else {
        usage();
    };
    let paths = krb5_config::KdcPaths::resolve(None).unwrap_or_else(|e| {
        // MIT `parse_args` (`kprop/kprop.c:154-159`): no realm prints only this context (MIT
        // passes errno, 0, to com_err), exit 1.
        if matches!(e, krb5_config::Error::NoDefaultRealm) {
            eprintln!("krb5-kprop: while getting default realm");
        } else {
            eprintln!("krb5-kprop: {e}");
        }
        std::process::exit(1);
    });
    // The database is judged first, then the stash, which opens it and wraps the dump: one that
    // cannot be read is named before anything is sent.
    // MIT `open_db_and_mkey` (`kadmin/dbutil/kdb5_util.c:378-401`): the dump kprop sends opens the database, and reads its master entry, before the master key is fetched.
    if let Err(e) = krb5_kdc::check_database(&paths.database_name) {
        eprintln!("krb5-kprop: load store: {e}");
        std::process::exit(1);
    }
    if let Err(e) = std::fs::File::open(&paths.key_stash_file) {
        eprintln!("krb5-kprop: stash {}: {e}", paths.key_stash_file.display());
        std::process::exit(1);
    }
    let store = load_store(&paths.database_name, &paths.key_stash_file).unwrap_or_else(|e| {
        eprintln!("krb5-kprop: load store: {e}");
        std::process::exit(1);
    });
    let master =
        master_key(&store, &paths.database_name, &paths.key_stash_file).unwrap_or_else(|e| {
            eprintln!("krb5-kprop: {e}");
            std::process::exit(1);
        });
    let realm = store.realm().to_owned();
    let host_inst = instance.unwrap_or_else(|| replica.clone());
    let server = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", host_inst.as_str()]);
    let client = client_name(keytab.as_deref(), &server);
    let Some(princ) = store.get_name(&client) else {
        eprintln!("krb5-kprop: missing client {}", client.components_joined());
        std::process::exit(1);
    };
    let client_key = princ
        .best_key()
        .unwrap_or_else(|| {
            eprintln!("krb5-kprop: client has no key");
            std::process::exit(1);
        })
        .key
        .clone();
    let pa = pa_enc_timestamp(&client_key).unwrap_or_else(|e| {
        eprintln!("krb5-kprop: PA-ENC-TS: {e}");
        std::process::exit(1);
    });
    let as_req = as_req(client.clone(), &realm, 1, Some(vec![pa])).unwrap_or_else(|e| {
        eprintln!("krb5-kprop: AS-REQ: {e}");
        std::process::exit(1);
    });
    let as_out = issue_as(&store, &as_req).unwrap_or_else(|e| {
        eprintln!("krb5-kprop: issue AS: {e}");
        std::process::exit(1);
    });
    let tgs = tgs_req(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &realm,
        &client,
        server,
        &realm,
        2,
    )
    .unwrap_or_else(|e| {
        eprintln!("krb5-kprop: TGS-REQ: {e}");
        std::process::exit(1);
    });
    let tgs_out = issue_tgs(&store, &tgs).unwrap_or_else(|e| {
        eprintln!("krb5-kprop: issue TGS: {e}");
        std::process::exit(1);
    });
    let addr = format!("{replica}:{port}");
    let mut stream = TcpStream::connect(&addr).unwrap_or_else(|e| {
        eprintln!("krb5-kprop: connect {addr}: {e}");
        std::process::exit(1);
    });
    let send = if iprop {
        kprop_send_store_iprop
    } else {
        kprop_send_store
    };
    send(
        &mut stream,
        &store,
        &master,
        tgs_out.rep.0.ticket,
        &tgs_out.session_key,
        &krb5_types::ascii(&realm),
        &client,
    )
    .unwrap_or_else(|e| {
        eprintln!("krb5-kprop: send: {e}");
        std::process::exit(1);
    });
    println!("kprop ok {addr}");
}

/// The key the dump's keys are wrapped under: the stash's (it opened `store`), or with the
/// `test-hooks` feature one derived from `KRB5_MASTER_PASSWORD` with the type of the store's
/// `K/M` key.
fn master_key(store: &PrincipalStore, db: &Path, stash: &Path) -> Result<ProtocolKey, String> {
    #[cfg(feature = "test-hooks")]
    let hooked = std::env::var("KRB5_MASTER_PASSWORD")
        .ok()
        .map(zeroize::Zeroizing::new);
    #[cfg(not(feature = "test-hooks"))]
    let hooked: Option<zeroize::Zeroizing<String>> = None;
    match hooked {
        Some(pw) => {
            let etype = store
                .get(&format!("K/M@{}", store.realm()))
                .and_then(|km| km.keys.first())
                .map_or_else(krb5_kdc::default_master_etype, |k| k.etype);
            krb5_kdc::master_key_from_password(store.realm(), pw.as_bytes(), etype)
                .map_err(|e| e.to_string())
        }
        None => {
            krb5_kdc::read_stash(stash, db).map_err(|e| format!("stash {}: {e}", stash.display()))
        }
    }
}

fn client_name(keytab: Option<&std::path::Path>, server: &PrincipalName) -> PrincipalName {
    if let Some(path) = keytab {
        match std::fs::read(path)
            .and_then(|b| Keytab::parse(&b).map_err(|e| std::io::Error::other(e.to_string())))
        {
            Ok(kt) => {
                if let Some(e) = kt.entries.first() {
                    return e.name.clone();
                }
            }
            Err(e) => eprintln!("krb5-kprop: keytab {}: {e}", path.display()),
        }
    }
    server.clone()
}

fn need_arg(flag: &str) -> String {
    eprintln!("krb5-kprop: {flag} needs a value");
    usage();
}

fn usage() -> ! {
    eprintln!("usage: krb5-kprop [-i] [-P port] [-s keytab] [-n host-instance] replica");
    std::process::exit(2);
}
