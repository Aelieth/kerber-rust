//! MIT-compatible kadmind (GSS-RPC on TCP 749).
//!
//! Usage: `krb5-kadmind [--test-realm] [host:port]`
//!
//! Shares `KRB5_KDC_DB` / `KRB5_KDC_STASH` with `krb5-kdc`. `--test-realm`
//! bootstraps KERBER.TEST including `kadmin/admin` and `kadmin/changepw`.
//! TCP 749 is kadm5; UDP 464 is RFC 3244 kpasswd.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::Duration;

use krb5_admin::{serve_kadm5_conn, serve_kpasswd_tcp, serve_kpasswd_udp};
use krb5_crypto::ProtocolKey;
use krb5_kdc::{
    Acl, Error, PrincipalStore, acl_for_store, bootstrap_documented, default_acl_path,
    documented_changepw, documented_kadmin, documented_kiprop, open_store,
    shared_dump as shared_store,
};
use krb5_protocol::ReplayCache;

fn main() {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "krb5_admin=info,krb5_kdc=info".into()),
        )
        .try_init();

    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let test_realm = args.iter().any(|a| a == "--test-realm");
    args.retain(|a| a != "--test-realm");

    let kdc_conf = load_kdc_conf();
    let (db, stash) = db_and_stash(kdc_conf.as_ref());
    let mut store = if test_realm {
        bootstrap_documented()
            .unwrap_or_else(|e| {
                eprintln!("krb5-kadmind: bootstrap: {e}");
                std::process::exit(1);
            })
            .0
    } else {
        let lib = kdc_conf.as_ref().and_then(|c| c.db_library.as_deref());
        open_store(lib, &db, &stash).unwrap_or_else(|e| {
            eprintln!("krb5-kadmind: load: {e}");
            std::process::exit(1);
        })
    };
    let acl = load_acl(kdc_conf.as_ref(), store.realm(), &db, &stash);
    if let Some(conf) = &kdc_conf
        && let Err(e) = store.apply_kdc_conf(conf)
    {
        eprintln!("krb5-kadmind: kdc.conf: {e}");
        std::process::exit(1);
    }
    if let Some(c) = krb5_config::load_krb5_conf() {
        store.set_capaths(c.capaths.clone());
        store.apply_libdefaults(&c);
    }

    let realm = store.realm().to_owned();
    let changepw = documented_changepw();
    if acceptor_keys(&store).is_empty() {
        eprintln!("krb5-kadmind: no kadmin/admin keys");
        std::process::exit(1);
    }
    let cpw_key = store
        .get_name(&changepw)
        .and_then(|p| p.best_key())
        .map(|k| k.key.clone());
    match &store.persist_paths {
        Some((db, stash)) => println!("persist {} {}", db.display(), stash.display()),
        None => eprintln!("krb5-kadmind: no persist_paths (mutations stay in memory)"),
    }
    let shared = shared_store(store);
    let bind = args
        .first()
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:749".into());
    let listener = TcpListener::bind(&bind).unwrap_or_else(|e| {
        eprintln!("krb5-kadmind: bind {bind}: {e}");
        std::process::exit(1);
    });
    listener.set_nonblocking(true).ok();
    println!("listening {bind}");

    let kpasswd_bind =
        std::env::var("KRB5_KPASSWD_BIND").unwrap_or_else(|_| "127.0.0.1:464".into());
    if let Some(cpw_key) = cpw_key {
        let mut udp_ok = false;
        let mut tcp_ok = false;
        match UdpSocket::bind(&kpasswd_bind) {
            Ok(sock) => {
                let store = Arc::clone(&shared);
                let acl_cpw = acl.clone();
                let key = cpw_key.clone();
                let stop = Arc::new(AtomicBool::new(false));
                thread::spawn(move || {
                    let _ = serve_kpasswd_udp(store, acl_cpw, key, sock, stop);
                });
                udp_ok = true;
            }
            Err(e) => eprintln!("krb5-kadmind: kpasswd udp {kpasswd_bind}: {e}"),
        }
        match TcpListener::bind(&kpasswd_bind) {
            Ok(listener) => {
                let store = Arc::clone(&shared);
                let acl_cpw = acl.clone();
                let stop = Arc::new(AtomicBool::new(false));
                thread::spawn(move || {
                    let _ = serve_kpasswd_tcp(store, acl_cpw, cpw_key, listener, stop);
                });
                tcp_ok = true;
            }
            Err(e) => eprintln!("krb5-kadmind: kpasswd tcp {kpasswd_bind}: {e}"),
        }
        if udp_ok || tcp_ok {
            println!("kpasswd {kpasswd_bind}");
        }
    } else {
        eprintln!("krb5-kadmind: no kadmin/changepw keys (RFC 3244 not listening)");
    }
    let rcache = ReplayCache::new();
    loop {
        let accepted = listener.accept();
        match accepted {
            Ok((stream, _)) => {
                let store = Arc::clone(&shared);
                let keys = {
                    let g = store
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    acceptor_keys(&g)
                };
                let acl = acl.clone();
                let realm = realm.clone();
                let rcache = rcache.clone();
                thread::spawn(move || {
                    let _ = serve_kadm5_conn(store, acl, keys, realm, rcache, stream);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                eprintln!("krb5-kadmind: accept: {e}");
                break;
            }
        }
    }
}

fn acceptor_keys(store: &PrincipalStore) -> Vec<ProtocolKey> {
    let mut keys = Vec::new();
    for name in [
        documented_kadmin(),
        documented_changepw(),
        documented_kiprop(),
    ] {
        if let Some(p) = store.get_name(&name) {
            keys.extend(p.keys.iter().map(|k| k.key.clone()));
        }
    }
    keys
}

fn load_kdc_conf() -> Option<krb5_config::KdcConf> {
    let path = krb5_config::kdc_conf_path()?;
    match krb5_config::KdcConf::load_file(&path) {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("krb5-kadmind: kdc.conf: {e}");
            std::process::exit(1);
        }
    }
}

fn db_and_stash(conf: Option<&krb5_config::KdcConf>) -> (PathBuf, PathBuf) {
    let db = std::env::var("KRB5_KDC_DB")
        .ok()
        .map(PathBuf::from)
        .or_else(|| conf.and_then(|c| c.database_name.clone()))
        .unwrap_or_else(|| PathBuf::from("/var/lib/krb5kdc/principal"));
    let stash = std::env::var("KRB5_KDC_STASH")
        .ok()
        .map(PathBuf::from)
        .or_else(|| conf.and_then(|c| c.key_stash_file.clone()))
        .unwrap_or_else(|| PathBuf::from("/var/lib/krb5kdc/stash"));
    (db, stash)
}

fn kdc_dir(db: &Path, stash: &Path) -> PathBuf {
    stash
        .parent()
        .or_else(|| db.parent())
        .unwrap_or_else(|| Path::new("/var/lib/krb5kdc"))
        .to_path_buf()
}

fn load_acl(conf: Option<&krb5_config::KdcConf>, realm: &str, db: &Path, stash: &Path) -> Acl {
    let spec = if let Ok(p) = std::env::var("KRB5_ACL_FILE") {
        if p.is_empty() {
            None
        } else {
            Some(PathBuf::from(p))
        }
    } else if let Some(p) = conf.and_then(|c| c.acl_file.clone()) {
        if p.as_os_str().is_empty() {
            None
        } else {
            Some(p)
        }
    } else {
        Some(default_acl_path(&kdc_dir(db, stash)))
    };
    acl_for_store(realm, spec.as_deref()).unwrap_or_else(|e| {
        let msg = match e {
            Error::AclParse(s) => s,
            other => other.to_string(),
        };
        eprintln!("krb5-kadmind: {msg}");
        std::process::exit(1);
    })
}
