//! MIT-wire kpropd (TCP 754) wrapping dump version 7.
//!
//! Usage: `krb5-kpropd [host:port]`
//!
//! `KRB5_KPROP_KEYTAB` or host keys from `KRB5_KDC_DB`/`KRB5_KDC_STASH`
//! authenticate `sendauth`. The dump body is loaded with
//! `KRB5_MASTER_PASSWORD` and saved to the replica db.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use krb5_admin::{kpropd_handle_conn, KPROP_PORT};
use krb5_crypto::ProtocolKey;
use krb5_kdc::{documented_host, load_store};
use krb5_protocol::Keytab;

fn main() {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "krb5_admin=info,krb5_kdc=info".into()),
        )
        .try_init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let bind = args
        .first()
        .cloned()
        .unwrap_or_else(|| format!("127.0.0.1:{KPROP_PORT}"));
    let master = std::env::var("KRB5_MASTER_PASSWORD").unwrap_or_else(|_| {
        eprintln!("krb5-kpropd: set KRB5_MASTER_PASSWORD");
        std::process::exit(2);
    });
    let db = PathBuf::from(
        std::env::var("KRB5_KDC_DB").unwrap_or_else(|_| "/var/lib/krb5kdc/principal".into()),
    );
    let stash = PathBuf::from(
        std::env::var("KRB5_KDC_STASH").unwrap_or_else(|_| "/var/lib/krb5kdc/stash".into()),
    );
    let host_keys = load_host_keys();
    if host_keys.is_empty() {
        eprintln!("krb5-kpropd: no host keys (set KRB5_KPROP_KEYTAB or persist a host principal)");
        std::process::exit(1);
    }
    let listener = TcpListener::bind(&bind).unwrap_or_else(|e| {
        eprintln!("krb5-kpropd: bind {bind}: {e}");
        std::process::exit(1);
    });
    listener.set_nonblocking(true).ok();
    println!("listening {bind}");
    let stop = Arc::new(AtomicBool::new(false));
    let realm = kpropd_realm();
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let keys = host_keys.clone();
                let realm = realm.clone();
                let master = master.clone();
                let db = db.clone();
                let stash = stash.clone();
                thread::spawn(move || {
                    match kpropd_handle_conn(
                        &mut stream,
                        &keys,
                        None,
                        Some(realm.as_str()),
                        master.as_bytes(),
                        &db,
                        &stash,
                    ) {
                        Ok(_) => println!("kprop ok"),
                        Err(e) => eprintln!("krb5-kpropd: {e}"),
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                eprintln!("krb5-kpropd: accept: {e}");
                break;
            }
        }
    }
}

fn kpropd_realm() -> String {
    std::env::var("KRB5_KDC_REALM")
        .or_else(|_| std::env::var("KRB5_TEST_REALM"))
        .unwrap_or_else(|_| krb5_kdc::TEST_REALM.to_owned())
}

fn load_host_keys() -> Vec<ProtocolKey> {
    if let Ok(path) = std::env::var("KRB5_KPROP_KEYTAB") {
        match std::fs::read(&path).and_then(|b| Keytab::parse(&b)) {
            Ok(kt) => {
                return kt.entries.into_iter().map(|e| e.key).collect();
            }
            Err(e) => eprintln!("krb5-kpropd: keytab {path}: {e}"),
        }
    }
    let db = std::env::var("KRB5_KDC_DB").ok();
    let stash = std::env::var("KRB5_KDC_STASH").ok();
    if let (Some(db), Some(stash)) = (db, stash) {
        if let Ok(store) = load_store(std::path::Path::new(&db), std::path::Path::new(&stash)) {
            if store.realm() == krb5_kdc::TEST_REALM {
                let host = documented_host();
                if let Some(p) = store.get_name(&host) {
                    return p.keys.iter().map(|k| k.key.clone()).collect();
                }
            }
        }
    }
    Vec::new()
}
