//! MIT-compatible kadmind (GSS-RPC on TCP 749).
//!
//! Usage: `krb5-kadmind [--test-realm] [host:port]`
//!
//! Shares `KRB5_KDC_DB` / `KRB5_KDC_STASH` with `krb5-kdc`. `--test-realm`
//! bootstraps KERBER.TEST including `kadmin/admin`.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use krb5_admin::serve_kadm5_conn;
use krb5_kdc::{bootstrap_documented, documented_kadmin, load_store, shared_store, Acl};

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

    let (store, acl) = if test_realm {
        bootstrap_documented().unwrap_or_else(|e| {
            eprintln!("krb5-kadmind: bootstrap: {e}");
            std::process::exit(1);
        })
    } else {
        let db =
            std::env::var("KRB5_KDC_DB").unwrap_or_else(|_| "/var/lib/krb5kdc/principal".into());
        let stash =
            std::env::var("KRB5_KDC_STASH").unwrap_or_else(|_| "/var/lib/krb5kdc/stash".into());
        let store = load_store(std::path::Path::new(&db), std::path::Path::new(&stash))
            .unwrap_or_else(|e| {
                eprintln!("krb5-kadmind: load: {e}");
                std::process::exit(1);
            });
        let acl = Acl::allow_admin(krb5_kdc::documented_admin_id());
        (store, acl)
    };

    let realm = store.realm().to_owned();
    let kadmin = documented_kadmin();
    let keys: Vec<_> = store
        .get_name(&kadmin)
        .map(|p| p.keys.iter().map(|k| k.key.clone()).collect())
        .unwrap_or_default();
    if keys.is_empty() {
        eprintln!("krb5-kadmind: no kadmin/admin keys");
        std::process::exit(1);
    }
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
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let store = Arc::clone(&shared);
                let acl = acl.clone();
                let keys = keys.clone();
                let kadmin = kadmin.clone();
                let realm = realm.clone();
                thread::spawn(move || {
                    let _ = serve_kadm5_conn(store, acl, keys, kadmin, realm, stream);
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
