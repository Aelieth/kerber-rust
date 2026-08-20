//! Launch the KDC.
//!
//! Usage: `krb5-kdc [--test-realm] [host:port]`
//!
//! `--test-realm` bootstraps the documented KERBER.TEST principals. Without
//! it the daemon loads `KRB5_KDC_DB` + `KRB5_KDC_STASH` (see kdc.conf).

use std::sync::Arc;

use krb5_kdc::{
    bind_preferred, bootstrap_documented, drop_privileges, load_store, serve, BIND_CANDIDATES,
};

fn main() {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "krb5_kdc=info,krb5_crypto=info,krb5_asn1=info".into()),
        )
        .try_init();

    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let test_realm = args.iter().any(|a| a == "--test-realm");
    args.retain(|a| a != "--test-realm");
    let mut export_pkinit: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--export-pkinit" {
            export_pkinit = args.get(i + 1).cloned();
            args.remove(i);
            if i < args.len() {
                args.remove(i);
            }
            continue;
        }
        i += 1;
    }

    let store = if test_realm {
        bootstrap_documented()
            .expect("bootstrap documented realm")
            .0
    } else if let (Ok(db), Ok(stash)) = (
        std::env::var("KRB5_KDC_DB"),
        std::env::var("KRB5_KDC_STASH"),
    ) {
        load_store(std::path::Path::new(&db), std::path::Path::new(&stash)).unwrap_or_else(|e| {
            eprintln!("krb5-kdc: load store: {e}");
            std::process::exit(1);
        })
    } else {
        eprintln!("krb5-kdc: pass --test-realm or set KRB5_KDC_DB and KRB5_KDC_STASH");
        std::process::exit(2);
    };
    if let Some(dir) = export_pkinit.as_ref() {
        let _ = std::fs::create_dir_all(dir);
        if let Some(pem) = store.pkinit_anchor_pem() {
            let _ = std::fs::write(format!("{dir}/ca.pem"), pem);
            println!("pkinit-ca {dir}/ca.pem");
        }
        if let Some(pem) = store.pkinit_user_pem("user@KERBER.TEST") {
            let _ = std::fs::write(format!("{dir}/user.pem"), pem);
            println!("pkinit-user {dir}/user.pem");
        }
    }
    let store = Arc::new(store);

    let pinned: Option<String> = args
        .into_iter()
        .next()
        .or_else(|| std::env::var("KRB5_KDC_BIND").ok());
    let owned: Vec<String>;
    let candidates: Vec<&str> = if let Some(bind) = pinned {
        owned = vec![bind];
        owned.iter().map(String::as_str).collect()
    } else {
        BIND_CANDIDATES.to_vec()
    };

    let (addr, udp, tcp) = bind_preferred(&candidates).unwrap_or_else(|e| {
        eprintln!("krb5-kdc: bind failed: {e}");
        std::process::exit(1);
    });
    match drop_privileges() {
        Ok(true) => eprintln!("krb5-kdc: dropped privileges"),
        Ok(false) => {}
        Err(e) => {
            eprintln!("krb5-kdc: privilege drop: {e}");
            std::process::exit(1);
        }
    }
    println!("listening {addr}");
    serve(store, udp, tcp).expect("serve");
}
