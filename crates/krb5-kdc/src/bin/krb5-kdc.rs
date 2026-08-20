//! Launch the documented test-realm KDC on UDP/TCP 88 (fallback 8888).
//!
//! Usage: `krb5-kdc [host:port]`
//!
//! Realm `KERBER.TEST`, principals `user@KERBER.TEST` / `userpassword`,
//! `admin@KERBER.TEST` (ACL `*`), `host/testhost.kerber.test`.

use std::sync::Arc;

use krb5_kdc::{bind_preferred, bootstrap_documented, serve, BIND_CANDIDATES};

fn main() {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "krb5_kdc=info,krb5_crypto=info,krb5_asn1=info".into()),
        )
        .try_init();

    let (store, _acl) = bootstrap_documented().expect("bootstrap documented realm");
    let store = Arc::new(store);

    let pinned: Option<String> = std::env::args()
        .nth(1)
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
    println!("listening {addr}");
    serve(store, udp, tcp).expect("serve");
}
