//! Launch the KDC.
//!
//! Usage: `krb5-kdc [--test-realm] [host:port]`
//!
//! `--test-realm` bootstraps the documented KERBER.TEST principals. Without
//! it the daemon loads `KRB5_KDC_DB`/`KRB5_KDC_STASH` or `database_name` /
//! `key_stash_file` from `kdc.conf`. Ticket policy comes from
//! `KRB5_KDC_PROFILE` / `KRB5_KDC_CONF` / `/etc/krb5kdc/kdc.conf`.
//! Passwords come from `KRB5_TEST_USER_PASSWORD` / `KRB5_TEST_ADMIN_PASSWORD`.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;

use krb5_kdc::{
    bind_preferred, documented_host, drop_privileges, load_store, serve, Acl, PrincipalStore,
    BIND_CANDIDATES, TEST_ADMIN, TEST_REALM, TEST_USER,
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

    let kdc_conf = load_kdc_conf();
    let mut store = if test_realm {
        bootstrap_test_realm()
    } else {
        let (db, stash) = db_and_stash(kdc_conf.as_ref());
        if let (Some(db), Some(stash)) = (db, stash) {
            load_store(&db, &stash).unwrap_or_else(|e| {
                eprintln!("krb5-kdc: load store: {e}");
                std::process::exit(1);
            })
        } else {
            eprintln!(
                "krb5-kdc: pass --test-realm or set KRB5_KDC_DB and KRB5_KDC_STASH (or database_name / key_stash_file in kdc.conf)"
            );
            std::process::exit(2);
        }
    };
    if let Some(conf) = &kdc_conf {
        store.apply_kdc_conf(conf);
    }
    let enable_pkinit =
        export_pkinit.is_some() || std::env::var("KRB5_ENABLE_PKINIT").ok().as_deref() == Some("1");
    if enable_pkinit {
        if let Err(e) = store.enable_pkinit_ca() {
            eprintln!("krb5-kdc: PKINIT CA: {e}");
            std::process::exit(1);
        }
    }
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
    let owned = bind_list(test_realm, pinned, kdc_conf.as_ref());
    let candidates: Vec<&str> = owned.iter().map(String::as_str).collect();

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
    if let Err(e) = serve(store, udp, tcp) {
        eprintln!("krb5-kdc: serve: {e}");
        std::process::exit(1);
    }
}

fn load_kdc_conf() -> Option<krb5_config::KdcConf> {
    let path = krb5_config::kdc_conf_path()?;
    match krb5_config::KdcConf::load_file(&path) {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("krb5-kdc: kdc.conf: {e}");
            std::process::exit(1);
        }
    }
}

fn db_and_stash(conf: Option<&krb5_config::KdcConf>) -> (Option<PathBuf>, Option<PathBuf>) {
    let db = std::env::var("KRB5_KDC_DB")
        .ok()
        .map(PathBuf::from)
        .or_else(|| conf.and_then(|c| c.database_name.clone()));
    let stash = std::env::var("KRB5_KDC_STASH")
        .ok()
        .map(PathBuf::from)
        .or_else(|| conf.and_then(|c| c.key_stash_file.clone()));
    (db, stash)
}

fn bind_list(
    test_realm: bool,
    pinned: Option<String>,
    conf: Option<&krb5_config::KdcConf>,
) -> Vec<String> {
    if let Some(bind) = pinned {
        return vec![bind];
    }
    if !test_realm {
        if let Some(c) = conf {
            if !c.kdc_listen.is_empty() {
                return c.kdc_listen.clone();
            }
        }
    }
    BIND_CANDIDATES.iter().map(|s| (*s).to_owned()).collect()
}

fn bootstrap_test_realm() -> PrincipalStore {
    let user_pw = std::env::var("KRB5_TEST_USER_PASSWORD").unwrap_or_else(|_| {
        eprintln!(
            "krb5-kdc: --test-realm requires KRB5_TEST_USER_PASSWORD (do not compile passwords in)"
        );
        std::process::exit(2);
    });
    let admin_pw = std::env::var("KRB5_TEST_ADMIN_PASSWORD").unwrap_or_else(|_| {
        eprintln!("krb5-kdc: --test-realm requires KRB5_TEST_ADMIN_PASSWORD");
        std::process::exit(2);
    });
    let realm = std::env::var("KRB5_TEST_REALM").unwrap_or_else(|_| TEST_REALM.to_owned());
    let mut store = PrincipalStore::bootstrap(
        &realm,
        TEST_USER,
        user_pw.as_bytes(),
        TEST_ADMIN,
        admin_pw.as_bytes(),
    )
    .unwrap_or_else(|e| {
        eprintln!("krb5-kdc: bootstrap: {e}");
        std::process::exit(1);
    });
    let actor = format!("{TEST_ADMIN}@{realm}");
    let acl = Acl::allow_admin(&actor);
    let host = if realm == TEST_REALM {
        documented_host()
    } else {
        krb5_types::PrincipalName::new(
            krb5_types::PrincipalName::NT_SRV_HST,
            ["host", "svc.other.test"],
        )
    };
    if let Err(e) = store.create_host(&acl, &actor, &host) {
        eprintln!("krb5-kdc: host principal: {e}");
        std::process::exit(1);
    }
    if let (Ok(foreign), Ok(hexkey)) = (
        std::env::var("KRB5_TEST_FOREIGN_REALM"),
        std::env::var("KRB5_TEST_INTERREALM_KEY"),
    ) {
        match parse_hex_key(&hexkey) {
            Ok(key) => {
                if let Err(e) = store.create_interrealm_key(&acl, &actor, &foreign, key) {
                    eprintln!("krb5-kdc: inter-realm: {e}");
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("krb5-kdc: KRB5_TEST_INTERREALM_KEY: {e}");
                std::process::exit(2);
            }
        }
    }
    store
}

fn parse_hex_key(hex: &str) -> Result<krb5_crypto::ProtocolKey, String> {
    let h = hex.trim();
    if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("need 32-byte hex (64 chars)".into());
    }
    let mut bytes = vec![0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    krb5_crypto::ProtocolKey::from_bytes(krb5_crypto::EncryptionType::Aes256CtsHmacSha196, &bytes)
        .map_err(|e| e.to_string())
}
