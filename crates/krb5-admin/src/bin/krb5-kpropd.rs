//! MIT-wire kpropd (TCP 754) wrapping dump version 7.
//!
//! Usage: `krb5-kpropd [-r realm] [host:port]`
//!
//! The realm is `-r`, else `KRB5_KDC_REALM`, else krb5.conf's `default_realm`, as MIT's kpropd
//! takes `-r` or the default realm. The dump body is opened with the replica's stash, as MIT's
//! kpropd loads it with `kdb5_util load` beside that stash, and saved to the replica db.
//!
//! kerber-rust's own environment, where this kpropd has none of MIT's options yet (it is not
//! installed as a service):
//! - `KRB5_KDC_REALM`: the realm, beside `-r`.
//! - `KRB5_KPROP_KEYTAB`: the keys that accept `sendauth` (MIT's `-s`, else the default
//!   keytab); unset, there are none and kpropd stops.
//! - `KRB5_KPROP_ACL`: the `kpropd.acl` file (MIT's `-a`, else `kpropd.acl` in the KDC
//!   directory); unset or empty, every peer is refused.
//!
//! With the `test-hooks` feature, the realm falls back to `KRB5_TEST_REALM`, else the documented
//! test realm, before the default realm; the documented test realm's host keys in the database
//! stand in for a keytab; and `KRB5_MASTER_PASSWORD` opens the dump instead of the stash when
//! set.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use krb5_admin::{KPROP_PORT, KpropdConfig, kpropd_handle_conn};
use krb5_crypto::ProtocolKey;

use krb5_protocol::{Keytab, ReplayCache};

fn main() {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "krb5_admin=info,krb5_kdc=info".into()),
        )
        .try_init();

    let argv: Vec<String> = std::env::args().collect();
    let progname = argv
        .first()
        .map_or("krb5-kpropd", |a| a.rsplit('/').next().unwrap_or(a))
        .to_owned();
    // MIT `parse_args` (`kprop/kpropd.c:1065-1126`): glibc getopt over the options, a value attached or apart; a bad option is the usage.
    let (opts, operands) = match krb5_cli::getopt(argv.get(1..).unwrap_or_default(), "r:", &[]) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("{progname}: {e}");
            usage(&progname);
        }
    };
    let realm_opt = opts
        .iter()
        .rev()
        .find(|o| o.flag == 'r')
        .and_then(|o| o.arg.clone());
    // The one operand, `host:port`, is this kpropd's own; MIT's takes none.
    if operands.len() > 1 {
        usage(&progname);
    }
    let bind = operands
        .first()
        .cloned()
        .unwrap_or_else(|| format!("127.0.0.1:{KPROP_PORT}"));
    #[cfg(feature = "test-hooks")]
    let master = std::env::var("KRB5_MASTER_PASSWORD")
        .ok()
        .map(zeroize::Zeroizing::new);
    #[cfg(not(feature = "test-hooks"))]
    let master: Option<zeroize::Zeroizing<String>> = None;
    let paths = kpropd_paths(realm_opt).unwrap_or_else(|e| {
        // MIT `parse_args` (`kprop/kpropd.c:1132-1138`): no realm is this line, exit 1.
        if matches!(e, krb5_config::Error::NoDefaultRealm) {
            eprintln!("krb5-kpropd: {e} Unable to get default realm");
        } else {
            eprintln!("krb5-kpropd: {e}");
        }
        std::process::exit(1);
    });
    let realm = paths.realm.clone().unwrap_or_default();
    let (db, stash) = (paths.database_name, paths.key_stash_file);
    let host_keys = load_host_keys(&db, &stash);
    if host_keys.is_empty() {
        eprintln!("krb5-kpropd: no host keys (set KRB5_KPROP_KEYTAB)");
        std::process::exit(1);
    }
    let listener = TcpListener::bind(&bind).unwrap_or_else(|e| {
        eprintln!("krb5-kpropd: bind {bind}: {e}");
        std::process::exit(1);
    });
    listener.set_nonblocking(true).ok();
    println!("listening {bind}");
    let stop = Arc::new(AtomicBool::new(false));
    let replay = ReplayCache::new();
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let accepted = listener.accept();
        match accepted {
            Ok((mut stream, _)) => {
                let keys = host_keys.clone();
                let realm = realm.clone();
                let master = master.clone();
                let db = db.clone();
                let stash = stash.clone();
                let allowed = kpropd_acl();
                let replay = replay.clone();
                thread::spawn(move || {
                    match kpropd_handle_conn(
                        &mut stream,
                        &KpropdConfig {
                            host_keys: &keys,
                            expected_server: None,
                            expected_realm: Some(realm.as_str()),
                            master_password: master.as_deref().map(String::as_bytes),
                            db: &db,
                            stash: &stash,
                            allowed_clients: allowed.as_deref(),
                        },
                        replay,
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

/// The usage text on stderr, exit status 1.
/// MIT `usage` (`kprop/kpropd.c:168-177`): the text, then `exit(1)`.
fn usage(progname: &str) -> ! {
    eprintln!("\nUsage: {progname} [-r realm] [host:port]");
    std::process::exit(1);
}

/// The realm's paths: `-r`, else `KRB5_KDC_REALM`, else (with the `test-hooks` feature)
/// `KRB5_TEST_REALM` or the documented test realm, else krb5.conf's `default_realm`.
/// MIT `parse_args` (`kprop/kpropd.c:1132-1145`): `-r`, else the default realm.
fn kpropd_paths(realm: Option<String>) -> Result<krb5_config::KdcPaths, krb5_config::Error> {
    #[cfg(feature = "test-hooks")]
    let test_realm = Some(
        std::env::var("KRB5_TEST_REALM")
            .unwrap_or_else(|_| krb5_kdc::testrealm::TEST_REALM.to_owned()),
    );
    #[cfg(not(feature = "test-hooks"))]
    let test_realm: Option<String> = None;
    let realm = realm
        .or_else(|| std::env::var("KRB5_KDC_REALM").ok())
        .or(test_realm);
    krb5_config::KdcPaths::resolve(realm.as_deref())
}

/// Raw `kpropd.acl` lines for `kpropd_authorized_principal`, read per
/// connection like MIT `authorized_principal` (`fopen` on every peer, so
/// edits apply without a restart). Unset `KRB5_KPROP_ACL` or an unopenable
/// file is `None`: every peer is refused. Only the trailing `\n` is
/// stripped (`fgets`, `buf[end] == '\n'`); a `\r`, leading whitespace or a
/// `#` stay in the line and simply never match a principal.
fn kpropd_acl() -> Option<Vec<String>> {
    let path = std::env::var("KRB5_KPROP_ACL").ok()?;
    let text = String::from_utf8_lossy(&std::fs::read(&path).ok()?).into_owned();
    Some(text.split('\n').map(str::to_owned).collect())
}

fn load_host_keys(db: &Path, stash: &Path) -> Vec<ProtocolKey> {
    if let Ok(path) = std::env::var("KRB5_KPROP_KEYTAB") {
        match std::fs::read(&path).and_then(|b| Keytab::parse(&b)) {
            Ok(kt) => {
                return kt.entries.into_iter().map(|e| e.key).collect();
            }
            Err(e) => eprintln!("krb5-kpropd: keytab {path}: {e}"),
        }
    }
    #[cfg(feature = "test-hooks")]
    if let Ok(store) = krb5_kdc::load_store(db, stash)
        && store.realm() == krb5_kdc::testrealm::TEST_REALM
        && let Some(p) = store.get_name(&krb5_kdc::testrealm::documented_host())
    {
        return p.keys.iter().map(|k| k.key.clone()).collect();
    }
    #[cfg(not(feature = "test-hooks"))]
    let _ = (db, stash);
    Vec::new()
}
