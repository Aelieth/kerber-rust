//! MIT-compatible kadmind (GSS-RPC on TCP 749).
//!
//! Usage: `krb5-kadmind [--test-realm] [host:port]`
//!
//! Shares `KRB5_KDC_DB` / `KRB5_KDC_STASH` with `krb5-kdc`. `--test-realm`
//! bootstraps KERBER.TEST including `kadmin/admin` and `kadmin/changepw`.
//! TCP 749 is kadm5; UDP + TCP 464 is RFC 3244 kpasswd. With no `host:port`, both
//! listen where MIT kadmind would: kdc.conf's `kadmind_listen` / `kadmind_port` and
//! `kpasswd_listen` / `kpasswd_port`, all local addresses by default.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::Duration;

use krb5_admin::{Kadm5RpcError, serve_kadm5_conn, serve_kpasswd_tcp, serve_kpasswd_udp};
use krb5_crypto::ProtocolKey;
use krb5_kdc::principals::{kadmin_admin, kadmin_changepw, kadmin_history};
use krb5_kdc::testrealm::{bootstrap_documented, documented_kiprop};
use krb5_kdc::{
    Acl, Error, PrincipalStore, acl_for_store, bind_tcp_listeners, bind_udp_listeners,
    default_acl_path, open_store, shared_dump as shared_store,
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
    let krb5_conf = krb5_config::load_krb5_conf();
    if let Some(c) = &krb5_conf {
        store.set_capaths(c.capaths.clone());
        store.apply_libdefaults(c);
    }

    let realm = store.realm().to_owned();
    let changepw = kadmin_changepw();
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
    let pinned = args.first().cloned();
    let (listeners, kpasswd_udp, kpasswd_tcp) = bind_sockets(
        test_realm,
        pinned,
        kdc_conf.as_ref(),
        krb5_admin_server(krb5_conf.as_ref(), &realm).as_deref(),
    );
    for l in &listeners {
        l.set_nonblocking(true).ok();
        if let Ok(a) = l.local_addr() {
            println!("listening {a}");
        }
    }

    if let Some(cpw_key) = cpw_key {
        let mut bound = Vec::new();
        for sock in kpasswd_udp {
            bound.extend(sock.local_addr().ok());
            let store = Arc::clone(&shared);
            let acl_cpw = acl.clone();
            let key = cpw_key.clone();
            let stop = Arc::new(AtomicBool::new(false));
            thread::spawn(move || {
                let _ = serve_kpasswd_udp(store, acl_cpw, key, sock, stop);
            });
        }
        for listener in kpasswd_tcp {
            bound.extend(listener.local_addr().ok());
            let store = Arc::clone(&shared);
            let acl_cpw = acl.clone();
            let key = cpw_key.clone();
            let stop = Arc::new(AtomicBool::new(false));
            thread::spawn(move || {
                let _ = serve_kpasswd_tcp(store, acl_cpw, key, listener, stop);
            });
        }
        bound.dedup();
        for a in bound {
            println!("kpasswd {a}");
        }
    } else {
        eprintln!("krb5-kadmind: no kadmin/changepw keys (RFC 3244 not listening)");
    }
    let rcache = ReplayCache::new();
    // MIT drives kadmind through the same net-server as the KDC: cap concurrent
    // connections and evict the oldest over the cap (kill_lru_stream_connection)
    // rather than spawning unbounded threads.
    let registry = krb5_kdc::ConnRegistry::new(krb5_kdc::MAX_TCP_WORKERS);
    loop {
        let mut idle = true;
        for listener in &listeners {
            match listener.accept() {
                Ok((stream, _)) => {
                    idle = false;
                    // A write timeout bounds a slow-reading client that would
                    // otherwise pin a worker in write_all. No short read
                    // timeout: MIT's net-server sets none on established kadmind
                    // connections (SO_KEEPALIVE only) and defends slow-loris with
                    // the connection cap + LRU eviction above; a 5 s read timeout
                    // would break a legitimate interactive session that pauses
                    // between commands.
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
                    let seq = registry.register(&stream);
                    let registry_g = Arc::clone(&registry);
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
                        let _guard = krb5_kdc::ConnGuard(registry_g, seq);
                        // Only an RPC that could not be handled is printed; a record or socket
                        // error ends the connection silently.
                        if let Err(e) = serve_kadm5_conn(store, acl, keys, realm, rcache, stream)
                            && let Some(rpc) =
                                e.get_ref().and_then(|x| x.downcast_ref::<Kadm5RpcError>())
                        {
                            eprintln!("kadm5: {rpc}");
                        }
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    eprintln!("krb5-kadmind: accept: {e}");
                    return;
                }
            }
        }
        if idle {
            thread::sleep(Duration::from_millis(20));
        }
    }
}

/// kadmind's RPC listeners and kpasswd's UDP / TCP sockets.
///
/// An address on the command line binds the RPC listener there, and `KRB5_KPASSWD_BIND`
/// does the same for kpasswd. With a command-line address or `--test-realm`, kpasswd keeps
/// its loopback default (464 on 127.0.0.1) and a kpasswd bind failure is only reported.
/// MIT `setup_loop` (`kadmin/server/ovsec_kadmd.c:147-156`): otherwise `kadmind_listen` on
/// the `admin_server` port / `kadmind_port` / 749 and `kpasswd_listen` on `kpasswd_port` /
/// 464, all local addresses when no list is written, and a bind failure is fatal.
fn bind_sockets(
    test_realm: bool,
    pinned: Option<String>,
    conf: Option<&krb5_config::KdcConf>,
    krb5_admin_server: Option<&str>,
) -> (Vec<TcpListener>, Vec<UdpSocket>, Vec<TcpListener>) {
    let default_conf = krb5_config::KdcConf::default();
    let conf = conf.unwrap_or(&default_conf);
    let fatal = |what: &str, e: &dyn std::fmt::Display| -> ! {
        eprintln!("krb5-kadmind: {what}: {e}");
        std::process::exit(1);
    };
    let legacy = test_realm || pinned.is_some();
    let listeners =
        if let Some(bind) = pinned.or_else(|| test_realm.then(|| "127.0.0.1:749".into())) {
            match TcpListener::bind(&bind) {
                Ok(l) => vec![l],
                Err(e) => fatal(&format!("bind {bind}"), &e),
            }
        } else {
            let addrs = conf
                .kadmind_listeners(krb5_admin_server)
                .unwrap_or_else(|e| fatal("kdc.conf", &e));
            bind_tcp_listeners(&addrs).unwrap_or_else(|e| fatal("bind", &e))
        };
    let kpasswd_pin = std::env::var("KRB5_KPASSWD_BIND")
        .ok()
        .or_else(|| legacy.then(|| "127.0.0.1:464".into()));
    let (udp, tcp) = if let Some(bind) = kpasswd_pin {
        let udp = UdpSocket::bind(&bind)
            .map_err(|e| eprintln!("krb5-kadmind: kpasswd udp {bind}: {e}"))
            .ok();
        let tcp = TcpListener::bind(&bind)
            .map_err(|e| eprintln!("krb5-kadmind: kpasswd tcp {bind}: {e}"))
            .ok();
        (udp.into_iter().collect(), tcp.into_iter().collect())
    } else {
        let addrs = conf
            .kpasswd_listeners()
            .unwrap_or_else(|e| fatal("kdc.conf", &e));
        (
            bind_udp_listeners(&addrs).unwrap_or_else(|e| fatal("kpasswd bind", &e)),
            bind_tcp_listeners(&addrs).unwrap_or_else(|e| fatal("kpasswd bind", &e)),
        )
    };
    (listeners, udp, tcp)
}

/// The realm's `admin_server` from krb5.conf, written with its port only when the port is
/// not the default 749: the parsed endpoint fills a missing port with 749, and a portless
/// value must leave `kadmind_port` in charge (MIT `parse_admin_server_port` sets the port
/// only when one is written).
fn krb5_admin_server(conf: Option<&krb5_config::Krb5Conf>, realm: &str) -> Option<String> {
    let ep = conf?.admin_servers.get(realm)?.first()?;
    (ep.port != krb5_config::listen::KADMIND_PORT).then(|| format!("{}:{}", ep.host, ep.port))
}

fn acceptor_keys(store: &PrincipalStore) -> Vec<ProtocolKey> {
    let mut keys = Vec::new();
    for name in [
        kadmin_admin(),
        kadmin_changepw(),
        documented_kiprop(),
        kadmin_history(),
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
        for line in msg.lines() {
            eprintln!("krb5-kadmind: {line}");
        }
        std::process::exit(1);
    })
}
