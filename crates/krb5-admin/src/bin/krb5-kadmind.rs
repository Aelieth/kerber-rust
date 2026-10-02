//! `kadmind`: the kadm5 (TCP 749) and kpasswd (UDP and TCP 464) daemon, started as MIT's.
//!
//! ```text
//! kadmind [-x db_args]* [-r realm] [-m] [-nofork] [-port port-number] [-proponly]
//!         [-p path-to-kdb5_util] [-F dump-file] [-K path-to-kprop] [-k kprop-port]
//!         [-P pid_file]
//! ```
//!
//! The options are read as MIT's loop reads them: each by its exact spelling, the first argument
//! that is none of them ends them, and anything left prints the usage.
//!
//! - `-r` names the realm, else krb5.conf's `default_realm`.
//! - `-x dbname=PATH` names the database instead of kdc.conf's `database_name`; the other
//!   database arguments are `krb5kdc`'s.
//! - `-port N` is the kadm5 port, over `admin_server`'s port and `kadmind_port`.
//! - `-nofork` keeps kadmind in the foreground; without it kadmind binds its sockets, detaches
//!   (`daemon(3)`) and then writes the `-P` pid file.
//! - `-W`, `-p`, `-F`, `-K` and `-k` are accepted and unused: an iprop full resync needs no
//!   `kdb5_util` or `kprop` here. `-proponly` stops kadmind as MIT's does when `iprop_enable` is
//!   not set (this port reads none), and `-m` stops it: the master key comes from the stash.
//!
//! The database, stash and ACL are where [`krb5_config::KdcPaths`] finds them. kadm5 and kpasswd
//! listen where kdc.conf's `kadmind_listen` / `kadmind_port` and `kpasswd_listen` /
//! `kpasswd_port` say, all local addresses by default. The daemon log goes where
//! `[logging] admin_server` (else `default`) says, in MIT's line format; SIGHUP reopens its files
//! and SIGTERM or SIGINT ends kadmind. The JSON structured log stays on standard output.
//!
//! Builds with the `test-hooks` feature also take `--test-realm` (the documented realm) and a
//! `host:port` operand (kadm5 there, kpasswd on `KRB5_KPASSWD_BIND`, else 127.0.0.1:464), both
//! in the foreground.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd as _;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use krb5_admin::{Kadm5RpcError, serve_kadm5_conn, serve_kpasswd_tcp, serve_kpasswd_udp};
use krb5_cli::{MitArgs, MitOpt, Placement};
use krb5_crypto::ProtocolKey;
use krb5_kdc::principals::{kadmin_admin, kadmin_changepw, kadmin_history};
use krb5_kdc::{
    Acl, ClosingFd, Error, OpenFailure, PrincipalStore, Signals, acl_for_store, bind_rpc_listeners,
    bind_tcp_listeners, bind_udp_listeners, detach, names_relative_database, open_database,
    shared_dump as shared_store, write_pid_file,
};
use krb5_log::klog::{self, JsonLog, Severity, os_error_text};
use krb5_protocol::ReplayCache;

/// MIT `main` (`kadmin/server/ovsec_kadmd.c:362-432`): kadmind's options, each matched by
/// spelling; a test-hooks build adds the gates' `--test-realm`.
const OPTIONS: &[MitOpt] = &[
    MitOpt::value("-x"),
    MitOpt::value("-r"),
    MitOpt::flag("-m"),
    MitOpt::flag("-nofork"),
    MitOpt::flag("-proponly"),
    MitOpt::value("-port"),
    MitOpt::value("-P"),
    MitOpt::flag("-W"),
    MitOpt::value("-p"),
    MitOpt::value("-F"),
    MitOpt::value("-K"),
    MitOpt::value("-k"),
    #[cfg(feature = "test-hooks")]
    MitOpt::flag("--test-realm"),
];

/// MIT `usage` (`kadmin/server/ovsec_kadmd.c:80-91`): the text on standard error, then exit 1.
fn usage() -> ! {
    eprint!(
        "Usage: kadmind [-x db_args]* [-r realm] [-m] [-nofork] [-port port-number]\n\
         \t\t[-proponly] [-p path-to-kdb5_util] [-F dump-file]\n\
         \t\t[-K path-to-kprop] [-k kprop-port] [-P pid_file]\n\
         \n\
         where,\n\
         \t[-x db_args]* - any number of database specific arguments.\n\
         \t\t\tLook at each database documentation for supported arguments\n"
    );
    std::process::exit(1);
}

/// Report why kadmind cannot start, on standard error and in the daemon log, and exit 1.
/// MIT `fail_to_start` (`kadmin/server/ovsec_kadmd.c:100-114`): with an error,
/// `<error> while <doing>, aborting` (the log line keeps MIT's trailing newline); without,
/// `<what>, aborting`.
fn fail_to_start(progname: &str, error: Option<&str>, msg: &str) -> ! {
    if let Some(e) = error {
        eprintln!("{progname}: {e} while {msg}, aborting");
        klog::syslog(Severity::Err, &format!("{e} while {msg}, aborting\n"));
    } else {
        eprintln!("{progname}: {msg}, aborting");
        klog::syslog(Severity::Err, &format!("{msg}, aborting"));
    }
    std::process::exit(1);
}

/// C `atoi`: optional space and sign, then digits; anything else stops it, and none is 0.
fn atoi(s: &str) -> i64 {
    let t = s.trim_start();
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let n = digits
        .bytes()
        .take_while(u8::is_ascii_digit)
        .fold(0i64, |n, d| {
            n.saturating_mul(10).saturating_add(i64::from(d - b'0'))
        });
    if neg { -n } else { n }
}

/// The basename of `argv[0]`, the name kadmind logs and prints under.
/// MIT `main` (`kadmin/server/ovsec_kadmd.c:357-358`): `progname` is the last path component.
fn progname(argv0: Option<&String>) -> String {
    argv0
        .map(|a| a.rsplit('/').next().unwrap_or(a).to_owned())
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| "kadmind".to_owned())
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let progname = progname(argv.first());

    // MIT `main` (`kadmin/server/ovsec_kadmd.c:434-435`): an argument left after the options
    // prints the usage.
    let args = MitArgs::parse(
        argv.get(1..).unwrap_or_default(),
        OPTIONS,
        Placement::Leading,
    )
    .unwrap_or_else(|_| usage());
    #[cfg(feature = "test-hooks")]
    let test_realm = args.flag("--test-realm");
    #[cfg(not(feature = "test-hooks"))]
    let test_realm = false;
    let pinned = match args.operands.as_slice() {
        [] => None,
        #[cfg(feature = "test-hooks")]
        [addr] => Some(addr.clone()),
        _ => usage(),
    };
    let nofork = args.flag("-nofork") || test_realm || pinned.is_some();

    // MIT `main` (`kadmin/server/ovsec_kadmd.c:444-444`): the daemon log, once the options are
    // read.
    let specs = krb5_config::LogSpecs::load("admin_server");
    klog::init(&progname, &specs.specs, specs.debug);
    // The JSON log only where `[logging] json` names a destination (MIT has none), standard
    // output or error only in the foreground: a detached kadmind has neither.
    if let Some(json) = specs
        .json
        .as_deref()
        .and_then(|s| JsonLog::open(&progname, s))
        && (nofork || json.is_file())
    {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_writer(json.make_writer())
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "krb5_admin=info,krb5_kdc=info,krb5_protocol=warn".into()),
            )
            .try_init();
    }
    if args.flag("-m") {
        fail_to_start(
            &progname,
            None,
            "Reading the master key from the keyboard (-m) is not supported",
        );
    }

    let (mut store, paths) = open_realm(&progname, &args, test_realm);
    let realm = store.realm().to_owned();
    let kdc_conf = paths.conf.as_ref();
    // The dictionary is read here once; kpasswd, every kadm5 connection and every reread of the
    // database share it.
    // MIT `main` (`kadmin/server/ovsec_kadmd.c:446-450`): `kadm5_init` sets up the password-quality modules, and a dictionary that cannot be read stops kadmind "while initializing".
    if let Err(e) = store.init_pwqual(kdc_conf) {
        fail_to_start(&progname, Some(&os_error_text(&e)), "initializing");
    }
    if let Some(conf) = kdc_conf
        && let Err(e) = store.apply_kdc_conf(conf)
    {
        fail_to_start(&progname, Some(&e.to_string()), "getting config parameters");
    }
    let krb5_conf = krb5_config::load_krb5_conf();
    if let Some(c) = &krb5_conf {
        store.set_capaths(c.capaths.clone());
        store.apply_libdefaults(c);
    }
    // MIT `main` (`kadmin/server/ovsec_kadmd.c:459-462`): the propagation-only mode needs
    // iprop_enable, which this port does not read.
    if args.flag("-proponly") {
        fail_to_start(
            &progname,
            None,
            "-proponly can only be used when iprop_enable is true",
        );
    }
    if acceptor_keys(&store).is_empty() {
        fail_to_start(&progname, None, "Cannot set up KDB keytab");
    }
    let changepw = kadmin_changepw();
    let cpw_key = store
        .get_name(&changepw)
        .and_then(|p| p.best_key())
        .map(|k| k.key.clone());
    #[cfg(feature = "test-hooks")]
    let persist = store.persist_paths.clone();
    let shared = shared_store(store);
    let kadmind_port = args
        .value("-port")
        .map(|p| u16::try_from(atoi(p)).unwrap_or(0));

    // MIT `setup_loop` (`kadmin/server/ovsec_kadmd.c:134-174`): the signal handlers, then kpasswd
    // and kadm5 sockets, before the ACL file is read.
    let signals = Signals::install();
    klog::syslog(Severity::Info, "setting up network...");
    let (listeners, kpasswd_udp, kpasswd_tcp) = bind_sockets(
        &progname,
        test_realm,
        pinned,
        kdc_conf,
        krb5_admin_server(krb5_conf.as_ref(), &realm).as_deref(),
        kadmind_port,
    );
    klog::syslog(
        Severity::Info,
        &format!(
            "set up {} sockets",
            listeners.len() + kpasswd_udp.len() + kpasswd_tcp.len()
        ),
    );
    let mut socket_fds: Vec<i32> = listeners
        .iter()
        .map(std::os::fd::AsRawFd::as_raw_fd)
        .chain(kpasswd_udp.iter().map(std::os::fd::AsRawFd::as_raw_fd))
        .chain(kpasswd_tcp.iter().map(std::os::fd::AsRawFd::as_raw_fd))
        .collect();
    socket_fds.sort_unstable_by(|a, b| b.cmp(a));
    let acl = load_acl(&progname, paths.acl_file.as_deref(), &realm);

    // MIT `main` (`kadmin/server/ovsec_kadmd.c:507-513`): detach unless -nofork, then the pid
    // file.
    if !nofork && let Err(e) = detach() {
        fail_to_start(
            &progname,
            Some(&os_error_text(&e)),
            "spawning daemon process",
        );
    }
    if let Some(pid_file) = args.value("-P")
        && let Err(e) = write_pid_file(Path::new(pid_file))
    {
        fail_to_start(&progname, Some(&os_error_text(&e)), "creating PID file");
    }
    // MIT `main` (`kadmin/server/ovsec_kadmd.c:515-519`): the database is opened again after
    // daemon(), so a relative database or stash name now opens from `/`, or kadmind stops as at
    // its start.
    let db_args: Vec<String> = args.values("-x").into_iter().map(str::to_owned).collect();
    if !nofork && names_relative_database(&paths, &db_args) {
        if let Err(e) = open_database(&paths, &db_args, "K/M") {
            let (OpenFailure::Database(msg) | OpenFailure::MasterKey(msg)) = e;
            fail_to_start(&progname, Some(&msg), "initializing");
        }
        let reloaded = shared
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reload();
        if let Err(e) = reloaded {
            fail_to_start(&progname, Some(&e.to_string()), "initializing");
        }
    }
    for l in &listeners {
        l.set_nonblocking(true).ok();
    }
    #[cfg(feature = "test-hooks")]
    announce(
        &progname,
        persist.as_ref(),
        &listeners,
        cpw_key
            .is_some()
            .then_some((kpasswd_udp.as_slice(), kpasswd_tcp.as_slice())),
    );
    signals.spawn_log_reopener();
    if let Some(cpw_key) = cpw_key {
        for sock in kpasswd_udp {
            let (store, acl, key, stop) = (
                Arc::clone(&shared),
                acl.clone(),
                cpw_key.clone(),
                signals.stop_flag(),
            );
            thread::spawn(move || {
                let _ = serve_kpasswd_udp(store, acl, key, sock, stop);
            });
        }
        for listener in kpasswd_tcp {
            let (store, acl, key, stop) = (
                Arc::clone(&shared),
                acl.clone(),
                cpw_key.clone(),
                signals.stop_flag(),
            );
            thread::spawn(move || {
                let _ = serve_kpasswd_tcp(store, acl, key, listener, stop);
            });
        }
    } else {
        eprintln!("{progname}: no kadmin/changepw keys (RFC 3244 not listening)");
    }
    // MIT `main` (`kadmin/server/ovsec_kadmd.c:538-540`): "starting", and in the foreground
    // "<prog>: starting..." on standard error.
    klog::syslog(Severity::Info, "starting");
    if nofork {
        eprintln!("{progname}: starting...");
    }
    serve(&listeners, &shared, &acl, &realm, &signals);
    // MIT's loop ends after the request in hand. A change in flight holds the store until its
    // database and update log are saved, so taking the store here waits for it; it stays taken
    // until the process exits, so no change starts after it.
    let _finished = shared
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // MIT `main` (`kadmin/server/ovsec_kadmd.c:543-555`): "finished, exiting" when the loop ends,
    // then each socket is logged as the loop is freed, before the log closes.
    klog::syslog(Severity::Debug, "Got signal to request exit");
    klog::syslog(Severity::Info, "finished, exiting");
    for fd in socket_fds {
        klog::syslog(Severity::Info, &format!("closing down fd {fd}"));
    }
    klog::close();
    // MIT `main` (`kadmin/server/ovsec_kadmd.c:557-557`): kadmind exits 0 once the log is closed.
    // `exit` runs no destructors, so the store is still taken as the process ends: returning
    // from main would release it first, and a change waiting on it could start saving.
    std::process::exit(0);
}

/// The realm's store: the test realm in a test-hooks build, else the database
/// [`krb5_config::KdcPaths`] names, opened as MIT `kadm5_init` opens it.
/// MIT `main` (`kadmin/server/ovsec_kadmd.c:446-450`): a database that does not open, or no
/// realm, stops kadmind "while initializing".
fn open_realm(
    progname: &str,
    args: &MitArgs,
    test_realm: bool,
) -> (PrincipalStore, krb5_config::KdcPaths) {
    #[cfg(feature = "test-hooks")]
    let realm = if test_realm {
        Some(krb5_kdc::testrealm::TEST_REALM)
    } else {
        args.value("-r")
    };
    #[cfg(not(feature = "test-hooks"))]
    let realm = args.value("-r");
    let paths = krb5_config::KdcPaths::resolve(realm)
        .unwrap_or_else(|e| fail_to_start(progname, Some(&e.to_string()), "initializing"));
    #[cfg(feature = "test-hooks")]
    if test_realm {
        let store = krb5_kdc::testrealm::bootstrap_documented()
            .unwrap_or_else(|e| fail_to_start(progname, Some(&e.to_string()), "initializing"))
            .0;
        return (store, paths);
    }
    let _ = test_realm;
    let db_args: Vec<String> = args.values("-x").into_iter().map(str::to_owned).collect();
    let store = open_database(&paths, &db_args, "K/M").unwrap_or_else(|e| {
        let (OpenFailure::Database(msg) | OpenFailure::MasterKey(msg)) = e;
        fail_to_start(progname, Some(&msg), "initializing")
    });
    (store, paths)
}

/// The gates' readiness lines on standard output: `persist`, one `listening` line per kadm5
/// listener and one `kpasswd` line per kpasswd address.
#[cfg(feature = "test-hooks")]
fn announce(
    progname: &str,
    persist: Option<&(std::path::PathBuf, std::path::PathBuf)>,
    listeners: &[TcpListener],
    kpasswd: Option<(&[UdpSocket], &[TcpListener])>,
) {
    match persist {
        Some((db, stash)) => println!("persist {} {}", db.display(), stash.display()),
        None => eprintln!("{progname}: no persist_paths (mutations stay in memory)"),
    }
    for a in listeners.iter().filter_map(|l| l.local_addr().ok()) {
        println!("listening {a}");
    }
    if let Some((udp, tcp)) = kpasswd {
        let mut bound: Vec<_> = udp
            .iter()
            .filter_map(|s| s.local_addr().ok())
            .chain(tcp.iter().filter_map(|l| l.local_addr().ok()))
            .collect();
        bound.dedup();
        for a in bound {
            println!("kpasswd {a}");
        }
    }
}

/// Serve kadm5 connections until SIGINT, SIGTERM or SIGQUIT; each connection on its own
/// thread, the oldest dropped past the connection cap.
fn serve(
    listeners: &[TcpListener],
    shared: &krb5_kdc::SharedDump,
    acl: &Acl,
    realm: &str,
    signals: &Signals,
) {
    let rcache = ReplayCache::new();
    // MIT drives kadmind through the same net-server as the KDC: cap concurrent
    // connections and evict the oldest over the cap (kill_lru_stream_connection)
    // rather than spawning unbounded threads.
    let registry = krb5_kdc::ConnRegistry::new(krb5_kdc::MAX_TCP_WORKERS);
    while !signals.stop_requested() {
        accept_pass(listeners, |stream| {
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
            let store = Arc::clone(shared);
            // The acceptor keys as the database holds them now, as MIT's KDB keytab
            // reads them for each context, under the database's lock: a lock that may
            // not be taken leaves the context no key, so it is not accepted.
            // MIT `krb5_db2_get_principal` (`plugins/kdb/db2/kdb_db2.c:769-773`): the KDB keytab's lookup takes the shared lock, and fails when it cannot.
            let keys = {
                let mut g = store
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match g.reload_if_stale() {
                    Ok(()) => acceptor_keys(&g),
                    Err(e) => {
                        klog::syslog(Severity::Err, &format!("{e} while reloading database"));
                        Vec::new()
                    }
                }
            };
            let acl = acl.clone();
            let realm = realm.to_owned();
            let rcache = rcache.clone();
            let fd = stream.as_raw_fd();
            thread::spawn(move || {
                let _guard = krb5_kdc::ConnGuard(registry_g, seq);
                let _closed = ClosingFd(fd);
                // Only an RPC that could not be handled is printed; a record or socket
                // error ends the connection silently.
                if let Err(e) = serve_kadm5_conn(store, acl, keys, realm, rcache, stream)
                    && let Some(rpc) = e.get_ref().and_then(|x| x.downcast_ref::<Kadm5RpcError>())
                {
                    eprintln!("kadm5: {rpc}");
                }
            });
        });
    }
}

/// One pass over kadmind's listeners: each connection taken goes to `take`, and an accept that
/// fails is logged. A pass that took nothing waits for the next connection, or, after a failed
/// accept, pauses instead: the connection that could not be taken (EMFILE, ENFILE, ENOBUFS,
/// ENOMEM) keeps the listener readable, so the wait would return at once and the loop would spin.
fn accept_pass(listeners: &[TcpListener], mut take: impl FnMut(TcpStream)) {
    let mut idle = true;
    let mut failed = false;
    for listener in listeners {
        match listener.accept() {
            Ok((stream, _)) => {
                idle = false;
                take(stream);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            // MIT `accept_rpc_connection` (`lib/apputils/net-server.c:1527-1539`): the woken
            // kadm5 listener is served by the RPC library's `rendezvous_request`.
            // MIT `rendezvous_request` (`lib/rpc/svc_tcp.c:284-291`): an accept that fails
            // other than with EINTR is dropped, and the loop goes on.
            Err(e) => {
                failed = true;
                tracing::error!(
                    event = krb5_log::events::ADMIN,
                    component = "krb5-admin",
                    outcome = "error",
                    error = %e,
                    detail = "kadm5 accept",
                );
            }
        }
    }
    if !idle {
        return;
    }
    if failed {
        thread::sleep(ACCEPT_FAILURE_PAUSE);
    } else {
        // The next connection is taken as it arrives; the stop flag is looked at between.
        let waiting: Vec<&TcpListener> = listeners.iter().collect();
        krb5_kdc::wait_for_connection(&waiting, STOP_POLL);
    }
}

/// How long an idle accept loop waits for a connection before it looks at its stop flag again.
const STOP_POLL: Duration = Duration::from_millis(100);

/// The pause after an accept that failed, as kpasswd's TCP listener pauses.
const ACCEPT_FAILURE_PAUSE: Duration = Duration::from_millis(20);

/// kadmind's RPC listeners and kpasswd's UDP / TCP sockets; a bind failure is logged and fatal.
///
/// MIT `setup_loop` (`kadmin/server/ovsec_kadmd.c:147-156`): `kadmind_listen` on `-port`, else
/// the `admin_server` port / `kadmind_port` / 749, and `kpasswd_listen` on `kpasswd_port` / 464,
/// all local addresses when no list is written. In a test-hooks build an address operand, or
/// `--test-realm`, binds the RPC listener there (127.0.0.1:749) and kpasswd on
/// `KRB5_KPASSWD_BIND` or 127.0.0.1:464, where a kpasswd bind failure is only reported.
fn bind_sockets(
    progname: &str,
    test_realm: bool,
    pinned: Option<String>,
    conf: Option<&krb5_config::KdcConf>,
    krb5_admin_server: Option<&str>,
    kadmind_port: Option<u16>,
) -> (Vec<TcpListener>, Vec<UdpSocket>, Vec<TcpListener>) {
    let default_conf = krb5_config::KdcConf::default();
    let conf = conf.unwrap_or(&default_conf);
    let fatal = |what: &str, e: &dyn std::fmt::Display| -> ! {
        eprintln!("{progname}: {what}: {e}");
        std::process::exit(1);
    };
    #[cfg(feature = "test-hooks")]
    if test_realm || pinned.is_some() {
        return legacy_sockets(progname, pinned);
    }
    let _ = (test_realm, pinned);
    // MIT `setup_loop` (`kadmin/server/ovsec_kadmd.c:146-156`): kpasswd on UDP, then on TCP,
    // then the kadm5 RPC service; a listener that fails is logged as it fails.
    let addrs = conf
        .kpasswd_listeners()
        .unwrap_or_else(|e| fatal("kdc.conf", &e));
    let udp = bind_udp_listeners(&addrs).unwrap_or_else(|_| std::process::exit(1));
    let tcp = bind_tcp_listeners(&addrs).unwrap_or_else(|_| std::process::exit(1));
    let addrs = match kadmind_port {
        Some(port) => krb5_config::listen::listen_addrs(conf.kadmind_listen.as_deref(), port),
        None => conf.kadmind_listeners(krb5_admin_server),
    }
    .unwrap_or_else(|e| fatal("kdc.conf", &e));
    let listeners = bind_rpc_listeners(&addrs).unwrap_or_else(|_| std::process::exit(1));
    (listeners, udp, tcp)
}

/// The gates' sockets: the RPC listener on the operand (else 127.0.0.1:749) and kpasswd on
/// `KRB5_KPASSWD_BIND` (else 127.0.0.1:464).
#[cfg(feature = "test-hooks")]
fn legacy_sockets(
    progname: &str,
    pinned: Option<String>,
) -> (Vec<TcpListener>, Vec<UdpSocket>, Vec<TcpListener>) {
    let bind = pinned.unwrap_or_else(|| "127.0.0.1:749".into());
    let listeners = match TcpListener::bind(&bind) {
        Ok(l) => vec![l],
        Err(e) => {
            eprintln!("{progname}: bind {bind}: {e}");
            std::process::exit(1);
        }
    };
    let kpasswd = std::env::var("KRB5_KPASSWD_BIND").unwrap_or_else(|_| "127.0.0.1:464".into());
    let udp = UdpSocket::bind(&kpasswd)
        .map_err(|e| eprintln!("{progname}: kpasswd udp {kpasswd}: {e}"))
        .ok();
    let tcp = TcpListener::bind(&kpasswd)
        .map_err(|e| eprintln!("{progname}: kpasswd tcp {kpasswd}: {e}"))
        .ok();
    (
        listeners,
        udp.into_iter().collect(),
        tcp.into_iter().collect(),
    )
}

/// The realm's `admin_server` from krb5.conf, written with its port only when the port is
/// not the default 749: the parsed endpoint fills a missing port with 749, and a portless
/// value must leave `kadmind_port` in charge (MIT `parse_admin_server_port` sets the port
/// only when one is written).
fn krb5_admin_server(conf: Option<&krb5_config::Krb5Conf>, realm: &str) -> Option<String> {
    let ep = conf?.admin_servers.get(realm)?.first()?;
    (ep.port != krb5_config::listen::KADMIND_PORT).then(|| format!("{}:{}", ep.host, ep.port))
}

/// The keys a kadm5 or iprop client may authenticate to: the realm's `kadmin/admin`,
/// `kadmin/changepw` and `kadmin/history`, and every `kiprop/<host>` (a replica's iprop service).
/// The RPC layer then admits only the acceptor names each program allows.
/// MIT `setup_kdb_keytab` (`kadmin/server/ovsec_kadmd.c:178-190`): the acceptor keytab is the
/// whole database, and `check_rpcsec_auth` decides which names may call.
fn acceptor_keys(store: &PrincipalStore) -> Vec<ProtocolKey> {
    let mut keys = Vec::new();
    for name in [kadmin_admin(), kadmin_changepw(), kadmin_history()] {
        if let Some(p) = store.get_name(&name) {
            keys.extend(p.keys.iter().map(|k| k.key.clone()));
        }
    }
    let realm_suffix = format!("@{}", store.realm());
    for id in store.ids() {
        let Some(name) = id.strip_suffix(&realm_suffix) else {
            continue;
        };
        if let Some(host) = name.strip_prefix("kiprop/")
            && !host.is_empty()
            && !host.contains('/')
            && let Some(p) = store.get(&id)
        {
            keys.extend(p.keys.iter().map(|k| k.key.clone()));
        }
    }
    keys
}

/// kadmind's ACL, `acl_file` as [`krb5_config::KdcPaths`] resolved it; `None` is self-service
/// only. A file that cannot be read or parsed stops kadmind.
/// MIT `main` (`kadmin/server/ovsec_kadmd.c:497-501`): `auth_init`, else "while initializing
/// ACL file".
fn load_acl(progname: &str, acl_file: Option<&Path>, realm: &str) -> Acl {
    acl_for_store(realm, acl_file).unwrap_or_else(|e| {
        let msg = match e {
            Error::AclParse(s) => s,
            other => other.to_string(),
        };
        let lines: Vec<&str> = msg.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            eprintln!("{progname}: {line}");
            let end = if i + 1 == lines.len() { "\n" } else { "" };
            klog::syslog(Severity::Err, &format!("{line}{end}"));
        }
        std::process::exit(1);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An accept that keeps failing pauses each pass: the listener stays readable, so a wait for
    /// the next connection would return at once and the loop would spin. A connected socket whose
    /// peer has closed stands for such a listener: its accept fails (EINVAL) and poll finds it
    /// readable at once.
    #[test]
    fn a_failing_accept_does_not_spin() {
        let real = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(real.local_addr().unwrap()).unwrap();
        drop(real.accept().unwrap());
        let listener = TcpListener::from(std::os::fd::OwnedFd::from(client));
        listener.set_nonblocking(true).unwrap();
        let listeners = [listener];
        let start = std::time::Instant::now();
        let mut passes = 0;
        while start.elapsed() < Duration::from_millis(200) {
            accept_pass(&listeners, |_| panic!("no connection to take"));
            passes += 1;
        }
        assert!(passes <= 20, "{passes} passes in 200 ms");
    }

    #[test]
    fn progname_and_atoi() {
        assert_eq!(progname(Some(&"/usr/sbin/kadmind".to_owned())), "kadmind");
        assert_eq!(atoi("7749"), 7749);
        assert_eq!(atoi("abc"), 0);
    }

    #[test]
    fn options_stop_at_the_first_unknown_argument() {
        let argv: Vec<String> = ["-nofork", "-port", "7749", "extra"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let a = MitArgs::parse(&argv, OPTIONS, Placement::Leading).unwrap_or_default();
        assert!(a.flag("-nofork"));
        assert_eq!(a.value("-port"), Some("7749"));
        assert_eq!(a.operands, ["extra"]);
    }
}
