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
//! - `-port N` is the kadm5 port, over `kadmind_port`; a port written in `admin_server` is over
//!   both.
//! - `-nofork` keeps kadmind in the foreground; without it kadmind binds its sockets, detaches
//!   (`daemon(3)`) and then writes the `-P` pid file.
//! - `-W`, `-p`, `-F`, `-K` and `-k` are accepted and unused: this kadmind starts no
//!   `kdb5_util` or `kprop` for an iprop full resync, whose dump is sent by hand:
//!   `kdb5_util dump -i1`, then `kprop -f`.
//! - `-proponly` sets up the iprop listeners alone; without `iprop_enable` it is refused with
//!   MIT's text (`-proponly can only be used when iprop_enable is true`).
//! - `-m` reads the master key from the keyboard, including when kdc.conf names a
//!   `key_stash_file`. In the foreground it is read twice.
//!
//! With `iprop_enable` set for the realm ([`krb5_config::IpropParams`], which also needs
//! `iprop_port`), kadmind maps the update log as the primary's, logs every principal put and
//! delete there, and serves the iprop program (100423); without it the log is never touched and
//! the program is not served.
//!
//! The database, stash and ACL are where [`krb5_config::KdcPaths`] finds them. kpasswd, kadm5
//! and iprop listen where the realm's `kpasswd_listen` / `kpasswd_port`, `kadmind_listen` /
//! `kadmind_port` and `iprop_listen` / `iprop_port` say ([`krb5_config::KadmindListen`]: kdc.conf's
//! relations, then krb5.conf's, the last value of each), all local addresses by default. A
//! listener of the same kind on the same port as one set up before it is not added, so with
//! `iprop_port` equal to kadmind's port the iprop program is not served, as MIT's is not. Every
//! RPC listener serves every program that has one, and all are served from MIT's one net-server
//! loop on the main thread. The daemon log goes where `[logging] admin_server` (else
//! `default`) says, in MIT's line format; SIGHUP reopens its files, and SIGTERM, SIGINT or
//! SIGQUIT ends kadmind. The JSON structured log goes only where `[logging] json` names a
//! destination. A kadm5 call that cannot be handled gets no reply and prints `kadm5: <message>`
//! on standard error.
//!
//! Builds with the `test-hooks` feature also take `--test-realm` (the documented realm) and a
//! `host:port` operand (kadm5 there, kpasswd on `KRB5_KPASSWD_BIND`, else 127.0.0.1:464), both
//! in the foreground.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![allow(
    clippy::disallowed_methods,
    reason = "a program reads its profile and environment when it starts"
)]

use std::io::Write as _;
use std::net::{TcpListener, UdpSocket};
use std::path::Path;
use std::sync::Arc;

use krb5_admin::{Kadmind, Programs, acceptor_names_served, serve_kadmind};
use krb5_cli::{MitArgs, MitOpt, Placement};
use krb5_config::listen::{BindAddresses, BindType, ListenLog};
use krb5_kdc::net_server::Sockets;
use krb5_kdc::principals::kadmin_changepw;
use krb5_kdc::{
    Acl, DEFAULT_TCP_LISTEN_BACKLOG, Error, IpropRole, OpenFailure, PrincipalStore, Signals,
    acl_for_store, bind_rpc_listeners, bind_tcp_listeners_with_backlog, bind_udp_listeners,
    copy_persist_master, detach, kadmind_mkey_from_kbd, names_relative_database, open_database,
    open_database_with_key, open_database_with_password, shared_dump as shared_store,
    write_pid_file,
};
use krb5_log::klog::{self, JsonLog, Severity, os_error_text};
use krb5_protocol::AcceptorConfig;

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

    // MIT `main` (`kadmin/server/ovsec_kadmd.c:437-442`): the KDC context once the options are
    // read; a profile it refuses ends kadmind.
    if let Err(e) = krb5_config::init_kdc_profile() {
        eprintln!(
            "{progname}: {} while initializing context, aborting",
            e.init_text()
        );
        std::process::exit(1);
    }

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
            .with_env_filter(krb5_kdc::json_log_filter(
                "krb5_admin=info,krb5_kdc=info,krb5_protocol=warn",
            ))
            .try_init();
    }
    let (mut store, paths) = open_realm(&progname, &args, test_realm, nofork);
    let realm = store.realm().to_owned();
    let kdc_conf = paths.conf.as_ref();
    // MIT `kadm5_init` (`lib/kadm5/srv/server_init.c:222-228`): with iprop enabled and no `iprop_port`, kadmind does not start.
    let iprop = krb5_config::IpropParams::load(&realm, &paths.database_name);
    // MIT `kadm5_init` (`lib/kadm5/srv/server_init.c:207-218`): a realm value that did not convert left its required parameter unset.
    if iprop.missing_required() || krb5_kdc::realm_kadm5_params_missing(&paths, &realm, true) {
        fail_to_start(
            &progname,
            Some(krb5_config::MISSING_CONF_PARAMS),
            "initializing",
        );
    }
    // The dictionary is read here once; kpasswd, every kadm5 connection and every reread of the
    // database share it.
    // MIT `main` (`kadmin/server/ovsec_kadmd.c:446-450`): `kadm5_init` sets up the password-quality modules, and a dictionary that cannot be read stops kadmind "while initializing".
    if let Err(e) = store.init_pwqual(kdc_conf) {
        fail_to_start(&progname, Some(&os_error_text(&e)), "initializing");
    }
    // MIT `main` (`kadmin/server/ovsec_kadmd.c:446-457`): `kadm5_init` and `kadm5_get_config_params` read the realm's profile, kdc.conf before krb5.conf; here it is read once and applied in the KDC's order.
    let profile = krb5_config::ProfileSet::from_env_files(&paths)
        .unwrap_or_else(|e| fail_to_start(&progname, Some(&e.init_text()), "initializing context"));
    if let Err(e) = store.apply_profile(&profile) {
        fail_to_start(&progname, Some(&e.to_string()), "getting config parameters");
    }
    // A relation MIT's programs read and this one reads past is named once in the log.
    for line in profile
        .kdc
        .iter()
        .flat_map(krb5_config::KdcConf::unsupported_lines)
    {
        klog::syslog(Severity::Warning, &line);
    }
    // MIT `kadm5_init_krb5_context` (`lib/kadm5/srv/server_init.c:334-345`): kadmind's GSS contexts, as its own, read the KDC profile, kdc.conf ahead of krb5.conf; kpasswd's `krb5_rd_req` too.
    let conf = AcceptorConfig::from_profile(&profile);
    // MIT `main` (`kadmin/server/ovsec_kadmd.c:459-462`): the propagation-only mode needs iprop_enable.
    let proponly = args.flag("-proponly");
    if proponly && !iprop.enabled {
        fail_to_start(
            &progname,
            None,
            "-proponly can only be used when iprop_enable is true",
        );
    }
    // MIT `main` (`kadmin/server/ovsec_kadmd.c:476-477`): `svcauth_gssapi_set_names` acquires a credential for `kadmin/admin` and for `kadmin/changepw`, each of which the KDB keytab must have a key for.
    if !acceptor_names_served(&store, &conf) {
        fail_to_start(&progname, None, "Cannot set GSSAPI authentication names");
    }
    let changepw = kadmin_changepw();
    let cpw_key = store
        .get_name(&changepw)
        .and_then(|p| p.best_key())
        .map(|k| k.key.clone());
    #[cfg(feature = "test-hooks")]
    let persist = store.persist_paths.clone();
    let keyboard = kadmind_mkey_from_kbd(args.flag("-m"));
    let held_master = if keyboard {
        copy_persist_master(&store)
    } else {
        None
    };
    let shared = shared_store(store);
    // MIT `main` (`kadmin/server/ovsec_kadmd.c:395-400`): `-port` is read with `atoi`.
    let port_arg = args.value("-port").map(|p| {
        let [a, b, c, d, ..] = atoi(p).to_le_bytes();
        i32::from_le_bytes([a, b, c, d])
    });
    let listen =
        krb5_config::KadmindListen::for_realm(Some(&profile.kdc_context), &realm, port_arg);

    // MIT `setup_loop` (`kadmin/server/ovsec_kadmd.c:134-174`): the signal handlers, then the
    // listeners, before the ACL file is read.
    let signals = Signals::install();
    let (listeners, kpasswd_udp, kpasswd_tcp, programs) = setup_loop(
        &progname,
        test_realm,
        pinned,
        &listen,
        iprop.enabled.then_some(&iprop),
        proponly,
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
        let reopened = if keyboard {
            match &held_master {
                Some(key) => open_database_with_key(&paths, &db_args, "K/M", key).map(|_| ()),
                None => Err(OpenFailure::MasterKey("Cannot read password".into())),
            }
        } else {
            open_database(&paths, &db_args, "K/M").map(|_| ())
        };
        if let Err(e) = reopened {
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
    // MIT `main` (`kadmin/server/ovsec_kadmd.c:521-531`): with iprop enabled the update log is mapped as the primary's, and in the foreground the iprop service is announced.
    if iprop.enabled {
        let mapped = shared
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .map_ulog(&iprop.logfile, iprop.ulogsize, IpropRole::Primary);
        if let Err(e) = mapped {
            fail_to_start(&progname, Some(&e.to_string()), "mapping update log");
        }
        if nofork {
            eprintln!("{progname}: create IPROP svc (PROG=100423, VERS=1)");
        }
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
    // Without kadmin/changepw's keys kpasswd's sockets stay bound and unserved.
    let (udp, tcp): (&[UdpSocket], &[TcpListener]) = if cpw_key.is_some() {
        (&kpasswd_udp, &kpasswd_tcp)
    } else {
        eprintln!("{progname}: no kadmin/changepw keys (RFC 3244 not listening)");
        (&[], &[])
    };
    let sockets = Sockets {
        udp,
        tcp,
        rpc: &listeners,
    };
    let mut kadmind = Kadmind::new(shared, acl, cpw_key, conf)
        .serve_programs(programs)
        .report_unhandled(Arc::new(|message| {
            let _ = writeln!(std::io::stderr(), "kadm5: {message}");
        }));
    // MIT `main` (`kadmin/server/ovsec_kadmd.c:538-540`): "starting", and in the foreground
    // "<prog>: starting..." on standard error.
    klog::syslog(Severity::Info, "starting");
    if nofork {
        eprintln!("{progname}: starting...");
    }
    let open = serve_kadmind(&mut kadmind, &sockets, &signals).unwrap_or_else(|e| {
        klog::com_err(Some(&e.to_string()), "while serving");
        eprintln!("{progname}: serve: {e}");
        std::process::exit(1);
    });
    // MIT `main` (`kadmin/server/ovsec_kadmd.c:543-555`): "finished, exiting" when the loop ends,
    // then each event left is freed, the newest first, every connection and socket with
    // "closing down fd", before the log closes.
    klog::syslog(Severity::Info, "finished, exiting");
    for fd in open.into_iter().chain(socket_fds) {
        klog::syslog(Severity::Info, &format!("closing down fd {fd}"));
    }
    klog::close();
    // MIT `main` (`kadmin/server/ovsec_kadmd.c:557-557`): kadmind exits 0 once the log is closed.
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
    nofork: bool,
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
    let realm_name = paths.realm.clone().unwrap_or_default();
    let keyboard = kadmind_mkey_from_kbd(args.flag("-m"));
    let mut store = if keyboard {
        open_database_with_password(&paths, &db_args, "K/M", &realm_name)
    } else {
        open_database(&paths, &db_args, "K/M")
    }
    .unwrap_or_else(|e| {
        let (OpenFailure::Database(msg) | OpenFailure::MasterKey(msg)) = e;
        fail_to_start(progname, Some(&msg), "initializing")
    });
    // MIT `main` (`kadmin/server/ovsec_kadmd.c:502-519`): the handle is destroyed and `kadm5_init` runs again, so `-nofork` reads the master key twice.
    if nofork && keyboard {
        store =
            open_database_with_password(&paths, &db_args, "K/M", &realm_name).unwrap_or_else(|e| {
                let (OpenFailure::Database(msg) | OpenFailure::MasterKey(msg)) = e;
                fail_to_start(progname, Some(&msg), "initializing")
            });
    }
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

/// The service a listener is set up for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Service {
    Kpasswd,
    Kadm,
    Iprop,
}

/// kadmind's listeners, added to one list in MIT's order and bound in that order: kpasswd's UDP
/// and TCP sockets and the kadm5 program unless `-proponly`, then the iprop program when `iprop`
/// is enabled. The programs served are those whose listener stayed in the list. A list
/// that does not parse, or a port outside 0 to 65535, stops kadmind "while initializing
/// network"; a socket that does not bind stops it as [`bind_rpc_listeners`] logs. In a
/// test-hooks build an address operand, or `--test-realm`, binds the RPC listener there
/// (127.0.0.1:749) and kpasswd on `KRB5_KPASSWD_BIND` or 127.0.0.1:464, where a kpasswd bind
/// failure is only reported.
/// MIT `setup_loop` (`kadmin/server/ovsec_kadmd.c:146-171`): kpasswd's UDP and TCP lists, the kadm5 program, kpasswd's UNIX-domain sockets, then the iprop program; `-proponly` adds iprop's alone.
/// MIT `main` (`kadmin/server/ovsec_kadmd.c:464-466`): a list that is refused stops kadmind "while initializing network".
fn setup_loop(
    progname: &str,
    test_realm: bool,
    pinned: Option<String>,
    listen: &krb5_config::KadmindListen,
    iprop: Option<&krb5_config::IpropParams>,
    proponly: bool,
) -> (Vec<TcpListener>, Vec<UdpSocket>, Vec<TcpListener>, Programs) {
    #[cfg(feature = "test-hooks")]
    if test_realm || pinned.is_some() {
        klog::syslog(Severity::Info, "setting up network...");
        let (rpc, udp, tcp) = legacy_sockets(progname, pinned);
        return (rpc, udp, tcp, Programs::BOTH);
    }
    let _ = (test_realm, pinned);
    let mut list = BindAddresses::default();
    let mut added = Ok(());
    if !proponly {
        let kpasswd = listen.kpasswd_listen.as_deref();
        added = added
            .and_then(|()| {
                list.add_addresses(
                    kpasswd,
                    listen.kpasswd_port,
                    BindType::Udp,
                    &Service::Kpasswd,
                )
            })
            .and_then(|()| {
                list.add_addresses(
                    kpasswd,
                    listen.kpasswd_port,
                    BindType::Tcp,
                    &Service::Kpasswd,
                )
            })
            .and_then(|()| {
                list.add_addresses(
                    listen.kadmind_listen.as_deref(),
                    listen.kadmind_port,
                    BindType::Rpc,
                    &Service::Kadm,
                )
            });
        // MIT `loop_add_unix_socket` (`lib/apputils/net-server.c:461-468`): kpasswd's `/path` entries are UNIX-domain sockets, which this port does not bind.
        for entry in kpasswd
            .into_iter()
            .flat_map(|l| l.split([',', ';', ' ']))
            .filter(|e| e.starts_with('/'))
        {
            klog::syslog(
                Severity::Warning,
                &format!(
                    "kpasswd_listen entry {entry} is a UNIX-domain socket, which is not supported; it is skipped"
                ),
            );
        }
    }
    if let Some(iprop) = iprop {
        added = added.and_then(|()| {
            list.add_addresses(
                iprop.listen.as_deref(),
                iprop.port.unwrap_or_default(),
                BindType::Rpc,
                &Service::Iprop,
            )
        });
    }
    for line in list.take_log() {
        match line {
            ListenLog::Debug(l) => klog::syslog(Severity::Debug, &l),
            ListenLog::Err(l) => klog::syslog(Severity::Err, &l),
        }
    }
    if added.is_err() {
        fail_to_start(progname, Some("Invalid argument"), "initializing network");
    }
    // MIT `loop_setup_network` (`lib/apputils/net-server.c:1068-1068`): the line before the sockets are set up.
    klog::syslog(Severity::Info, "setting up network...");
    let (mut rpc, mut udp, mut tcp) = (Vec::new(), Vec::new(), Vec::new());
    let mut programs = Programs {
        kadm: false,
        iprop: false,
    };
    // MIT `setup_addresses` (`lib/apputils/net-server.c:965-1042`): the list is set up in its order, and a socket that does not bind stops the daemon.
    for entry in list.entries() {
        let one = std::slice::from_ref(&entry.addr);
        match entry.kind {
            BindType::Udp => {
                udp.extend(bind_udp_listeners(one).unwrap_or_else(|_| std::process::exit(1)));
            }
            // MIT `setup_loop` (`kadmin/server/ovsec_kadmd.c:173-174`): the stream listeners listen with `DEFAULT_TCP_LISTEN_BACKLOG` (5), not the KDC's default.
            BindType::Tcp => tcp.extend(
                bind_tcp_listeners_with_backlog(one, DEFAULT_TCP_LISTEN_BACKLOG)
                    .unwrap_or_else(|_| std::process::exit(1)),
            ),
            BindType::Rpc => {
                rpc.extend(bind_rpc_listeners(one).unwrap_or_else(|_| std::process::exit(1)));
                match entry.service {
                    Service::Kadm => programs.kadm = true,
                    Service::Iprop => programs.iprop = true,
                    Service::Kpasswd => {}
                }
            }
        }
    }
    (rpc, udp, tcp, programs)
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

/// kadmind's ACL, `acl_file` as [`krb5_config::KdcPaths`] resolved it; `None` is self-service
/// only. A file that cannot be read or parsed stops kadmind: what MIT's ACL module logs goes to
/// the log alone, and the last line, `fail_to_start`'s, to standard error and the log.
/// MIT `main` (`kadmin/server/ovsec_kadmd.c:497-501`): `auth_init`, else "while initializing
/// ACL file".
/// MIT `fail_to_start` (`kadmin/server/ovsec_kadmd.c:100-114`): `progname: <message> while
/// <doing>, aborting` on standard error, and the same, a newline after it, to the log.
fn load_acl(progname: &str, acl_file: Option<&Path>, realm: &str) -> Acl {
    acl_for_store(realm, acl_file).unwrap_or_else(|e| {
        let msg = match e {
            Error::AclParse(s) => s,
            other => other.to_string(),
        };
        let lines: Vec<&str> = msg.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if i + 1 == lines.len() {
                eprintln!("{progname}: {line}");
                klog::syslog(Severity::Err, &format!("{line}\n"));
            } else {
                klog::syslog(Severity::Err, line);
            }
        }
        std::process::exit(1);
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
