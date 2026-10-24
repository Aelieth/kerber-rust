//! `kadmind`: the kadm5 (TCP 749) and kpasswd (UDP and TCP 464) daemon, started as MIT's.
//! ```text
//! kadmind [-x db_args]* [-r realm] [-m] [-nofork] [-port port-number] [-proponly]
//!         [-p path-to-kdb5_util] [-F dump-file] [-K path-to-kprop] [-k kprop-port]
//!         [-P pid_file]
//! ```
//! - `-proponly` sets up the iprop listeners alone; without `iprop_enable` it is refused with MIT's text (`-proponly can only be used when iprop_enable is true`).
//!
//! With `iprop_enable` set for the realm, kadmind maps the update log as the primary's, logs every principal put and delete there, and serves the iprop program (100423); without it the log is never touched and the program is not served.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![allow(
    clippy::disallowed_methods,
    reason = "a program reads its profile and environment when it starts"
)]

use std::io::Write as _;
#[cfg(feature = "test-hooks")]
use std::net::{TcpListener, UdpSocket};
use std::path::Path;
use std::sync::Arc;

use krb5_admin::{
    IpropConfig, Kadmind, KadmindConfig, ServeLimits, Services, StartError, serve_kadmind,
};
use krb5_cli::{MitArgs, MitOpt, Placement};
use krb5_kdc::net_server::Sockets;
use krb5_kdc::{
    Acl, Error, IpropRole, OpenFailure, PrincipalStore, Signals, acl_for_store,
    copy_persist_master, detach, kadmind_mkey_from_kbd, names_relative_database, open_database,
    open_database_with_key, open_database_with_password, shared_dump as shared_store,
    write_pid_file,
};
use krb5_log::klog::{self, JsonLog, Severity, os_error_text};

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

// MIT: `usage` (kadmin/server/ovsec_kadmd.c:80-91)
/// the text on standard error, then exit 1.
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

// MIT: `fail_to_start` (kadmin/server/ovsec_kadmd.c:100-114)
/// with an error, `<error> while <doing>, aborting` (the log line keeps MIT's trailing newline); without, `<what>, aborting`.
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

/// Map a `Listeners::bind` failure to MIT's two paths: a bad or empty listen list stops kadmind
/// "while initializing network"; a socket that will not bind has already been logged by the bind
/// helper ("Error setting up network"), so this just exits 1, as MIT and the tip do.
fn bind_fail(progname: &str, e: StartError) -> ! {
    match e {
        StartError::Bind(_) => std::process::exit(1),
        StartError::Listen(msg) => fail_to_start(progname, Some(&msg), "initializing network"),
        other => fail_to_start(progname, Some(&other.to_string()), "initializing network"),
    }
}

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

fn progname(argv0: Option<&String>) -> String {
    argv0
        .map(|a| a.rsplit('/').next().unwrap_or(a).to_owned())
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| "kadmind".to_owned())
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let progname = progname(argv.first());

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
    let pinned: Option<String> = match args.operands.as_slice() {
        [] => None,
        #[cfg(feature = "test-hooks")]
        [addr] => Some(addr.clone()),
        _ => usage(),
    };
    let nofork = args.flag("-nofork") || test_realm || pinned.is_some();

    // the KDC context once the options are read; a profile it refuses ends kadmind.
    let profile_read = krb5_config::ReadOnce::start();
    if let Err(e) = krb5_config::init_kdc_profile() {
        eprintln!(
            "{progname}: {} while initializing context, aborting",
            e.init_text()
        );
        std::process::exit(1);
    }

    let specs = krb5_config::LogSpecs::load("admin_server");
    klog::init(&progname, &specs.specs, specs.debug);
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
    let (store, paths) = open_realm(&progname, &args, test_realm, nofork);
    let realm = store.realm().to_owned();
    let iprop = krb5_config::IpropParams::load(&realm, &paths.database_name);
    if iprop.missing_required() || krb5_kdc::realm_kadm5_params_missing(&paths, &realm, true) {
        fail_to_start(
            &progname,
            Some(krb5_config::MISSING_CONF_PARAMS),
            "initializing",
        );
    }
    let profile = krb5_config::ProfileSet::from_env_files(&paths)
        .unwrap_or_else(|e| fail_to_start(&progname, Some(&e.init_text()), "initializing context"));
    drop(profile_read);
    for line in profile
        .kdc
        .iter()
        .flat_map(krb5_config::KdcConf::unsupported_lines)
    {
        klog::syslog(Severity::Warning, &line);
    }
    #[cfg(feature = "test-hooks")]
    let persist = store.persist_paths.clone();
    let keyboard = kadmind_mkey_from_kbd(args.flag("-m"));
    let held_master = if keyboard {
        copy_persist_master(&store)
    } else {
        None
    };
    let shared = shared_store(store);
    // Before the network, as MIT does.
    Kadmind::prepare_store(&shared, &profile).unwrap_or_else(|e| match e {
        StartError::Pwqual(err) => {
            fail_to_start(&progname, Some(&os_error_text(&err)), "initializing")
        }
        StartError::Config(msg) => {
            fail_to_start(&progname, Some(&msg), "getting config parameters")
        }
        other => fail_to_start(&progname, Some(&other.to_string()), "initializing"),
    });
    let proponly = args.flag("-proponly");
    if proponly && !iprop.enabled {
        fail_to_start(
            &progname,
            None,
            "-proponly can only be used when iprop_enable is true",
        );
    }
    let port_arg = args.value("-port").map(|p| {
        let [a, b, c, d, ..] = atoi(p).to_le_bytes();
        i32::from_le_bytes([a, b, c, d])
    });
    let listen =
        krb5_config::KadmindListen::for_realm(Some(&profile.kdc_context), &realm, port_arg);
    let services = Services {
        kpasswd_udp: !proponly,
        kpasswd_tcp: !proponly,
        kadm5: !proponly,
        iprop: iprop.enabled,
    };
    let iprop_cfg = iprop.enabled.then(|| IpropConfig {
        listen: iprop.listen.clone(),
        port: iprop.port.unwrap_or_default(),
        dump_file: Some(
            args.value("-F")
                .map_or_else(krb5_config::default_kprop_file, std::path::PathBuf::from),
        ),
        kprop_port: args
            .value("-k")
            .map(str::to_owned)
            .or_else(|| std::env::var("KPROP_PORT").ok()),
    });

    let signals = Signals::install();
    // MIT sets up the network before the names check; test-hooks hands pre-bound sockets.
    #[cfg(feature = "test-hooks")]
    let listeners = if test_realm || pinned.is_some() {
        let (rpc, udp, tcp) = legacy_sockets(&progname, pinned);
        krb5_admin::Listeners::from_sockets(udp, tcp, rpc, krb5_admin::Programs::BOTH)
    } else {
        krb5_admin::Listeners::bind(
            &listen,
            services,
            iprop_cfg.as_ref(),
            &krb5_admin::KlogAdmin,
        )
        .unwrap_or_else(|e| bind_fail(&progname, e))
    };
    #[cfg(not(feature = "test-hooks"))]
    let listeners = krb5_admin::Listeners::bind(
        &listen,
        services,
        iprop_cfg.as_ref(),
        &krb5_admin::KlogAdmin,
    )
    .unwrap_or_else(|e| bind_fail(&progname, e));
    let socket_fds: Vec<i32> = {
        let s = listeners.sockets();
        let mut fds: Vec<i32> = s
            .rpc
            .iter()
            .map(std::os::fd::AsRawFd::as_raw_fd)
            .chain(s.udp.iter().map(std::os::fd::AsRawFd::as_raw_fd))
            .chain(s.tcp.iter().map(std::os::fd::AsRawFd::as_raw_fd))
            .collect();
        fds.sort_unstable_by(|a, b| b.cmp(a));
        fds
    };
    let acl = load_acl(&progname, paths.acl_file.as_deref(), &realm);
    let cfg = KadmindConfig {
        profile: Arc::new(profile),
        services,
        listen,
        limits: ServeLimits::default(),
        acl,
        auth_modules: Vec::new(),
        log: std::sync::Arc::new(krb5_admin::KlogAdmin),
        pwqual: Vec::new(),
        hooks: Vec::new(),
        iprop: iprop_cfg,
    };
    // Before daemonizing, as MIT does; the names check is after the network above.
    let mut kadmind = Kadmind::new(Arc::clone(&shared), cfg)
        .unwrap_or_else(|e| match e {
            StartError::Pwqual(err) => {
                fail_to_start(&progname, Some(&os_error_text(&err)), "initializing")
            }
            StartError::Config(msg) => {
                fail_to_start(&progname, Some(&msg), "getting config parameters")
            }
            StartError::AcceptorNames => {
                fail_to_start(&progname, None, "Cannot set GSSAPI authentication names")
            }
            other => fail_to_start(&progname, Some(&other.to_string()), "initializing"),
        })
        .serve_programs(listeners.programs())
        .report_unhandled(Arc::new(|message| {
            let _ = writeln!(std::io::stderr(), "kadm5: {message}");
        }));

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
    {
        let s = listeners.sockets();
        announce(
            &progname,
            persist.as_ref(),
            s.rpc,
            kadmind.serves_kpasswd().then_some((s.udp, s.tcp)),
        );
    }
    let full = listeners.sockets();
    let sockets = if kadmind.serves_kpasswd() {
        full
    } else {
        eprintln!("{progname}: no kadmin/changepw keys (RFC 3244 not listening)");
        Sockets {
            rpc: full.rpc,
            ..Sockets::default()
        }
    };
    klog::syslog(Severity::Info, "starting");
    if nofork {
        eprintln!("{progname}: starting...");
    }
    let open = serve_kadmind(&mut kadmind, &sockets, &signals).unwrap_or_else(|e| {
        klog::com_err(Some(&e.to_string()), "while serving");
        eprintln!("{progname}: serve: {e}");
        std::process::exit(1);
    });
    klog::syslog(Severity::Info, "finished, exiting");
    for fd in open.into_iter().chain(socket_fds) {
        klog::syslog(Severity::Info, &format!("closing down fd {fd}"));
    }
    klog::close();
    std::process::exit(0);
}

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
    if nofork && keyboard {
        store =
            open_database_with_password(&paths, &db_args, "K/M", &realm_name).unwrap_or_else(|e| {
                let (OpenFailure::Database(msg) | OpenFailure::MasterKey(msg)) = e;
                fail_to_start(progname, Some(&msg), "initializing")
            });
    }
    (store, paths)
}

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
