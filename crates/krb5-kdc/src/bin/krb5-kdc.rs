//! `krb5kdc`: the KDC daemon, started as MIT's.
//!
//! ```text
//! krb5kdc [-x db_args]* [-d dbpathname] [-r dbrealmname] [-R replaycachename] [-m]
//!         [-k masterenctype] [-M masterkeyname] [-p port] [-P pid_file] [-n]
//!         [-w numworkers] [-T time_offset]
//! ```
//!
//! The options are read as MIT's `getopt` loop reads them; an option written after `-r` would
//! apply to a next realm, so here it applies to none.
//!
//! - `-r` names the realm, else krb5.conf's `default_realm`; one realm per process.
//! - The database and stash are where [`krb5_config::KdcPaths`] finds them: the realm's
//!   `database_name` / `key_stash_file` in kdc.conf, else MIT's defaults; a `test-hooks` build
//!   (the gates') takes `KRB5_KDC_DB` / `KRB5_KDC_STASH` first when they are set.
//! - `-d PATH` and `-x dbname=PATH` name the database instead of kdc.conf's `database_name`;
//!   `-x temporary` opens `PATH~`; `-x merge_nra` and `-x hash=…` are accepted; any other `-x`
//!   stops the KDC as MIT's database module does.
//! - `-p PORTS` replaces the default listener list (`[kdcdefaults]`, else 88) unless the realm
//!   stanza writes its own `kdc_listen` / `kdc_ports`.
//! - `-n` keeps the KDC in the foreground. Without it the KDC binds its sockets, detaches
//!   (`daemon(3)`) and then writes the `-P` pid file.
//! - `-w N` is accepted (requests already run on threads); `-R`, `-4` and `-X` are ignored; `-k`
//!   is only checked; `-M` must be `K/M`; `-T` must be 0. `-m` is ignored when the realm stanza
//!   names `key_stash_file`, as in MIT; otherwise the KDC stops as MIT's does when it cannot
//!   read the master password.
//!
//! The daemon log ([`krb5_log::klog`]) goes where `[logging] kdc` (else `default`) in kdc.conf
//! and krb5.conf says, in MIT's line format, and SIGHUP reopens its files. The JSON structured
//! log stays on standard output.
//!
//! Builds with the `test-hooks` feature also take the gates' forms, which stay in the
//! foreground: `--test-realm` (the documented `KERBER.TEST` realm), `--export-keytab PATH`,
//! `--export-krbtgt-keytab PATH`, `--export-pkinit DIR`, a `host:port` operand or
//! `KRB5_KDC_BIND` (one listener pair), and the test environment the gates set.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;

use krb5_crypto::EncryptionType;
use krb5_kdc::{
    ListenLimits, OpenFailure, PrincipalStore, Signals, bind_tcp_listeners, bind_udp_listeners,
    detach, names_relative_database, open_database, serve_all_until, shared_store, write_pid_file,
};
use krb5_log::klog::{self, JsonLog, Severity, os_error_text};

/// MIT `initialize_realms` (`kdc/main.c:669-669`): krb5kdc's option letters.
const OPTSTRING: &str = "x:r:d:mM:k:R:P:p:nw:4:T:X3";

/// MIT `usage` (`kdc/main.c:582-595`): the text on standard error, then exit 1.
fn usage(progname: &str) -> ! {
    eprint!(
        "usage: {progname} [-x db_args]* [-d dbpathname] [-r dbrealmname]\n\
         \t\t[-T time_offset] [-m] [-k masterenctype]\n\
         \t\t[-M masterkeyname] [-p port] [-P pid_file]\n\
         \t\t[-n] [-w numworkers] [/]\n\
         \n\
         where,\n\
         \t[-x db_args]* - Any number of database specific arguments.\n\
         \t\t\tLook at each database module documentation for \t\t\tsupported arguments\n"
    );
    std::process::exit(1);
}

/// What `-r` (or the end of the options, when there is no `-r`) took for the realm.
#[derive(Clone, Default)]
struct RealmArgs {
    db_args: Vec<String>,
    listen: Option<String>,
    manual: bool,
    mkey_name: Option<String>,
}

/// The command line.
#[derive(Default)]
struct Options {
    realm: Option<String>,
    /// A second realm: this KDC serves one.
    extra_realm: Option<String>,
    args: RealmArgs,
    pid_file: Option<PathBuf>,
    nofork: bool,
    time_offset: i64,
    operands: Vec<String>,
    #[cfg(feature = "test-hooks")]
    hooks: hooks::Args,
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

/// MIT `initialize_realms` (`kdc/main.c:668-787`): each option in order; `-r` takes the options
/// before it for its realm and starts the database arguments over; with no `-r` the realm takes
/// them all. A bad option or `-w` below 1 prints the usage.
fn parse_options(progname: &str, args: &[String]) -> Options {
    #[cfg(feature = "test-hooks")]
    let longs = hooks::LONGS;
    #[cfg(not(feature = "test-hooks"))]
    let longs: &[krb5_cli::LongOpt] = &[];
    let (opts, operands) = krb5_cli::getopt(args, OPTSTRING, longs).unwrap_or_else(|msg| {
        eprintln!("{progname}: {msg}");
        usage(progname)
    });
    let mut out = Options {
        operands,
        ..Options::default()
    };
    let mut cur = RealmArgs::default();
    let mut db_name: Option<String> = None;
    let mut taken: Option<RealmArgs> = None;
    for o in opts {
        let arg = o.arg.unwrap_or_default();
        #[cfg(feature = "test-hooks")]
        if let Some(name) = o.long {
            out.hooks.take(name, arg);
            continue;
        }
        match o.flag {
            'x' => cur.db_args.push(arg),
            'r' => match &out.realm {
                None => {
                    out.realm = Some(arg);
                    taken = Some(RealmArgs {
                        db_args: std::mem::take(&mut cur.db_args),
                        ..cur.clone()
                    });
                }
                Some(r) if *r != arg => {
                    out.extra_realm.get_or_insert(arg);
                }
                Some(_) => {}
            },
            'd' => {
                let name = db_name.get_or_insert_with(|| format!("dbname={arg}"));
                cur.db_args.push(name.clone());
            }
            'm' => cur.manual = true,
            'M' => cur.mkey_name = Some(arg),
            'n' => out.nofork = true,
            'w' if atoi(&arg) > 0 => {}
            'k' => {
                if EncryptionType::from_mit_name(&arg).is_err() {
                    klog::com_err(None, &format!("invalid enctype {arg}"));
                }
            }
            'R' | '4' | 'X' => {}
            'P' => out.pid_file = Some(PathBuf::from(arg)),
            'p' => cur.listen = Some(arg),
            'T' => out.time_offset = atoi(&arg),
            _ => usage(progname),
        }
    }
    out.args = taken.unwrap_or(cur);
    out
}

/// The basename of `argv[0]`, the name the KDC logs and prints under.
/// MIT `main` (`kdc/main.c:899-900`): `argv[0]` is cut to its last path component.
fn progname(argv0: Option<&String>) -> String {
    argv0
        .map(|a| a.rsplit('/').next().unwrap_or(a).to_owned())
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| "krb5kdc".to_owned())
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let progname = progname(argv.first());
    // MIT `main` (`kdc/main.c:917-921`): the KDC context first, its profile kdc.conf ahead of
    // krb5.conf; a profile it refuses ends krb5kdc, named as invoked.
    if let Err(e) = krb5_config::init_kdc_profile() {
        let argv0 = argv.first().map_or("krb5kdc", String::as_str);
        eprintln!("{argv0}: {} while initializing krb5", e.init_text());
        std::process::exit(1);
    }
    // MIT `main` (`kdc/main.c:917-922`): the daemon log is set up from the profile before the
    // options are read.
    let specs = krb5_config::LogSpecs::load("kdc");
    klog::init(&progname, &specs.specs, specs.debug);
    let opts = parse_options(&progname, argv.get(1..).unwrap_or_default());
    #[cfg(feature = "test-hooks")]
    let foreground = opts.nofork || opts.hooks.foreground(&opts.operands);
    #[cfg(not(feature = "test-hooks"))]
    let foreground = opts.nofork;
    // The JSON log only where `[logging] json` names a destination (MIT has none), standard
    // output or error only in the foreground: a detached KDC has neither.
    if let Some(json) = specs
        .json
        .as_deref()
        .and_then(|s| JsonLog::open(&progname, s))
        && (foreground || json.is_file())
    {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_writer(json.make_writer())
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    "krb5_kdc=info,krb5_crypto=info,krb5_asn1=info,krb5_protocol=warn".into()
                }),
            )
            .try_init();
    }
    if opts.time_offset != 0 {
        eprintln!("{progname}: -T (a clock offset for testing) is not supported");
        std::process::exit(1);
    }
    #[cfg(feature = "test-hooks")]
    let test_realm = opts.hooks.test_realm;
    #[cfg(not(feature = "test-hooks"))]
    let test_realm = false;
    #[cfg(feature = "test-hooks")]
    let realm_arg = if test_realm {
        Some(hooks::test_realm_name())
    } else {
        opts.realm.clone()
    };
    #[cfg(not(feature = "test-hooks"))]
    let realm_arg = opts.realm.clone();
    let paths = krb5_config::KdcPaths::resolve(realm_arg.as_deref()).unwrap_or_else(|e| {
        // MIT `initialize_realms` (`kdc/main.c:793-800`): no realm is logged "while attempting to
        // retrieve default realm" and printed "…, attempting to retrieve default realm", exit 1.
        if matches!(e, krb5_config::Error::NoDefaultRealm) {
            klog::com_err(
                Some(&e.to_string()),
                "while attempting to retrieve default realm",
            );
            eprintln!("{progname}: {e}, attempting to retrieve default realm");
        } else {
            eprintln!("{progname}: {e}");
        }
        std::process::exit(1);
    });
    let realm = paths.realm.clone().unwrap_or_default();
    if let Some(extra) = &opts.extra_realm {
        cannot_initialize(
            &progname,
            extra,
            "Only one realm per KDC process is supported",
            &format!("while initializing database for realm {extra}"),
        );
    }
    let mut kdc_conf = paths.conf.clone();
    #[cfg(feature = "test-hooks")]
    let mut store = if test_realm {
        hooks::test_realm_store(kdc_conf.as_ref())
    } else {
        init_realm(&progname, &realm, &paths, &opts.args)
    };
    #[cfg(not(feature = "test-hooks"))]
    let mut store = init_realm(&progname, &realm, &paths, &opts.args);
    // MIT builds the KDC profile with kdc.conf before krb5.conf, so kdc.conf
    // wins (`init_os_ctx.c add_kdc_config_file`). Apply krb5.conf [libdefaults]
    // first as the base, then let kdc.conf override.
    if let Some(c) = krb5_config::load_krb5_conf() {
        store.set_capaths(c.capaths.clone());
        store.apply_libdefaults(&c);
    }
    if let Some(conf) = &kdc_conf
        && let Err(e) = store.apply_kdc_conf(conf)
    {
        eprintln!("{progname}: kdc.conf: {e}");
        std::process::exit(2);
    }
    #[cfg(feature = "test-hooks")]
    hooks::before_serving(&mut store, &opts.hooks);
    #[cfg(feature = "test-hooks")]
    let persist = store.persist_paths.clone();
    #[cfg(feature = "test-hooks")]
    let env_lib = hooks::db_library();
    #[cfg(not(feature = "test-hooks"))]
    let env_lib: Option<String> = None;
    let lib = env_lib
        .as_deref()
        .or_else(|| kdc_conf.as_ref().and_then(|c| c.db_library.as_deref()));
    let memory = lib == Some("memory");
    let store = if memory {
        shared_store(krb5_kdc::MemoryStore::from_dump(&store))
    } else {
        shared_store(store)
    };
    if let (Some(conf), Some(ports)) = (kdc_conf.as_mut(), opts.args.listen.as_deref()) {
        conf.apply_port_option(ports);
    }
    #[cfg(feature = "test-hooks")]
    let pinned = hooks::pinned(&opts.operands);
    #[cfg(not(feature = "test-hooks"))]
    let pinned: Option<String> = None;
    let _ = &opts.operands;
    // MIT `main` (`kdc/main.c:976-983`): the signal handlers are set up before the network.
    let signals = Signals::install();
    // MIT `loop_setup_network` (`lib/apputils/net-server.c:1068-1074`): the network lines around
    // binding every listener.
    klog::syslog(Severity::Info, "setting up network...");
    let (udp, tcp) = bind_sockets(
        &progname,
        test_realm,
        pinned,
        kdc_conf.as_ref(),
        opts.args.listen.as_deref(),
    );
    klog::syslog(
        Severity::Info,
        &format!("set up {} sockets", udp.len() + tcp.len()),
    );
    // MIT `main` (`kdc/main.c:996-1008`): detach unless -n, then the pid file, each failure
    // logged and fatal.
    if !foreground && let Err(e) = detach() {
        klog::com_err(Some(&os_error_text(&e)), "while detaching from tty");
        std::process::exit(1);
    }
    if let Some(pid_file) = &opts.pid_file
        && let Err(e) = write_pid_file(pid_file)
    {
        klog::com_err(Some(&os_error_text(&e)), "while creating PID file");
        std::process::exit(1);
    }
    // MIT `main` (`kdc/main.c:1016-1016`): the realm is opened again after daemon(), so a
    // relative database or stash name now opens from `/`, or the KDC stops as at its start.
    if !foreground && names_relative_database(&paths, &opts.args.db_args) {
        let _ = init_realm(&progname, &realm, &paths, &opts.args);
        let mut s = store
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(e) = krb5_kdc::StoreLifecycle::reload_if_stale(&mut **s) {
            cannot_initialize(
                &progname,
                &realm,
                &e.to_string(),
                &format!("while initializing database for realm {realm}"),
            );
        }
    }
    #[cfg(feature = "test-hooks")]
    hooks::announce(&progname, persist.as_ref(), memory, &udp, &tcp);
    signals.spawn_log_reopener();
    // MIT `main` (`kdc/main.c:1025-1028`): "commencing operation", and in the foreground
    // "<prog>: starting..." on standard error.
    klog::syslog(Severity::Info, "commencing operation");
    if foreground {
        eprintln!("{progname}: starting...");
    }
    krb5_kdc::current_audit().kdc_start(true);
    let served = serve_all_until(
        store,
        udp,
        tcp,
        signals.stop_flag(),
        ListenLimits::default(),
    );
    if signals.stop_requested() {
        klog::syslog(Severity::Debug, "Got signal to request exit");
    }
    if let Err(e) = served {
        krb5_kdc::current_audit().kdc_stop(false);
        klog::com_err(Some(&e.to_string()), "while serving");
        eprintln!("{progname}: serve: {e}");
        std::process::exit(1);
    }
    krb5_kdc::current_audit().kdc_stop(true);
    // MIT `main` (`kdc/main.c:1031-1032`): "shutting down" once the loop ends.
    klog::syslog(Severity::Info, "shutting down");
    klog::close();
}

/// The realm cannot start: the reason to the daemon log, MIT's line on standard error, exit 1.
/// MIT `initialize_realms` (`kdc/main.c:688-698`): "cannot initialize realm … - see log file for
/// details" after `init_realm` logged why.
fn cannot_initialize(progname: &str, realm: &str, error: &str, during: &str) -> ! {
    klog::com_err(Some(error), during);
    eprintln!("{progname}: cannot initialize realm {realm} - see log file for details");
    std::process::exit(1);
}

/// Open the realm's database as MIT `init_realm` does; each failure is logged and stops the KDC.
/// MIT `init_realm` (`kdc/main.c:351-382`): open the database, then fetch the master key from the
/// stash, or from the keyboard with `-m` when kdc.conf names no stash.
fn init_realm(
    progname: &str,
    realm: &str,
    paths: &krb5_config::KdcPaths,
    args: &RealmArgs,
) -> PrincipalStore {
    let opening = format!("while initializing database for realm {realm}");
    let mkey_name = args.mkey_name.as_deref().unwrap_or("K/M");
    let fetching = format!("while fetching master key {mkey_name} for realm {realm}");
    // MIT `init_realm` (`kdc/main.c:285-290`): `-m` counts only when kdc.conf names no stash.
    #[cfg(feature = "test-hooks")]
    let stash_env = std::env::var_os("KRB5_KDC_STASH").is_some();
    #[cfg(not(feature = "test-hooks"))]
    let stash_env = false;
    let stash_relation = paths
        .conf
        .as_ref()
        .is_some_and(|c| c.key_stash_file.is_some())
        || stash_env;
    let keyboard = args.manual && !stash_relation;
    match open_database(paths, &args.db_args, mkey_name) {
        Err(OpenFailure::Database(e)) => cannot_initialize(progname, realm, &e, &opening),
        _ if keyboard => cannot_initialize(progname, realm, "Cannot read password", &fetching),
        Err(OpenFailure::MasterKey(e)) => cannot_initialize(progname, realm, &e, &fetching),
        Ok(store) => store,
    }
}

/// The listening sockets. A pinned address (test-hooks builds) binds one UDP + TCP pair on it,
/// and `--test-realm` alone on the first loopback candidate that binds. Otherwise the KDC
/// listens where MIT's would: every `kdc_listen` / `kdc_ports` entry (after `-p`) for UDP and
/// every `kdc_tcp_listen` / `kdc_tcp_ports` entry (else the UDP list) for TCP, a bare port on
/// all local addresses, port 88 when nothing names one. A bind failure is logged and fatal.
/// MIT `main` (`kdc/main.c:960-973`): UDP and TCP listeners for each realm's lists.
fn bind_sockets(
    progname: &str,
    test_realm: bool,
    pinned: Option<String>,
    conf: Option<&krb5_config::KdcConf>,
    ports: Option<&str>,
) -> (Vec<UdpSocket>, Vec<TcpListener>) {
    #[cfg(feature = "test-hooks")]
    if pinned.is_some() || test_realm {
        return hooks::bind_pinned(pinned);
    }
    let _ = (test_realm, pinned);
    let mut default_conf = krb5_config::KdcConf::default();
    if let Some(p) = ports {
        default_conf.apply_port_option(p);
    }
    let conf = conf.unwrap_or(&default_conf);
    let lists = conf
        .kdc_udp_listeners()
        .and_then(|u| conf.kdc_tcp_listeners().map(|t| (u, t)));
    let (udp_addrs, tcp_addrs) = lists.unwrap_or_else(|e| {
        eprintln!("{progname}: kdc.conf: {e}");
        std::process::exit(1);
    });
    let udp = bind_udp_listeners(&udp_addrs).unwrap_or_else(|_| std::process::exit(1));
    let tcp = bind_tcp_listeners(&tcp_addrs).unwrap_or_else(|_| std::process::exit(1));
    (udp, tcp)
}

/// The gates' test realm, key exports and environment hooks; off in a release build.
#[cfg(feature = "test-hooks")]
mod hooks {
    use std::net::{TcpListener, UdpSocket};
    use std::path::PathBuf;

    use krb5_cli::LongOpt;
    use krb5_kdc::principals::{kadmin_admin, kadmin_changepw};
    use krb5_kdc::testrealm::{TEST_ADMIN, TEST_REALM, TEST_USER, documented_kiprop};
    use krb5_kdc::{
        Acl, BIND_CANDIDATES, KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_DUP_SKEY, KDB_DISALLOW_SVR,
        KDB_OK_TO_AUTH_AS_DELEGATE, PrincipalStore, apply_kadm5_create_service_attrs,
        bind_preferred,
    };

    /// The gates' long options.
    pub(super) const LONGS: &[LongOpt] = &[
        LongOpt {
            name: "test-realm",
            takes_arg: false,
            short: None,
        },
        LongOpt {
            name: "export-keytab",
            takes_arg: true,
            short: None,
        },
        LongOpt {
            name: "export-krbtgt-keytab",
            takes_arg: true,
            short: None,
        },
        LongOpt {
            name: "export-pkinit",
            takes_arg: true,
            short: None,
        },
    ];

    /// The gates' arguments.
    #[derive(Default)]
    pub(super) struct Args {
        pub(super) test_realm: bool,
        export_keytab: Option<String>,
        export_krbtgt: Option<String>,
        export_pkinit: Option<String>,
    }

    impl Args {
        pub(super) fn take(&mut self, name: &str, arg: String) {
            match name {
                "test-realm" => self.test_realm = true,
                "export-keytab" => self.export_keytab = Some(arg),
                "export-krbtgt-keytab" => self.export_krbtgt = Some(arg),
                "export-pkinit" => self.export_pkinit = Some(arg),
                _ => {}
            }
        }

        /// The gates' forms run in the foreground, as the KDC did before it detached.
        pub(super) fn foreground(&self, operands: &[String]) -> bool {
            self.test_realm
                || self.export_keytab.is_some()
                || self.export_krbtgt.is_some()
                || self.export_pkinit.is_some()
                || pinned(operands).is_some()
        }
    }

    /// The one address to bind: the first operand, else `KRB5_KDC_BIND`.
    pub(super) fn pinned(operands: &[String]) -> Option<String> {
        operands
            .first()
            .cloned()
            .or_else(|| std::env::var("KRB5_KDC_BIND").ok())
    }

    /// The test realm's name keeps the stash default from needing krb5.conf's default_realm.
    pub(super) fn test_realm_name() -> String {
        std::env::var("KRB5_TEST_REALM").unwrap_or_else(|_| TEST_REALM.to_owned())
    }

    /// The bootstrapped test realm, saved to and reloaded from `KRB5_KDC_DB` / `KRB5_KDC_STASH`
    /// when both are set.
    pub(super) fn test_realm_store(kdc: Option<&krb5_config::KdcConf>) -> PrincipalStore {
        let store = bootstrap_test_realm(kdc);
        if let (Ok(db), Ok(stash)) = (
            std::env::var("KRB5_KDC_DB"),
            std::env::var("KRB5_KDC_STASH"),
        ) {
            let db = std::path::PathBuf::from(db);
            let stash = std::path::PathBuf::from(stash);
            if let Err(e) = krb5_kdc::save_store(&store, &db, &stash) {
                eprintln!("krb5-kdc: save store: {e}");
                std::process::exit(1);
            }
            return krb5_kdc::load_store(&db, &stash).unwrap_or_else(|e| {
                eprintln!("krb5-kdc: reload store: {e}");
                std::process::exit(1);
            });
        }
        store
    }

    /// One UDP + TCP pair on the pinned address, else on the first loopback candidate.
    pub(super) fn bind_pinned(pinned: Option<String>) -> (Vec<UdpSocket>, Vec<TcpListener>) {
        let owned: Vec<String> = pinned.map_or_else(
            || BIND_CANDIDATES.iter().map(|s| (*s).to_owned()).collect(),
            |b| vec![b],
        );
        let candidates: Vec<&str> = owned.iter().map(String::as_str).collect();
        let (_, udp, tcp) = bind_preferred(&candidates).unwrap_or_else(|e| {
            eprintln!("krb5-kdc: bind failed: {e}");
            std::process::exit(1);
        });
        (vec![udp], vec![tcp])
    }

    /// The test policy, audit sink, PKINIT CA and key exports.
    pub(super) fn before_serving(store: &mut PrincipalStore, args: &Args) {
        if std::env::var("KRB5_KDCPOLICY").ok().as_deref() == Some("test") {
            krb5_kdc::set_policy(std::sync::Arc::new(krb5_kdc::testrealm::TestPolicy));
        }
        if std::env::var("KRB5_KDC_AUDIT").ok().as_deref() == Some("test") {
            let path = std::env::var("KRB5_KDC_AUDIT_LOG").unwrap_or_else(|_| "au.log".into());
            match krb5_kdc::testrealm::TestAudit::open(&path) {
                Ok(a) => krb5_kdc::set_audit(std::sync::Arc::new(a)),
                Err(e) => {
                    eprintln!("krb5-kdc: KRB5_KDC_AUDIT_LOG {path}: {e}");
                    std::process::exit(1);
                }
            }
        }
        let enable_pkinit = args.export_pkinit.is_some()
            || std::env::var("KRB5_ENABLE_PKINIT").ok().as_deref() == Some("1");
        if enable_pkinit && let Err(e) = store.enable_pkinit_ca() {
            eprintln!("krb5-kdc: PKINIT CA: {e}");
            std::process::exit(1);
        }
        let export_keytab = args
            .export_keytab
            .clone()
            .or_else(|| std::env::var("KRB5_EXPORT_KEYTAB").ok());
        let export_krbtgt = args
            .export_krbtgt
            .clone()
            .or_else(|| std::env::var("KRB5_EXPORT_KRBTGT_KEYTAB").ok());
        if let Some(path) = export_keytab.as_ref() {
            let host_inst = std::env::var("KRB5_TEST_HOST").unwrap_or_else(|_| {
                if store.realm() == TEST_REALM {
                    krb5_kdc::testrealm::TEST_HOST.to_owned()
                } else {
                    "svc.other.test".into()
                }
            });
            let host = krb5_types::PrincipalName::new(
                krb5_types::PrincipalName::NT_SRV_HST,
                ["host", host_inst.as_str()],
            );
            export(store, &host, path, "export-keytab", "keytab");
        }
        if let (Ok(path), Ok(extra_inst)) = (
            std::env::var("KRB5_EXPORT_KEYTAB_EXTRA"),
            std::env::var("KRB5_TEST_EXTRA_HOST"),
        ) {
            let extra = krb5_types::PrincipalName::new(
                krb5_types::PrincipalName::NT_SRV_HST,
                ["host", extra_inst.as_str()],
            );
            export(store, &extra, &path, "export-keytab-extra", "keytab-extra");
        }
        if let Some(path) = export_krbtgt.as_ref() {
            let tgt = krb5_types::PrincipalName::krbtgt(store.realm());
            export(store, &tgt, path, "export-krbtgt-keytab", "krbtgt-keytab");
        }
        if let Some(dir) = args.export_pkinit.as_ref() {
            export_pkinit(store, dir);
        }
    }

    fn export(
        store: &PrincipalStore,
        name: &krb5_types::PrincipalName,
        path: &str,
        what: &str,
        label: &str,
    ) {
        match store.export_keytab_local(name) {
            Ok(kt) => {
                if let Err(e) = kt.write_file(path) {
                    eprintln!("krb5-kdc: {what} {path}: {e}");
                    std::process::exit(1);
                }
                println!("{label} {path}");
            }
            Err(e) => {
                eprintln!("krb5-kdc: {what}: {e}");
                std::process::exit(1);
            }
        }
    }

    fn export_pkinit(store: &PrincipalStore, dir: &str) {
        let _ = std::fs::create_dir_all(dir);
        if let Some(pem) = store.pkinit_anchor_pem() {
            let _ = std::fs::write(format!("{dir}/ca.pem"), pem);
            println!("pkinit-ca {dir}/ca.pem");
        }
        if let Some(pem) = store.pkinit_user_pem("user@KERBER.TEST") {
            let _ = std::fs::write(format!("{dir}/user.pem"), pem);
            println!("pkinit-user {dir}/user.pem");
        }
        if let Some(pem) = store.pkinit_user_pem("other@KERBER.TEST") {
            let _ = std::fs::write(format!("{dir}/other.pem"), pem);
            println!("pkinit-other {dir}/other.pem");
        }
        if let Some(pem) = store.pkinit_kdc_pem() {
            let _ = std::fs::write(format!("{dir}/kdc.pem"), pem);
            println!("pkinit-kdc {dir}/kdc.pem");
        }
        if let Some(pem) = store
            .pkinit_ca()
            .and_then(|c| c.kdc_identity_pem_for("OTHER.TEST"))
        {
            let _ = std::fs::write(format!("{dir}/kdc-wrong-realm.pem"), pem);
            println!("pkinit-kdc-wrong-realm {dir}/kdc-wrong-realm.pem");
        }
    }

    /// The greet authdata module of MIT's test plugins, when `KERBER_KDC_GREET=1`.
    fn authdata() {
        if std::env::var("KERBER_KDC_GREET").ok().as_deref() == Some("1") {
            krb5_kdc::register_authdata(std::sync::Arc::new(krb5_kdc::testrealm::GreetAuth));
        }
    }

    /// The store gate's backend selector (`memory`), over kdc.conf's `db_library`.
    pub(super) fn db_library() -> Option<String> {
        std::env::var("KRB5_KDC_DB_LIBRARY").ok()
    }

    /// The gates' readiness lines on standard output (`persist`, `backend`, one `listening`
    /// line per UDP address and a `listening tcp` line for a TCP address that is not also a UDP
    /// one), the authdata hook, and the privilege drop of a KDC that serves no database file.
    pub(super) fn announce(
        progname: &str,
        persist: Option<&(PathBuf, PathBuf)>,
        memory: bool,
        udp: &[UdpSocket],
        tcp: &[TcpListener],
    ) {
        match persist {
            Some((db, stash)) => println!("persist {} {}", db.display(), stash.display()),
            None => println!("persist none"),
        }
        println!("backend {}", if memory { "memory" } else { "dump" });
        // Kadmind writes the db as the kadmind uid (root in the gate). Dropping
        // to nobody would make 0600 persist files unreadable on reload.
        if persist.is_none() {
            match krb5_kdc::drop_privileges() {
                Ok(true) => eprintln!("{progname}: dropped privileges"),
                Ok(false) => {}
                Err(e) => {
                    eprintln!("{progname}: privilege drop: {e}");
                    std::process::exit(1);
                }
            }
        } else {
            eprintln!("{progname}: privilege drop skipped (shared persist db)");
        }
        authdata();
        let udp_addrs: Vec<_> = udp.iter().filter_map(|u| u.local_addr().ok()).collect();
        for a in &udp_addrs {
            println!("listening {a}");
        }
        for a in tcp.iter().filter_map(|t| t.local_addr().ok()) {
            if !udp_addrs.contains(&a) {
                println!("listening tcp {a}");
            }
        }
    }

    fn bootstrap_test_realm(kdc: Option<&krb5_config::KdcConf>) -> PrincipalStore {
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
        let realm = test_realm_name();
        let mut store = PrincipalStore::bootstrap_with_kdc_conf(
            &realm,
            TEST_USER,
            user_pw.as_bytes(),
            TEST_ADMIN,
            admin_pw.as_bytes(),
            kdc,
        )
        .unwrap_or_else(|e| {
            eprintln!("krb5-kdc: bootstrap: {e}");
            std::process::exit(1);
        });
        let actor = format!("{TEST_ADMIN}@{realm}");
        let acl = Acl::allow_admin(&actor).unwrap_or_else(|e| {
            eprintln!("krb5-kdc: acl: {e}");
            std::process::exit(1);
        });
        let host_inst = std::env::var("KRB5_TEST_HOST").unwrap_or_else(|_| {
            if realm == TEST_REALM {
                krb5_kdc::testrealm::TEST_HOST.to_owned()
            } else {
                "svc.other.test".into()
            }
        });
        let host = krb5_types::PrincipalName::new(
            krb5_types::PrincipalName::NT_SRV_HST,
            ["host", host_inst.as_str()],
        );
        if let Err(e) = store.create_host(&acl, &actor, &host) {
            eprintln!("krb5-kdc: host principal: {e}");
            std::process::exit(1);
        }
        if std::env::var("KRB5_TEST_OK_TO_AUTH_AS_DELEGATE").as_deref() == Ok("1") {
            add_attribute(
                &mut store,
                &host,
                KDB_OK_TO_AUTH_AS_DELEGATE,
                "ok_to_auth_as_delegate",
            );
        }
        if let Ok(targets) = std::env::var("KRB5_TEST_S4U_TO") {
            for to in targets.split(',') {
                let to = to.trim();
                if !to.is_empty() {
                    store.allow_s4u_to(&host, to);
                }
            }
        }
        if let Ok(froms) = std::env::var("KRB5_TEST_S4U_FROM") {
            for from in froms.split(',') {
                let from = from.trim();
                if !from.is_empty() {
                    store.allow_s4u_from(&host, from);
                }
            }
        }
        if let Ok(extra_inst) = std::env::var("KRB5_TEST_EXTRA_HOST") {
            let extra = krb5_types::PrincipalName::new(
                krb5_types::PrincipalName::NT_SRV_HST,
                ["host", extra_inst.as_str()],
            );
            if let Err(e) = store.create_host(&acl, &actor, &extra) {
                eprintln!("krb5-kdc: extra host principal: {e}");
                std::process::exit(1);
            }
            if let Ok(froms) = std::env::var("KRB5_TEST_S4U_FROM") {
                for from in froms.split(',') {
                    let from = from.trim();
                    if !from.is_empty() {
                        store.allow_s4u_from(&extra, from);
                    }
                }
            }
        }
        if std::env::var("KRB5_TEST_DISALLOW_DUP_SKEY").as_deref() == Ok("1") {
            add_attribute(
                &mut store,
                &host,
                KDB_DISALLOW_DUP_SKEY,
                "disallow_dup_skey",
            );
        }
        if let Err(e) = store.create_host(&acl, &actor, &kadmin_admin()) {
            eprintln!("krb5-kdc: kadmin/admin: {e}");
            std::process::exit(1);
        }
        if let Err(e) = store.create_host(&acl, &actor, &kadmin_changepw()) {
            eprintln!("krb5-kdc: kadmin/changepw: {e}");
            std::process::exit(1);
        }
        if let Err(e) = store.create_host(&acl, &actor, &documented_kiprop()) {
            eprintln!("krb5-kdc: kiprop: {e}");
            std::process::exit(1);
        }
        if let Err(e) = apply_kadm5_create_service_attrs(&mut store) {
            eprintln!("krb5-kdc: kadmin service attrs: {e}");
            std::process::exit(1);
        }
        interrealm_keys(&mut store, &acl, &actor);
        apply_test_disallow(&mut store, "KRB5_TEST_DISALLOW_TIX", KDB_DISALLOW_ALL_TIX);
        apply_test_disallow(&mut store, "KRB5_TEST_DISALLOW_SVR", KDB_DISALLOW_SVR);
        if let Ok(pw) = std::env::var("KRB5_TEST_LOCKED_USER")
            && !pw.is_empty()
        {
            let locked =
                krb5_types::PrincipalName::new(krb5_types::PrincipalName::NT_PRINCIPAL, ["locked"]);
            if let Err(e) = store.create_password(&acl, &actor, &locked, pw.as_bytes()) {
                eprintln!("krb5-kdc: locked user: {e}");
                std::process::exit(1);
            }
            if let Err(e) = store.set_status(&locked, true, 0) {
                eprintln!("krb5-kdc: lock user: {e}");
                std::process::exit(1);
            }
        }
        if let Ok(pw) = std::env::var("KRB5_TEST_PW_EXPIRED_USER")
            && !pw.is_empty()
        {
            let expired = krb5_types::PrincipalName::new(
                krb5_types::PrincipalName::NT_PRINCIPAL,
                ["expired"],
            );
            if let Err(e) = store.create_password(&acl, &actor, &expired, pw.as_bytes()) {
                eprintln!("krb5-kdc: expired user: {e}");
                std::process::exit(1);
            }
            if let Err(e) = store.apply_admin_fields(
                &expired,
                krb5_kdc::AdminFields {
                    attributes: None,
                    max_life: None,
                    expiration: None,
                    pw_expire: Some(1),
                    policy: None,
                    clear_policy: false,
                    max_renewable_life: None,
                },
            ) {
                eprintln!("krb5-kdc: expire user: {e}");
                std::process::exit(1);
            }
        }
        store
    }

    /// The test inter-realm keys of `KRB5_TEST_FOREIGN_REALM` / `KRB5_TEST_INTERREALM_KEY`.
    fn interrealm_keys(store: &mut PrincipalStore, acl: &Acl, actor: &str) {
        let (Ok(foreigns), Ok(hexkey)) = (
            std::env::var("KRB5_TEST_FOREIGN_REALM"),
            std::env::var("KRB5_TEST_INTERREALM_KEY"),
        ) else {
            return;
        };
        match parse_hex_key(&hexkey) {
            Ok(key) => {
                for foreign in foreigns.split(',') {
                    let foreign = foreign.trim();
                    if foreign.is_empty() {
                        continue;
                    }
                    if let Err(e) = store.create_interrealm_key(acl, actor, foreign, key.clone()) {
                        eprintln!("krb5-kdc: inter-realm {foreign}: {e}");
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("krb5-kdc: KRB5_TEST_INTERREALM_KEY: {e}");
                std::process::exit(2);
            }
        }
        // Peer-issued tickets (AD outbound) may use a second AES key
        // (Windows TDO inbound/outbound salts differ).
        let Ok(hex2) = std::env::var("KRB5_TEST_INTERREALM_KEY_ACCEPT") else {
            return;
        };
        let mut first = true;
        for part in hex2.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            match parse_hex_key(part) {
                Ok(key) => {
                    for foreign in foreigns.split(',') {
                        let foreign = foreign.trim();
                        if foreign.is_empty() {
                            continue;
                        }
                        let put = if first {
                            store.set_interrealm_decrypt_key(acl, actor, foreign, key.clone())
                        } else {
                            store.add_interrealm_decrypt_key(acl, actor, foreign, key.clone())
                        };
                        if let Err(e) = put {
                            eprintln!("krb5-kdc: inter-realm accept key {foreign}: {e}");
                            std::process::exit(1);
                        }
                    }
                    first = false;
                }
                Err(e) => {
                    eprintln!("krb5-kdc: KRB5_TEST_INTERREALM_KEY_ACCEPT: {e}");
                    std::process::exit(2);
                }
            }
        }
    }

    fn add_attribute(
        store: &mut PrincipalStore,
        name: &krb5_types::PrincipalName,
        flag: u32,
        what: &str,
    ) {
        let a = if let Some(p) = store.get_name(name) {
            p.attributes | flag
        } else {
            eprintln!("krb5-kdc: host missing after create");
            std::process::exit(1);
        };
        if let Err(e) = store.apply_admin_fields(
            name,
            krb5_kdc::AdminFields {
                attributes: Some(a),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        ) {
            eprintln!("krb5-kdc: {what}: {e}");
            std::process::exit(1);
        }
    }

    fn apply_test_disallow(store: &mut PrincipalStore, env: &str, flag: u32) {
        let Ok(spec) = std::env::var(env) else {
            return;
        };
        let spec = spec.trim();
        if spec.is_empty() {
            return;
        }
        let (name_spec, princ_realm) = match spec.rsplit_once('@') {
            Some((n, r)) if !r.is_empty() => (n.trim(), r.to_owned()),
            _ => (spec, store.realm().to_owned()),
        };
        let Some(name) = test_princ(name_spec) else {
            eprintln!("krb5-kdc: {env}: empty principal");
            std::process::exit(2);
        };
        let a = if let Some(p) = store.get_in_realm(&name, &princ_realm) {
            p.attributes | flag
        } else {
            eprintln!("krb5-kdc: {env}: {spec} missing");
            std::process::exit(1);
        };
        if let Err(e) = store.apply_admin_fields_in(
            &name,
            &princ_realm,
            krb5_kdc::AdminFields {
                attributes: Some(a),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
            &format!("kadmin/admin@{princ_realm}"),
        ) {
            eprintln!("krb5-kdc: {env}: {e}");
            std::process::exit(1);
        }
    }

    fn test_princ(spec: &str) -> Option<krb5_types::PrincipalName> {
        let spec = spec.split('@').next().unwrap_or(spec).trim();
        if spec.is_empty() {
            return None;
        }
        if let Some((a, b)) = spec.split_once('/') {
            Some(krb5_types::PrincipalName::new(
                krb5_types::PrincipalName::NT_SRV_INST,
                [a, b],
            ))
        } else {
            Some(krb5_types::PrincipalName::new(
                krb5_types::PrincipalName::NT_PRINCIPAL,
                [spec],
            ))
        }
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
        krb5_crypto::ProtocolKey::from_bytes(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            &bytes,
        )
        .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn atoi_reads_like_c() {
        assert_eq!(atoi("2"), 2);
        assert_eq!(atoi(" 7x"), 7);
        assert_eq!(atoi("abc"), 0);
        assert_eq!(atoi("-3"), -3);
    }

    #[test]
    fn options_after_r_do_not_apply_to_its_realm() {
        let o = parse_options("krb5kdc", &s(&["-n", "-r", "R.TEST", "-p", "7088"]));
        assert_eq!(o.realm.as_deref(), Some("R.TEST"));
        assert_eq!(o.args.listen, None);
        assert!(o.nofork);
        let o = parse_options("krb5kdc", &s(&["-p", "7088", "-r", "R.TEST"]));
        assert_eq!(o.args.listen.as_deref(), Some("7088"));
        let o = parse_options("krb5kdc", &s(&["-p", "7088"]));
        assert_eq!(o.args.listen.as_deref(), Some("7088"));
    }

    #[test]
    fn database_arguments_are_mits_db2_ones() {
        use std::path::Path;
        let d = Path::new("/k/principal");
        let a = |v: &[&str]| krb5_kdc::database_path(d, &s(v));
        assert_eq!(a(&[]).unwrap(), d);
        assert_eq!(a(&["dbname=/x"]).unwrap(), Path::new("/x"));
        assert_eq!(a(&["dbname=/x", "temporary"]).unwrap(), Path::new("/x~"));
        assert_eq!(a(&["merge_nra", "hash=1"]).unwrap(), d);
        assert_eq!(
            a(&["foo"]).unwrap_err(),
            "Unsupported argument \"foo\" for db2"
        );
        assert_eq!(
            a(&["hash"]).unwrap_err(),
            "Unsupported argument \"hash\" for db2"
        );
        assert_eq!(
            a(&["foo=bar"]).unwrap_err(),
            "Unsupported argument \"foo\" for db2"
        );
        let o = parse_options("krb5kdc", &s(&["-d", "/a", "-d", "/b"]));
        assert_eq!(o.args.db_args, ["dbname=/a", "dbname=/a"]);
    }

    #[test]
    fn progname_is_the_basename() {
        assert_eq!(progname(Some(&"/usr/sbin/krb5kdc".to_owned())), "krb5kdc");
        assert_eq!(progname(Some(&"krb5-kdc".to_owned())), "krb5-kdc");
        assert_eq!(progname(None), "krb5kdc");
    }
}
