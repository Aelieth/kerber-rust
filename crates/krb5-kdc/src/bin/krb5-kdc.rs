//! krb5kdc: one realm, started as MIT's.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![allow(
    clippy::disallowed_methods,
    reason = "a program reads its profile and environment when it starts"
)]

use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;

use krb5_crypto::EncryptionType;
use krb5_kdc::{
    KdcLog, ListenLimits, OpenFailure, PrincipalStore, Signals, bind_tcp_listeners_with_backlog,
    bind_udp_listeners, copy_persist_master, detach, manual_master_key, mkey_log_context,
    names_relative_database, open_database, open_database_with_key, open_database_with_password,
    serve_daemon, shared_store, write_pid_file,
};
use krb5_log::klog::{self, JsonLog, Severity, os_error_text};

// MIT: `initialize_realms` (kdc/main.c:669-669)
const OPTSTRING: &str = "x:r:d:mM:k:R:P:p:nw:4:T:X3";

// MIT: `usage` (kdc/main.c:582-595)
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

#[derive(Clone, Default)]
struct RealmArgs {
    db_args: Vec<String>,
    listen: Option<String>,
    manual: bool,
    mkey_name: Option<String>,
}

#[derive(Default)]
struct Options {
    realm: Option<String>,
    extra_realm: Option<String>,
    args: RealmArgs,
    pid_file: Option<PathBuf>,
    nofork: bool,
    time_offset: i64,
    operands: Vec<String>,
    #[cfg(feature = "test-hooks")]
    hooks: hooks::Args,
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
            // -x temporary appends a tilde. Any other unknown -x is refused.
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
            // -m reads the master key only when the realm names no stash.
            'm' => cur.manual = true,
            // -M must be K/M when the database opens.
            'M' => cur.mkey_name = Some(arg),
            'n' => out.nofork = true,
            'w' if atoi(&arg) > 0 => {}
            'k' => {
                if EncryptionType::from_mit_name(&arg).is_err() {
                    klog::com_err(None, &format!("invalid enctype {arg}"));
                }
            }
            // -R, -4 and -X are ignored. -k is only checked. A positive -w is ignored.
            'R' | '4' | 'X' => {}
            'P' => out.pid_file = Some(PathBuf::from(arg)),
            'p' => cur.listen = Some(arg),
            'T' => out.time_offset = atoi(&arg),
            _ => usage(progname),
        }
    }
    // An option after -r applies to none.
    out.args = taken.unwrap_or(cur);
    out
}

// MIT: `main` (kdc/main.c:899-900)
fn progname(argv0: Option<&String>) -> String {
    argv0
        .map(|a| a.rsplit('/').next().unwrap_or(a).to_owned())
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| "krb5kdc".to_owned())
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let progname = progname(argv.first());
    // MIT: `main` (kdc/main.c:917-921)
    let profile_read = krb5_config::ReadOnce::start();
    // The profile is read once; a refusal ends the process.
    if let Err(e) = krb5_config::init_kdc_profile() {
        let argv0 = argv.first().map_or("krb5kdc", String::as_str);
        eprintln!("{argv0}: {} while initializing krb5", e.init_text());
        std::process::exit(1);
    }
    let specs = krb5_config::LogSpecs::load("kdc");
    klog::init(&progname, &specs.specs, specs.debug);
    let opts = parse_options(&progname, argv.get(1..).unwrap_or_default());
    #[cfg(feature = "test-hooks")]
    let foreground = opts.nofork || opts.hooks.foreground(&opts.operands);
    #[cfg(not(feature = "test-hooks"))]
    let foreground = opts.nofork;
    if let Some(json) = specs
        .json
        .as_deref()
        .and_then(|s| JsonLog::open(&progname, s))
        && (foreground || json.is_file())
    {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_writer(json.make_writer())
            .with_env_filter(krb5_kdc::json_log_filter("krb5_kdc=info,krb5_admin=info"))
            .try_init();
    }
    // -T must be 0.
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
    // A second, different -r stops the KDC.
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
    if foreground && !test_realm && manual_master_key(opts.args.manual, &paths) {
        store = init_realm(&progname, &realm, &paths, &opts.args);
    }
    let profile = krb5_config::ProfileSet::from_env_files(&paths).unwrap_or_else(|e| {
        let argv0 = argv.first().map_or("krb5kdc", String::as_str);
        eprintln!("{argv0}: {} while initializing krb5", e.init_text());
        std::process::exit(1);
    });
    drop(profile_read);
    if let Err(e) = store.apply_profile(&profile) {
        eprintln!("{progname}: kdc.conf: {e}");
        std::process::exit(2);
    }
    for line in profile
        .kdc
        .iter()
        .flat_map(krb5_config::KdcConf::unsupported_lines)
    {
        klog::syslog(Severity::Warning, &line);
    }
    #[cfg(feature = "test-hooks")]
    let kdcpolicy_relations = store.policy.kdcpolicy.clone();
    #[cfg(feature = "test-hooks")]
    krb5_kdc::register_kdcpolicy_test_if_selected(&mut store.policy.plugins, &kdcpolicy_relations);
    #[cfg(feature = "test-hooks")]
    hooks::install_greet(&mut store.policy.plugins);
    let pkinit_failure = store.init_pkinit(&profile);
    #[cfg(feature = "test-hooks")]
    hooks::before_serving(&mut store, &opts.hooks);
    let pkinit_failure = pkinit_failure.filter(|_| store.pkinit().is_none());
    // MIT: `load_preauth_plugins` (kdc/kdc_preauth.c:207-219)
    // A preauth module whose init fails is logged at error and left out.
    for (level, line) in
        krb5_kdc::preauth_startup_lines(&store.policy.kdcpreauth, pkinit_failure.as_deref())
    {
        let severity = if level == "error" {
            Severity::Err
        } else {
            Severity::Info
        };
        klog::syslog(severity, &line);
    }
    for (_, line) in krb5_kdc::otp_startup_lines(&store.policy) {
        klog::syslog(Severity::Err, &line);
    }
    if let Err(msg) = store.policy.spake_kdc() {
        klog::syslog(
            Severity::Err,
            &format!("preauth spake failed to initialize: {msg}"),
        );
    }
    #[cfg(feature = "test-hooks")]
    let persist = store.persist_paths.clone();
    #[cfg(feature = "test-hooks")]
    let memory = {
        let env_lib = hooks::db_library();
        let lib = env_lib
            .as_deref()
            .or_else(|| kdc_conf.as_ref().and_then(|c| c.db_library.as_deref()));
        lib == Some("memory")
    };
    let keyboard = manual_master_key(opts.args.manual, &paths);
    let held_master = if keyboard {
        copy_persist_master(&store)
    } else {
        None
    };
    #[cfg(feature = "test-hooks")]
    let store = if memory {
        shared_store(krb5_kdc::MemoryStore::from_dump(&store))
    } else {
        shared_store(store)
    };
    #[cfg(not(feature = "test-hooks"))]
    let store = shared_store(store);
    if let (Some(conf), Some(ports)) = (kdc_conf.as_mut(), opts.args.listen.as_deref()) {
        conf.apply_port_option(ports);
    }
    #[cfg(feature = "test-hooks")]
    let pinned = hooks::pinned(&opts.operands);
    #[cfg(not(feature = "test-hooks"))]
    let pinned: Option<String> = None;
    let _ = &opts.operands;
    // MIT: `main` (kdc/main.c:976-983)
    // Signal handlers are installed before the listeners are bound.
    let signals = Signals::install();
    // MIT: `loop_setup_network` (lib/apputils/net-server.c:1068-1074)
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
    // MIT: `main` (kdc/main.c:996-1008)
    // -n stays in the foreground. Otherwise bind, then detach, then the pid file.
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
    // MIT: `main` (kdc/main.c:1016-1016)
    // A relative database or stash is opened again after detach, from /.
    if !foreground && names_relative_database(&paths, &opts.args.db_args) {
        if keyboard {
            let fetching = format!(
                "while fetching master key {} for realm {realm}",
                opts.args.mkey_name.as_deref().unwrap_or("K/M")
            );
            let Some(key) = &held_master else {
                cannot_initialize(&progname, &realm, "Cannot read password", &fetching);
            };
            if let Err(e) = open_database_with_key(
                &paths,
                &opts.args.db_args,
                opts.args.mkey_name.as_deref().unwrap_or("K/M"),
                key,
            ) {
                let (msg, during) = match e {
                    OpenFailure::Database(msg) => (
                        msg,
                        format!("while initializing database for realm {realm}"),
                    ),
                    OpenFailure::MasterKey(msg) => {
                        let during = mkey_log_context(
                            &msg,
                            &realm,
                            opts.args.mkey_name.as_deref().unwrap_or("K/M"),
                        );
                        (msg, during)
                    }
                };
                cannot_initialize(&progname, &realm, &msg, &during);
            }
        } else {
            let _ = init_realm(&progname, &realm, &paths, &opts.args);
        }
        let mut s = store
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(e) = krb5_kdc::StoreLifecycle::reload_if_stale(&mut *s) {
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
    klog::syslog(Severity::Info, "commencing operation");
    if foreground {
        eprintln!("{progname}: starting...");
    }
    {
        let g = store
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        krb5_kdc::audit_kdc_start(&*g, true);
    }
    // MIT: `finish_dispatch` (kdc/dispatch.c:54-55)
    let max_dgram = kdc_conf.as_ref().map_or(krb5_kdc::MAX_DGRAM_REPLY, |c| {
        // The UDP reply cap is the value's unsigned bits.
        usize::try_from(c.kdc_max_dgram_reply_size.cast_unsigned()).unwrap_or(usize::MAX)
    });
    let limits = ListenLimits {
        max_dgram_reply_size: max_dgram,
        ..ListenLimits::default()
    };
    let served = serve_daemon(
        store.clone(),
        udp,
        tcp,
        &signals,
        limits,
        &KdcLog::process(),
    );
    if let Err(e) = served {
        {
            let g = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            krb5_kdc::audit_kdc_stop(&*g, false);
        }
        klog::com_err(Some(&e.to_string()), "while serving");
        eprintln!("{progname}: serve: {e}");
        std::process::exit(1);
    }
    {
        let g = store
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        krb5_kdc::audit_kdc_stop(&*g, true);
    }
    klog::syslog(Severity::Info, "shutting down");
    klog::close();
}

fn cannot_initialize(progname: &str, realm: &str, error: &str, during: &str) -> ! {
    klog::com_err(Some(error), during);
    eprintln!("{progname}: cannot initialize realm {realm} - see log file for details");
    std::process::exit(1);
}

// MIT: `init_realm` (kdc/main.c:351-382)
fn init_realm(
    progname: &str,
    realm: &str,
    paths: &krb5_config::KdcPaths,
    args: &RealmArgs,
) -> PrincipalStore {
    let opening = format!("while initializing database for realm {realm}");
    let mkey_name = args.mkey_name.as_deref().unwrap_or("K/M");
    let opened = if manual_master_key(args.manual, paths) {
        open_database_with_password(paths, &args.db_args, mkey_name, realm)
    } else {
        open_database(paths, &args.db_args, mkey_name)
    };
    match opened {
        Err(OpenFailure::Database(e)) => cannot_initialize(progname, realm, &e, &opening),
        Err(OpenFailure::MasterKey(e)) => {
            let during = mkey_log_context(&e, realm, mkey_name);
            cannot_initialize(progname, realm, &e, &during)
        }
        Ok(store) => store,
    }
}

// MIT: `main` (kdc/main.c:960-973)
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
    // MIT: `initialize_realms` (kdc/main.c:639-644)
    let tcp = bind_tcp_listeners_with_backlog(&tcp_addrs, conf.kdc_tcp_listen_backlog)
        .unwrap_or_else(|_| std::process::exit(1));
    (udp, tcp)
}

#[cfg(feature = "test-hooks")]
mod hooks {
    use std::net::{TcpListener, UdpSocket};
    use std::path::PathBuf;

    use krb5_cli::LongOpt;
    use krb5_kdc::testrealm::{TEST_ADMIN, TEST_REALM, TEST_USER, documented_kiprop};
    use krb5_kdc::{
        Acl, BIND_CANDIDATES, KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_DUP_SKEY, KDB_DISALLOW_SVR,
        KDB_OK_TO_AUTH_AS_DELEGATE, PrincipalStore, add_admin_principals, bind_preferred,
    };

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

        pub(super) fn foreground(&self, operands: &[String]) -> bool {
            self.test_realm
                || self.export_keytab.is_some()
                || self.export_krbtgt.is_some()
                || self.export_pkinit.is_some()
                || pinned(operands).is_some()
        }
    }

    pub(super) fn pinned(operands: &[String]) -> Option<String> {
        operands
            .first()
            .cloned()
            .or_else(|| std::env::var("KRB5_KDC_BIND").ok())
    }

    pub(super) fn test_realm_name() -> String {
        std::env::var("KRB5_TEST_REALM").unwrap_or_else(|_| TEST_REALM.to_owned())
    }

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

    pub(super) fn before_serving(store: &mut PrincipalStore, args: &Args) {
        if std::env::var("KRB5_KDCPOLICY").ok().as_deref() == Some("test") {
            store
                .policy
                .plugins
                .set_policy(std::sync::Arc::new(krb5_kdc::testrealm::TestPolicy));
        }
        if std::env::var("KRB5_KDC_AUDIT").ok().as_deref() == Some("test") {
            let path = std::env::var("KRB5_KDC_AUDIT_LOG").unwrap_or_else(|_| "au.log".into());
            match krb5_kdc::testrealm::TestAudit::open(&path) {
                Ok(a) => store.policy.plugins.set_audit(std::sync::Arc::new(a)),
                Err(e) => {
                    eprintln!("krb5-kdc: KRB5_KDC_AUDIT_LOG {path}: {e}");
                    std::process::exit(1);
                }
            }
        }
        let enable_pkinit = args.export_pkinit.is_some()
            || std::env::var("KRB5_ENABLE_PKINIT").ok().as_deref() == Some("1");
        let pkinit_ca = enable_pkinit.then(|| test_pkinit(store));
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
        if let (Some(dir), Some(ca)) = (args.export_pkinit.as_ref(), pkinit_ca.as_ref()) {
            export_pkinit(store, ca, dir);
        }
    }

    fn test_pkinit(store: &mut PrincipalStore) -> krb5_types::pkinit::PkinitCa {
        let ca = krb5_types::pkinit::PkinitCa::generate();
        let identity = ca
            .as_ref()
            .and_then(|c| c.kdc_pkinit_identity(store.realm()));
        let (Some(ca), Some(identity)) = (ca, identity) else {
            eprintln!("krb5-kdc: PKINIT CA: pkinit CA generate failed");
            std::process::exit(1);
        };
        store.set_pkinit(Some(krb5_kdc::PkinitKdc::new(
            identity,
            vec![ca.ca_cert.clone()],
        )));
        ca
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

    fn export_pkinit(store: &PrincipalStore, ca: &krb5_types::pkinit::PkinitCa, dir: &str) {
        let _ = std::fs::create_dir_all(dir);
        let _ = std::fs::write(format!("{dir}/ca.pem"), ca.cert_pem());
        println!("pkinit-ca {dir}/ca.pem");
        if let Some(pem) = ca.user_identity_pem("user@KERBER.TEST") {
            let _ = std::fs::write(format!("{dir}/user.pem"), pem);
            println!("pkinit-user {dir}/user.pem");
        }
        if let Some(pem) = ca.user_identity_pem("other@KERBER.TEST") {
            let _ = std::fs::write(format!("{dir}/other.pem"), pem);
            println!("pkinit-other {dir}/other.pem");
        }
        if let Some(pem) = ca.kdc_identity_pem_for(store.realm()) {
            let _ = std::fs::write(format!("{dir}/kdc.pem"), pem);
            println!("pkinit-kdc {dir}/kdc.pem");
        }
        if let Some(pem) = ca.kdc_identity_pem_for("OTHER.TEST") {
            let _ = std::fs::write(format!("{dir}/kdc-wrong-realm.pem"), pem);
            println!("pkinit-kdc-wrong-realm {dir}/kdc-wrong-realm.pem");
        }
    }

    pub(super) fn install_greet(plugins: &mut krb5_kdc::PluginSet) {
        if std::env::var("KERBER_KDC_GREET").ok().as_deref() == Some("1") {
            plugins.register_authdata(std::sync::Arc::new(krb5_kdc::testrealm::GreetAuth));
        }
    }

    pub(super) fn db_library() -> Option<String> {
        std::env::var("KRB5_KDC_DB_LIBRARY").ok()
    }

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
        if persist.is_none() {
            // Privileges drop only when no database file is served.
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
        if let Err(e) = store.create_host(&acl, &actor, &documented_kiprop()) {
            eprintln!("krb5-kdc: kiprop: {e}");
            std::process::exit(1);
        }
        if let Err(e) = add_admin_principals(&mut store, 1) {
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
            if let Err(e) = store.set_status(&locked, true, 0, "db_creation") {
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
                    if let Err(e) =
                        store.create_interrealm_key(acl, actor, foreign, key.clone(), None)
                    {
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
                            store.set_interrealm_decrypt_key(acl, actor, foreign, key.clone(), None)
                        } else {
                            store.add_interrealm_decrypt_key(acl, actor, foreign, key.clone(), None)
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
