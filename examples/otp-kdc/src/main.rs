#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![allow(
    clippy::disallowed_methods,
    reason = "a program reads its profile and environment when it starts"
)]

mod rfc6238;

use std::process::exit;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, PoisonError};

use krb5_config::{KdcConf, KdcPaths, LogSpecs, ProfileSet};
use krb5_kdc::{ListenLimits, MAX_DGRAM_REPLY, OpenFailure, SharedStore};
use krb5_log::klog::{self, Severity};

const DEFAULT_PROGNAME: &str = "krb5-otp-kdc";

const MKEY_NAME: &str = "K/M";

const STOP_SIGNALS: [i32; 2] = [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT];

fn progname(argv0: Option<&str>) -> String {
    argv0
        .and_then(|path| path.rsplit('/').next())
        .filter(|name| !name.is_empty())
        .unwrap_or(DEFAULT_PROGNAME)
        .to_owned()
}

fn usage(progname: &str) -> ! {
    eprintln!("usage: {progname} [-n]");
    exit(1)
}

fn cannot_initialize(progname: &str, realm: &str, error: &str, during: &str) -> ! {
    klog::com_err(Some(error), during);
    eprintln!("{progname}: cannot initialize realm {realm} - see log file for details");
    exit(1)
}

fn audit_stop(store: &SharedStore, success: bool) {
    let guard = store.read().unwrap_or_else(PoisonError::into_inner);
    krb5_kdc::audit_kdc_stop(&**guard, success);
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let progname = progname(argv.first().map(String::as_str));
    if argv.iter().skip(1).any(|arg| arg != "-n") {
        usage(&progname);
    }
    if let Err(e) = krb5_config::init_kdc_profile() {
        eprintln!("{progname}: {} while initializing krb5", e.init_text());
        exit(1);
    }
    let specs = LogSpecs::load("kdc");
    klog::init(&progname, &specs.specs, specs.debug);

    let paths = KdcPaths::resolve(None).unwrap_or_else(|e| {
        if matches!(e, krb5_config::Error::NoDefaultRealm) {
            klog::com_err(
                Some(&e.to_string()),
                "while attempting to retrieve default realm",
            );
            eprintln!("{progname}: {e}, attempting to retrieve default realm");
        } else {
            eprintln!("{progname}: {e}");
        }
        exit(1);
    });
    let realm = paths.realm.clone().unwrap_or_default();
    let mut store = match krb5_kdc::open_database(&paths, &[], MKEY_NAME) {
        Ok(store) => store,
        Err(OpenFailure::Database(e)) => cannot_initialize(
            &progname,
            &realm,
            &e,
            &format!("while initializing database for realm {realm}"),
        ),
        Err(OpenFailure::MasterKey(e)) => cannot_initialize(
            &progname,
            &realm,
            &e,
            &format!("while fetching master key {MKEY_NAME} for realm {realm}"),
        ),
    };

    let profile = ProfileSet::from_env_files(&paths).unwrap_or_else(|e| {
        eprintln!("{progname}: {} while initializing krb5", e.init_text());
        exit(1);
    });
    if let Err(e) = store.apply_profile(&profile) {
        eprintln!("{progname}: kdc.conf: {e}");
        exit(2);
    }
    for line in profile
        .kdc
        .iter()
        .flat_map(krb5_config::KdcConf::unsupported_lines)
    {
        klog::syslog(Severity::Warning, &line);
    }
    krb5_kdc::register_kdcpolicy_test_if_selected(&store.policy().kdcpolicy);
    let kdc_conf = paths.conf;
    for (level, line) in krb5_kdc::preauth_startup_lines(
        store.realm(),
        &store.policy.kdcpreauth,
        store.pkinit_ca().is_some(),
    ) {
        let severity = if level == "error" {
            Severity::Err
        } else {
            Severity::Info
        };
        klog::syslog(severity, &line);
    }
    // MIT load_preauth_plugins; see docs/parity/a3-preauth.md
    for (_, line) in krb5_kdc::otp_startup_lines(&store.policy) {
        klog::syslog(Severity::Err, &line);
    }
    if let Err(msg) = store.policy.spake_kdc() {
        klog::syslog(
            Severity::Err,
            &format!("preauth spake failed to initialize: {msg}"),
        );
    }

    // The registry is process-wide: this thread runs the loop below, and a list set for this
    // thread alone would not apply while it runs.
    if std::env::var_os(rfc6238::SEEDS_ENV).is_none() {
        klog::syslog(
            Severity::Warning,
            "KERBER_EXAMPLE_TOTP_SEEDS is unset: every totp OTP is refused",
        );
    }
    krb5_kdc::register_otp_verifier(Arc::new(rfc6238::TotpVerifier::from_env()));

    let store = krb5_kdc::shared_store(store);
    let shutdown = Arc::new(AtomicBool::new(false));
    for sig in STOP_SIGNALS {
        if let Err(e) = signal_hook::flag::register(sig, Arc::clone(&shutdown)) {
            eprintln!("{progname}: cannot catch signal {sig}: {e}");
            exit(1);
        }
    }

    klog::syslog(Severity::Info, "setting up network...");
    let fallback = KdcConf::default();
    let conf = kdc_conf.as_ref().unwrap_or(&fallback);
    let lists = conf
        .kdc_udp_listeners()
        .and_then(|udp| conf.kdc_tcp_listeners().map(|tcp| (udp, tcp)));
    let (udp_addrs, tcp_addrs) = lists.unwrap_or_else(|e| {
        eprintln!("{progname}: kdc.conf: {e}");
        exit(1);
    });
    let udp = krb5_kdc::bind_udp_listeners(&udp_addrs).unwrap_or_else(|e| {
        eprintln!("{progname}: cannot bind UDP: {e}");
        exit(1);
    });
    let tcp = krb5_kdc::bind_tcp_listeners_with_backlog(&tcp_addrs, conf.kdc_tcp_listen_backlog)
        .unwrap_or_else(|e| {
            eprintln!("{progname}: cannot bind TCP: {e}");
            exit(1);
        });
    klog::syslog(
        Severity::Info,
        &format!("set up {} sockets", udp.len() + tcp.len()),
    );
    let max_dgram = kdc_conf.as_ref().map_or(MAX_DGRAM_REPLY, |c| {
        usize::try_from(c.kdc_max_dgram_reply_size.cast_unsigned()).unwrap_or(usize::MAX)
    });

    klog::syslog(Severity::Info, "commencing operation");
    eprintln!("{progname}: starting...");
    {
        let guard = store.read().unwrap_or_else(PoisonError::into_inner);
        krb5_kdc::audit_kdc_start(&**guard, true);
    }
    let limits = ListenLimits {
        max_dgram_reply_size: max_dgram,
        ..ListenLimits::default()
    };
    match krb5_kdc::serve_all_until(store.clone(), udp, tcp, shutdown, limits) {
        Ok(()) => {
            audit_stop(&store, true);
            klog::syslog(Severity::Info, "shutting down");
            klog::close();
        }
        Err(e) => {
            audit_stop(&store, false);
            klog::com_err(Some(&e.to_string()), "while serving");
            eprintln!("{progname}: serve: {e}");
            exit(1);
        }
    }
}
