//! `krb5-otp-kdc`: the kerber-rust KDC run in-process through the library's embed API, with a TOTP
//! `OtpVerifier` registered before it serves. It is the KLLDAP integration in miniature, kept to
//! prove OTP preauth end to end against MIT `kinit`; it is not a shipped product.
//!
//! It starts as `krb5-kdc` does for the realm the profile names, in the foreground: the profile,
//! the daemon log, the realm's database and stash, kdc.conf and the plugin relations, then the
//! listeners. One loop on this thread serves until SIGTERM or SIGINT. `-n` is accepted and changes
//! nothing: the program never detaches and writes no pid file. The verifier is in `rfc6238`.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod rfc6238;

use std::process::exit;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, PoisonError};

use krb5_config::{KdcConf, KdcPaths, LogSpecs};
use krb5_kdc::{ListenLimits, MAX_DGRAM_REPLY, OpenFailure, SharedStore};
use krb5_log::klog::{self, Severity};

/// The name used when `argv[0]` has none.
const DEFAULT_PROGNAME: &str = "krb5-otp-kdc";

/// The master key principal the database opens with, as `krb5-kdc` opens it without `-M`.
const MKEY_NAME: &str = "K/M";

/// The signals that set the loop's stop flag.
const STOP_SIGNALS: [i32; 2] = [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT];

/// The program's name: `argv[0]` without its directory.
fn progname(argv0: Option<&str>) -> String {
    argv0
        .and_then(|path| path.rsplit('/').next())
        .filter(|name| !name.is_empty())
        .unwrap_or(DEFAULT_PROGNAME)
        .to_owned()
}

/// The usage line, on standard error, then exit 1.
fn usage(progname: &str) -> ! {
    eprintln!("usage: {progname} [-n]");
    exit(1)
}

/// The realm cannot start: the reason to the daemon log, then the message on standard error, and
/// exit 1.
fn cannot_initialize(progname: &str, realm: &str, error: &str, during: &str) -> ! {
    klog::com_err(Some(error), during);
    eprintln!("{progname}: cannot initialize realm {realm} - see log file for details");
    exit(1)
}

/// `audit_kdc_stop` under the store's read lock, as `krb5-kdc` calls it when its loop ends.
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
    // The profile first, its kdc.conf ahead of krb5.conf; a profile it refuses ends the program.
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

    // krb5.conf's [libdefaults] is the base, and kdc.conf is applied over it.
    let krb5_conf = krb5_config::load_krb5_conf();
    if let Some(conf) = krb5_conf.as_ref() {
        store.set_capaths(conf.capaths.clone());
        store.apply_libdefaults(conf);
    }
    let kdc_conf = paths.conf;
    if let Some(conf) = &kdc_conf
        && let Err(e) = store.apply_kdc_conf(conf)
    {
        eprintln!("{progname}: kdc.conf: {e}");
        exit(2);
    }
    store.apply_kdcpreauth_plugins(kdc_conf.as_ref(), krb5_conf.as_ref());
    // MIT `otp_state_new` (`plugins/preauth/otp/otp_state.c:579-585`): the otp module reads `[otp]` from the same profile, once, when it starts.
    store.apply_otp(kdc_conf.as_ref(), krb5_conf.as_ref());
    store.apply_kdcpolicy_plugins(kdc_conf.as_ref(), krb5_conf.as_ref());
    krb5_kdc::register_kdcpolicy_test_if_selected(&store.policy().kdcpolicy);
    store.apply_audit_plugins(kdc_conf.as_ref(), krb5_conf.as_ref());
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
    // MIT `load_preauth_plugins` (`kdc/kdc_preauth.c:207-219`): the modules initialize in the order pkinit, otp, spake, and one that fails is logged and left out.
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

    // The listeners: kdc.conf's lists, else the defaults, as `krb5-kdc` binds them.
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
