//! `krb5-embed-realm`: kadmind run in-process through the library's embed API — [`Kadmind::new`],
//! [`Listeners::bind`] and [`Kadmind::serve`] with a [`Shutdown`] — over a realm's shared store,
//! the way an embedder (the KLLDAP seam) starts the admin service. It is the kadmind counterpart
//! of `otp-kdc`'s in-process KDC, kept to prove the embed path end to end against MIT `kadmin` and
//! `kpasswd`; it is not a shipped product.
//!
//! It reads the profile the daemon reads (kdc.conf over krb5.conf), opens the realm's database and
//! stash, binds kpasswd (464) and the kadm5 RPC program (749) over the shared store, and serves one
//! loop on this thread until SIGTERM or SIGINT trigger the `Shutdown`. Unlike the daemon it never
//! detaches and writes no pid file: a bad dictionary, profile or port stops it in the foreground,
//! where `Listeners::bind` and `Kadmind::new` return a `StartError`.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::process::exit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use krb5_admin::{Kadmind, KadmindConfig, Listeners, ServeLimits, Services, Shutdown};
use krb5_config::{KadmindListen, KdcPaths, LogSpecs, ProfileSet};
use krb5_kdc::OpenFailure;
use krb5_log::klog::{self, Severity, os_error_text};

mod auth_modules;

/// The name used when `argv[0]` has none.
const DEFAULT_PROGNAME: &str = "krb5-embed-realm";
/// The master key principal the database opens with, as the daemon opens it without `-m`.
const MKEY_NAME: &str = "K/M";
/// The signals that trigger the shutdown, as the daemon's do.
const STOP_SIGNALS: [i32; 2] = [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT];

/// The program's name: `argv[0]` without its directory.
fn progname(argv0: Option<&str>) -> String {
    argv0
        .and_then(|path| path.rsplit('/').next())
        .filter(|name| !name.is_empty())
        .unwrap_or(DEFAULT_PROGNAME)
        .to_owned()
}

/// The embedder cannot start: the reason on standard error, and exit 1. No pid file is written and
/// no service is left behind, because every check runs before the serve loop.
fn cannot_start(progname: &str, error: &str) -> ! {
    eprintln!("{progname}: {error}, aborting");
    exit(1)
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let progname = progname(argv.first().map(String::as_str));
    if argv.len() > 1 {
        eprintln!("usage: {progname}");
        exit(1);
    }

    // The profile first, kdc.conf ahead of krb5.conf; a profile it refuses ends the program.
    if let Err(e) = krb5_config::init_kdc_profile() {
        cannot_start(
            &progname,
            &format!("{} while initializing context", e.init_text()),
        );
    }
    let specs = LogSpecs::load("admin_server");
    klog::init(&progname, &specs.specs, specs.debug);

    // The realm's database and stash, then the admin-side profile for the same files.
    let paths = KdcPaths::resolve(None)
        .unwrap_or_else(|e| cannot_start(&progname, &format!("{e} while initializing")));
    let store = match krb5_kdc::open_database(&paths, &[], MKEY_NAME) {
        Ok(store) => store,
        Err(OpenFailure::Database(e) | OpenFailure::MasterKey(e)) => {
            cannot_start(&progname, &format!("{e} while initializing"));
        }
    };
    let realm = store.realm().to_owned();
    let shared = krb5_kdc::shared_dump(store);
    let profile = ProfileSet::from_env_files(&paths).unwrap_or_else(|e| {
        cannot_start(
            &progname,
            &format!("{} while initializing context", e.init_text()),
        );
    });

    // The listen ports and the ACL the realm's profile names; kpasswd and kadm5, no iprop.
    let listen = KadmindListen::for_realm(Some(&profile.kdc_context), &realm, None);
    let services = Services::DAEMON;
    let acl = krb5_kdc::acl_for_store(&realm, paths.acl_file.as_deref())
        .unwrap_or_else(|e| cannot_start(&progname, &format!("{e} while initializing")));

    // Bind the listeners, then set up the admin service over the shared store — both here, in the
    // foreground, as the daemon does before it forks.
    let listeners = Listeners::bind(&listen, services, None)
        .unwrap_or_else(|e| cannot_start(&progname, &format!("{e} while initializing network")));
    let cfg = KadmindConfig {
        profile: Arc::new(profile),
        services,
        listen,
        limits: ServeLimits::default(),
        acl,
        auth_modules: auth_modules::example_modules(),
        iprop: None,
    };
    let mut kadmind = Kadmind::new(shared, cfg)
        .unwrap_or_else(|e| cannot_start(&progname, &format!("{e} while initializing")));

    // SIGTERM and SIGINT trigger the one `Shutdown`. The serve loop blocks on the shutdown pipe with
    // no poll of its own, so a watcher thread notices the signal flag within 100 ms and triggers the
    // shutdown, which then wakes the loop at once.
    let stop = Shutdown::new();
    let flagged = Arc::new(AtomicBool::new(false));
    for sig in STOP_SIGNALS {
        if let Err(e) = signal_hook::flag::register(sig, Arc::clone(&flagged)) {
            cannot_start(
                &progname,
                &format!("cannot catch signal {sig}: {e} while initializing"),
            );
        }
    }
    let trigger = stop.clone();
    thread::spawn(move || {
        while !flagged.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(100));
        }
        trigger.trigger();
    });

    // "starting" is MIT kadmind's line just before it serves, and our daemon's too.
    klog::syslog(Severity::Info, "starting");
    eprintln!("{progname}: serving {realm} (kpasswd 464, kadm5 749); SIGTERM or SIGINT to stop");
    match kadmind.serve(&listeners, &stop) {
        Ok(_summary) => {
            klog::syslog(Severity::Info, "shutting down");
            klog::close();
        }
        Err(e) => {
            klog::com_err(Some(&os_error_text(&e)), "while serving");
            eprintln!("{progname}: serve: {e}");
            exit(1);
        }
    }
}
