//! `krb5-embed-realm`: kadmind run in-process through the library's embed API — [`Kadmind::new`],
//! [`Listeners::bind`] and [`Kadmind::serve`] with a [`Shutdown`] — over a realm's shared store,
//! the way an embedder (the KLLDAP seam) starts the admin service. It is the kadmind half of this
//! example, beside the `krb5-otp-kdc` KDC, kept to prove the embed path end to end against MIT
//! `kadmin` and `kpasswd`; it is not a shipped product. It installs a stock
//! tracing fmt subscriber at info, so each kadm5 operation and each password
//! change shows one `admin` event.
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

use krb5_admin::{
    Kadmind, KadmindConfig, Listeners, ServeLimits, Services, Shutdown, TracingAdmin,
};
use krb5_config::{KadmindListen, KdcPaths, LogSpecs, ProfileSet};
use krb5_log::klog::{self, Severity, os_error_text};

mod auth_modules;

/// The name used when `argv[0]` has none.
const DEFAULT_PROGNAME: &str = "krb5-embed-realm";
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

struct Trust {
    realm: String,
    key_file: String,
    kvno: Option<u32>,
}

struct Allow {
    service: String,
    target: String,
}

enum Job {
    Serve { bootstrap_only: bool },
    Trust(Trust),
    Allow(Allow),
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let progname = progname(argv.first().map(String::as_str));
    let job = parse_args(&progname, &argv);

    // The profile first, kdc.conf ahead of krb5.conf; a profile it refuses ends the program.
    if let Err(e) = krb5_config::init_kdc_profile() {
        cannot_start(
            &progname,
            &format!("{} while initializing context", e.init_text()),
        );
    }
    let specs = LogSpecs::load("admin_server");
    klog::init(&progname, &specs.specs, specs.debug);
    let _ = tracing_subscriber::fmt()
        .with_env_filter("krb5_kdc=info,krb5_admin=info")
        .try_init();

    // The profile names the realm. A missing database is created; a present one is opened.
    let paths = KdcPaths::resolve(None)
        .unwrap_or_else(|e| cannot_start(&progname, &format!("{e} while initializing")));
    let Some(realm) = paths.realm.clone() else {
        cannot_start(&progname, "no default realm while initializing");
    };
    let profile = ProfileSet::from_env_files(&paths).unwrap_or_else(|e| {
        cannot_start(
            &progname,
            &format!("{} while initializing context", e.init_text()),
        );
    });
    let mut store = open_or_create(&progname, &paths, &profile);
    match job {
        Job::Trust(trust) => {
            store
                .apply_profile(&profile)
                .unwrap_or_else(|e| cannot_start(&progname, &format!("{e} while initializing")));
            create_trust(&progname, &mut store, &paths, &realm, &trust);
            klog::close();
            return;
        }
        Job::Allow(allow) => {
            store
                .apply_profile(&profile)
                .unwrap_or_else(|e| cannot_start(&progname, &format!("{e} while initializing")));
            allow_delegate(&progname, &mut store, &realm, &allow);
            klog::close();
            return;
        }
        Job::Serve {
            bootstrap_only: true,
        } => {
            klog::close();
            return;
        }
        Job::Serve {
            bootstrap_only: false,
        } => {}
    }
    let shared = krb5_kdc::shared_dump(store);

    // The listen ports and the ACL the realm's profile names; kpasswd and kadm5, no iprop.
    let listen = KadmindListen::for_realm(Some(&profile.kdc_context), &realm, None);
    let services = Services::DAEMON;
    let acl = krb5_kdc::acl_for_store(&realm, paths.acl_file.as_deref())
        .unwrap_or_else(|e| cannot_start(&progname, &format!("{e} while initializing")));

    // Bind the listeners, then set up the admin service over the shared store — both here, in the
    // foreground, as the daemon does before it forks.
    let listeners = Listeners::bind(&listen, services, None, &TracingAdmin)
        .unwrap_or_else(|e| cannot_start(&progname, &format!("{e} while initializing network")));
    let cfg = KadmindConfig {
        profile: Arc::new(profile),
        services,
        listen,
        limits: ServeLimits::default(),
        acl,
        auth_modules: auth_modules::example_modules(),
        log: Arc::new(TracingAdmin),
        pwqual: Vec::new(),
        hooks: Vec::new(),
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

fn parse_args(progname: &str, argv: &[String]) -> Job {
    let mut bootstrap_only = false;
    let mut realm = None;
    let mut key_file = None;
    let mut kvno = None;
    let mut service = None;
    let mut target = None;
    let mut i = 1usize;
    while i < argv.len() {
        match argv[i].as_str() {
            "--bootstrap-only" => bootstrap_only = true,
            "--create-trust" => {
                i += 1;
                realm = Some(need_arg(progname, argv, i, "--create-trust"));
            }
            "--key-file" => {
                i += 1;
                key_file = Some(need_arg(progname, argv, i, "--key-file"));
            }
            "--kvno" => {
                i += 1;
                let text = need_arg(progname, argv, i, "--kvno");
                let n = text.parse::<u32>().unwrap_or_else(|_| {
                    cannot_start(progname, "--kvno wants a number from 1 to 65535");
                });
                if n == 0 || n > 65535 {
                    cannot_start(progname, "--kvno wants a number from 1 to 65535");
                }
                kvno = Some(n);
            }
            "--allow-to-delegate" => {
                service = Some(need_arg(progname, argv, i + 1, "--allow-to-delegate"));
                target = Some(need_arg(progname, argv, i + 2, "--allow-to-delegate"));
                i += 2;
            }
            _ => usage(progname),
        }
        i += 1;
    }
    let trust = match (realm, key_file) {
        (Some(realm), Some(key_file)) => Some(Trust {
            realm,
            key_file,
            kvno,
        }),
        (None, None) if kvno.is_none() => None,
        _ => usage(progname),
    };
    let allow = match (service, target) {
        (Some(service), Some(target)) => Some(Allow { service, target }),
        (None, None) => None,
        _ => usage(progname),
    };
    match (bootstrap_only, trust, allow) {
        (false, Some(trust), None) => Job::Trust(trust),
        (false, None, Some(allow)) => Job::Allow(allow),
        (_, None, None) => Job::Serve { bootstrap_only },
        _ => usage(progname),
    }
}

fn need_arg(progname: &str, argv: &[String], i: usize, flag: &str) -> String {
    argv.get(i).cloned().unwrap_or_else(|| {
        cannot_start(progname, &format!("{flag} needs a value"));
    })
}

fn usage(progname: &str) -> ! {
    eprintln!(
        "usage: {progname} [--bootstrap-only]\n       \
         {progname} --create-trust REALM --key-file FILE [--kvno N]\n       \
         {progname} --allow-to-delegate SERVICE TARGET"
    );
    exit(1);
}

fn create_trust(
    progname: &str,
    store: &mut krb5_kdc::PrincipalStore,
    paths: &KdcPaths,
    realm: &str,
    trust: &Trust,
) {
    let key = read_trust_key(progname, &trust.key_file);
    let acl = krb5_kdc::acl_for_store(realm, paths.acl_file.as_deref())
        .unwrap_or_else(|e| cannot_start(progname, &format!("{e} while initializing")));
    let actor = format!("admin/admin@{realm}");
    let created =
        store.change(|s| s.create_interrealm_key(&acl, &actor, &trust.realm, key, trust.kvno));
    match created {
        Ok(Ok(())) => {
            eprintln!("{progname}: created trust {}", trust.realm);
        }
        Ok(Err(e)) | Err(e) => cannot_start(progname, &format!("{e} while creating the trust")),
    }
}

fn allow_delegate(
    progname: &str,
    store: &mut krb5_kdc::PrincipalStore,
    realm: &str,
    allow: &Allow,
) {
    let (name, name_realm) = krb5_types::principal_from_unparsed(&allow.service, realm)
        .unwrap_or_else(|_| {
            cannot_start(progname, "service name is not a principal");
        });
    if name_realm != realm {
        cannot_start(progname, "service is in another realm");
    }
    let recorded = store.change(|s| s.record_s4u_to(&name, &allow.target));
    match recorded {
        Ok(Ok(())) => {
            eprintln!(
                "{progname}: allowed {} to delegate to {}",
                allow.service, allow.target
            );
        }
        Ok(Err(e)) | Err(e) => cannot_start(progname, &format!("{e} while recording the grant")),
    }
}

fn read_trust_key(progname: &str, path: &str) -> krb5_crypto::ProtocolKey {
    use zeroize::Zeroizing;
    let raw = krb5_protocol::read_secret_file(std::path::Path::new(path))
        .unwrap_or_else(|e| cannot_start(progname, &format!("{e} while reading {path}")));
    let start = raw
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(0);
    let end = raw
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |i| i + 1);
    let hex = &raw[start..end];
    if hex.len() != 64 {
        cannot_start(
            progname,
            "key file needs 32 bytes of aes256 as 64 hex characters",
        );
    }
    let mut bytes = Zeroizing::new(vec![0u8; 32]);
    for i in 0..32 {
        let hi = nibble(hex[i * 2]);
        let lo = nibble(hex[i * 2 + 1]);
        match (hi, lo) {
            (Some(hi), Some(lo)) => bytes[i] = (hi << 4) | lo,
            _ => cannot_start(
                progname,
                "key file needs 32 bytes of aes256 as 64 hex characters",
            ),
        }
    }
    krb5_crypto::ProtocolKey::from_bytes(krb5_crypto::EncryptionType::Aes256CtsHmacSha196, &bytes)
        .unwrap_or_else(|e| cannot_start(progname, &format!("{e} while reading {path}")))
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn open_or_create(
    progname: &str,
    paths: &KdcPaths,
    profile: &ProfileSet,
) -> krb5_kdc::PrincipalStore {
    use krb5_kdc::AdminSpec;
    use krb5_types::PrincipalName;

    let admin = Some(AdminSpec::new(PrincipalName::new(
        PrincipalName::NT_PRINCIPAL,
        ["admin", "admin"],
    )));
    let (store, boot) = krb5_kdc::open_or_create(paths, profile, admin)
        .unwrap_or_else(|e| cannot_start(progname, &format!("{e} while initializing")));
    if let Some(keytab) = &boot.admin_keytab {
        let path = paths.database_name.with_file_name("admin.keytab");
        if let Err(e) = keytab.write_file(&path) {
            cannot_start(progname, &format!("{e} while writing {}", path.display()));
        }
        eprintln!("{progname}: keytab {}", path.display());
    }
    eprintln!("{progname}: created {}", boot.created.join(" "));
    store
}
