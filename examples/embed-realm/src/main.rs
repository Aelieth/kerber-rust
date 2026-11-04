//! `krb5-embed-realm`: one process, one store, two loops. [`Kadmind::serve`] runs kadmind and
//! kpasswd on this thread. [`krb5_kdc::serve_all_until`] runs the KDC on another. One [`Shutdown`]
//! stops both. It is an embedder's skeleton, beside `krb5-otp-kdc`, kept to prove the path against
//! MIT `kadmin`, `kpasswd`, and `kinit`. It is not a shipped product. A tracing subscriber at info
//! shows one `admin` event per kadm5 operation and per password change.
//!
//! It reads the profile the daemon reads (kdc.conf over krb5.conf), opens or creates the database,
//! and binds the KDC ports from that profile plus kpasswd (464) and kadm5 (749). Unlike the daemon
//! it never detaches and writes no pid file. A bad dictionary, profile, or port stops it in the
//! foreground.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::net::{TcpListener, UdpSocket};
use std::process::exit;
use std::sync::Arc;
use std::sync::atomic::Ordering;
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
    let kdc_store: krb5_kdc::SharedStore = shared.clone();
    let (kdc_udp, kdc_tcp, kdc_limits) = bind_kdc(&progname, &profile);

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

    // One `Shutdown`. SIGTERM and SIGINT set its flag, which the KDC loop polls. Kadmind waits on
    // the pipe, so a watcher calls `trigger` within 100 ms of the flag.
    let stop = Shutdown::new();
    let flagged = stop.stop_flag();
    for sig in STOP_SIGNALS {
        if let Err(e) = signal_hook::flag::register(sig, Arc::clone(&flagged)) {
            cannot_start(
                &progname,
                &format!("cannot catch signal {sig}: {e} while initializing"),
            );
        }
    }
    let trigger = stop.clone();
    let watch = Arc::clone(&flagged);
    thread::spawn(move || {
        while !watch.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(100));
        }
        trigger.trigger();
    });
    let kdc_flag = Arc::clone(&flagged);
    let kdc_stop = stop.clone();
    let kdc = thread::spawn(move || {
        let log = krb5_kdc::KdcLog::process();
        let served =
            krb5_kdc::serve_all_until(kdc_store, kdc_udp, kdc_tcp, kdc_flag, kdc_limits, &log);
        if served.is_err() {
            kdc_stop.trigger();
        }
        served
    });

    // "starting" is MIT kadmind's line just before it serves, and our daemon's too.
    klog::syslog(Severity::Info, "starting");
    eprintln!(
        "{progname}: serving {realm} (kdc, kpasswd 464, kadm5 749); SIGTERM or SIGINT to stop"
    );
    let served = kadmind.serve(&listeners, &stop);
    flagged.store(true, Ordering::Relaxed);
    let Ok(kdc_served) = kdc.join() else {
        cannot_start(&progname, "kdc loop stopped while serving");
    };
    match (served, kdc_served) {
        (Ok(_summary), Ok(())) => {
            klog::syslog(Severity::Info, "shutting down");
            klog::close();
        }
        (Err(e), _) | (_, Err(e)) => {
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
    let actor = format!("admin/admin@{realm}");
    let recorded = store.change(|s| s.record_s4u_to(&name, &allow.target, &actor));
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

/// Bind the KDC ports the profile names, and take its datagram reply cap.
fn bind_kdc(
    progname: &str,
    profile: &ProfileSet,
) -> (Vec<UdpSocket>, Vec<TcpListener>, krb5_kdc::ListenLimits) {
    let default_conf = krb5_config::KdcConf::default();
    let conf = profile.kdc.as_ref().unwrap_or(&default_conf);
    let udp_addrs = conf.kdc_udp_listeners().unwrap_or_else(|e| {
        cannot_start(progname, &format!("kdc.conf: {e}"));
    });
    let tcp_addrs = conf.kdc_tcp_listeners().unwrap_or_else(|e| {
        cannot_start(progname, &format!("kdc.conf: {e}"));
    });
    let udp = krb5_kdc::bind_udp_listeners(&udp_addrs).unwrap_or_else(|e| {
        cannot_start(progname, &format!("{e} while initializing network"));
    });
    let tcp = krb5_kdc::bind_tcp_listeners_with_backlog(&tcp_addrs, conf.kdc_tcp_listen_backlog)
        .unwrap_or_else(|e| {
            cannot_start(progname, &format!("{e} while initializing network"));
        });
    let max_dgram =
        usize::try_from(conf.kdc_max_dgram_reply_size.cast_unsigned()).unwrap_or(usize::MAX);
    (
        udp,
        tcp,
        krb5_kdc::ListenLimits {
            max_dgram_reply_size: max_dgram,
            ..krb5_kdc::ListenLimits::default()
        },
    )
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
