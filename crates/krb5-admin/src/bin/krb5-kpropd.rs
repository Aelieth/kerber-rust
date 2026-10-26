//! MIT-wire kpropd (TCP 754) wrapping dump version 7: a replica's full propagation, and with `iprop_enable` its incremental propagation.
//! ```text
//! kpropd [-r realm] [-s keytab] [-d] [-D] [-S] [-t] [-P port] [-a acl_file] [-A admin_server] [host:port]
//! ```
//!   for another principal is refused; with `ignore_acceptor_hostname` any `host` entry of the   realm serves. A keytab that cannot be read, or has no such entry, answers "Service key not   available", and one that is no keytab "Unsupported key table format version number"; a   default name of no known type answers "Unknown Key table type", and a `-s` one ends the   connection, as MIT's. A name of its own that is not ASCII stops kpropd at its start.
//!   each connection, as MIT's is; one that cannot be opened refuses every peer.
//!   syslog. `-D` and `-S` change nothing: kpropd never detaches and is always standalone.
//! the realm, kpropd maps the replica's update log at the start, and a dump must be an iprop one, whose serial and time the log then keeps (MIT's `load -i`); without it, an iprop dump is refused as a plain `load` refuses it.
//! test realm, before the default realm, and `KRB5_MASTER_PASSWORD` opens the dump instead of the stash when set.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![allow(
    clippy::disallowed_methods,
    reason = "a program reads its profile and environment when it starts"
)]

use std::io::{self, Read as _};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, ToSocketAddrs};
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use krb5_admin::{
    IpropWake, KPROP_PORT, KPROPD_IO_TIMEOUT, KpropdConfig, KpropdIprop, KpropdKeys,
    kprop_service_port, kpropd_do_iprop, kpropd_handle_conn, kpropd_keytab_keys,
    kpropd_server_name,
};
use krb5_log::klog::{self, JsonLog, Severity, os_error_text};
use nix::sys::socket::{
    AddressFamily, Backlog, SockFlag, SockType, SockaddrStorage, bind, listen, setsockopt, socket,
    sockopt,
};

use krb5_config::ProfileSet;
use krb5_protocol::{AcceptorConfig, ReplayCache};
use krb5_types::PrincipalName;

/// MIT forks uncapped. mit-deviations.
const MAX_HANDLERS: usize = 64;

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let progname = argv
        .first()
        .map_or("krb5-kpropd", |a| a.rsplit('/').next().unwrap_or(a))
        .to_owned();
    // the KDC context before the options; a profile it refuses ends kpropd, named as invoked.
    let profile_read = krb5_config::ReadOnce::start();
    if let Err(e) = krb5_config::init_kdc_profile() {
        let argv0 = argv.first().map_or("kpropd", String::as_str);
        eprintln!("{argv0}: {} while initializing krb5", e.init_text());
        std::process::exit(1);
    }
    if let Some(json) =
        krb5_config::LogSpecs::load_json().and_then(|s| JsonLog::open(&progname, &s))
    {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_writer(json.make_writer())
            .with_env_filter(krb5_kdc::json_log_filter("krb5_kdc=info,krb5_admin=info"))
            .try_init();
    }
    let Options {
        realm: realm_opt,
        keytab,
        acl_file,
        address,
        port,
        admin_server,
        runonce,
        debug,
    } = parse_options(&progname, argv.get(1..).unwrap_or_default());
    klog::init("kpropd", &["SYSLOG:INFO:DAEMON".to_owned()], false);
    #[cfg(feature = "test-hooks")]
    let master = std::env::var("KRB5_MASTER_PASSWORD")
        .ok()
        .map(zeroize::Zeroizing::new);
    #[cfg(not(feature = "test-hooks"))]
    let master: Option<zeroize::Zeroizing<String>> = None;
    let paths = kpropd_paths(realm_opt.as_deref()).unwrap_or_else(|e| {
        if matches!(e, krb5_config::Error::NoDefaultRealm) {
            eprintln!("krb5-kpropd: {e} Unable to get default realm");
        } else {
            eprintln!("krb5-kpropd: {e}");
        }
        std::process::exit(1);
    });
    let realm = paths.realm.clone().unwrap_or_default();
    let profile = ProfileSet::from_env_files(&paths).unwrap_or_else(|e| {
        let argv0 = argv.first().map_or("kpropd", String::as_str);
        eprintln!("{argv0}: {} while initializing krb5", e.init_text());
        std::process::exit(1);
    });
    let conf = Arc::new(AcceptorConfig::from_profile(&profile));
    let kdc_context = Arc::new(krb5_config::ClientContext::new(profile.kdc_context));
    let (db, stash) = (paths.database_name, paths.key_stash_file);
    let server = kpropd_server_name(&kdc_context.profile).unwrap_or_else(|_| {
        let argv0 = argv.first().map_or("kpropd", String::as_str);
        eprintln!(
            "{argv0}: Illegal character in component name while trying to construct my service name"
        );
        std::process::exit(1);
    });
    let iprop = krb5_config::IpropParams::load(&realm, &db);
    drop(profile_read);
    if iprop.enabled
        && let Err(e) = krb5_kdc::Ulog::map(&iprop.logfile, iprop.ulogsize)
    {
        eprintln!("{progname}: {e} Unable to map log!");
        std::process::exit(1);
    }
    // Before the iprop gate, so it applies with iprop off too.
    let resync_timeout =
        std::time::Duration::from_secs(u64::try_from(iprop.resync_timeout).unwrap_or(0));
    let iprop = iprop.enabled.then_some(iprop);
    let addr = listen_addr(&progname, address.as_deref(), port.as_deref());
    let listener = standalone_listener(&progname, addr);
    listener.set_nonblocking(true).ok();
    println!("listening {}", listener.local_addr().unwrap_or(addr));
    let wake = iprop.clone().map(|params| {
        start_iprop(Poll {
            argv0: argv.first().cloned().unwrap_or_else(|| "kpropd".to_owned()),
            realm: realm.clone(),
            keytab: keytab.clone(),
            admin_server: admin_server
                .as_deref()
                .map(|a| krb5_config::listen::admin_server_host(a).to_owned())
                .or_else(|| params.admin_server.clone()),
            params,
            db: db.clone(),
            stash: stash.clone(),
            runonce,
            debug,
            ctx: Arc::clone(&kdc_context),
        })
    });
    let stop = Arc::new(AtomicBool::new(false));
    // SIGTERM/SIGINT stop the accept loop.
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        let _ = signal_hook::flag::register(sig, Arc::clone(&stop));
    }
    let live = Arc::new(AtomicUsize::new(0));
    let replay = ReplayCache::new();
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let accepted = listener.accept();
        match accepted {
            Ok((mut stream, _)) => {
                let _ = stream.set_read_timeout(Some(KPROPD_IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(KPROPD_IO_TIMEOUT));
                if live.load(Ordering::Relaxed) >= MAX_HANDLERS {
                    continue; // dropping `stream` closes the refused connection
                }
                let progname = progname.clone();
                let keytab = keytab.clone();
                let server = server.clone();
                let realm = realm.clone();
                let master = master.clone();
                let db = db.clone();
                let stash = stash.clone();
                let allowed = kpropd_acl(&acl_file);
                let replay = replay.clone();
                let iprop = iprop.clone();
                let poll = wake.clone();
                let alone = poll.is_none();
                let conf = Arc::clone(&conf);
                let kdc_context = Arc::clone(&kdc_context);
                let mut conn = move || {
                    if let Some(keys) =
                        host_keys(&progname, keytab.as_deref(), &server, &kdc_context)
                    {
                        match kpropd_handle_conn(
                            &mut stream,
                            &KpropdConfig {
                                host_keys: &[],
                                keytab: Some(&keys),
                                // recvauth takes kpropd's own principal as the server, so a ticket for another one is refused.
                                expected_server: Some(&server),
                                expected_realm: Some(realm.as_str()),
                                master_password: master.as_deref().map(String::as_bytes),
                                db: &db,
                                stash: &stash,
                                allowed_clients: allowed.as_deref(),
                                iprop: iprop.as_ref(),
                                resync_timeout,
                                conf: &conf,
                            },
                            &replay,
                        ) {
                            Ok(_) => println!("kprop ok"),
                            Err(e) => eprintln!("krb5-kpropd: {e}"),
                        }
                    }
                    // MIT: `do_standalone` (kprop/kpropd.c:466-472)
                    // when a connection is done the iprop poll is woken; without iprop, `-t` ends kpropd.
                    if let Some(w) = &poll {
                        w.poke();
                    }
                };
                if runonce && alone {
                    conn();
                    std::process::exit(0);
                }
                live.fetch_add(1, Ordering::Relaxed);
                let live = Arc::clone(&live);
                thread::spawn(move || {
                    conn();
                    live.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                eprintln!("krb5-kpropd: accept: {e}");
                break;
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Options {
    realm: Option<String>,
    keytab: Option<String>,
    acl_file: PathBuf,
    address: Option<String>,
    port: Option<String>,
    admin_server: Option<String>,
    runonce: bool,
    debug: bool,
}

fn parse_options(progname: &str, args: &[String]) -> Options {
    let (opts, operands) = match krb5_cli::getopt(args, "A:P:r:s:a:DdSt", &[]) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("{progname}: {e}");
            usage(progname);
        }
    };
    let last = |flag: char| {
        opts.iter()
            .rev()
            .find(|o| o.flag == flag)
            .and_then(|o| o.arg.clone())
    };
    let has = |flag: char| opts.iter().any(|o| o.flag == flag);
    if operands.len() > 1 {
        usage(progname);
    }
    Options {
        realm: last('r'),
        keytab: last('s'),
        acl_file: last('a').map_or_else(krb5_config::default_kpropd_acl, PathBuf::from),
        address: operands.into_iter().next(),
        port: last('P'),
        admin_server: last('A'),
        runonce: has('t'),
        debug: has('d'),
    }
}

// MIT: `get_wildcard_addr` (kprop/kpropd.c:362-377)
/// the service is `-P`'s, a services name or a number.
fn listen_addr(progname: &str, operand: Option<&str>, port: Option<&str>) -> SocketAddr {
    if let Some(op) = operand {
        match op.to_socket_addrs().map(|mut a| a.next()) {
            Ok(Some(a)) => return a,
            Ok(None) => eprintln!("{progname}: {op}: no address"),
            Err(e) => eprintln!("{progname}: {op}: {e}"),
        }
        std::process::exit(1);
    }
    let port = port.map_or(KPROP_PORT, |p| {
        kprop_service_port(p).unwrap_or_else(|| {
            eprintln!("getaddrinfo: Servname not supported for ai_socktype");
            std::process::exit(1);
        })
    });
    let (v4, v6) = configured_families();
    wildcard_addr(v4, v6, port).unwrap_or_else(|| {
        eprintln!("getaddrinfo: Name or service not known");
        std::process::exit(1);
    })
}

fn wildcard_addr(v4: bool, v6: bool, port: u16) -> Option<SocketAddr> {
    if v6 {
        Some(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)))
    } else if v4 {
        Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
    } else {
        None
    }
}

/// them: `127.0.0.1` and `::1` do not count, and when the addresses cannot be listed both are taken as present.
fn configured_families() -> (bool, bool) {
    let Ok(addrs) = nix::ifaddrs::getifaddrs() else {
        return (true, true);
    };
    let (mut v4, mut v6) = (false, false);
    for a in addrs.filter_map(|i| i.address) {
        if let Some(sin) = a.as_sockaddr_in() {
            v4 |= sin.ip() != Ipv4Addr::LOCALHOST;
        } else if let Some(sin6) = a.as_sockaddr_in6() {
            v6 |= sin6.ip() != Ipv6Addr::LOCALHOST;
        }
    }
    (v4, v6)
}

fn standalone_listener(progname: &str, addr: SocketAddr) -> TcpListener {
    let report = |e: nix::Error, what: &str| {
        eprintln!(
            "{progname}: {} {what}",
            os_error_text(&std::io::Error::from(e))
        );
    };
    let fatal = |e: nix::Error, what: &str| -> ! {
        report(e, what);
        std::process::exit(1);
    };
    let family = if addr.is_ipv6() {
        AddressFamily::Inet6
    } else {
        AddressFamily::Inet
    };
    let fd = socket(family, SockType::Stream, SockFlag::SOCK_CLOEXEC, None)
        .unwrap_or_else(|e| fatal(e, "while obtaining socket"));
    if let Err(e) = setsockopt(&fd, sockopt::ReuseAddr, &true) {
        report(e, "while setting SO_REUSEADDR option");
    }
    if addr.is_ipv6()
        && let Err(e) = setsockopt(&fd, sockopt::Ipv6V6Only, &false)
    {
        report(e, "while unsetting IPV6_V6ONLY option");
    }
    if let Err(e) = bind(fd.as_raw_fd(), &SockaddrStorage::from(addr)) {
        fatal(e, "while binding listener socket");
    }
    if let Err(e) = listen(&fd, Backlog::new(5).unwrap_or(Backlog::MAXCONN)) {
        fatal(e, "in listen call");
    }
    TcpListener::from(fd)
}

fn usage(progname: &str) -> ! {
    eprintln!(
        "\nUsage: {progname} [-r realm] [-s keytab] [-d] [-D] [-S]\n\t[-P port] [-a acl_file] [-A admin_server] [host:port]"
    );
    std::process::exit(1);
}

struct Poll {
    argv0: String,
    realm: String,
    keytab: Option<String>,
    admin_server: Option<String>,
    params: krb5_config::IpropParams,
    db: PathBuf,
    stash: PathBuf,
    runonce: bool,
    debug: bool,
    ctx: Arc<krb5_config::ClientContext>,
}

fn start_iprop(poll: Poll) -> Arc<IpropWake> {
    let wake = Arc::new(IpropWake::default());
    usr1_wakes(Arc::clone(&wake));
    let poke = Arc::clone(&wake);
    thread::spawn(move || {
        let ret = kpropd_do_iprop(
            &KpropdIprop {
                progname: &poll.argv0,
                realm: &poll.realm,
                keytab: poll.keytab.as_deref(),
                admin_server: poll.admin_server.as_deref(),
                params: &poll.params,
                db: &poll.db,
                stash: &poll.stash,
                runonce: poll.runonce,
                debug: poll.debug,
                ctx: &poll.ctx,
            },
            &poke,
        );
        if ret == 0 {
            std::process::exit(0);
        }
        let line = format!(
            "{}: {} do_iprop failed.",
            poll.argv0,
            os_error_text(&io::Error::from_raw_os_error(1))
        );
        if poll.debug {
            eprintln!("{line}");
        } else {
            klog::syslog(Severity::Err, &line);
        }
        std::process::exit(1);
    });
    wake
}

fn usr1_wakes(wake: Arc<IpropWake>) {
    let Ok((mut rx, tx)) = UnixStream::pair() else {
        return;
    };
    if signal_hook::low_level::pipe::register(signal_hook::consts::SIGUSR1, tx).is_err() {
        return;
    }
    thread::spawn(move || {
        let mut buf = [0u8; 16];
        while rx.read(&mut buf).is_ok_and(|n| n > 0) {
            wake.poke();
        }
    });
}

fn kpropd_paths(realm: Option<&str>) -> Result<krb5_config::KdcPaths, krb5_config::Error> {
    #[cfg(feature = "test-hooks")]
    let test_realm = std::env::var("KRB5_TEST_REALM")
        .unwrap_or_else(|_| krb5_kdc::testrealm::TEST_REALM.to_owned());
    #[cfg(feature = "test-hooks")]
    let realm = realm.or(Some(test_realm.as_str()));
    krb5_config::KdcPaths::resolve(realm)
}

/// read: every peer is refused. Only the trailing `\n` is stripped (`fgets`, `buf[end] == '\n'`); a `\r`, leading whitespace or a `#` stay in the line and simply never match a principal.
fn kpropd_acl(path: &Path) -> Option<Vec<String>> {
    let text = String::from_utf8_lossy(&std::fs::read(path).ok()?).into_owned();
    Some(text.split('\n').map(str::to_owned).collect())
}

fn host_keys(
    progname: &str,
    keytab: Option<&str>,
    server: &PrincipalName,
    ctx: &krb5_config::ClientContext,
) -> Option<KpropdKeys> {
    match kpropd_keytab_keys(keytab, Some(server), ctx) {
        Ok(keys) => Some(keys),
        Err(e) => {
            eprintln!("{progname}: Error in krb5_kt_resolve: {e}");
            None
        }
    }
}
