//! MIT-wire kpropd (TCP 754) wrapping dump version 7.
//!
//! Usage: `krb5-kpropd [-r realm] [host:port]`
//!
//! Without an address kpropd listens as MIT's standalone kpropd: on port 754 of every address,
//! through one IPv6 socket that also takes IPv4 when the host has an IPv6 address other than
//! `::1`, else through an IPv4 one when it has an IPv4 address other than `127.0.0.1`; with
//! neither, kpropd stops as MIT's does.
//!
//! The realm is `-r`, else `KRB5_KDC_REALM`, else krb5.conf's `default_realm`, as MIT's kpropd
//! takes `-r` or the default realm. The dump body is opened with the replica's stash, as MIT's
//! kpropd loads it with `kdb5_util load` beside that stash, and saved to the replica db.
//!
//! kerber-rust's own environment, where this kpropd has none of MIT's options yet (it is not
//! installed as a service):
//! - `KRB5_KDC_REALM`: the realm, beside `-r`.
//! - `KRB5_KPROP_KEYTAB`: the keys that accept `sendauth` (MIT's `-s`, else the default
//!   keytab); unset, there are none and kpropd stops.
//! - `KRB5_KPROP_ACL`: the `kpropd.acl` file (MIT's `-a`, else `kpropd.acl` in the KDC
//!   directory); unset or empty, every peer is refused.
//!
//! With the `test-hooks` feature, the realm falls back to `KRB5_TEST_REALM`, else the documented
//! test realm, before the default realm; the documented test realm's host keys in the database
//! stand in for a keytab; and `KRB5_MASTER_PASSWORD` opens the dump instead of the stash when
//! set.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, ToSocketAddrs};
use std::os::fd::AsRawFd as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use krb5_admin::{KPROP_PORT, KpropdConfig, kpropd_handle_conn};
use krb5_crypto::ProtocolKey;
use krb5_log::klog::os_error_text;
use nix::sys::socket::{
    AddressFamily, Backlog, SockFlag, SockType, SockaddrStorage, bind, listen, setsockopt, socket,
    sockopt,
};

use krb5_protocol::{Keytab, ReplayCache};

fn main() {
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "krb5_admin=info,krb5_kdc=info".into()),
        )
        .try_init();

    let argv: Vec<String> = std::env::args().collect();
    let progname = argv
        .first()
        .map_or("krb5-kpropd", |a| a.rsplit('/').next().unwrap_or(a))
        .to_owned();
    // MIT `parse_args` (`kprop/kpropd.c:1065-1126`): glibc getopt over the options, a value attached or apart; a bad option is the usage.
    let (opts, operands) = match krb5_cli::getopt(argv.get(1..).unwrap_or_default(), "r:", &[]) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("{progname}: {e}");
            usage(&progname);
        }
    };
    let realm_opt = opts
        .iter()
        .rev()
        .find(|o| o.flag == 'r')
        .and_then(|o| o.arg.clone());
    // The one operand, `host:port`, is this kpropd's own; MIT's takes none.
    if operands.len() > 1 {
        usage(&progname);
    }
    #[cfg(feature = "test-hooks")]
    let master = std::env::var("KRB5_MASTER_PASSWORD")
        .ok()
        .map(zeroize::Zeroizing::new);
    #[cfg(not(feature = "test-hooks"))]
    let master: Option<zeroize::Zeroizing<String>> = None;
    let paths = kpropd_paths(realm_opt).unwrap_or_else(|e| {
        // MIT `parse_args` (`kprop/kpropd.c:1132-1138`): no realm is this line, exit 1.
        if matches!(e, krb5_config::Error::NoDefaultRealm) {
            eprintln!("krb5-kpropd: {e} Unable to get default realm");
        } else {
            eprintln!("krb5-kpropd: {e}");
        }
        std::process::exit(1);
    });
    let realm = paths.realm.clone().unwrap_or_default();
    let (db, stash) = (paths.database_name, paths.key_stash_file);
    let host_keys = load_host_keys(&db, &stash);
    if host_keys.is_empty() {
        eprintln!("krb5-kpropd: no host keys (set KRB5_KPROP_KEYTAB)");
        std::process::exit(1);
    }
    let addr = listen_addr(&progname, operands.first().map(String::as_str));
    let listener = standalone_listener(&progname, addr);
    listener.set_nonblocking(true).ok();
    println!("listening {}", listener.local_addr().unwrap_or(addr));
    let stop = Arc::new(AtomicBool::new(false));
    let replay = ReplayCache::new();
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let accepted = listener.accept();
        match accepted {
            Ok((mut stream, _)) => {
                let keys = host_keys.clone();
                let realm = realm.clone();
                let master = master.clone();
                let db = db.clone();
                let stash = stash.clone();
                let allowed = kpropd_acl();
                let replay = replay.clone();
                thread::spawn(move || {
                    match kpropd_handle_conn(
                        &mut stream,
                        &KpropdConfig {
                            host_keys: &keys,
                            expected_server: None,
                            expected_realm: Some(realm.as_str()),
                            master_password: master.as_deref().map(String::as_bytes),
                            db: &db,
                            stash: &stash,
                            allowed_clients: allowed.as_deref(),
                        },
                        replay,
                    ) {
                        Ok(_) => println!("kprop ok"),
                        Err(e) => eprintln!("krb5-kpropd: {e}"),
                    }
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

/// The address to listen on: the operand, else the wildcard of [`wildcard_addr`]; one that cannot
/// be had ends kpropd.
/// MIT `do_standalone` (`kprop/kpropd.c:389-393`): with no wildcard address `getaddrinfo` fails (`EAI_NONAME`), and kpropd exits.
fn listen_addr(progname: &str, operand: Option<&str>) -> SocketAddr {
    if let Some(op) = operand {
        match op.to_socket_addrs().map(|mut a| a.next()) {
            Ok(Some(a)) => return a,
            Ok(None) => eprintln!("{progname}: {op}: no address"),
            Err(e) => eprintln!("{progname}: {op}: {e}"),
        }
        std::process::exit(1);
    }
    let (v4, v6) = configured_families();
    wildcard_addr(v4, v6, KPROP_PORT).unwrap_or_else(|| {
        eprintln!("getaddrinfo: Name or service not known");
        std::process::exit(1);
    })
}

/// The wildcard kpropd listens on: IPv6's when the host has an IPv6 address, else IPv4's when it
/// has an IPv4 one; with neither there is none.
/// MIT `get_wildcard_addr` (`kprop/kpropd.c:362-377`): a passive `AI_ADDRCONFIG` lookup for IPv6, then for IPv4.
fn wildcard_addr(v4: bool, v6: bool, port: u16) -> Option<SocketAddr> {
    if v6 {
        Some(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)))
    } else if v4 {
        Some(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
    } else {
        None
    }
}

/// Whether the host has an IPv4 address and an IPv6 address, as glibc's `AI_ADDRCONFIG` counts
/// them: `127.0.0.1` and `::1` do not count, and when the addresses cannot be listed both are
/// taken as present.
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

/// kpropd's listening socket on `addr`, as MIT's standalone kpropd makes it: `SO_REUSEADDR`, an
/// IPv6 socket that takes IPv4 too whatever the host's default (`IPV6_V6ONLY` off), and a backlog
/// of 5. A failure is reported as MIT's reports it; one other than an option's ends kpropd.
/// MIT `do_standalone` (`kprop/kpropd.c:395-422`): the socket, `SO_REUSEADDR` and `IPV6_V6ONLY` off (their failures reported and let pass), then bind and listen.
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

/// The usage text on stderr, exit status 1.
/// MIT `usage` (`kprop/kpropd.c:168-177`): the text, then `exit(1)`.
fn usage(progname: &str) -> ! {
    eprintln!("\nUsage: {progname} [-r realm] [host:port]");
    std::process::exit(1);
}

/// The realm's paths: `-r`, else `KRB5_KDC_REALM`, else (with the `test-hooks` feature)
/// `KRB5_TEST_REALM` or the documented test realm, else krb5.conf's `default_realm`.
/// MIT `parse_args` (`kprop/kpropd.c:1132-1145`): `-r`, else the default realm.
fn kpropd_paths(realm: Option<String>) -> Result<krb5_config::KdcPaths, krb5_config::Error> {
    #[cfg(feature = "test-hooks")]
    let test_realm = Some(
        std::env::var("KRB5_TEST_REALM")
            .unwrap_or_else(|_| krb5_kdc::testrealm::TEST_REALM.to_owned()),
    );
    #[cfg(not(feature = "test-hooks"))]
    let test_realm: Option<String> = None;
    let realm = realm
        .or_else(|| std::env::var("KRB5_KDC_REALM").ok())
        .or(test_realm);
    krb5_config::KdcPaths::resolve(realm.as_deref())
}

/// Raw `kpropd.acl` lines for `kpropd_authorized_principal`, read per
/// connection like MIT `authorized_principal` (`fopen` on every peer, so
/// edits apply without a restart). Unset `KRB5_KPROP_ACL` or an unopenable
/// file is `None`: every peer is refused. Only the trailing `\n` is
/// stripped (`fgets`, `buf[end] == '\n'`); a `\r`, leading whitespace or a
/// `#` stay in the line and simply never match a principal.
fn kpropd_acl() -> Option<Vec<String>> {
    let path = std::env::var("KRB5_KPROP_ACL").ok()?;
    let text = String::from_utf8_lossy(&std::fs::read(&path).ok()?).into_owned();
    Some(text.split('\n').map(str::to_owned).collect())
}

fn load_host_keys(db: &Path, stash: &Path) -> Vec<ProtocolKey> {
    if let Ok(path) = std::env::var("KRB5_KPROP_KEYTAB") {
        match std::fs::read(&path).and_then(|b| Keytab::parse(&b)) {
            Ok(kt) => {
                return kt.entries.into_iter().map(|e| e.key).collect();
            }
            Err(e) => eprintln!("krb5-kpropd: keytab {path}: {e}"),
        }
    }
    #[cfg(feature = "test-hooks")]
    if let Ok(store) = krb5_kdc::load_store(db, stash)
        && store.realm() == krb5_kdc::testrealm::TEST_REALM
        && let Some(p) = store.get_name(&krb5_kdc::testrealm::documented_host())
    {
        return p.keys.iter().map(|k| k.key.clone()).collect();
    }
    #[cfg(not(feature = "test-hooks"))]
    let _ = (db, stash);
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wildcard_prefers_ipv6_as_mits_get_wildcard_addr() {
        let v6 = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 754));
        let v4 = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 754));
        assert_eq!(wildcard_addr(true, true, 754), Some(v6));
        assert_eq!(wildcard_addr(false, true, 754), Some(v6));
        assert_eq!(wildcard_addr(true, false, 754), Some(v4));
        assert_eq!(wildcard_addr(false, false, 754), None);
    }

    /// MIT `do_standalone` (`kprop/kpropd.c:401-412`): the IPv6 listener takes IPv4 too, whatever `net.ipv6.bindv6only` says.
    #[test]
    fn the_ipv6_listener_takes_ipv4_too() {
        use nix::sys::socket::{getsockopt, sockopt};
        if std::net::UdpSocket::bind("[::1]:0").is_err() {
            return;
        }
        let l = standalone_listener("kpropd", SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)));
        assert!(!getsockopt(&l, sockopt::Ipv6V6Only).unwrap());
        assert!(getsockopt(&l, sockopt::ReuseAddr).unwrap());
        let port = l.local_addr().unwrap().port();
        for a in [
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
        ] {
            let _client = std::net::TcpStream::connect(a).unwrap();
            assert!(l.accept().is_ok(), "{a}");
        }
    }
}
