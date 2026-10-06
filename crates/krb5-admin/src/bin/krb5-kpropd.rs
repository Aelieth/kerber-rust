//! MIT-wire kpropd (TCP 754) wrapping dump version 7: a replica's full propagation.
//!
//! ```text
//! kpropd [-r realm] [-s keytab] [-a acl_file] [host:port]
//! ```
//!
//! The options are MIT's, read as its `getopt` reads them, the last of each one winning; MIT's
//! others (`-A`, `-d`, `-D`, `-f`, `-F`, `-p`, `-P`, `-S`, `-t`, `-x`, `--pid-file`) print the
//! usage. kpropd reads no environment of its own: MIT's reads none.
//! - `-r` names the realm, else krb5.conf's `default_realm`.
//! - `-s` names the keytab, else the default keytab (`KRB5_KTNAME`, else the KDC profile's
//!   `default_keytab_name`, else `/etc/krb5.keytab`), read for each connection, as MIT's is.
//!   kpropd authenticates as its own principal, `host/<this host>@<realm>`
//!   ([`kpropd_server_name`]: without DNS, a hostname without a dot gains the profile's
//!   `qualify_shortname`, else the resolver's first search domain): the keytab's entry for it, of
//!   the ticket's kvno and enctype, is the key kprop's ticket must open, as MIT's, so a ticket
//!   for another principal is refused; with `ignore_acceptor_hostname` any `host` entry of the
//!   realm serves. A keytab that cannot be read, or has no such entry, answers "Service key not
//!   available", and one that is no keytab "Unsupported key table format version number"; a
//!   default name of no known type answers "Unknown Key table type", and a `-s` one ends the
//!   connection, as MIT's. A name of its own that is not ASCII stops kpropd at its start.
//! - `-a` names the `kpropd.acl` file, else `kpropd.acl` in the KDC directory. It is read for
//!   each connection, as MIT's is; one that cannot be opened refuses every peer.
//! - The one operand, `host:port`, is this kpropd's own (MIT's takes none): the address to
//!   listen on.
//!
//! Without an address kpropd listens as MIT's standalone kpropd: on port 754 of every address,
//! through one IPv6 socket that also takes IPv4 when the host has an IPv6 address other than
//! `::1`, else through an IPv4 one when it has an IPv4 address other than `127.0.0.1`; with
//! neither, kpropd stops as MIT's does. It does not detach.
//!
//! The dump body is opened with the replica's stash, as MIT's kpropd loads it with
//! `kdb5_util load` beside that stash, and saved to the replica db. With `iprop_enable` set for
//! the realm, kpropd maps the replica's update log at the start, and a dump must be an iprop one,
//! whose serial and time the log then keeps (MIT's `load -i`); without it, an iprop dump is
//! refused as a plain `load` refuses it.
//!
//! With the `test-hooks` feature, the realm falls back to `KRB5_TEST_REALM`, else the documented
//! test realm, before the default realm, and `KRB5_MASTER_PASSWORD` opens the dump instead of the
//! stash when set.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, ToSocketAddrs};
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use krb5_admin::{
    KPROP_PORT, KpropdConfig, KpropdKeys, kpropd_handle_conn, kpropd_keytab_keys,
    kpropd_server_name,
};
use krb5_log::klog::{JsonLog, os_error_text};
use nix::sys::socket::{
    AddressFamily, Backlog, SockFlag, SockType, SockaddrStorage, bind, listen, setsockopt, socket,
    sockopt,
};

use krb5_protocol::ReplayCache;
use krb5_types::PrincipalName;

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let progname = argv
        .first()
        .map_or("krb5-kpropd", |a| a.rsplit('/').next().unwrap_or(a))
        .to_owned();
    // MIT `parse_args` (`kprop/kpropd.c:1056-1062`): the KDC context before the options; a
    // profile it refuses ends kpropd, named as invoked.
    if let Err(e) = krb5_config::init_kdc_profile() {
        let argv0 = argv.first().map_or("kpropd", String::as_str);
        eprintln!("{argv0}: {} while initializing krb5", e.init_text());
        std::process::exit(1);
    }
    // The JSON log only where the KDC profile's `[logging] json` names a destination (MIT has
    // none).
    if let Some(json) =
        krb5_config::LogSpecs::load_json().and_then(|s| JsonLog::open(&progname, &s))
    {
        let _ = tracing_subscriber::fmt()
            .json()
            .with_writer(json.make_writer())
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "krb5_admin=info,krb5_kdc=info".into()),
            )
            .try_init();
    }
    let Options {
        realm: realm_opt,
        keytab,
        acl_file,
        address,
    } = parse_options(&progname, argv.get(1..).unwrap_or_default());
    #[cfg(feature = "test-hooks")]
    let master = std::env::var("KRB5_MASTER_PASSWORD")
        .ok()
        .map(zeroize::Zeroizing::new);
    #[cfg(not(feature = "test-hooks"))]
    let master: Option<zeroize::Zeroizing<String>> = None;
    let paths = kpropd_paths(realm_opt.as_deref()).unwrap_or_else(|e| {
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
    // MIT `parse_args` (`kprop/kpropd.c:1147-1153`): kpropd's own principal, `host` and this host in its realm, is made once; a name that cannot be made ends kpropd.
    let server = kpropd_server_name().unwrap_or_else(|_| {
        let argv0 = argv.first().map_or("kpropd", String::as_str);
        eprintln!(
            "{argv0}: Illegal character in component name while trying to construct my service name"
        );
        std::process::exit(1);
    });
    // MIT `parse_args` (`kprop/kpropd.c:1170-1177`): with iprop enabled the replica's update log is mapped at the start, and one that cannot be is fatal.
    let iprop = krb5_config::IpropParams::load(&realm, &db);
    if iprop.enabled
        && let Err(e) = krb5_kdc::Ulog::map(&iprop.logfile, iprop.ulogsize)
    {
        eprintln!("{progname}: {e} Unable to map log!");
        std::process::exit(1);
    }
    let iprop = iprop.enabled.then_some(iprop);
    let addr = listen_addr(&progname, address.as_deref());
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
                thread::spawn(move || {
                    let Some(keys) = host_keys(&progname, keytab.as_deref(), &server) else {
                        return;
                    };
                    match kpropd_handle_conn(
                        &mut stream,
                        &KpropdConfig {
                            host_keys: &[],
                            keytab: Some(&keys),
                            // MIT `kerberos_authenticate` (`kprop/kpropd.c:1258-1259`): recvauth takes kpropd's own principal as the server, so a ticket for another one is refused.
                            expected_server: Some(&server),
                            expected_realm: Some(realm.as_str()),
                            master_password: master.as_deref().map(String::as_bytes),
                            db: &db,
                            stash: &stash,
                            allowed_clients: allowed.as_deref(),
                            iprop: iprop.as_ref(),
                        },
                        &replay,
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

/// The command line.
#[derive(Debug, PartialEq, Eq)]
struct Options {
    /// `-r`.
    realm: Option<String>,
    /// `-s`: the keytab's name, read for each connection; `None` is the default keytab.
    keytab: Option<String>,
    /// `-a`, else `kpropd.acl` in the KDC directory.
    acl_file: PathBuf,
    /// The `host:port` operand, this kpropd's own.
    address: Option<String>,
}

/// kpropd's options; a bad option, or more than one operand, prints the usage.
/// MIT `parse_args` (`kprop/kpropd.c:1065-1126`): glibc getopt over the options, a value attached or apart; a bad option is the usage.
fn parse_options(progname: &str, args: &[String]) -> Options {
    let (opts, operands) = match krb5_cli::getopt(args, "r:s:a:", &[]) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("{progname}: {e}");
            usage(progname);
        }
    };
    // MIT `parse_args` (`kprop/kpropd.c:1084-1101`): `-r` the realm, `-s` the keytab, `-a` the ACL file, each option's last value kept.
    let last = |flag: char| {
        opts.iter()
            .rev()
            .find(|o| o.flag == flag)
            .and_then(|o| o.arg.clone())
    };
    // The one operand, `host:port`, is this kpropd's own; MIT's takes none.
    if operands.len() > 1 {
        usage(progname);
    }
    Options {
        realm: last('r'),
        keytab: last('s'),
        // MIT `acl_file_name` (`kprop/kpropd.c:137-137`): `KPROPD_ACL_FILE` unless `-a` names another.
        acl_file: last('a').map_or_else(krb5_config::default_kpropd_acl, PathBuf::from),
        address: operands.into_iter().next(),
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
    eprintln!("\nUsage: {progname} [-r realm] [-s keytab] [-a acl_file] [host:port]");
    std::process::exit(1);
}

/// The realm's paths: `-r`, else (with the `test-hooks` feature) `KRB5_TEST_REALM` or the
/// documented test realm, else krb5.conf's `default_realm`.
/// MIT `parse_args` (`kprop/kpropd.c:1132-1145`): `-r`, else the default realm.
fn kpropd_paths(realm: Option<&str>) -> Result<krb5_config::KdcPaths, krb5_config::Error> {
    #[cfg(feature = "test-hooks")]
    let test_realm = std::env::var("KRB5_TEST_REALM")
        .unwrap_or_else(|_| krb5_kdc::testrealm::TEST_REALM.to_owned());
    #[cfg(feature = "test-hooks")]
    let realm = realm.or(Some(test_realm.as_str()));
    krb5_config::KdcPaths::resolve(realm)
}

/// Raw `kpropd.acl` lines for `kpropd_authorized_principal`, read from `path` (`-a`, else
/// `kpropd.acl` in the KDC directory) for each connection; `None` for a file that cannot be
/// read: every peer is refused. Only the trailing `\n` is stripped (`fgets`,
/// `buf[end] == '\n'`); a `\r`, leading whitespace or a `#` stay in the line and simply never
/// match a principal.
/// MIT `authorized_principal` (`kprop/kpropd.c:1312-1314`): `acl_file_name` is opened for every peer, so edits apply without a restart, and one that does not open authorizes no one.
fn kpropd_acl(path: &Path) -> Option<Vec<String>> {
    let text = String::from_utf8_lossy(&std::fs::read(path).ok()?).into_owned();
    Some(text.split('\n').map(str::to_owned).collect())
}

/// kpropd's keytab for one connection ([`kpropd_keytab_keys`]); `None` when `-s` names a keytab
/// of a type `krb5_kt_resolve` does not know: the connection then ends.
/// MIT `kerberos_authenticate` (`kprop/kpropd.c:1249-1256`): a keytab name that does not resolve is logged ("Error in krb5_kt_resolve") and ends the connection.
fn host_keys(progname: &str, keytab: Option<&str>, server: &PrincipalName) -> Option<KpropdKeys> {
    match kpropd_keytab_keys(keytab, Some(server)) {
        Ok(keys) => Some(keys),
        Err(e) => {
            eprintln!("{progname}: Error in krb5_kt_resolve: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    /// MIT `parse_args` (`kprop/kpropd.c:1084-1101`): the keytab, ACL file and realm come from `-s`, `-a` and `-r`, the last of each winning.
    #[test]
    fn the_keytab_acl_and_realm_are_mits_options() {
        let o = parse_options(
            "kpropd",
            &args(&[
                "-s", "/k1", "-a/a1", "-r", "R1", "-s/k2", "-a", "/a2", "-rR2", "h:1",
            ]),
        );
        assert_eq!(
            o,
            Options {
                realm: Some("R2".into()),
                keytab: Some("/k2".into()),
                acl_file: PathBuf::from("/a2"),
                address: Some("h:1".into()),
            }
        );
    }

    /// MIT `acl_file_name` (`kprop/kpropd.c:137-137`): without `-a` the ACL is `kpropd.acl` in the KDC directory, and without `-s` the keytab is the default one.
    #[test]
    fn without_options_the_acl_and_keytab_are_mits_defaults() {
        let o = parse_options("kpropd", &[]);
        assert_eq!(
            o,
            Options {
                realm: None,
                keytab: None,
                acl_file: Path::new(krb5_config::KDC_DIR).join("kpropd.acl"),
                address: None,
            }
        );
    }

    /// MIT `authorized_principal` (`kprop/kpropd.c:1312-1314`): the file is read again for each peer, and one that does not open authorizes no one.
    #[test]
    fn the_acl_is_read_for_each_connection() {
        let dir = krb5_testkit::scratch_dir("kpropd-acl");
        let acl = dir.join("kpropd.acl");
        assert_eq!(kpropd_acl(&acl), None);
        std::fs::write(&acl, "host/a@R\nhost/b@R\n").unwrap();
        assert_eq!(
            kpropd_acl(&acl).unwrap(),
            ["host/a@R", "host/b@R", ""].map(String::from)
        );
        std::fs::write(&acl, "host/c@R").unwrap();
        assert_eq!(kpropd_acl(&acl).unwrap(), ["host/c@R"].map(String::from));
        let _ = std::fs::remove_dir_all(&dir);
    }

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
