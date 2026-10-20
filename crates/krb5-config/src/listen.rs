//! Listener address lists: `kdc_listen` / `kdc_ports`, `kdc_tcp_listen` / `kdc_tcp_ports`,
//! `kadmind_listen` / `kadmind_port`, `kpasswd_listen` / `kpasswd_port`.
//!
//! MIT `loop_add_addresses` (`lib/apputils/net-server.c:381-433`): a list is split on `,`,
//! `;` or space, and a `/path` entry is a UNIX-domain listener (skipped here: this port binds
//! no UNIX sockets).
//! MIT `k5_parse_host_string` (`lib/krb5/krb/parse_host_string.c:70-124`): an entry is a
//! port, a host, `host:port` or `[v6]:port`; a bad port is an error, so the daemon does not
//! start.
//! MIT `loop_add_address` (`lib/apputils/net-server.c:304-361`): a daemon's listeners are one
//! list ([`BindAddresses`]) that each service adds to before any socket is bound; an entry
//! without a host is the wildcard, which drops the direct addresses of its kind on its port, and
//! one that meets the wildcard or itself there is not added.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use super::Error;

/// MIT `KRB5_DEFAULT_PORT` (`include/osconf.hin:95-95`): the KDC's port.
pub const KDC_PORT: u16 = 88;
/// MIT `DEFAULT_KDC_PORTLIST` (`include/osconf.hin:99-99`): the KDC's UDP list when neither
/// the realm stanza nor `[kdcdefaults]` names one.
pub const DEFAULT_KDC_PORTLIST: &str = "88";
/// MIT `DEFAULT_KADM5_PORT` (`include/osconf.hin:107-107`): kadmind's port.
pub const KADMIND_PORT: u16 = 749;
/// MIT `DEFAULT_KPASSWD_PORT` (`include/osconf.hin:97-97`): kpasswd's port.
pub const KPASSWD_PORT: u16 = 464;
/// MIT `ADDRESSES_DELIM` (`include/net-server.h:36-36`): the list separators.
const ADDRESSES_DELIM: &[char] = &[',', ';', ' '];

/// One requested listener. `host` `None` is the wildcard address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenAddr {
    /// Host name or address literal (brackets removed); `None` for the wildcard.
    pub host: Option<String>,
    /// Port.
    pub port: u16,
}

impl ListenAddr {
    /// The socket addresses to bind.
    /// MIT `setup_addresses` (`lib/apputils/net-server.c:927-1049`): `getaddrinfo` with
    /// `AI_PASSIVE` gives the wildcard as `0.0.0.0` and `[::]`, and a host name as every
    /// address it resolves to.
    ///
    /// # Errors
    ///
    /// [`Error::Parse`] when the host does not resolve (MIT: "Failed getting address info",
    /// and the daemon does not start).
    pub fn resolve(&self) -> Result<Vec<SocketAddr>, Error> {
        let Some(host) = self.host.as_deref() else {
            return Ok(vec![
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, self.port)),
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, self.port)),
            ]);
        };
        let mut out: Vec<SocketAddr> = Vec::new();
        let addrs = (host, self.port)
            .to_socket_addrs()
            .map_err(|e| Error::Parse(format!("listen address {host}: {e}")))?;
        for a in addrs {
            if !out.contains(&a) {
                out.push(a);
            }
        }
        if out.is_empty() {
            return Err(Error::Parse(format!("listen address {host}: no addresses")));
        }
        Ok(out)
    }
}

impl std::fmt::Display for ListenAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.host.as_deref() {
            None => write!(f, "*:{}", self.port),
            Some(h) if h.contains(':') => write!(f, "[{h}]:{}", self.port),
            Some(h) => write!(f, "{h}:{}", self.port),
        }
    }
}

/// MIT `k5_parse_host_string`: an all-digit entry is a port; `[host]` or `[host]:port`;
/// otherwise the host runs to the first space, tab or colon and a colon starts the port.
///
/// # Errors
///
/// [`Error::Parse`] for an empty entry, one that starts with `:`, or a port that is not a
/// decimal number up to 65535 (MIT `EINVAL`).
pub fn parse_host_string(address: &str, default_port: u16) -> Result<ListenAddr, Error> {
    parse_entry(address, i32::from(default_port))
}

/// [`parse_host_string`] on a default port as the profile gives it, an `int`.
/// MIT `k5_parse_host_string` (`lib/krb5/krb/parse_host_string.c:85-108`): a default port outside 0 to 65535 is `EINVAL`, and a written one is read with `strtoul`, which takes leading blanks and a sign, and must end the entry.
fn parse_entry(address: &str, default_port: i32) -> Result<ListenAddr, Error> {
    let bad = || Error::Parse(format!("listen address {address:?}: invalid"));
    if address.is_empty() || address.starts_with(':') {
        return Err(bad());
    }
    let default_port = u16::try_from(default_port).map_err(|_| bad())?;
    let (host, port): (Option<&str>, Option<&str>) = if address.bytes().all(|b| b.is_ascii_digit())
    {
        (None, Some(address))
    } else if let Some(rest) = address.strip_prefix('[')
        && let Some(close) = rest.find(']')
    {
        let after = &rest[close + 1..];
        (Some(&rest[..close]), after.strip_prefix(':'))
    } else {
        let end = address.find([' ', '\t', ':']).unwrap_or(address.len());
        let port = address[end..].strip_prefix(':');
        (Some(&address[..end]), port)
    };
    let port = match port {
        Some(p) => strtoul_port(p).ok_or_else(bad)?,
        None => default_port,
    };
    Ok(ListenAddr {
        host: host.map(ToOwned::to_owned),
        port,
    })
}

/// C `strtoul(p, &end, 10)` taken as a port: blanks, then a sign, then at least one digit, which
/// must run to the end; a minus sign wraps the value, so only `-0` stays a port.
fn strtoul_port(p: &str) -> Option<u16> {
    let t = p.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u16 = digits.parse().ok()?;
    (!neg || n == 0).then_some(n)
}

/// MIT `loop_add_addresses`: the listeners one configured list asks for, as [`BindAddresses`]
/// keeps them. `None` is the wildcard on `default_port`.
///
/// # Errors
///
/// [`Error::Parse`] from [`parse_host_string`] for any entry.
pub fn listen_addrs(addresses: Option<&str>, default_port: u16) -> Result<Vec<ListenAddr>, Error> {
    let mut list = BindAddresses::default();
    list.add_addresses(addresses, i32::from(default_port), BindType::Udp, &())?;
    Ok(list.entries.into_iter().map(|b| b.addr).collect())
}

/// A listener's socket kind. This port binds no UNIX-domain socket.
/// MIT `enum bind_type` (`lib/apputils/net-server.c:130-132`): UDP, TCP, RPC or UNIX.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindType {
    /// A UDP socket.
    Udp,
    /// A TCP stream.
    Tcp,
    /// A TCP stream an ONC RPC program is served on.
    Rpc,
}

impl BindType {
    /// MIT `bind_type_names` (`lib/apputils/net-server.c:134-139`): the name the daemon log gives the kind.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Rpc => "RPC",
        }
    }
}

/// One listener of a daemon's list: the address, the socket kind, and the service it was added
/// for (for an RPC listener, its program).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindAddress<S> {
    /// The address and port.
    pub addr: ListenAddr,
    /// The socket kind.
    pub kind: BindType,
    /// The service that added it.
    pub service: S,
}

/// A line [`BindAddresses`] logs as entries are added, at MIT's priority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenLog {
    /// `LOG_DEBUG`.
    Debug(String),
    /// `LOG_ERR`.
    Err(String),
}

/// A daemon's listener list, which each of its services adds to before any socket is bound, so
/// that one service's entry can drop or replace another's of the same kind and port. MIT's
/// net-server keeps one, `bind_addresses`, for the process.
/// MIT `struct bind_address` (`lib/apputils/net-server.c:214-219`): an entry is an address, a port, a kind and an RPC program.
#[derive(Clone, Debug)]
pub struct BindAddresses<S> {
    entries: Vec<BindAddress<S>>,
    log: Vec<ListenLog>,
}

impl<S> Default for BindAddresses<S> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            log: Vec::new(),
        }
    }
}

impl<S: Clone> BindAddresses<S> {
    /// Add each listener `addresses` names, on `default_port` when an entry has no port; `None`
    /// is the wildcard there. A `/path` entry is a UNIX-domain socket, skipped here as for any
    /// kind but MIT's UNIX one.
    /// MIT `loop_add_addresses` (`lib/apputils/net-server.c:381-433`): the list is split on `ADDRESSES_DELIM`, and each entry parsed by `k5_parse_host_string` and added by `loop_add_address`.
    ///
    /// # Errors
    ///
    /// [`Error::Parse`] for an entry [`parse_host_string`] refuses, or a port outside 0 to
    /// 65535 (MIT `EINVAL`).
    pub fn add_addresses(
        &mut self,
        addresses: Option<&str>,
        default_port: i32,
        kind: BindType,
        service: &S,
    ) -> Result<(), Error> {
        let Some(addresses) = addresses else {
            return self.add(None, default_port, kind, service);
        };
        for entry in addresses.split(ADDRESSES_DELIM).filter(|s| !s.is_empty()) {
            if entry.starts_with('/') {
                continue;
            }
            let addr = parse_entry(entry, default_port)?;
            self.add(addr.host, i32::from(addr.port), kind, service)?;
        }
        Ok(())
    }

    /// Add one listener. From the last entry to the first, one of the same kind on the same port
    /// conflicts: a wildcard being added removes a direct address, and when the one there is the
    /// wildcard or the same address, the new one is not added.
    /// MIT `loop_add_address` (`lib/apputils/net-server.c:313-339`): "Invalid port %d" at error for a port outside 0 to 65535; "Removing address %s since wildcard address is being added" and "Address already added to server" at debug.
    /// MIT `FOREACH_ELT` (`lib/apputils/net-server.c:178-179`): the list is walked from the top.
    /// MIT `DEL` (`lib/apputils/net-server.c:197-198`): a removed entry takes the last one's place.
    ///
    /// # Errors
    ///
    /// [`Error::Parse`] for a port outside 0 to 65535.
    pub fn add(
        &mut self,
        host: Option<String>,
        port: i32,
        kind: BindType,
        service: &S,
    ) -> Result<(), Error> {
        let Ok(port) = u16::try_from(port) else {
            let line = format!("Invalid port {port}");
            self.log.push(ListenLog::Err(line.clone()));
            return Err(Error::Parse(line));
        };
        for i in (0..self.entries.len()).rev() {
            let val = &self.entries[i];
            if val.kind != kind || val.addr.port != port {
                continue;
            }
            match (&host, &val.addr.host) {
                (None, Some(direct)) => {
                    self.log.push(ListenLog::Debug(format!(
                        "Removing address {direct} since wildcard address is being added"
                    )));
                    self.entries.swap_remove(i);
                }
                (_, None) => {
                    self.log
                        .push(ListenLog::Debug("Address already added to server".into()));
                    return Ok(());
                }
                (Some(h), Some(v)) if h == v => {
                    self.log
                        .push(ListenLog::Debug("Address already added to server".into()));
                    return Ok(());
                }
                _ => {}
            }
        }
        self.entries.push(BindAddress {
            addr: ListenAddr { host, port },
            kind,
            service: service.clone(),
        });
        Ok(())
    }

    /// The listeners, in the order they are set up.
    #[must_use]
    pub fn entries(&self) -> &[BindAddress<S>] {
        &self.entries
    }

    /// The lines adding has logged, in order, taken once for the daemon log.
    pub fn take_log(&mut self) -> Vec<ListenLog> {
        std::mem::take(&mut self.log)
    }
}

/// The port written in an `admin_server` value (`host:port` or `[v6]:port`), which sets
/// kadmind's port ahead of `-port` and `kadmind_port`; `None` when the value names no port.
/// MIT `parse_admin_server_port` (`lib/kadm5/alt_prof.c:395-417`): a written port is read with `atoi`, so one that is no number is 0, and it is kept.
#[must_use]
pub fn admin_server_port(server: &str) -> Option<i32> {
    let port = if let Some(rest) = server.strip_prefix('[')
        && let Some(close) = rest.find(']')
    {
        rest[close + 1..].strip_prefix(':')?
    } else {
        server.split_once(':')?.1
    };
    Some(atoi(port))
}

/// C `atoi`: `(int) strtol(s, NULL, 10)`: blanks, a sign, then the digits up to the first other
/// character; none is 0, and a value past a `long` is clamped before it is cut to an `int`.
fn atoi(s: &str) -> i32 {
    let t = s.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let (neg, rest) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let mut n: i128 = 0;
    for b in rest.bytes().take_while(u8::is_ascii_digit) {
        n = (n * 10 + i128::from(b - b'0')).min(i128::from(i64::MAX) + 1);
    }
    let n = if neg { -n } else { n };
    let long =
        i64::try_from(n.clamp(i128::from(i64::MIN), i128::from(i64::MAX))).unwrap_or_default();
    let [a, b, c, d, ..] = long.to_le_bytes();
    i32::from_le_bytes([a, b, c, d])
}

/// The host an `admin_server` value names: the name or address inside brackets, else the value
/// up to its first colon.
/// MIT `parse_admin_server_port` (`lib/kadm5/alt_prof.c:395-417`): brackets are taken off, else the name ends at the first colon.
#[must_use]
pub fn admin_server_host(server: &str) -> &str {
    if let Some(rest) = server.strip_prefix('[')
        && let Some(close) = rest.find(']')
    {
        return &rest[..close];
    }
    server.split(':').next().unwrap_or(server)
}
