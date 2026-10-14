//! Listener address lists: `kdc_listen` / `kdc_ports`, `kdc_tcp_listen` / `kdc_tcp_ports`,
//! `kadmind_listen` / `kadmind_port`, `kpasswd_listen` / `kpasswd_port`.
//!
//! MIT `loop_add_addresses` (`lib/apputils/net-server.c:381-433`): a list is split on `,`,
//! `;` or space, and a `/path` entry is a UNIX-domain listener (skipped here: this port binds
//! no UNIX sockets).
//! MIT `k5_parse_host_string` (`lib/krb5/krb/parse_host_string.c:70-124`): an entry is a
//! port, a host, `host:port` or `[v6]:port`; a bad port is an error, so the daemon does not
//! start.
//! MIT `loop_add_address` (`lib/apputils/net-server.c:304-361`): an entry without a host is
//! the wildcard, which drops the direct addresses on its port; a repeat is ignored.

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
    let bad = || Error::Parse(format!("listen address {address:?}: invalid"));
    if address.is_empty() || address.starts_with(':') {
        return Err(bad());
    }
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
        Some(p) => {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            p.parse::<u16>().map_err(|_| bad())?
        }
        None => default_port,
    };
    Ok(ListenAddr {
        host: host.map(ToOwned::to_owned),
        port,
    })
}

/// MIT `loop_add_addresses`: the listeners a configured list asks for. `None` is the
/// wildcard on `default_port`. Within the list a wildcard removes the direct addresses on
/// its port and a later duplicate (or a direct address on a wildcard's port) is dropped,
/// as `loop_add_address` does.
///
/// # Errors
///
/// [`Error::Parse`] from [`parse_host_string`] for any entry.
pub fn listen_addrs(addresses: Option<&str>, default_port: u16) -> Result<Vec<ListenAddr>, Error> {
    let mut out: Vec<ListenAddr> = Vec::new();
    let Some(addresses) = addresses else {
        add_unique(
            &mut out,
            ListenAddr {
                host: None,
                port: default_port,
            },
        );
        return Ok(out);
    };
    for entry in addresses.split(ADDRESSES_DELIM).filter(|s| !s.is_empty()) {
        if entry.starts_with('/') {
            continue;
        }
        add_unique(&mut out, parse_host_string(entry, default_port)?);
    }
    Ok(out)
}

/// MIT `loop_add_address` (`lib/apputils/net-server.c:304-361`): a wildcard replaces the
/// direct addresses on its port, and a repeat is not added.
fn add_unique(list: &mut Vec<ListenAddr>, addr: ListenAddr) {
    if addr.host.is_none() {
        list.retain(|v| v.port != addr.port || v.host.is_none());
    } else if list
        .iter()
        .any(|v| v.port == addr.port && (v.host.is_none() || v.host == addr.host))
    {
        return;
    }
    if !list.contains(&addr) {
        list.push(addr);
    }
}

/// The port written in an `admin_server` value (`host:port` or `[v6]:port`), which sets
/// kadmind's port ahead of `kadmind_port`; `None` when the value names no port.
/// MIT `parse_admin_server_port` (`lib/kadm5/alt_prof.c:395-417`): a written port is read
/// with `atoi`, so a bad one is 0, which is refused here.
#[must_use]
pub fn admin_server_port(server: &str) -> Option<u16> {
    let port = if let Some(rest) = server.strip_prefix('[')
        && let Some(close) = rest.find(']')
    {
        rest[close + 1..].strip_prefix(':')?
    } else {
        server.split_once(':')?.1
    };
    port.trim().parse::<u16>().ok().filter(|p| *p != 0)
}
