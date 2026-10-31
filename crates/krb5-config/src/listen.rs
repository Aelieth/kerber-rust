// MIT: `loop_add_addresses` (lib/apputils/net-server.c:381-433)
// MIT: `k5_parse_host_string` (lib/krb5/krb/parse_host_string.c:70-124)
// `/path` (UNIX) is skipped: no port.
// MIT: `loop_add_address` (lib/apputils/net-server.c:304-361)

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use super::Error;

// MIT: `KRB5_DEFAULT_PORT` (include/osconf.hin:95-95)
pub const KDC_PORT: u16 = 88;
// MIT: `DEFAULT_KDC_PORTLIST` (include/osconf.hin:99-99)
pub const DEFAULT_KDC_PORTLIST: &str = "88";
// MIT: `DEFAULT_KADM5_PORT` (include/osconf.hin:107-107)
pub const KADMIND_PORT: u16 = 749;
// MIT: `DEFAULT_KPASSWD_PORT` (include/osconf.hin)
pub const KPASSWD_PORT: u16 = 464;
// MIT: `ADDRESSES_DELIM` (include/net-server.h:36-36)
const ADDRESSES_DELIM: &[char] = &[',', ';', ' '];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenAddr {
    pub host: Option<String>,
    pub port: u16,
}

impl ListenAddr {
    // MIT: `setup_addresses` (lib/apputils/net-server.c:927-1049)
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

pub fn parse_host_string(address: &str, default_port: u16) -> Result<ListenAddr, Error> {
    parse_entry(address, i32::from(default_port))
}

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

pub fn listen_addrs(addresses: Option<&str>, default_port: u16) -> Result<Vec<ListenAddr>, Error> {
    let mut list = BindAddresses::default();
    list.add_addresses(addresses, i32::from(default_port), BindType::Udp, &())?;
    Ok(list.entries.into_iter().map(|b| b.addr).collect())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindType {
    Udp,
    Tcp,
    Rpc,
}

impl BindType {
    // MIT: `bind_type_names` (lib/apputils/net-server.c:134-139)
    // Name in the daemon log.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Rpc => "RPC",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindAddress<S> {
    pub addr: ListenAddr,
    pub kind: BindType,
    pub service: S,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenLog {
    Debug(String),
    Err(String),
}

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

    // MIT: `FOREACH_ELT` (lib/apputils/net-server.c:178-179)
    // Walked from the top.
    // MIT: `DEL` (lib/apputils/net-server.c:197-198)
    // A removed entry takes the last one's place.
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

    #[must_use]
    pub fn entries(&self) -> &[BindAddress<S>] {
        &self.entries
    }

    pub fn take_log(&mut self) -> Vec<ListenLog> {
        std::mem::take(&mut self.log)
    }
}

// MIT: `parse_admin_server_port` (lib/kadm5/alt_prof.c:395-417)
// `atoi`: a non-number is 0, and kept.
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

#[must_use]
pub fn admin_server_host(server: &str) -> &str {
    if let Some(rest) = server.strip_prefix('[')
        && let Some(close) = rest.find(']')
    {
        return &rest[..close];
    }
    server.split(':').next().unwrap_or(server)
}
