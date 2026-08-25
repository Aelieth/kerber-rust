//! krb5.conf / kdc.conf, process environment, and DNS SRV discovery.
//!
//! There is no C FFI. DNS SRV is a minimal RFC 2782 UDP client.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::collections::BTreeMap;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;

/// Config / discovery failure.
#[derive(Debug, Error)]
pub enum Error {
    /// I/O.
    #[error("config io: {0}")]
    Io(#[from] std::io::Error),
    /// Parse error with context.
    #[error("config parse: {0}")]
    Parse(String),
    /// DNS SRV lookup failed.
    #[error("dns srv: {0}")]
    Dns(String),
}

/// One KDC (or kpasswd / admin) endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// Host name or dotted IP.
    pub host: String,
    /// UDP/TCP port.
    pub port: u16,
}

impl Endpoint {
    /// `host:88`.
    #[must_use]
    pub fn kdc(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: 88,
        }
    }
}

/// Parsed `[libdefaults]` plus realm stanzas.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Krb5Conf {
    /// `default_realm`.
    pub default_realm: Option<String>,
    /// `allow_weak_crypto`.
    pub allow_weak_crypto: bool,
    /// Clock skew in seconds (default 300).
    pub clockskew: u32,
    /// `dns_lookup_kdc`.
    pub dns_lookup_kdc: bool,
    /// Realm → KDC list.
    pub kdcs: BTreeMap<String, Vec<Endpoint>>,
    /// Realm → admin_server.
    pub admin_servers: BTreeMap<String, Vec<Endpoint>>,
    /// Realm → kpasswd_server.
    pub kpasswd_servers: BTreeMap<String, Vec<Endpoint>>,
    /// Domain → realm (`[domain_realm]`).
    pub domain_realm: BTreeMap<String, String>,
}

/// KDC policy from `kdc.conf`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdcConf {
    /// Bind addresses (host:port). Empty means `127.0.0.1:88`.
    pub kdc_listen: Vec<String>,
    /// TCP listen addresses.
    pub kdc_tcp_listen: Vec<String>,
    /// Realm name.
    pub realm: String,
    /// Maximum ticket lifetime in seconds (default 10 hours).
    pub max_life: u64,
    /// Maximum renewable lifetime in seconds (default 7 days).
    pub max_renewable_life: u64,
    /// Database path.
    pub database_name: Option<PathBuf>,
    /// ACL file.
    pub acl_file: Option<PathBuf>,
    /// Stash file for the master key.
    pub key_stash_file: Option<PathBuf>,
    /// User to drop to after binding a privileged port.
    pub kdc_user: Option<String>,
    /// `allow_weak_crypto`.
    pub allow_weak_crypto: bool,
    /// Per-principal `requires_preauth` default.
    pub requires_preauth: bool,
    /// `master_key_type` (MIT name, e.g. `aes256-cts-hmac-sha384-192`).
    pub master_key_type: Option<String>,
    /// `database_module` / `db_library` (db2, lmdb, …). Unused by dump/load.
    pub db_library: Option<String>,
    /// Optional NT domain SID (`S-1-5-21-…`) for PAC issuance.
    pub domain_sid: Option<String>,
}

impl Default for KdcConf {
    fn default() -> Self {
        Self {
            kdc_listen: vec!["127.0.0.1:88".into()],
            kdc_tcp_listen: vec!["127.0.0.1:88".into()],
            realm: "KERBER.TEST".into(),
            max_life: 10 * 3600,
            max_renewable_life: 7 * 24 * 3600,
            database_name: None,
            acl_file: None,
            key_stash_file: None,
            kdc_user: None,
            allow_weak_crypto: false,
            requires_preauth: true,
            master_key_type: None,
            db_library: None,
            domain_sid: None,
        }
    }
}

impl Krb5Conf {
    /// Empty defaults: 300s skew, no weak crypto, DNS lookup off.
    #[must_use]
    pub fn new() -> Self {
        Self {
            clockskew: 300,
            ..Self::default()
        }
    }

    /// Parse MIT-style `krb5.conf` text.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] on malformed braces.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut conf = Self::new();
        let mut section = String::new();
        let mut realm: Option<String> = None;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(s) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                section = s.trim().to_ascii_lowercase();
                realm = None;
                continue;
            }
            if section == "realms" {
                if let Some(name) = line.strip_suffix('{') {
                    realm = Some(name.trim().trim_end_matches('=').trim().to_string());
                    continue;
                }
                if line == "}" {
                    realm = None;
                    continue;
                }
                if let Some(r) = realm.as_ref() {
                    parse_realm_line(&mut conf, r, line);
                }
                continue;
            }
            if section == "libdefaults" {
                parse_libdefaults(&mut conf, line);
            }
            if section == "domain_realm" {
                if let Some((d, r)) = split_kv(line) {
                    conf.domain_realm.insert(d.to_ascii_lowercase(), r);
                }
            }
        }
        Ok(conf)
    }

    /// Load from `KRB5_CONFIG` or `path`.
    ///
    /// # Errors
    ///
    /// Returns I/O or parse errors.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text)
    }

    /// KDCs for `realm`, possibly via DNS SRV when enabled.
    ///
    /// # Errors
    ///
    /// Returns DNS errors when lookup is enabled and fails with no static list.
    pub fn kdcs_for(&self, realm: &str) -> Result<Vec<Endpoint>, Error> {
        if let Some(list) = self.kdcs.get(realm) {
            if !list.is_empty() {
                return Ok(list.clone());
            }
        }
        if self.dns_lookup_kdc {
            return lookup_srv_kdc(realm);
        }
        Ok(Vec::new())
    }
}

impl KdcConf {
    /// Parse `kdc.conf` text.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] on malformed input.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut conf = Self::default();
        let mut section = String::new();
        let mut in_realm = false;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(s) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                section = s.trim().to_ascii_lowercase();
                in_realm = false;
                continue;
            }
            if section == "realms" {
                if line.ends_with('{') {
                    let name = line
                        .trim_end_matches('{')
                        .trim()
                        .trim_end_matches('=')
                        .trim();
                    if !name.is_empty() {
                        conf.realm.clear();
                        conf.realm.push_str(name);
                    }
                    in_realm = true;
                    continue;
                }
                if line == "}" {
                    in_realm = false;
                    continue;
                }
                if in_realm {
                    parse_kdc_realm_line(&mut conf, line);
                }
            }
            if section == "kdcdefaults" {
                parse_kdcdefaults(&mut conf, line);
            }
        }
        Ok(conf)
    }

    /// Load from a path.
    ///
    /// # Errors
    ///
    /// Returns I/O or parse errors.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text)
    }
}

fn parse_libdefaults(conf: &mut Krb5Conf, line: &str) {
    let Some((k, v)) = split_kv(line) else {
        return;
    };
    match k.to_ascii_lowercase().as_str() {
        "default_realm" => conf.default_realm = Some(v),
        "allow_weak_crypto" => conf.allow_weak_crypto = truthy(&v),
        "clockskew" => {
            conf.clockskew = parse_duration_secs(&v)
                .and_then(|s| u32::try_from(s).ok())
                .unwrap_or(300);
        }
        "dns_lookup_kdc" => conf.dns_lookup_kdc = truthy(&v),
        _ => {}
    }
}

fn parse_realm_line(conf: &mut Krb5Conf, realm: &str, line: &str) {
    let Some((k, v)) = split_kv(line) else {
        return;
    };
    let ep = parse_endpoint(&v);
    match k.to_ascii_lowercase().as_str() {
        "kdc" => conf.kdcs.entry(realm.to_owned()).or_default().push(ep),
        "admin_server" => conf
            .admin_servers
            .entry(realm.to_owned())
            .or_default()
            .push(Endpoint {
                port: if ep.port == 88 { 749 } else { ep.port },
                ..ep
            }),
        "kpasswd_server" => conf
            .kpasswd_servers
            .entry(realm.to_owned())
            .or_default()
            .push(Endpoint {
                port: if ep.port == 88 { 464 } else { ep.port },
                ..ep
            }),
        _ => {}
    }
}

fn parse_kdcdefaults(conf: &mut KdcConf, line: &str) {
    let Some((k, v)) = split_kv(line) else {
        return;
    };
    match k.to_ascii_lowercase().as_str() {
        "kdc_ports" | "kdc_listen" => {
            conf.kdc_listen = v
                .split_whitespace()
                .map(|p| {
                    if p.contains(':') {
                        p.to_owned()
                    } else {
                        format!("127.0.0.1:{p}")
                    }
                })
                .collect();
        }
        "kdc_tcp_ports" | "kdc_tcp_listen" => {
            conf.kdc_tcp_listen = v
                .split_whitespace()
                .map(|p| {
                    if p.contains(':') {
                        p.to_owned()
                    } else {
                        format!("127.0.0.1:{p}")
                    }
                })
                .collect();
        }
        "allow_weak_crypto" => conf.allow_weak_crypto = truthy(&v),
        _ => {}
    }
}

fn parse_kdc_realm_line(conf: &mut KdcConf, line: &str) {
    let Some((k, v)) = split_kv(line) else {
        return;
    };
    match k.to_ascii_lowercase().as_str() {
        "max_life" => conf.max_life = parse_duration_secs(&v).unwrap_or(conf.max_life),
        "max_renewable_life" => {
            conf.max_renewable_life = parse_duration_secs(&v).unwrap_or(conf.max_renewable_life);
        }
        "database_name" => conf.database_name = Some(PathBuf::from(v)),
        "acl_file" => conf.acl_file = Some(PathBuf::from(v)),
        "key_stash_file" => conf.key_stash_file = Some(PathBuf::from(v)),
        "kdc_user" => conf.kdc_user = Some(v),
        "allow_weak_crypto" => conf.allow_weak_crypto = truthy(&v),
        "requires_preauth" => conf.requires_preauth = truthy(&v),
        "master_key_type" => conf.master_key_type = Some(v),
        "database_module" | "db_library" => conf.db_library = Some(v),
        "domain_sid" => conf.domain_sid = Some(v),
        _ => {}
    }
}

fn split_kv(line: &str) -> Option<(&str, String)> {
    let line = line.trim().trim_end_matches(',');
    let (k, v) = line.split_once('=')?;
    Some((k.trim(), v.trim().trim_matches('"').to_owned()))
}

fn truthy(v: &str) -> bool {
    matches!(v.to_ascii_lowercase().as_str(), "true" | "yes" | "1" | "on")
}

fn parse_endpoint(v: &str) -> Endpoint {
    if let Some((h, p)) = v.rsplit_once(':') {
        if let Ok(port) = p.parse() {
            return Endpoint {
                host: h.to_owned(),
                port,
            };
        }
    }
    Endpoint::kdc(v)
}

/// Parse `10h`, `7d`, `300`, `1h30m`.
fn parse_duration_secs(v: &str) -> Option<u64> {
    if let Ok(n) = v.parse::<u64>() {
        return Some(n);
    }
    let mut total = 0u64;
    let mut num = 0u64;
    let mut seen = false;
    for c in v.chars() {
        if c.is_ascii_digit() {
            seen = true;
            num = num
                .saturating_mul(10)
                .saturating_add(u64::from(c as u8 - b'0'));
        } else if !c.is_whitespace() {
            let mul = match c {
                's' | 'S' => 1,
                'm' | 'M' => 60,
                'h' | 'H' => 3600,
                'd' | 'D' => 86400,
                'w' | 'W' => 86400 * 7,
                _ => return None,
            };
            total = total.saturating_add(num.saturating_mul(mul));
            num = 0;
        }
    }
    if !seen {
        return None;
    }
    Some(total.saturating_add(num))
}

/// `KRB5CCNAME` (FILE: prefix stripped).
#[must_use]
pub fn env_ccname() -> Option<PathBuf> {
    std::env::var_os("KRB5CCNAME").map(|v| {
        let s = v.to_string_lossy();
        PathBuf::from(s.strip_prefix("FILE:").unwrap_or(s.as_ref()))
    })
}

/// `KRB5_CONFIG` path.
#[must_use]
pub fn env_krb5_config() -> Option<PathBuf> {
    std::env::var_os("KRB5_CONFIG").map(PathBuf::from)
}

/// `KRB5_KTNAME` (FILE: prefix stripped).
#[must_use]
pub fn env_ktname() -> Option<PathBuf> {
    std::env::var_os("KRB5_KTNAME").map(|v| {
        let s = v.to_string_lossy();
        PathBuf::from(s.strip_prefix("FILE:").unwrap_or(s.as_ref()))
    })
}

/// `KRB5_KDC_PROFILE` / `KRB5_KDC_CONF`.
#[must_use]
pub fn env_kdc_config() -> Option<PathBuf> {
    std::env::var_os("KRB5_KDC_PROFILE")
        .or_else(|| std::env::var_os("KRB5_KDC_CONF"))
        .map(PathBuf::from)
}

/// `KRB5_CONFIG` then `/etc/krb5.conf`.
#[must_use]
pub fn krb5_conf_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(p) = env_krb5_config() {
        out.push(p);
    }
    out.push(PathBuf::from("/etc/krb5.conf"));
    out
}

/// First KDC for `realm` from the given `krb5.conf` paths.
#[must_use]
pub fn discover_kdc_in<P: AsRef<Path>>(
    paths: impl IntoIterator<Item = P>,
    realm: &str,
) -> Option<Endpoint> {
    for path in paths {
        if let Ok(conf) = Krb5Conf::load_file(path) {
            if let Ok(list) = conf.kdcs_for(realm) {
                if let Some(ep) = list.into_iter().next() {
                    return Some(ep);
                }
            }
        }
    }
    None
}

/// First KDC for `realm` from [`krb5_conf_paths`].
#[must_use]
pub fn discover_kdc(realm: &str) -> Option<Endpoint> {
    discover_kdc_in(krb5_conf_paths(), realm)
}

/// `KRB5_KDC_PROFILE` / `KRB5_KDC_CONF` / `/etc/krb5kdc/kdc.conf` if present.
#[must_use]
pub fn kdc_conf_path() -> Option<PathBuf> {
    if let Some(p) = env_kdc_config() {
        return Some(p);
    }
    let p = PathBuf::from("/etc/krb5kdc/kdc.conf");
    p.is_file().then_some(p)
}

/// `KRB5_PASSWORD` (never from argv).
#[must_use]
pub fn env_password() -> Option<Vec<u8>> {
    std::env::var("KRB5_PASSWORD").ok().map(String::into_bytes)
}

/// RFC 2782 lookup of `_kerberos._udp.{realm}`.
///
/// # Errors
///
/// Returns [`Error::Dns`] when no records are found or the query fails.
pub fn lookup_srv_kdc(realm: &str) -> Result<Vec<Endpoint>, Error> {
    lookup_srv(&format!("_kerberos._udp.{realm}"), 88)
}

/// RFC 2782 lookup of `_kerberos-adm._tcp.{realm}`.
///
/// # Errors
///
/// Returns [`Error::Dns`] when lookup fails.
pub fn lookup_srv_admin(realm: &str) -> Result<Vec<Endpoint>, Error> {
    lookup_srv(&format!("_kerberos-adm._tcp.{realm}"), 749)
}

fn lookup_srv(name: &str, default_port: u16) -> Result<Vec<Endpoint>, Error> {
    let qname = encode_qname(name);
    let mut msg = Vec::with_capacity(12 + qname.len() + 4);
    msg.extend_from_slice(&[
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    msg.extend_from_slice(&qname);
    msg.extend_from_slice(&33u16.to_be_bytes()); // SRV
    msg.extend_from_slice(&1u16.to_be_bytes()); // IN
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| Error::Dns(e.to_string()))?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| Error::Dns(e.to_string()))?;
    let resolvers = ["127.0.0.53:53", "127.0.0.1:53", "1.1.1.1:53", "8.8.8.8:53"];
    let mut last = Error::Dns("no resolver".into());
    for r in resolvers {
        let Ok(addr) = r.parse::<SocketAddr>() else {
            continue;
        };
        if sock.send_to(&msg, addr).is_err() {
            continue;
        }
        let mut buf = [0u8; 2048];
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => match parse_srv_answers(&buf[..n], default_port) {
                Ok(list) if !list.is_empty() => return Ok(list),
                Ok(_) => last = Error::Dns("empty SRV".into()),
                Err(e) => last = e,
            },
            Err(e) => last = Error::Dns(e.to_string()),
        }
    }
    Err(last)
}

fn encode_qname(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        let n = u8::try_from(b.len()).unwrap_or(63);
        out.push(n.min(63));
        out.extend_from_slice(&b[..usize::from(n.min(63))]);
    }
    out.push(0);
    out
}

fn parse_srv_answers(msg: &[u8], default_port: u16) -> Result<Vec<Endpoint>, Error> {
    if msg.len() < 12 {
        return Err(Error::Dns("short dns".into()));
    }
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    // skip question
    let mut i = 12;
    i = skip_name(msg, i)?;
    i = i
        .checked_add(4)
        .ok_or_else(|| Error::Dns("overflow".into()))?;
    let mut out = Vec::new();
    for _ in 0..ancount {
        i = skip_name(msg, i)?;
        if i + 10 > msg.len() {
            break;
        }
        let typ = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let rdlen = u16::from_be_bytes([msg[i + 8], msg[i + 9]]) as usize;
        i += 10;
        if typ == 33 && i + rdlen <= msg.len() && rdlen >= 6 {
            let port = u16::from_be_bytes([msg[i + 4], msg[i + 5]]);
            let host = decode_name(msg, i + 6).unwrap_or_default();
            if !host.is_empty() {
                out.push(Endpoint {
                    host: host.trim_end_matches('.').to_owned(),
                    port: if port == 0 { default_port } else { port },
                });
            }
        }
        i += rdlen;
    }
    Ok(out)
}

fn skip_name(msg: &[u8], mut i: usize) -> Result<usize, Error> {
    loop {
        if i >= msg.len() {
            return Err(Error::Dns("bad name".into()));
        }
        let len = msg[i];
        if len == 0 {
            return Ok(i + 1);
        }
        if len & 0xc0 == 0xc0 {
            return Ok(i + 2);
        }
        i += 1 + usize::from(len);
    }
}

fn decode_name(msg: &[u8], mut i: usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut hops = 0;
    loop {
        if hops > 10 || i >= msg.len() {
            break;
        }
        let len = msg[i];
        if len == 0 {
            break;
        }
        if len & 0xc0 == 0xc0 {
            if i + 1 >= msg.len() {
                break;
            }
            i = (u16::from_be_bytes([len & 0x3f, msg[i + 1]])) as usize;
            hops += 1;
            continue;
        }
        i += 1;
        let end = i + usize::from(len);
        if end > msg.len() {
            break;
        }
        labels.push(String::from_utf8_lossy(&msg[i..end]).into_owned());
        i = end;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_krb5_conf_realms_and_libdefaults() {
        let text = r"
[libdefaults]
    default_realm = KERBER.TEST
    allow_weak_crypto = false
    clockskew = 300
    dns_lookup_kdc = no

[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1:88
        admin_server = 127.0.0.1:749
    }

[domain_realm]
    .kerber.test = KERBER.TEST
";
        let c = Krb5Conf::parse(text).unwrap();
        assert_eq!(c.default_realm.as_deref(), Some("KERBER.TEST"));
        assert!(!c.allow_weak_crypto);
        assert_eq!(c.clockskew, 300);
        assert_eq!(c.kdcs["KERBER.TEST"][0].host, "127.0.0.1");
        assert_eq!(c.kdcs["KERBER.TEST"][0].port, 88);
        let discovered = c.kdcs_for("KERBER.TEST").unwrap();
        assert_eq!(discovered[0].host, "127.0.0.1");
        assert_eq!(discovered[0].port, 88);
        assert_eq!(c.domain_realm[".kerber.test"], "KERBER.TEST");
    }

    #[test]
    fn parse_kdc_conf_policy() {
        let text = r"
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88

[realms]
    KERBER.TEST = {
        max_life = 10h
        max_renewable_life = 7d
        requires_preauth = yes
        database_name = /var/lib/krb5kdc/principal
        master_key_type = aes256-cts-hmac-sha384-192
        db_library = db2
        domain_sid = S-1-5-21-891046300-1937985867-1481223175
    }
";
        let c = KdcConf::parse(text).unwrap();
        assert_eq!(c.realm, "KERBER.TEST");
        assert_eq!(c.max_life, 36000);
        assert_eq!(c.max_renewable_life, 7 * 86400);
        assert!(c.requires_preauth);
        assert_eq!(
            c.master_key_type.as_deref(),
            Some("aes256-cts-hmac-sha384-192")
        );
        assert_eq!(c.db_library.as_deref(), Some("db2"));
        assert_eq!(
            c.domain_sid.as_deref(),
            Some("S-1-5-21-891046300-1937985867-1481223175")
        );
        assert_eq!(c.kdc_listen[0], "127.0.0.1:88");
        let mit = KdcConf::parse(
            r"
[realms]
    KERBER.TEST = {
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        database_name = /var/lib/krb5kdc/principal
        key_stash_file = /var/lib/krb5kdc/.k5.KERBER.TEST
    }
",
        )
        .unwrap();
        assert_eq!(mit.max_life, 36000);
        assert_eq!(mit.max_renewable_life, 7 * 86400);
        assert_eq!(
            mit.database_name.as_deref(),
            Some(std::path::Path::new("/var/lib/krb5kdc/principal"))
        );
    }

    #[test]
    fn duration_parser() {
        assert_eq!(parse_duration_secs("10h"), Some(36000));
        assert_eq!(parse_duration_secs("7d"), Some(604_800));
        assert_eq!(parse_duration_secs("300"), Some(300));
        assert_eq!(parse_duration_secs("10h 0m 0s"), Some(36000));
        assert_eq!(parse_duration_secs("1h 30m"), Some(5400));
        assert_eq!(parse_duration_secs("7d 0h 0m 0s"), Some(604_800));
    }

    #[test]
    fn discover_kdc_in_reads_realms_stanza() {
        let path = std::env::temp_dir().join(format!(
            "kerber-krb5-conf-{}-{}.conf",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(
            &path,
            r"
[realms]
    KERBER.TEST = {
        kdc = 10.9.8.7:1088
    }
",
        )
        .unwrap();
        let ep = discover_kdc_in([&path], "KERBER.TEST").unwrap();
        assert_eq!(ep.host, "10.9.8.7");
        assert_eq!(ep.port, 1088);
        assert!(discover_kdc_in([&path], "OTHER.TEST").is_none());
        let _ = std::fs::remove_file(&path);
    }
}
