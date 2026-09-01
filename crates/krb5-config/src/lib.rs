//! krb5.conf / kdc.conf, process environment, and DNS SRV discovery.
//!
//! There is no C FFI. DNS SRV is a minimal RFC 2782 UDP client.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::collections::{BTreeMap, BTreeSet};
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
    /// `dns_lookup_realm` (MIT `krb5_get_host_realm`).
    pub dns_lookup_realm: bool,
    /// `udp_preference_limit` (MIT default 1465). `None` = default.
    pub udp_preference_limit: Option<u32>,
    /// `rdns`. Parsed; we do not reverse-resolve addresses.
    pub rdns: bool,
    /// `kdc_timesync`. Parsed; AS already resyncs on KRB-ERROR SKEW.
    pub kdc_timesync: bool,
    /// `permitted_enctypes`.
    pub permitted_enctypes: Vec<String>,
    /// `default_tkt_enctypes`.
    pub default_tkt_enctypes: Vec<String>,
    /// `default_tgs_enctypes`.
    pub default_tgs_enctypes: Vec<String>,
    /// `forwardable`.
    pub forwardable: bool,
    /// `proxiable`.
    pub proxiable: bool,
    /// `ticket_lifetime` seconds.
    pub ticket_lifetime: Option<u64>,
    /// `renew_lifetime` seconds.
    pub renew_lifetime: Option<u64>,
    /// Heimdal `kdc_timeout` — no MIT parse site; stored and unused.
    pub kdc_timeout: Option<String>,
    /// Heimdal `max_retries` — no MIT parse site; stored and unused.
    pub max_retries: Option<String>,
    /// `[libdefaults] kcm_socket` (MIT; `KCM_SOCKET` env overrides).
    pub kcm_socket: Option<String>,
    /// `[libdefaults] default_ccache_name` (MIT parameter expansion).
    pub default_ccache_name: Option<String>,
    /// Realm → KDC list.
    pub kdcs: BTreeMap<String, Vec<Endpoint>>,
    /// Realm → admin_server.
    pub admin_servers: BTreeMap<String, Vec<Endpoint>>,
    /// Realm → kpasswd_server.
    pub kpasswd_servers: BTreeMap<String, Vec<Endpoint>>,
    /// Domain → realm (`[domain_realm]`).
    pub domain_realm: BTreeMap<String, String>,
    /// Realm → `pkinit_identities` FILE values.
    pub pkinit_identities: BTreeMap<String, Vec<String>>,
    /// Realm → `pkinit_anchors` FILE values.
    pub pkinit_anchors: BTreeMap<String, Vec<String>>,
    /// `[capaths]` client-realm → server-realm → intermediates (`.` = direct).
    pub capaths: BTreeMap<String, BTreeMap<String, Vec<String>>>,
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
    /// Whether `max_renewable_life` was present in kdc.conf (unset ≠ 0).
    pub max_renewable_life_set: bool,
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
    /// `database_module` / `db_library`. Default dump-v7; unknown names error.
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
            max_renewable_life_set: false,
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
            rdns: true,
            kdc_timesync: true,
            ..Self::default()
        }
    }

    /// Parse MIT-style `krb5.conf` text (no `include` / `includedir`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Parse`] on malformed braces.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut conf = Self::new();
        let mut seen = BTreeSet::new();
        parse_into(&mut conf, &mut seen, text, None)?;
        Ok(conf)
    }

    /// Load a file or directory, honoring `include` / `includedir`.
    ///
    /// # Errors
    ///
    /// Returns I/O or parse errors, including include cycles.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let mut conf = Self::new();
        let mut seen = BTreeSet::new();
        let mut stack = Vec::new();
        load_path_into(&mut conf, &mut seen, &mut stack, path.as_ref())?;
        Ok(conf)
    }

    /// Longest-suffix `[domain_realm]` map (MIT hostrealm profile).
    #[must_use]
    pub fn realm_for_host(&self, host: &str) -> Option<&str> {
        host_to_realm(&self.domain_realm, host)
    }

    /// KDCs for `realm`, possibly via DNS SRV when enabled.
    ///
    /// # Errors
    ///
    /// Returns DNS errors when lookup is enabled and fails with no static list.
    pub fn kdcs_for(&self, realm: &str) -> Result<Vec<Endpoint>, Error> {
        if let Some(list) = self.kdcs.get(realm)
            && !list.is_empty()
        {
            return Ok(list.clone());
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

const MAX_INCLUDE_DEPTH: usize = 32;

enum IncludeKind<'a> {
    File(&'a str),
    Dir(&'a str),
}

fn include_directive(raw: &str) -> Option<IncludeKind<'_>> {
    if let Some(rest) = raw.strip_prefix("includedir")
        && rest.starts_with(|c: char| c.is_whitespace())
    {
        let p = rest.trim();
        if !p.is_empty() {
            return Some(IncludeKind::Dir(p));
        }
    }
    if let Some(rest) = raw.strip_prefix("include")
        && rest.starts_with(|c: char| c.is_whitespace())
    {
        let p = rest.trim();
        if !p.is_empty() {
            return Some(IncludeKind::File(p));
        }
    }
    None
}

fn valid_include_name(name: &str) -> bool {
    if name.starts_with('.') {
        return false;
    }
    // MIT `valid_name`: suffix is the lowercase bytes ".conf", not a case-fold.
    if name.len() >= 5 && name.as_bytes().ends_with(b".conf") {
        return true;
    }
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn host_to_realm<'a>(map: &'a BTreeMap<String, String>, host: &str) -> Option<&'a str> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if let Some(r) = map.get(&host) {
        return Some(r.as_str());
    }
    let mut rest = host.as_str();
    while let Some((_, suffix)) = rest.split_once('.') {
        if let Some(r) = map.get(&format!(".{suffix}")) {
            return Some(r.as_str());
        }
        if let Some(r) = map.get(suffix) {
            return Some(r.as_str());
        }
        rest = suffix;
    }
    None
}

fn take_first(seen: &mut BTreeSet<String>, key: &str) -> bool {
    seen.insert(key.to_owned())
}

fn parse_into(
    conf: &mut Krb5Conf,
    seen: &mut BTreeSet<String>,
    text: &str,
    mut stack: Option<&mut Vec<PathBuf>>,
) -> Result<(), Error> {
    let mut section = String::new();
    let mut realm: Option<String> = None;
    let mut capaths_client: Option<String> = None;
    for raw in text.lines() {
        if let Some(kind) = include_directive(raw)
            && let Some(st) = stack.as_deref_mut()
        {
            match kind {
                IncludeKind::File(p) => load_file_into(conf, seen, st, Path::new(p))?,
                IncludeKind::Dir(p) => load_dir_into(conf, seen, st, Path::new(p))?,
            }
            continue;
        }
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(s) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = s.trim().to_ascii_lowercase();
            realm = None;
            capaths_client = None;
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
                parse_realm_line(conf, r, line);
            }
            continue;
        }
        if section == "libdefaults" {
            parse_libdefaults(conf, seen, line);
        }
        if section == "domain_realm"
            && let Some((d, r)) = split_kv(line)
        {
            conf.domain_realm.entry(d.to_ascii_lowercase()).or_insert(r);
        }
        if section == "capaths" {
            if let Some(name) = line.strip_suffix('{') {
                capaths_client = Some(name.trim().trim_end_matches('=').trim().to_string());
                continue;
            }
            if line == "}" {
                capaths_client = None;
                continue;
            }
            if let Some(client) = capaths_client.as_ref()
                && let Some((server, hop)) = split_kv(line)
            {
                conf.capaths
                    .entry(client.clone())
                    .or_default()
                    .entry(server.to_string())
                    .or_default()
                    .push(hop);
            }
        }
    }
    Ok(())
}

fn load_path_into(
    conf: &mut Krb5Conf,
    seen: &mut BTreeSet<String>,
    stack: &mut Vec<PathBuf>,
    path: &Path,
) -> Result<(), Error> {
    if path.is_dir() {
        load_dir_into(conf, seen, stack, path)
    } else {
        load_file_into(conf, seen, stack, path)
    }
}

fn load_file_into(
    conf: &mut Krb5Conf,
    seen: &mut BTreeSet<String>,
    stack: &mut Vec<PathBuf>,
    path: &Path,
) -> Result<(), Error> {
    if stack.len() >= MAX_INCLUDE_DEPTH {
        return Err(Error::Parse("include nesting too deep".into()));
    }
    let canon = std::fs::canonicalize(path)?;
    if stack.iter().any(|p| p == &canon) {
        return Err(Error::Parse("include cycle".into()));
    }
    let text = std::fs::read_to_string(&canon)?;
    stack.push(canon);
    let result = parse_into(conf, seen, &text, Some(stack));
    stack.pop();
    result
}

fn load_dir_into(
    conf: &mut Krb5Conf,
    seen: &mut BTreeSet<String>,
    stack: &mut Vec<PathBuf>,
    dir: &Path,
) -> Result<(), Error> {
    if !dir.is_dir() {
        return Err(Error::Parse(format!(
            "includedir not a directory: {}",
            dir.display()
        )));
    }
    let mut names = Vec::new();
    for ent in std::fs::read_dir(dir)? {
        let ent = ent?;
        let name = ent.file_name();
        let Some(s) = name.to_str() else {
            continue;
        };
        if valid_include_name(s) {
            names.push(s.to_owned());
        }
    }
    names.sort();
    for name in names {
        let p = dir.join(name);
        if p.is_file() {
            load_file_into(conf, seen, stack, &p)?;
        }
    }
    Ok(())
}

fn parse_libdefaults(conf: &mut Krb5Conf, seen: &mut BTreeSet<String>, line: &str) {
    let Some((k, v)) = split_kv(line) else {
        return;
    };
    let key = k.to_ascii_lowercase();
    match key.as_str() {
        "default_realm" if take_first(seen, "default_realm") => conf.default_realm = Some(v),
        "allow_weak_crypto" if take_first(seen, "allow_weak_crypto") => {
            conf.allow_weak_crypto = truthy(&v);
        }
        "clockskew" if take_first(seen, "clockskew") => {
            conf.clockskew = parse_duration_secs(&v)
                .and_then(|s| u32::try_from(s).ok())
                .unwrap_or(300);
        }
        "dns_lookup_kdc" if take_first(seen, "dns_lookup_kdc") => {
            conf.dns_lookup_kdc = truthy(&v);
        }
        "dns_lookup_realm" if take_first(seen, "dns_lookup_realm") => {
            conf.dns_lookup_realm = truthy(&v);
        }
        "udp_preference_limit" if take_first(seen, "udp_preference_limit") => {
            conf.udp_preference_limit = v.parse().ok();
        }
        "rdns" if take_first(seen, "rdns") => conf.rdns = truthy(&v),
        "kdc_timesync" if take_first(seen, "kdc_timesync") => conf.kdc_timesync = truthy(&v),
        "permitted_enctypes" if take_first(seen, "permitted_enctypes") => {
            conf.permitted_enctypes = split_ws(&v);
        }
        "default_tkt_enctypes" if take_first(seen, "default_tkt_enctypes") => {
            conf.default_tkt_enctypes = split_ws(&v);
        }
        "default_tgs_enctypes" if take_first(seen, "default_tgs_enctypes") => {
            conf.default_tgs_enctypes = split_ws(&v);
        }
        "forwardable" if take_first(seen, "forwardable") => conf.forwardable = truthy(&v),
        "proxiable" if take_first(seen, "proxiable") => conf.proxiable = truthy(&v),
        "ticket_lifetime" if take_first(seen, "ticket_lifetime") => {
            conf.ticket_lifetime = parse_duration_secs(&v);
        }
        "renew_lifetime" if take_first(seen, "renew_lifetime") => {
            conf.renew_lifetime = parse_duration_secs(&v);
        }
        "kdc_timeout" if take_first(seen, "kdc_timeout") => conf.kdc_timeout = Some(v),
        "max_retries" if take_first(seen, "max_retries") => conf.max_retries = Some(v),
        "kcm_socket" if take_first(seen, "kcm_socket") => conf.kcm_socket = Some(v),
        "default_ccache_name" if take_first(seen, "default_ccache_name") => {
            conf.default_ccache_name = Some(v);
        }
        _ => {}
    }
}

fn split_ws(v: &str) -> Vec<String> {
    v.split_whitespace().map(ToOwned::to_owned).collect()
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
        "pkinit_identities" => conf
            .pkinit_identities
            .entry(realm.to_owned())
            .or_default()
            .push(v),
        "pkinit_anchors" => conf
            .pkinit_anchors
            .entry(realm.to_owned())
            .or_default()
            .push(v),
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
            conf.max_renewable_life_set = true;
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
    if let Some((h, p)) = v.rsplit_once(':')
        && let Ok(port) = p.parse()
    {
        return Endpoint {
            host: h.to_owned(),
            port,
        };
    }
    Endpoint::kdc(v)
}

/// Parse MIT `krb5_string_to_deltat` (`10h`, `7d`, `300`, `1h30m`).
#[must_use]
pub fn parse_deltat(v: &str) -> Option<u64> {
    parse_duration_secs(v)
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

/// MIT `KRB5_CC_UNKNOWN_TYPE`.
pub const KRB5_CC_UNKNOWN_TYPE: &str = "Unknown credential cache type";

/// Resolved ccache name (`krb5_cc_resolve`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CcSpec {
    /// `FILE:path` or a residual with no type prefix.
    File(PathBuf),
    /// `MEMORY:name` (process-global).
    Memory(String),
    /// `DIR:dirname` or `DIR::filepath`.
    Dir(String),
    /// `KCM:` or `KCM:residual` (sssd-kcm / Heimdal daemon).
    Kcm(String),
}

/// `KRB5CCNAME` (FILE: prefix stripped). Non-FILE names are ignored.
#[must_use]
pub fn env_ccname() -> Option<PathBuf> {
    std::env::var_os("KRB5CCNAME").and_then(|v| parse_ccname(&v.to_string_lossy()).ok())
}

const BUILTIN_CCACHE: &str = "FILE:/tmp/krb5cc_%{uid}";

/// Expand MIT `default_ccache_name` tokens (`%{uid}` / `%{USERID}` / `%{euid}`).
///
/// # Errors
///
/// Unknown `%{token}` (MIT fails closed).
pub fn expand_ccache_params(s: &str) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("%{") {
        out.push_str(&rest[..start]);
        rest = &rest[start + 2..];
        let Some(end) = rest.find('}') else {
            out.push_str("%{");
            out.push_str(rest);
            return Ok(out);
        };
        let token = &rest[..end];
        rest = &rest[end + 1..];
        out.push_str(&ccache_param(token)?);
    }
    out.push_str(rest);
    Ok(out)
}

fn ccache_param(token: &str) -> Result<String, String> {
    match token {
        "uid" | "USERID" => Ok(unix_uid().to_string()),
        "euid" => Ok(unix_euid().to_string()),
        "null" => Ok(String::new()),
        "TEMP" => Ok("/tmp".into()),
        "username" => Ok(unix_username()),
        _ => Err(format!("unknown ccache parameter %{{{token}}}")),
    }
}

fn unix_uid() -> u32 {
    #[cfg(unix)]
    {
        nix::unistd::Uid::current().as_raw()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn unix_euid() -> u32 {
    #[cfg(unix)]
    {
        nix::unistd::Uid::effective().as_raw()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn unix_username() -> String {
    #[cfg(unix)]
    {
        nix::unistd::User::from_uid(nix::unistd::Uid::effective())
            .ok()
            .flatten()
            .map(|u| u.name)
            .unwrap_or_default()
    }
    #[cfg(not(unix))]
    {
        String::new()
    }
}

/// `-c` flag, else `KRB5CCNAME`, else conf `default_ccache_name`, else builtin.
///
/// # Errors
///
/// [`KRB5_CC_UNKNOWN_TYPE`] or an unknown `%{token}`.
pub fn resolve_ccspec(flag: Option<&str>) -> Result<CcSpec, String> {
    if let Some(s) = flag {
        return parse_ccspec(s);
    }
    if let Some(v) = std::env::var_os("KRB5CCNAME") {
        return parse_ccspec(&v.to_string_lossy());
    }
    default_ccspec()
}

/// Conf `default_ccache_name` after token expansion, else builtin FILE.
///
/// # Errors
///
/// Unknown `%{token}` or [`KRB5_CC_UNKNOWN_TYPE`].
pub fn default_ccspec() -> Result<CcSpec, String> {
    let raw = load_krb5_conf()
        .and_then(|c| c.default_ccache_name)
        .unwrap_or_else(|| BUILTIN_CCACHE.to_owned());
    parse_ccspec(&expand_ccache_params(&raw)?)
}

/// `-c` flag, else `KRB5CCNAME`, else [`default_ccache_name`]. FILE only.
///
/// # Errors
///
/// [`KRB5_CC_UNKNOWN_TYPE`].
pub fn resolve_ccname(flag: Option<&str>) -> Result<PathBuf, String> {
    match resolve_ccspec(flag)? {
        CcSpec::File(p) => Ok(p),
        _ => Err(KRB5_CC_UNKNOWN_TYPE.to_owned()),
    }
}

/// Split `TYPE:residual`. A residual with no type prefix is FILE.
///
/// # Errors
///
/// [`KRB5_CC_UNKNOWN_TYPE`] for unrecognized or unbuilt prefixes.
pub fn parse_ccspec(spec: &str) -> Result<CcSpec, String> {
    match split_cc_type(spec) {
        None => Ok(CcSpec::File(PathBuf::from(spec))),
        Some(("FILE", rest)) => Ok(CcSpec::File(PathBuf::from(rest))),
        Some(("MEMORY", rest)) => Ok(CcSpec::Memory(rest.to_owned())),
        Some(("DIR", rest)) => Ok(CcSpec::Dir(rest.to_owned())),
        Some(("KCM", rest)) => Ok(CcSpec::Kcm(rest.to_owned())),
        Some(_) => Err(KRB5_CC_UNKNOWN_TYPE.to_owned()),
    }
}

/// FILE residual, or a bare path.
///
/// # Errors
///
/// [`KRB5_CC_UNKNOWN_TYPE`].
pub fn parse_ccname(spec: &str) -> Result<PathBuf, String> {
    match parse_ccspec(spec)? {
        CcSpec::File(p) => Ok(p),
        _ => Err(KRB5_CC_UNKNOWN_TYPE.to_owned()),
    }
}

fn split_cc_type(spec: &str) -> Option<(&str, &str)> {
    let (ty, rest) = spec.split_once(':')?;
    if ty.is_empty() {
        return None;
    }
    if !ty.bytes().all(|b| b.is_ascii_alphabetic() || b == b'_') {
        return None;
    }
    Some((ty, rest))
}

/// Builtin `FILE:/tmp/krb5cc_%{uid}` residual (no conf).
#[must_use]
pub fn default_ccache_name() -> PathBuf {
    PathBuf::from(format!("/tmp/krb5cc_{}", unix_uid()))
}

/// `KRB5_CONFIG` path list (colon-split). Missing env is [`None`].
#[must_use]
pub fn env_krb5_config() -> Option<PathBuf> {
    std::env::var_os("KRB5_CONFIG").map(PathBuf::from)
}

/// Colon-split `KRB5_CONFIG` (empty components dropped).
#[must_use]
pub fn split_krb5_config_paths(value: &str) -> Vec<PathBuf> {
    value
        .split(':')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
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

/// `KRB5_CONFIG` (colon-split) or `/etc/krb5.conf` when unset.
#[must_use]
pub fn krb5_conf_paths() -> Vec<PathBuf> {
    match std::env::var_os("KRB5_CONFIG") {
        Some(v) => split_krb5_config_paths(&v.to_string_lossy()),
        None => vec![PathBuf::from("/etc/krb5.conf")],
    }
}

/// Merge `krb5.conf` paths (includes, first-wins scalars, appended `kdc=`).
///
/// # Errors
///
/// Missing paths are skipped. A present file with a bad include is an error.
pub fn load_krb5_conf_paths<P: AsRef<Path>>(
    paths: impl IntoIterator<Item = P>,
) -> Result<Krb5Conf, Error> {
    let mut conf = Krb5Conf::new();
    let mut seen = BTreeSet::new();
    let mut stack = Vec::new();
    let mut any = false;
    for path in paths {
        let path = path.as_ref();
        match load_path_into(&mut conf, &mut seen, &mut stack, path) {
            Ok(()) => any = true,
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    if any {
        Ok(conf)
    } else {
        Err(std::io::Error::from(std::io::ErrorKind::NotFound).into())
    }
}

/// First KDC for `realm` from the given `krb5.conf` paths (merged).
#[must_use]
pub fn discover_kdc_in<P: AsRef<Path>>(
    paths: impl IntoIterator<Item = P>,
    realm: &str,
) -> Option<Endpoint> {
    let conf = load_krb5_conf_paths(paths).ok()?;
    conf.kdcs_for(realm).ok()?.into_iter().next()
}

/// First KDC for `realm` from [`krb5_conf_paths`].
#[must_use]
pub fn discover_kdc(realm: &str) -> Option<Endpoint> {
    discover_kdc_in(krb5_conf_paths(), realm)
}

/// Merged `krb5.conf` from [`krb5_conf_paths`].
#[must_use]
pub fn load_krb5_conf() -> Option<Krb5Conf> {
    load_krb5_conf_paths(krb5_conf_paths()).ok()
}

/// MIT `udp_preference_limit` (default 1465). Messages larger go TCP first.
#[must_use]
pub fn udp_preference_limit() -> usize {
    load_krb5_conf()
        .and_then(|c| c.udp_preference_limit)
        .map_or(1465, |n| usize::try_from(n).unwrap_or(1465))
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
        assert!(!c.dns_lookup_kdc);
        assert!(c.kdc_timeout.is_none());
        assert!(c.max_retries.is_none());
        assert!(!c.allow_weak_crypto);
        assert_eq!(c.clockskew, 300);
        assert_eq!(c.kdcs["KERBER.TEST"][0].host, "127.0.0.1");
        assert_eq!(c.kdcs["KERBER.TEST"][0].port, 88);
        assert!(c.pkinit_identities.is_empty());
        assert!(c.pkinit_anchors.is_empty());
        let discovered = c.kdcs_for("KERBER.TEST").unwrap();
        assert_eq!(discovered[0].host, "127.0.0.1");
        assert_eq!(discovered[0].port, 88);
        assert_eq!(c.domain_realm[".kerber.test"], "KERBER.TEST");
        assert_eq!(c.realm_for_host("app.kerber.test"), Some("KERBER.TEST"));
        assert_eq!(c.realm_for_host("kerber.test"), None);
        let mapped = Krb5Conf::parse(
            r"
[domain_realm]
    testhost.kerber.test = EXACT.TEST
    .kerber.test = DOT.TEST
    kerber.test = BARE.TEST
    .test = SHORT.TEST
",
        )
        .unwrap();
        assert_eq!(
            mapped.realm_for_host("testhost.kerber.test"),
            Some("EXACT.TEST")
        );
        assert_eq!(mapped.realm_for_host("app.kerber.test"), Some("DOT.TEST"));
        assert_eq!(mapped.realm_for_host("kerber.test"), Some("BARE.TEST"));
        assert_eq!(mapped.realm_for_host("other.test"), Some("SHORT.TEST"));
    }

    #[test]
    fn parse_fleet_knobs_and_ignore_heimdal_spellings() {
        let c = Krb5Conf::parse(
            r"
[libdefaults]
    udp_preference_limit = 0
    rdns = false
    kdc_timesync = no
    forwardable = true
    ticket_lifetime = 10h
    renew_lifetime = 7d
    dns_lookup_realm = no
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tkt_enctypes = aes256-cts-hmac-sha1-96
    default_tgs_enctypes = aes128-cts-hmac-sha1-96
    kdc_timeout = 1
    max_retries = 1
",
        )
        .unwrap();
        assert_eq!(c.udp_preference_limit, Some(0));
        assert!(!c.rdns);
        assert!(!c.kdc_timesync);
        assert!(c.forwardable);
        assert!(!c.proxiable);
        let px = Krb5Conf::parse("[libdefaults]\n    proxiable = true\n").unwrap();
        assert!(px.proxiable);
        assert_eq!(c.ticket_lifetime, Some(10 * 3600));
        assert_eq!(c.renew_lifetime, Some(7 * 86400));
        assert_eq!(c.permitted_enctypes.len(), 2);
        assert_eq!(c.default_tkt_enctypes, ["aes256-cts-hmac-sha1-96"]);
        assert_eq!(c.kdc_timeout.as_deref(), Some("1"));
        assert_eq!(c.max_retries.as_deref(), Some("1"));
        assert!(c.kcm_socket.is_none());
        assert!(c.default_ccache_name.is_none());
        let sock = Krb5Conf::parse("[libdefaults]\n    kcm_socket = /tmp/kcm.sock\n").unwrap();
        assert_eq!(sock.kcm_socket.as_deref(), Some("/tmp/kcm.sock"));
        let cc =
            Krb5Conf::parse("[libdefaults]\n    default_ccache_name = FILE:/tmp/krb5cc_%{uid}\n")
                .unwrap();
        assert_eq!(
            cc.default_ccache_name.as_deref(),
            Some("FILE:/tmp/krb5cc_%{uid}")
        );
    }

    #[test]
    fn default_ccache_name_uses_process_uid() {
        let uid = nix::unistd::Uid::current().as_raw();
        assert_eq!(
            default_ccache_name(),
            PathBuf::from(format!("/tmp/krb5cc_{uid}"))
        );
        if uid != 0 {
            assert_ne!(default_ccache_name(), PathBuf::from("/tmp/krb5cc_0"));
        }
    }

    #[test]
    fn expand_ccache_params_uid_tokens() {
        let uid = unix_uid();
        let euid = unix_euid();
        assert_eq!(
            expand_ccache_params("FILE:/tmp/x_%{uid}_%{USERID}_%{euid}").unwrap(),
            format!("FILE:/tmp/x_{uid}_{uid}_{euid}")
        );
        assert_eq!(
            expand_ccache_params("FILE:/tmp/n_%{null}x").unwrap(),
            "FILE:/tmp/n_x"
        );
        assert!(
            expand_ccache_params("FILE:/tmp/%{nope}")
                .unwrap_err()
                .contains("nope")
        );
        let expanded = expand_ccache_params("FILE:/tmp/krb5cc_%{uid}").unwrap();
        assert_eq!(
            parse_ccspec(&expanded).unwrap(),
            CcSpec::File(default_ccache_name())
        );
    }

    #[test]
    fn parse_ccname_file_and_rejects_other_types() {
        assert_eq!(
            parse_ccname("FILE:/tmp/krb5cc_1").unwrap(),
            PathBuf::from("/tmp/krb5cc_1")
        );
        assert_eq!(
            parse_ccname("KEYRING:user:foo").unwrap_err(),
            KRB5_CC_UNKNOWN_TYPE
        );
        assert_eq!(
            parse_ccname("/tmp/krb5cc_9").unwrap(),
            PathBuf::from("/tmp/krb5cc_9")
        );
    }

    #[test]
    fn parse_ccspec_file_memory_dir_and_unknown() {
        assert_eq!(
            parse_ccspec("FILE:/tmp/a").unwrap(),
            CcSpec::File(PathBuf::from("/tmp/a"))
        );
        assert_eq!(
            parse_ccspec("/tmp/a").unwrap(),
            CcSpec::File(PathBuf::from("/tmp/a"))
        );
        assert_eq!(
            parse_ccspec("MEMORY:foo").unwrap(),
            CcSpec::Memory("foo".into())
        );
        assert_eq!(
            parse_ccspec("DIR:/tmp/cc").unwrap(),
            CcSpec::Dir("/tmp/cc".into())
        );
        assert_eq!(
            parse_ccspec("DIR::/tmp/cc/tkt").unwrap(),
            CcSpec::Dir(":/tmp/cc/tkt".into())
        );
        assert_eq!(
            parse_ccspec("KEYRING:persistent:1").unwrap_err(),
            KRB5_CC_UNKNOWN_TYPE
        );
        assert_eq!(parse_ccspec("KCM:").unwrap(), CcSpec::Kcm(String::new()));
        assert_eq!(parse_ccspec("KCM:0").unwrap(), CcSpec::Kcm("0".into()));
        assert_eq!(parse_ccspec("JUNK:x").unwrap_err(), KRB5_CC_UNKNOWN_TYPE);
        assert!(!parse_ccspec("KEYRING:x").unwrap_err().contains("G8"));
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
    fn parse_pkinit_identities_and_anchors() {
        let c = Krb5Conf::parse(
            r"
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
        pkinit_identities = FILE:/tmp/pkinit/user.pem
        pkinit_anchors = FILE:/tmp/pkinit/ca.pem
    }
",
        )
        .unwrap();
        assert_eq!(
            c.pkinit_identities["KERBER.TEST"],
            vec!["FILE:/tmp/pkinit/user.pem".to_owned()]
        );
        assert_eq!(
            c.pkinit_anchors["KERBER.TEST"],
            vec!["FILE:/tmp/pkinit/ca.pem".to_owned()]
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

    fn g9a_tree(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "kerber-g9a-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn split_krb5_config_paths_colon() {
        assert_eq!(
            split_krb5_config_paths("/a.conf:/b.conf"),
            vec![PathBuf::from("/a.conf"), PathBuf::from("/b.conf")]
        );
        assert!(split_krb5_config_paths("").is_empty());
        assert_eq!(
            split_krb5_config_paths("/a.conf:"),
            vec![PathBuf::from("/a.conf")]
        );
    }

    #[test]
    fn includedir_reads_dotted_conf() {
        let root = g9a_tree("dot");
        let drop = root.join("d.d");
        std::fs::create_dir(&drop).unwrap();
        std::fs::write(
            root.join("main.conf"),
            format!(
                "includedir {}\n[libdefaults]\n    dns_lookup_kdc = false\n",
                drop.display()
            ),
        )
        .unwrap();
        std::fs::write(
            drop.join("10.conf"),
            r"
[libdefaults]
    default_realm = DOTTED.TEST
[realms]
    DOTTED.TEST = {
        kdc = 10.9.8.7:1088
    }
",
        )
        .unwrap();
        let c = Krb5Conf::load_file(root.join("main.conf")).unwrap();
        assert_eq!(c.default_realm.as_deref(), Some("DOTTED.TEST"));
        assert_eq!(c.kdcs["DOTTED.TEST"][0].host, "10.9.8.7");
        assert_eq!(c.kdcs["DOTTED.TEST"][0].port, 1088);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn two_file_merge_first_wins_scalar_appends_kdc() {
        let root = g9a_tree("merge");
        let a = root.join("a.conf");
        let b = root.join("b.conf");
        std::fs::write(
            &a,
            r"
[libdefaults]
    default_realm = FIRST.TEST
[realms]
    FIRST.TEST = {
        kdc = 10.0.0.1
        kdc = 10.0.0.2
    }
",
        )
        .unwrap();
        std::fs::write(
            &b,
            r"
[libdefaults]
    default_realm = SECOND.TEST
[realms]
    FIRST.TEST = {
        kdc = 10.0.0.3
    }
",
        )
        .unwrap();
        let c = load_krb5_conf_paths([&a, &b]).unwrap();
        assert_eq!(c.default_realm.as_deref(), Some("FIRST.TEST"));
        let kdcs: Vec<_> = c.kdcs["FIRST.TEST"]
            .iter()
            .map(|e| e.host.as_str())
            .collect();
        assert_eq!(kdcs, ["10.0.0.1", "10.0.0.2", "10.0.0.3"]);
        let rev = load_krb5_conf_paths([&b, &a]).unwrap();
        assert_eq!(rev.default_realm.as_deref(), Some("SECOND.TEST"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn include_then_local_keeps_included_scalar() {
        let root = g9a_tree("inc");
        let child = root.join("child.conf");
        let parent = root.join("parent.conf");
        std::fs::write(&child, "[libdefaults]\n    default_realm = CHILD.TEST\n").unwrap();
        std::fs::write(
            &parent,
            format!(
                "include {}\n[libdefaults]\n    default_realm = PARENT.TEST\n",
                child.display()
            ),
        )
        .unwrap();
        let c = Krb5Conf::load_file(&parent).unwrap();
        assert_eq!(c.default_realm.as_deref(), Some("CHILD.TEST"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn include_cycle_is_error() {
        let root = g9a_tree("cyc");
        let a = root.join("a.conf");
        let b = root.join("b.conf");
        std::fs::write(
            &a,
            format!(
                "include {}\n[libdefaults]\n    default_realm = A.TEST\n",
                b.display()
            ),
        )
        .unwrap();
        std::fs::write(
            &b,
            format!(
                "include {}\n[libdefaults]\n    default_realm = B.TEST\n",
                a.display()
            ),
        )
        .unwrap();
        let err = Krb5Conf::load_file(&a).unwrap_err();
        assert!(
            matches!(err, Error::Parse(ref s) if s.contains("cycle")),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_include_is_error() {
        let root = g9a_tree("miss");
        let main = root.join("main.conf");
        std::fs::write(
            &main,
            format!(
                "include {}\n[libdefaults]\n    default_realm = X.TEST\n",
                root.join("nope.conf").display()
            ),
        )
        .unwrap();
        assert!(Krb5Conf::load_file(&main).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn parse_capaths_client_server_hops() {
        let c = Krb5Conf::parse(
            r"
[capaths]
    A.TEST = {
        C.TEST = B.TEST
        B.TEST = .
    }
    C.TEST = {
        A.TEST = B.TEST
    }
",
        )
        .unwrap();
        assert_eq!(c.capaths["A.TEST"]["C.TEST"], ["B.TEST"]);
        assert_eq!(c.capaths["A.TEST"]["B.TEST"], ["."]);
        assert_eq!(c.capaths["C.TEST"]["A.TEST"], ["B.TEST"]);
    }

    #[test]
    fn parse_text_does_not_follow_include() {
        let c = Krb5Conf::parse(
            "include /no/such/file.conf\n[libdefaults]\n    default_realm = LOCAL.TEST\n",
        )
        .unwrap();
        assert_eq!(c.default_realm.as_deref(), Some("LOCAL.TEST"));
    }
}
