//! krb5.conf / kdc.conf, process environment, and DNS SRV discovery.
//!
//! There is no C FFI. DNS SRV is a minimal RFC 2782 UDP client.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// `allow_rc4` (unset = false at the KDC unless kdc.conf set it).
    pub allow_rc4: Option<bool>,
    /// `allow_des3`.
    pub allow_des3: Option<bool>,
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
    /// `kdc_timesync`. Default true (`init_ctx.c:268-270`). AS-REP
    /// `verify_as_reply` skips starttime vs the local clock when set.
    pub kdc_timesync: bool,
    /// `verify_ap_req_nofail`. Default false (`vfy_increds.c:38-51`).
    pub verify_ap_req_nofail: bool,
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
    /// `canonicalize`. Default false (`get_in_tkt.c:921-930`).
    pub canonicalize: bool,
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
    /// `[libdefaults] spake_preauth_groups`. `None` = omitted (KDC default none).
    pub spake_preauth_groups: Option<Vec<String>>,
    /// `[libdefaults] preferred_preauth_types`. Empty = MIT default `17, 16, 15, 14`.
    pub preferred_preauth_types: Vec<i32>,
    /// `[libdefaults] ignore_acceptor_hostname`. Default false
    /// (`sname_match.c:51-53`).
    pub ignore_acceptor_hostname: bool,
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
    /// Maximum ticket lifetime in seconds (default 1 day, `alt_prof.c`).
    pub max_life: u64,
    /// kadm5 create default for `max_renewable_life` (`alt_prof.c:577-578`
    /// `GET_DELTAT_PARAM(max_rlife, …, 0)`). Omitted = 0.
    pub max_renewable_life: u64,
    /// KDC realm renewable cap (`kdc/main.c:316-319` `realm_maxrlife`,
    /// omitted = `KRB5_KDB_MAX_RLIFE` = 7 days). A written
    /// `max_renewable_life` sets this and [`Self::max_renewable_life`].
    pub realm_max_renewable_life: u64,
    /// Database path.
    pub database_name: Option<PathBuf>,
    /// ACL file.
    pub acl_file: Option<PathBuf>,
    /// Stash file for the master key.
    pub key_stash_file: Option<PathBuf>,
    /// User to drop to after binding a privileged port.
    pub kdc_user: Option<String>,
    /// `allow_weak_crypto`.
    pub allow_weak_crypto: Option<bool>,
    /// `allow_rc4` (`[libdefaults]` / `[kdcdefaults]`).
    pub allow_rc4: Option<bool>,
    /// `allow_des3`.
    pub allow_des3: Option<bool>,
    /// `permitted_enctypes` (empty = MIT DEFAULT).
    pub permitted_enctypes: Vec<String>,
    /// Realm `supported_enctypes` keysalt list.
    pub supported_enctypes: Vec<String>,
    /// Per-principal `requires_preauth` default.
    pub requires_preauth: bool,
    /// `[realms] default_principal_flags` as written (MIT `alt_prof.c:596-632`
    /// `KADM5_CONFIG_FLAGS`; the flagspec list is parsed by the store). `None`
    /// = `KRB5_KDB_DEF_FLAGS` (0).
    pub default_principal_flags: Option<String>,
    /// `[realms] default_principal_expiration` as written (MIT
    /// `alt_prof.c:580-594` `KADM5_CONFIG_EXPIRATION`, a
    /// `krb5_string_to_timestamp` form; the store converts it). `None` = 0.
    pub default_principal_expiration: Option<String>,
    /// `master_key_type` (MIT name, e.g. `aes256-cts-hmac-sha384-192`).
    pub master_key_type: Option<String>,
    /// `database_module` / `db_library`. Default dump-v7; unknown names error.
    pub db_library: Option<String>,
    /// Optional NT domain SID (`S-1-5-21-…`) for PAC issuance.
    pub domain_sid: Option<String>,
    /// `reject_bad_transit` (default true). When false, a failed transited
    /// check is accepted without `TRANSITED_POLICY_CHECKED`.
    pub reject_bad_transit: bool,
    /// MIT `disable_pac` (default false).
    pub disable_pac: bool,
    /// MIT `restrict_anonymous_to_tgt` (default false).
    pub restrict_anon: bool,
    /// MIT `pkinit_require_freshness` (default false).
    pub pkinit_require_freshness: bool,
    /// MIT `host_based_services` (space/comma-separated).
    pub host_based_services: String,
    /// MIT `no_host_referral` (space/comma-separated).
    pub no_host_referral: String,
    /// `[realms] encrypted_challenge_indicator`.
    pub encrypted_challenge_indicator: Option<String>,
    /// `[realms] pkinit_indicator` (repeatable).
    pub pkinit_indicators: Vec<String>,
    /// `[realms] spake_preauth_indicator` (repeatable).
    pub spake_preauth_indicators: Vec<String>,
    /// `[libdefaults] spake_preauth_groups`. `None` = omitted.
    pub spake_preauth_groups: Option<Vec<String>>,
    /// `[realms] dict_file` for the `dict` password-quality module. MIT
    /// `alt_prof.c:486-513` reads it from the realm stanza only, never from
    /// `[kdcdefaults]`.
    pub dict_file: Option<PathBuf>,
}

impl Default for KdcConf {
    fn default() -> Self {
        Self {
            kdc_listen: vec!["127.0.0.1:88".into()],
            kdc_tcp_listen: vec!["127.0.0.1:88".into()],
            realm: "KERBER.TEST".into(),
            max_life: 24 * 3600,
            max_renewable_life: 0,
            realm_max_renewable_life: 7 * 24 * 3600,
            database_name: None,
            acl_file: None,
            key_stash_file: None,
            kdc_user: None,
            allow_weak_crypto: None,
            allow_rc4: None,
            allow_des3: None,
            permitted_enctypes: Vec::new(),
            supported_enctypes: Vec::new(),
            requires_preauth: true,
            default_principal_flags: None,
            default_principal_expiration: None,
            master_key_type: None,
            db_library: None,
            domain_sid: None,
            reject_bad_transit: true,
            disable_pac: false,
            restrict_anon: false,
            pkinit_require_freshness: false,
            host_based_services: String::new(),
            no_host_referral: String::new(),
            encrypted_challenge_indicator: None,
            pkinit_indicators: Vec::new(),
            spake_preauth_indicators: Vec::new(),
            spake_preauth_groups: None,
            dict_file: None,
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

    /// MIT `k5_client_realm_path`: client, `[capaths]` hops, server.
    ///
    /// `.` means a direct path (`[client, server]`). Missing capaths is
    /// also direct (hierarchical tweens are `krb5_walk_realm_tree` only).
    #[must_use]
    pub fn client_realm_path(&self, client: &str, server: &str) -> Vec<String> {
        client_realm_path(&self.capaths, client, server)
    }
}

/// MIT `k5_client_realm_path` over an already-parsed `[capaths]` map.
#[must_use]
pub fn client_realm_path(
    capaths: &BTreeMap<String, BTreeMap<String, Vec<String>>>,
    client: &str,
    server: &str,
) -> Vec<String> {
    if client == server {
        return vec![client.to_owned()];
    }
    let mut path = vec![client.to_owned()];
    if let Some(vals) = capaths.get(client).and_then(|m| m.get(server))
        && !(vals.len() == 1 && vals[0] == ".")
    {
        for v in vals {
            if v != "." {
                path.push(v.clone());
            }
        }
    }
    path.push(server.to_owned());
    path
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
        let mut realm_lines = Vec::new();
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
                    realm_lines.push(line.to_owned());
                    parse_kdc_realm_line(&mut conf, line);
                }
            }
            if section == "kdcdefaults" {
                parse_kdcdefaults(&mut conf, line);
            }
            if section == "libdefaults" {
                parse_kdc_libdefaults(&mut conf, line);
            }
        }
        // MIT `main.c:286-345`: realm stanza, then `[kdcdefaults]` fallback.
        // Re-apply realm booleans so a later defaults section cannot win.
        for line in &realm_lines {
            overlay_realm_booleans(&mut conf, line);
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

/// MIT `k5_is_numeric_address` (`hostrealm.c:318-338`).
#[must_use]
pub fn is_numeric_address(name: &str) -> bool {
    if name.contains(':') {
        return true;
    }
    if name.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return name.bytes().filter(|&b| b == b'.').count() == 3;
    }
    false
}

/// Longest-suffix `[domain_realm]` map (MIT hostrealm profile).
#[must_use]
pub fn host_to_realm<'a>(map: &'a BTreeMap<String, String>, host: &str) -> Option<&'a str> {
    if is_numeric_address(host) {
        return None;
    }
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
        // MIT: column-0 include is a directive; indented include inside a
        // section is Improper format (a relation with no '='). At file start
        // (no section) MIT ignores it.
        if !section.is_empty()
            && split_kv(line).is_none()
            && include_directive(line).is_some()
            && include_directive(raw).is_none()
        {
            return Err(Error::Parse("improper format: indented include".into()));
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
                let entry = conf
                    .capaths
                    .entry(client.clone())
                    .or_default()
                    .entry(server.to_string())
                    .or_default();
                for h in hop.split_whitespace() {
                    entry.push(h.to_string());
                }
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
    let canon = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !stack.is_empty() => {
            return Err(Error::Parse(format!(
                "include target not found: {}",
                path.display()
            )));
        }
        Err(e) => return Err(e.into()),
    };
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
        "allow_rc4" if take_first(seen, "allow_rc4") => {
            conf.allow_rc4 = Some(truthy(&v));
        }
        "allow_des3" if take_first(seen, "allow_des3") => {
            conf.allow_des3 = Some(truthy(&v));
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
        "verify_ap_req_nofail" if take_first(seen, "verify_ap_req_nofail") => {
            conf.verify_ap_req_nofail = truthy(&v);
        }
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
        "canonicalize" if take_first(seen, "canonicalize") => conf.canonicalize = truthy(&v),
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
        "spake_preauth_groups" if take_first(seen, "spake_preauth_groups") => {
            conf.spake_preauth_groups = Some(split_ws(&v));
        }
        "preferred_preauth_types" if take_first(seen, "preferred_preauth_types") => {
            conf.preferred_preauth_types = parse_i32_list(&v);
        }
        "ignore_acceptor_hostname" if take_first(seen, "ignore_acceptor_hostname") => {
            conf.ignore_acceptor_hostname = truthy(&v);
        }
        _ => {}
    }
}

fn combine_ws(dst: &mut String, more: &str) {
    let more = more.trim();
    if more.is_empty() {
        return;
    }
    if dst.is_empty() {
        more.clone_into(dst);
    } else {
        dst.push(' ');
        dst.push_str(more);
    }
}

fn parse_i32_list(v: &str) -> Vec<i32> {
    v.split(|c: char| c == ',' || c.is_ascii_whitespace())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect()
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
        "reject_bad_transit" => conf.reject_bad_transit = truthy(&v),
        "disable_pac" => conf.disable_pac = truthy(&v),
        "restrict_anonymous_to_tgt" => conf.restrict_anon = truthy(&v),
        "pkinit_require_freshness" => conf.pkinit_require_freshness = truthy(&v),
        "host_based_services" => combine_ws(&mut conf.host_based_services, &v),
        "no_host_referral" => combine_ws(&mut conf.no_host_referral, &v),
        _ => {}
    }
}

/// MIT reads the enctype policy knobs from `[libdefaults]` only
/// (`init_ctx.c get_boolean`, `krb5_get_permitted_enctypes`); a copy under
/// `[kdcdefaults]` or a realm stanza is ignored, so the KDC's own context
/// sees what every krb5 library on the host sees.
fn parse_kdc_libdefaults(conf: &mut KdcConf, line: &str) {
    let Some((k, v)) = split_kv(line) else {
        return;
    };
    match k.to_ascii_lowercase().as_str() {
        "allow_weak_crypto" => conf.allow_weak_crypto = Some(truthy(&v)),
        "allow_rc4" => conf.allow_rc4 = Some(truthy(&v)),
        "allow_des3" => conf.allow_des3 = Some(truthy(&v)),
        "permitted_enctypes" => conf.permitted_enctypes = split_ws(&v),
        "spake_preauth_groups" => conf.spake_preauth_groups = Some(split_ws(&v)),
        // MIT reads kdc_ports/kdc_tcp_ports/reject_bad_transit only from
        // [kdcdefaults] or a realm stanza (main.c:257-261,622-626), never
        // [libdefaults]; no fallthrough, so a kdcdefaults knob placed under
        // [libdefaults] is ignored like MIT.
        _ => {}
    }
}

/// MIT realm-first booleans: a realm value beats a later `[kdcdefaults]`.
fn overlay_realm_booleans(conf: &mut KdcConf, line: &str) {
    let Some((k, v)) = split_kv(line) else {
        return;
    };
    match k.to_ascii_lowercase().as_str() {
        "reject_bad_transit" => conf.reject_bad_transit = truthy(&v),
        "disable_pac" => conf.disable_pac = truthy(&v),
        "restrict_anonymous_to_tgt" => conf.restrict_anon = truthy(&v),
        "pkinit_require_freshness" => conf.pkinit_require_freshness = truthy(&v),
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
            if let Some(secs) = parse_duration_secs(&v) {
                conf.max_renewable_life = secs;
                conf.realm_max_renewable_life = secs;
            }
        }
        "database_name" => conf.database_name = Some(PathBuf::from(v)),
        "acl_file" => conf.acl_file = Some(PathBuf::from(v)),
        "key_stash_file" => conf.key_stash_file = Some(PathBuf::from(v)),
        "kdc_user" => conf.kdc_user = Some(v),
        "supported_enctypes" => conf.supported_enctypes = split_ws(&v),
        "requires_preauth" => conf.requires_preauth = truthy(&v),
        "default_principal_flags" => conf.default_principal_flags = Some(v),
        "default_principal_expiration" => conf.default_principal_expiration = Some(v),
        "master_key_type" => conf.master_key_type = Some(v),
        "database_module" | "db_library" => conf.db_library = Some(v),
        "domain_sid" => conf.domain_sid = Some(v),
        "reject_bad_transit" => conf.reject_bad_transit = truthy(&v),
        "disable_pac" => conf.disable_pac = truthy(&v),
        "restrict_anonymous_to_tgt" => conf.restrict_anon = truthy(&v),
        "pkinit_require_freshness" => conf.pkinit_require_freshness = truthy(&v),
        "host_based_services" => combine_ws(&mut conf.host_based_services, &v),
        "no_host_referral" => combine_ws(&mut conf.no_host_referral, &v),
        "encrypted_challenge_indicator" => {
            conf.encrypted_challenge_indicator = Some(v);
        }
        "pkinit_indicator" => conf.pkinit_indicators.push(v),
        "spake_preauth_indicator" => conf.spake_preauth_indicators.push(v),
        "dict_file" => conf.dict_file = Some(PathBuf::from(v)),
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

/// Parse MIT `krb5_string_to_deltat` (`x-deltat.y`).
#[must_use]
pub fn parse_deltat(v: &str) -> Option<u64> {
    parse_duration_secs(v)
}

fn parse_duration_secs(v: &str) -> Option<u64> {
    krb5_types::deltat::parse(v)
        .ok()
        .and_then(|n| u64::try_from(n).ok())
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
/// Unknown `%{token}` or unterminated `%{` (MIT fails closed).
pub fn expand_ccache_params(s: &str) -> Result<String, String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("%{") {
        out.push_str(&rest[..start]);
        rest = &rest[start + 2..];
        let Some(end) = rest.find('}') else {
            return Err("unterminated %{token}".into());
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

thread_local! {
    static TEST_KRB5_PATHS: RefCell<Option<Vec<PathBuf>>> = const { RefCell::new(None) };
    static TEST_KRB5_ISOLATION: RefCell<Option<IsolatedKrb5>> = const { RefCell::new(None) };
}

static ISOLATE_SEQ: AtomicU64 = AtomicU64::new(0);

struct IsolatedKrb5 {
    path: PathBuf,
}

impl Drop for IsolatedKrb5 {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn isolate_scratch_dir() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_TARGET_TMPDIR")
        && !p.is_empty()
    {
        return PathBuf::from(p);
    }
    if let Ok(p) = std::env::var("CARGO_TARGET_DIR")
        && !p.is_empty()
    {
        return PathBuf::from(p).join("test-krb5");
    }
    if let Ok(p) = std::env::var("KERBER_SCRATCH")
        && !p.is_empty()
    {
        return PathBuf::from(p);
    }
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../target/test-krb5"
    ))
}

/// Test overlay for [`krb5_conf_paths`] (avoids the host `/etc/krb5.conf`).
pub fn set_test_krb5_paths(paths: Option<Vec<PathBuf>>) {
    TEST_KRB5_PATHS.with(|c| *c.borrow_mut() = paths);
}

/// Pin a realm-only profile so host `udp_preference_limit` cannot force TCP.
pub fn isolate_test_krb5() {
    let dir = isolate_scratch_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!(
        "kerber-test-krb5-{}-{}.conf",
        std::process::id(),
        ISOLATE_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::write(
        &path,
        "[libdefaults]\n    default_realm = KERBER.TEST\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n",
    );
    set_test_krb5_paths(Some(vec![path.clone()]));
    TEST_KRB5_ISOLATION.with(|c| *c.borrow_mut() = Some(IsolatedKrb5 { path }));
}

/// `KRB5_CONFIG` (colon-split) or `/etc/krb5.conf` when unset.
#[must_use]
pub fn krb5_conf_paths() -> Vec<PathBuf> {
    if let Some(paths) = TEST_KRB5_PATHS.with(|c| c.borrow().clone()) {
        return paths;
    }
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

/// `KRB5_NEW_PASSWORD` for `gic_pwd.c` KEY_EXP → changepw (never from argv).
#[must_use]
pub fn env_new_password() -> Option<Vec<u8>> {
    std::env::var("KRB5_NEW_PASSWORD")
        .ok()
        .map(String::into_bytes)
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
mod tests;
