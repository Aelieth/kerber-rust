//! krb5.conf profile (`util/profile/prof_parse.c` `profile_parse_file`,
//! `prof_init.c` `profile_init` / `profile_init_path`;
//! `krb/init_ctx.c` `get_boolean` / `krb5_get_permitted_enctypes`;
//! `os/hostrealm.c` `k5_is_numeric_address` / `krb5_get_host_realm`;
//! `os/hostrealm_profile.c` `profile_host_realm`;
//! `os/locate_kdc.c` `prof_locate_server`;
//! `os/init_os_ctx.c` `os_init_paths`;
//! `krb/walk_rtree.c` `k5_client_realm_path`): parse,
//! `include` / `includedir`, `[libdefaults]` / `[realms]` /
//! `[domain_realm]` / `[capaths]`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::srv::lookup_srv_kdc;
use super::testenv::TEST_KRB5_PATHS;
use super::{Endpoint, Error, Krb5Conf};

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

pub(super) fn combine_ws(dst: &mut String, more: &str) {
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

pub(super) fn split_ws(v: &str) -> Vec<String> {
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

pub(super) fn split_kv(line: &str) -> Option<(&str, String)> {
    let line = line.trim().trim_end_matches(',');
    let (k, v) = line.split_once('=')?;
    Some((k.trim(), v.trim().trim_matches('"').to_owned()))
}

pub(super) fn truthy(v: &str) -> bool {
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

pub(super) fn parse_duration_secs(v: &str) -> Option<u64> {
    krb5_types::deltat::parse(v)
        .ok()
        .and_then(|n| u64::try_from(n).ok())
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
