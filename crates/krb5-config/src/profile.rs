use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::srv::{DnsSrv, lookup_srv_kdc_traced, lookup_srv_kerberos_adm, lookup_srv_kpasswd};
use super::testenv::TEST_KRB5_PATHS;
use super::{Endpoint, Error, KdcTransport, Krb5Conf, ProfileError, RealmLibdefaults};

impl Krb5Conf {
    #[must_use]
    pub fn encrypted_timestamp_disabled(&self, realm: &str) -> bool {
        self.disable_encrypted_timestamp
            .get(realm)
            .copied()
            .unwrap_or(false)
    }

    #[must_use]
    pub fn forwardable_for(&self, realm: &str) -> bool {
        self.realm_bool(realm, |node| node.forwardable)
            .unwrap_or(self.forwardable)
    }

    #[must_use]
    pub fn proxiable_for(&self, realm: &str) -> bool {
        self.realm_bool(realm, |node| node.proxiable)
            .unwrap_or(self.proxiable)
    }

    #[must_use]
    pub fn canonicalize_for(&self, realm: &str) -> bool {
        self.realm_bool(realm, |node| node.canonicalize)
            .unwrap_or(self.canonicalize)
    }

    #[must_use]
    pub fn ticket_lifetime_for(&self, realm: &str) -> Option<u64> {
        self.realm_libdefaults
            .get(realm)
            .and_then(|node| node.ticket_lifetime)
            .or(self.ticket_lifetime)
    }

    #[must_use]
    pub fn renew_lifetime_for(&self, realm: &str) -> Option<u64> {
        self.realm_libdefaults
            .get(realm)
            .and_then(|node| node.renew_lifetime)
            .or(self.renew_lifetime)
    }

    #[must_use]
    pub fn noaddresses_for(&self, realm: &str) -> Option<bool> {
        self.realm_bool(realm, |node| node.noaddresses)
            .or(self.noaddresses)
    }

    #[must_use]
    pub fn verify_ap_req_nofail_for(&self, realm: &str) -> bool {
        self.realm_bool(realm, |node| node.verify_ap_req_nofail)
            .unwrap_or(self.verify_ap_req_nofail)
    }

    // MIT: `sort_krb5_padata_sequence` (lib/krb5/krb/get_in_tkt.c:418-424)
    // The realm string, else "17, 16, 15, 14".
    #[must_use]
    pub fn preferred_preauth_for(&self, realm: &str) -> Option<&[i32]> {
        if let Some(list) = self
            .realm_libdefaults
            .get(realm)
            .and_then(|node| node.preferred_preauth_types.as_deref())
        {
            return Some(list);
        }
        if self.preferred_preauth_types.is_empty() {
            None
        } else {
            Some(self.preferred_preauth_types.as_slice())
        }
    }

    fn realm_bool(
        &self,
        realm: &str,
        pick: impl Fn(&RealmLibdefaults) -> Option<bool>,
    ) -> Option<bool> {
        self.realm_libdefaults.get(realm).and_then(pick)
    }

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse(text: &str) -> Result<Self, Error> {
        Self::parse_files(&[text])
    }

    pub fn parse_files(texts: &[&str]) -> Result<Self, Error> {
        let mut conf = Self::new();
        let mut seen = BTreeSet::new();
        let mut plugin_profile = super::plugin_profile::PluginProfile::default();
        for text in texts {
            parse_into(&mut conf, &mut seen, text, None, &mut plugin_profile)?;
        }
        conf.plugins = plugin_profile;
        conf.apply_dns_lookup_default(&seen);
        Ok(conf)
    }

    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let mut conf = Self::new();
        let mut seen = BTreeSet::new();
        let mut stack = Vec::new();
        let mut plugin_profile = super::plugin_profile::PluginProfile::default();
        load_path_into(
            &mut conf,
            &mut seen,
            &mut stack,
            path.as_ref(),
            &mut plugin_profile,
        )?;
        conf.plugins = plugin_profile;
        conf.apply_dns_lookup_default(&seen);
        Ok(conf)
    }

    #[must_use]
    pub fn realm_for_host(&self, host: &str) -> Option<&str> {
        host_to_realm(&self.domain_realm, host)
    }

    // MIT: `_krb5_use_dns_kdc` (lib/krb5/os/locate_kdc.c:88-91)
    pub(crate) fn apply_dns_lookup_default(&mut self, seen: &BTreeSet<String>) {
        if seen.contains("dns_lookup_kdc") || seen.contains("dns_fallback") {
            return;
        }
        self.dns_lookup_kdc = true;
    }

    #[must_use]
    pub fn udp_limit(&self) -> usize {
        self.udp_preference_limit
            .map_or(1465, |n| usize::try_from(n).unwrap_or(1465))
    }

    pub fn kdcs_for(&self, realm: &str) -> Result<Vec<Endpoint>, Error> {
        self.kdcs_for_traced(realm, &mut |_| {})
    }

    pub fn kdcs_for_traced(
        &self,
        realm: &str,
        trace: &mut dyn FnMut(DnsSrv),
    ) -> Result<Vec<Endpoint>, Error> {
        if self.kdc_host_invalid.contains(realm) {
            return Err(Error::InvalidArgument);
        }
        if let Some(list) = self.kdcs.get(realm)
            && !list.is_empty()
        {
            return Ok(list.clone());
        }
        if self.dns_lookup_kdc {
            return lookup_srv_kdc_traced(realm, trace);
        }
        Ok(Vec::new())
    }

    // MIT: `locate_kpasswd` (lib/krb5/os/changepw.c:61-90)
    pub fn locate_kpasswd(&self, realm: &str) -> Result<Vec<Endpoint>, Error> {
        self.locate_kpasswd_traced(realm, &mut |_| {})
    }

    pub fn locate_kpasswd_traced(
        &self,
        realm: &str,
        trace: &mut dyn FnMut(DnsSrv),
    ) -> Result<Vec<Endpoint>, Error> {
        if self.kpasswd_host_invalid.contains(realm) {
            return Err(Error::InvalidArgument);
        }
        if let Some(list) = self.kpasswd_servers.get(realm).filter(|l| !l.is_empty()) {
            return Ok(list.clone());
        }
        if self.dns_lookup_kdc
            && let Ok(list) = lookup_srv_kpasswd(realm, trace)
            && !list.is_empty()
        {
            return Ok(list);
        }
        if self.admin_host_invalid.contains(realm) {
            return Err(Error::InvalidArgument);
        }
        if let Some(list) = self.admin_servers.get(realm).filter(|l| !l.is_empty()) {
            return Ok(kpasswd_from_admin(list));
        }
        if self.dns_lookup_kdc
            && let Ok(list) = lookup_srv_kerberos_adm(realm, trace)
            && !list.is_empty()
        {
            return Ok(kpasswd_from_admin(&list));
        }
        Ok(Vec::new())
    }

    #[must_use]
    pub fn client_realm_path(&self, client: &str, server: &str) -> Vec<String> {
        client_realm_path(&self.capaths, client, server)
    }
}

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

// MIT: `parse_file` (prof_parse.c:351-359)
// Each line goes to `parse_line` whole.
// MIT: `strip_line` (prof_parse.c:40-45)
fn profile_lines(text: &str) -> impl Iterator<Item = &str> {
    text.split_terminator('\n')
        .map(|line| line.trim_end_matches(['\r', '\n']))
}

// MIT: `parse_line` (prof_parse.c:331-335)
pub fn join_subsection_braces(text: &str) -> Result<String, Error> {
    let mut out = String::with_capacity(text.len());
    let mut in_section = false;
    let mut pending: Option<&str> = None;
    for raw in profile_lines(text) {
        if include_directive(raw).is_some() {
            out.push_str(raw);
            out.push('\n');
            continue;
        }
        if let Some(tag) = pending.take() {
            if !raw.trim_start().starts_with('{') {
                return Err(Error::Profile(
                    ProfileError::Syntax,
                    format!("improper format: no {{ after {tag} ="),
                ));
            }
            out.push_str(tag);
            out.push_str(" = {\n");
            continue;
        }
        let line = raw.trim();
        if line.starts_with('[') {
            in_section = true;
        } else if in_section
            && !line.starts_with(['#', ';'])
            && let Some((tag, value)) = line.split_once('=')
            && value.trim().is_empty()
            && !tag.trim().is_empty()
        {
            pending = Some(tag.trim());
            continue;
        }
        out.push_str(raw);
        out.push('\n');
    }
    if let Some(tag) = pending {
        out.push_str(tag);
        out.push_str(" = {\n");
    }
    Ok(out)
}

fn valid_include_name(name: &str) -> bool {
    if name.starts_with('.') {
        return false;
    }
    if name.len() >= 5 && name.as_bytes().ends_with(b".conf") {
        return true;
    }
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub(crate) fn resolve_includes(text: &str, stack: &mut Vec<PathBuf>) -> Result<String, Error> {
    let joined = join_subsection_braces(text)?;
    let mut out = String::with_capacity(joined.len());
    let mut heading = "[ ]";
    let mut depth = 0usize;
    for line in joined.lines() {
        if let Some(kind) = include_directive(line) {
            if depth > 0 {
                return Err(Error::Profile(
                    ProfileError::Syntax,
                    "an include inside a { } group is not supported".into(),
                ));
            }
            out.push_str("[ ]\n");
            match kind {
                IncludeKind::File(p) => out.push_str(&include_file_text(Path::new(p), stack)?),
                IncludeKind::Dir(d) => out.push_str(&include_dir_text(Path::new(d), stack)?),
            }
            out.push_str(heading);
            out.push('\n');
            continue;
        }
        let t = line.trim();
        if depth == 0 && t.starts_with('[') {
            heading = line;
        } else if !t.starts_with(['#', ';']) {
            if t.ends_with('{') {
                depth += 1;
            } else if t.starts_with('}') {
                depth = depth.saturating_sub(1);
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    Ok(out)
}

fn include_file_text(path: &Path, stack: &mut Vec<PathBuf>) -> Result<String, Error> {
    let include = |what: String| Error::Profile(ProfileError::IncludeFile, what);
    let unread = |e: std::io::Error| {
        if e.kind() == std::io::ErrorKind::NotFound {
            include(format!("include target not found: {}", path.display()))
        } else {
            include(format!("include target {}: {e}", path.display()))
        }
    };
    if stack.len() >= MAX_INCLUDE_DEPTH {
        return Err(include("include nesting too deep".into()));
    }
    let canon = std::fs::canonicalize(path).map_err(unread)?;
    if stack.iter().any(|p| p == &canon) {
        return Err(include("include cycle".into()));
    }
    let bytes = super::files::read(&canon).map_err(unread)?;
    stack.push(canon);
    let text = resolve_includes(&String::from_utf8_lossy(&bytes), stack);
    stack.pop();
    text
}

fn include_dir_text(dir: &Path, stack: &mut Vec<PathBuf>) -> Result<String, Error> {
    let unlisted = |what: String| Error::Profile(ProfileError::IncludeDir, what);
    if !dir.is_dir() {
        return Err(unlisted(format!(
            "includedir not a directory: {}",
            dir.display()
        )));
    }
    let list = |e: std::io::Error| unlisted(format!("includedir {}: {e}", dir.display()));
    let mut names = Vec::new();
    for name in super::files::dir_names(dir).map_err(list)? {
        if let Some(s) = name.to_str()
            && valid_include_name(s)
        {
            names.push(s.to_owned());
        }
    }
    names.sort();
    let mut out = String::new();
    for name in names {
        let p = dir.join(name);
        if p.is_file() {
            out.push_str("[ ]\n");
            out.push_str(&include_file_text(&p, stack)?);
        }
    }
    Ok(out)
}

// MIT: `k5_is_numeric_address` (lib/krb5/os/hostrealm.c)
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

// MIT: `profile_parse_file` (prof_parse.c:431-434)
// A parse error is not a successful profile.
fn parse_into(
    conf: &mut Krb5Conf,
    seen: &mut BTreeSet<String>,
    text: &str,
    mut stack: Option<&mut Vec<PathBuf>>,
    plugin_profile: &mut super::plugin_profile::PluginProfile,
) -> Result<(), Error> {
    let mut section = String::new();
    let mut libdefaults_exact = false;
    let mut libdefaults_depth = 0usize;
    let mut libdefaults_realm: Option<String> = None;
    let mut kdcdefaults_depth = 0usize;
    let mut realm: Option<String> = None;
    let mut capaths_client: Option<String> = None;
    let text = join_subsection_braces(text)?;
    let mut plugins = super::plugin_profile::Cursor::new();
    let mut otp = super::otp_profile::Cursor::new();
    for raw in text.lines() {
        if let Some(kind) = include_directive(raw)
            && let Some(st) = stack.as_deref_mut()
        {
            match kind {
                IncludeKind::File(p) => {
                    load_file_into(conf, seen, st, Path::new(p), plugin_profile)?;
                }
                IncludeKind::Dir(p) => load_dir_into(conf, seen, st, Path::new(p), plugin_profile)?,
            }
            continue;
        }
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if !section.is_empty()
            && split_kv(line).is_none()
            && include_directive(line).is_some()
            && include_directive(raw).is_none()
        {
            return Err(Error::Profile(
                ProfileError::Syntax,
                "improper format: indented include".into(),
            ));
        }
        if let Some((body, starred)) = super::otp_profile::section_header(line) {
            otp.observe_header(&mut conf.otp, body, starred);
        }
        if let Some(s) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = s.trim().to_ascii_lowercase();
            libdefaults_exact = s == "libdefaults";
            libdefaults_depth = 0;
            libdefaults_realm = None;
            kdcdefaults_depth = 0;
            realm = None;
            capaths_client = None;
            plugins.observe_header(plugin_profile, s, false);
            continue;
        }
        if super::plugin_profile::starred_plugins_header(line) {
            section = "plugins".into();
            libdefaults_exact = false;
            libdefaults_depth = 0;
            libdefaults_realm = None;
            kdcdefaults_depth = 0;
            realm = None;
            capaths_client = None;
            plugins.observe_header(plugin_profile, "plugins", true);
            continue;
        }
        plugins.observe_line(plugin_profile, line);
        otp.observe_line(&mut conf.otp, line);
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
        if section == "libdefaults" && libdefaults_exact {
            if line.starts_with('}') {
                if libdefaults_depth == 1 {
                    libdefaults_realm = None;
                }
                libdefaults_depth = libdefaults_depth.saturating_sub(1);
            } else if opens_subsection(line) {
                if libdefaults_depth == 0 {
                    libdefaults_realm = subsection_name(line);
                }
                libdefaults_depth += 1;
            }
            let top = libdefaults_depth == 0;
            let node = if libdefaults_depth == 1 {
                libdefaults_realm.as_deref()
            } else {
                None
            };
            parse_libdefaults(conf, seen, line, top, node);
        }
        if section == "kdcdefaults" {
            if opens_subsection(line) {
                kdcdefaults_depth += 1;
            } else if line.starts_with('}') {
                kdcdefaults_depth = kdcdefaults_depth.saturating_sub(1);
            } else if kdcdefaults_depth == 0
                && let Some((k, v)) = split_kv(line)
                && k.starts_with("pkinit_")
            {
                conf.kdcdefaults_pkinit.push((k.to_owned(), v));
            }
        }
        if section == "domain_realm"
            && let Some((d, r)) = split_kv(line)
        {
            conf.domain_realm.entry(d.to_ascii_lowercase()).or_insert(r);
        }
        if section == "logging"
            && let Some((k, v)) = split_kv(line)
        {
            conf.logging.push((k.to_owned(), v));
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
    plugin_profile: &mut super::plugin_profile::PluginProfile,
) -> Result<(), Error> {
    if path.is_dir() {
        load_dir_into(conf, seen, stack, path, plugin_profile)
    } else {
        load_file_into(conf, seen, stack, path, plugin_profile)
    }
}

fn load_file_into(
    conf: &mut Krb5Conf,
    seen: &mut BTreeSet<String>,
    stack: &mut Vec<PathBuf>,
    path: &Path,
    plugin_profile: &mut super::plugin_profile::PluginProfile,
) -> Result<(), Error> {
    let include = |what: String| Error::Profile(ProfileError::IncludeFile, what);
    let unread = |e: std::io::Error| {
        if stack.is_empty() {
            Error::Io(e)
        } else if e.kind() == std::io::ErrorKind::NotFound {
            include(format!("include target not found: {}", path.display()))
        } else {
            include(format!("include target {}: {e}", path.display()))
        }
    };
    if stack.len() >= MAX_INCLUDE_DEPTH {
        return Err(include("include nesting too deep".into()));
    }
    let canon = std::fs::canonicalize(path).map_err(unread)?;
    if stack.iter().any(|p| p == &canon) {
        return Err(include("include cycle".into()));
    }
    let bytes = super::files::read(&canon).map_err(unread)?;
    let text = String::from_utf8_lossy(&bytes);
    stack.push(canon);
    let result = parse_into(conf, seen, &text, Some(stack), plugin_profile);
    stack.pop();
    result
}

fn load_dir_into(
    conf: &mut Krb5Conf,
    seen: &mut BTreeSet<String>,
    stack: &mut Vec<PathBuf>,
    dir: &Path,
    plugin_profile: &mut super::plugin_profile::PluginProfile,
) -> Result<(), Error> {
    let unlisted = |what: String| Error::Profile(ProfileError::IncludeDir, what);
    if !dir.is_dir() {
        return Err(unlisted(format!(
            "includedir not a directory: {}",
            dir.display()
        )));
    }
    let list = |e: std::io::Error| unlisted(format!("includedir {}: {e}", dir.display()));
    let mut names = Vec::new();
    for name in super::files::dir_names(dir).map_err(list)? {
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
            load_file_into(conf, seen, stack, &p, plugin_profile)?;
        }
    }
    Ok(())
}

fn subsection_name(line: &str) -> Option<String> {
    let name = line.split_once('=')?.0.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_owned())
    }
}

fn realm_key(top: bool, realm: Option<&str>, k: &str, name: &str) -> bool {
    k == name && (top || realm.is_some())
}

fn seen_key(realm: Option<&str>, name: &str) -> String {
    match realm {
        Some(r) => format!("{r}\0{name}"),
        None => name.to_owned(),
    }
}

fn realm_node<'a>(conf: &'a mut Krb5Conf, realm: &str) -> &'a mut RealmLibdefaults {
    conf.realm_libdefaults.entry(realm.to_owned()).or_default()
}

fn opens_subsection(line: &str) -> bool {
    line.split_once('=')
        .is_some_and(|(_, v)| v.trim_matches(c_isspace) == "{")
}

pub(crate) const fn c_isspace(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r')
}

fn relation_name(tag: &str) -> &str {
    tag.split_once('*').map_or(tag, |(name, _)| name)
}

// MIT: `profile_get_string` (prof_get.c:265-270)
fn parse_libdefaults(
    conf: &mut Krb5Conf,
    seen: &mut BTreeSet<String>,
    line: &str,
    top: bool,
    realm: Option<&str>,
) {
    let Some((tag, v)) = split_kv(line) else {
        return;
    };
    let k = relation_name(tag);
    if k.starts_with("pkinit_") {
        match (top, realm) {
            (true, _) => conf.libdefaults_pkinit.push((k.to_owned(), v.clone())),
            (false, Some(r)) => conf
                .realm_libdefaults_pkinit
                .entry(r.to_owned())
                .or_default()
                .push((k.to_owned(), v.clone())),
            (false, None) => {}
        }
    }
    let key = k.to_ascii_lowercase();
    let exact = top && k == key;
    match key.as_str() {
        "default_realm" if top && k == "default_realm" && take_first(seen, "default_realm") => {
            conf.default_realm = Some(v);
        }
        "allow_weak_crypto" if exact && take_first(seen, "allow_weak_crypto") => {
            conf.allow_weak_crypto = context_boolean(conf, &v);
        }
        "allow_rc4" if exact && take_first(seen, "allow_rc4") => {
            conf.allow_rc4 = Some(context_boolean(conf, &v));
        }
        "allow_des3" if exact && take_first(seen, "allow_des3") => {
            conf.allow_des3 = Some(context_boolean(conf, &v));
        }
        "enforce_ok_as_delegate" if exact && take_first(seen, "enforce_ok_as_delegate") => {
            context_boolean(conf, &v);
        }
        "request_timeout" if exact && take_first(seen, "request_timeout") => {
            match krb5_types::deltat::parse(&v) {
                Err(_) => refuse(conf, ProfileError::BadDeltat),
                Ok(secs) if secs > 0 => {
                    conf.request_timeout =
                        u64::try_from(secs).ok().map(std::time::Duration::from_secs);
                }
                Ok(secs) if secs < 0 => conf.request_timeout = Some(std::time::Duration::ZERO),
                Ok(_) => {}
            }
        }
        "plugin_base_dir" if exact && take_first(seen, "plugin_base_dir") => {
            if !path_tokens_expand(&v) {
                refuse(conf, ProfileError::BadPathToken);
            }
        }
        "clockskew" if top && k == "clockskew" && take_first(seen, "clockskew") => {
            conf.clockskew = parse_profile_int(&v).unwrap_or(300);
        }
        "dns_lookup_kdc" if top && k == "dns_lookup_kdc" && take_first(seen, "dns_lookup_kdc") => {
            conf.dns_lookup_kdc = truthy(&v);
        }
        // MIT: `maybe_use_dns` (lib/krb5/os/locate_kdc.c:52-72)
        "dns_fallback" if top && k == "dns_fallback" && take_first(seen, "dns_fallback") => {
            if !seen.contains("dns_lookup_kdc") {
                conf.dns_lookup_kdc = truthy(&v);
            }
        }
        "dns_lookup_realm"
            if top && k == "dns_lookup_realm" && take_first(seen, "dns_lookup_realm") =>
        {
            conf.dns_lookup_realm = truthy(&v);
        }
        // MIT: `generate_authenticator` (lib/krb5/krb/mk_req_ext.c:301-308)
        "client_aware_channel_bindings"
            if top
                && k == "client_aware_channel_bindings"
                && take_first(seen, "client_aware_channel_bindings") =>
        {
            if let Some(b) = mit_boolean(&v) {
                conf.client_aware_channel_bindings = b;
            } else {
                // MIT: `profile_parse_boolean` (util/profile/prof_get.c:347-369)
                conf.client_aware_channel_bindings_invalid = true;
            }
        }
        "udp_preference_limit"
            if top && k == "udp_preference_limit" && take_first(seen, "udp_preference_limit") =>
        {
            conf.udp_preference_limit = v.parse().ok();
        }
        "rdns" if top && k == "rdns" && take_first(seen, "rdns") => conf.rdns = truthy(&v),
        "kdc_timesync" if top && k == "kdc_timesync" && take_first(seen, "kdc_timesync") => {
            if let Some(n) = parse_profile_int(&v) {
                conf.kdc_timesync = n != 0;
            }
        }
        // MIT: `krb5_init_context_profile` (lib/krb5/krb/init_ctx.c:265-267)
        "kdc_default_options" if exact && take_first(seen, "kdc_default_options") => {
            conf.kdc_default_options = parse_profile_int(&v).unwrap_or(0x10);
        }
        "verify_ap_req_nofail"
            if realm_key(top, realm, k, "verify_ap_req_nofail")
                && take_first(seen, &seen_key(realm, "verify_ap_req_nofail")) =>
        {
            let on = truthy(&v);
            if let Some(r) = realm {
                realm_node(conf, r).verify_ap_req_nofail = Some(on);
            } else {
                conf.verify_ap_req_nofail = on;
            }
        }
        "permitted_enctypes"
            if top && k == "permitted_enctypes" && take_first(seen, "permitted_enctypes") =>
        {
            conf.permitted_enctypes = Some(split_ws(&v));
        }
        "default_tkt_enctypes"
            if top && k == "default_tkt_enctypes" && take_first(seen, "default_tkt_enctypes") =>
        {
            conf.default_tkt_enctypes = split_ws(&v);
        }
        "default_tgs_enctypes"
            if top && k == "default_tgs_enctypes" && take_first(seen, "default_tgs_enctypes") =>
        {
            conf.default_tgs_enctypes = split_ws(&v);
        }
        "forwardable"
            if realm_key(top, realm, k, "forwardable")
                && take_first(seen, &seen_key(realm, "forwardable")) =>
        {
            let on = truthy(&v);
            if let Some(r) = realm {
                realm_node(conf, r).forwardable = Some(on);
            } else {
                conf.forwardable = on;
            }
        }
        "proxiable"
            if realm_key(top, realm, k, "proxiable")
                && take_first(seen, &seen_key(realm, "proxiable")) =>
        {
            let on = truthy(&v);
            if let Some(r) = realm {
                realm_node(conf, r).proxiable = Some(on);
            } else {
                conf.proxiable = on;
            }
        }
        "canonicalize"
            if realm_key(top, realm, k, "canonicalize")
                && take_first(seen, &seen_key(realm, "canonicalize")) =>
        {
            let on = truthy(&v);
            if let Some(r) = realm {
                realm_node(conf, r).canonicalize = Some(on);
            } else {
                conf.canonicalize = on;
            }
        }
        "ticket_lifetime"
            if realm_key(top, realm, k, "ticket_lifetime")
                && take_first(seen, &seen_key(realm, "ticket_lifetime")) =>
        {
            let life = parse_duration_secs(&v);
            if let Some(r) = realm {
                realm_node(conf, r).ticket_lifetime = life;
            } else {
                conf.ticket_lifetime = life;
            }
        }
        "renew_lifetime"
            if realm_key(top, realm, k, "renew_lifetime")
                && take_first(seen, &seen_key(realm, "renew_lifetime")) =>
        {
            let life = parse_duration_secs(&v);
            if let Some(r) = realm {
                realm_node(conf, r).renew_lifetime = life;
            } else {
                conf.renew_lifetime = life;
            }
        }
        "noaddresses"
            if realm_key(top, realm, k, "noaddresses")
                && take_first(seen, &seen_key(realm, "noaddresses")) =>
        {
            let on = truthy(&v);
            if let Some(r) = realm {
                realm_node(conf, r).noaddresses = Some(on);
            } else {
                conf.noaddresses = Some(on);
            }
        }
        "kdc_timeout" if top && k == "kdc_timeout" && take_first(seen, "kdc_timeout") => {
            conf.kdc_timeout = Some(v);
        }
        "max_retries" if top && k == "max_retries" && take_first(seen, "max_retries") => {
            conf.max_retries = Some(v);
        }
        "kcm_socket" if top && k == "kcm_socket" && take_first(seen, "kcm_socket") => {
            conf.kcm_socket = Some(v);
        }
        "default_ccache_name"
            if top && k == "default_ccache_name" && take_first(seen, "default_ccache_name") =>
        {
            conf.default_ccache_name = Some(v);
        }
        "default_keytab_name"
            if top && k == "default_keytab_name" && take_first(seen, "default_keytab_name") =>
        {
            conf.default_keytab_name = Some(v);
        }
        "default_client_keytab_name"
            if top
                && k == "default_client_keytab_name"
                && take_first(seen, "default_client_keytab_name") =>
        {
            conf.default_client_keytab_name = Some(v);
        }
        "spake_preauth_groups"
            if top && k == "spake_preauth_groups" && take_first(seen, "spake_preauth_groups") =>
        {
            conf.spake_preauth_groups = Some(split_ws(&v));
        }
        "preferred_preauth_types"
            if realm_key(top, realm, k, "preferred_preauth_types")
                && take_first(seen, &seen_key(realm, "preferred_preauth_types")) =>
        {
            let list = parse_i32_list(&v);
            if let Some(r) = realm {
                realm_node(conf, r).preferred_preauth_types = Some(list);
            } else {
                conf.preferred_preauth_types = list;
            }
        }
        "ignore_acceptor_hostname" if exact && take_first(seen, "ignore_acceptor_hostname") => {
            conf.ignore_acceptor_hostname = context_boolean(conf, &v);
        }
        "qualify_shortname" if exact && take_first(seen, "qualify_shortname") => {
            conf.qualify_shortname = Some(v);
        }
        "realm_try_domains" if exact && take_first(seen, "realm_try_domains") => {
            conf.realm_try_domains = Some(v);
        }
        "dns_canonicalize_hostname" if exact && take_first(seen, "dns_canonicalize_hostname") => {
            match canon_host(&v) {
                Some(mode) => conf.dns_canonicalize_hostname = mode,
                None => refuse(conf, ProfileError::BadTristate),
            }
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
    if k.starts_with("pkinit_") {
        conf.pkinit
            .entry(realm.to_owned())
            .or_default()
            .push((k.to_owned(), v.clone()));
    }
    match k.to_ascii_lowercase().as_str() {
        "kdc" => match located_host(&v, crate::listen::KDC_PORT) {
            Ok(ep) => conf.kdcs.entry(realm.to_owned()).or_default().push(ep),
            Err(()) => {
                conf.kdc_host_invalid.insert(realm.to_owned());
            }
        },
        "admin_server" => {
            match located_host(&v, crate::listen::KADMIND_PORT) {
                Ok(ep) => conf
                    .admin_servers
                    .entry(realm.to_owned())
                    .or_default()
                    .push(ep),
                Err(()) => {
                    conf.admin_host_invalid.insert(realm.to_owned());
                }
            }
            conf.kadm5
                .entry(realm.to_owned())
                .or_default()
                .push(("admin_server".to_owned(), v));
        }
        "kpasswd_server" => match located_host(&v, crate::listen::KPASSWD_PORT) {
            Ok(ep) => conf
                .kpasswd_servers
                .entry(realm.to_owned())
                .or_default()
                .push(ep),
            Err(()) => {
                conf.kpasswd_host_invalid.insert(realm.to_owned());
            }
        },
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
        "disable_encrypted_timestamp" => {
            conf.disable_encrypted_timestamp
                .entry(realm.to_owned())
                .or_insert_with(|| mit_boolean(&v).unwrap_or(false));
        }
        name if name.starts_with("iprop_")
            || matches!(
                name,
                "kadmind_listen" | "kadmind_port" | "kpasswd_listen" | "kpasswd_port"
            ) =>
        {
            conf.kadm5
                .entry(realm.to_owned())
                .or_default()
                .push((name.to_owned(), v));
        }
        _ => {}
    }
}

pub(super) fn split_kv(line: &str) -> Option<(&str, String)> {
    let line = line.trim();
    let (k, v) = line.split_once('=')?;
    Some((k.trim(), relation_value(v)))
}

pub(crate) fn relation_value(v: &str) -> String {
    let v = v.trim_start();
    v.strip_prefix('"')
        .map_or_else(|| v.trim_end().to_owned(), parse_quoted_string)
}

// MIT: `parse_quoted_string` (prof_parse.c:47-72)
fn parse_quoted_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => break,
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('b') => out.push('\u{8}'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            },
            other => out.push(other),
        }
    }
    out
}

pub(super) fn mit_boolean(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "y" | "yes" | "true" | "t" | "1" | "on" => Some(true),
        "n" | "no" | "false" | "nil" | "0" | "off" => Some(false),
        _ => None,
    }
}

pub(super) fn aprof_boolean(v: &str) -> Option<bool> {
    if v.eq_ignore_ascii_case("f") {
        Some(false)
    } else {
        mit_boolean(v)
    }
}

pub(crate) fn parse_profile_int(v: &str) -> Option<i32> {
    let v = v.trim_start_matches(|c: char| c.is_ascii_whitespace());
    if v.is_empty() {
        return None;
    }
    let (sign, rest) = if let Some(r) = v.strip_prefix('+') {
        (1i64, r)
    } else if let Some(r) = v.strip_prefix('-') {
        (-1i64, r)
    } else {
        (1, v)
    };
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mag = rest.parse::<i64>().ok()?;
    i32::try_from(sign.checked_mul(mag)?).ok()
}

pub(super) fn truthy(v: &str) -> bool {
    mit_boolean(v).unwrap_or(false)
}

fn context_boolean(conf: &mut Krb5Conf, v: &str) -> bool {
    mit_boolean(v).unwrap_or_else(|| {
        refuse(conf, ProfileError::BadBoolean);
        false
    })
}

fn refuse(conf: &mut Krb5Conf, why: ProfileError) {
    if conf
        .context_refusal
        .is_none_or(|first| first.context_rank() > why.context_rank())
    {
        conf.context_refusal = Some(why);
    }
}

// MIT: `expand_token` (lib/krb5/os/expand_path.c:403-422)
// An empty token, or one no table name starts with, is `EINVAL`.
// MIT: `k5_expand_path_tokens_extra` (lib/krb5/os/expand_path.c:500-506)
fn path_tokens_expand(path: &str) -> bool {
    const TOKENS: [&str; 9] = [
        "LIBDIR", "BINDIR", "SBINDIR", "euid", "username", "TEMP", "USERID", "uid", "null",
    ];
    let mut rest = path;
    while let Some(start) = rest.find("%{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            return false;
        };
        let token = &after[..end];
        if token.is_empty() || !TOKENS.iter().any(|t| t.starts_with(token)) {
            return false;
        }
        rest = &after[end + 1..];
    }
    true
}

fn canon_host(v: &str) -> Option<super::CanonHost> {
    match mit_boolean(v) {
        Some(true) => Some(super::CanonHost::True),
        Some(false) => Some(super::CanonHost::False),
        None if v.eq_ignore_ascii_case("fallback") => Some(super::CanonHost::Fallback),
        None => None,
    }
}

fn located_host(v: &str, default_port: u16) -> Result<Endpoint, ()> {
    let addr = crate::listen::parse_host_string(v, default_port).map_err(|_| ())?;
    let Some(host) = addr.host.filter(|h| !h.is_empty()) else {
        return Err(());
    };
    Ok(Endpoint {
        host,
        port: addr.port,
        transport: super::KdcTransport::Either,
    })
}

fn kpasswd_from_admin(list: &[Endpoint]) -> Vec<Endpoint> {
    list.iter()
        .map(|e| Endpoint {
            host: e.host.clone(),
            port: 464,
            transport: if e.transport == KdcTransport::Tcp {
                KdcTransport::Either
            } else {
                e.transport
            },
        })
        .collect()
}

#[must_use]
pub fn parse_deltat(v: &str) -> Option<u64> {
    parse_duration_secs(v)
}

pub(super) fn parse_duration_secs(v: &str) -> Option<u64> {
    krb5_types::deltat::parse(v)
        .ok()
        .and_then(|n| u64::try_from(n).ok())
}

#[must_use]
pub fn split_krb5_config_paths(value: &str) -> Vec<PathBuf> {
    value
        .split(':')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

#[must_use]
pub fn env_ktname() -> Option<PathBuf> {
    std::env::var_os("KRB5_KTNAME").map(|v| {
        let s = v.to_string_lossy();
        PathBuf::from(s.strip_prefix("FILE:").unwrap_or(s.as_ref()))
    })
}

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

pub fn load_krb5_conf_paths<P: AsRef<Path>>(
    paths: impl IntoIterator<Item = P>,
) -> Result<Krb5Conf, Error> {
    let mut conf = Krb5Conf::new();
    let mut seen = BTreeSet::new();
    let mut stack = Vec::new();
    let mut plugin_profile = super::plugin_profile::PluginProfile::default();
    let mut any = false;
    let mut access = None;
    for path in paths {
        let path = path.as_ref();
        match load_path_into(&mut conf, &mut seen, &mut stack, path, &mut plugin_profile) {
            Ok(()) => any = true,
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                access = Some(e);
            }
            Err(e) => return Err(e),
        }
    }
    if any {
        conf.plugins = plugin_profile;
        conf.apply_dns_lookup_default(&seen);
        if let Some(p) = conf.context_refusal {
            return Err(Error::Profile(p, p.text().to_owned()));
        }
        Ok(conf)
    } else {
        Err(access
            .unwrap_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
            .into())
    }
}

pub fn init_profile() -> Result<Krb5Conf, Error> {
    match load_krb5_conf_paths(krb5_conf_paths()) {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut conf = Krb5Conf::new();
            conf.apply_dns_lookup_default(&BTreeSet::new());
            Ok(conf)
        }
        loaded => loaded,
    }
}

pub fn init_kdc_profile() -> Result<(), Error> {
    let mut paths = vec![crate::kdc_conf_path()];
    paths.extend(krb5_conf_paths());
    match load_krb5_conf_paths(paths) {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        loaded => loaded.map(drop),
    }
}

// MIT: `locate_server` (lib/krb5/os/locate_kdc.c:823-836)
// DNS only when the `kdc` list is empty; a `..` SRV target stays.
pub fn discover_kdc_in<P: AsRef<Path>>(
    paths: impl IntoIterator<Item = P>,
    realm: &str,
) -> Result<Vec<Endpoint>, Error> {
    let Ok(conf) = load_krb5_conf_paths(paths) else {
        return Ok(Vec::new());
    };
    match conf.kdcs_for_traced(realm, &mut |_| {}) {
        Err(Error::InvalidArgument) => Err(Error::InvalidArgument),
        Err(_) => Ok(Vec::new()),
        Ok(list) => Ok(list),
    }
}

#[must_use]
pub fn load_krb5_conf() -> Option<Krb5Conf> {
    load_krb5_conf_paths(krb5_conf_paths()).ok()
}

#[must_use]
pub fn env_password() -> Option<Vec<u8>> {
    #[cfg(feature = "test-hooks")]
    {
        std::env::var("KRB5_PASSWORD").ok().map(String::into_bytes)
    }
    #[cfg(not(feature = "test-hooks"))]
    {
        None
    }
}

#[must_use]
pub fn env_new_password() -> Option<Vec<u8>> {
    #[cfg(feature = "test-hooks")]
    {
        std::env::var("KRB5_NEW_PASSWORD")
            .ok()
            .map(String::into_bytes)
    }
    #[cfg(not(feature = "test-hooks"))]
    {
        None
    }
}
