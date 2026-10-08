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
use super::{Endpoint, Error, Krb5Conf, ProfileError, RealmLibdefaults};

impl Krb5Conf {
    /// Whether encrypted timestamp is off for `realm`.
    /// MIT `encts_disabled` (`lib/krb5/krb/get_in_tkt.c:757-772`): the profile boolean, default false.
    #[must_use]
    pub fn encrypted_timestamp_disabled(&self, realm: &str) -> bool {
        self.disable_encrypted_timestamp
            .get(realm)
            .copied()
            .unwrap_or(false)
    }

    /// `forwardable` for `realm`: the realm subsection, then the top level.
    /// MIT `krb5_init_creds_init` (`lib/krb5/krb/get_in_tkt.c:902-908`): the caller flag, else the profile boolean, else false.
    #[must_use]
    pub fn forwardable_for(&self, realm: &str) -> bool {
        self.realm_bool(realm, |node| node.forwardable)
            .unwrap_or(self.forwardable)
    }

    /// `proxiable` for `realm`: the realm subsection, then the top level.
    /// MIT `krb5_init_creds_init` (`lib/krb5/krb/get_in_tkt.c:913-918`): the caller flag, else the profile boolean, else false.
    #[must_use]
    pub fn proxiable_for(&self, realm: &str) -> bool {
        self.realm_bool(realm, |node| node.proxiable)
            .unwrap_or(self.proxiable)
    }

    /// `canonicalize` for `realm`: the realm subsection, then the top level.
    /// MIT `krb5_init_creds_init` (`lib/krb5/krb/get_in_tkt.c:924-929`): the caller flag, else the profile boolean, else false.
    #[must_use]
    pub fn canonicalize_for(&self, realm: &str) -> bool {
        self.realm_bool(realm, |node| node.canonicalize)
            .unwrap_or(self.canonicalize)
    }

    /// `ticket_lifetime` seconds for `realm`: the realm subsection, then the top level.
    /// MIT `krb5_init_creds_init` (`lib/krb5/krb/get_in_tkt.c:939-947`): the caller lifetime, else the profile duration, else 24 hours.
    #[must_use]
    pub fn ticket_lifetime_for(&self, realm: &str) -> Option<u64> {
        self.realm_libdefaults
            .get(realm)
            .and_then(|node| node.ticket_lifetime)
            .or(self.ticket_lifetime)
    }

    /// `renew_lifetime` seconds for `realm`: the realm subsection, then the top level.
    /// MIT `krb5_init_creds_init` (`lib/krb5/krb/get_in_tkt.c:952-960`): the caller lifetime, else the profile duration, else 0.
    #[must_use]
    pub fn renew_lifetime_for(&self, realm: &str) -> Option<u64> {
        self.realm_libdefaults
            .get(realm)
            .and_then(|node| node.renew_lifetime)
            .or(self.renew_lifetime)
    }

    /// `noaddresses` for `realm`: the realm subsection, then the top level. `None` is absent.
    /// MIT `krb5_init_creds_init` (`lib/krb5/krb/get_in_tkt.c:991-1005`): absent or true sends no addresses, and false sends the local addresses.
    #[must_use]
    pub fn noaddresses_for(&self, realm: &str) -> Option<bool> {
        self.realm_bool(realm, |node| node.noaddresses)
            .or(self.noaddresses)
    }

    /// `verify_ap_req_nofail` for `realm`: the realm subsection, then the top level.
    /// MIT `nofail` (`lib/krb5/krb/vfy_increds.c:39-51`): the client credential's realm, default false.
    #[must_use]
    pub fn verify_ap_req_nofail_for(&self, realm: &str) -> bool {
        self.realm_bool(realm, |node| node.verify_ap_req_nofail)
            .unwrap_or(self.verify_ap_req_nofail)
    }

    /// `preferred_preauth_types` for `realm`. `None` means unset, so the caller uses MIT's default.
    /// MIT `sort_krb5_padata_sequence` (`lib/krb5/krb/get_in_tkt.c:418-424`): the realm string, else "17, 16, 15, 14".
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
    /// [`Error::Profile`] with [`ProfileError::Syntax`] when an indented `include` /
    /// `includedir` directive (no `=`) sits inside a section, or a relation with no value is not
    /// followed by a line that starts with `{` (MIT's improper format); no other line fails.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut conf = Self::new();
        let mut seen = BTreeSet::new();
        let mut plugin_profile = super::plugin_profile::PluginProfile::default();
        parse_into(&mut conf, &mut seen, text, None, &mut plugin_profile)?;
        conf.plugins = plugin_profile;
        Ok(conf)
    }

    /// Load a file or directory, honoring `include` / `includedir`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when `path` cannot be read; [`Error::Profile`] when an `include` target is
    /// missing or cannot be read, an `includedir` is not a directory or cannot be listed, includes
    /// form a cycle or nest 32 deep, an indented include sits inside a section, or a relation
    /// with no value is not followed by a line that starts with `{`.
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
    /// [`Error::Dns`] when `realm` has no static KDC list, `dns_lookup_kdc` is on, and the SRV
    /// lookup (`_kerberos._udp` then `_kerberos._tcp`) fails or finds no records.
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

/// The text's lines as MIT's profile parser meets them off Apple, where
/// `PROFILE_SUPPORTS_FOREIGN_NEWLINES` is not defined: each `\n`-ended line, its trailing `\r` and
/// `\n` characters dropped, so a CRLF file reads as an LF one. A line is not cut at MIT's
/// 2047-byte `fgets` buffer.
/// MIT `parse_file` (`prof_parse.c:351-359`): each `fgets` line goes to `parse_line` whole.
/// MIT `strip_line` (`prof_parse.c:40-45`): a line's trailing `\n` and `\r` characters go.
fn profile_lines(text: &str) -> impl Iterator<Item = &str> {
    text.split_terminator('\n')
        .map(|line| line.trim_end_matches(['\r', '\n']))
}

/// `text` with each relation that has no value joined to the `{` that must start the next line,
/// as `tag = {`, so that the section parsers meet one form. Before the first section such a line
/// is not a relation; a column-0 `include` or `includedir` between the two is left where it is.
/// MIT `parse_std_line` (`prof_parse.c:174-176`): a relation with no value opens a subsection,
/// its `{` due on the next line.
/// MIT `parse_line` (`prof_parse.c:331-335`): that line must start with `{`, its rest unread,
/// else `PROF_MISSING_OBRACE`.
///
/// # Errors
///
/// [`Error::Profile`] with [`ProfileError::Syntax`] when the line after a relation with no value
/// does not start with `{`.
pub(crate) fn join_subsection_braces(text: &str) -> Result<String, Error> {
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
    // MIT `valid_name`: suffix is the lowercase bytes ".conf", not a case-fold.
    if name.len() >= 5 && name.as_bytes().ends_with(b".conf") {
        return true;
    }
    name.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// MIT `k5_is_numeric_address` (`hostrealm.c:318-338`): a name of only digits and three dots
/// (IPv4), or with a colon (IPv6), is a numeric address.
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

/// MIT `profile_parse_file` (`prof_parse.c:431-434`): a parse error is not a successful profile.
/// An indented include inside a section is a format error, and one before any section is ignored.
fn parse_into(
    conf: &mut Krb5Conf,
    seen: &mut BTreeSet<String>,
    text: &str,
    mut stack: Option<&mut Vec<PathBuf>>,
    plugin_profile: &mut super::plugin_profile::PluginProfile,
) -> Result<(), Error> {
    let mut section = String::new();
    // Whether the section header is `[libdefaults]` exactly, and how deep in a subsection of it
    // a line is: the relations `krb5_init_context` reads are only those at its top, by name.
    let mut libdefaults_exact = false;
    let mut libdefaults_depth = 0usize;
    let mut libdefaults_realm: Option<String> = None;
    let mut realm: Option<String> = None;
    let mut capaths_client: Option<String> = None;
    let text = join_subsection_braces(text)?;
    let mut plugins = super::plugin_profile::Cursor::new();
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
        // MIT: column-0 include is a directive; indented include inside a
        // section is Improper format (a relation with no '='). At file start
        // (no section) MIT ignores it.
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
        if let Some(s) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = s.trim().to_ascii_lowercase();
            libdefaults_exact = s == "libdefaults";
            libdefaults_depth = 0;
            libdefaults_realm = None;
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
            realm = None;
            capaths_client = None;
            plugins.observe_header(plugin_profile, "plugins", true);
            continue;
        }
        plugins.observe_line(plugin_profile, line);
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
    // MIT `parse_include_file` (`prof_parse.c:229-231`): an included file that does not open
    // fails the whole profile.
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
    // MIT `parse_file` reads the file's bytes: a profile need not be UTF-8.
    let bytes = std::fs::read(&canon).map_err(unread)?;
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
    // MIT `parse_include_dir` (`prof_parse.c:271-272`): an includedir that does not list fails
    // the whole profile.
    let unlisted = |what: String| Error::Profile(ProfileError::IncludeDir, what);
    if !dir.is_dir() {
        return Err(unlisted(format!(
            "includedir not a directory: {}",
            dir.display()
        )));
    }
    let list = |e: std::io::Error| unlisted(format!("includedir {}: {e}", dir.display()));
    let mut names = Vec::new();
    for ent in std::fs::read_dir(dir).map_err(list)? {
        let ent = ent.map_err(list)?;
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

/// A per-realm key is accepted at the top of `[libdefaults]` or in that realm's node.
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

/// Whether a relation line opens a subsection: its value is a `{` alone, unquoted (a relation with
/// no value has been joined to the `{` of the next line by [`join_subsection_braces`]).
/// MIT `parse_std_line` (`util/profile/prof_parse.c:75-212`): a value that starts with a quote is a string, and a `{` opens a subsection only when nothing but blanks follows it.
fn opens_subsection(line: &str) -> bool {
    line.split_once('=')
        .is_some_and(|(_, v)| v.trim_matches(c_isspace) == "{")
}

/// C `isspace` in the C locale: space, tab, newline, vertical tab, form feed, carriage return.
pub(crate) const fn c_isspace(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r')
}

/// A relation's name as MIT's profile stores it: the tag up to its first `*`, which marks the
/// relation final.
/// MIT `parse_std_line` (`util/profile/prof_parse.c:75-212`): a `*` in the tag ends the name, the relation being final.
fn relation_name(tag: &str) -> &str {
    tag.split_once('*').map_or(tag, |(name, _)| name)
}

/// MIT `profile_get_string` (`prof_get.c:265-270`): a missing relation keeps the default, and
/// a found value is what is returned.
/// The first exact spelling of a key wins, and a line with no equals sign is not a setting.
/// `realm` is the depth-1 subsection; only the eight per-realm keys are stored on it.
/// MIT `profile_node_iterator` (`util/profile/prof_tree.c:586-616`): a lookup matches the section and the relation by `strcmp`.
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
            // MIT `krb5_init_context_profile` (`lib/krb5/krb/init_ctx.c:254-263`): a `request_timeout` `krb5_string_to_deltat` refuses fails the context.
            if krb5_types::deltat::parse(&v).is_err() {
                refuse(conf, ProfileError::BadDeltat);
            }
        }
        "plugin_base_dir" if exact && take_first(seen, "plugin_base_dir") => {
            // MIT `krb5_init_context_profile` (`lib/krb5/krb/init_ctx.c:272-281`): a `plugin_base_dir` whose tokens do not expand fails the context.
            if !path_tokens_expand(&v) {
                refuse(conf, ProfileError::BadPathToken);
            }
        }
        "clockskew" if top && k == "clockskew" && take_first(seen, "clockskew") => {
            conf.clockskew = parse_duration_secs(&v)
                .and_then(|s| u32::try_from(s).ok())
                .unwrap_or(300);
        }
        "dns_lookup_kdc" if top && k == "dns_lookup_kdc" && take_first(seen, "dns_lookup_kdc") => {
            conf.dns_lookup_kdc = truthy(&v);
        }
        "dns_lookup_realm"
            if top && k == "dns_lookup_realm" && take_first(seen, "dns_lookup_realm") =>
        {
            conf.dns_lookup_realm = truthy(&v);
        }
        "udp_preference_limit"
            if top && k == "udp_preference_limit" && take_first(seen, "udp_preference_limit") =>
        {
            conf.udp_preference_limit = v.parse().ok();
        }
        "rdns" if top && k == "rdns" && take_first(seen, "rdns") => conf.rdns = truthy(&v),
        "kdc_timesync" if top && k == "kdc_timesync" && take_first(seen, "kdc_timesync") => {
            // MIT `parse_int` (`util/profile/prof_get.c:283-305`): `strtol` of the whole value.
            // MIT `krb5_init_context_profile` (`lib/krb5/krb/init_ctx.c:269-270`): a value that is not an integer leaves the default 1 and does not fail the context.
            if let Some(n) = parse_profile_int(&v) {
                conf.kdc_timesync = n != 0;
            }
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
            conf.permitted_enctypes = split_ws(&v);
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
        "disable_encrypted_timestamp" => {
            // MIT `encts_disabled` (`lib/krb5/krb/get_in_tkt.c:767-771`): the first boolean, and a value that is not a boolean is the default false.
            conf.disable_encrypted_timestamp
                .entry(realm.to_owned())
                .or_insert_with(|| mit_boolean(&v).unwrap_or(false));
        }
        name if name.starts_with("iprop_") => conf
            .iprop
            .entry(realm.to_owned())
            .or_default()
            .push((name.to_owned(), v)),
        _ => {}
    }
}

/// Split `name = value`. A trailing comma stays in the value.
/// MIT `parse_std_line` (`util/profile/prof_parse.c:169-183`): trailing whitespace is cut, and a comma is kept.
pub(super) fn split_kv(line: &str) -> Option<(&str, String)> {
    let line = line.trim();
    let (k, v) = line.split_once('=')?;
    Some((k.trim(), relation_value(v)))
}

/// A relation's value: one that opens with `"` is the quoted string, else the text with its
/// trailing blanks cut.
/// MIT `parse_std_line` (`prof_parse.c:169-183`): a value that starts with a quote goes through
/// `parse_quoted_string`; any other loses its trailing whitespace.
pub(crate) fn relation_value(v: &str) -> String {
    let v = v.trim_start();
    v.strip_prefix('"')
        .map_or_else(|| v.trim_end().to_owned(), parse_quoted_string)
}

/// MIT `parse_quoted_string` (`prof_parse.c:47-72`): up to the closing quote; `\n`, `\t` and `\b`
/// are those characters, a backslash before any other character is that character, and a
/// backslash that ends the value stays.
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

/// A profile boolean as MIT reads one; `None` for a value that is none.
/// MIT `profile_parse_boolean` (`util/profile/prof_get.c:354-368`): `y yes true t 1 on` and `n no false nil 0 off`, without case; anything else is `PROF_BAD_BOOLEAN`.
pub(super) fn mit_boolean(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "y" | "yes" | "true" | "t" | "1" | "on" => Some(true),
        "n" | "no" | "false" | "nil" | "0" | "off" => Some(false),
        _ => None,
    }
}

/// An integer as MIT's `parse_int`: `strtol` base 10 of the whole string, in C `int` range.
/// MIT `parse_int` (`util/profile/prof_get.c:283-305`): leading space is skipped, and any other trailing byte is `PROF_BAD_INTEGER`.
fn parse_profile_int(v: &str) -> Option<i32> {
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

/// A profile boolean, a value that is none being false.
pub(super) fn truthy(v: &str) -> bool {
    mit_boolean(v).unwrap_or(false)
}

/// A boolean `krb5_init_context` reads; a value that is none marks the profile refused.
/// MIT `krb5_init_context_profile` (`lib/krb5/krb/init_ctx.c:219-242`): a bad `allow_weak_crypto`, `allow_des3`, `allow_rc4`, `ignore_acceptor_hostname` or `enforce_ok_as_delegate` fails the context.
fn context_boolean(conf: &mut Krb5Conf, v: &str) -> bool {
    mit_boolean(v).unwrap_or_else(|| {
        refuse(conf, ProfileError::BadBoolean);
        false
    })
}

/// Mark the profile refused with `why`, unless a check `krb5_init_context` makes first already
/// refused it.
/// MIT `krb5_init_context_profile` (`lib/krb5/krb/init_ctx.c:219-281`): the booleans, then `dns_canonicalize_hostname`, then `request_timeout`, then `plugin_base_dir`; the first that fails is the context's error.
fn refuse(conf: &mut Krb5Conf, why: ProfileError) {
    if conf
        .context_refusal
        .is_none_or(|first| first.context_rank() > why.context_rank())
    {
        conf.context_refusal = Some(why);
    }
}

/// Whether MIT's `k5_expand_path_tokens` expands `path`: each `%{` needs its `}`, and the text
/// between must be one of MIT's token names or, as `strncmp` over its own length compares it,
/// the start of one.
/// MIT `expand_token` (`lib/krb5/os/expand_path.c:403-422`): an empty token, or one no table name starts with, is `EINVAL`.
/// MIT `k5_expand_path_tokens_extra` (`lib/krb5/os/expand_path.c:500-506`): a `%{` with no `}` is `EINVAL`.
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

/// A `dns_canonicalize_hostname` value: MIT's booleans, else `fallback` (case aside); `None` for
/// a value that is neither, which makes MIT's context fail (`EINVAL`).
/// MIT `get_tristate` (`lib/krb5/krb/init_ctx.c:107-120`): `profile_get_boolean`, else the third option's name compared without case.
fn canon_host(v: &str) -> Option<super::CanonHost> {
    match mit_boolean(v) {
        Some(true) => Some(super::CanonHost::True),
        Some(false) => Some(super::CanonHost::False),
        None if v.eq_ignore_ascii_case("fallback") => Some(super::CanonHost::Fallback),
        None => None,
    }
}

fn parse_endpoint(v: &str) -> Endpoint {
    if let Some((h, p)) = v.rsplit_once(':')
        && let Ok(port) = p.parse()
    {
        return Endpoint {
            host: h.to_owned(),
            port,
            transport: super::KdcTransport::Either,
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
/// MIT `profile_init_flags` (`prof_init.c:198-206`): a missing file (`ENOENT`) is skipped; one
/// that cannot be read (`EACCES` / `EPERM`) is remembered and skipped; any other failure ends the
/// load.
/// MIT `profile_init_flags` (`prof_init.c:217-224`): with no file loaded, the error is the
/// remembered access error, else `ENOENT`.
///
/// # Errors
///
/// [`Error::Io`] when no path loads: the access error (`PermissionDenied`) of one that could not
/// be read, else `ErrorKind::NotFound`; the `io::Error` of a present file or directory that
/// cannot be read for another reason; [`Error::Profile`] as [`Krb5Conf::load_file`] reports it
/// (an include target missing or unreadable, an `includedir` that is no directory or does not
/// list, an include cycle or 32-deep nesting, an indented include, a relation with no value not
/// followed by a line that starts with `{`).
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
        // MIT `krb5_init_context_profile` (`lib/krb5/krb/init_ctx.c:219-248`): a context boolean that is none, or a `dns_canonicalize_hostname` that is neither one nor `fallback`, fails the context.
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

/// MIT `krb5_init_context`'s profile: [`load_krb5_conf_paths`] of [`krb5_conf_paths`], an empty
/// profile when no file is found.
/// MIT `os_init_paths` (`init_os_ctx.c:388-391`): no file that opens is an empty profile.
///
/// # Errors
///
/// As [`load_krb5_conf_paths`], except that no file found is no error.
pub fn init_profile() -> Result<Krb5Conf, Error> {
    match load_krb5_conf_paths(krb5_conf_paths()) {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(Krb5Conf::new()),
        loaded => loaded,
    }
}

/// MIT `krb5int_init_context_kdc`'s profile: the KDC profile ([`crate::kdc_conf_path`]) ahead of
/// the krb5.conf files, loaded as [`init_profile`] loads them. A KDC-side tool checks it before
/// anything else and stops on its error, as MIT's do.
/// MIT `add_kdc_config_file` (`init_os_ctx.c:340-366`): the KDC profile goes first in the list.
///
/// # Errors
///
/// As [`load_krb5_conf_paths`], except that no file found is no error.
pub fn init_kdc_profile() -> Result<(), Error> {
    let mut paths = vec![crate::kdc_conf_path()];
    paths.extend(krb5_conf_paths());
    match load_krb5_conf_paths(paths) {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        loaded => loaded.map(drop),
    }
}

/// KDCs for `realm` from the given `krb5.conf` paths (merged).
/// MIT `locate_server` (`lib/krb5/os/locate_kdc.c:823-836`): the profile `[realms] kdc` list when
/// it has any entry, and DNS only when that list is empty. An unreadable profile or a failed
/// lookup is an empty list. A `..` SRV target stays in the list.
#[must_use]
pub fn discover_kdc_in<P: AsRef<Path>>(
    paths: impl IntoIterator<Item = P>,
    realm: &str,
) -> Vec<Endpoint> {
    let Ok(conf) = load_krb5_conf_paths(paths) else {
        return Vec::new();
    };
    conf.kdcs_for(realm).unwrap_or_default()
}

/// KDCs for `realm` from [`krb5_conf_paths`], as [`discover_kdc_in`].
#[must_use]
pub fn discover_kdc(realm: &str) -> Vec<Endpoint> {
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

/// The gates' password, `KRB5_PASSWORD`, in a `test-hooks` build. A release build reads no
/// password from the environment (MIT's tools take one from the terminal or stdin only), so this
/// is `None` there and the tools prompt.
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

/// The gates' new password for a `gic_pwd.c` KEY_EXP change, `KRB5_NEW_PASSWORD`, in a
/// `test-hooks` build; `None` in a release build, as [`env_password`].
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
