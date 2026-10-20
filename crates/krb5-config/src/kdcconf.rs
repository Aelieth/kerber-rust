//! kdc.conf (`kadm5/alt_prof.c` `GET_DELTAT_PARAM` / `dict_file` /
//! `KADM5_CONFIG_FLAGS`; `kdc/main.c` `kdc_ports` / `kdc_tcp_ports` /
//! `realm_maxrlife` / `reject_bad_transit`): realm stanza,
//! `[kdcdefaults]`, `[libdefaults]` enctype knobs; and where the KDC-side
//! tools find kdc.conf and the database (`os/init_os_ctx.c`
//! `add_kdc_config_file`, `kadm5/alt_prof.c` `kadm5_get_config_params`).

use std::ffi::OsString;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::listen::{self, ListenAddr};
use super::profile::{
    aprof_boolean, combine_ws, join_subsection_braces, parse_duration_secs, parse_profile_int,
    split_kv, split_ws, truthy,
};
use super::{Error, KdcConf};

/// The four KDC listener relations of one profile section, as written.
#[derive(Default)]
struct ListenRelations {
    listen: Option<String>,
    ports: Option<String>,
    tcp_listen: Option<String>,
    tcp_ports: Option<String>,
}

impl ListenRelations {
    /// Record `line` if it is one of the four; the first value wins, as
    /// `krb5_aprof_get_string` returns the first.
    fn take(&mut self, line: &str) -> bool {
        let Some((k, v)) = split_kv(line) else {
            return false;
        };
        let slot = match k {
            "kdc_listen" => &mut self.listen,
            "kdc_ports" => &mut self.ports,
            "kdc_tcp_listen" => &mut self.tcp_listen,
            "kdc_tcp_ports" => &mut self.tcp_ports,
            _ => return false,
        };
        if slot.is_none() {
            *slot = Some(v);
        }
        true
    }

    fn udp(&self) -> Option<&String> {
        self.listen.as_ref().or(self.ports.as_ref())
    }

    fn tcp(&self) -> Option<&String> {
        self.tcp_listen.as_ref().or(self.tcp_ports.as_ref())
    }
}

impl Default for KdcConf {
    fn default() -> Self {
        Self {
            kdc_listen: listen::DEFAULT_KDC_PORTLIST.into(),
            kdc_listen_in_realm: false,
            kdc_tcp_listen: None,
            realm: "KERBER.TEST".into(),
            max_life: 24 * 3600,
            max_renewable_life: 0,
            realm_max_renewable_life: 7 * 24 * 3600,
            database_name: None,
            acl_file: None,
            key_stash_file: None,
            allow_weak_crypto: None,
            allow_rc4: None,
            allow_des3: None,
            permitted_enctypes: None,
            clockskew: None,
            supported_enctypes: Vec::new(),
            requires_preauth: true,
            default_principal_flags: None,
            default_principal_expiration: None,
            master_key_type: None,
            db_library: None,
            disable_last_success: false,
            disable_lockout: false,
            domain_sid: None,
            reject_bad_transit: true,
            disable_pac: false,
            restrict_anon: false,
            host_based_services: String::new(),
            no_host_referral: String::new(),
            encrypted_challenge_indicator: None,
            spake_preauth_indicators: Vec::new(),
            spake_preauth_groups: None,
            spake_preauth_kdc_challenge: None,
            dict_file: None,
            logging: Vec::new(),
            kdc_max_dgram_reply_size: MAX_DGRAM_SIZE,
            kdc_tcp_listen_backlog: DEFAULT_TCP_LISTEN_BACKLOG,
            plugins: super::plugin_profile::PluginProfile::default(),
            otp: super::otp_profile::OtpTree::default(),
            unsupported: Vec::new(),
        }
    }
}

/// MIT `MAX_DGRAM_SIZE` (`include/osconf.hin:113-113`): the largest UDP reply by default.
pub const MAX_DGRAM_SIZE: i32 = 65_536;
/// MIT `DEFAULT_TCP_LISTEN_BACKLOG` (`include/osconf.hin:100-100`): MIT's TCP listen backlog is 5; the KDC's default here is 128 (`docs/mit-deviations.md`). The name is kept for the `kdc_tcp_listen_backlog` profile lookup.
pub const DEFAULT_TCP_LISTEN_BACKLOG: i32 = 128;

/// A profile value read as C's `sscanf("%d")` reads it: blanks, an optional sign, then at least
/// one digit; a value past `long` stops there and is cut to `int` as glibc stores it.
pub(crate) fn sscanf_int(v: &str) -> Option<i32> {
    let t = v.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let run = digits.bytes().take_while(u8::is_ascii_digit).count();
    if run == 0 {
        return None;
    }
    let n = digits.as_bytes()[..run].iter().fold(0i64, |n, d| {
        n.saturating_mul(10).saturating_add(i64::from(d - b'0'))
    });
    let n = if neg { n.saturating_neg() } else { n };
    let low = n.rem_euclid(1 << 32);
    i32::try_from(if low >= 1 << 31 { low - (1 << 32) } else { low }).ok()
}

impl KdcConf {
    /// Parse `kdc.conf` text with at most one realm stanza, read by MIT's one profile parser as
    /// krb5.conf is (`join_subsection_braces`).
    ///
    /// # Errors
    ///
    /// [`Error::Profile`] with [`crate::ProfileError::Syntax`] when a relation with no value is
    /// not followed by a line that starts with `{` (MIT's `PROF_MISSING_OBRACE`); every other
    /// malformed or unknown line is skipped. [`Error::Parse`] when `[realms]` holds stanzas for
    /// more than one realm: such a file is read for one realm, [`Self::parse_for_realm`].
    pub fn parse(text: &str) -> Result<Self, Error> {
        let text = join_subsection_braces(text)?;
        let names = stanza_names(&text);
        if names.len() > 1 {
            return Err(Error::Parse(format!(
                "kdc.conf has stanzas for the realms {}; read it for one realm",
                names.join(", ")
            )));
        }
        Ok(Self::parse_joined(&text))
    }

    /// The settings of `text` that apply to `realm`: every section but `[realms]`, and only
    /// `realm`'s own stanza there, so another realm's relations are never lent to this one.
    /// MIT `get_string_param` (`lib/kadm5/alt_prof.c:310-336`): a realm parameter is read from that realm's stanza, else it takes the default.
    ///
    /// # Errors
    ///
    /// [`Error::Profile`] as [`Self::parse`].
    pub fn parse_for_realm(text: &str, realm: &str) -> Result<Self, Error> {
        let text = join_subsection_braces(text)?;
        Ok(Self::parse_joined(&stanza_of(&text, Some(realm))))
    }

    /// The settings of `text` that belong to no realm, such as `[logging]` and `[libdefaults]`;
    /// every realm stanza is left out.
    ///
    /// # Errors
    ///
    /// [`Error::Profile`] as [`Self::parse`].
    pub fn parse_without_realms(text: &str) -> Result<Self, Error> {
        let text = join_subsection_braces(text)?;
        Ok(Self::parse_joined(&stanza_of(&text, None)))
    }

    /// [`Self::parse_without_realms`] of the file at `path`, its includes followed.
    ///
    /// # Errors
    ///
    /// As [`Self::load_file`].
    pub fn load_file_without_realms(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::parse_without_realms(&read_with_includes(path.as_ref())?)
    }

    /// [`Self::parse_for_realm`] of the file at `path`, its includes followed.
    ///
    /// # Errors
    ///
    /// As [`Self::load_file`].
    pub fn load_file_for_realm(path: impl AsRef<Path>, realm: &str) -> Result<Self, Error> {
        Self::parse_for_realm(&read_with_includes(path.as_ref())?, realm)
    }

    fn parse_joined(text: &str) -> Self {
        let mut conf = Self::default();
        let mut section = String::new();
        let mut in_realm = false;
        let mut libdefaults_depth = 0usize;
        let mut libdefaults_seen = Vec::new();
        let mut booleans = RealmBooleans::default();
        let mut realm_listen = ListenRelations::default();
        let mut default_listen = ListenRelations::default();
        let mut database_module: Option<String> = None;
        let mut max_dgram: Option<String> = None;
        let mut backlog: Option<String> = None;
        let mut dbmodule: Option<String> = None;
        let mut dbmodules: Vec<(String, String, String)> = Vec::new();
        let mut plugin_profile = super::plugin_profile::PluginProfile::default();
        let mut plugins = super::plugin_profile::Cursor::new();
        let mut otp_tree = super::otp_profile::OtpTree::default();
        let mut otp = super::otp_profile::Cursor::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((body, starred)) = super::otp_profile::section_header(line) {
                otp.observe_header(&mut otp_tree, body, starred);
            }
            if let Some(s) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                s.trim().clone_into(&mut section);
                in_realm = false;
                libdefaults_depth = 0;
                dbmodule = None;
                plugins.observe_header(&mut plugin_profile, s, false);
                continue;
            }
            if super::plugin_profile::starred_plugins_header(line) {
                section = "plugins".into();
                in_realm = false;
                dbmodule = None;
                plugins.observe_header(&mut plugin_profile, "plugins", true);
                continue;
            }
            plugins.observe_line(&mut plugin_profile, line);
            otp.observe_line(&mut otp_tree, line);
            if section == "dbmodules" {
                if let Some(head) = line.strip_suffix('{') {
                    dbmodule = Some(head.trim().trim_end_matches('=').trim().to_owned());
                } else if line == "}" {
                    dbmodule = None;
                } else if let (Some(module), Some((k, v))) = (&dbmodule, split_kv(line)) {
                    dbmodules.push((module.clone(), k.to_owned(), v));
                }
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
                    if database_module.is_none()
                        && let Some((k, v)) = split_kv(line)
                        && k == "database_module"
                    {
                        database_module = Some(v);
                    }
                    if !realm_listen.take(line) && !booleans.realm(line) {
                        parse_kdc_realm_line(&mut conf, line);
                    }
                }
            }
            if section == "kdcdefaults" && !default_listen.take(line) {
                match split_kv(line) {
                    Some(("kdc_max_dgram_reply_size", v)) => {
                        max_dgram = Some(v);
                    }
                    Some(("kdc_tcp_listen_backlog", v)) => {
                        backlog = Some(v);
                    }
                    _ if booleans.defaults(line) => {}
                    _ => parse_kdcdefaults(&mut conf, line),
                }
            }
            // MIT `get_integer` (`lib/krb5/krb/init_ctx.c:76-85`): a `[libdefaults]` relation is read at the section's top level; a subsection's is another name.
            if section == "libdefaults" {
                if line.ends_with('{') {
                    libdefaults_depth += 1;
                } else if line == "}" {
                    libdefaults_depth = libdefaults_depth.saturating_sub(1);
                } else if libdefaults_depth == 0 {
                    parse_kdc_libdefaults(&mut conf, &mut libdefaults_seen, line);
                }
            }
            if section == "logging"
                && let Some((k, v)) = split_kv(line)
            {
                conf.logging.push((k.to_owned(), v));
            }
        }
        booleans.apply(&mut conf);
        // MIT `initialize_realms` (`kdc/main.c:622-660`): the `[kdcdefaults]` lists, else `88`.
        // MIT `init_realm` (`kdc/main.c:257-282`): the realm stanza's lists win over those.
        if let Some(v) = realm_listen.udp().or(default_listen.udp()) {
            conf.kdc_listen.clone_from(v);
        }
        conf.kdc_listen_in_realm = realm_listen.udp().is_some();
        conf.kdc_tcp_listen = realm_listen.tcp().or(default_listen.tcp()).cloned();
        // MIT `get_conf_section` (`lib/kdb/kdb5.c:219-227`): the realm's `database_module`, else the realm name, names the module's section.
        let module = database_module.unwrap_or_else(|| conf.realm.clone());
        let flag = |name: &str| {
            dbmodules
                .iter()
                .find(|(m, k, _)| *m == module && k == name)
                .is_some_and(|(_, _, v)| truthy(v))
        };
        for (m, k, _) in &dbmodules {
            if *m == module && matches!(k.as_str(), "db_library" | "db_module_dir") {
                note_unsupported(&mut conf, k);
            }
        }
        conf.disable_last_success = flag("disable_last_success");
        conf.disable_lockout = flag("disable_lockout");
        // MIT `krb5_aprof_get_int32` (`lib/kadm5/alt_prof.c:284-298`): the last value, read with `sscanf("%d")`; one that does not read leaves the caller's default.
        conf.kdc_max_dgram_reply_size = max_dgram
            .as_deref()
            .and_then(sscanf_int)
            .unwrap_or(MAX_DGRAM_SIZE);
        conf.kdc_tcp_listen_backlog = backlog
            .as_deref()
            .and_then(sscanf_int)
            .unwrap_or(DEFAULT_TCP_LISTEN_BACKLOG);
        conf.plugins = plugin_profile;
        conf.otp = otp_tree;
        conf
    }

    /// Apply `krb5kdc -p`: it replaces the default listener list (`[kdcdefaults]`, else 88) but
    /// not a realm stanza's own, and TCP follows it when no TCP list is written.
    /// MIT `initialize_realms` (`kdc/main.c:766-773`): `-p` replaces the default list.
    /// MIT `init_realm` (`kdc/main.c:257-263`): the realm stanza's list wins over that default.
    pub fn apply_port_option(&mut self, ports: &str) {
        if !self.kdc_listen_in_realm {
            ports.clone_into(&mut self.kdc_listen);
        }
    }

    /// The KDC's UDP listeners.
    /// MIT `main` (`kdc/main.c:961-965`): UDP listens on the realm's `kdc_listen` list.
    ///
    /// # Errors
    ///
    /// [`Error::Parse`] for an entry [`listen::parse_host_string`] refuses.
    pub fn kdc_udp_listeners(&self) -> Result<Vec<ListenAddr>, Error> {
        listen::listen_addrs(Some(&self.kdc_listen), listen::KDC_PORT)
    }

    /// The KDC's TCP listeners: [`Self::kdc_tcp_listen`], else the UDP list.
    /// MIT `main` (`kdc/main.c:969-973`): TCP falls back to the UDP list.
    ///
    /// # Errors
    ///
    /// [`Error::Parse`] for an entry [`listen::parse_host_string`] refuses.
    pub fn kdc_tcp_listeners(&self) -> Result<Vec<ListenAddr>, Error> {
        let list = self.kdc_tcp_listen.as_deref().unwrap_or(&self.kdc_listen);
        listen::listen_addrs(Some(list), listen::KDC_PORT)
    }

    /// Load from a path.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when `path` cannot be read (its bytes need not be UTF-8, as MIT's need not
    /// be); [`Error::Profile`] as [`KdcConf::parse`], and when an included file does not read.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::parse(&read_with_includes(path.as_ref())?)
    }
}

fn parse_kdcdefaults(conf: &mut KdcConf, line: &str) {
    let Some((k, v)) = split_kv(line) else {
        return;
    };
    match k {
        "host_based_services" => combine_ws(&mut conf.host_based_services, &v),
        "no_host_referral" => combine_ws(&mut conf.no_host_referral, &v),
        // MIT `group_init_state` (`groups.c:247-249`): `profile_get_string`, so the first value.
        "spake_preauth_kdc_challenge" if conf.spake_preauth_kdc_challenge.is_none() => {
            conf.spake_preauth_kdc_challenge = Some(v);
        }
        "pkinit_dh_min_bits" => note_unsupported(conf, k),
        _ => {}
    }
}

/// MIT reads the enctype policy knobs from `[libdefaults]` only
/// (`krb/init_ctx.c get_boolean`, `krb5_get_permitted_enctypes`); a copy under
/// `[kdcdefaults]` or a realm stanza is ignored, so the KDC's own context
/// sees what every krb5 library on the host sees. Each relation is the first one written: `seen`
/// holds the names taken.
/// MIT `krb5_init_context_profile` (`lib/krb5/krb/init_ctx.c:218-232`): the KDC context reads `allow_weak_crypto`, `allow_des3` and `allow_rc4` with `get_boolean`, so the first value.
fn parse_kdc_libdefaults(conf: &mut KdcConf, seen: &mut Vec<String>, line: &str) {
    let Some((k, v)) = split_kv(line) else {
        return;
    };
    if seen.iter().any(|s| s == k) {
        return;
    }
    match k {
        // MIT `profile_get_integer` (`util/profile/prof_get.c:309-333`): one that is no integer is the default.
        "clockskew" => conf.clockskew = Some(parse_profile_int(&v).map_or(300, i64::from)),
        "allow_weak_crypto" => conf.allow_weak_crypto = Some(truthy(&v)),
        "allow_rc4" => conf.allow_rc4 = Some(truthy(&v)),
        "allow_des3" => conf.allow_des3 = Some(truthy(&v)),
        // MIT `krb5_get_permitted_enctypes` (`lib/krb5/krb/init_ctx.c:585-587`): `profile_get_string`, so the first value.
        "permitted_enctypes" => conf.permitted_enctypes = Some(split_ws(&v)),
        // MIT `group_init_state` (`groups.c:227-229`): `profile_get_string`, so the first value.
        "spake_preauth_groups" => conf.spake_preauth_groups = Some(split_ws(&v)),
        // MIT reads kdc_ports/kdc_tcp_ports/reject_bad_transit only from
        // [kdcdefaults] or a realm stanza, never [libdefaults]; no fallthrough,
        // so a kdcdefaults knob placed under [libdefaults] is ignored like MIT.
        // MIT `init_realm` (`kdc/main.c:257-261`): the realm stanza's `kdc_listen`, then
        // `kdc_ports`.
        // MIT `initialize_realms` (`kdc/main.c:622-626`): the `[kdcdefaults]` `kdc_listen`,
        // then `kdc_ports`.
        _ => return,
    }
    seen.push(k.to_owned());
}

/// The KDC booleans as written: the realm stanza's last `reject_bad_transit`, `disable_pac` and
/// `restrict_anonymous_to_tgt`, and `[kdcdefaults]`'s last `restrict_anonymous_to_tgt`. Their
/// names are matched exactly, as the profile's.
#[derive(Default)]
struct RealmBooleans {
    reject_bad_transit: Option<String>,
    disable_pac: Option<String>,
    restrict_anon: Option<String>,
    restrict_anon_default: Option<String>,
}

impl RealmBooleans {
    /// Record `line` of the realm stanza if it is one of them.
    fn realm(&mut self, line: &str) -> bool {
        let Some((k, v)) = split_kv(line) else {
            return false;
        };
        match k {
            "reject_bad_transit" => self.reject_bad_transit = Some(v),
            "disable_pac" => self.disable_pac = Some(v),
            "restrict_anonymous_to_tgt" => self.restrict_anon = Some(v),
            _ => return false,
        }
        true
    }

    /// Record `line` of `[kdcdefaults]` if it is one of them. MIT reads neither
    /// `reject_bad_transit` nor `disable_pac` there.
    fn defaults(&mut self, line: &str) -> bool {
        let Some((k, v)) = split_kv(line) else {
            return false;
        };
        match k {
            "restrict_anonymous_to_tgt" => self.restrict_anon_default = Some(v),
            _ => return false,
        }
        true
    }

    /// MIT `init_realm` (`kdc/main.c:292-295`): a realm `restrict_anonymous_to_tgt` that does not read as a boolean leaves `[kdcdefaults]`'s.
    /// MIT `init_realm` (`kdc/main.c:306-309`): a `reject_bad_transit` that does not read as a boolean is TRUE.
    /// MIT `init_realm` (`kdc/main.c:338-341`): a `disable_pac` that does not read as a boolean is FALSE.
    fn apply(self, conf: &mut KdcConf) {
        let read = |v: Option<String>| v.as_deref().and_then(aprof_boolean);
        conf.reject_bad_transit = read(self.reject_bad_transit).unwrap_or(true);
        conf.disable_pac = read(self.disable_pac).unwrap_or(false);
        conf.restrict_anon = read(self.restrict_anon)
            .or_else(|| read(self.restrict_anon_default))
            .unwrap_or(false);
    }
}

/// The realm a `[realms]` stanza's opening line `NAME = {` names.
fn stanza_name(line: &str) -> &str {
    line.trim_end_matches('{')
        .trim()
        .trim_end_matches('=')
        .trim()
}

/// The names of `[realms]`' stanzas in `text` (subsection braces joined), each once, in order.
fn stanza_names(text: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut section = String::new();
    let mut depth = 0usize;
    for raw in text.lines() {
        let line = raw.trim();
        if depth == 0
            && let Some(s) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        {
            s.trim().clone_into(&mut section);
        } else if section == "realms" {
            if line.ends_with('{') {
                if depth == 0 {
                    let name = stanza_name(line);
                    if !names.iter().any(|n| n == name) {
                        names.push(name.to_owned());
                    }
                }
                depth += 1;
            } else if line.starts_with('}') {
                depth = depth.saturating_sub(1);
            }
        }
    }
    names
}

/// `text` (subsection braces joined) with every section but `[realms]`, and of `[realms]` only
/// the stanza of `realm`; none with `None`.
fn stanza_of(text: &str, realm: Option<&str>) -> String {
    let mut kept = String::with_capacity(text.len());
    let mut section = String::new();
    let mut depth = 0usize;
    let mut keep = true;
    for raw in text.lines() {
        let line = raw.trim();
        if depth == 0
            && let Some(s) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        {
            s.trim().clone_into(&mut section);
            keep = true;
        } else if section == "realms" {
            if line.ends_with('{') {
                if depth == 0 {
                    keep = Some(stanza_name(line)) == realm;
                }
                depth += 1;
            } else if line.starts_with('}') && depth > 0 {
                depth -= 1;
                if depth == 0 {
                    if keep {
                        kept.push_str(raw);
                        kept.push('\n');
                    }
                    keep = true;
                    continue;
                }
            }
        }
        if keep {
            kept.push_str(raw);
            kept.push('\n');
        }
    }
    kept
}

fn parse_kdc_realm_line(conf: &mut KdcConf, line: &str) {
    let Some((k, v)) = split_kv(line) else {
        return;
    };
    match k {
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
        "supported_enctypes" => conf.supported_enctypes = split_ws(&v),
        "requires_preauth" => conf.requires_preauth = truthy(&v),
        "default_principal_flags" => conf.default_principal_flags = Some(v),
        "default_principal_expiration" => conf.default_principal_expiration = Some(v),
        "master_key_type" => conf.master_key_type = Some(v),
        "database_module" | "db_library" => conf.db_library = Some(v),
        "domain_sid" => conf.domain_sid = Some(v),
        "host_based_services" => combine_ws(&mut conf.host_based_services, &v),
        "no_host_referral" => combine_ws(&mut conf.no_host_referral, &v),
        "encrypted_challenge_indicator" => {
            conf.encrypted_challenge_indicator = Some(v);
        }
        "spake_preauth_indicator" => conf.spake_preauth_indicators.push(v),
        "dict_file" => conf.dict_file = Some(PathBuf::from(v)),
        "master_key_name" | "pkinit_dh_min_bits" => {
            note_unsupported(conf, k);
        }
        _ => {}
    }
}

/// Record that the relation `k` is there and read past.
fn note_unsupported(conf: &mut KdcConf, k: &str) {
    if !conf.unsupported.iter().any(|u| u == k) {
        conf.unsupported.push(k.to_owned());
    }
}

impl KdcConf {
    /// One line for each relation MIT's programs read that this port reads past, for the startup
    /// log: the relations [`Self::unsupported`] names, a `supported_enctypes` salt type other
    /// than `normal`, and a UNIX-domain socket in a listen list.
    /// MIT `init_realm` (`kdc/main.c:247-250`): `master_key_name` names the master key principal.
    /// MIT `krb5_string_to_keysalts` (`lib/kadm5/str_conv.c:319-366`): a tuple's salt type is kept.
    #[must_use]
    pub fn unsupported_lines(&self) -> Vec<String> {
        let mut lines: Vec<String> = self
            .unsupported
            .iter()
            .map(|k| format!("kdc.conf: {k} is not supported and is ignored"))
            .collect();
        let mut salts: Vec<&str> = Vec::new();
        for tuple in &self.supported_enctypes {
            if let Some((_, salt)) = tuple.split_once(':')
                && salt != "normal"
                && !salts.contains(&salt)
            {
                salts.push(salt);
                lines.push(format!(
                    "kdc.conf: supported_enctypes salt type {salt} is not supported; keys get the normal salt"
                ));
            }
        }
        let lists = [
            ("kdc_listen", Some(&self.kdc_listen)),
            ("kdc_tcp_listen", self.kdc_tcp_listen.as_ref()),
        ];
        for (name, list) in lists {
            for entry in list
                .into_iter()
                .flat_map(|l| l.split(|c: char| c == ',' || c.is_ascii_whitespace()))
                .filter(|e| e.starts_with('/'))
            {
                lines.push(format!(
                    "kdc.conf: {name} entry {entry} is a UNIX-domain socket, which is not supported; it is skipped"
                ));
            }
        }
        lines
    }
}

/// The directory the KDC profile, database, stash and ACL default to: `KERBER_KDC_DIR` at
/// build time, else `/var/kerberos/krb5kdc` (the Fedora / RHEL / KLLDAP layout).
/// MIT `KDC_DIR` (`osconf.hin:72-72`): `$(localstatedir)/krb5kdc` in MIT's own build.
pub const KDC_DIR: &str = match option_env!("KERBER_KDC_DIR") {
    Some(dir) => dir,
    None => "/var/kerberos/krb5kdc",
};

/// `KDC_DIR/kdc.conf`.
/// MIT `DEFAULT_KDC_PROFILE` (`osconf.hin:81-81`): the KDC profile when `KRB5_KDC_PROFILE` is unset.
#[must_use]
pub fn default_kdc_profile() -> PathBuf {
    Path::new(KDC_DIR).join("kdc.conf")
}

/// `KDC_DIR/principal`.
/// MIT `DEFAULT_KDB_FILE` (`osconf.hin:74-74`): `database_name` when kdc.conf has none.
#[must_use]
pub fn default_kdb_file() -> PathBuf {
    Path::new(KDC_DIR).join("principal")
}

/// `KDC_DIR/kadm5.acl`.
/// MIT `DEFAULT_KADM5_ACL_FILE` (`osconf.hin:106-106`): `acl_file` when kdc.conf has none.
#[must_use]
pub fn default_acl_file() -> PathBuf {
    Path::new(KDC_DIR).join("kadm5.acl")
}

/// `KDC_DIR/kpropd.acl`.
/// MIT `KPROPD_ACL_FILE` (`osconf.hin:132-132`): kpropd's ACL file when `-a` names none.
#[must_use]
pub fn default_kpropd_acl() -> PathBuf {
    Path::new(KDC_DIR).join("kpropd.acl")
}

/// `KDC_DIR/replica_datatrans`.
/// MIT `KPROP_DEFAULT_FILE` (`osconf.hin:127-127`): the dump kprop sends when `-f` names none.
#[must_use]
pub fn default_kprop_file() -> PathBuf {
    Path::new(KDC_DIR).join("replica_datatrans")
}

/// `KDC_DIR/.k5.<realm>`.
/// MIT `krb5_def_store_mkey_list` (`kdb_default.c:126-129`): `DEFAULT_KEYFILE_STUB` plus the
/// realm when no `key_stash_file` is set.
#[must_use]
pub fn default_stash_file(realm: &str) -> PathBuf {
    Path::new(KDC_DIR).join(format!(".k5.{realm}"))
}

/// `KRB5_KDC_PROFILE`; in a `test-hooks` build, else the gates' `KRB5_KDC_CONF` alias.
#[must_use]
pub fn env_kdc_config() -> Option<PathBuf> {
    env_kdc_config_in(&|name| std::env::var_os(name))
}

fn env_kdc_config_in(env: &dyn Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let profile = env("KRB5_KDC_PROFILE");
    #[cfg(feature = "test-hooks")]
    let profile = profile.or_else(|| env("KRB5_KDC_CONF"));
    profile.map(PathBuf::from)
}

/// The KDC profile path: [`env_kdc_config`], else [`default_kdc_profile`], whether or not the
/// file exists; on a thread a test pinned with [`crate::set_test_kdc_profile`], that path.
/// MIT `add_kdc_config_file` (`init_os_ctx.c:340-366`): `KRB5_KDC_PROFILE`, else
/// `DEFAULT_KDC_PROFILE`, put ahead of the krb5.conf files.
#[must_use]
pub fn kdc_conf_path() -> PathBuf {
    if let Some(path) = super::testenv::TEST_KDC_PROFILE.with(|c| c.borrow().clone()) {
        return path;
    }
    kdc_conf_path_in(&|name| std::env::var_os(name))
}

pub(super) fn kdc_conf_path_in(env: &dyn Fn(&str) -> Option<OsString>) -> PathBuf {
    env_kdc_config_in(env).unwrap_or_else(default_kdc_profile)
}

/// The KDC profile's text, its bytes taken as lossy UTF-8 since MIT's need not be UTF-8; `None`
/// when the file is missing, unreadable or a directory.
/// MIT `profile_init_flags` (`prof_init.c:198-206`): a missing (`ENOENT`) or unreadable
/// (`EACCES` / `EPERM`) file is skipped, so its defaults apply; any other failure is fatal.
fn read_kdc_profile(path: &Path) -> Result<Option<String>, Error> {
    match super::files::read(path) {
        Ok(bytes) => Ok(Some(with_includes(path, &bytes)?)),
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::NotFound | ErrorKind::PermissionDenied | ErrorKind::IsADirectory
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(Error::Io(std::io::Error::new(
            e.kind(),
            format!("{}: {e}", path.display()),
        ))),
    }
}

/// The text of the kdc.conf at `path`, its includes followed.
fn read_with_includes(path: &Path) -> Result<String, Error> {
    with_includes(path, &super::files::read(path)?)
}

/// `bytes`, read from the kdc.conf at `path`, as text with its includes followed: the KDC profile
/// is one profile file, and MIT's parser follows a file's includes wherever it is read.
fn with_includes(path: &Path, bytes: &[u8]) -> Result<String, Error> {
    let mut stack = vec![std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())];
    super::profile::resolve_includes(&String::from_utf8_lossy(bytes), &mut stack)
}

/// The path relations of one realm's `[realms]` stanza.
#[derive(Default)]
struct RealmPaths {
    database_name: Option<PathBuf>,
    key_stash_file: Option<PathBuf>,
    acl_file: Option<PathBuf>,
    master_key_type: Option<String>,
}

impl RealmPaths {
    /// `realm`'s stanza in `text` (its subsection braces joined, `join_subsection_braces`),
    /// empty when the profile has none, so that MIT's defaults apply; no other realm's stanza is
    /// read. A relation written twice takes its last value.
    /// MIT `get_string_param` (`alt_prof.c:310-336`): `krb5_aprof_get_string(…, TRUE, …)`, the
    /// last value under `[realms]` → realm, else the default.
    fn stanza(text: &str, realm: &str) -> Self {
        let mut out = Self::default();
        let mut section = String::new();
        let mut current: Option<String> = None;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(s) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                s.trim().clone_into(&mut section);
                current = None;
                continue;
            }
            if section != "realms" {
                continue;
            }
            if let Some(head) = line.strip_suffix('{') {
                current = Some(head.trim().trim_end_matches('=').trim().to_owned());
                continue;
            }
            if line == "}" {
                current = None;
                continue;
            }
            if current.as_deref() != Some(realm) {
                continue;
            }
            let Some((k, v)) = split_kv(line) else {
                continue;
            };
            match k {
                "database_name" => out.database_name = Some(PathBuf::from(v)),
                "key_stash_file" => out.key_stash_file = Some(PathBuf::from(v)),
                "acl_file" => out.acl_file = Some(PathBuf::from(v)),
                "master_key_type" => out.master_key_type = Some(v),
                _ => {}
            }
        }
        out
    }
}

/// The gates' overrides of a realm's paths and master key type, read from the environment only
/// in a `test-hooks` build: MIT's tools take these from kdc.conf and argv alone.
#[derive(Default)]
struct EnvOverrides {
    database_name: Option<PathBuf>,
    key_stash_file: Option<PathBuf>,
    acl_file: Option<PathBuf>,
    master_key_type: Option<String>,
}

impl EnvOverrides {
    fn read(env: &dyn Fn(&str) -> Option<OsString>) -> Self {
        #[cfg(feature = "test-hooks")]
        {
            Self {
                database_name: env("KRB5_KDC_DB").map(PathBuf::from),
                key_stash_file: env("KRB5_KDC_STASH").map(PathBuf::from),
                acl_file: env("KRB5_ACL_FILE").map(PathBuf::from),
                master_key_type: env("KRB5_MASTER_ETYPE").map(|v| v.to_string_lossy().into_owned()),
            }
        }
        #[cfg(not(feature = "test-hooks"))]
        {
            let _ = env;
            Self::default()
        }
    }
}

/// Where a KDC-side tool finds its profile, database, master-key stash and ACL, and which master
/// key type it uses.
///
/// Each path is the relation in the realm's own kdc.conf stanza, else MIT's default under
/// [`KDC_DIR`]; a `test-hooks` build puts the gates' environment overrides on top. With no realm
/// known the resolver fails, as MIT's tools do, unless (in a `test-hooks` build) `KRB5_KDC_DB`
/// and `KRB5_KDC_STASH` name both files.
/// MIT `kadm5_get_config_params` (`alt_prof.c:447-560`): the realm is the caller's, else
/// `krb5_get_default_realm`; `database_name` / `acl_file` / `master_key_type` /
/// `key_stash_file` come from that realm's stanza, with `DEFAULT_KDB_FILE` /
/// `DEFAULT_KADM5_ACL_FILE` defaults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdcPaths {
    /// The KDC profile ([`kdc_conf_path`]).
    pub profile: PathBuf,
    /// The profile, parsed; `None` when the file is missing or unreadable.
    pub conf: Option<KdcConf>,
    /// The realm the paths are for: the caller's, else krb5.conf's `default_realm`.
    pub realm: Option<String>,
    /// `database_name`, else [`default_kdb_file`]; a `test-hooks` build's `KRB5_KDC_DB` first.
    pub database_name: PathBuf,
    /// `key_stash_file`, else [`default_stash_file`]; a `test-hooks` build's `KRB5_KDC_STASH`
    /// first.
    pub key_stash_file: PathBuf,
    /// `acl_file`, else [`default_acl_file`]; a `test-hooks` build's `KRB5_ACL_FILE` first, and
    /// its default beside the stash when `KRB5_KDC_STASH` moved it. `None` when the value chosen
    /// is empty: no ACL file, self-service only.
    /// MIT `main` (`ovsec_kadmd.c:497-497`): an empty `acl_file` becomes NULL.
    pub acl_file: Option<PathBuf>,
    /// `master_key_type`, as written; a `test-hooks` build's `KRB5_MASTER_ETYPE` first. `None`
    /// leaves the tool's default.
    pub master_key_type: Option<String>,
}

impl KdcPaths {
    /// Resolve the paths for `realm`, else for krb5.conf's `default_realm`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the KDC profile exists but cannot be read (a missing or unreadable one
    /// is skipped, as MIT skips it); [`Error::Profile`] when it has a relation with
    /// no value not followed by a line that starts with `{`; [`Error::NoDefaultRealm`] when neither
    /// `realm` nor krb5.conf's `default_realm` names a realm and the gates' overrides do not name
    /// both the database and the stash.
    pub fn resolve(realm: Option<&str>) -> Result<Self, Error> {
        Self::resolve_in(&|name| std::env::var_os(name), realm, || {
            crate::load_krb5_conf().and_then(|c| c.default_realm)
        })
    }

    pub(super) fn resolve_in(
        env: &dyn Fn(&str) -> Option<OsString>,
        realm: Option<&str>,
        default_realm: impl FnOnce() -> Option<String>,
    ) -> Result<Self, Error> {
        let profile = kdc_conf_path_in(env);
        let text = read_kdc_profile(&profile)?
            .as_deref()
            .map(join_subsection_braces)
            .transpose()?;
        let over = EnvOverrides::read(env);
        let realm = realm.map(str::to_owned).or_else(default_realm);
        // MIT `init_realm` (`kdc/main.c:229-231`): the realm's relations are read under `[realms]` → that realm only.
        let conf = text
            .as_deref()
            .map(|t| match realm.as_deref() {
                Some(r) => KdcConf::parse_for_realm(t, r),
                None => KdcConf::parse(t),
            })
            .transpose()?;
        // MIT `main` (`kdb5_util.c:304-312`): no realm is fatal before any path is read. Only the
        // gates' KRB5_KDC_DB and KRB5_KDC_STASH, naming both files, stand in for one.
        let relations = match realm.as_deref() {
            Some(realm) => RealmPaths::stanza(text.as_deref().unwrap_or_default(), realm),
            None if over.database_name.is_some() && over.key_stash_file.is_some() => {
                RealmPaths::default()
            }
            None => return Err(Error::NoDefaultRealm),
        };
        let database_name = over
            .database_name
            .or(relations.database_name)
            .unwrap_or_else(default_kdb_file);
        let key_stash_file = match over.key_stash_file.clone().or(relations.key_stash_file) {
            Some(path) => path,
            None => default_stash_file(realm.as_deref().ok_or(Error::NoDefaultRealm)?),
        };
        let acl_file = over.acl_file.or(relations.acl_file).unwrap_or_else(|| {
            over.key_stash_file
                .as_deref()
                .and_then(Path::parent)
                .map_or_else(default_acl_file, |dir| dir.join("kadm5.acl"))
        });
        let master_key_type = over.master_key_type.or(relations.master_key_type);
        Ok(Self {
            profile,
            conf,
            realm,
            database_name,
            key_stash_file,
            acl_file: (!acl_file.as_os_str().is_empty()).then_some(acl_file),
            master_key_type,
        })
    }
}
