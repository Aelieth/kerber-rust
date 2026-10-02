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
use super::profile::{combine_ws, parse_duration_secs, split_kv, split_ws, truthy};
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
        let slot = match k.to_ascii_lowercase().as_str() {
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
            admin_server: None,
            kadmind_listen: None,
            kadmind_port: None,
            kpasswd_listen: None,
            kpasswd_port: None,
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
            logging: Vec::new(),
        }
    }
}

impl KdcConf {
    /// Parse `kdc.conf` text.
    ///
    /// # Errors
    ///
    /// None: a malformed or unknown line is skipped, so this is `Ok` even when `text` is not
    /// valid kdc.conf.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut conf = Self::default();
        let mut section = String::new();
        let mut in_realm = false;
        let mut realm_lines = Vec::new();
        let mut realm_listen = ListenRelations::default();
        let mut default_listen = ListenRelations::default();
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
                    if !realm_listen.take(line) {
                        parse_kdc_realm_line(&mut conf, line);
                    }
                }
            }
            if section == "kdcdefaults" && !default_listen.take(line) {
                parse_kdcdefaults(&mut conf, line);
            }
            if section == "libdefaults" {
                parse_kdc_libdefaults(&mut conf, line);
            }
            if section == "logging"
                && let Some((k, v)) = split_kv(line)
            {
                conf.logging.push((k.to_owned(), v));
            }
        }
        // MIT `init_realm` (`kdc/main.c:286-345`): realm stanza, then `[kdcdefaults]` fallback.
        // Re-apply realm booleans so a later defaults section cannot win.
        for line in &realm_lines {
            overlay_realm_booleans(&mut conf, line);
        }
        // MIT `initialize_realms` (`kdc/main.c:622-660`): the `[kdcdefaults]` lists, else `88`.
        // MIT `init_realm` (`kdc/main.c:257-282`): the realm stanza's lists win over those.
        if let Some(v) = realm_listen.udp().or(default_listen.udp()) {
            conf.kdc_listen.clone_from(v);
        }
        conf.kdc_listen_in_realm = realm_listen.udp().is_some();
        conf.kdc_tcp_listen = realm_listen.tcp().or(default_listen.tcp()).cloned();
        Ok(conf)
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

    /// kadmind's port: the port written in `admin_server` (this file's, else
    /// `krb5_admin_server` from krb5.conf), else `kadmind_port`, else 749.
    /// MIT `kadm5_get_config_params` (`lib/kadm5/alt_prof.c:496-531`): `admin_server`'s port
    /// is read before `kadmind_port`.
    #[must_use]
    pub fn kadmind_port(&self, krb5_admin_server: Option<&str>) -> u16 {
        self.admin_server
            .as_deref()
            .or(krb5_admin_server)
            .and_then(listen::admin_server_port)
            .or(self.kadmind_port)
            .unwrap_or(listen::KADMIND_PORT)
    }

    /// kadmind's RPC listeners; no `kadmind_listen` is the wildcard.
    /// MIT `setup_loop` (`kadmin/server/ovsec_kadmd.c:153-156`): RPC on `kadmind_listen`.
    ///
    /// # Errors
    ///
    /// [`Error::Parse`] for an entry [`listen::parse_host_string`] refuses.
    pub fn kadmind_listeners(
        &self,
        krb5_admin_server: Option<&str>,
    ) -> Result<Vec<ListenAddr>, Error> {
        listen::listen_addrs(
            self.kadmind_listen.as_deref(),
            self.kadmind_port(krb5_admin_server),
        )
    }

    /// kpasswd's UDP and TCP listeners, on `kpasswd_port` (default 464).
    /// MIT `setup_loop` (`kadmin/server/ovsec_kadmd.c:147-152`): UDP and TCP on one list.
    ///
    /// # Errors
    ///
    /// [`Error::Parse`] for an entry [`listen::parse_host_string`] refuses.
    pub fn kpasswd_listeners(&self) -> Result<Vec<ListenAddr>, Error> {
        listen::listen_addrs(
            self.kpasswd_listen.as_deref(),
            self.kpasswd_port.unwrap_or(listen::KPASSWD_PORT),
        )
    }

    /// Load from a path.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when `path` cannot be read as UTF-8 text; the parse itself cannot fail.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text)
    }
}

fn parse_kdcdefaults(conf: &mut KdcConf, line: &str) {
    let Some((k, v)) = split_kv(line) else {
        return;
    };
    match k.to_ascii_lowercase().as_str() {
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
/// (`krb/init_ctx.c get_boolean`, `krb5_get_permitted_enctypes`); a copy under
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
        // [kdcdefaults] or a realm stanza, never [libdefaults]; no fallthrough,
        // so a kdcdefaults knob placed under [libdefaults] is ignored like MIT.
        // MIT `init_realm` (`kdc/main.c:257-261`): the realm stanza's `kdc_listen`, then
        // `kdc_ports`.
        // MIT `initialize_realms` (`kdc/main.c:622-626`): the `[kdcdefaults]` `kdc_listen`,
        // then `kdc_ports`.
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
        "admin_server" => {
            conf.admin_server.get_or_insert(v);
        }
        "kadmind_listen" => {
            conf.kadmind_listen.get_or_insert(v);
        }
        "kpasswd_listen" => {
            conf.kpasswd_listen.get_or_insert(v);
        }
        "kadmind_port" if conf.kadmind_port.is_none() => conf.kadmind_port = v.parse().ok(),
        "kpasswd_port" if conf.kpasswd_port.is_none() => conf.kpasswd_port = v.parse().ok(),
        _ => {}
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
/// file exists.
/// MIT `add_kdc_config_file` (`init_os_ctx.c:340-366`): `KRB5_KDC_PROFILE`, else
/// `DEFAULT_KDC_PROFILE`, put ahead of the krb5.conf files.
#[must_use]
pub fn kdc_conf_path() -> PathBuf {
    kdc_conf_path_in(&|name| std::env::var_os(name))
}

pub(super) fn kdc_conf_path_in(env: &dyn Fn(&str) -> Option<OsString>) -> PathBuf {
    env_kdc_config_in(env).unwrap_or_else(default_kdc_profile)
}

/// The KDC profile's text; `None` when the file is missing, unreadable or a directory.
/// MIT `profile_init_flags` (`prof_init.c:198-206`): a missing (`ENOENT`) or unreadable
/// (`EACCES` / `EPERM`) file is skipped, so its defaults apply; any other failure is fatal.
fn read_kdc_profile(path: &Path) -> Result<Option<String>, Error> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
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

/// The path relations of one realm's `[realms]` stanza.
#[derive(Default)]
struct RealmPaths {
    database_name: Option<PathBuf>,
    key_stash_file: Option<PathBuf>,
    acl_file: Option<PathBuf>,
    master_key_type: Option<String>,
}

impl RealmPaths {
    /// `realm`'s stanza in `text`, empty when the profile has none, so that MIT's defaults
    /// apply; no other realm's stanza is read. A relation written twice takes its last value.
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
                section = s.trim().to_ascii_lowercase();
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
            match k.to_ascii_lowercase().as_str() {
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
    /// [`Error::Io`] when the KDC profile exists but cannot be read as UTF-8 text (a missing or
    /// unreadable one is skipped, as MIT skips it); [`Error::NoDefaultRealm`] when neither
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
        let text = read_kdc_profile(&profile)?;
        let conf = text.as_deref().map(KdcConf::parse).transpose()?;
        let over = EnvOverrides::read(env);
        let realm = realm.map(str::to_owned).or_else(default_realm);
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
