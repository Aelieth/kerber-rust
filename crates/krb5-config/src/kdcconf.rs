//! kdc.conf (`kadm5/alt_prof.c` `GET_DELTAT_PARAM` / `dict_file` /
//! `KADM5_CONFIG_FLAGS`; `kdc/main.c` `kdc_ports` / `kdc_tcp_ports` /
//! `realm_maxrlife` / `reject_bad_transit`): realm stanza,
//! `[kdcdefaults]`, `[libdefaults]` enctype knobs.

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
        conf.kdc_tcp_listen = realm_listen.tcp().or(default_listen.tcp()).cloned();
        Ok(conf)
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

/// `KRB5_KDC_PROFILE` / `KRB5_KDC_CONF`.
#[must_use]
pub fn env_kdc_config() -> Option<PathBuf> {
    std::env::var_os("KRB5_KDC_PROFILE")
        .or_else(|| std::env::var_os("KRB5_KDC_CONF"))
        .map(PathBuf::from)
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
