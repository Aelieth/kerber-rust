//! kdc.conf (`kadm5/alt_prof.c` `GET_DELTAT_PARAM` / `dict_file` /
//! `KADM5_CONFIG_FLAGS`; `kdc/main.c` `kdc_ports` / `kdc_tcp_ports` /
//! `realm_maxrlife` / `reject_bad_transit`): realm stanza,
//! `[kdcdefaults]`, `[libdefaults]` enctype knobs.

use std::path::{Path, PathBuf};

use super::profile::{combine_ws, parse_duration_secs, split_kv, split_ws, truthy};
use super::{Error, KdcConf};

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

impl KdcConf {
    /// Parse `kdc.conf` text.
    ///
    /// # Errors
    ///
    /// [`Error::Parse`] on malformed input.
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
        // MIT `otp_verify` (`main.c:286-345`): realm stanza, then `[kdcdefaults]` fallback.
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
    /// [`Error::Io`] or [`Error::Parse`].
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
        // MIT `main` (`main.c:257-622`): [kdcdefaults] or a realm stanza -626), never
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
