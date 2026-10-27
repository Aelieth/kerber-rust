use std::path::{Path, PathBuf};

use super::{Krb5Conf, kdc_conf_path, krb5_conf_paths, load_krb5_conf_paths};

// MIT: `DEF_ULOGENTRIES` (include/kdb_log.h:42-42)
// Update-log entries when unset.
pub const DEF_ULOGENTRIES: u32 = 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpropParams {
    pub enabled: bool,
    pub port: Option<i32>,
    pub logfile: PathBuf,
    pub ulogsize: u32,
    pub poll_time: i32,
    pub resync_timeout: i32,
    pub admin_server: Option<String>,
    pub listen: Option<String>,
}

impl IpropParams {
    // MIT: `kadm5_get_config_params` (lib/kadm5/alt_prof.c)
    #[must_use]
    pub fn for_realm(profile: Option<&Krb5Conf>, realm: &str, dbname: &Path) -> Self {
        let last = |name: &str| last_value(profile, realm, name);
        let positive = |name: &str| {
            last(name)
                .and_then(sscanf_int)
                .and_then(|n| u32::try_from(n).ok())
                .filter(|&n| n > 0)
        };
        let deltat = |name: &str| last(name).and_then(|v| krb5_types::deltat::parse(v).ok());
        let mut logfile = dbname.as_os_str().to_os_string();
        logfile.push(".ulog");
        Self {
            enabled: last("iprop_enable").is_some_and(yes_word),
            port: last("iprop_port").and_then(sscanf_int),
            logfile: last("iprop_logfile").map_or_else(|| PathBuf::from(logfile), PathBuf::from),
            ulogsize: positive("iprop_ulogsize")
                .or_else(|| positive("iprop_master_ulogsize"))
                .unwrap_or(DEF_ULOGENTRIES),
            poll_time: match deltat("iprop_replica_poll").unwrap_or(-1) {
                -1 => deltat("iprop_slave_poll").unwrap_or(2 * 60),
                t => t,
            },
            resync_timeout: deltat("iprop_resync_timeout").unwrap_or(60 * 5),
            admin_server: profile
                .and_then(|p| p.admin_servers.get(realm))
                .and_then(|v| v.last())
                .map(|e| crate::listen::admin_server_host(&e.host).to_owned()),
            listen: last("iprop_listen").map(ToOwned::to_owned),
        }
    }

    #[must_use]
    pub fn load(realm: &str, dbname: &Path) -> Self {
        let mut paths = vec![kdc_conf_path()];
        paths.extend(krb5_conf_paths());
        let profile = load_krb5_conf_paths(paths).ok();
        Self::for_realm(profile.as_ref(), realm, dbname)
    }

    // MIT: `kadm5_init` (lib/kadm5/srv/server_init.c)
    #[must_use]
    pub fn missing_required(&self) -> bool {
        self.enabled && self.port.is_none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KadmindListen {
    pub kadmind_port: i32,
    pub kpasswd_port: i32,
    pub kadmind_listen: Option<String>,
    pub kpasswd_listen: Option<String>,
}

impl KadmindListen {
    // MIT: `get_port_param` (lib/kadm5/alt_prof.c:342-362)
    #[must_use]
    pub fn for_realm(profile: Option<&Krb5Conf>, realm: &str, port_arg: Option<i32>) -> Self {
        let last = |name: &str| last_value(profile, realm, name);
        let admin_port = last("admin_server").and_then(crate::listen::admin_server_port);
        Self {
            kadmind_port: admin_port.or(port_arg).unwrap_or_else(|| {
                last("kadmind_port")
                    .and_then(sscanf_int)
                    .unwrap_or(i32::from(crate::listen::KADMIND_PORT))
            }),
            kpasswd_port: last("kpasswd_port")
                .and_then(sscanf_int)
                .unwrap_or(i32::from(crate::listen::KPASSWD_PORT)),
            kadmind_listen: last("kadmind_listen").map(ToOwned::to_owned),
            kpasswd_listen: last("kpasswd_listen").map(ToOwned::to_owned),
        }
    }
}

// MIT: `krb5_aprof_get_string` (lib/kadm5/alt_prof.c:184-211)
// with `uselast`, the last of the values.
// MIT: `krb5_aprof_get_int32` (lib/kadm5/alt_prof.c:277-299)
fn last_value<'a>(profile: Option<&'a Krb5Conf>, realm: &str, name: &str) -> Option<&'a str> {
    profile
        .and_then(|p| p.kadm5.get(realm))?
        .iter()
        .rev()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

// MIT: `KADM5_MISSING_CONF_PARAMS` (lib/kadm5/kadm_err.et)
pub const MISSING_CONF_PARAMS: &str = "Required parameters in kdc.conf missing";

// MIT: `string_to_boolean` (lib/kadm5/alt_prof.c)
fn yes_word(v: &str) -> bool {
    ["y", "yes", "true", "t", "1", "on"]
        .iter()
        .any(|w| w.eq_ignore_ascii_case(v))
}

fn sscanf_int(s: &str) -> Option<i32> {
    let t = s.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let (neg, rest) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let digits: &str = &rest[..rest.bytes().take_while(u8::is_ascii_digit).count()];
    if digits.is_empty() {
        return None;
    }
    let n: i64 = digits.parse().ok()?;
    i32::try_from(if neg { -n } else { n }).ok()
}
