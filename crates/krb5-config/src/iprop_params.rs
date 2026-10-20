//! A realm's incremental-propagation parameters, read as MIT's `kadm5_get_config_params` reads
//! them (`lib/kadm5/alt_prof.c`) from the profile a KDC-side program opens: kdc.conf, then the
//! krb5.conf files.

use std::path::{Path, PathBuf};

use super::{Krb5Conf, kdc_conf_path, krb5_conf_paths, load_krb5_conf_paths};

/// MIT `DEF_ULOGENTRIES` (`include/kdb_log.h:42-42`): the update log's entries when no size is configured.
pub const DEF_ULOGENTRIES: u32 = 1000;

/// One realm's iprop parameters: whether its programs keep the update log, where, how many
/// entries it holds, and whether `iprop_port` is set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpropParams {
    /// `iprop_enable`: the primary keeps an update log and serves the iprop program, a replica
    /// pulls from it. False unless the last value is one of MIT's yes words.
    pub enabled: bool,
    /// `iprop_port`, when a value is there that reads as a number; `kadm5_init` requires one
    /// whenever iprop is enabled ([`Self::missing_required`]).
    pub port: Option<i32>,
    /// `iprop_logfile`, else the database name with `.ulog` added.
    pub logfile: PathBuf,
    /// `iprop_ulogsize`, else `iprop_master_ulogsize`, when positive; else
    /// [`DEF_ULOGENTRIES`].
    pub ulogsize: u32,
    /// `iprop_replica_poll`, else `iprop_slave_poll`, else two minutes: the seconds between a
    /// replica's requests for updates.
    pub poll_time: i32,
    /// `iprop_resync_timeout`, else five minutes: the seconds a replica waits for a full resync
    /// it asked for.
    pub resync_timeout: i32,
    /// The host of the realm's last `admin_server`: the primary a replica polls.
    pub admin_server: Option<String>,
}

impl IpropParams {
    /// The parameters of `realm` in `profile` (kdc.conf's relations first, then krb5.conf's, as
    /// [`load_krb5_conf_paths`] merges them), for the database named `dbname`. Each relation's
    /// last value counts.
    /// MIT `kadm5_get_config_params` (`lib/kadm5/alt_prof.c:674-688`): `iprop_enable` is the last value read as a boolean, and false when there is none or it is not one.
    /// MIT `kadm5_get_config_params` (`lib/kadm5/alt_prof.c:690-697`): `iprop_logfile`, else the database name with `.ulog` added.
    /// MIT `kadm5_get_config_params` (`lib/kadm5/alt_prof.c:699-700`): `iprop_port` has no default, so only a value that reads as a number sets it.
    /// MIT `kadm5_get_config_params` (`lib/kadm5/alt_prof.c:706-724`): `iprop_ulogsize`, else `iprop_master_ulogsize`, when positive; else `DEF_ULOGENTRIES`.
    /// MIT `kadm5_get_config_params` (`lib/kadm5/alt_prof.c:703-704`): `iprop_resync_timeout` is a delta time, five minutes by default.
    /// MIT `kadm5_get_config_params` (`lib/kadm5/alt_prof.c:726-731`): `iprop_replica_poll`, and only when it is absent or no delta time, `iprop_slave_poll` or two minutes.
    /// MIT `kadm5_get_config_params` (`lib/kadm5/alt_prof.c:496-502`): `admin_server`'s last value, its port taken off.
    #[must_use]
    pub fn for_realm(profile: Option<&Krb5Conf>, realm: &str, dbname: &Path) -> Self {
        let relations = profile
            .and_then(|p| p.iprop.get(realm))
            .map_or(&[][..], Vec::as_slice);
        let last = |name: &str| {
            relations
                .iter()
                .rev()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
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
        }
    }

    /// The parameters of `realm` in this process's KDC profile ([`kdc_conf_path`], then the
    /// krb5.conf files), for the database named `dbname`. A profile that does not load counts as
    /// empty, so iprop is off.
    #[must_use]
    pub fn load(realm: &str, dbname: &Path) -> Self {
        let mut paths = vec![kdc_conf_path()];
        paths.extend(krb5_conf_paths());
        let profile = load_krb5_conf_paths(paths).ok();
        Self::for_realm(profile.as_ref(), realm, dbname)
    }

    /// Whether `kadm5_init` refuses these parameters: iprop is enabled and `iprop_port` is not
    /// set. The caller reports MIT's `KADM5_MISSING_CONF_PARAMS` text,
    /// [`MISSING_CONF_PARAMS`].
    /// MIT `kadm5_init` (`lib/kadm5/srv/server_init.c:222-228`): with iprop enabled, the log file and the port are required parameters.
    #[must_use]
    pub fn missing_required(&self) -> bool {
        self.enabled && self.port.is_none()
    }
}

/// MIT `KADM5_MISSING_CONF_PARAMS` (`lib/kadm5/kadm_err.et:55-55`): the text of a required parameter that is not set.
pub const MISSING_CONF_PARAMS: &str = "Required parameters in kdc.conf missing";

/// MIT `string_to_boolean` (`lib/kadm5/alt_prof.c:82-101`): the yes words, in any case; every other value is no, or not a boolean.
fn yes_word(v: &str) -> bool {
    ["y", "yes", "true", "t", "1", "on"]
        .iter()
        .any(|w| w.eq_ignore_ascii_case(v))
}

/// C `sscanf(s, "%d")`: optional blanks and a sign, then at least one digit, up to the first
/// other character; `None` when there is no digit or the number is past an `int`.
/// MIT `krb5_aprof_get_int32` (`lib/kadm5/alt_prof.c:277-299`): a value that does not scan as `%d` is not a number.
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
