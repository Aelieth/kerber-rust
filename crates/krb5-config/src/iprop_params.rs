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
}

impl IpropParams {
    /// The parameters of `realm` in `profile` (kdc.conf's relations first, then krb5.conf's, as
    /// [`load_krb5_conf_paths`] merges them), for the database named `dbname`. Each relation's
    /// last value counts.
    /// MIT `kadm5_get_config_params` (`lib/kadm5/alt_prof.c:674-688`): `iprop_enable` is the last value read as a boolean, and false when there is none or it is not one.
    /// MIT `kadm5_get_config_params` (`lib/kadm5/alt_prof.c:690-697`): `iprop_logfile`, else the database name with `.ulog` added.
    /// MIT `kadm5_get_config_params` (`lib/kadm5/alt_prof.c:699-700`): `iprop_port` has no default, so only a value that reads as a number sets it.
    /// MIT `kadm5_get_config_params` (`lib/kadm5/alt_prof.c:706-724`): `iprop_ulogsize`, else `iprop_master_ulogsize`, when positive; else `DEF_ULOGENTRIES`.
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
        let mut logfile = dbname.as_os_str().to_os_string();
        logfile.push(".ulog");
        Self {
            enabled: last("iprop_enable").is_some_and(yes_word),
            port: last("iprop_port").and_then(sscanf_int),
            logfile: last("iprop_logfile").map_or_else(|| PathBuf::from(logfile), PathBuf::from),
            ulogsize: positive("iprop_ulogsize")
                .or_else(|| positive("iprop_master_ulogsize"))
                .unwrap_or(DEF_ULOGENTRIES),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// kdc.conf's text then krb5.conf's, as one profile: the order [`load_krb5_conf_paths`]
    /// reads the two files in.
    fn profile(kdc: &str, krb5: &str) -> Krb5Conf {
        Krb5Conf::parse(&format!("{kdc}\n{krb5}")).unwrap()
    }

    #[test]
    fn iprop_is_off_with_no_relation_and_the_log_sits_beside_the_database() {
        let p = IpropParams::for_realm(None, "R.TEST", Path::new("/var/db/principal"));
        assert!(!p.enabled);
        assert_eq!(p.port, None);
        assert_eq!(p.logfile, PathBuf::from("/var/db/principal.ulog"));
        assert_eq!(p.ulogsize, DEF_ULOGENTRIES);
        assert!(!p.missing_required());
    }

    /// The last value of the KDC profile counts: kdc.conf's relations come first, so a
    /// krb5.conf value is the last one.
    #[test]
    fn the_last_value_across_kdc_conf_then_krb5_conf_counts() {
        let conf = profile(
            "[realms]\n R.TEST = {\n  iprop_enable = false\n  iprop_ulogsize = 7\n }\n",
            "[realms]\n R.TEST = {\n  iprop_enable = TRUE\n  iprop_port = 2121\n }\n \
             O.TEST = {\n  iprop_enable = true\n }\n",
        );
        let p = IpropParams::for_realm(Some(&conf), "R.TEST", Path::new("/d/principal"));
        assert!(p.enabled);
        assert_eq!(p.port, Some(2121));
        assert_eq!(p.ulogsize, 7);
        let other = IpropParams::for_realm(Some(&conf), "X.TEST", Path::new("/d/principal"));
        assert!(!other.enabled);
    }

    #[test]
    fn mits_yes_words_and_nothing_else_enable_iprop() {
        for (v, want) in [
            ("y", true),
            ("On", true),
            ("1", true),
            ("t", true),
            ("f", false),
            ("nil", false),
            ("enabled", false),
        ] {
            let conf = profile(
                &format!("[realms]\n R.TEST = {{\n  iprop_enable = {v}\n }}\n"),
                "",
            );
            let p = IpropParams::for_realm(Some(&conf), "R.TEST", Path::new("p"));
            assert_eq!(p.enabled, want, "{v:?}");
        }
        // No value at all is no profile: MIT's parser wants a `{` on the next line.
        assert!(Krb5Conf::parse("[realms]\n R.TEST = {\n  iprop_enable =\n }\n").is_err());
    }

    /// `iprop_ulogsize` wins when positive, then `iprop_master_ulogsize`, then 1000; a size that
    /// does not scan as a number, zero or a negative one counts as none.
    #[test]
    fn the_ulog_size_falls_back_as_mits_does() {
        for (rels, want) in [
            ("iprop_master_ulogsize = 3\n iprop_ulogsize = 5", 5),
            ("iprop_master_ulogsize = 3", 3),
            ("iprop_ulogsize = 0\n iprop_master_ulogsize = 9", 9),
            ("iprop_ulogsize = -4", DEF_ULOGENTRIES),
            ("iprop_ulogsize = big", DEF_ULOGENTRIES),
            ("iprop_ulogsize = 12abc", 12),
            ("iprop_ulogsize = 0", DEF_ULOGENTRIES),
        ] {
            let conf = profile(&format!("[realms]\n R.TEST = {{\n {rels}\n }}\n"), "");
            let p = IpropParams::for_realm(Some(&conf), "R.TEST", Path::new("p"));
            assert_eq!(p.ulogsize, want, "{rels}");
        }
    }

    /// Settled live: MIT 1.22.2's kadmin.local and kdb5_util stop with "Required parameters in
    /// kdc.conf missing" when `iprop_enable` is true and no `iprop_port` is set.
    #[test]
    fn iprop_without_a_port_is_missing_a_required_parameter() {
        let conf = profile("[realms]\n R.TEST = {\n  iprop_enable = true\n }\n", "");
        let p = IpropParams::for_realm(Some(&conf), "R.TEST", Path::new("p"));
        assert!(p.missing_required());
        let conf = profile(
            "[realms]\n R.TEST = {\n  iprop_enable = true\n  iprop_port = x\n  \
             iprop_logfile = /var/log/r.ulog\n }\n",
            "",
        );
        let p = IpropParams::for_realm(Some(&conf), "R.TEST", Path::new("p"));
        assert!(p.missing_required(), "a port that is no number is not set");
        assert_eq!(p.logfile, PathBuf::from("/var/log/r.ulog"));
    }

    #[test]
    fn sscanf_reads_a_leading_number() {
        assert_eq!(sscanf_int(" +42x"), Some(42));
        assert_eq!(sscanf_int("-7"), Some(-7));
        assert_eq!(sscanf_int("x1"), None);
        assert_eq!(sscanf_int("-"), None);
        assert_eq!(sscanf_int("99999999999"), None);
    }
}
