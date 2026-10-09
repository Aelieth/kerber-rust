//! `[logging]` (`lib/kadm5/logger.c` `krb5_klog_init`): where a daemon's log lines go. A
//! daemon's profile is kdc.conf followed by krb5.conf (`os/init_os_ctx.c`
//! `add_kdc_config_file`), so both files' `[logging]` sections count, kdc.conf's first.

use super::{KdcConf, Krb5Conf, kdc_conf_path, load_krb5_conf};

/// The `[logging]` destinations of one program (`kdc`, `admin_server`), as written: the strings
/// `krb5_log::klog` opens.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogSpecs {
    /// Every value of the program's relation across the profile, else every `default` value;
    /// empty when there is neither (the log then goes to syslog).
    pub specs: Vec<String>,
    /// `[logging] debug`: debug lines also go to the destinations that are not syslog.
    pub debug: bool,
    /// `[logging] json`, a relation MIT does not read: the destination of the JSON structured log
    /// (`krb5_log::klog::JsonLog`), the first value in the profile; `None` leaves it off.
    pub json: Option<String>,
}

impl LogSpecs {
    /// The destinations of program `ename` in the profile `kdc` then `krb5`.
    /// MIT `krb5_klog_init` (`lib/kadm5/logger.c:269-273`): every `[logging]` value of `ename`,
    /// and only when there is none, every value of `default`.
    /// MIT `krb5_klog_init` (`lib/kadm5/logger.c:252-254`): `debug` is the first value read as a
    /// boolean; a value that is not one leaves it off.
    #[must_use]
    pub fn for_program(kdc: Option<&KdcConf>, krb5: Option<&Krb5Conf>, ename: &str) -> Self {
        let relations = relations(kdc, krb5);
        let values = |name: &str| -> Vec<String> {
            relations
                .iter()
                .filter(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
                .collect()
        };
        let mut specs = values(ename);
        if specs.is_empty() {
            specs = values("default");
        }
        let debug = relations
            .iter()
            .find(|(k, _)| k == "debug")
            .and_then(|(_, v)| profile_boolean(v))
            .unwrap_or(false);
        Self {
            specs,
            debug,
            json: json_value(&relations),
        }
    }

    /// [`Self::for_program`] on the daemon's own profile: [`kdc_conf_path`] (a missing or
    /// unreadable file counts as empty) and the krb5.conf files.
    #[must_use]
    pub fn load(ename: &str) -> Self {
        let kdc = KdcConf::load_file(kdc_conf_path()).ok();
        let krb5 = load_krb5_conf();
        Self::for_program(kdc.as_ref(), krb5.as_ref(), ename)
    }

    /// The [`Self::json`] relation of that profile alone, for a program that keeps no
    /// MIT-format log (kprop, kpropd).
    #[must_use]
    pub fn load_json() -> Option<String> {
        let kdc = KdcConf::load_file(kdc_conf_path()).ok();
        let krb5 = load_krb5_conf();
        json_value(&relations(kdc.as_ref(), krb5.as_ref()))
    }
}

/// Every `[logging]` relation of the profile, kdc.conf's first.
fn relations<'a>(
    kdc: Option<&'a KdcConf>,
    krb5: Option<&'a Krb5Conf>,
) -> Vec<&'a (String, String)> {
    kdc.map(|c| c.logging.iter())
        .into_iter()
        .flatten()
        .chain(krb5.map(|c| c.logging.iter()).into_iter().flatten())
        .collect()
}

/// The first `json` value.
fn json_value(relations: &[&(String, String)]) -> Option<String> {
    relations
        .iter()
        .find(|(k, _)| k == "json")
        .map(|(_, v)| v.clone())
}

/// MIT `profile_parse_boolean` (`util/profile/prof_get.c:347-369`): the yes and no words, any
/// case; anything else is not a boolean.
fn profile_boolean(v: &str) -> Option<bool> {
    const YES: [&str; 6] = ["y", "yes", "true", "t", "1", "on"];
    const NO: [&str; 6] = ["n", "no", "false", "nil", "0", "off"];
    if YES.iter().any(|w| w.eq_ignore_ascii_case(v)) {
        Some(true)
    } else if NO.iter().any(|w| w.eq_ignore_ascii_case(v)) {
        Some(false)
    } else {
        None
    }
}
