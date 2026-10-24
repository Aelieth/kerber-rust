use super::{KdcConf, Krb5Conf, kdc_conf_path, load_krb5_conf};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LogSpecs {
    pub specs: Vec<String>,
    pub debug: bool,
    pub json: Option<String>,
}

impl LogSpecs {
    // MIT krb5_klog_init; see docs/parity/a3-preauth.md
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

    #[must_use]
    pub fn load(ename: &str) -> Self {
        let kdc = kdc_conf_logging();
        let krb5 = load_krb5_conf();
        Self::for_program(kdc.as_ref(), krb5.as_ref(), ename)
    }

    #[must_use]
    pub fn load_json() -> Option<String> {
        let kdc = kdc_conf_logging();
        let krb5 = load_krb5_conf();
        json_value(&relations(kdc.as_ref(), krb5.as_ref()))
    }
}

fn kdc_conf_logging() -> Option<KdcConf> {
    KdcConf::load_file_without_realms(kdc_conf_path()).ok()
}

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

fn json_value(relations: &[&(String, String)]) -> Option<String> {
    relations
        .iter()
        .find(|(k, _)| k == "json")
        .map(|(_, v)| v.clone())
}

// MIT profile_parse_boolean; see docs/parity/b1-client.md
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
