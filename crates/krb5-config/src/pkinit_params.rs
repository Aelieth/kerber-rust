use super::Krb5Conf;
use super::profile::truthy;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PkinitParams {
    pub identity: Option<String>,
    pub anchors: Vec<String>,
    pub pool: Vec<String>,
    pub revoke: Vec<String>,
    pub kdc_ocsp: Option<String>,
    pub require_crl_checking: bool,
    pub require_freshness: bool,
    pub require_eku: bool,
    pub accept_secondary_eku: bool,
    pub allow_upn: bool,
    pub indicators: Vec<String>,
    pub dh_min_bits: Option<String>,
}

impl PkinitParams {
    // MIT: `pkinit_kdcdefault_strings` (plugins/preauth/pkinit/pkinit_profile.c:90-144)
    // The realm's values, else `[kdcdefaults]`'s.
    // MIT: `pkinit_kdcdefault_string` (plugins/preauth/pkinit/pkinit_profile.c:147-167)
    // The first of those values.
    // MIT: `pkinit_kdcdefault_boolean` (plugins/preauth/pkinit/pkinit_profile.c)
    // MIT: `pkinit_init_kdc_profile` (plugins/preauth/pkinit/pkinit_srv.c)
    #[must_use]
    pub fn for_realm(profile: &Krb5Conf, realm: &str) -> Self {
        let realm_relations = profile.pkinit.get(realm).map_or(&[][..], Vec::as_slice);
        let values = |name: &str| -> Vec<String> {
            let pick = |relations: &[(String, String)]| -> Vec<String> {
                relations
                    .iter()
                    .filter(|(k, _)| k == name)
                    .map(|(_, v)| v.clone())
                    .collect()
            };
            let own = pick(realm_relations);
            if own.is_empty() {
                pick(&profile.kdcdefaults_pkinit)
            } else {
                own
            }
        };
        let first = |name: &str| values(name).into_iter().next();
        let boolean = |name: &str| first(name).is_some_and(|v| truthy(&v));
        let (require_eku, accept_secondary_eku) = match first("pkinit_eku_checking") {
            Some(v) if v.eq_ignore_ascii_case("scLogin") => (true, true),
            Some(v) if v.eq_ignore_ascii_case("none") => (false, false),
            _ => (true, false),
        };
        Self {
            identity: first("pkinit_identity"),
            anchors: values("pkinit_anchors"),
            pool: values("pkinit_pool"),
            revoke: values("pkinit_revoke"),
            kdc_ocsp: first("pkinit_kdc_ocsp"),
            require_crl_checking: boolean("pkinit_require_crl_checking"),
            require_freshness: boolean("pkinit_require_freshness"),
            require_eku,
            accept_secondary_eku,
            allow_upn: boolean("pkinit_allow_upn"),
            indicators: values("pkinit_indicator"),
            dh_min_bits: first("pkinit_dh_min_bits"),
        }
    }
}

impl Krb5Conf {
    // MIT: `pkinit_libdefault_strings` (plugins/preauth/pkinit/pkinit_profile.c)
    #[must_use]
    pub fn pkinit_libdefault_strings(&self, realm: &str, option: &str) -> Vec<String> {
        let values = |rels: Option<&Vec<(String, String)>>| -> Vec<String> {
            rels.into_iter()
                .flatten()
                .filter(|(k, _)| k == option)
                .map(|(_, v)| v.clone())
                .collect()
        };
        [
            values(self.realm_libdefaults_pkinit.get(realm)),
            values(self.pkinit.get(realm)),
            values(Some(&self.libdefaults_pkinit)),
        ]
        .into_iter()
        .find(|v| !v.is_empty())
        .unwrap_or_default()
    }
}
