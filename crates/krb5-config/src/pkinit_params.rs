//! A realm's KDC PKINIT parameters, read as MIT's `pkinit_init_kdc_profile` reads them
//! (`plugins/preauth/pkinit/pkinit_srv.c`) from the KDC's profile: kdc.conf, then the krb5.conf
//! files.

use super::Krb5Conf;
use super::profile::truthy;

/// One realm's KDC PKINIT options. `identity` and `anchors` are required for the module to
/// initialize; the KDC checks that, as MIT's init does.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PkinitParams {
    /// `pkinit_identity`, the first value.
    pub identity: Option<String>,
    /// `pkinit_anchors`, every value.
    pub anchors: Vec<String>,
    /// `pkinit_pool`, every value.
    pub pool: Vec<String>,
    /// `pkinit_revoke`, every value.
    pub revoke: Vec<String>,
    /// `pkinit_kdc_ocsp`, the first value.
    pub kdc_ocsp: Option<String>,
    /// `pkinit_require_crl_checking` (default false).
    pub require_crl_checking: bool,
    /// `pkinit_require_freshness` (default false).
    pub require_freshness: bool,
    /// The client certificate needs an acceptable extended key usage (default true).
    pub require_eku: bool,
    /// Microsoft's smart-card logon key usage is acceptable too (default false).
    pub accept_secondary_eku: bool,
    /// `pkinit_allow_upn`: a client certificate's UPN may name the client (default false).
    pub allow_upn: bool,
    /// `pkinit_indicator`, every value.
    pub indicators: Vec<String>,
}

impl PkinitParams {
    /// The options of `realm` in `profile`, kdc.conf's relations first, then krb5.conf's.
    /// MIT `pkinit_kdcdefault_strings` (`plugins/preauth/pkinit/pkinit_profile.c:90-144`): the realm's values, else `[kdcdefaults]`'s.
    /// MIT `pkinit_kdcdefault_string` (`plugins/preauth/pkinit/pkinit_profile.c:147-167`): the first of those values.
    /// MIT `pkinit_kdcdefault_boolean` (`plugins/preauth/pkinit/pkinit_profile.c:170-185`): that value read as a yes word, else the default.
    /// MIT `pkinit_init_kdc_profile` (`plugins/preauth/pkinit/pkinit_srv.c:1016-1034`): `pkinit_eku_checking` is `kpClientAuth`, `scLogin` or `none` in any case; another value keeps the default.
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
        }
    }
}
