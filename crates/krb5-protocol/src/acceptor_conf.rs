//! Read once at startup, so no request reads a file.

use std::collections::BTreeMap;

use krb5_config::{Krb5Conf, ProfileSet};
use krb5_crypto::{EncryptionType, parse_enctype_list};

use crate::error::Error;

// MIT: `krb5_init_context_profile` (lib/krb5/krb/init_ctx.c:235-252)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptorConfig {
    /// Unset is 300 seconds.
    /// A negative skew fails every check.
    pub clockskew: i32,
    /// Weak enctypes stay out unless allow_weak_crypto is set.
    pub permitted_enctypes: Vec<EncryptionType>,
    pub ignore_acceptor_hostname: bool,
    /// For the transited check.
    pub capaths: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

impl Default for AcceptorConfig {
    fn default() -> Self {
        Self::from_krb5_conf(&Krb5Conf::new())
    }
}

impl AcceptorConfig {
    // MIT: `krb5_get_permitted_enctypes` (lib/krb5/krb/init_ctx.c:574-595)
    /// Unset permitted_enctypes is DEFAULT.
    #[must_use]
    pub fn from_krb5_conf(conf: &Krb5Conf) -> Self {
        let profstr = conf
            .permitted_enctypes
            .as_ref()
            .map_or_else(|| "DEFAULT".to_owned(), |names| names.join(" "));
        Self {
            clockskew: conf.clockskew,
            permitted_enctypes: parse_enctype_list(&profstr, conf.allow_weak_crypto)
                .unwrap_or_default(),
            ignore_acceptor_hostname: conf.ignore_acceptor_hostname,
            capaths: conf.capaths.clone(),
        }
    }

    // MIT: `kadm5_init_krb5_context` (lib/kadm5/srv/server_init.c:334-344)
    /// The KDC profile, kdc.conf ahead of krb5.conf.
    #[must_use]
    pub fn from_profile(profile: &ProfileSet) -> Self {
        Self::from_krb5_conf(&profile.kdc_context)
    }

    // MIT: `krb5int_parse_enctype_list` (lib/krb5/krb/init_ctx.c:497-500)
    /// An empty list is KRB5_CONFIG_ETYPE_NOSUPP.
    pub fn permitted(&self) -> Result<&[EncryptionType], Error> {
        if self.permitted_enctypes.is_empty() {
            return Err(Error::ConfigEtypeNosupp);
        }
        Ok(&self.permitted_enctypes)
    }
}
