//! What an acceptor takes from its profile, read once when the program starts, so that no request
//! reads a file: the values MIT's `krb5_rd_req`, `krb5_rd_priv`, `krb5_rd_safe` and GSS acceptor
//! take from their context.

use std::collections::BTreeMap;

use krb5_config::{Krb5Conf, ProfileSet};
use krb5_crypto::{EncryptionType, parse_enctype_list};

use crate::error::Error;

/// An acceptor's profile values, from one context's profile: krb5.conf's for a service
/// ([`AcceptorConfig::from_krb5_conf`]), the KDC context's for kadmind and kpropd
/// ([`AcceptorConfig::from_profile`]).
/// MIT `krb5_init_context_profile` (`lib/krb5/krb/init_ctx.c:235-252`): the context takes `ignore_acceptor_hostname` and `clockskew` from its profile when it is made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptorConfig {
    /// `[libdefaults] clockskew`, in seconds; 300 when it is unset. A negative skew fails every
    /// time check.
    pub clockskew: i32,
    /// `[libdefaults] permitted_enctypes` (MIT's `DEFAULT` when unset), less the weak enctypes
    /// unless `allow_weak_crypto` is set; empty when the list names no enctype, an empty value
    /// among them.
    pub permitted_enctypes: Vec<EncryptionType>,
    /// `[libdefaults] ignore_acceptor_hostname`.
    pub ignore_acceptor_hostname: bool,
    /// `[capaths]`, for the transited check of a cross-realm ticket.
    pub capaths: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

impl Default for AcceptorConfig {
    /// The values of an empty profile.
    fn default() -> Self {
        Self::from_krb5_conf(&Krb5Conf::new())
    }
}

impl AcceptorConfig {
    /// The values of the profile `conf`.
    /// MIT `krb5_get_permitted_enctypes` (`lib/krb5/krb/init_ctx.c:574-595`): the first `permitted_enctypes` the profile holds, else `DEFAULT`.
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

    /// The values of the KDC context's profile, kdc.conf ahead of krb5.conf, as kadmind's and
    /// kpropd's acceptors read them.
    /// MIT `kadm5_init_krb5_context` (`lib/kadm5/srv/server_init.c:334-344`): kadmind's GSS acceptor reads the KDC profile.
    #[must_use]
    pub fn from_profile(profile: &ProfileSet) -> Self {
        Self::from_krb5_conf(&profile.kdc_context)
    }

    /// The enctypes the acceptor permits.
    ///
    /// # Errors
    ///
    /// [`Error::ConfigEtypeNosupp`] when the profile's list names no enctype.
    /// MIT `krb5int_parse_enctype_list` (`lib/krb5/krb/init_ctx.c:497-500`): a list left empty is `KRB5_CONFIG_ETYPE_NOSUPP`.
    pub fn permitted(&self) -> Result<&[EncryptionType], Error> {
        if self.permitted_enctypes.is_empty() {
            return Err(Error::ConfigEtypeNosupp);
        }
        Ok(&self.permitted_enctypes)
    }
}
