//! One KDC-side program's profile, read once: its realm's kdc.conf and krb5.conf's relations,
//! which the program applies in one place and one order (`krb5_kdc::PrincipalStore::apply_profile`).

use super::{Error, KdcConf, KdcPaths, Krb5Conf, krb5_conf_paths, load_krb5_conf_paths};

/// A KDC-side program's profile for one realm: krb5.conf's relations and the realm's kdc.conf,
/// each with its includes followed when read from a file.
/// MIT `krb5int_init_context_kdc` (`lib/krb5/krb/init_ctx.c:149-152`): the KDC context reads one profile, kdc.conf and then the krb5.conf files.
#[derive(Clone, Debug)]
pub struct ProfileSet {
    /// The realm served.
    pub realm: String,
    /// krb5.conf's relations; [`Krb5Conf::new`]'s defaults when no file is there.
    pub krb5: Krb5Conf,
    /// The realm's kdc.conf; `None` when there is no KDC profile.
    pub kdc: Option<KdcConf>,
}

impl ProfileSet {
    /// The profile from texts the caller holds: no file and no environment is read, and an
    /// `include` line is not followed.
    ///
    /// # Errors
    ///
    /// As [`Krb5Conf::parse`] and [`KdcConf::parse_for_realm`].
    pub fn from_text(realm: &str, krb5_conf: &str, kdc_conf: Option<&str>) -> Result<Self, Error> {
        Ok(Self {
            realm: realm.to_owned(),
            krb5: Krb5Conf::parse(krb5_conf)?,
            kdc: kdc_conf
                .map(|t| KdcConf::parse_for_realm(t, realm))
                .transpose()?,
        })
    }

    /// The profile from structs the caller built.
    #[must_use]
    pub fn from_structs(realm: &str, krb5: Krb5Conf, kdc: Option<KdcConf>) -> Self {
        Self {
            realm: realm.to_owned(),
            krb5,
            kdc,
        }
    }

    /// The profile a daemon reads: the krb5.conf files `KRB5_CONFIG` names (else
    /// `/etc/krb5.conf`), and the realm's kdc.conf as `paths` resolved it.
    /// MIT `profile_init_flags` (`util/profile/prof_init.c:198-206`): a missing or unreadable file is skipped, so its defaults apply.
    ///
    /// # Errors
    ///
    /// As [`load_krb5_conf_paths`], except that no krb5.conf file, or none that can be read, is
    /// the defaults.
    pub fn from_env_files(paths: &KdcPaths) -> Result<Self, Error> {
        let krb5 = match load_krb5_conf_paths(krb5_conf_paths()) {
            Ok(conf) => conf,
            Err(Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                Krb5Conf::new()
            }
            Err(e) => return Err(e),
        };
        Ok(Self {
            realm: paths.realm.clone().unwrap_or_default(),
            krb5,
            kdc: paths.conf.clone(),
        })
    }
}
