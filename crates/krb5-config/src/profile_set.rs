use std::path::PathBuf;

use super::{Error, KdcConf, KdcPaths, Krb5Conf, krb5_conf_paths, load_krb5_conf_paths};

// MIT: `krb5int_init_context_kdc` (lib/krb5/krb/init_ctx.c:149-152)
// the KDC context reads one profile, kdc.conf and then the krb5.conf files.
#[derive(Clone, Debug)]
pub struct ProfileSet {
    pub realm: String,
    pub krb5: Krb5Conf,
    pub kdc: Option<KdcConf>,
    pub kdc_context: Krb5Conf,
}

impl ProfileSet {
    pub fn from_text(realm: &str, krb5_conf: &str, kdc_conf: Option<&str>) -> Result<Self, Error> {
        let krb5 = Krb5Conf::parse(krb5_conf)?;
        let kdc_context = match kdc_conf {
            Some(text) => Krb5Conf::parse_files(&[text, krb5_conf])?,
            None => krb5.clone(),
        };
        Ok(Self {
            realm: realm.to_owned(),
            krb5,
            kdc: kdc_conf
                .map(|t| KdcConf::parse_for_realm(t, realm))
                .transpose()?,
            kdc_context,
        })
    }

    #[must_use]
    pub fn from_structs(realm: &str, krb5: Krb5Conf, kdc: Option<KdcConf>) -> Self {
        Self {
            realm: realm.to_owned(),
            kdc_context: krb5.clone(),
            krb5,
            kdc,
        }
    }

    pub fn from_env_files(paths: &KdcPaths) -> Result<Self, Error> {
        let files = krb5_conf_paths();
        let mut kdc_files = vec![paths.profile.clone()];
        kdc_files.extend(files.iter().cloned());
        Ok(Self {
            realm: paths.realm.clone().unwrap_or_default(),
            krb5: load_or_defaults(files)?,
            kdc: paths.conf.clone(),
            kdc_context: load_or_defaults(kdc_files)?,
        })
    }
}

fn load_or_defaults(paths: Vec<PathBuf>) -> Result<Krb5Conf, Error> {
    match load_krb5_conf_paths(paths) {
        Ok(conf) => Ok(conf),
        Err(Error::Io(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            Ok(Krb5Conf::new())
        }
        Err(e) => Err(e),
    }
}
