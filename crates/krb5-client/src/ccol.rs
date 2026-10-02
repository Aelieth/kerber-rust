//! MIT's cache collection: a cache resolved to its concrete name, the collection of the default
//! name's type (its primary first), the match by principal, a new cache in the collection, and
//! the switch of the primary.

use std::path::{Path, PathBuf};

use krb5_config::CcSpec;

use crate::creds::{Princ, princ_eq};
use crate::errmsg::{Code, Krb5Error};

/// One concrete cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cache {
    /// A FILE cache.
    File(PathBuf),
    /// A DIR collection's subsidiary file.
    Dir(PathBuf),
    /// A KCM cache, by name.
    Kcm(String),
    /// A MEMORY cache, by name.
    Memory(String),
}

impl Cache {
    /// MIT `krb5_cc_get_type`.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::File(_) => "FILE",
            Self::Dir(_) => "DIR",
            Self::Kcm(_) => "KCM",
            Self::Memory(_) => "MEMORY",
        }
    }

    /// MIT `krb5_cc_get_name`: a FILE cache's path, a DIR subsidiary's `:path`, a KCM or MEMORY
    /// cache's name.
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::File(p) => p.display().to_string(),
            Self::Dir(p) => format!(":{}", p.display()),
            Self::Kcm(n) | Self::Memory(n) => n.clone(),
        }
    }

    /// MIT `krb5_cc_get_full_name`: `TYPE:name`.
    #[must_use]
    pub fn full_name(&self) -> String {
        format!("{}:{}", self.type_name(), self.name())
    }

    /// The name the cache functions of this crate take.
    #[must_use]
    pub fn spec(&self) -> CcSpec {
        match self {
            Self::File(p) => CcSpec::File(p.clone()),
            Self::Dir(p) => CcSpec::Dir(format!(":{}", p.display())),
            Self::Kcm(n) => CcSpec::Kcm(n.clone()),
            Self::Memory(n) => CcSpec::Memory(n.clone()),
        }
    }

    /// MIT `krb5_cc_get_principal`: the default principal of an initialized cache.
    ///
    /// # Errors
    ///
    /// [`Krb5Error`] `KRB5_FCC_NOFILE` for a cache that does not exist or is not initialized,
    /// with MIT's message for its type, or the read error.
    pub fn principal(&self) -> Result<Princ, Krb5Error> {
        if let Self::Kcm(n) = self {
            return krb5_protocol::kcm_principal(n).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Krb5Error::new(
                        Code::FccNofile,
                        format!("Credentials cache 'KCM:{n}' not found"),
                    )
                } else {
                    Krb5Error::new(Code::Other, e.to_string())
                }
            });
        }
        let spec = self.spec();
        crate::load_ccache(&spec)
            .map(|cc| cc.primary)
            .map_err(|e| crate::cache_read_error(&spec, e.as_ref()))
    }

    /// MIT `krb5_cc_destroy`.
    ///
    /// # Errors
    ///
    /// [`Krb5Error`] `KRB5_FCC_NOFILE` "No credentials cache found" when there is no such cache,
    /// or the error of the removal.
    pub fn destroy(&self) -> Result<(), Krb5Error> {
        crate::destroy_ccache(&self.spec()).map_err(|e| {
            let missing = e
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
                || e.to_string() == "No credentials cache found";
            if missing {
                Krb5Error::of(Code::FccNofile)
            } else {
                Krb5Error::new(Code::Other, e.to_string())
            }
        })
    }

    /// MIT `krb5_cc_support_switch` (`ccbase.c:457-465`): a DIR or KCM cache can become its
    /// collection's primary.
    #[must_use]
    pub const fn supports_switch(&self) -> bool {
        matches!(self, Self::Dir(_) | Self::Kcm(_))
    }

    /// MIT `krb5_cc_switch` (`ccfns.c:294-300`): make this cache its collection's primary; a type
    /// that cannot switch does nothing.
    /// MIT `dcc_switch_to` (`cc_dir.c:719-741`): a DIR collection's `primary` file names it.
    /// MIT `kcm_switch_to` (`cc_kcm.c:1330-1340`): SET_DEFAULT_CACHE.
    ///
    /// # Errors
    ///
    /// [`Krb5Error`] with the error of the `primary` write or the KCM request.
    pub fn switch_to(&self) -> Result<(), Krb5Error> {
        let other = |e: std::io::Error| Krb5Error::new(Code::Other, e.to_string());
        match self {
            Self::Dir(p) => krb5_protocol::dir_switch(&format!(":{}", p.display())).map_err(other),
            Self::Kcm(n) => krb5_protocol::kcm_switch(n).map_err(other),
            Self::File(_) | Self::Memory(_) => Ok(()),
        }
    }
}

/// MIT `krb5_cc_resolve`: the concrete cache a name stands for.
/// MIT `dcc_resolve` (`cc_dir.c:331-385`): a DIR collection name stands for its primary, `tkt`
/// when there is no `primary` file. MIT makes a missing collection there; a resolve here is a
/// read, which leaves it missing ([`crate::dir_read_path`]), and the store makes it.
/// MIT `kcm_resolve` (`cc_kcm.c:740-768`): the empty KCM name stands for the collection's
/// primary.
///
/// # Errors
///
/// [`Krb5Error`] when a DIR collection cannot be read, or the KCM daemon cannot be asked.
pub fn resolve(spec: &CcSpec) -> Result<Cache, Krb5Error> {
    let other = |e: std::io::Error| Krb5Error::new(Code::Other, e.to_string());
    Ok(match spec {
        CcSpec::File(p) => Cache::File(p.clone()),
        CcSpec::Memory(n) => Cache::Memory(n.clone()),
        CcSpec::Dir(r) => Cache::Dir(crate::dir_read_path(r).map_err(other)?),
        CcSpec::Kcm(n) if n.is_empty() => {
            Cache::Kcm(krb5_protocol::kcm_primary_name().map_err(other)?)
        }
        CcSpec::Kcm(n) => Cache::Kcm(n.clone()),
    })
}

/// The name kinit writes a cache it resolved from `name` under: a DIR collection's own name, so
/// that the store makes a missing collection, the directory and a `primary` naming `tkt`, as MIT
/// makes it on the resolve; any other cache under its own name.
#[must_use]
pub fn store_spec(name: &CcSpec, cache: &Cache) -> CcSpec {
    match name {
        CcSpec::Dir(r) if !r.starts_with(':') => name.clone(),
        _ => cache.spec(),
    }
}

/// MIT `krb5_cccol_cursor_next` (`cccursor.c:83-124`): the caches of the collection the default
/// name `default` belongs to, its primary first.
/// MIT `fcc_ptcursor_next` (`cc_file.c:1205-1241`): a FILE default is a collection of itself,
/// when its file exists.
/// MIT `dcc_ptcursor_next` (`cc_dir.c:634-677`): a DIR collection lists the primary, when its file
/// exists, then every other `tkt*` file; a `DIR::` subsidiary default is a collection of itself.
/// MIT `kcm_ptcursor_next` (`cc_kcm.c:1210-1263`): a KCM collection lists the primary, when it is
/// initialized, then every other cache; a named KCM default is a collection of itself.
///
/// # Errors
///
/// [`Krb5Error`] when a DIR collection cannot be listed or the KCM daemon cannot be asked.
pub fn collection(default: &CcSpec) -> Result<Vec<Cache>, Krb5Error> {
    let other = |e: std::io::Error| Krb5Error::new(Code::Other, e.to_string());
    match default {
        CcSpec::File(p) => Ok(if p.exists() {
            vec![Cache::File(p.clone())]
        } else {
            Vec::new()
        }),
        CcSpec::Memory(_) => Ok(Vec::new()),
        CcSpec::Dir(r) => {
            if let Some(file) = r.strip_prefix(':') {
                let p = PathBuf::from(file);
                return Ok(if p.exists() {
                    vec![Cache::Dir(p)]
                } else {
                    Vec::new()
                });
            }
            let dir = Path::new(r);
            if !dir.is_dir() {
                return Ok(Vec::new());
            }
            let primary = krb5_protocol::dir_primary(dir).filter(|p| p.exists());
            let mut out: Vec<Cache> = primary.iter().cloned().map(Cache::Dir).collect();
            for p in krb5_protocol::dir_subsidiaries(dir).map_err(other)? {
                if primary.as_ref() != Some(&p) {
                    out.push(Cache::Dir(p));
                }
            }
            Ok(out)
        }
        CcSpec::Kcm(n) if !n.is_empty() => Ok(if krb5_protocol::kcm_principal(n).is_ok() {
            vec![Cache::Kcm(n.clone())]
        } else {
            Vec::new()
        }),
        CcSpec::Kcm(_) => {
            let names = krb5_protocol::kcm_cache_names().map_err(other)?;
            if names.is_empty() {
                return Ok(Vec::new());
            }
            let primary = krb5_protocol::kcm_primary_name().map_err(other)?;
            let mut out = Vec::new();
            if krb5_protocol::kcm_principal(&primary).is_ok() {
                out.push(Cache::Kcm(primary.clone()));
            }
            out.extend(names.into_iter().filter(|n| *n != primary).map(Cache::Kcm));
            Ok(out)
        }
    }
}

/// MIT `krb5_cc_cache_match` (`cccursor.c:183-219`): the first cache of the collection whose
/// default principal is `princ`.
/// MIT `match_caches` (`cccursor.c:145-181`): a cache that is not initialized is passed over.
///
/// # Errors
///
/// [`Krb5Error`] `KRB5_CC_NOTFOUND` "Matching credential not found" when no cache is for `princ`,
/// or the collection's error.
pub fn cache_match(default: &CcSpec, princ: &Princ) -> Result<Cache, Krb5Error> {
    collection(default)?
        .into_iter()
        .find(|c| c.principal().is_ok_and(|p| princ_eq(&p, princ)))
        .ok_or_else(|| Krb5Error::of(Code::CcNotfound))
}

/// MIT `krb5_cc_new_unique` (`ccbase.c:289-307`): a new cache in the collection of `default`.
/// MIT `dcc_gen_new` (`cc_dir.c:387-429`): only a DIR collection name (not a `DIR::` subsidiary)
/// can make one.
/// MIT `kcm_gen_new` (`cc_kcm.c:795-822`): GEN_NEW names it.
///
/// # Errors
///
/// [`Krb5Error`] `KRB5_DCC_CANNOT_CREATE` for a default that is not a DIR collection, or the error
/// of the file creation or the KCM request.
pub fn new_unique(default: &CcSpec) -> Result<Cache, Krb5Error> {
    let other = |e: std::io::Error| Krb5Error::new(Code::Other, e.to_string());
    match default {
        CcSpec::Dir(r) if !r.starts_with(':') => krb5_protocol::dir_gen_new(Path::new(r))
            .map(Cache::Dir)
            .map_err(other),
        CcSpec::Kcm(_) => krb5_protocol::kcm_gen_new().map(Cache::Kcm).map_err(other),
        _ => Err(Krb5Error::new(
            Code::Other,
            "Can't create new subsidiary cache because default cache is not a directory collection",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_protocol::{FileCcache, realm};
    use krb5_types::PrincipalName;

    fn princ(name: &str) -> Princ {
        (
            realm("KERBER.TEST"),
            PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]),
        )
    }

    /// Live MIT 1.22.2 on a DIR collection: the primary first, a new
    /// subsidiary `tktXXXXXX` per principal, the match by principal, the switch.
    #[test]
    fn dir_collection_lists_primary_first_and_matches_by_principal() {
        let dir = krb5_testkit::scratch_dir("ccol-dir").join("cc");
        let _ = std::fs::remove_dir_all(&dir);
        let default = CcSpec::Dir(dir.display().to_string());
        assert_eq!(collection(&default).unwrap(), Vec::new());
        let primary = resolve(&default).unwrap();
        assert_eq!(primary, Cache::Dir(dir.join("tkt")));
        assert_eq!(primary.full_name(), format!("DIR::{}/tkt", dir.display()));
        // A read leaves a missing collection missing (docs/security.md); the store makes it.
        assert!(!dir.exists());
        assert_eq!(
            primary.principal().unwrap_err().message,
            format!(
                "No credentials cache found (filename: {}/tkt)",
                dir.display()
            )
        );
        crate::store_ccache(&primary.spec(), FileCcache::new(princ("alice"), Vec::new())).unwrap();
        let bob = new_unique(&default).unwrap();
        let Cache::Dir(bob_path) = &bob else {
            panic!("DIR cache expected");
        };
        assert!(
            bob_path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.len() == 9 && n.starts_with("tkt"))
        );
        FileCcache::new(princ("bob"), Vec::new())
            .write_file(bob_path)
            .unwrap();
        bob.switch_to().unwrap();
        let listed = collection(&default).unwrap();
        assert_eq!(listed, vec![bob.clone(), primary.clone()]);
        assert_eq!(cache_match(&default, &princ("alice")).unwrap(), primary);
        assert_eq!(
            cache_match(&default, &princ("carol")).unwrap_err().code,
            Code::CcNotfound
        );
        assert!(primary.supports_switch() && !Cache::File(dir.clone()).supports_switch());
        primary.destroy().unwrap();
        assert_eq!(primary.destroy().unwrap_err().code, Code::FccNofile);
        assert_eq!(collection(&default).unwrap(), vec![bob]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// MIT `fcc_ptcursor_next`: a FILE default is listed only when its file exists.
    #[test]
    fn file_collection_is_the_default_file_when_it_exists() {
        let path = krb5_testkit::scratch_dir("ccol-file").join("cc");
        let _ = std::fs::remove_file(&path);
        let default = CcSpec::File(path.clone());
        assert_eq!(collection(&default).unwrap(), Vec::new());
        let err = resolve(&default).unwrap().principal().unwrap_err();
        assert_eq!(
            err.message,
            format!("No credentials cache found (filename: {})", path.display())
        );
        FileCcache::new(princ("alice"), Vec::new())
            .write_file(&path)
            .unwrap();
        assert_eq!(
            collection(&default).unwrap(),
            vec![Cache::File(path.clone())]
        );
        assert!(new_unique(&default).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
