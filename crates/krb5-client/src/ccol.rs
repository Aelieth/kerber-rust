use std::path::{Path, PathBuf};

use krb5_config::{CcSpec, ClientContext};

use crate::creds::{Princ, princ_eq};
use crate::errmsg::{Code, Krb5Error};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cache {
    File(PathBuf),
    Dir(PathBuf),
    Kcm(String),
    Memory(String),
}

impl Cache {
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::File(_) => "FILE",
            Self::Dir(_) => "DIR",
            Self::Kcm(_) => "KCM",
            Self::Memory(_) => "MEMORY",
        }
    }

    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::File(p) => p.display().to_string(),
            Self::Dir(p) => format!(":{}", p.display()),
            Self::Kcm(n) | Self::Memory(n) => n.clone(),
        }
    }

    #[must_use]
    pub fn full_name(&self) -> String {
        format!("{}:{}", self.type_name(), self.name())
    }

    #[must_use]
    pub fn spec(&self) -> CcSpec {
        match self {
            Self::File(p) => CcSpec::File(p.clone()),
            Self::Dir(p) => CcSpec::Dir(format!(":{}", p.display())),
            Self::Kcm(n) => CcSpec::Kcm(n.clone()),
            Self::Memory(n) => CcSpec::Memory(n.clone()),
        }
    }

    pub fn principal(&self, ctx: &ClientContext) -> Result<Princ, Krb5Error> {
        if let Self::Kcm(n) = self {
            return krb5_protocol::kcm_principal(&ctx.profile, n).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Krb5Error::new(
                        Code::FccNofile,
                        format!("Credentials cache 'KCM:{n}' not found"),
                    )
                } else {
                    Krb5Error::from_kcm(&e)
                }
            });
        }
        let spec = self.spec();
        crate::load_ccache(ctx, &spec)
            .map(|cc| cc.primary)
            .map_err(|e| crate::cache_read_error(ctx, &spec, e.as_ref()))
    }

    pub fn destroy(&self, ctx: &ClientContext) -> Result<(), Krb5Error> {
        // MIT: `krb5_cc_destroy` (lib/krb5/ccache/ccfns.c:66-71)
        // The destroy is traced first.
        if krb5_protocol::trace::enabled() {
            krb5_protocol::trace::cc_destroy(&self.full_name());
        }
        crate::destroy_ccache(ctx, &self.spec()).map_err(|e| {
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

    // MIT: `krb5_cc_support_switch` (ccbase.c:457-465)
    #[must_use]
    pub const fn supports_switch(&self) -> bool {
        matches!(self, Self::Dir(_) | Self::Kcm(_))
    }

    // MIT: `krb5_cc_switch` (lib/krb5/ccache/ccfns.c:294-300)
    // MIT: `dcc_switch_to` (cc_dir.c:719-741)
    // A DIR collection's `primary` file names it.
    // MIT: `kcm_switch_to` (cc_kcm.c:1330-1340)
    // SET_DEFAULT_CACHE.
    pub fn switch_to(&self, ctx: &ClientContext) -> Result<(), Krb5Error> {
        let other = |e: std::io::Error| Krb5Error::new(Code::Other, e.to_string());
        match self {
            Self::Dir(p) => krb5_protocol::dir_switch(&format!(":{}", p.display())).map_err(other),
            Self::Kcm(n) => {
                krb5_protocol::kcm_switch(&ctx.profile, n).map_err(|e| Krb5Error::from_kcm(&e))
            }
            Self::File(_) | Self::Memory(_) => Ok(()),
        }
    }
}

// MIT: `dcc_resolve` (cc_dir.c:331-385)
// MIT: `kcm_resolve` (cc_kcm.c:740-768)
pub fn resolve(ctx: &ClientContext, spec: &CcSpec) -> Result<Cache, Krb5Error> {
    let other = |e: std::io::Error| Krb5Error::new(Code::Other, e.to_string());
    let kcm = |e: std::io::Error| Krb5Error::from_kcm(&e);
    Ok(match spec {
        CcSpec::File(p) => Cache::File(p.clone()),
        CcSpec::Memory(n) => Cache::Memory(n.clone()),
        CcSpec::Dir(r) => Cache::Dir(krb5_protocol::dir_cache_path(r).map_err(other)?),
        CcSpec::Kcm(n) if n.is_empty() => {
            Cache::Kcm(krb5_protocol::kcm_primary_name(&ctx.profile).map_err(kcm)?)
        }
        CcSpec::Kcm(n) => {
            krb5_protocol::kcm_reachable(&ctx.profile).map_err(kcm)?;
            Cache::Kcm(n.clone())
        }
    })
}

#[must_use]
pub fn store_spec(name: &CcSpec, cache: &Cache) -> CcSpec {
    match name {
        CcSpec::Dir(r) if !r.starts_with(':') => name.clone(),
        _ => cache.spec(),
    }
}

// MIT: `krb5_cccol_cursor_next` (cccursor.c:83-124)
// MIT: `fcc_ptcursor_next` (cc_file.c:1205-1241)
// MIT: `dcc_ptcursor_next` (cc_dir.c:634-677)
// MIT: `kcm_ptcursor_next` (cc_kcm.c:1210-1263)
pub fn collection(ctx: &ClientContext, default: &CcSpec) -> Result<Vec<Cache>, Krb5Error> {
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
        CcSpec::Kcm(n) if !n.is_empty() => {
            // MIT: `kcm_ptcursor_new` (cc_kcm.c:1155-1157)
            krb5_protocol::kcm_reachable(&ctx.profile).map_err(|e| Krb5Error::from_kcm(&e))?;
            Ok(if krb5_protocol::kcm_principal(&ctx.profile, n).is_ok() {
                vec![Cache::Kcm(n.clone())]
            } else {
                Vec::new()
            })
        }
        CcSpec::Kcm(_) => {
            let kcm = |e: std::io::Error| Krb5Error::from_kcm(&e);
            let names = krb5_protocol::kcm_cache_names(&ctx.profile).map_err(kcm)?;
            if names.is_empty() {
                return Ok(Vec::new());
            }
            let primary = krb5_protocol::kcm_primary_name(&ctx.profile).map_err(kcm)?;
            let mut out = Vec::new();
            if krb5_protocol::kcm_principal(&ctx.profile, &primary).is_ok() {
                out.push(Cache::Kcm(primary.clone()));
            }
            out.extend(names.into_iter().filter(|n| *n != primary).map(Cache::Kcm));
            Ok(out)
        }
    }
}

// MIT: `krb5_cc_cache_match` (cccursor.c:183-219)
// MIT: `match_caches` (cccursor.c:145-181)
// A cache that is not initialized is passed over.
pub fn cache_match(
    ctx: &ClientContext,
    default: &CcSpec,
    princ: &Princ,
) -> Result<Cache, Krb5Error> {
    let found = collection(ctx, default)?
        .into_iter()
        .find(|c| c.principal(ctx).is_ok_and(|p| princ_eq(&p, princ)));
    crate::trace::cache_match(princ, found.is_some());
    found.ok_or_else(|| Krb5Error::of(Code::CcNotfound))
}

// MIT: `krb5_cc_new_unique` (ccbase.c:289-307)
// A new cache in the collection of `default`.
// MIT: `dcc_gen_new` (cc_dir.c:387-429)
// Only a DIR collection name (not a `DIR::` subsidiary)
// MIT: `kcm_gen_new` (cc_kcm.c:795-822)
// GEN_NEW names it.
pub fn new_unique(ctx: &ClientContext, default: &CcSpec) -> Result<Cache, Krb5Error> {
    let other = |e: std::io::Error| Krb5Error::new(Code::Other, e.to_string());
    krb5_protocol::trace::cc_new_unique(match default {
        CcSpec::File(_) => "FILE",
        CcSpec::Dir(_) => "DIR",
        CcSpec::Kcm(_) => "KCM",
        CcSpec::Memory(_) => "MEMORY",
    });
    match default {
        CcSpec::Dir(r) if !r.starts_with(':') => krb5_protocol::dir_gen_new(Path::new(r))
            .map(Cache::Dir)
            .map_err(other),
        CcSpec::Kcm(_) => krb5_protocol::kcm_gen_new(&ctx.profile)
            .map(Cache::Kcm)
            .map_err(|e| Krb5Error::from_kcm(&e)),
        _ => Err(Krb5Error::new(
            Code::Other,
            "Can't create new subsidiary cache because default cache is not a directory collection",
        )),
    }
}
