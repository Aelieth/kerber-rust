//! Credential-cache names (`os/ccdefname.c` `get_from_os` /
//! `krb5_cc_default_name` / `k5_expand_path_tokens`;
//! `ccache/ccbase.c` `krb5_cc_resolve`; `ccache/ccdefault.c`
//! `krb5_cc_default`; `ccache/cc_file.c` `fcc_resolve`;
//! `ccache/cc_memory.c` `krb5_mcc_resolve`; `ccache/cc_dir.c`
//! `dcc_resolve`; `ccache/cc_kcm.c` `kcm_resolve`): `TYPE:residual`
//! and `%{uid}` expansion.

use std::path::PathBuf;

use super::CcSpec;
use super::Error;
use super::profile::load_krb5_conf;

/// MIT `KRB5_CC_UNKNOWN_TYPE`.
pub const KRB5_CC_UNKNOWN_TYPE: &str = "Unknown credential cache type";

const BUILTIN_CCACHE: &str = "FILE:/tmp/krb5cc_%{uid}";

/// Expand MIT `default_ccache_name` tokens (`%{uid}` / `%{USERID}` / `%{euid}`).
///
/// # Errors
///
/// Unknown `%{token}` or unterminated `%{` (MIT fails closed).
pub fn expand_ccache_params(s: &str) -> Result<String, Error> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("%{") {
        out.push_str(&rest[..start]);
        rest = &rest[start + 2..];
        let Some(end) = rest.find('}') else {
            return Err(Error::Ccache("unterminated %{token}".into()));
        };
        let token = &rest[..end];
        rest = &rest[end + 1..];
        out.push_str(&ccache_param(token)?);
    }
    out.push_str(rest);
    Ok(out)
}

fn ccache_param(token: &str) -> Result<String, Error> {
    match token {
        "uid" | "USERID" => Ok(unix_uid().to_string()),
        "euid" => Ok(unix_euid().to_string()),
        "null" => Ok(String::new()),
        "TEMP" => Ok("/tmp".into()),
        "username" => Ok(unix_username()),
        _ => Err(Error::Ccache(format!(
            "unknown ccache parameter %{{{token}}}"
        ))),
    }
}

pub(super) fn unix_uid() -> u32 {
    #[cfg(unix)]
    {
        nix::unistd::Uid::current().as_raw()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

pub(super) fn unix_euid() -> u32 {
    #[cfg(unix)]
    {
        nix::unistd::Uid::effective().as_raw()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn unix_username() -> String {
    #[cfg(unix)]
    {
        nix::unistd::User::from_uid(nix::unistd::Uid::effective())
            .ok()
            .flatten()
            .map(|u| u.name)
            .unwrap_or_default()
    }
    #[cfg(not(unix))]
    {
        String::new()
    }
}

/// `-c` flag, else `KRB5CCNAME`, else conf `default_ccache_name`, else builtin.
///
/// # Errors
///
/// [`KRB5_CC_UNKNOWN_TYPE`] or an unknown `%{token}`.
pub fn resolve_ccspec(flag: Option<&str>) -> Result<CcSpec, Error> {
    if let Some(s) = flag {
        return parse_ccspec(s);
    }
    if let Some(v) = std::env::var_os("KRB5CCNAME") {
        return parse_ccspec(&v.to_string_lossy());
    }
    default_ccspec()
}

/// Conf `default_ccache_name` after token expansion, else builtin FILE.
///
/// # Errors
///
/// Unknown `%{token}` or [`KRB5_CC_UNKNOWN_TYPE`].
pub fn default_ccspec() -> Result<CcSpec, Error> {
    let raw = load_krb5_conf()
        .and_then(|c| c.default_ccache_name)
        .unwrap_or_else(|| BUILTIN_CCACHE.to_owned());
    parse_ccspec(&expand_ccache_params(&raw)?)
}

/// Split `TYPE:residual`. A residual with no type prefix is FILE.
///
/// # Errors
///
/// [`KRB5_CC_UNKNOWN_TYPE`] for unrecognized or unbuilt prefixes.
pub fn parse_ccspec(spec: &str) -> Result<CcSpec, Error> {
    match split_cc_type(spec) {
        None => Ok(CcSpec::File(PathBuf::from(spec))),
        Some(("FILE", rest)) => Ok(CcSpec::File(PathBuf::from(rest))),
        Some(("MEMORY", rest)) => Ok(CcSpec::Memory(rest.to_owned())),
        Some(("DIR", rest)) => Ok(CcSpec::Dir(rest.to_owned())),
        Some(("KCM", rest)) => Ok(CcSpec::Kcm(rest.to_owned())),
        Some(_) => Err(Error::Ccache(KRB5_CC_UNKNOWN_TYPE.to_owned())),
    }
}

/// FILE residual, or a bare path.
///
/// # Errors
///
/// [`KRB5_CC_UNKNOWN_TYPE`].
pub fn parse_ccname(spec: &str) -> Result<PathBuf, Error> {
    match parse_ccspec(spec)? {
        CcSpec::File(p) => Ok(p),
        _ => Err(Error::Ccache(KRB5_CC_UNKNOWN_TYPE.to_owned())),
    }
}

fn split_cc_type(spec: &str) -> Option<(&str, &str)> {
    let (ty, rest) = spec.split_once(':')?;
    if ty.is_empty() {
        return None;
    }
    if !ty.bytes().all(|b| b.is_ascii_alphabetic() || b == b'_') {
        return None;
    }
    Some((ty, rest))
}

/// Builtin `FILE:/tmp/krb5cc_%{uid}` residual (no conf).
#[must_use]
pub fn default_ccache_name() -> PathBuf {
    PathBuf::from(format!("/tmp/krb5cc_{}", unix_uid()))
}
