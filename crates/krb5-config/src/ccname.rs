use std::path::PathBuf;

use super::CcSpec;
use super::Error;
use super::{ClientContext, Krb5Conf};

pub const KRB5_CC_UNKNOWN_TYPE: &str = "Unknown credential cache type";

const BUILTIN_CCACHE: &str = "FILE:/tmp/krb5cc_%{uid}";

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

pub fn resolve_ccspec(ctx: &ClientContext, flag: Option<&str>) -> Result<CcSpec, Error> {
    match flag.or(ctx.ccname()) {
        Some(s) => parse_ccspec(s),
        None => default_ccspec(&ctx.profile),
    }
}

pub fn default_ccspec(profile: &Krb5Conf) -> Result<CcSpec, Error> {
    let raw = profile
        .default_ccache_name
        .clone()
        .unwrap_or_else(|| BUILTIN_CCACHE.to_owned());
    parse_ccspec(&expand_ccache_params(&raw)?)
}

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

#[must_use]
pub fn default_ccache_name() -> PathBuf {
    PathBuf::from(format!("/tmp/krb5cc_{}", unix_uid()))
}
