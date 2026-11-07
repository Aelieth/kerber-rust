use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};

use dns_lookup::{AddrInfoHints, LookupErrorKind, getaddrinfo, getnameinfo};
use krb5_types::{NameError, PrincipalName, Realm, try_ascii};
use nix::libc::{AI_CANONNAME, NI_NAMEREQD, NI_NUMERICHOST};

use super::{CanonHost, Krb5Conf};

const RESOLV_CONF: &str = "/etc/resolv.conf";

// MIT: `krb5_sname_to_principal` (lib/krb5/os/sn2princ.c:347-352)
fn this_host() -> String {
    nix::unistd::gethostname()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default()
}

// MIT: `expand_hostname` (lib/krb5/os/sn2princ.c:89-154)
// Non-UTF-8 canonname panics: no name.
fn expand_hostname(host: &str, conf: &Krb5Conf, use_dns: bool) -> String {
    let dns = use_dns
        .then(|| {
            catch_unwind(AssertUnwindSafe(|| dns_name(host, conf.rdns)))
                .ok()
                .flatten()
        })
        .flatten();
    let mut name = dns.unwrap_or_else(|| qualify_shortname(host, conf));
    name.make_ascii_lowercase();
    if name.ends_with('.') {
        name.pop();
    }
    name
}

fn dns_name(host: &str, rdns: bool) -> Option<String> {
    let hints = AddrInfoHints {
        flags: AI_CANONNAME,
        ..AddrInfoHints::default()
    };
    let first = getaddrinfo(Some(host), None, Some(hints))
        .ok()?
        .next()?
        .ok()?;
    let reverse = rdns.then(|| getnameinfo(&first.sockaddr, NI_NAMEREQD).ok());
    reverse.flatten().map(|(name, _)| name).or(first.canonname)
}

// MIT: `doit` (kprop/kpropd.c:491-520)
#[must_use]
pub fn name_of_addr(sa: SocketAddr) -> Option<String> {
    const INET6_ADDRSTRLEN: usize = 46;
    let name = match catch_unwind(|| getnameinfo(&sa, 0)) {
        Ok(Ok((name, _))) => name,
        Ok(Err(e)) if !matches!(e.kind(), LookupErrorKind::IO) => return None,
        // Not UTF-8.
        _ => getnameinfo(&sa, NI_NUMERICHOST).ok()?.0,
    };
    (name.len() <= INET6_ADDRSTRLEN).then_some(name)
}

// MIT: `qualify_shortname` (lib/krb5/os/sn2princ.c:60-86)
fn qualify_shortname(host: &str, conf: &Krb5Conf) -> String {
    if host.contains('.') {
        return host.to_owned();
    }
    let domain = conf.qualify_shortname.clone().or_else(primary_domain);
    match domain.filter(|d| !d.is_empty()) {
        Some(d) => format!("{host}.{d}"),
        None => host.to_owned(),
    }
}

pub type HostPrinc = (Realm, PrincipalName);

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SnameError {
    #[error("Conversion to service principal undefined for name type")]
    UnsupportedNameType,
    #[error("Configuration file does not specify default realm")]
    NoDefaultRealm,
    #[error(transparent)]
    Name(#[from] NameError),
}

pub fn sname_to_principal(
    conf: &Krb5Conf,
    hostname: Option<&str>,
    sname: Option<&str>,
    name_type: i32,
) -> Result<HostPrinc, SnameError> {
    if name_type != PrincipalName::NT_UNKNOWN && name_type != PrincipalName::NT_SRV_HST {
        return Err(SnameError::UnsupportedNameType);
    }
    let local;
    let hostname = if let Some(h) = hostname {
        h
    } else {
        local = this_host();
        local.as_str()
    };
    let princ = (
        try_ascii("")?,
        PrincipalName::try_new(name_type, [sname.unwrap_or("host"), hostname])?,
    );
    if name_type == PrincipalName::NT_SRV_HST
        && conf.dns_canonicalize_hostname == CanonHost::Fallback
    {
        return Ok(princ);
    }
    let iter = CanonPrinc::new(conf, &princ);
    let (host, combined) = iter.expand(conf.dns_canonicalize_hostname == CanonHost::True);
    iter.with_host(&host, &combined)
}

// MIT: `k5_canonprinc` (lib/krb5/os/sn2princ.c:279-285)
#[derive(Debug)]
pub struct CanonPrinc<'a> {
    conf: &'a Krb5Conf,
    princ: &'a HostPrinc,
    pub no_hostrealm: bool,
    pub subst_defrealm: bool,
    step: u32,
    canonhost: Option<String>,
}

impl<'a> CanonPrinc<'a> {
    #[must_use]
    pub const fn new(conf: &'a Krb5Conf, princ: &'a HostPrinc) -> Self {
        Self {
            conf,
            princ,
            no_hostrealm: false,
            subst_defrealm: false,
            step: 0,
            canonhost: None,
        }
    }

    pub fn next_candidate(&mut self) -> Result<Option<HostPrinc>, SnameError> {
        self.step = self.step.saturating_add(1);
        let host_based = match self.princ.1.name_string.as_slice() {
            [_, host] => {
                self.princ.1.name_type == PrincipalName::NT_SRV_HST && !host.as_bytes().is_empty()
            }
            _ => false,
        };
        if !host_based {
            return Ok((self.step == 1).then(|| self.princ.clone()));
        }
        if self.conf.dns_canonicalize_hostname != CanonHost::Fallback {
            if self.step > 1 {
                return Ok(None);
            }
            let mut copy = self.princ.clone();
            if self.subst_defrealm && copy.0.as_bytes().is_empty() {
                copy.0 = self.default_realm()?;
            }
            return Ok(Some(copy));
        }
        if self.step > 2 {
            return Ok(None);
        }
        let (host, combined) = self.expand(self.step == 2);
        if self.canonhost.as_deref() == Some(combined.as_str()) {
            return Ok(None);
        }
        let princ = self.with_host(&host, &combined)?;
        self.canonhost = Some(combined);
        Ok(Some(princ))
    }

    // MIT: `canonicalize_princ` (lib/krb5/os/sn2princ.c:195-221)
    fn expand(&self, use_dns: bool) -> (String, String) {
        let host = match self.princ.1.name_string.as_slice() {
            [_, host] => String::from_utf8_lossy(host.as_bytes()).into_owned(),
            _ => String::new(),
        };
        let (name, trailer) = split_trailer(&host);
        let expanded = if self.princ.1.name_type == PrincipalName::NT_SRV_HST {
            expand_hostname(name, self.conf, use_dns)
        } else {
            name.to_owned()
        };
        let combined = format!("{expanded}{trailer}");
        (expanded, combined)
    }

    fn with_host(&self, host: &str, combined: &str) -> Result<HostPrinc, SnameError> {
        let realm = if self.princ.0.as_bytes().is_empty() && !self.no_hostrealm {
            match self.conf.realm_for_host(host) {
                Some(r) => try_ascii(r)?,
                None if self.subst_defrealm => self.default_realm()?,
                None => self.princ.0.clone(),
            }
        } else {
            self.princ.0.clone()
        };
        let service = match self.princ.1.name_string.as_slice() {
            [service, _] => String::from_utf8_lossy(service.as_bytes()).into_owned(),
            _ => String::new(),
        };
        let name = PrincipalName::try_new(self.princ.1.name_type, [service.as_str(), combined])?;
        Ok((realm, name))
    }

    fn default_realm(&self) -> Result<Realm, SnameError> {
        let realm = self
            .conf
            .default_realm
            .as_deref()
            .ok_or(SnameError::NoDefaultRealm)?;
        Ok(try_ascii(realm)?)
    }
}

impl Iterator for CanonPrinc<'_> {
    type Item = HostPrinc;

    fn next(&mut self) -> Option<HostPrinc> {
        self.next_candidate().unwrap_or_else(|_| {
            self.step = u32::MAX;
            None
        })
    }
}

// MIT: `krb5_get_fallback_host_realm` (lib/krb5/os/hostrealm.c)
// MIT: `clean_hostname` (lib/krb5/os/hostrealm.c:301-310)
// MIT: `domain_fallback_realm` (lib/krb5/os/hostrealm_domain.c:57-102)
// Address: no answer. KDC suffixes, upper-cased parent, realm or not; no dot: none.
#[must_use]
pub fn fallback_host_realm(conf: &Krb5Conf, host: &str) -> Option<String> {
    fallback_host_realm_traced(conf, host, &mut |_| {})
}

pub fn fallback_host_realm_traced(
    conf: &Krb5Conf,
    host: &str,
    trace: &mut dyn FnMut(super::DnsSrv),
) -> Option<String> {
    let mut clean = host.to_ascii_lowercase();
    if clean.ends_with('.') {
        clean.pop();
    }
    if !super::is_numeric_address(&clean) {
        let upper = clean.to_ascii_uppercase();
        let mut limit = match conf.realm_try_domains.as_deref() {
            None => -1,
            Some(v) => parse_int(v)?,
        };
        let mut suffix = upper.as_str();
        while limit >= 0 {
            let Some(next_limit) = limit.checked_sub(1) else {
                break;
            };
            limit = next_limit;
            let Some((_, rest)) = suffix.split_once('.') else {
                break;
            };
            if conf
                .kdcs_for_traced(suffix, trace)
                .is_ok_and(|kdcs| !kdcs.is_empty())
            {
                return Some(suffix.to_owned());
            }
            suffix = rest;
        }
        if let Some((_, parent)) = upper.split_once('.') {
            return Some(parent.to_owned());
        }
    }
    conf.default_realm.clone()
}

// MIT: `parse_int` (util/profile/prof_get.c:288-305)
// Empty, overflow, trailing junk: PROF_BAD_INTEGER.
fn parse_int(value: &str) -> Option<i32> {
    let t = value.trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b');
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    t.parse::<i64>().ok().and_then(|n| i32::try_from(n).ok())
}

// MIT: `split_trailer` (lib/krb5/os/sn2princ.c:170-181)
fn split_trailer(host: &str) -> (&str, &str) {
    match host.split_once(':') {
        Some((name, rest)) if !rest.is_empty() && !rest.contains(':') => {
            (name, &host[name.len()..])
        }
        _ => (host, ""),
    }
}

// MIT: `k5_primary_domain` (lib/krb5/os/dnsglue.c:500-510)
// `res_ninit`'s first search domain.
fn primary_domain() -> Option<String> {
    let localdomain = std::env::var_os("LOCALDOMAIN").map(|v| v.to_string_lossy().into_owned());
    let conf = std::fs::read(RESOLV_CONF).ok();
    primary_domain_in(localdomain.as_deref(), conf.as_deref(), &this_host())
}

fn primary_domain_in(
    localdomain: Option<&str>,
    resolv_conf: Option<&[u8]>,
    host: &str,
) -> Option<String> {
    let blank = [' ', '\t', '\n'];
    if let Some(v) = localdomain {
        return Some(v.split(blank).next().unwrap_or_default().to_owned());
    }
    let from_host = || host.split_once('.').map(|(_, domain)| domain.to_owned());
    let Some(conf) = resolv_conf else {
        return from_host();
    };
    let text = String::from_utf8_lossy(conf);
    let mut first = None;
    for line in text.split('\n') {
        if line.starts_with([';', '#']) {
            continue;
        }
        let Some(rest) = ["domain", "search"]
            .iter()
            .find_map(|k| line.strip_prefix(k).filter(|r| r.starts_with([' ', '\t'])))
        else {
            continue;
        };
        let names = rest.trim_start_matches([' ', '\t']);
        if names.is_empty() {
            continue;
        }
        first = names.split(blank).next().map(str::to_owned);
    }
    first.or_else(from_host)
}
