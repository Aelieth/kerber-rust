//! Host-based service principals as MIT's `krb5_sname_to_principal` makes them without DNS, and
//! the candidates `k5_canonprinc` tries when one is used: MIT `lib/krb5/os/sn2princ.c`
//! (`expand_hostname`, `qualify_shortname`, `split_trailer`, `canonicalize_princ`,
//! `k5_canonprinc`, `krb5_sname_to_principal`), and `lib/krb5/os/dnsglue.c` `k5_primary_domain`
//! (glibc's `res_ninit` search list).

use krb5_types::{NameError, PrincipalName, Realm, try_ascii};

use super::{CanonHost, Krb5Conf};

/// The resolver configuration glibc's `res_ninit` reads.
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// This host's name as `gethostname` gives it.
/// MIT `krb5_sname_to_principal` (`lib/krb5/os/sn2princ.c:347-352`): no hostname is the local one, `gethostname`'s.
#[must_use]
pub fn this_host() -> String {
    nix::unistd::gethostname()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `host` expanded by [`expand_hostname_no_dns`] with `conf`'s `qualify_shortname`, else the
/// resolver's first search domain: the host part of a service principal MIT makes when it does
/// not ask DNS.
#[must_use]
pub fn expand_hostname(host: &str, conf: &Krb5Conf) -> String {
    expand_hostname_no_dns(host, conf.qualify_shortname.as_deref(), primary_domain)
}

/// This host's name ([`this_host`]) as [`expand_hostname`] expands it.
#[must_use]
pub fn local_host_name(conf: &Krb5Conf) -> String {
    expand_hostname(&this_host(), conf)
}

/// `host` as MIT expands a hostname it does not look up in DNS: a name without a dot gains a
/// dot and `qualify_shortname` (the profile's; `Some("")` adds nothing), or when that is unset
/// the resolver's first search domain (`primary_domain`, asked only then), if not empty; then the
/// name is lowercased and loses one trailing dot.
/// MIT `expand_hostname` (`lib/krb5/os/sn2princ.c:121-144`): a one-component name is qualified when DNS was not used, then lowercased, then a trailing dot removed.
/// MIT `qualify_shortname` (`lib/krb5/os/sn2princ.c:66-80`): the profile's `qualify_shortname` when set, else `k5_primary_domain`'s, appended only when not empty.
#[must_use]
pub fn expand_hostname_no_dns(
    host: &str,
    qualify_shortname: Option<&str>,
    primary_domain: impl FnOnce() -> Option<String>,
) -> String {
    let mut name = host.to_owned();
    if !host.contains('.') {
        let domain = match qualify_shortname {
            Some(d) => Some(d.to_owned()),
            None => primary_domain(),
        };
        if let Some(d) = domain.filter(|d| !d.is_empty()) {
            name = format!("{host}.{d}");
        }
    }
    name.make_ascii_lowercase();
    if name.ends_with('.') {
        name.pop();
    }
    name
}

/// A principal as MIT's `krb5_sname_to_principal` and `k5_canonprinc` hand it: its realm (empty
/// for the referral realm) and its name.
pub type HostPrinc = (Realm, PrincipalName);

/// Why [`sname_to_principal`] or [`CanonPrinc::next_candidate`] gives no principal.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SnameError {
    /// `KRB5_SNAME_UNSUPP_NAMETYPE`: a name type neither unknown nor host-based.
    #[error("Conversion to service principal undefined for name type")]
    UnsupportedNameType,
    /// `KRB5_CONFIG_NODEFREALM`: the default realm was to stand for the referral realm, and the
    /// profile names none.
    #[error("Configuration file does not specify default realm")]
    NoDefaultRealm,
    /// A name or realm this port's principal names cannot hold (not ASCII), which MIT's can.
    #[error(transparent)]
    Name(#[from] NameError),
}

/// The principal for the service `sname` (else `host`) on `hostname` (else this host,
/// [`this_host`]), of `name_type`, unknown or host-based. Under `dns_canonicalize_hostname =
/// fallback` a host-based name is handed back as given, in the referral realm, for
/// [`CanonPrinc`] to expand when it is used. Otherwise a host-based name's hostname is expanded
/// now ([`expand_hostname`]) and any name takes the expanded host's realm (`[domain_realm]`),
/// the referral realm when none is mapped.
/// MIT `krb5_sname_to_principal` (`lib/krb5/os/sn2princ.c:344-370`): only an unknown or a host-based name type is converted; the name starts in the referral realm, and under `fallback` a host-based one is returned so.
/// MIT `krb5_sname_to_principal` (`lib/krb5/os/sn2princ.c:372-376`): otherwise it is canonicalized at once, through DNS only under `true`.
///
/// # Errors
///
/// [`SnameError::UnsupportedNameType`] for another name type; [`SnameError::Name`] for a name or
/// realm that is not ASCII.
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
    let (host, combined) = iter.expand();
    iter.with_host(&host, &combined)
}

/// The candidates a principal stands for when it is used, in turn ([`Self::next_candidate`]).
/// A host-based name with a hostname is, under `dns_canonicalize_hostname = fallback`, expanded
/// when it is used; any other name is its own one candidate. Without `fallback` the name is its
/// own one candidate.
/// Under `fallback` the second candidate is the same expanded name, not a DNS name: this port does not look the host up.
/// MIT `k5_canonprinc` (`lib/krb5/os/sn2princ.c:279-285`): a name that is not a two-part host-based name with a hostname is its only candidate.
/// MIT `k5_canonprinc` (`lib/krb5/os/sn2princ.c:287-307`): without `fallback` the name is its only candidate, the default realm put in for the referral realm when asked; under `fallback` step 1 is without DNS and step 2 with it.
#[derive(Debug)]
pub struct CanonPrinc<'a> {
    conf: &'a Krb5Conf,
    princ: &'a HostPrinc,
    /// MIT `no_hostrealm`: under `fallback`, the referral realm is kept rather than looked up
    /// for the expanded host.
    pub no_hostrealm: bool,
    /// MIT `subst_defrealm`: the referral realm becomes the default realm.
    pub subst_defrealm: bool,
    step: u32,
    canonhost: Option<String>,
}

impl<'a> CanonPrinc<'a> {
    /// The candidates of `princ` under `conf`, neither flag set.
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

    /// The next candidate, `None` once there is no other.
    ///
    /// # Errors
    ///
    /// [`SnameError::NoDefaultRealm`] when the default realm is to stand for the referral realm
    /// and the profile names none; [`SnameError::Name`] for an expanded name or realm that is not
    /// ASCII.
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
        let (host, combined) = self.expand();
        if self.canonhost.as_deref() == Some(combined.as_str()) {
            return Ok(None);
        }
        let princ = self.with_host(&host, &combined)?;
        self.canonhost = Some(combined);
        Ok(Some(princ))
    }

    /// The host part expanded, without its trailer and with it: a host-based name's hostname by
    /// [`expand_hostname`], any other's as it is.
    /// MIT `canonicalize_princ` (`lib/krb5/os/sn2princ.c:195-221`): the hostname is split from its trailer, expanded only for a host-based name, and the trailer put back.
    fn expand(&self) -> (String, String) {
        let host = match self.princ.1.name_string.as_slice() {
            [_, host] => String::from_utf8_lossy(host.as_bytes()).into_owned(),
            _ => String::new(),
        };
        let (name, trailer) = split_trailer(&host);
        let expanded = if self.princ.1.name_type == PrincipalName::NT_SRV_HST {
            expand_hostname(name, self.conf)
        } else {
            name.to_owned()
        };
        let combined = format!("{expanded}{trailer}");
        (expanded, combined)
    }

    /// The principal with `combined` for its host part, in its own realm or, for the referral
    /// realm, the realm `[domain_realm]` maps `host` to (the referral realm when it maps none,
    /// then the default realm under [`Self::subst_defrealm`]), unless [`Self::no_hostrealm`].
    /// MIT `canonicalize_princ` (`lib/krb5/os/sn2princ.c:231-260`): a referral realm is looked up for the expanded host unless asked not to, an unknown host's referral realm becoming the default realm only when asked.
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

/// The realm `host` falls back to when a referral request for a service on it failed: with
/// `realm_try_domains` at 0 or more, the first of that many of its domain suffixes (upper-cased,
/// the whole name first) that has KDCs, else its parent domain upper-cased; for an address or a
/// name with no dot, the default realm. `None` when `realm_try_domains` is not an integer
/// (MIT's `PROF_BAD_INTEGER`) or there is no default realm (`KRB5_CONFIG_NODEFREALM`).
/// MIT `krb5_get_fallback_host_realm` (`lib/krb5/os/hostrealm.c:410-441`): the host is cleaned, each module asked in turn, and with none answering the fallback is the default realm.
/// MIT `clean_hostname` (`lib/krb5/os/hostrealm.c:301-310`): the name is lowercased and loses a trailing dot.
/// MIT `domain_fallback_realm` (`lib/krb5/os/hostrealm_domain.c:57-102`): an address has no answer; `realm_try_domains` suffixes with KDCs come first, then the upper-cased parent domain whether or not it is a realm, and a name with no dot has none.
#[must_use]
pub fn fallback_host_realm(conf: &Krb5Conf, host: &str) -> Option<String> {
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
            if conf.kdcs_for(suffix).is_ok_and(|kdcs| !kdcs.is_empty()) {
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

/// A profile integer: optional leading white space and sign, then decimal digits only, within
/// `int`'s range.
/// MIT `parse_int` (`util/profile/prof_get.c:288-305`): an empty value, an overflow, a value outside `int`, or anything after the digits is `PROF_BAD_INTEGER`.
fn parse_int(value: &str) -> Option<i32> {
    let t = value.trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b');
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    t.parse::<i64>().ok().and_then(|n| i32::try_from(n).ok())
}

/// `host` and its trailer (`:port` or `:instance`, as in an MSSQLSvc principal): one colon
/// followed by at least one character; a name with more colons (an IPv6 address) has none.
/// MIT `split_trailer` (`lib/krb5/os/sn2princ.c:170-181`): only a single colon followed by one or more characters starts a trailer.
fn split_trailer(host: &str) -> (&str, &str) {
    match host.split_once(':') {
        Some((name, rest)) if !rest.is_empty() && !rest.contains(':') => {
            (name, &host[name.len()..])
        }
        _ => (host, ""),
    }
}

/// The resolver's first search domain, as glibc's `res_ninit` sets it: `LOCALDOMAIN`'s first
/// name when that is set, else the first name of `/etc/resolv.conf`'s last `domain` or `search`
/// line, else the part of this host's name after its first dot.
/// MIT `k5_primary_domain` (`lib/krb5/os/dnsglue.c:500-510`): `res_ninit`'s first search domain.
fn primary_domain() -> Option<String> {
    let localdomain = std::env::var_os("LOCALDOMAIN").map(|v| v.to_string_lossy().into_owned());
    let conf = std::fs::read(RESOLV_CONF).ok();
    primary_domain_in(localdomain.as_deref(), conf.as_deref(), &this_host())
}

/// [`primary_domain`] from `LOCALDOMAIN`'s value, `/etc/resolv.conf`'s bytes and this host's
/// name. glibc reads `LOCALDOMAIN` up to its first blank or newline (empty when it starts with
/// one) and then skips the file's `domain` and `search` lines; in the file a line opening with
/// `;` or `#` is a comment, a keyword is followed by a blank, a line with no name after it is
/// passed over, and each `domain` or `search` line replaces the list the ones before it made.
/// With no list from either, glibc takes the host name's part after its first dot, if it has one.
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
