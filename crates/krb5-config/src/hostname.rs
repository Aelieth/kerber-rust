//! This host's name as MIT's `krb5_sname_to_principal` makes it without DNS: MIT
//! `lib/krb5/os/sn2princ.c` `expand_hostname` and `qualify_shortname`, and
//! `lib/krb5/os/dnsglue.c` `k5_primary_domain` (glibc's `res_ninit` search list).

use super::Krb5Conf;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn expand(host: &str, qualify: Option<&str>, os: Option<&str>) -> String {
        expand_hostname_no_dns(host, qualify, || os.map(str::to_owned))
    }

    /// MIT `expand_hostname` (`lib/krb5/os/sn2princ.c:121-144`): only a name without a dot is qualified; every name is lowercased and loses one trailing dot.
    #[test]
    fn a_short_name_is_qualified_lowercased_and_loses_a_trailing_dot() {
        assert_eq!(
            expand("kdc2", None, Some("example.com")),
            "kdc2.example.com"
        );
        assert_eq!(
            expand("KDC2", None, Some("Example.COM")),
            "kdc2.example.com"
        );
        assert_eq!(expand("kdc2", None, None), "kdc2");
        assert_eq!(expand("kdc2.lan", None, Some("example.com")), "kdc2.lan");
        assert_eq!(
            expand("Kdc2.Example.Com.", None, Some("x")),
            "kdc2.example.com"
        );
        assert_eq!(
            expand("kdc2", None, Some("example.com.")),
            "kdc2.example.com"
        );
        assert_eq!(expand("kdc2", None, Some(".")), "kdc2.");
        assert_eq!(expand("", None, Some("example.com")), ".example.com");
    }

    /// MIT `qualify_shortname` (`lib/krb5/os/sn2princ.c:66-80`): the profile's value wins, an empty one adds nothing, and the resolver is asked only when it is unset.
    #[test]
    fn the_profiles_qualify_shortname_comes_before_the_resolver() {
        assert_eq!(
            expand("kdc2", Some("prof.test"), Some("os.test")),
            "kdc2.prof.test"
        );
        assert_eq!(expand("kdc2", Some(""), Some("os.test")), "kdc2");
        let asked = std::cell::Cell::new(false);
        let name = expand_hostname_no_dns("kdc2", Some("prof.test"), || {
            asked.set(true);
            None
        });
        assert_eq!(name, "kdc2.prof.test");
        assert!(!asked.get());
    }

    /// glibc `res_ninit`: `LOCALDOMAIN` first, else the last `domain` or `search` line's first name, else the host name's part after its first dot.
    #[test]
    fn the_first_search_domain_is_glibcs() {
        let conf = |s: &str| primary_domain_in(None, Some(s.as_bytes()), "kdc2");
        assert_eq!(
            conf("nameserver 1.1.1.1\nsearch a.test b.test\n"),
            Some("a.test".into())
        );
        assert_eq!(
            conf("search a.test\ndomain d.test\n"),
            Some("d.test".into())
        );
        assert_eq!(
            conf("domain d.test x\nsearch\ta.test\n"),
            Some("a.test".into())
        );
        assert_eq!(conf("search a.test\nsearch \n"), Some("a.test".into()));
        assert_eq!(
            conf("#search a.test\n;domain d.test\nsearchx a.test\n"),
            None
        );
        assert_eq!(conf("search  \t a.test\r\n"), Some("a.test\r".into()));
        assert_eq!(conf("nameserver 1.1.1.1\n"), None);
        assert_eq!(primary_domain_in(None, None, "kdc2"), None);
        let env = |v: &str| primary_domain_in(Some(v), Some(b"search a.test\n"), "kdc1.h.test");
        assert_eq!(env("e.test f.test"), Some("e.test".into()));
        assert_eq!(env(""), Some(String::new()));
        assert_eq!(env(" e.test"), Some(String::new()));
        let host = |conf: Option<&[u8]>, h: &str| primary_domain_in(None, conf, h);
        assert_eq!(host(None, "kdc1.h.test"), Some("h.test".into()));
        assert_eq!(
            host(Some(b"nameserver 1.1.1.1\n"), "kdc1.h.test"),
            Some("h.test".into())
        );
        assert_eq!(
            host(Some(b"search a.test\n"), "kdc1.h.test"),
            Some("a.test".into())
        );
        assert_eq!(
            host(Some(b"search\n"), "kdc1.h.test"),
            Some("h.test".into())
        );
        assert_eq!(host(None, "kdc1."), Some(String::new()));
        assert_eq!(host(None, "kdc1"), None);
    }
}
