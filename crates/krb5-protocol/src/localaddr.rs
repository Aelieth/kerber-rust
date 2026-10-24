//! Host addresses a KRB-PRIV or KRB-SAFE checks when no local address is set.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use krb5_types::HostAddress;
use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;

use crate::error::Error;

// MIT: `krb5_os_localaddr` (lib/krb5/os/localaddr.c:1311-1315)
// MIT: `get_localaddrs` (lib/krb5/os/localaddr.c:1317-1368)
/// extra_addresses is not read.
/// A failed getifaddrs is Io, with the errno text.
pub fn os_localaddr() -> Result<Vec<HostAddress>, Error> {
    let interfaces = getifaddrs().map_err(getifaddrs_error)?;
    Ok(host_addresses_from(interfaces.map(|i| {
        let ip = i.address.and_then(|a| {
            a.as_sockaddr_in()
                .map(|v4| IpAddr::V4(v4.ip()))
                .or_else(|| a.as_sockaddr_in6().map(|v6| IpAddr::V6(v6.ip())))
        });
        (i.flags.contains(InterfaceFlags::IFF_UP), ip)
    })))
}

fn getifaddrs_error(errno: nix::errno::Errno) -> Error {
    let raw = errno as i32;
    Error::Io {
        message: crate::trace::error_message(i64::from(raw)),
        kind: std::io::Error::from_raw_os_error(raw).kind(),
        retryable: false,
    }
}

// MIT: `krb5_init_creds_init` (lib/krb5/krb/get_in_tkt.c:998-1005)
/// Absent or true sends none.
pub fn init_creds_addresses(noaddresses: Option<bool>) -> Result<Option<Vec<HostAddress>>, Error> {
    init_creds_addresses_from(noaddresses, os_localaddr)
}

fn init_creds_addresses_from(
    noaddresses: Option<bool>,
    local: impl FnOnce() -> Result<Vec<HostAddress>, Error>,
) -> Result<Option<Vec<HostAddress>>, Error> {
    if noaddresses == Some(false) {
        local().map(Some)
    } else {
        Ok(None)
    }
}

// MIT: `foreach_localaddr` (lib/krb5/os/localaddr.c:415-481)
/// A down, empty, loopback, or repeated entry is skipped.
// MIT: `add_addr` (lib/krb5/os/localaddr.c:1162-1195)
#[must_use]
pub fn host_addresses_from(
    entries: impl IntoIterator<Item = (bool, Option<IpAddr>)>,
) -> Vec<HostAddress> {
    let mut kept: Vec<IpAddr> = Vec::new();
    for (up, ip) in entries {
        let Some(ip) = ip else { continue };
        if !up || is_loopback(ip) || kept.contains(&ip) {
            continue;
        }
        kept.push(ip);
    }
    kept.into_iter().filter_map(host_address).collect()
}

// MIT: `is_loopback_address` (localaddr.c:179-190)
/// Only 127.0.0.1 and ::1.
fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4 == Ipv4Addr::LOCALHOST,
        IpAddr::V6(v6) => v6 == Ipv6Addr::LOCALHOST,
    }
}

fn host_address(ip: IpAddr) -> Option<HostAddress> {
    match ip {
        IpAddr::V4(v4) => Some(HostAddress {
            addr_type: HostAddress::ADDRTYPE_INET,
            address: v4.octets().to_vec().into(),
        }),
        IpAddr::V6(v6) => {
            let o = v6.octets();
            // fe80::/10 is link-local and is dropped.
            if o[0] == 0xfe && o[1] & 0xc0 == 0x80 {
                return None;
            }
            Some(HostAddress {
                addr_type: HostAddress::ADDRTYPE_INET6,
                address: o.to_vec().into(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn inet(a: u8, b: u8, c: u8, d: u8) -> HostAddress {
        HostAddress {
            addr_type: 2,
            address: vec![a, b, c, d].into(),
        }
    }

    #[test]
    fn loopback_is_only_127_0_0_1_and_colon_colon_1() {
        let got = host_addresses_from([
            (true, Some(v4(127, 0, 0, 1))),
            (true, Some(IpAddr::V6(Ipv6Addr::LOCALHOST))),
            (true, Some(v4(127, 0, 0, 2))),
            (true, Some(v4(192, 0, 2, 7))),
        ]);
        assert_eq!(got, vec![inet(127, 0, 0, 2), inet(192, 0, 2, 7)]);
    }

    #[test]
    fn down_entries_and_entries_without_an_address_are_passed_over() {
        let got = host_addresses_from([
            (false, Some(v4(192, 0, 2, 1))),
            (true, None),
            (true, Some(v4(192, 0, 2, 2))),
        ]);
        assert_eq!(got, vec![inet(192, 0, 2, 2)]);
    }

    #[test]
    fn a_repeated_address_is_listed_once_in_interface_order() {
        let got = host_addresses_from([
            (true, Some(v4(192, 0, 2, 9))),
            (true, Some(v4(198, 51, 100, 1))),
            (true, Some(v4(192, 0, 2, 9))),
        ]);
        assert_eq!(got, vec![inet(192, 0, 2, 9), inet(198, 51, 100, 1)]);
    }

    #[test]
    fn ipv6_link_local_is_dropped_and_ipv4_mapped_stays_ipv6() {
        let linklocal: Ipv6Addr = "fe80::1".parse().unwrap();
        let global: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let mapped: Ipv6Addr = "::ffff:192.0.2.5".parse().unwrap();
        let got = host_addresses_from([
            (true, Some(IpAddr::V6(linklocal))),
            (true, Some(IpAddr::V6(global))),
            (true, Some(IpAddr::V6(mapped))),
        ]);
        let want = |a: Ipv6Addr| HostAddress {
            addr_type: 24,
            address: a.octets().to_vec().into(),
        };
        assert_eq!(got, vec![want(global), want(mapped)]);
    }

    fn inet6(a: &str) -> HostAddress {
        HostAddress {
            addr_type: 24,
            address: a.parse::<Ipv6Addr>().unwrap().octets().to_vec().into(),
        }
    }

    fn multi_homed_host() -> Vec<(bool, Option<IpAddr>)> {
        vec![
            (true, Some(v4(127, 0, 0, 1))),
            (true, Some(IpAddr::V6(Ipv6Addr::LOCALHOST))),
            (true, Some(v4(10, 10, 42, 59))),
            (
                true,
                Some(IpAddr::V6("fe80::53f2:c09:7db8:51e9".parse().unwrap())),
            ),
            (true, Some(IpAddr::V6("2001:db8::5".parse().unwrap()))),
            (true, Some(v4(192, 168, 122, 1))),
            (false, Some(v4(172, 17, 0, 1))),
            (true, None),
        ]
    }

    /// `kinit -a` and a false `noaddresses` send this list, not the one address a route towards 8.8.8.8 picks.
    #[test]
    fn a_multi_homed_host_lists_every_up_address_ipv6_included_in_interface_order() {
        let want = vec![
            inet(10, 10, 42, 59),
            inet6("2001:db8::5"),
            inet(192, 168, 122, 1),
        ];
        assert_eq!(host_addresses_from(multi_homed_host()), want);
        let sent =
            init_creds_addresses_from(Some(false), || Ok(host_addresses_from(multi_homed_host())));
        assert_eq!(sent.unwrap(), Some(want));
    }

    #[test]
    fn noaddresses_false_alone_reads_the_interfaces() {
        let read = std::cell::Cell::new(0);
        let local = || {
            read.set(read.get() + 1);
            Ok(host_addresses_from(multi_homed_host()))
        };
        assert_eq!(init_creds_addresses_from(None, local).unwrap(), None);
        assert_eq!(init_creds_addresses_from(Some(true), local).unwrap(), None);
        assert_eq!(read.get(), 0, "an absent or true noaddresses sends none");
        assert_eq!(
            init_creds_addresses_from(Some(false), local)
                .unwrap()
                .map(|l| l.len()),
            Some(3)
        );
        assert_eq!(read.get(), 1);
    }

    #[test]
    fn a_failed_getifaddrs_is_the_errno_and_fails_a_false_noaddresses() {
        match getifaddrs_error(nix::errno::Errno::EACCES) {
            Error::Io { message, kind, .. } => {
                assert_eq!(message, "Permission denied");
                assert_eq!(kind, std::io::ErrorKind::PermissionDenied);
            }
            e => panic!("{e}"),
        }
        let failing = || Err(getifaddrs_error(nix::errno::Errno::EACCES));
        assert!(init_creds_addresses_from(Some(false), failing).is_err());
        assert!(init_creds_addresses_from(None, failing).unwrap().is_none());
    }

    #[test]
    fn the_os_list_holds_no_loopback_and_no_duplicate() {
        let list = os_localaddr().unwrap();
        for a in &list {
            assert!(
                a.address.as_ref() != [127, 0, 0, 1] && a.addr_type != 0,
                "{a:?}"
            );
        }
        let mut sorted: Vec<_> = list
            .iter()
            .map(|a| (a.addr_type, a.address.to_vec()))
            .collect();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), list.len());
    }
}
