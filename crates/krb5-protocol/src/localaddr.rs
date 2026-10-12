//! The host's own addresses (`lib/krb5/os/localaddr.c`), which a KRB-PRIV's or KRB-SAFE's receiver
//! address is looked up in when the auth context holds no local address of its own.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use krb5_types::HostAddress;
use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;

use crate::error::Error;

/// The host's addresses, in interface order.
/// MIT `krb5_os_localaddr` (`lib/krb5/os/localaddr.c:1311-1315`): the addresses of the interfaces that are up, through `getifaddrs`, as [`host_addresses_from`] picks them.
/// MIT `get_localaddrs` (`lib/krb5/os/localaddr.c:1317-1368`): the interfaces' addresses, then those `[libdefaults] extra_addresses` names; the second half is not read.
///
/// # Errors
///
/// [`Error::Io`] when `getifaddrs` fails (MIT returns its errno).
pub fn os_localaddr() -> Result<Vec<HostAddress>, Error> {
    let interfaces = getifaddrs().map_err(|e| Error::Io {
        message: format!("getifaddrs: {e}"),
        kind: std::io::ErrorKind::Other,
        retryable: false,
    })?;
    Ok(host_addresses_from(interfaces.map(|i| {
        let ip = i.address.and_then(|a| {
            a.as_sockaddr_in()
                .map(|v4| IpAddr::V4(v4.ip()))
                .or_else(|| a.as_sockaddr_in6().map(|v6| IpAddr::V6(v6.ip())))
        });
        (i.flags.contains(InterfaceFlags::IFF_UP), ip)
    })))
}

/// The host addresses of interface entries `(is up, address)`, an address of another family or
/// none being `None`.
/// MIT `foreach_localaddr` (`lib/krb5/os/localaddr.c:415-481`): an entry that is down, has no address, holds the loopback address (exactly 127.0.0.1 or ::1, not the rest of 127/8) or repeats the address of an earlier kept entry is passed over.
/// MIT `add_addr` (`lib/krb5/os/localaddr.c:1162-1195`): makes `ADDRTYPE_INET` of an IPv4 address and `ADDRTYPE_INET6` of an IPv6 one, an IPv4-mapped one included, and drops a link-local IPv6 address (fe80::/10).
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

/// MIT `is_loopback_address` (`localaddr.c:179-190`): `INADDR_LOOPBACK` and `in6addr_loopback`
/// only.
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
            // IN6_IS_ADDR_LINKLOCAL: fe80::/10.
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
