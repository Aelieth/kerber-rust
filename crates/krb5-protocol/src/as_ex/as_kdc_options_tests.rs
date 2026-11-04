use super::*;

fn times_of(ticket: AsTicketOpts, canonicalize: bool) -> AsReqTimes {
    let kdc = KdcAddr::new("127.0.0.1");
    let req = AsRequest {
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        realm: "KERBER.TEST",
        password: b"x",
        kdc: &kdc,
        profile: &krb5_config::isolated_profile(),
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize,
        sname: None,
        etypes: None,
        ticket,
    };
    ticket_body(&req, &KerberosTime::now())
}

#[test]
fn gic_opt_starttime_sets_postdated_and_from() {
    let t = times_of(
        AsTicketOpts {
            starttime: Some(3600),
            ..AsTicketOpts::default()
        },
        false,
    );
    assert!(
        t.opts.bit(flag_bit::MAY_POSTDATE),
        "get_in_tkt.c:932-934 ALLOW_POSTDATE"
    );
    assert!(t.opts.bit(flag_bit::POSTDATED), "get_in_tkt.c:932-934");
    assert!(
        t.from.is_some(),
        "get_in_tkt.c:711-714 omits from only at 0"
    );
    let plain = times_of(AsTicketOpts::default(), false);
    assert!(plain.from.is_none());
    assert!(!plain.opts.bit(flag_bit::POSTDATED));
    assert!(!plain.opts.bit(flag_bit::MAY_POSTDATE));
    let past = times_of(
        AsTicketOpts {
            starttime: Some(-3600),
            ..AsTicketOpts::default()
        },
        false,
    );
    assert!(past.from.is_some(), "a start in the past is still sent");
    assert!(!past.opts.bit(flag_bit::POSTDATED));
    assert!(!past.opts.bit(flag_bit::MAY_POSTDATE));
}

fn sent_addresses(
    addresses: Option<krb5_types::HostAddresses>,
) -> Option<krb5_types::HostAddresses> {
    let kdc = KdcAddr::new("127.0.0.1");
    let req = AsRequest {
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        realm: "KERBER.TEST",
        password: b"x",
        kdc: &kdc,
        profile: &krb5_config::isolated_profile(),
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize: false,
        sname: None,
        etypes: None,
        ticket: AsTicketOpts {
            addresses,
            ..AsTicketOpts::default()
        },
    };
    let bound = ticket_body(&req, &KerberosTime::now());
    let built = build_as_req_from(&req, 7, &bound, None, &[18]).unwrap();
    let der = krb5_asn1::encode(&built).unwrap();
    krb5_asn1::decode::<krb5_types::AsReq>(&der)
        .unwrap()
        .0
        .req_body
        .addresses
}

// MIT: `req_body_9` (lib/krb5/asn.1/asn1_k_encode.c:457-458)
/// The request's addresses are an optional-if-empty field.
// MIT: `DEFOPTIONALEMPTYTYPE` (lib/krb5/asn.1/asn1_encode.h:389-396)
/// Present only for a list with an element: `kinit -a` on a host with no usable address sends none.
#[test]
fn the_request_carries_an_ipv4_and_an_ipv6_address_and_an_empty_list_is_no_field() {
    let list = vec![
        krb5_types::HostAddress {
            addr_type: 2,
            address: vec![192, 0, 2, 7].into(),
        },
        krb5_types::HostAddress {
            addr_type: 24,
            address: "2001:db8::5"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec()
                .into(),
        },
    ];
    assert_eq!(sent_addresses(Some(list.clone())), Some(list));
    assert_eq!(sent_addresses(Some(Vec::new())), None);
    assert_eq!(sent_addresses(None), None);
}
