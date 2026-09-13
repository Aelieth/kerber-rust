//! W1-B B1: `kinit -C` / `-s` KDCOptions. MIT `gic_opt.c:76-83`,
//! `get_in_tkt.c:711-714,921-934`.
//! Live oracle: `client-differential-gate.sh` `MIT_kinit_canonicalize` /
//! `MIT_kinit_postdated`.

use krb5_protocol::{AsRequest, AsTicketOpts, KdcAddr, as_init_creds_options};
use krb5_types::{PrincipalName, flag_bit};

fn options_of(
    ticket: AsTicketOpts,
    canonicalize: bool,
) -> (krb5_types::KdcOptions, Option<krb5_types::KerberosTime>) {
    let kdc = KdcAddr::new("127.0.0.1");
    let req = AsRequest {
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        realm: "KERBER.TEST",
        password: b"x",
        kdc: &kdc,
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize,
        sname: None,
        etypes: None,
        ticket,
    };
    as_init_creds_options(&req)
}

#[test]
fn b1_gic_opt_canonicalize_sets_kdc_option() {
    let (opts, from) = options_of(AsTicketOpts::default(), true);
    assert!(
        opts.bit(flag_bit::CANONICALIZE),
        "get_in_tkt.c:921-930 / gic_opt.c:76-83"
    );
    assert!(from.is_none());
    let (plain, _) = options_of(AsTicketOpts::default(), false);
    assert!(!plain.bit(flag_bit::CANONICALIZE));
}

#[test]
fn b1_gic_opt_starttime_sets_postdated_and_from() {
    let (opts, from) = options_of(
        AsTicketOpts {
            starttime: Some(3600),
            ..AsTicketOpts::default()
        },
        false,
    );
    assert!(
        opts.bit(flag_bit::MAY_POSTDATE),
        "get_in_tkt.c:932-934 ALLOW_POSTDATE"
    );
    assert!(opts.bit(flag_bit::POSTDATED), "get_in_tkt.c:932-934");
    assert!(from.is_some(), "get_in_tkt.c:711-714 omits from only at 0");
    let (plain, none) = options_of(AsTicketOpts::default(), false);
    assert!(none.is_none());
    assert!(!plain.bit(flag_bit::POSTDATED));
    assert!(!plain.bit(flag_bit::MAY_POSTDATE));
}
