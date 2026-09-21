use super::*;

fn options_of(ticket: AsTicketOpts) -> KdcOptions {
    let kdc = KdcAddr::new("127.0.0.1");
    let req = AsRequest {
        cname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        realm: "KERBER.TEST",
        password: b"x",
        kdc: &kdc,
        want_spake: false,
        fast_armor: None,
        pkinit: None,
        canonicalize: false,
        sname: None,
        etypes: None,
        ticket,
    };
    ticket_body(&req).0.opts
}

fn times_of(ticket: AsTicketOpts, canonicalize: bool) -> AsReqTimes {
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
    ticket_body(&req).0
}

#[test]
fn default_as_options_include_renewable_ok() {
    let opts = options_of(AsTicketOpts::default());
    assert!(opts.bit(flag_bit::FORWARDABLE));
    assert!(opts.bit(flag_bit::RENEWABLE_OK), "MIT init_ctx.c:265-267");
    assert!(!opts.bit(flag_bit::RENEWABLE));
}

#[test]
fn renew_life_clears_renewable_ok() {
    let opts = options_of(AsTicketOpts {
        rlife: Some(7 * 24 * 3600),
        ..AsTicketOpts::default()
    });
    assert!(opts.bit(flag_bit::RENEWABLE), "get_in_tkt.c:718-723");
    assert!(
        !opts.bit(flag_bit::RENEWABLE_OK),
        "get_in_tkt.c:723 clears RENEWABLE_OK when renew_life > 0"
    );
}

#[test]
fn gic_opt_canonicalize_sets_kdc_option() {
    let opts = times_of(AsTicketOpts::default(), true).opts;
    assert!(
        opts.bit(flag_bit::CANONICALIZE),
        "get_in_tkt.c:921-930 / gic_opt.c:76-83"
    );
    let plain = times_of(AsTicketOpts::default(), false).opts;
    assert!(!plain.bit(flag_bit::CANONICALIZE));
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
}

#[test]
fn omitted_lifetime_is_one_day() {
    let t = times_of(AsTicketOpts::default(), false);
    let now = i64::from(KerberosTime::now().unix_seconds());
    let till = i64::from(t.till.unix_seconds());
    let delta = till - now;
    assert!(
        (86_400 - 5..=86_400 + 5).contains(&delta),
        "get_in_tkt.c:947 omitted till is 24 h, got {delta}"
    );
}

#[test]
fn renew_life_shorter_than_till_is_clamped() {
    let t = times_of(
        AsTicketOpts {
            rlife: Some(12 * 3600),
            ..AsTicketOpts::default()
        },
        false,
    );
    let rtime = t
        .rtime
        .expect("get_in_tkt.c:718 sets rtime when renew_life > 0");
    assert_eq!(
        rtime.unix_seconds(),
        t.till.unix_seconds(),
        "get_in_tkt.c:718-722 rtime is max(from+renew_life, till)"
    );
}
