//! W1-B B1: `kinit -R` KDCOptions. MIT `val_renew.c:62-67` `get_new_creds`.
//! Live oracle: `client-differential-gate.sh` flow `renew`.

use krb5_protocol::tgs_renew_options;
use krb5_types::{TicketFlags, flag_bit};

#[test]
fn b1_renew_options_are_common_mask_plus_renew() {
    let flags = TicketFlags::from_u32(0x5480_0000);
    let opts = tgs_renew_options(&flags);
    assert!(opts.bit(flag_bit::FORWARDABLE));
    assert!(opts.bit(flag_bit::PROXIABLE));
    assert!(opts.bit(flag_bit::MAY_POSTDATE));
    assert!(opts.bit(flag_bit::RENEWABLE));
    assert!(opts.bit(flag_bit::RENEW), "val_renew.c:129 KDC_OPT_RENEW");
    assert!(
        !opts.bit(flag_bit::CANONICALIZE),
        "renew is not the get_creds referral walk"
    );
}

#[test]
fn b1_renew_options_omit_unset_ticket_flags() {
    let flags = TicketFlags::from_u32(0x4000_0000);
    let opts = tgs_renew_options(&flags);
    assert!(opts.bit(flag_bit::FORWARDABLE));
    assert!(opts.bit(flag_bit::RENEW));
    assert!(!opts.bit(flag_bit::PROXIABLE));
    assert!(!opts.bit(flag_bit::RENEWABLE));
    assert!(!opts.bit(flag_bit::CANONICALIZE));
}
