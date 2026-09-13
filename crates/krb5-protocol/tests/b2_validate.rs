//! W1-B B2: `kinit -v` KDCOptions. MIT `val_renew.c:62-67` `get_new_creds`.
//! Live oracle: `client-differential-gate.sh` `MIT_kinit_validate`.
//! Unit-only: `tgs_validate_options` is new at the parent.

use krb5_protocol::tgs_validate_options;
use krb5_types::{TicketFlags, flag_bit};

#[test]
fn b2_validate_options_are_common_mask_plus_validate() {
    let flags = TicketFlags::from_u32(0x5480_0000);
    let opts = tgs_validate_options(&flags);
    assert!(opts.bit(flag_bit::FORWARDABLE));
    assert!(opts.bit(flag_bit::PROXIABLE));
    assert!(opts.bit(flag_bit::MAY_POSTDATE));
    assert!(opts.bit(flag_bit::RENEWABLE));
    assert!(
        opts.bit(flag_bit::VALIDATE),
        "val_renew.c:116-121 KDC_OPT_VALIDATE"
    );
    assert!(!opts.bit(flag_bit::RENEW));
    assert!(
        !opts.bit(flag_bit::CANONICALIZE),
        "validate is not the get_creds referral walk"
    );
}

#[test]
fn b2_validate_options_omit_unset_ticket_flags() {
    let flags = TicketFlags::from_u32(0x4000_0000);
    let opts = tgs_validate_options(&flags);
    assert!(opts.bit(flag_bit::FORWARDABLE));
    assert!(opts.bit(flag_bit::VALIDATE));
    assert!(!opts.bit(flag_bit::PROXIABLE));
    assert!(!opts.bit(flag_bit::RENEWABLE));
    assert!(!opts.bit(flag_bit::RENEW));
    assert!(!opts.bit(flag_bit::CANONICALIZE));
}
