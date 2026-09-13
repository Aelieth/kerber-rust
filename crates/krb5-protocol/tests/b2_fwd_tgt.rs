//! W1-B B2: MIT `krb5_fwd_tgt_creds` options. `fwd_tgt.c:147-153`.
//! Live oracle: GSS / `kvno` cells (`MIT_fwd_tgt`).
//! Unit-only: `tgs_forward_options` is new at the parent.
//! Remote `k5_os_hostaddr` when the TGT has addresses is deferred (B3).

use krb5_protocol::tgs_forward_options;
use krb5_types::{TicketFlags, flag_bit};

fn common_flags() -> TicketFlags {
    TicketFlags::none()
        .with_bit(flag_bit::FORWARDABLE, true)
        .with_bit(flag_bit::RENEWABLE, true)
}

#[test]
fn b2_fwd_tgt_options_are_common_mask_plus_forwarded() {
    let opts = tgs_forward_options(&common_flags(), true);
    assert!(opts.bit(flag_bit::FORWARDED));
    assert!(opts.bit(flag_bit::FORWARDABLE));
    assert!(opts.bit(flag_bit::RENEWABLE));
    assert!(!opts.bit(flag_bit::CANONICALIZE));
    assert!(!opts.bit(flag_bit::PROXIABLE));
}

#[test]
fn b2_fwd_tgt_not_forwardable_clears_forwardable() {
    let opts = tgs_forward_options(&common_flags(), false);
    assert!(opts.bit(flag_bit::FORWARDED));
    assert!(!opts.bit(flag_bit::FORWARDABLE));
    assert!(opts.bit(flag_bit::RENEWABLE));
}
