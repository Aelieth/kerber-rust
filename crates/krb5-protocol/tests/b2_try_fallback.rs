//! W1-B B2: MIT `try_fallback` after the first referral TGS error.
//! `get_creds.c:503-543`. Live oracle: `kvno` cells (`MIT_try_fallback`).
//! Unit-only: `tgs_try_fallback` is new at the parent. Host-realm DNS
//! rewrite is deferred (B3 `krb5_get_fallback_host_realm`).

use krb5_protocol::{TgsFallback, tgs_non_referral_options, tgs_try_fallback};
use krb5_types::{KdcOptions, flag_bit};

#[test]
fn b2_try_fallback_specified_realm_is_non_referral() {
    assert_eq!(tgs_try_fallback(1, true, 2), TgsFallback::NonReferral);
}

#[test]
fn b2_try_fallback_later_hop_keeps_error() {
    assert_eq!(tgs_try_fallback(2, true, 2), TgsFallback::KeepError);
    assert_eq!(tgs_try_fallback(2, false, 2), TgsFallback::KeepError);
}

#[test]
fn b2_try_fallback_referral_one_comp_is_host_realm_unknown() {
    assert_eq!(tgs_try_fallback(1, false, 1), TgsFallback::HostRealmUnknown);
}

#[test]
fn b2_try_fallback_referral_host_is_host_realm() {
    assert_eq!(tgs_try_fallback(1, false, 2), TgsFallback::HostRealm);
}

#[test]
fn b2_try_fallback_non_referral_drops_canonicalize() {
    let opts = KdcOptions::forwardable().with_bit(flag_bit::CANONICALIZE, true);
    let retry = tgs_non_referral_options(opts);
    assert!(!retry.bit(flag_bit::CANONICALIZE));
    assert!(retry.bit(flag_bit::FORWARDABLE));
}
