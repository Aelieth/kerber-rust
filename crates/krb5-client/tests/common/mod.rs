//! Client-crate test glue. Cross-crate helpers live in `krb5-testkit`.

#![allow(dead_code)]

/// Pin a realm-only profile so host `udp_preference_limit` cannot force TCP.
///
/// Replaces `r1_ccache_config.rs`'s `isolate_host_krb5`.
pub fn isolate_host_krb5() {
    krb5_config::isolate_test_krb5();
}
