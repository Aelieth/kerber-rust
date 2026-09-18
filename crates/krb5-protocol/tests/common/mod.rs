//! Protocol-crate test glue. Cross-crate helpers live in `krb5-testkit`.

#![allow(dead_code)]

use krb5_crypto::ProtocolKey;
use krb5_kdc::{TEST_USER, TEST_USER_PASSWORD};
use krb5_testkit::password_key;

/// Pin a realm-only profile so host `udp_preference_limit` cannot force TCP.
///
/// Replaces the eight `isolate_host_krb5` copies that called
/// [`krb5_config::isolate_test_krb5`].
pub fn isolate_host_krb5() {
    krb5_config::isolate_test_krb5();
}

/// `TEST_USER` string-to-key with the documented password.
///
/// Replaces the five protocol `client_key` copies (`unwrap` vs
/// `expect("s2k")`).
pub fn client_key() -> ProtocolKey {
    password_key(TEST_USER, TEST_USER_PASSWORD)
}
