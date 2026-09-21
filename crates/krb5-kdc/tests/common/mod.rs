//! KDC-crate test glue. Cross-crate helpers live in `krb5-testkit`.

#![allow(dead_code)]

use krb5_crypto::ProtocolKey;
use krb5_kdc::testrealm::{TEST_USER, TEST_USER_PASSWORD};

use krb5_testkit::password_key;

/// `TEST_USER` string-to-key with the documented password.
///
/// Replaces `issue_acl_ap.rs`'s `client_key`.
pub fn client_key() -> ProtocolKey {
    password_key(TEST_USER, TEST_USER_PASSWORD)
}
