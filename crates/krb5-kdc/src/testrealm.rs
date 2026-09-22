//! Documented `KERBER.TEST` realm the product binaries seed.
//!
//! `krb5-kdc` and `krb5-kdb create` build this realm from these
//! constants. The module is always compiled.

use super::{Acl, Error, PrincipalStore, admin_id_for_realm, bootstrap_realm};
use krb5_types::PrincipalName;

/// Documented test realm.
pub const TEST_REALM: &str = "KERBER.TEST";
/// Password principal used by MIT `kinit` gates.
pub const TEST_USER: &str = "user";
/// Password for [`TEST_USER`].
pub const TEST_USER_PASSWORD: &[u8] = b"userpassword";
/// Admin principal granted `*` in the documented ACL.
pub const TEST_ADMIN: &str = "admin";
/// Password for [`TEST_ADMIN`].
pub const TEST_ADMIN_PASSWORD: &[u8] = b"adminpassword";
/// Host name component of the documented POSIX host principal.
pub const TEST_HOST: &str = "testhost.kerber.test";

/// `host/testhost.kerber.test` as NT-SRV-HST.
#[must_use]
pub fn documented_host() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", TEST_HOST])
}

/// `kiprop/testhost.kerber.test` as NT-SRV-HST (MIT iprop acceptor).
#[must_use]
pub fn documented_kiprop() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_HST, ["kiprop", TEST_HOST])
}

/// `admin@KERBER.TEST` actor string.
#[must_use]
pub fn documented_admin_id() -> String {
    admin_id_for_realm(TEST_REALM)
}

/// Bootstrap the documented realm: krbtgt, user, admin, host.
///
/// # Errors
///
/// Returns crypto failures from string-to-key or ACL-gated host create.
pub fn bootstrap_documented() -> Result<(PrincipalStore, Acl), Error> {
    bootstrap_realm(
        TEST_REALM,
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
    )
}

mod test_plugins;

pub use test_plugins::{
    DemoPolicy, DemoPreauth, GREET_AD_TYPE, GREET_TEXT, GreetAuth, TestAudit, TestPolicy,
};

#[cfg(test)]
pub use test_plugins::DenyPolicy;
