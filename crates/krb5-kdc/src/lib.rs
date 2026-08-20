//! Pure-Rust Kerberos V5 KDC: AS/TGS issue, ACL-gated admin, keytab export.
//!
//! Ticket issuance, ACL checks, and keytab export are pure functions so tests
//! do not need a bound socket. UDP/TCP 88 is a thin listener over
//! [`handle_request`]. There is no C FFI.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod acl;
mod ad;
mod error;
mod issue;
mod listen;
mod persist;
mod preauth;
mod store;

pub use acl::{Acl, AclEntry, AdminOp};
pub use ad::{decrypt_ticket_part, pac_from_ticket_part, sign_pac, verify_pac};
pub use error::Error;
pub use issue::{handle_request, issue_as, issue_tgs, IssuedAs, IssuedTgs};
pub use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};
pub use listen::{bind_preferred, bind_udp_tcp, serve, BIND_CANDIDATES};
pub use persist::{load_store, save_store, PersistError};
pub use preauth::spake_w_from_key;
pub use store::{random_key, s2k_params, KeyEntry, Policy, Principal, PrincipalStore, S2K_ITERS};

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

/// `admin@KERBER.TEST` actor string.
#[must_use]
pub fn documented_admin_id() -> String {
    format!("{TEST_ADMIN}@{TEST_REALM}")
}

/// Bootstrap the documented realm: krbtgt, user, admin, host.
///
/// # Errors
///
/// Returns crypto failures from string-to-key or ACL-gated host create.
pub fn bootstrap_documented() -> Result<(PrincipalStore, Acl), Error> {
    let mut store = PrincipalStore::bootstrap(
        TEST_REALM,
        TEST_USER,
        TEST_USER_PASSWORD,
        TEST_ADMIN,
        TEST_ADMIN_PASSWORD,
    )?;
    let acl = Acl::allow_admin(documented_admin_id());
    store.create_host(&acl, &documented_admin_id(), &documented_host())?;
    Ok((store, acl))
}
