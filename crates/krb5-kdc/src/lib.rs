//! Pure-Rust Kerberos V5 KDC: AS/TGS issue, ACL-gated admin, keytab export.
//!
//! Ticket issuance, ACL checks, and keytab export are pure functions so tests
//! do not need a bound socket. UDP/TCP 88 is a thin listener over
//! [`handle_request`]. There is no C FFI.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod acl;
mod ad;
mod error;
mod issue;
mod kdb_dump;
mod listen;
mod mkey;
mod persist;
mod preauth;
mod store;

pub use acl::{Acl, AclEntry, AdminOp};
pub use ad::{
    decrypt_ticket_part, pac_from_ticket_part, sign_pac, ticket_checksum_der, verify_pac,
    verify_pac_signatures, wrap_win2k_pac,
};
pub use error::Error;
pub use issue::{handle_request, issue_as, issue_tgs, IssuedAs, IssuedTgs};
pub use kdb_dump::{
    dump_store, dump_store_etype, load_dump, load_dump_etype, load_dump_mkey, load_dump_path,
    parse_dump, write_dump, write_dump_path, write_dump_path_etype, DumpError, DumpFile,
    DumpKeyData, DumpKeySlot, DumpPrincipal, KDB_DUMP_VERSION, KDB_DUMP_VERSION_R18, TL_KADM_DATA,
    TL_KERBER_SID, TL_LAST_PWD_CHANGE, TL_MKVNO, TL_MOD_PRINC,
};
pub use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};
pub use listen::{
    bind_preferred, bind_udp_tcp, drop_privileges, drop_privileges_to, serve, serve_until,
    shared_store, ListenLimits, SharedStore, BIND_CANDIDATES, MAX_TCP_REQUEST, MAX_TCP_WORKERS,
};
pub use mkey::{harness_master_etype, master_key_from_password, MASTER_NAME};
pub use persist::{load_store, save_store, save_store_legacy_kdb3, PersistError};
pub use store::{
    random_key, s2k_params, KeyEntry, Policy, Principal, PrincipalStore, TlData,
    KDB_DISALLOW_ALL_TIX, KDB_LOCKDOWN_KEYS, KDB_REQUIRES_PRE_AUTH, KDB_V1_BASE_LENGTH,
    RID_ADMINISTRATOR, RID_FIRST_USER, RID_KRBTGT, S2K_ITERS,
};

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

/// `kadmin/admin` as NT-SRV-INST (MIT kadmind acceptor).
#[must_use]
pub fn documented_kadmin() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "admin"])
}

/// `kadmin/changepw` as NT-SRV-INST (RFC 3244 kpasswd acceptor).
#[must_use]
pub fn documented_changepw() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "changepw"])
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
    store.create_host(&acl, &documented_admin_id(), &documented_kadmin())?;
    store.create_host(&acl, &documented_admin_id(), &documented_changepw())?;
    Ok((store, acl))
}
