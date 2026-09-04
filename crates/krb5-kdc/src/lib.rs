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
mod kdb;
mod kdb_dump;
mod listen;
mod mkey;
mod persist;
mod plugins;
mod preauth;
mod store;

pub use acl::{Acl, AclEntry, AdminOp, Restrictions};
pub use ad::{
    decrypt_ticket_part, pac_from_ticket_part, sign_pac, ticket_checksum_der, verify_pac,
    verify_pac_signatures, wrap_win2k_pac,
};
pub use error::Error;
pub use issue::{IssuedAs, IssuedTgs, handle_request, issue_as, issue_tgs, kdc_error_bytes};
pub use kdb::{
    KdcEnv, MemoryStore, PrincipalRead, PrincipalWrite, Store, StoreLifecycle, lookup_principal_id,
    open_store,
};
pub use kdb_dump::{
    DumpError, DumpFile, DumpKeyData, DumpKeySlot, DumpPrincipal, KDB_DUMP_VERSION,
    KDB_DUMP_VERSION_R18, TL_KADM_DATA, TL_KERBER_HIST, TL_KERBER_POLICY, TL_KERBER_SERIAL,
    TL_KERBER_SID, TL_LAST_PWD_CHANGE, TL_MKVNO, TL_MOD_PRINC, TL_STRING_ATTRS, dump_store,
    dump_store_etype, dump_store_iprop, load_dump, load_dump_etype, load_dump_mkey, load_dump_path,
    parse_dump, write_dump, write_dump_path, write_dump_path_etype,
};
pub use krb5_protocol::{as_req, pa_enc_timestamp, tgs_req};
pub use listen::{
    BIND_CANDIDATES, ListenLimits, MAX_DGRAM_REPLY, MAX_TCP_REQUEST, MAX_TCP_WORKERS, SharedDump,
    SharedStore, bind_preferred, bind_udp_tcp, drop_privileges, drop_privileges_to, serve,
    serve_until, shared_dump, shared_store,
};
pub use mkey::{MASTER_NAME, harness_master_etype, master_key_from_password};
pub use persist::{PersistError, load_store, save_store, save_store_legacy_kdb3};
pub use plugins::{
    DemoPolicy, DemoPreauth, DenyPolicy, KdcPolicy, KdcPreauth, clear_thread_policy,
    current_policy, register_preauth, set_policy, set_thread_policy,
};
pub use store::{
    IPROP_FULL_RESYNC, IPROP_NIL, IPROP_OK, IPROP_PERM_DENIED, KDB_DISALLOW_ALL_TIX,
    KDB_DISALLOW_FORWARDABLE, KDB_DISALLOW_POSTDATED, KDB_DISALLOW_PROXIABLE,
    KDB_DISALLOW_RENEWABLE, KDB_DISALLOW_SVR, KDB_DISALLOW_TGT_BASED, KDB_LOCKDOWN_KEYS,
    KDB_NO_AUTH_DATA_REQUIRED, KDB_OK_AS_DELEGATE, KDB_OK_TO_AUTH_AS_DELEGATE,
    KDB_PWCHANGE_SERVICE, KDB_REQUIRES_HW_AUTH, KDB_REQUIRES_PRE_AUTH, KDB_REQUIRES_PWCHANGE,
    KDB_V1_BASE_LENGTH, KeyEntry, NamedPolicy, Policy, Principal, PrincipalStore,
    RID_ADMINISTRATOR, RID_FIRST_USER, RID_KRBTGT, S2K_ITERS, TlData, UlogEntry, random_key,
    s2k_params,
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

/// `admin@<realm>` actor string used by kadmind when no `acl_file` is set.
#[must_use]
pub fn admin_id_for_realm(realm: &str) -> String {
    format!("{TEST_ADMIN}@{realm}")
}

/// `host/testhost.<realm-as-dns>` as NT-SRV-HST.
#[must_use]
pub fn host_for_realm(realm: &str) -> PrincipalName {
    let inst = format!("testhost.{}", realm.to_ascii_lowercase());
    PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", inst.as_str()])
}

/// Kadmind ACL: a readable `acl_file` is the ACL (`auth_acl.c` `acl_init`). No file is the documented default.
///
/// # Errors
///
/// Returns [`Error::Crypto`] when `acl_file` is set but unreadable; [`Error::AclParse`] when the file does not load.
pub fn acl_for_store(realm: &str, acl_file: Option<&std::path::Path>) -> Result<Acl, Error> {
    let default = Acl::parse_with_realm(
        &format!("{} *\nkiprop/*@{realm} p\n", admin_id_for_realm(realm)),
        realm,
    )?;
    let Some(path) = acl_file else {
        return Ok(default);
    };
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::Crypto(format!("acl_file {}: {e}", path.display())))?;
    Acl::parse_with_realm(&text, realm)
}

/// Bootstrap a named realm: krbtgt, user, admin, host, `kadmin/admin`, `kadmin/changepw`.
///
/// # Errors
///
/// Returns crypto failures from string-to-key or ACL-gated host create.
pub fn bootstrap_realm(
    realm: &str,
    user: &str,
    user_password: &[u8],
    admin: &str,
    admin_password: &[u8],
) -> Result<(PrincipalStore, Acl), Error> {
    let mut store = PrincipalStore::bootstrap(realm, user, user_password, admin, admin_password)?;
    let actor = admin_id_for_realm(realm);
    let acl = Acl::allow_admin(&actor)?;
    store.create_host(&acl, &actor, &host_for_realm(realm))?;
    store.create_host(&acl, &actor, &documented_kadmin())?;
    store.create_host(&acl, &actor, &documented_changepw())?;
    store.create_host(&acl, &actor, &documented_kiprop())?;
    apply_kadm5_create_service_attrs(&mut store)?;
    Ok((store, acl))
}

/// MIT `kadm5_create` (`kadm5_create.c`) flags. `create_principal` does not set these.
///
/// # Errors
///
/// [`Error::NotFound`] when the kadmin principals are missing.
pub fn apply_kadm5_create_service_attrs(store: &mut PrincipalStore) -> Result<(), Error> {
    store.apply_admin_fields(
        &documented_kadmin(),
        Some(store::KDB_DISALLOW_TGT_BASED | store::KDB_LOCKDOWN_KEYS),
        None,
        None,
        None,
        None,
        false,
    )?;
    store.apply_admin_fields(
        &documented_changepw(),
        Some(
            store::KDB_DISALLOW_TGT_BASED | store::KDB_PWCHANGE_SERVICE | store::KDB_LOCKDOWN_KEYS,
        ),
        None,
        None,
        None,
        None,
        false,
    )?;
    Ok(())
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
