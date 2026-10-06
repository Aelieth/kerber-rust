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
/// The key types the documented realm gives a principal when its profile names no
/// `supported_enctypes`: all four AES types, where a production realm takes MIT's two.
pub const TEST_SUPPORTED_ENCTYPES: [krb5_crypto::EncryptionType; 4] = [
    krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
    krb5_crypto::EncryptionType::Aes128CtsHmacSha196,
    krb5_crypto::EncryptionType::Aes256CtsHmacSha384192,
    krb5_crypto::EncryptionType::Aes128CtsHmacSha256128,
];

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

/// The master password the gates' realms are made with.
#[cfg(any(test, feature = "test-hooks"))]
pub const TEST_MASTER_PASSWORD: &[u8] = b"masterpassword";

/// Give a store with no database an update log in memory of `entries` entries, in `role`, and
/// a `K/M` entry holding the master key [`TEST_MASTER_PASSWORD`] makes for its realm, which the
/// keys of its logged updates are wrapped under (as a database's are under its stash's). Returns
/// that key.
///
/// # Errors
///
/// [`Error::Crypto`] when the master key cannot be derived; [`Error::Db`] when the log cannot be
/// made.
#[cfg(any(test, feature = "test-hooks"))]
pub fn map_memory_ulog(
    store: &mut PrincipalStore,
    entries: u32,
    role: crate::IpropRole,
) -> Result<krb5_crypto::ProtocolKey, Error> {
    let realm = store.realm().to_owned();
    let master = crate::master_key_from_password(
        &realm,
        TEST_MASTER_PASSWORD,
        crate::default_master_etype(),
    )?;
    if store.get(&format!("K/M@{realm}")).is_none() {
        let km = crate::create_realm(&realm, None, &master, 1)?
            .get_raw(&format!("K/M@{realm}"))
            .cloned()
            .ok_or(Error::NotFound)?;
        store.debug_insert(km);
    }
    let ulog = crate::Ulog::memory(entries).map_err(|e| Error::Db {
        kind: std::io::ErrorKind::Other,
        text: e.to_string(),
    })?;
    store.set_ulog(ulog, role);
    Ok(master)
}

/// Bootstrap the documented realm: krbtgt, user, admin, host.
///
/// # Errors
///
/// [`Error::Rng`] when the CSPRNG fails while generating a random key.
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
