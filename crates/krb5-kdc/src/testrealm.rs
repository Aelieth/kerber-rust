//! KERBER.TEST, the documented realm.

use super::{Acl, Error, PrincipalStore, admin_id_for_realm, bootstrap_realm};
use krb5_types::PrincipalName;

pub const TEST_REALM: &str = "KERBER.TEST";
pub const TEST_USER: &str = "user";
pub const TEST_USER_PASSWORD: &[u8] = b"userpassword";
pub const TEST_ADMIN: &str = "admin";
pub const TEST_ADMIN_PASSWORD: &[u8] = b"adminpassword";
pub const TEST_HOST: &str = "testhost.kerber.test";
pub const TEST_SUPPORTED_ENCTYPES: [krb5_crypto::EncryptionType; 4] = [
    krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
    krb5_crypto::EncryptionType::Aes128CtsHmacSha196,
    krb5_crypto::EncryptionType::Aes256CtsHmacSha384192,
    krb5_crypto::EncryptionType::Aes128CtsHmacSha256128,
];

#[must_use]
pub fn documented_host() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", TEST_HOST])
}

#[must_use]
pub fn documented_kiprop() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_HST, ["kiprop", TEST_HOST])
}

#[must_use]
pub fn documented_admin_id() -> String {
    admin_id_for_realm(TEST_REALM)
}

#[cfg(any(test, feature = "test-hooks"))]
pub const TEST_MASTER_PASSWORD: &[u8] = b"masterpassword";

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
