//! In-memory principal database and ACL-gated mutations.

use std::collections::HashMap;

use krb5_client::{Keytab, KeytabEntry};
use krb5_crypto::{string_to_key, EncryptionType, ProtocolKey};
use krb5_types::PrincipalName;

use crate::acl::{Acl, AdminOp};
use crate::error::Error;

/// Default PBKDF2 iteration count advertised in ETYPE-INFO2 (RFC 3962 default).
pub const S2K_ITERS: u32 = 4096;

/// Long-term key for one etype.
#[derive(Clone, Debug)]
pub struct KeyEntry {
    /// Encryption type.
    pub etype: EncryptionType,
    /// Protocol key.
    pub key: ProtocolKey,
    /// Key version.
    pub kvno: u32,
}

/// One realm principal.
#[derive(Clone, Debug)]
pub struct Principal {
    /// Name (no realm).
    pub name: PrincipalName,
    /// Realm.
    pub realm: String,
    /// Keys by etype.
    pub keys: Vec<KeyEntry>,
    /// Salt used for password-derived keys.
    pub salt: Vec<u8>,
}

impl Principal {
    /// `name@REALM` lookup key.
    #[must_use]
    pub fn id(&self) -> String {
        format!("{}@{}", self.name.components_joined(), self.realm)
    }

    /// First key of `etype`, if present.
    #[must_use]
    pub fn key_for(&self, etype: EncryptionType) -> Option<&KeyEntry> {
        self.keys.iter().find(|k| k.etype == etype)
    }

    /// Preferred stored key (highest etype in [`EncryptionType::preferred`]).
    #[must_use]
    pub fn best_key(&self) -> Option<&KeyEntry> {
        EncryptionType::preferred()
            .into_iter()
            .find_map(|e| self.key_for(e))
            .or_else(|| self.keys.first())
    }
}

/// Realm principal store.
#[derive(Clone, Debug)]
pub struct PrincipalStore {
    realm: String,
    map: HashMap<String, Principal>,
}

impl PrincipalStore {
    /// Empty store for `realm`.
    #[must_use]
    pub fn new(realm: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
            map: HashMap::new(),
        }
    }

    /// Realm name.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Seed krbtgt, a password user, and an admin. Host principals are added
    /// through [`Self::create_host`].
    ///
    /// # Errors
    ///
    /// Returns crypto failures from string-to-key.
    pub fn bootstrap(
        realm: &str,
        user: &str,
        user_password: &[u8],
        admin: &str,
        admin_password: &[u8],
    ) -> Result<Self, Error> {
        let mut store = Self::new(realm);
        store.insert_randkey(
            &PrincipalName::krbtgt(realm),
            &[EncryptionType::Aes256CtsHmacSha196],
        )?;
        store.insert_password(
            &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [user]),
            user_password,
        )?;
        store.insert_password(
            &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [admin]),
            admin_password,
        )?;
        Ok(store)
    }

    /// Lookup `name@realm`.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Principal> {
        self.map.get(id)
    }

    /// Lookup by name components in this realm.
    #[must_use]
    pub fn get_name(&self, name: &PrincipalName) -> Option<&Principal> {
        self.map
            .get(&format!("{}@{}", name.components_joined(), self.realm))
    }

    /// `krbtgt/REALM@REALM`.
    #[must_use]
    pub fn krbtgt(&self) -> Option<&Principal> {
        self.get_name(&PrincipalName::krbtgt(&self.realm))
    }

    /// ACL-gated create of a password principal.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::AlreadyExists`].
    pub fn create_password(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: PrincipalName,
        password: &[u8],
    ) -> Result<(), Error> {
        acl.check(actor, AdminOp::Create)?;
        let id = format!("{}@{}", name.components_joined(), self.realm);
        if self.map.contains_key(&id) {
            return Err(Error::AlreadyExists);
        }
        self.insert_password(&name, password)
    }

    /// ACL-gated create of a random-key host (or other) principal.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::AlreadyExists`].
    pub fn create_host(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: PrincipalName,
    ) -> Result<(), Error> {
        acl.check(actor, AdminOp::Create)?;
        let id = format!("{}@{}", name.components_joined(), self.realm);
        if self.map.contains_key(&id) {
            return Err(Error::AlreadyExists);
        }
        self.insert_randkey(&name, &[EncryptionType::Aes256CtsHmacSha196])
    }

    /// ACL-gated delete.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn delete(&mut self, acl: &Acl, actor: &str, name: &PrincipalName) -> Result<(), Error> {
        acl.check(actor, AdminOp::Delete)?;
        let id = format!("{}@{}", name.components_joined(), self.realm);
        self.map.remove(&id).ok_or(Error::NotFound)?;
        Ok(())
    }

    /// ACL-gated keytab export using the existing v2 writer.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn export_keytab(
        &self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
    ) -> Result<Keytab, Error> {
        acl.check(actor, AdminOp::Ktadd)?;
        let p = self.get_name(name).ok_or(Error::NotFound)?;
        let key = p.best_key().ok_or(Error::NotFound)?;
        Ok(Keytab {
            entries: vec![KeytabEntry {
                realm: krb5_types::ascii(&p.realm),
                name: p.name.clone(),
                timestamp: krb5_types::KerberosTime::now().unix_seconds(),
                kvno: key.kvno,
                key: key.key.clone(),
            }],
        })
    }

    fn insert_password(&mut self, name: &PrincipalName, password: &[u8]) -> Result<(), Error> {
        let salt = name.default_salt(&self.realm);
        let params = S2K_ITERS.to_be_bytes();
        let mut keys = Vec::new();
        for etype in [
            EncryptionType::Aes256CtsHmacSha196,
            EncryptionType::Aes128CtsHmacSha196,
        ] {
            let key = string_to_key(etype, password, &salt, Some(&params))?;
            keys.push(KeyEntry {
                etype,
                key,
                kvno: 1,
            });
        }
        let p = Principal {
            name: name.clone(),
            realm: self.realm.clone(),
            keys,
            salt,
        };
        self.map.insert(p.id(), p);
        Ok(())
    }

    fn insert_randkey(
        &mut self,
        name: &PrincipalName,
        etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        let mut keys = Vec::new();
        for etype in etypes {
            keys.push(KeyEntry {
                etype: *etype,
                key: random_key(*etype)?,
                kvno: 1,
            });
        }
        let p = Principal {
            name: name.clone(),
            realm: self.realm.clone(),
            keys,
            salt: name.default_salt(&self.realm),
        };
        self.map.insert(p.id(), p);
        Ok(())
    }
}

/// Fill a random protocol key of `etype`.
///
/// # Errors
///
/// [`Error::Rng`] when the CSPRNG fails.
pub fn random_key(etype: EncryptionType) -> Result<ProtocolKey, Error> {
    let mut buf = vec![0u8; etype.key_len()];
    getrandom::getrandom(&mut buf).map_err(|_| Error::Rng)?;
    ProtocolKey::from_bytes(etype, &buf).map_err(Error::from)
}

/// s2kparams (4-byte big-endian iteration count) used in ETYPE-INFO2.
#[must_use]
pub fn s2k_params() -> Vec<u8> {
    S2K_ITERS.to_be_bytes().to_vec()
}
