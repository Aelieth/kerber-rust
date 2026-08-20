//! In-memory principal database and ACL-gated mutations.

use std::collections::HashMap;
use std::time::Duration;

use krb5_crypto::{spake_w, string_to_key, EncryptionType, ProtocolKey};
use krb5_protocol::{Keytab, KeytabEntry, ReplayCache};
use krb5_types::pkinit::PkinitCa;
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
    /// Keys by etype (may include multiple kvnos).
    pub keys: Vec<KeyEntry>,
    /// Salt used for password-derived keys.
    pub salt: Vec<u8>,
    /// Whether AS requires PA-ENC-TIMESTAMP.
    pub requires_preauth: bool,
    /// Max ticket life in seconds (0 = use realm policy).
    pub max_life: u64,
    /// Locked out.
    pub locked: bool,
    /// Password expiry unix seconds (0 = none).
    pub pw_expire: u32,
    /// SPAKE2 `w` derived from the password (or key bytes for random-key principals).
    pub spake_w: [u8; 32],
}

/// Realm-wide ticket policy.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Max ticket lifetime seconds.
    pub max_life: u64,
    /// Max renewable lifetime seconds.
    pub max_renewable_life: u64,
    /// Clock skew seconds.
    pub skew: i64,
    /// Allow weak etypes.
    pub allow_weak_crypto: bool,
    /// Default requires_preauth for new principals.
    pub requires_preauth: bool,
    /// Cross-realm transited realms that are rejected (`KDC_ERR_PATH_NOT_ACCEPTED`).
    pub transited_reject: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_life: 10 * 3600,
            max_renewable_life: 7 * 24 * 3600,
            skew: 300,
            allow_weak_crypto: false,
            requires_preauth: true,
            transited_reject: Vec::new(),
        }
    }
}

impl Principal {
    /// `name@REALM` lookup key.
    #[must_use]
    pub fn id(&self) -> String {
        format!("{}@{}", self.name.components_joined(), self.realm)
    }

    /// First key of `etype`, if present (highest kvno preferred).
    #[must_use]
    pub fn key_for(&self, etype: EncryptionType) -> Option<&KeyEntry> {
        self.keys
            .iter()
            .filter(|k| k.etype == etype)
            .max_by_key(|k| k.kvno)
    }

    /// Key matching `etype` and `kvno`.
    #[must_use]
    pub fn key_for_kvno(&self, etype: EncryptionType, kvno: u32) -> Option<&KeyEntry> {
        self.keys
            .iter()
            .find(|k| k.etype == etype && k.kvno == kvno)
            .or_else(|| self.key_for(etype))
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
    /// Ticket policy.
    pub policy: Policy,
    /// TGS authenticator replay cache.
    pub tgs_replay: ReplayCache,
    /// PA-ENC-TIMESTAMP replay cache.
    pub pa_replay: ReplayCache,
    /// PKINIT test CA (`pkinit_anchors` FILE).
    pub pkinit_ca: Option<PkinitCa>,
    /// Optional `(db, stash)` paths; mutations write through when set.
    pub persist_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
}

impl PrincipalStore {
    /// Empty store for `realm`.
    #[must_use]
    pub fn new(realm: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
            map: HashMap::new(),
            policy: Policy::default(),
            tgs_replay: ReplayCache::with_limits(50_000, Duration::from_secs(300)),
            pa_replay: ReplayCache::with_limits(50_000, Duration::from_secs(300)),
            pkinit_ca: None,
            persist_paths: None,
        }
    }

    fn save_if_configured(&self) -> Result<(), Error> {
        let Some((db, stash)) = &self.persist_paths else {
            return Ok(());
        };
        crate::persist::save_store(self, db, stash).map_err(|e| Error::Crypto(e.to_string()))
    }

    /// Provision a PKINIT test CA. Off by default so a KDC without an
    /// operator-supplied trust anchor does not mint untrusted CMS.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when P-256 key generation fails.
    pub fn enable_pkinit_ca(&mut self) -> Result<&PkinitCa, Error> {
        if self.pkinit_ca.is_none() {
            self.pkinit_ca = PkinitCa::generate();
        }
        self.pkinit_ca
            .as_ref()
            .ok_or_else(|| Error::Crypto("pkinit CA generate failed".into()))
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

    /// PEM of the PKINIT test CA for MIT `pkinit_anchors = FILE:`.
    #[must_use]
    pub fn pkinit_anchor_pem(&self) -> Option<String> {
        self.pkinit_ca.as_ref().map(PkinitCa::cert_pem)
    }

    /// User identity PEM (cert+key) for MIT `X509_user_identity=FILE:`.
    #[must_use]
    pub fn pkinit_user_pem(&self, cn: &str) -> Option<String> {
        self.pkinit_ca
            .as_ref()
            .and_then(|c| c.user_identity_pem(cn))
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
        name: &PrincipalName,
        password: &[u8],
    ) -> Result<(), Error> {
        acl.check(actor, AdminOp::Create)?;
        let id = format!("{}@{}", name.components_joined(), self.realm);
        if self.map.contains_key(&id) {
            return Err(Error::AlreadyExists);
        }
        self.insert_password(name, password)
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
        name: &PrincipalName,
    ) -> Result<(), Error> {
        acl.check(actor, AdminOp::Create)?;
        let id = format!("{}@{}", name.components_joined(), self.realm);
        if self.map.contains_key(&id) {
            return Err(Error::AlreadyExists);
        }
        self.insert_randkey(name, &[EncryptionType::Aes256CtsHmacSha196])
    }

    /// Replace password-derived keys (kpasswd): bump kvno, keep prior keys
    /// and principal policy.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when the principal is missing.
    pub fn set_password(&mut self, name: &PrincipalName, password: &[u8]) -> Result<(), Error> {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        let Some(existing) = self.map.get(&id) else {
            return Err(Error::NotFound);
        };
        let salt = existing.salt.clone();
        let next_kvno = existing
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let params = S2K_ITERS.to_be_bytes();
        let mut new_keys = Vec::new();
        for etype in [
            EncryptionType::Aes256CtsHmacSha196,
            EncryptionType::Aes128CtsHmacSha196,
            EncryptionType::Aes256CtsHmacSha384192,
            EncryptionType::Aes128CtsHmacSha256128,
        ] {
            let key = string_to_key(etype, password, &salt, Some(&params))?;
            new_keys.push(KeyEntry {
                etype,
                key,
                kvno: next_kvno,
            });
        }
        let w = spake_w(new_keys[0].key.as_bytes(), &salt);
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        p.keys.extend(new_keys);
        p.spake_w = w;
        self.save_if_configured()
    }

    /// ACL-gated inter-realm `krbtgt/FOREIGN` (shared key with the foreign KDC).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::AlreadyExists`].
    pub fn create_interrealm(
        &mut self,
        acl: &Acl,
        actor: &str,
        foreign_realm: &str,
        password: &[u8],
    ) -> Result<(), Error> {
        acl.check(actor, AdminOp::Create)?;
        let name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", foreign_realm]);
        let id = format!("{}@{}", name.components_joined(), self.realm);
        if self.map.contains_key(&id) {
            return Err(Error::AlreadyExists);
        }
        self.insert_password(&name, password)?;
        if let Some(p) = self.map.get_mut(&id) {
            p.requires_preauth = false;
        }
        self.save_if_configured()
    }

    /// ACL-gated password change (admin `c` / `*`).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn change_password(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
        password: &[u8],
    ) -> Result<(), Error> {
        acl.check(actor, AdminOp::ChangePassword)?;
        self.set_password(name, password)
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
        self.save_if_configured()
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
        if p.keys.is_empty() {
            return Err(Error::NotFound);
        }
        let ts = krb5_types::KerberosTime::now().unix_seconds();
        let realm =
            krb5_types::try_ascii(&p.realm).map_err(|_| Error::Crypto("non-ascii realm".into()))?;
        let entries = p
            .keys
            .iter()
            .map(|key| KeytabEntry {
                realm: realm.clone(),
                name: p.name.clone(),
                timestamp: ts,
                kvno: key.kvno,
                key: key.key.clone(),
            })
            .collect();
        Ok(Keytab {
            version: 0x0502,
            skipped_unknown_etype: 0,
            entries,
        })
    }

    fn insert_password(&mut self, name: &PrincipalName, password: &[u8]) -> Result<(), Error> {
        let salt = name.default_salt(&self.realm);
        let params = S2K_ITERS.to_be_bytes();
        let mut keys = Vec::new();
        for etype in [
            EncryptionType::Aes256CtsHmacSha196,
            EncryptionType::Aes128CtsHmacSha196,
            EncryptionType::Aes256CtsHmacSha384192,
            EncryptionType::Aes128CtsHmacSha256128,
        ] {
            let key = string_to_key(etype, password, &salt, Some(&params))?;
            keys.push(KeyEntry {
                etype,
                key,
                kvno: 1,
            });
        }
        let w = spake_w(keys[0].key.as_bytes(), &salt);
        let p = Principal {
            name: name.clone(),
            realm: self.realm.clone(),
            keys,
            salt,
            requires_preauth: self.policy.requires_preauth,
            max_life: 0,
            locked: false,
            pw_expire: 0,
            spake_w: w,
        };
        self.map.insert(p.id(), p);
        self.save_if_configured()
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
        let salt = name.default_salt(&self.realm);
        let w = keys.first().map_or_else(
            || spake_w(&salt, &salt),
            |k| spake_w(k.key.as_bytes(), &salt),
        );
        let p = Principal {
            name: name.clone(),
            realm: self.realm.clone(),
            keys,
            salt,
            requires_preauth: false,
            max_life: 0,
            locked: false,
            pw_expire: 0,
            spake_w: w,
        };
        self.map.insert(p.id(), p);
        self.save_if_configured()
    }

    /// Key of `etype` at `kvno` for principal `name`.
    #[must_use]
    pub fn key_kvno(
        &self,
        name: &PrincipalName,
        etype: EncryptionType,
        kvno: Option<u32>,
    ) -> Option<&KeyEntry> {
        let p = self.get_name(name)?;
        match kvno {
            Some(v) => p.key_for_kvno(etype, v),
            None => p.key_for(etype),
        }
    }

    /// Iterate principals (persistence).
    pub(crate) fn debug_principals(&self) -> impl Iterator<Item = &Principal> {
        self.map.values()
    }

    /// Insert a fully-formed principal (persistence).
    pub(crate) fn debug_insert(&mut self, p: Principal) {
        self.map.insert(p.id(), p);
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
