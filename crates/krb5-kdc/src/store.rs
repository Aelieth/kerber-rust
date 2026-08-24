//! In-memory principal database and ACL-gated mutations.

use std::collections::HashMap;
use std::time::Duration;

use krb5_crypto::{string_to_key, EncryptionType, ProtocolKey};
use krb5_protocol::{Keytab, KeytabEntry, ReplayCache};
use krb5_types::pkinit::PkinitCa;
use krb5_types::PrincipalName;

use crate::acl::{Acl, AdminOp};
use crate::error::Error;

/// Default PBKDF2 iteration count advertised in ETYPE-INFO2 (RFC 3962 default).
pub const S2K_ITERS: u32 = 4096;

/// MIT `KRB5_KDB_REQUIRES_PRE_AUTH`. Captured `getprinc` + dump field is **128**, not `0x8`.
pub const KDB_REQUIRES_PRE_AUTH: u32 = 0x0000_0080;
/// MIT `KRB5_KDB_DISALLOW_ALL_TIX`.
pub const KDB_DISALLOW_ALL_TIX: u32 = 0x0000_0040;
/// MIT `KRB5_KDB_LOCKDOWN_KEYS`.
pub const KDB_LOCKDOWN_KEYS: u32 = 0x0080_0000;
/// MIT `KRB5_KDB_V1_BASE_LENGTH` (dump `len` field).
pub const KDB_V1_BASE_LENGTH: u32 = 38;

/// Long-term key for one etype.
#[derive(Clone, Debug)]
pub struct KeyEntry {
    /// Encryption type.
    pub etype: EncryptionType,
    /// Protocol key.
    pub key: ProtocolKey,
    /// Key version.
    pub kvno: u32,
    /// MIT `key_data_type[1]` when dump `ver` is 2.
    pub salt_type: Option<i32>,
    /// MIT `key_data_contents[1]` (salt) when dump `ver` is 2.
    pub kdb_salt: Option<Vec<u8>>,
}

impl KeyEntry {
    /// Key without dump salt metadata (`ver` 1 on write).
    #[must_use]
    pub fn new(etype: EncryptionType, key: ProtocolKey, kvno: u32) -> Self {
        Self {
            etype,
            key,
            kvno,
            salt_type: None,
            kdb_salt: None,
        }
    }
}

/// MIT dump `tl_data` triplet (type, length implied by contents).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlData {
    /// `tl_data_type` (`KRB5_TL_*`).
    pub ty: i32,
    /// Raw contents (length is `contents.len()`).
    pub contents: Vec<u8>,
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
    /// MIT KDB attributes bitfield (passthrough for dump/load).
    pub attributes: u32,
    /// Max renewable life in seconds (0 = use realm policy).
    pub max_renewable_life: u64,
    /// Principal expiration unix seconds (0 = never).
    pub expiration: u32,
    /// Last successful authentication unix seconds.
    pub last_success: u32,
    /// Last failed authentication unix seconds.
    pub last_failed: u32,
    /// Failed password attempts.
    pub fail_auth_count: u32,
    /// Master-key kvno that encrypts `key_data`.
    pub mkvno: u16,
    /// Dump `len` field (`KRB5_KDB_V1_BASE_LENGTH` = 38).
    pub db_entry_len: u32,
    /// Opaque MIT `tl_data` for lossless dump round-trip.
    pub tl_data: Vec<TlData>,
    /// Opaque MIT extra data (`e_data`).
    pub e_data: Vec<u8>,
}

impl Principal {
    /// Construct a principal with dump metadata zeroed (KDB3 / bootstrap).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_keys(
        name: PrincipalName,
        realm: String,
        keys: Vec<KeyEntry>,
        salt: Vec<u8>,
        requires_preauth: bool,
        max_life: u64,
        locked: bool,
        pw_expire: u32,
    ) -> Self {
        let mut attributes = 0u32;
        if requires_preauth {
            attributes |= KDB_REQUIRES_PRE_AUTH;
        }
        if locked {
            attributes |= KDB_DISALLOW_ALL_TIX;
        }
        Self {
            name,
            realm,
            keys,
            salt,
            requires_preauth,
            max_life,
            locked,
            pw_expire,
            attributes,
            max_renewable_life: 0,
            expiration: 0,
            last_success: 0,
            last_failed: 0,
            fail_auth_count: 0,
            mkvno: 1,
            db_entry_len: KDB_V1_BASE_LENGTH,
            tl_data: Vec::new(),
            e_data: Vec::new(),
        }
    }
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

    /// MS-KILE `PA-SUPPORTED-ENCTYPES` bits for keys actually present.
    ///
    /// AES-SHA1 17/18 are 0x08/0x10; RFC 8009 19/20 use 0x20/0x40 (the
    /// original MS-KILE table stopped at AES-SHA1; those bits are unused
    /// by FAST/claims which live at 0x00010000+).
    #[must_use]
    pub fn supported_enctypes_mask(&self) -> u32 {
        let mut m = 0u32;
        for k in &self.keys {
            m |= match k.etype {
                EncryptionType::Des3CbcSha1 => 0x0000_0002,
                EncryptionType::Rc4Hmac => 0x0000_0004,
                EncryptionType::Aes128CtsHmacSha196 => 0x0000_0008,
                EncryptionType::Aes256CtsHmacSha196 => 0x0000_0010,
                EncryptionType::Aes128CtsHmacSha256128 => 0x0000_0020,
                EncryptionType::Aes256CtsHmacSha384192 => 0x0000_0040,
                EncryptionType::Camellia128CtsCmac => 0x0000_0080,
                EncryptionType::Camellia256CtsCmac => 0x0000_0100,
            };
        }
        m
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
    /// Last observed (mtime, len) of the db file; kadmind mutations bump it.
    pub(crate) db_stamp: Option<(Option<std::time::SystemTime>, u64)>,
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
            db_stamp: None,
        }
    }

    /// Reload from stash/db when the file mtime or length changed.
    ///
    /// Kadmind and the KDC are separate processes sharing `KRB5_KDC_DB`.
    /// Length is part of the stamp because some filesystems have 1s mtime.
    ///
    /// # Errors
    ///
    /// Persist load failures.
    pub fn reload_if_stale(&mut self) -> Result<(), Error> {
        let Some((db, stash)) = self.persist_paths.clone() else {
            return Ok(());
        };
        let Ok(meta) = std::fs::metadata(&db) else {
            return Ok(());
        };
        let stamp = (meta.modified().ok(), meta.len());
        if Some(stamp) == self.db_stamp {
            return Ok(());
        }
        tracing::info!(
            event = krb5_log::events::KDC_ISSUE,
            component = "krb5-kdc",
            outcome = "ok",
            detail = "reload store",
            db_len = stamp.1,
        );
        let mut loaded =
            crate::persist::load_store(&db, &stash).map_err(|e| Error::Crypto(e.to_string()))?;
        loaded.db_stamp = Some(stamp);
        *self = loaded;
        Ok(())
    }

    fn save_if_configured(&self) -> Result<(), Error> {
        let Some((db, stash)) = &self.persist_paths else {
            return Ok(());
        };
        crate::persist::save_store(self, db, stash).map_err(|e| Error::Crypto(e.to_string()))?;
        tracing::info!(
            event = krb5_log::events::ADMIN,
            component = "krb5-kdc",
            outcome = "ok",
            detail = "saved store",
            db = %db.display(),
        );
        Ok(())
    }

    /// Apply `kdc.conf` ticket policy.
    pub fn apply_kdc_conf(&mut self, conf: &krb5_config::KdcConf) {
        self.policy.max_life = conf.max_life;
        self.policy.max_renewable_life = conf.max_renewable_life;
        self.policy.allow_weak_crypto = conf.allow_weak_crypto;
        self.policy.requires_preauth = conf.requires_preauth;
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
        store.insert_randkey(&PrincipalName::krbtgt(realm), &randkey_etypes())?;
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

    /// Local TGT keys plus inter-realm `krbtgt/FOREIGN` keys (incoming referrals).
    #[must_use]
    pub fn krbtgt_keys(&self) -> Vec<&ProtocolKey> {
        let mut out = Vec::new();
        if let Some(p) = self.krbtgt() {
            for k in &p.keys {
                out.push(&k.key);
            }
        }
        for p in self.map.values() {
            if p.name.is_krbtgt() && !p.name.is_krbtgt_for(&self.realm) {
                for k in &p.keys {
                    out.push(&k.key);
                }
            }
        }
        out
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
        self.insert_randkey(name, &randkey_etypes())
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
        let mut new_keys = Vec::new();
        for etype in [
            EncryptionType::Aes256CtsHmacSha196,
            EncryptionType::Aes128CtsHmacSha196,
            EncryptionType::Aes256CtsHmacSha384192,
            EncryptionType::Aes128CtsHmacSha256128,
        ] {
            let params = s2k_params(etype);
            let key = string_to_key(etype, password, &salt, Some(&params))?;
            new_keys.push(KeyEntry::new(etype, key, next_kvno));
        }
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        p.keys.extend(new_keys);
        self.save_if_configured()
    }

    /// Set lockout and password-expiry, then persist when `persist_paths` is set.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when the principal is missing, or persist I/O.
    pub fn set_status(
        &mut self,
        name: &PrincipalName,
        locked: bool,
        pw_expire: u32,
    ) -> Result<(), Error> {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        p.locked = locked;
        p.pw_expire = pw_expire;
        if locked {
            p.attributes |= KDB_DISALLOW_ALL_TIX;
        } else {
            p.attributes &= !KDB_DISALLOW_ALL_TIX;
        }
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

    /// Inter-realm `krbtgt/FOREIGN` with an explicit shared key (same bytes
    /// on both KDCs; default salts would diverge).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::AlreadyExists`].
    pub fn create_interrealm_key(
        &mut self,
        acl: &Acl,
        actor: &str,
        foreign_realm: &str,
        key: ProtocolKey,
    ) -> Result<(), Error> {
        acl.check(actor, AdminOp::Create)?;
        let name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", foreign_realm]);
        let id = format!("{}@{}", name.components_joined(), self.realm);
        if self.map.contains_key(&id) {
            return Err(Error::AlreadyExists);
        }
        let salt = name.default_salt(&self.realm);
        let p = Principal::from_keys(
            name,
            self.realm.clone(),
            vec![KeyEntry::new(key.etype(), key, 1)],
            salt,
            false,
            0,
            false,
            0,
        );
        self.map.insert(id, p);
        self.save_if_configured()
    }

    /// Extra inter-realm key used only to decrypt tickets the peer issued.
    ///
    /// Windows TDOs derive inbound and outbound AES keys from the same
    /// password with different salts. Insert at the front so [`Principal::best_key`]
    /// (highest kvno, last among ties) stays the issue key.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn add_interrealm_decrypt_key(
        &mut self,
        acl: &Acl,
        actor: &str,
        foreign_realm: &str,
        key: ProtocolKey,
    ) -> Result<(), Error> {
        acl.check(actor, AdminOp::Create)?;
        let name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", foreign_realm]);
        let id = format!("{}@{}", name.components_joined(), self.realm);
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        let kvno = p.keys.iter().map(|k| k.kvno).min().unwrap_or(1);
        p.keys.insert(0, KeyEntry::new(key.etype(), key, kvno));
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
        let mut keys = Vec::new();
        for etype in [
            EncryptionType::Aes256CtsHmacSha196,
            EncryptionType::Aes128CtsHmacSha196,
            EncryptionType::Aes256CtsHmacSha384192,
            EncryptionType::Aes128CtsHmacSha256128,
        ] {
            let params = s2k_params(etype);
            let key = string_to_key(etype, password, &salt, Some(&params))?;
            keys.push(KeyEntry::new(etype, key, 1));
        }
        let p = Principal::from_keys(
            name.clone(),
            self.realm.clone(),
            keys,
            salt,
            self.policy.requires_preauth,
            0,
            false,
            0,
        );
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
            keys.push(KeyEntry::new(*etype, random_key(*etype)?, 1));
        }
        let salt = name.default_salt(&self.realm);
        let p = Principal::from_keys(
            name.clone(),
            self.realm.clone(),
            keys,
            salt,
            false,
            0,
            false,
            0,
        );
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

fn randkey_etypes() -> [EncryptionType; 4] {
    [
        EncryptionType::Aes256CtsHmacSha196,
        EncryptionType::Aes128CtsHmacSha196,
        EncryptionType::Aes256CtsHmacSha384192,
        EncryptionType::Aes128CtsHmacSha256128,
    ]
}

/// s2kparams (4-byte big-endian iteration count) for `etype`.
///
/// RFC 3962 default 4096; RFC 8009 default 32768. MIT 1.22 rejects the
/// SHA-1 count on SHA-2 etypes (`KRB5_ERR_BAD_S2K_PARAMS`).
#[must_use]
pub fn s2k_params(etype: EncryptionType) -> Vec<u8> {
    etype.default_iterations().to_be_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_kdc_conf_sets_ticket_policy() {
        let mut store = PrincipalStore::new("KERBER.TEST");
        let conf = krb5_config::KdcConf::parse(
            r"
[realms]
    KERBER.TEST = {
        max_life = 1h 30m
        max_renewable_life = 2d 0h 0m 0s
        requires_preauth = no
        allow_weak_crypto = yes
    }
",
        )
        .unwrap();
        store.apply_kdc_conf(&conf);
        assert_eq!(store.policy.max_life, 5400);
        assert_eq!(store.policy.max_renewable_life, 2 * 86400);
        assert!(!store.policy.requires_preauth);
        assert!(store.policy.allow_weak_crypto);
    }
}
