//! Public KDB extension surface (MIT kdb capabilities as Rust traits).
//!
//! Dump-v7 [`crate::PrincipalStore`] is the default at-rest backend.
//! `db_library` selects the factory; unknown names error. Process-local
//! replay caches and the PKINIT CA live on [`KdcEnv`], not dump rows.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use krb5_crypto::ProtocolKey;
use krb5_protocol::ReplayCache;
use krb5_types::PrincipalName;
use krb5_types::pac::{PacIdentity, RpcSid};
use krb5_types::pkinit::PkinitCa;

use crate::error::Error;
use crate::persist::{PersistError, load_store};
use crate::store::{NamedPolicy, Policy, Principal, PrincipalStore, RID_FIRST_USER};

/// Map a wire name to a `user@REALM` store id.
///
/// NT-ENTERPRISE is a single `user@suffix` component (RFC 6806), not a
/// `/`-joined name. A suffix equal to `realm` (RFC 4120 §6.1, exact
/// octets) maps to `user@realm`. Mixed-case `user@kerber.test` in
/// `KERBER.TEST` is not a local alias (MIT `CLIENT_NOT_FOUND`).
#[must_use]
pub fn lookup_principal_id(name: &PrincipalName, realm: &str) -> String {
    if name.name_type == PrincipalName::NT_ENTERPRISE {
        let raw = name.components_joined();
        if let Some((user, suffix)) = raw.rsplit_once('@')
            && !user.is_empty()
        {
            if suffix == realm {
                return format!("{user}@{realm}");
            }
            return format!("{raw}@{realm}");
        }
        return format!("{raw}@{realm}");
    }
    format!("{}@{}", name.components_joined(), realm)
}

/// Process-local KDC state (replay + PKINIT CA). Not dump/persist rows.
#[derive(Clone, Debug)]
pub struct KdcEnv {
    /// TGS authenticator replay cache.
    pub tgs_replay: ReplayCache,
    /// PA-ENC-TIMESTAMP replay cache.
    pub pa_replay: ReplayCache,
    /// PKINIT test CA.
    pub pkinit_ca: Option<PkinitCa>,
}

impl Default for KdcEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl KdcEnv {
    /// Empty CA, default replay windows.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tgs_replay: ReplayCache::with_limits(50_000, std::time::Duration::from_secs(300)),
            pa_replay: ReplayCache::with_limits(50_000, std::time::Duration::from_secs(300)),
            pkinit_ca: None,
        }
    }
}

/// MIT kdb lookup / iterate (owned rows so a fetch-on-demand backend can impl).
pub trait PrincipalRead: Send + Sync {
    /// Realm name.
    fn realm(&self) -> &str;
    /// Ticket policy.
    fn policy(&self) -> &Policy;
    /// Domain SID.
    fn domain_sid(&self) -> &RpcSid;
    /// Process-local env.
    fn env(&self) -> &KdcEnv;
    /// Lookup `name@REALM`.
    ///
    /// # Errors
    ///
    /// Backend I/O or decode failures.
    fn fetch(&self, id: &str) -> Result<Option<Principal>, Error>;
    /// Lookup by name in this realm.
    ///
    /// # Errors
    ///
    /// Backend failures.
    fn fetch_name(&self, name: &PrincipalName) -> Result<Option<Principal>, Error> {
        self.fetch(&lookup_principal_id(name, self.realm()))
    }
    /// `krbtgt/REALM@REALM`.
    ///
    /// # Errors
    ///
    /// Backend failures.
    fn fetch_krbtgt(&self) -> Result<Option<Principal>, Error> {
        self.fetch_name(&PrincipalName::krbtgt(self.realm()))
    }
    /// Local + inter-realm krbtgt keys.
    ///
    /// # Errors
    ///
    /// Backend failures.
    fn krbtgt_keys(&self) -> Result<Vec<ProtocolKey>, Error>;
    /// Principal ids, sorted.
    ///
    /// # Errors
    ///
    /// Backend failures.
    fn list_ids(&self) -> Result<Vec<String>, Error>;
    /// All principals (iterate).
    ///
    /// # Errors
    ///
    /// Backend failures.
    fn list_principals(&self) -> Result<Vec<Principal>, Error>;
    /// TGS replay cache.
    fn tgs_replay(&self) -> &ReplayCache {
        &self.env().tgs_replay
    }
    /// PA-ENC-TIMESTAMP replay cache.
    fn pa_replay(&self) -> &ReplayCache {
        &self.env().pa_replay
    }
    /// PKINIT CA if provisioned.
    fn pkinit_ca(&self) -> Option<&PkinitCa> {
        self.env().pkinit_ca.as_ref()
    }
    /// Fail-count used for lockout (principal row plus overlay).
    fn fail_auth_of(&self, p: &Principal) -> u32 {
        p.fail_auth_count
    }
    /// Last failed AS unix seconds (overlay or dump field).
    fn last_failed_of(&self, p: &Principal) -> u32 {
        p.last_failed
    }
    /// Last successful AS unix seconds (overlay or dump field).
    fn last_success_of(&self, p: &Principal) -> u32 {
        p.last_success
    }
    /// Max failures before CLIENT_REVOKED (0 = none).
    fn max_fail_for(&self, p: &Principal) -> u32 {
        let _ = p;
        0
    }
    /// Record AS password success/failure.
    fn record_as_outcome(&self, _name: &PrincipalName, _ok: bool) {}
    /// Bound named policy, if any.
    fn named_policy_for(&self, p: &Principal) -> Option<NamedPolicy> {
        let _ = p;
        None
    }
    /// Zero fail count without stamping last_success (interval window).
    fn clear_as_fail_count(&self, _name: &PrincipalName) {}
    /// PAC identity for `name` in `crealm`.
    fn pac_identity(&self, name: &PrincipalName, crealm: &str) -> PacIdentity {
        let rid = self
            .fetch_name(name)
            .ok()
            .flatten()
            .map_or(RID_FIRST_USER, |p| {
                if p.rid == 0 { RID_FIRST_USER } else { p.rid }
            });
        PacIdentity {
            sam: name.components_joined(),
            realm: crealm.to_owned(),
            domain_sid: self.domain_sid().clone(),
            rid,
        }
    }
}

/// MIT kdb mutate.
pub trait PrincipalWrite: PrincipalRead {
    /// Insert or replace a principal.
    ///
    /// # Errors
    ///
    /// Backend failures.
    fn put_principal(&mut self, p: Principal) -> Result<(), Error>;
    /// Delete by `name@REALM`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] or backend failures.
    fn remove_id(&mut self, id: &str) -> Result<(), Error>;
    /// Provision a PKINIT CA on the process-local env.
    ///
    /// # Errors
    ///
    /// Key generation failure.
    fn enable_pkinit_ca(&mut self) -> Result<&PkinitCa, Error>;
}

/// Reload / persist gate.
pub trait StoreLifecycle {
    /// Reload from disk when the file stamp changed.
    ///
    /// # Errors
    ///
    /// Persist load failures.
    fn reload_if_stale(&mut self) -> Result<(), Error>;
    /// Write through when persist paths are set.
    ///
    /// # Errors
    ///
    /// Persist save failures.
    fn save_if_configured(&self) -> Result<(), Error>;
}

/// Combined kdb extension surface. Kadmind still locks
/// [`PrincipalStore`] (`SharedDump`); dyn-Store admin is deferred.
pub trait Store: PrincipalRead + PrincipalWrite + StoreLifecycle + Send + Sync {}

impl Store for PrincipalStore {}

impl<T: PrincipalRead + ?Sized> PrincipalRead for std::sync::Arc<T> {
    fn realm(&self) -> &str {
        (**self).realm()
    }
    fn policy(&self) -> &Policy {
        (**self).policy()
    }
    fn domain_sid(&self) -> &RpcSid {
        (**self).domain_sid()
    }
    fn env(&self) -> &KdcEnv {
        (**self).env()
    }
    fn fetch(&self, id: &str) -> Result<Option<Principal>, Error> {
        (**self).fetch(id)
    }
    fn krbtgt_keys(&self) -> Result<Vec<ProtocolKey>, Error> {
        <T as PrincipalRead>::krbtgt_keys(&**self)
    }
    fn list_ids(&self) -> Result<Vec<String>, Error> {
        (**self).list_ids()
    }
    fn list_principals(&self) -> Result<Vec<Principal>, Error> {
        (**self).list_principals()
    }
    fn fail_auth_of(&self, p: &Principal) -> u32 {
        (**self).fail_auth_of(p)
    }
    fn last_failed_of(&self, p: &Principal) -> u32 {
        (**self).last_failed_of(p)
    }
    fn last_success_of(&self, p: &Principal) -> u32 {
        (**self).last_success_of(p)
    }
    fn max_fail_for(&self, p: &Principal) -> u32 {
        (**self).max_fail_for(p)
    }
    fn record_as_outcome(&self, name: &PrincipalName, ok: bool) {
        (**self).record_as_outcome(name, ok);
    }
    fn named_policy_for(&self, p: &Principal) -> Option<NamedPolicy> {
        (**self).named_policy_for(p)
    }
    fn clear_as_fail_count(&self, name: &PrincipalName) {
        (**self).clear_as_fail_count(name);
    }
}

/// Open a backend from `db_library` (kdc.conf). Dump-v7 is the default.
///
/// # Errors
///
/// Unknown `db_library`, or dump load failures.
pub fn open_store(
    db_library: Option<&str>,
    db: &Path,
    stash: &Path,
) -> Result<PrincipalStore, PersistError> {
    match db_library.map(str::trim).filter(|s| !s.is_empty()) {
        None | Some("dump" | "dump-v7" | "kdb5_dump") => load_store(db, stash),
        Some(name) => Err(PersistError::UnknownDbLibrary(name.to_owned())),
    }
}

/// In-tree second backend (BTreeMap). Servable when `db_library=memory`
/// (seeded from dump). Kadmind still mutates dump-v7 [`PrincipalStore`].
#[derive(Debug)]
pub struct MemoryStore {
    realm: String,
    map: BTreeMap<String, Principal>,
    policy: Policy,
    domain_sid: RpcSid,
    next_rid: u32,
    env: KdcEnv,
    lookups: AtomicU64,
    policies: HashMap<String, NamedPolicy>,
    as_fail: Arc<Mutex<HashMap<String, crate::store::AsFailState>>>,
}

impl MemoryStore {
    /// Empty realm.
    #[must_use]
    pub fn new(realm: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
            map: BTreeMap::new(),
            policy: Policy::default(),
            domain_sid: RpcSid::from_sddl("S-1-5-21-10-20-30").unwrap_or_else(RpcSid::dummy_domain),
            next_rid: RID_FIRST_USER,
            env: KdcEnv::new(),
            lookups: AtomicU64::new(0),
            policies: HashMap::new(),
            as_fail: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Copy principals out of a dump-v7 store.
    #[must_use]
    pub fn from_dump(store: &PrincipalStore) -> Self {
        let mut m = Self::new(store.realm());
        m.policy = store.policy().clone();
        m.domain_sid = store.domain_sid().clone();
        m.next_rid = store.next_rid();
        m.policies.clone_from(store.policies());
        for p in store.debug_principals() {
            m.map.insert(p.id(), p.clone());
        }
        m
    }

    /// How many [`PrincipalRead::fetch`] calls hit this map.
    #[must_use]
    pub fn lookup_count(&self) -> u64 {
        self.lookups.load(Ordering::SeqCst)
    }
}

impl PrincipalRead for MemoryStore {
    fn realm(&self) -> &str {
        &self.realm
    }
    fn policy(&self) -> &Policy {
        &self.policy
    }
    fn domain_sid(&self) -> &RpcSid {
        &self.domain_sid
    }
    fn env(&self) -> &KdcEnv {
        &self.env
    }
    fn fetch(&self, id: &str) -> Result<Option<Principal>, Error> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        Ok(self.map.get(id).cloned())
    }
    fn krbtgt_keys(&self) -> Result<Vec<ProtocolKey>, Error> {
        let mut out = Vec::new();
        if let Some(p) = self.fetch_krbtgt()? {
            out.extend(p.keys.iter().map(|k| k.key.clone()));
        }
        for p in self.map.values() {
            if p.name.is_krbtgt() && !p.name.is_krbtgt_for(&self.realm) {
                out.extend(p.keys.iter().map(|k| k.key.clone()));
            }
        }
        Ok(out)
    }
    fn list_ids(&self) -> Result<Vec<String>, Error> {
        Ok(self.map.keys().cloned().collect())
    }
    fn list_principals(&self) -> Result<Vec<Principal>, Error> {
        Ok(self.map.values().cloned().collect())
    }
    fn fail_auth_of(&self, p: &Principal) -> u32 {
        self.as_fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&p.id())
            .map_or(p.fail_auth_count, |s| s.count)
    }
    fn last_failed_of(&self, p: &Principal) -> u32 {
        self.as_fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&p.id())
            .map_or(p.last_failed, |s| s.last_failed)
    }
    fn last_success_of(&self, p: &Principal) -> u32 {
        self.as_fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&p.id())
            .map_or(p.last_success, |s| s.last_success)
    }
    fn max_fail_for(&self, p: &Principal) -> u32 {
        p.pw_policy
            .as_ref()
            .and_then(|n| self.policies.get(n))
            .map_or(0, |pol| pol.max_fail)
    }
    fn record_as_outcome(&self, name: &PrincipalName, ok: bool) {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        let fallback = self
            .map
            .get(&id)
            .map_or(crate::store::AsFailState::default(), |p| {
                crate::store::AsFailState {
                    count: p.fail_auth_count,
                    last_failed: p.last_failed,
                    last_success: p.last_success,
                }
            });
        let now = crate::store::unix_now_u32();
        let mut g = self
            .as_fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cur = g.get(&id).copied().unwrap_or(fallback);
        if ok {
            g.insert(
                id,
                crate::store::AsFailState {
                    count: 0,
                    last_failed: cur.last_failed,
                    last_success: now,
                },
            );
        } else {
            g.insert(
                id,
                crate::store::AsFailState {
                    count: cur.count.saturating_add(1),
                    last_failed: now,
                    last_success: cur.last_success,
                },
            );
        }
    }
    fn named_policy_for(&self, p: &Principal) -> Option<NamedPolicy> {
        p.pw_policy
            .as_ref()
            .and_then(|n| self.policies.get(n).cloned())
    }
    fn clear_as_fail_count(&self, name: &PrincipalName) {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        let fallback = self
            .map
            .get(&id)
            .map_or(crate::store::AsFailState::default(), |p| {
                crate::store::AsFailState {
                    count: 0,
                    last_failed: p.last_failed,
                    last_success: p.last_success,
                }
            });
        let mut g = self
            .as_fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match g.get_mut(&id) {
            Some(s) => s.count = 0,
            None => {
                g.insert(id, fallback);
            }
        }
    }
}

impl PrincipalWrite for MemoryStore {
    fn put_principal(&mut self, p: Principal) -> Result<(), Error> {
        self.map.insert(p.id(), p);
        Ok(())
    }
    fn remove_id(&mut self, id: &str) -> Result<(), Error> {
        self.map.remove(id).ok_or(Error::NotFound)?;
        Ok(())
    }
    fn enable_pkinit_ca(&mut self) -> Result<&PkinitCa, Error> {
        if self.env.pkinit_ca.is_none() {
            self.env.pkinit_ca = PkinitCa::generate();
        }
        self.env
            .pkinit_ca
            .as_ref()
            .ok_or_else(|| Error::Crypto("pkinit CA generate failed".into()))
    }
}

impl StoreLifecycle for MemoryStore {
    fn reload_if_stale(&mut self) -> Result<(), Error> {
        Ok(())
    }
    fn save_if_configured(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl Store for MemoryStore {}

impl PrincipalRead for PrincipalStore {
    fn realm(&self) -> &str {
        self.realm()
    }
    fn policy(&self) -> &Policy {
        self.policy()
    }
    fn domain_sid(&self) -> &RpcSid {
        self.domain_sid()
    }
    fn env(&self) -> &KdcEnv {
        self.env()
    }
    fn fetch(&self, id: &str) -> Result<Option<Principal>, Error> {
        Ok(self.get(id).cloned())
    }
    fn fetch_name(&self, name: &PrincipalName) -> Result<Option<Principal>, Error> {
        Ok(self.get_name(name).cloned())
    }
    fn krbtgt_keys(&self) -> Result<Vec<ProtocolKey>, Error> {
        Ok(self.krbtgt_key_vec())
    }
    fn list_ids(&self) -> Result<Vec<String>, Error> {
        Ok(self.ids())
    }
    fn list_principals(&self) -> Result<Vec<Principal>, Error> {
        Ok(self.debug_principals().cloned().collect())
    }
    fn fail_auth_of(&self, p: &Principal) -> u32 {
        PrincipalStore::fail_auth_of(self, p)
    }
    fn last_failed_of(&self, p: &Principal) -> u32 {
        PrincipalStore::last_failed_of(self, p)
    }
    fn last_success_of(&self, p: &Principal) -> u32 {
        PrincipalStore::last_success_of(self, p)
    }
    fn max_fail_for(&self, p: &Principal) -> u32 {
        PrincipalStore::max_fail_for(self, p)
    }
    fn record_as_outcome(&self, name: &PrincipalName, ok: bool) {
        PrincipalStore::record_as_outcome(self, name, ok);
    }
    fn named_policy_for(&self, p: &Principal) -> Option<NamedPolicy> {
        PrincipalStore::named_policy_for(self, p)
    }
    fn clear_as_fail_count(&self, name: &PrincipalName) {
        PrincipalStore::clear_as_fail_count(self, name);
    }
}

impl PrincipalWrite for PrincipalStore {
    fn put_principal(&mut self, p: Principal) -> Result<(), Error> {
        self.debug_insert(p);
        Ok(())
    }
    fn remove_id(&mut self, id: &str) -> Result<(), Error> {
        self.remove_id_inner(id)
    }
    fn enable_pkinit_ca(&mut self) -> Result<&PkinitCa, Error> {
        PrincipalStore::enable_pkinit_ca(self)
    }
}

impl StoreLifecycle for PrincipalStore {
    fn reload_if_stale(&mut self) -> Result<(), Error> {
        PrincipalStore::reload_if_stale(self)
    }
    fn save_if_configured(&self) -> Result<(), Error> {
        self.save_configured()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TEST_REALM;
    use crate::bootstrap_documented;
    use krb5_protocol::as_req;
    use krb5_types::PrincipalName;

    #[test]
    fn unknown_db_library_errors() {
        let err = open_store(Some("lmdb"), Path::new("/nope"), Path::new("/nope")).unwrap_err();
        match err {
            PersistError::UnknownDbLibrary(n) => assert_eq!(n, "lmdb"),
            other => panic!("expected UnknownDbLibrary, got {other}"),
        }
    }

    #[test]
    fn issue_as_hits_memory_store() {
        let (dump, _) = bootstrap_documented().unwrap();
        let mem = MemoryStore::from_dump(&dump);
        let before = mem.lookup_count();
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        let key = dump
            .get_name(&cname)
            .expect("user")
            .best_key()
            .expect("key")
            .key
            .clone();
        let padata = vec![krb5_protocol::pa_enc_timestamp(&key).expect("pa-ts")];
        let req = as_req(cname, TEST_REALM, 11, Some(padata)).unwrap();
        crate::issue_as(&mem, &req).expect("AS via MemoryStore");
        assert!(
            mem.lookup_count() > before,
            "issue_as must fetch through MemoryStore"
        );
    }

    #[test]
    fn memory_store_lockout_revokes_after_max_fail() {
        use krb5_protocol::{pa_enc_timestamp, pa_enc_timestamp_at};
        use krb5_types::KerberosTime;

        use crate::TEST_USER;
        use crate::error::Error;

        let (mut dump, _) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        dump.put_policy(NamedPolicy {
            name: "strict".into(),
            min_length: 8,
            min_classes: 2,
            history: 1,
            max_fail: 3,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
        });
        dump.set_principal_policy(&user, Some("strict".into()))
            .unwrap();
        let mem = MemoryStore::from_dump(&dump);
        let key = dump
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let good = as_req(
            user.clone(),
            TEST_REALM,
            1,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        let zeros = krb5_crypto::ProtocolKey::from_bytes(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            &[0u8; 32],
        )
        .unwrap();
        let mut skew = 0i64;
        let mut bad_as = || {
            skew += 1;
            let ts = KerberosTime::now().add_seconds(skew).unwrap();
            as_req(
                user.clone(),
                TEST_REALM,
                1,
                Some(vec![pa_enc_timestamp_at(&zeros, &ts).unwrap()]),
            )
            .unwrap()
        };
        let revoked = |e: &Error| matches!(e, Error::Protocol { code, .. } if *code == krb5_types::err::CLIENT_REVOKED);
        assert!(crate::issue_as(&mem, &bad_as()).is_err());
        assert!(crate::issue_as(&mem, &bad_as()).is_err());
        crate::issue_as(&mem, &good).expect("success must reset fail count");
        assert!(crate::issue_as(&mem, &bad_as()).is_err());
        let second = crate::issue_as(&mem, &bad_as()).unwrap_err();
        assert!(
            !revoked(&second),
            "second fail after success must not lock: {second:?}"
        );
        assert!(crate::issue_as(&mem, &bad_as()).is_err());
        let locked = crate::issue_as(&mem, &bad_as()).unwrap_err();
        assert!(revoked(&locked), "expected CLIENT_REVOKED, got {locked:?}");
    }
}
