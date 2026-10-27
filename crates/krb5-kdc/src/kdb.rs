//! The KDB traits and dump-v7.

#[cfg(any(test, feature = "test-hooks"))]
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
#[cfg(any(test, feature = "test-hooks"))]
use std::sync::Mutex;
#[cfg(any(test, feature = "test-hooks"))]
use std::sync::atomic::{AtomicU64, Ordering};

use krb5_types::PrincipalName;
use krb5_types::pac::{PacIdentity, RpcSid};

use crate::dblock::DbLockHold;
use crate::error::Error;
#[cfg(any(test, feature = "test-hooks"))]
use crate::lockout::Lockout;
use crate::lockout::LockoutUpdate;
use crate::persist::{PersistError, load_store};
use crate::store::{
    MAX_ALIAS_DEPTH, NamedPolicy, Policy, Principal, PrincipalStore, RID_FIRST_USER, strip_db_args,
};

#[must_use]
/// An enterprise suffix matches the realm byte for byte.
pub fn lookup_principal_id(name: &PrincipalName, realm: &str) -> String {
    if name.name_type == PrincipalName::NT_ENTERPRISE {
        let raw = name.components_joined();
        if let Some((user, suffix)) = raw.rsplit_once('@')
            && !user.is_empty()
        {
            if suffix == realm {
                return format!("{user}@{realm}");
            }
            return krb5_types::unparse_name(std::slice::from_ref(&raw), realm);
        }
        return krb5_types::unparse_name(std::slice::from_ref(&raw), realm);
    }
    name.unparse_with_realm(realm)
}

// MIT: `krb5_db_get_principal` (kdb5.c:800-840)
/// One hop past the depth is none, not that hop.
pub fn resolve_alias_id<'a>(
    realm: &str,
    lookup: impl Fn(&str) -> Option<&'a Principal>,
    id: &str,
) -> Option<String> {
    let mut id = id.to_owned();
    let mut p = lookup(&id)?;
    let mut depth = 0usize;
    while let Some(target) = p.alias_target() {
        depth += 1;
        if depth > MAX_ALIAS_DEPTH {
            return None;
        }
        let (name, target_realm) = krb5_types::principal_from_unparsed(&target, realm).ok()?;
        id = lookup_principal_id(&name, &target_realm);
        p = lookup(&id)?;
    }
    Some(id)
}

// MIT: `kdc_process_tgs_req` (kdc/kdc_util.c:189-191)
// MIT: `enc_ts_verify` (kdc/kdc_preauth_encts.c:47-118)
#[derive(Clone, Debug)]
pub struct KdcEnv {
    pub pkinit: Option<std::sync::Arc<crate::pkinit::PkinitKdc>>,
}

impl Default for KdcEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl KdcEnv {
    #[must_use]
    pub fn new() -> Self {
        Self { pkinit: None }
    }
}

/// A locked database is Error::Protocol SVC_UNAVAILABLE (MIT KRB5_KDB_CANTLOCK_DB).
pub trait PrincipalRead: Send + Sync {
    fn realm(&self) -> &str;
    fn policy(&self) -> &Policy;
    fn domain_sid(&self) -> &RpcSid;
    fn env(&self) -> &KdcEnv;
    fn fetch(&self, id: &str) -> Result<Option<Principal>, Error>;
    fn fetch_name(&self, name: &PrincipalName) -> Result<Option<Principal>, Error> {
        self.fetch(&lookup_principal_id(name, self.realm()))
    }
    fn fetch_krbtgt(&self) -> Result<Option<Principal>, Error> {
        self.fetch_name(&PrincipalName::krbtgt(self.realm()))
    }
    fn list_ids(&self) -> Result<Vec<String>, Error>;
    fn list_principals(&self) -> Result<Vec<Principal>, Error>;
    fn pkinit(&self) -> Option<&crate::pkinit::PkinitKdc> {
        self.env().pkinit.as_deref()
    }
    // MIT: `klmdb_get_principal` (plugins/kdb/lmdb/kdb_lmdb.c:713-744)
    fn merge_lockout(&self, p: &mut Principal) {
        let _ = p;
    }
    // MIT: `klmdb_update_lockout` (plugins/kdb/lmdb/kdb_lmdb.c:1054-1121)
    fn update_lockout(&self, p: &Principal, stamp: u32, update: LockoutUpdate) {
        let _ = (p, stamp, update);
    }
    fn fail_auth_of(&self, p: &Principal) -> u32 {
        let mut q = p.clone();
        self.merge_lockout(&mut q);
        q.fail_auth_count
    }
    fn last_failed_of(&self, p: &Principal) -> u32 {
        let mut q = p.clone();
        self.merge_lockout(&mut q);
        q.last_failed
    }
    fn last_success_of(&self, p: &Principal) -> u32 {
        let mut q = p.clone();
        self.merge_lockout(&mut q);
        q.last_success
    }
    /// The default of 0 does not lock the account.
    fn max_fail_for(&self, p: &Principal) -> u32 {
        let _ = p;
        0
    }
    #[cfg(feature = "test-hooks")]
    fn record_as_outcome(&self, name: &PrincipalName, ok: bool) {
        let Ok(Some(p)) = self.fetch_name(name) else {
            return;
        };
        let status = if ok {
            0
        } else {
            krb5_types::err::PREAUTH_FAILED
        };
        crate::lockout::lockout_audit(self, &p, crate::store::unix_now_u32(), status);
    }
    fn named_policy_for(&self, p: &Principal) -> Option<NamedPolicy> {
        let _ = p;
        None
    }
    // MIT: `krb5_ldap_check_allowed_to_delegate` (plugins/kdb/ldap/libkdb_ldap/kdb_ldap.c:286-316)
    fn allowed_to_delegate(&self, server: &Principal, proxy: &PrincipalName) -> bool {
        let realm = self.realm();
        server.s4u_allowed_to.iter().any(|entry| {
            krb5_types::principal_from_unparsed(entry, realm).is_ok_and(|(name, entry_realm)| {
                krb5_types::principal_compare(&name, &entry_realm, proxy, realm)
            })
        })
    }
    fn allowed_from(
        &self,
        resource: &Principal,
        client: &PrincipalName,
        client_realm: &str,
    ) -> bool {
        let _ = self;
        let from = client.unparse_with_realm(client_realm);
        resource.s4u_allowed_from.iter().any(|n| n == &from)
    }
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
    fn otp_runtime(&self) -> Option<&crate::plugins::OtpRuntime> {
        None
    }
}

pub trait PrincipalWrite: PrincipalRead {
    /// A KRB5_TL_DB_ARGS tag is refused.
    fn put_principal(&mut self, p: Principal) -> Result<(), Error>;
    fn remove_id(&mut self, id: &str) -> Result<(), Error>;
}

pub trait StoreLifecycle {
    fn reload_if_stale(&mut self) -> Result<(), Error>;
    fn read_hold(&self) -> Result<Option<(DbLockHold, bool)>, Error> {
        Ok(None)
    }
    fn install_otp_runtime(&mut self, rt: std::sync::Arc<crate::plugins::OtpRuntime>) {
        let _ = rt;
    }
    fn take_otp_runtime(&mut self) -> Option<std::sync::Arc<crate::plugins::OtpRuntime>> {
        None
    }
}

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
    fn list_ids(&self) -> Result<Vec<String>, Error> {
        (**self).list_ids()
    }
    fn list_principals(&self) -> Result<Vec<Principal>, Error> {
        (**self).list_principals()
    }
    fn merge_lockout(&self, p: &mut Principal) {
        (**self).merge_lockout(p);
    }
    fn update_lockout(&self, p: &Principal, stamp: u32, update: LockoutUpdate) {
        (**self).update_lockout(p, stamp, update);
    }
    fn max_fail_for(&self, p: &Principal) -> u32 {
        (**self).max_fail_for(p)
    }
    fn named_policy_for(&self, p: &Principal) -> Option<NamedPolicy> {
        (**self).named_policy_for(p)
    }
    fn otp_runtime(&self) -> Option<&crate::plugins::OtpRuntime> {
        (**self).otp_runtime()
    }
    fn allowed_to_delegate(&self, server: &Principal, proxy: &PrincipalName) -> bool {
        (**self).allowed_to_delegate(server, proxy)
    }
    fn allowed_from(
        &self,
        resource: &Principal,
        client: &PrincipalName,
        client_realm: &str,
    ) -> bool {
        (**self).allowed_from(resource, client, client_realm)
    }
}

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

#[derive(Debug)]
#[cfg(any(test, feature = "test-hooks"))]
pub struct MemoryStore {
    realm: String,
    map: BTreeMap<String, Principal>,
    policy: Policy,
    domain_sid: RpcSid,
    next_rid: u32,
    env: KdcEnv,
    lookups: AtomicU64,
    policies: HashMap<String, NamedPolicy>,
    lockout: Mutex<HashMap<String, Lockout>>,
}

#[cfg(any(test, feature = "test-hooks"))]
impl MemoryStore {
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
            lockout: Mutex::new(HashMap::new()),
        }
    }

    #[must_use]
    pub fn from_dump(store: &PrincipalStore) -> Self {
        let mut m = Self::new(store.realm());
        m.policy = store.policy().clone();
        m.domain_sid = store.domain_sid().clone();
        m.next_rid = store.next_rid();
        m.policies.clone_from(store.policies());
        m.env = store.env().clone();
        for p in store.debug_principals() {
            m.map.insert(p.id(), p.clone());
        }
        m
    }

    #[must_use]
    pub fn lookup_count(&self) -> u64 {
        self.lookups.load(Ordering::SeqCst)
    }
}

#[cfg(any(test, feature = "test-hooks"))]
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
        let id = resolve_alias_id(&self.realm, |k| self.map.get(k), id);
        Ok(id.and_then(|id| {
            self.map.get(&id).cloned().map(|mut p| {
                self.merge_lockout(&mut p);
                p
            })
        }))
    }
    fn list_ids(&self) -> Result<Vec<String>, Error> {
        Ok(self.map.keys().cloned().collect())
    }
    fn list_principals(&self) -> Result<Vec<Principal>, Error> {
        Ok(self
            .map
            .values()
            .cloned()
            .map(|mut p| {
                self.merge_lockout(&mut p);
                p
            })
            .collect())
    }
    fn merge_lockout(&self, p: &mut Principal) {
        if let Some(l) = self
            .lockout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&p.id())
        {
            l.set_on(p);
        }
    }
    /// Lockout sits beside the principal.
    fn update_lockout(&self, p: &Principal, stamp: u32, update: LockoutUpdate) {
        let mut g = self
            .lockout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let base = g.get(&p.id()).copied().unwrap_or_else(|| Lockout::of(p));
        g.insert(p.id(), update.apply(base, stamp));
    }
    fn max_fail_for(&self, p: &Principal) -> u32 {
        p.pw_policy
            .as_ref()
            .and_then(|n| self.policies.get(n))
            .map_or(0, |pol| pol.max_fail)
    }
    fn named_policy_for(&self, p: &Principal) -> Option<NamedPolicy> {
        p.pw_policy
            .as_ref()
            .and_then(|n| self.policies.get(n).cloned())
    }
}

#[cfg(any(test, feature = "test-hooks"))]
impl PrincipalWrite for MemoryStore {
    fn put_principal(&mut self, mut p: Principal) -> Result<(), Error> {
        strip_db_args(&mut p.tl_data)?;
        p.reconcile_flags();
        self.map.insert(p.id(), p);
        Ok(())
    }
    fn remove_id(&mut self, id: &str) -> Result<(), Error> {
        self.map.remove(id).ok_or(Error::NotFound)?;
        Ok(())
    }
}

#[cfg(any(test, feature = "test-hooks"))]
impl StoreLifecycle for MemoryStore {
    fn reload_if_stale(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(any(test, feature = "test-hooks"))]
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
    fn otp_runtime(&self) -> Option<&crate::plugins::OtpRuntime> {
        self.otp_runtime()
    }
    fn fetch(&self, id: &str) -> Result<Option<Principal>, Error> {
        Ok(self.get(id).cloned().map(|mut p| {
            self.merge_lockout(&mut p);
            p
        }))
    }
    fn fetch_name(&self, name: &PrincipalName) -> Result<Option<Principal>, Error> {
        Ok(self.get_name(name).cloned().map(|mut p| {
            self.merge_lockout(&mut p);
            p
        }))
    }
    fn list_ids(&self) -> Result<Vec<String>, Error> {
        Ok(self.ids())
    }
    fn list_principals(&self) -> Result<Vec<Principal>, Error> {
        Ok(self
            .debug_principals()
            .cloned()
            .map(|mut p| {
                self.merge_lockout(&mut p);
                p
            })
            .collect())
    }
    fn merge_lockout(&self, p: &mut Principal) {
        PrincipalStore::merge_lockout(self, p);
    }
    fn update_lockout(&self, p: &Principal, stamp: u32, update: LockoutUpdate) {
        PrincipalStore::update_lockout(self, p, stamp, update);
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
    #[cfg(feature = "test-hooks")]
    fn record_as_outcome(&self, name: &PrincipalName, ok: bool) {
        PrincipalStore::record_as_outcome(self, name, ok);
    }
    fn named_policy_for(&self, p: &Principal) -> Option<NamedPolicy> {
        PrincipalStore::named_policy_for(self, p)
    }
}

impl PrincipalWrite for PrincipalStore {
    // MIT: `krb5_db_put_principal` (lib/kdb/kdb5.c:987-1007)
    /// This put is an update-log record.
    fn put_principal(&mut self, mut p: Principal) -> Result<(), Error> {
        strip_db_args(&mut p.tl_data)?;
        self.change(|s| {
            PrincipalStore::put_principal(s, p)?;
            s.save_configured()
        })?
    }
    fn remove_id(&mut self, id: &str) -> Result<(), Error> {
        self.change(|s| s.remove_id_inner(id))?
    }
}

impl StoreLifecycle for PrincipalStore {
    fn reload_if_stale(&mut self) -> Result<(), Error> {
        PrincipalStore::reload_if_stale(self)
    }
    fn read_hold(&self) -> Result<Option<(DbLockHold, bool)>, Error> {
        PrincipalStore::read_hold(self)
    }
    fn install_otp_runtime(&mut self, rt: std::sync::Arc<crate::plugins::OtpRuntime>) {
        PrincipalStore::install_otp_runtime(self, rt);
    }
    fn take_otp_runtime(&mut self) -> Option<std::sync::Arc<crate::plugins::OtpRuntime>> {
        PrincipalStore::take_otp_runtime(self)
    }
}
