//! The in-memory principal database and its ACL-gated changes.

mod alias;
mod flags;
mod history;
mod iprop_ulog;
pub(crate) mod iprop_xdr;
mod kadm5_hook;
mod kdb_convert;
mod keys;
mod password;
mod policy;
mod principal;
mod pwqual;
mod pwqual_dict;
mod rid;
mod transit;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use krb5_types::PrincipalName;
use krb5_types::pac::RpcSid;

use crate::dblock::{DbLock, DbLockHold, DbLockMode};
use crate::error::Error;
use crate::persist::{DbStamp, Freshness, PersistError};
use iprop_ulog::{LogContext, LogNote, PrincipalMap};
use kadm5_hook::Post;
use principal::default_mod_actor;
use rid::generate_domain_sid;

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_KTADD_EXPORT: Cell<bool> = const { Cell::new(false) };
    static FAIL_NEXT_CHRAND_SAVE: Cell<bool> = const { Cell::new(false) };
}

pub mod kadm5_mask {
    pub const PRINCIPAL: u32 = 0x0000_0001;
    pub(crate) const PRINC_EXPIRE_TIME: u32 = 0x0000_0002;
    pub(crate) const PW_EXPIRATION: u32 = 0x0000_0004;
    pub const ATTRIBUTES: u32 = 0x0000_0010;
    pub const MAX_LIFE: u32 = 0x0000_0020;
    pub const KVNO: u32 = 0x0000_0100;
    pub const POLICY: u32 = 0x0000_0800;
    pub const POLICY_CLR: u32 = 0x0000_1000;
    pub(crate) const MAX_RLIFE: u32 = 0x0000_2000;
    pub const KEY_DATA: u32 = 0x0002_0000;
}

#[derive(Clone, Debug)]
pub struct PrincipalStore {
    realm: String,
    map: PrincipalMap,
    pub policy: Policy,
    env: crate::kdb::KdcEnv,
    pwqual_dict: Option<Arc<pwqual_dict::PwqualDict>>,
    pub persist_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
    pub(crate) persist_master: Option<(std::path::PathBuf, krb5_crypto::ProtocolKey)>,
    pub(crate) db_stamp: Option<DbStamp>,
    pub(crate) lockout_stamp: Option<(u64, u64, u64, i64, i64)>,
    pub(crate) loaded_span: Option<(u64, u64)>,
    pub(crate) dblock: Option<Arc<DbLock>>,
    changed: ChangeMark,
    wrote_through: ChangeMark,
    /// Never the dummy domain SID `S-1-5-21-1-2-3`.
    domain_sid: RpcSid,
    next_rid: u32,
    policies: HashMap<String, NamedPolicy>,
    lockout: Arc<crate::lockout::LockoutState>,
    log: Option<Arc<LogContext>>,
    pending: PendingNotes,
    saves_held: bool,
    post: Option<Vec<Post>>,
    otp_runtime: Option<Arc<crate::plugins::OtpRuntime>>,
}

#[derive(Debug, Default)]
struct ChangeMark(AtomicBool);

impl Clone for ChangeMark {
    fn clone(&self) -> Self {
        Self(AtomicBool::new(self.0.load(Ordering::Relaxed)))
    }
}

#[derive(Debug)]
struct PendingNotes(Arc<Mutex<Vec<LogNote>>>);

impl PendingNotes {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(Vec::new())))
    }
}

impl Clone for PendingNotes {
    fn clone(&self) -> Self {
        let notes = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        Self(Arc::new(Mutex::new(notes)))
    }
}

impl std::ops::Deref for PendingNotes {
    type Target = Mutex<Vec<LogNote>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct HeldSaves<'a>(&'a mut PrincipalStore);

impl<'a> HeldSaves<'a> {
    fn new(store: &'a mut PrincipalStore) -> Self {
        store.saves_held = true;
        Self(store)
    }
}

impl Drop for HeldSaves<'_> {
    fn drop(&mut self) {
        self.0.saves_held = false;
        if std::thread::panicking() {
            self.0.db_stamp = None;
            self.0.lockout_stamp = None;
        }
    }
}

struct PostQueue<'a>(&'a mut PrincipalStore);

impl<'a> PostQueue<'a> {
    fn new(store: &'a mut PrincipalStore) -> Self {
        store.post = Some(Vec::new());
        Self(store)
    }
}

impl Drop for PostQueue<'_> {
    fn drop(&mut self) {
        self.0.post = None;
    }
}

struct Before {
    policies: HashMap<String, NamedPolicy>,
    next_rid: u32,
    domain_sid: RpcSid,
}

impl Before {
    fn of(store: &PrincipalStore) -> Self {
        Self {
            policies: store.policies.clone(),
            next_rid: store.next_rid,
            domain_sid: store.domain_sid.clone(),
        }
    }

    fn restore(self, store: &mut PrincipalStore) -> bool {
        if !store.map.undo_change() {
            return false;
        }
        store.policies = self.policies;
        store.next_rid = self.next_rid;
        store.domain_sid = self.domain_sid;
        store
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        true
    }
}

pub(crate) fn unix_now_u32() -> u32 {
    krb5_types::unix_now()
}

impl PrincipalStore {
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn new(realm: impl Into<String>) -> Self {
        Self::try_new(realm).expect("the CSPRNG gave no domain SID")
    }

    pub fn try_new(realm: impl Into<String>) -> Result<Self, Error> {
        Ok(Self {
            realm: realm.into(),
            map: PrincipalMap::default(),
            policy: Policy::default(),
            env: crate::kdb::KdcEnv::new(),
            pwqual_dict: None,
            persist_paths: None,
            persist_master: None,
            db_stamp: None,
            lockout_stamp: None,
            loaded_span: None,
            dblock: None,
            changed: ChangeMark::default(),
            wrote_through: ChangeMark::default(),
            domain_sid: generate_domain_sid()?,
            next_rid: RID_FIRST_USER,
            policies: HashMap::new(),
            lockout: Arc::default(),
            log: None,
            pending: PendingNotes::new(),
            saves_held: false,
            post: None,
            otp_runtime: None,
        })
    }

    pub(crate) fn otp_runtime(&self) -> Option<&crate::plugins::OtpRuntime> {
        self.otp_runtime.as_deref()
    }

    pub(crate) fn install_otp_runtime(&mut self, rt: Arc<crate::plugins::OtpRuntime>) {
        self.otp_runtime = Some(rt);
    }

    pub(crate) fn take_otp_runtime(&mut self) -> Option<Arc<crate::plugins::OtpRuntime>> {
        self.otp_runtime.take()
    }

    // MIT: `ctx_lock` (plugins/kdb/db2/kdb_db2.c:439-455)
    pub fn reload_if_stale(&mut self) -> Result<(), Error> {
        let Some(db) = self.db_path().map(std::path::Path::to_path_buf) else {
            return Ok(());
        };
        let lock = self.db_lock()?;
        let _held = lock
            .hold(DbLockMode::Shared)
            .map_err(|e| Error::from(PersistError::from(e)))?;
        self.catch_up(&lock, &db).map(|_| ())
    }

    fn catch_up(&mut self, lock: &Arc<DbLock>, db: &std::path::Path) -> Result<Freshness, Error> {
        let fresh = self
            .db_stamp
            .as_ref()
            .map_or(Freshness::Other, |s| s.freshness(lock, db));
        match fresh {
            Freshness::Same => Ok(fresh),
            Freshness::Grown if self.take_appended(lock, db) => Ok(fresh),
            _ => self.reread(lock).map(|()| Freshness::Other),
        }
    }

    /// `K/M` and `kadmin/history` are not password changes.
    fn take_appended(&mut self, lock: &Arc<DbLock>, db: &std::path::Path) -> bool {
        use crate::kdb_dump::JournalOp;
        let (Some(stamp), Some(mkey)) = (self.db_stamp.clone(), self.journal_key()) else {
            return false;
        };
        let Ok(bytes) = crate::persist::read_appended(db, stamp.applied) else {
            return false;
        };
        let Ok(Ok(Some((ops, used)))) =
            std::str::from_utf8(&bytes).map(crate::kdb_dump::parse_journal_tail)
        else {
            return false;
        };
        let realm = self.realm.clone();
        let count = ops.len();
        let mut taken = Vec::with_capacity(count);
        for op in ops {
            match op {
                JournalOp::Put(dp) => {
                    if dp.name == format!("K/M@{realm}")
                        || dp.name == format!("kadmin/history@{realm}")
                    {
                        return false;
                    }
                    match dp.into_principal(&mkey) {
                        Ok((p, _)) => taken.push(Ok(p)),
                        Err(_) => return false,
                    }
                }
                JournalOp::Del(id) => taken.push(Err(id)),
            }
        }
        let mut ids = Vec::with_capacity(taken.len());
        for op in taken {
            match op {
                Ok(p) => {
                    ids.push(p.id());
                    self.debug_insert(p);
                }
                Err(id) => self.debug_remove(&id),
            }
        }
        self.resolve_history_of(&ids);
        self.merge_lockout_if_moved(db);
        let applied = stamp.applied + u64::try_from(used).unwrap_or_default();
        let records = stamp.records + u64::try_from(count).unwrap_or_default();
        self.db_stamp = DbStamp::holding(lock, db, records, applied);
        true
    }

    pub(crate) fn journal_key(&self) -> Option<krb5_crypto::ProtocolKey> {
        if let Some((_, master)) = &self.persist_master {
            return Some(master.clone());
        }
        self.get(&format!("K/M@{}", self.realm))
            .and_then(|km| km.keys.first())
            .map(|k| k.key.clone())
    }

    pub fn reload(&mut self) -> Result<(), Error> {
        self.db_stamp = None;
        self.lockout_stamp = None;
        self.reload_if_stale()
    }

    // MIT: `open_db` (plugins/kdb/db2/kdb_db2.c:386-389)
    pub(crate) fn reread(&mut self, lock: &Arc<DbLock>) -> Result<(), Error> {
        tracing::info!(
            event = krb5_log::events::KDC_LISTEN,
            correlation_id = krb5_log::current_correlation_id(),
            component = "krb5-kdc",
            outcome = "ok",
            detail = "reload store",
        );
        let (db, loaded) = match (&self.persist_master, &self.persist_paths) {
            (Some((db, master)), _) => {
                (db, crate::persist::read_store_with_master(db, master, lock))
            }
            (None, Some((db, stash))) => (db, crate::persist::read_store(db, stash, lock)),
            (None, None) => return Ok(()),
        };
        let mut loaded = loaded.map_err(|e| match e {
            e @ PersistError::Unopenable { .. } => Error::from(e),
            e => match Error::from(e) {
                Error::Db { kind, text } => Error::Db {
                    kind,
                    text: format!("Cannot open DB2 database '{}': {text}", db.display()),
                },
                other => other,
            },
        })?;
        loaded.policy = std::mem::take(&mut self.policy);
        loaded.pwqual_dict = self.pwqual_dict.take();
        if loaded.policy.ad_identity {
            loaded.domain_sid.clone_from(&self.domain_sid);
        }
        loaded.lockout = Arc::clone(&self.lockout);
        loaded.env = std::mem::take(&mut self.env);
        loaded.log = self.log.take();
        loaded.map.set_records_log(loaded.log.is_some());
        loaded.saves_held = self.saves_held;
        loaded.post = self.post.take();
        loaded.otp_runtime = self.otp_runtime.take();
        *self = loaded;
        Ok(())
    }

    pub(crate) fn db_path(&self) -> Option<&std::path::Path> {
        match (&self.persist_master, &self.persist_paths) {
            (Some((db, _)), _) | (None, Some((db, _))) => Some(db.as_path()),
            (None, None) => None,
        }
    }

    pub(crate) fn db_lock(&mut self) -> Result<Arc<DbLock>, Error> {
        if let Some(lock) = &self.dblock {
            return Ok(Arc::clone(lock));
        }
        let Some(db) = self.db_path() else {
            return Err(Error::Db {
                kind: std::io::ErrorKind::NotFound,
                text: "no database".to_owned(),
            });
        };
        let lock = Arc::new(DbLock::open(db).map_err(|e| Error::from(PersistError::from(e)))?);
        self.dblock = Some(Arc::clone(&lock));
        Ok(lock)
    }

    pub fn read_hold(&self) -> Result<Option<(DbLockHold, bool)>, Error> {
        let (Some(db), Some(lock)) = (self.db_path(), &self.dblock) else {
            return Ok(None);
        };
        let held = lock
            .hold(DbLockMode::Shared)
            .map_err(|e| Error::from(PersistError::from(e)))?;
        let stale = !self.db_stamp.as_ref().is_some_and(|s| s.same(lock, db));
        Ok(Some((held, stale)))
    }

    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    #[must_use]
    pub fn env(&self) -> &crate::kdb::KdcEnv {
        &self.env
    }

    pub(crate) fn save_configured(&self) -> Result<(), Error> {
        self.save_if_configured()
    }

    /// A store with a database refuses a save outside `change`.
    fn save_if_configured(&self) -> Result<(), Error> {
        self.changed.0.store(true, Ordering::Relaxed);
        if self.db_path().is_none() {
            return self.log_pending();
        }
        self.inside_change()
    }

    /// A put that must stick is written before the change can roll it back.
    fn save_through(&self) -> Result<(), Error> {
        self.inside_change()?;
        self.wrote_through.0.store(true, Ordering::Relaxed);
        self.logged_write(|| self.write_database())
    }

    pub(crate) fn flush_unlogged(&mut self) -> Result<(), Error> {
        self.save_through()
    }

    fn inside_change(&self) -> Result<(), Error> {
        match self.db_path() {
            Some(db) if !self.saves_held => Err(Error::Db {
                kind: std::io::ErrorKind::Other,
                text: format!(
                    "{}: a change outside the database's exclusive lock",
                    db.display()
                ),
            }),
            _ => Ok(()),
        }
    }

    fn write_database(&self) -> Result<(), PersistError> {
        match (&self.persist_master, &self.persist_paths) {
            (Some((db, master)), _) => crate::persist::save_store_with_master(
                self,
                db,
                master,
                crate::persist::DbWrite::InPlace,
            ),
            (None, Some((db, stash))) => crate::persist::save_store(self, db, stash),
            (None, None) => Ok(()),
        }
    }

    // MIT: `krb5_db2_put_principal` (plugins/kdb/db2/kdb_db2.c:828-854)
    // MIT: `ctx_lock` (plugins/kdb/db2/kdb_db2.c:439-455)
    /// The exclusive lock reopens the database, so the put starts from disk.
    pub fn change<T, E>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<Result<T, E>, Error> {
        if self.post.is_some() {
            return Ok(f(self));
        }
        let queue = PostQueue::new(self);
        let out = queue.0.change_locked(f);
        let calls = queue.0.post.take().unwrap_or_default();
        drop(queue);
        let committed = matches!(out, Ok(Ok(_)));
        for call in calls {
            if committed || call.always() {
                call.run(self);
            }
        }
        out
    }

    pub(crate) fn postcommit(&mut self, call: Post) {
        if let Some(calls) = self.post.as_mut() {
            calls.push(call);
        } else {
            call.run(self);
        }
    }

    fn change_locked<T, E>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<Result<T, E>, Error> {
        if self.saves_held {
            return Ok(f(self));
        }
        let Some(db) = self.db_path().map(std::path::Path::to_path_buf) else {
            return Ok(f(self));
        };
        let lock = self.db_lock()?;
        let held = lock
            .hold(DbLockMode::Exclusive)
            .map_err(|e| Error::from(PersistError::from(e)))?;
        self.refresh_for_change(&lock, &db)?;
        self.changed.0.store(false, Ordering::Relaxed);
        self.wrote_through.0.store(false, Ordering::Relaxed);
        let before = Before::of(self);
        self.map.begin_change();
        let done = {
            let inside = HeldSaves::new(self);
            f(&mut *inside.0)
        };
        let out = match done {
            Ok(v) if self.changed.0.load(Ordering::Relaxed) => {
                let append = self.append_plan(&before);
                let mut appended = 0;
                let written = self
                    .prepare_log()
                    .map_err(LoggedWrite::Before)
                    .and_then(|p| {
                        self.write_logged(p, || match &append {
                            Some((ids, _, _)) if ids.is_empty() => Ok(()),
                            Some((ids, master, at)) => {
                                appended =
                                    crate::persist::append_change(self, &db, master, *at, ids)?;
                                lock.update_age();
                                Ok(())
                            }
                            None => self.write_database().map_err(Error::from),
                        })
                    });
                match written {
                    Ok(()) | Err(LoggedWrite::After(_)) => {
                        self.map.end_change();
                        self.db_stamp = match (&append, &self.db_stamp) {
                            (Some((ids, _, at)), Some(s)) => DbStamp::holding(
                                &lock,
                                &db,
                                s.records + u64::try_from(ids.len()).unwrap_or_default(),
                                at + appended,
                            ),
                            _ => DbStamp::now(&lock, &db, self.map.len_u64()),
                        };
                        self.lockout_stamp = crate::lockout::lockout_file_stamp(&db);
                        tracing::info!(
                            event = krb5_log::events::ADMIN,
                            component = "krb5-kdc",
                            outcome = "ok",
                            detail = "saved store",
                            db = %db.display(),
                        );
                        written.map(|()| Ok(v)).map_err(LoggedWrite::into_error)
                    }
                    Err(e) => {
                        self.read_back(&lock);
                        Err(e.into_error())
                    }
                }
            }
            Ok(v) => {
                self.map.end_change();
                Ok(Ok(v))
            }
            Err(e) => {
                if self.wrote_through.0.load(Ordering::Relaxed) || !before.restore(self) {
                    self.read_back(&lock);
                }
                Ok(Err(e))
            }
        };
        drop(held);
        out
    }

    fn append_plan(&self, before: &Before) -> Option<(Vec<String>, krb5_crypto::ProtocolKey, u64)> {
        if self.wrote_through.0.load(Ordering::Relaxed)
            || before.policies != self.policies
            || before.domain_sid != self.domain_sid
        {
            return None;
        }
        let stamp = self.db_stamp.as_ref().filter(|s| s.dump)?;
        let live = self.map.len_u64();
        let dead = stamp.records.saturating_sub(live);
        if dead > live && dead >= 256 {
            return None;
        }
        Some((self.map.touched()?, self.journal_key()?, stamp.applied))
    }

    fn merge_lockout_if_moved(&mut self, db: &std::path::Path) {
        let now = crate::lockout::lockout_file_stamp(db);
        if now != self.lockout_stamp {
            crate::lockout::merge_lockout_file(self, db);
            self.lockout_stamp = now;
        }
    }

    fn refresh_for_change(
        &mut self,
        lock: &Arc<DbLock>,
        db: &std::path::Path,
    ) -> Result<(), Error> {
        let pending = !self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty();
        if pending {
            return self.reread(lock);
        }
        if self.catch_up(lock, db)? == Freshness::Same {
            self.merge_lockout_if_moved(db);
        }
        Ok(())
    }

    fn read_back(&mut self, lock: &Arc<DbLock>) {
        self.db_stamp = None;
        self.lockout_stamp = None;
        let _ = self.reread(lock);
    }

    // MIT: `kadm5_lock` (lib/kadm5/srv/server_init.c:285-296)
    pub fn lock_database(&mut self) -> Result<(), Error> {
        let lock = self.db_lock()?;
        lock.lock(DbLockMode::Exclusive)
            .map_err(|e| Error::from(PersistError::from(e)))
    }

    // MIT: `kadm5_unlock` (lib/kadm5/srv/server_init.c:298-309)
    pub fn unlock_database(&mut self) -> Result<(), Error> {
        let lock = self.db_lock()?;
        lock.unlock()
            .map_err(|e| Error::from(PersistError::from(e)))
    }

    #[must_use]
    pub fn pkinit(&self) -> Option<&crate::pkinit::PkinitKdc> {
        self.env.pkinit.as_deref()
    }

    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    pub fn bootstrap(
        realm: &str,
        user: &str,
        user_password: &[u8],
        admin: &str,
        admin_password: &[u8],
    ) -> Result<Self, Error> {
        Self::bootstrap_with_kdc_conf(realm, user, user_password, admin, admin_password, None)
    }

    pub fn bootstrap_with_kdc_conf(
        realm: &str,
        user: &str,
        user_password: &[u8],
        admin: &str,
        admin_password: &[u8],
        kdc: Option<&krb5_config::KdcConf>,
    ) -> Result<Self, Error> {
        let mut store = Self::try_new(realm)?;
        // No profile keeps a 7-day renewable life, so the test realm matches stock.
        store.policy.max_renewable_life = 7 * 24 * 3600;
        store.policy.spake_preauth_groups = vec![krb5_crypto::SpakeGroup::P256];
        store.policy.supported_enctypes = crate::testrealm::TEST_SUPPORTED_ENCTYPES.to_vec();
        if let Some(c) = kdc {
            store.apply_kdc_conf(c)?;
        }
        let tgt = PrincipalName::krbtgt(realm);
        store.create_principal_3_in(
            &tgt,
            realm,
            CreateKeys::Random,
            &[],
            &AdminEnt {
                mask: kadm5_mask::ATTRIBUTES,
                ..AdminEnt::default()
            },
            &default_mod_actor(realm),
        )?;
        store.apply_admin_fields(
            &tgt,
            AdminFields {
                attributes: Some(KDB_LOCKDOWN_KEYS),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
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

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Principal> {
        self.map.get(&self.resolve_id(id)?)
    }

    #[must_use]
    pub fn get_raw(&self, id: &str) -> Option<&Principal> {
        self.map.get(id)
    }

    #[must_use]
    pub fn get_name(&self, name: &PrincipalName) -> Option<&Principal> {
        self.get_in_realm(name, &self.realm)
    }

    #[must_use]
    pub fn get_in_realm(&self, name: &PrincipalName, princ_realm: &str) -> Option<&Principal> {
        self.get(&crate::kdb::lookup_principal_id(name, princ_realm))
    }

    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.map.keys().cloned().collect();
        v.sort();
        v
    }

    pub(crate) fn debug_principals(&self) -> impl Iterator<Item = &Principal> {
        self.map.values()
    }

    pub(crate) fn debug_insert(&mut self, mut p: Principal) {
        p.reconcile_flags();
        self.settle_rid(&mut p);
        self.map.insert_unlogged(p.id(), p);
    }

    pub(crate) fn principal_by_id(&self, id: &str) -> Option<&Principal> {
        self.map.get(id)
    }

    pub(crate) fn debug_remove(&mut self, id: &str) {
        self.map.remove_unlogged(id);
    }
}

pub use alias::MAX_ALIAS_DEPTH;
pub use flags::{
    KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_DUP_SKEY, KDB_DISALLOW_FORWARDABLE, KDB_DISALLOW_POSTDATED,
    KDB_DISALLOW_RENEWABLE, KDB_DISALLOW_SVR, KDB_DISALLOW_TGT_BASED, KDB_LOCKDOWN_KEYS,
    KDB_NO_AUTH_DATA_REQUIRED, KDB_OK_AS_DELEGATE, KDB_OK_TO_AUTH_AS_DELEGATE,
    KDB_PWCHANGE_SERVICE, KDB_REQUIRES_HW_AUTH, KDB_REQUIRES_PRE_AUTH, KDB_REQUIRES_PWCHANGE,
    KDB_V1_BASE_LENGTH,
};
pub(crate) use flags::{KDB_DISALLOW_PROXIABLE, KDB_NEW_PRINC, KDB_SUPPORT_DESMD5};
pub use iprop_ulog::{
    IPROP_ERROR, IPROP_FULL_RESYNC, IPROP_NIL, IPROP_OK, IPROP_PERM_DENIED, IpropRole, LoggedWrite,
    PreparedLog,
};
pub use iprop_xdr::{
    IncrLayout, KeyWrap, UlogTime, XdrError, decode_incr_update, decode_kdbe_bytes,
    encode_incr_update, encode_kdbe, walk_incr_update,
};
pub use kadm5_hook::{
    HookStage, Kadm5Hook, clear_thread_kadm5_hook, register_kadm5_hook, set_thread_kadm5_hook,
};
pub use kdb_convert::{
    AT_ATTRFLAGS, AT_EXP, AT_FAIL_AUTH_COUNT, AT_KEYDATA, AT_LAST_FAILED, AT_LAST_SUCCESS, AT_LEN,
    AT_MAX_LIFE, AT_MAX_RENEW_LIFE, AT_MOD_PRINC, AT_MOD_TIME, AT_MOD_WHERE, AT_PRINC, AT_PW_EXP,
    AT_PW_HIST, AT_PW_HIST_KVNO, AT_PW_LAST_CHANGE, AT_PW_POLICY, AT_PW_POLICY_SWITCH, AT_TL_DATA,
    IpropUpdate, KdbeVal, ULOG_ADD_ATTRS, attr_bit, conv_2dbentry, conv_2logentry,
};
pub(crate) use kdb_convert::{encode_string_attrs, update_tl_data};
pub use keys::{KeyEntry, KeyLookup, KtkdbError, ktkdb_get_entry, random_key};
pub use password::{
    PWQUAL_DICT, PWQUAL_EMPTY, PWQUAL_PRINC, S2K_ITERS, apply_keysalt_policy, s2k_params,
};
pub use policy::{NamedPolicy, Policy, SpakeKdc};
pub(crate) use principal::PrincipalFields;
pub use principal::{
    AdminEnt, AdminFields, CreateKeys, KadmData, Principal, PrincipalBuilder, TlData, strip_db_args,
};
pub(crate) use principal::{db_args_put_error, refresh_kadm_tl};
pub use pwqual::{Pwqual, clear_thread_pwqual, register_pwqual, set_thread_pwqual};
pub use rid::{RID_FIRST_USER, RID_KRBTGT};
pub(crate) use transit::walk_realm_instances;
