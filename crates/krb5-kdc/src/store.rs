//! In-memory principal database and ACL-gated mutations.
//!
//! One module per MIT source family: `flags` (`KRB5_KDB_*`), `principal`,
//! `policy`, `password` (quality, chpass, history compare), `keys`,
//! `alias`, `transit`, `iprop_ulog`, `history`, `rid`. In-src tests live
//! in `store/tests.rs`.

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
use std::time::{SystemTime, UNIX_EPOCH};

use krb5_types::PrincipalName;
use krb5_types::pac::RpcSid;

use crate::dblock::{DbLock, DbLockHold, DbLockMode};
use crate::error::Error;
use crate::persist::{DbStamp, Freshness, PersistError};
use iprop_ulog::{LogContext, LogNote, PrincipalMap};
use kadm5_hook::Post;
use principal::default_mod_actor;
use rid::generate_domain_sid;

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u32::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_KTADD_EXPORT: Cell<bool> = const { Cell::new(false) };
    static FAIL_NEXT_CHRAND_SAVE: Cell<bool> = const { Cell::new(false) };
}

/// kadm5 `KADM5_*` mask bits (`lib/kadm5/admin.h`) that a create or modify
/// request carries alongside its `kadm5_principal_ent_rec`.
pub mod kadm5_mask {
    /// `KADM5_PRINCIPAL`.
    pub const PRINCIPAL: u32 = 0x0000_0001;
    /// `KADM5_PRINC_EXPIRE_TIME`.
    pub(crate) const PRINC_EXPIRE_TIME: u32 = 0x0000_0002;
    /// `KADM5_PW_EXPIRATION`.
    pub(crate) const PW_EXPIRATION: u32 = 0x0000_0004;
    /// `KADM5_ATTRIBUTES`.
    pub const ATTRIBUTES: u32 = 0x0000_0010;
    /// `KADM5_MAX_LIFE`.
    pub const MAX_LIFE: u32 = 0x0000_0020;
    /// `KADM5_KVNO`.
    pub const KVNO: u32 = 0x0000_0100;
    /// `KADM5_POLICY`.
    pub const POLICY: u32 = 0x0000_0800;
    /// `KADM5_POLICY_CLR`.
    pub const POLICY_CLR: u32 = 0x0000_1000;
    /// `KADM5_MAX_RLIFE`.
    pub(crate) const MAX_RLIFE: u32 = 0x0000_2000;
    /// `KADM5_KEY_DATA`.
    pub const KEY_DATA: u32 = 0x0002_0000;
}

/// Realm principal store (dump-v7 / HashMap backend).
#[derive(Clone, Debug)]
pub struct PrincipalStore {
    realm: String,
    map: PrincipalMap,
    /// Ticket policy.
    pub policy: Policy,
    env: crate::kdb::KdcEnv,
    /// The `dict` password-quality module's words, the admin side's only (kadmind, kadmin.local,
    /// `kdb5_util create`), read once ([`Self::init_pwqual`]) and shared.
    pwqual_dict: Option<Arc<pwqual_dict::PwqualDict>>,
    /// Optional `(db, stash)` paths; mutations write through when set.
    pub persist_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
    /// `kadmin.local -m`: the database and the master key typed for it, which a save writes
    /// under in place of the stash's; the stash is not read.
    pub(crate) persist_master: Option<(std::path::PathBuf, krb5_crypto::ProtocolKey)>,
    /// The database's age and identity as this store last read it.
    pub(crate) db_stamp: Option<DbStamp>,
    pub(crate) loaded_span: Option<(u64, u64)>,
    /// The database's lock files, opened once with the database.
    pub(crate) dblock: Option<Arc<DbLock>>,
    /// Whether a mutation asked for a save during the current [`Self::change`].
    changed: ChangeMark,
    /// Whether the current [`Self::change`] wrote the database before its end
    /// ([`Self::save_through`]).
    wrote_through: ChangeMark,
    /// Per-realm NT domain SID (never the dummy `S-1-5-21-1-2-3`).
    domain_sid: RpcSid,
    /// Next RID to allocate (`RID_FIRST_USER` and up).
    next_rid: u32,
    policies: HashMap<String, NamedPolicy>,
    lockout: Arc<crate::lockout::LockoutState>,
    /// The update log this process mapped and its role, process-local and kept across rereads;
    /// `None` when iprop is off, so nothing is logged.
    log: Option<Arc<LogContext>>,
    /// The changes made since the database was last written, for the update log.
    pending: Arc<Mutex<Vec<LogNote>>>,
    /// Set while [`Self::change`] runs `f`: a mutation's own save is only noted, and the change
    /// writes the database once at its end.
    saves_held: bool,
    post: Option<Vec<Post>>,
}

/// Whether a mutation asked for a save; cloned with the store as a fresh flag of the same value.
#[derive(Debug, Default)]
struct ChangeMark(AtomicBool);

impl Clone for ChangeMark {
    fn clone(&self) -> Self {
        Self(AtomicBool::new(self.0.load(Ordering::Relaxed)))
    }
}

/// [`PrincipalStore::change`]'s hold on the store's saves while `f` runs, let go however `f`
/// ends; a panic leaves the store to be read again before its next use.
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

/// What a change may set besides the principal records, as it was before the change.
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

    /// Put `store` back as it was before a change `f` refused, without reading the database;
    /// false when the change went past the journal.
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
    u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(u32::MAX)
}

impl PrincipalStore {
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn new(realm: impl Into<String>) -> Self {
        Self::try_new(realm).expect("the CSPRNG gave no domain SID")
    }

    /// No predictable domain SID: a CSPRNG failure, all-zero bytes or the dummy SID is an error.
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
            loaded_span: None,
            dblock: None,
            changed: ChangeMark::default(),
            wrote_through: ChangeMark::default(),
            domain_sid: generate_domain_sid()?,
            next_rid: RID_FIRST_USER,
            policies: HashMap::new(),
            lockout: Arc::default(),
            log: None,
            pending: Arc::new(Mutex::new(Vec::new())),
            saves_held: false,
            post: None,
        })
    }

    /// Read the database again when another process changed it since this store read it.
    ///
    /// Kadmind and the KDC are separate processes sharing the database. Holding the database's
    /// lock shared, its age and its file's identity are compared with what this store last read,
    /// and the database is read again when they differ; the dump rows with the lockout attributes
    /// of `principal.lockout` and the named policies come from disk, and the kdc.conf ticket
    /// policy, the password dictionary, the lockout state this process keeps (its open
    /// `principal.lockout` and any counts kept in memory), the update log it mapped and the
    /// PKINIT CA stay process-local, carried over and never copied. The KDC's lockout writes move
    /// neither the age nor the file, so a reader that needs them now merges them per entry
    /// ([`Self::merge_lockout`]).
    /// MIT `ctx_lock` (`plugins/kdb/db2/kdb_db2.c:439-455`): each read takes the shared lock and reopens the database under it.
    ///
    /// # Errors
    ///
    /// [`Error::Db`] when the database's lock files do not open or the lock may not be taken
    /// (MIT's text), or the changed db or its stash cannot be read or parsed; [`Error::Crypto`]
    /// when the stash key does not decrypt it.
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

    /// False, the store unchanged, for `K/M` or `kadmin/history`, a bad key, or no master key.
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
        crate::lockout::merge_lockout_file(self, db);
        let applied = stamp.applied + u64::try_from(used).unwrap_or_default();
        let records = stamp.records + u64::try_from(count).unwrap_or_default();
        self.db_stamp = DbStamp::holding(lock, db, records, applied);
        true
    }

    /// `kadmin.local -m`'s key, else `K/M`'s, which a load checked against the stash.
    fn journal_key(&self) -> Option<krb5_crypto::ProtocolKey> {
        if let Some((_, master)) = &self.persist_master {
            return Some(master.clone());
        }
        self.get(&format!("K/M@{}", self.realm))
            .and_then(|km| km.keys.first())
            .map(|k| k.key.clone())
    }

    /// Read the database again, whatever its stamp says, so a change whose save failed does not
    /// stay in memory: the store is then what the file holds.
    ///
    /// # Errors
    ///
    /// As [`Self::reload_if_stale`].
    pub fn reload(&mut self) -> Result<(), Error> {
        self.db_stamp = None;
        self.reload_if_stale()
    }

    /// The store as the database holds it now, read while the caller holds `lock`, with the
    /// process-local state kept. A database that does not read again is named in the error, and
    /// the store stays as it was.
    /// MIT `open_db` (`plugins/kdb/db2/kdb_db2.c:386-389`): a database that does not open again is named in the error.
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
        loaded.domain_sid.clone_from(&self.domain_sid);
        loaded.lockout = Arc::clone(&self.lockout);
        loaded.env = std::mem::take(&mut self.env);
        loaded.log = self.log.take();
        loaded.saves_held = self.saves_held;
        loaded.post = self.post.take();
        *self = loaded;
        Ok(())
    }

    /// The database this store reads and writes: `kadmin.local -m`'s, else the stash-keyed one.
    pub(crate) fn db_path(&self) -> Option<&std::path::Path> {
        match (&self.persist_master, &self.persist_paths) {
            (Some((db, _)), _) | (None, Some((db, _))) => Some(db.as_path()),
            (None, None) => None,
        }
    }

    /// The database's lock files, opened once and kept; a store given its database's paths
    /// without them opens them now.
    ///
    /// # Errors
    ///
    /// [`Error::Db`] when the store has no database, or `principal.ok` or `principal.kadm5.lock`
    /// does not open (MIT's text).
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

    /// The database's shared lock for one request, and whether the database changed since this
    /// store read it; `None` for a store with no database file.
    ///
    /// # Errors
    ///
    /// [`Error::Db`] when the lock may not be taken, MIT's `KRB5_KDB_CANTLOCK_DB`.
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

    /// Ticket policy.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Process-local KDC env (the PKINIT CA).
    #[must_use]
    pub fn env(&self) -> &crate::kdb::KdcEnv {
        &self.env
    }

    pub(crate) fn save_configured(&self) -> Result<(), Error> {
        self.save_if_configured()
    }

    /// A mutation's save: inside [`Self::change`] it is noted and made once when the change
    /// ends; a store with a database refuses it anywhere else, since a write that did not read
    /// the database again under the exclusive lock would undo another process's change. A store
    /// with no database has made its change already, so its update log (when it has one) takes
    /// it now.
    fn save_if_configured(&self) -> Result<(), Error> {
        self.changed.0.store(true, Ordering::Relaxed);
        if self.db_path().is_none() {
            return self.log_pending();
        }
        self.inside_change()
    }

    /// Save the store now, inside [`Self::change`], for a write a later failure in the same
    /// change must not take back: what MIT commits with its own put, logged as that put is.
    fn save_through(&self) -> Result<(), Error> {
        self.inside_change()?;
        self.wrote_through.0.store(true, Ordering::Relaxed);
        self.logged_write(|| self.write_database())
    }

    /// Refuse a save outside [`Self::change`] for a store with a database.
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

    /// Write the store to its database: under the typed master key with `kadmin.local -m`, else
    /// under the stash's.
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

    /// One change to the database, whole, under its exclusive lock: the lock is taken (waiting
    /// for any other holder), the store is brought up to the database,
    /// `f` runs on the store, and when `f` returns `Ok` after a mutation the database is written
    /// once and its age moves forward; when `f` returns `Err`, what it changed is put back, so
    /// nothing of it stays in memory or on disk (a change that wrote part of itself early, or
    /// whose save failed, is read back from the database). A store with no database runs `f`
    /// alone, and so does a change inside a change.
    /// With an update log mapped as a primary's, each put and delete the change made is encoded
    /// before the write and appended to the log after it, one entry each, in order.
    /// MIT `krb5_db2_put_principal` (`plugins/kdb/db2/kdb_db2.c:828-854`): a put takes the exclusive lock, writes, moves the age and unlocks.
    /// MIT `ctx_lock` (`plugins/kdb/db2/kdb_db2.c:439-455`): the exclusive lock reopens the database, so the put starts from what is on disk.
    ///
    /// # Errors
    ///
    /// The outer [`Error::Db`] when the lock may not be taken (MIT's `KRB5_KDB_CANTLOCK_DB` text,
    /// or a missing lock file), the database cannot be read again, an update cannot be encoded
    /// for the log, or the write fails (a writer that may not write the database is refused with
    /// MIT's text, and the store is read back), or the log cannot be written after the database
    /// was (the change stays, as MIT's put does); the inner result is `f`'s.
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

    /// A postcommit call: kept until the running change has ended, else made now.
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

    /// `None` writes the whole database: a policy or SID change, a write-through, a database
    /// not read as dump text, or more replaced records than live ones, 256 at least.
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

    /// Under a change's exclusive lock, the store as the database holds it now. The database is
    /// read again when another writer moved its stamp, when the stamp is unknown (a panic, or a
    /// failed read), or when notes of an unwritten change are pending. Otherwise the store is
    /// what this process last wrote or read, but for the lockout records, which the KDC writes in
    /// place without moving the stamp: those are merged again, so the save that ends the change
    /// writes no stale count back over the KDC's.
    /// MIT `ctx_lock` (`plugins/kdb/db2/kdb_db2.c:439-455`): the exclusive lock reopens the database, so the put starts from what is on disk.
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
            crate::lockout::merge_lockout_file(self, db);
        }
        Ok(())
    }

    /// A failed change's store, read back from the database; when that read fails too, the stamp
    /// stays unknown, so the next use reads it.
    fn read_back(&mut self, lock: &Arc<DbLock>) {
        self.db_stamp = None;
        let _ = self.reread(lock);
    }

    /// Hold the database's lock exclusively until [`Self::unlock_database`], across changes:
    /// kadmin.local's `lock`. Every other process waits meanwhile.
    /// MIT `kadm5_lock` (`lib/kadm5/srv/server_init.c:285-296`): `krb5_db_lock` in exclusive mode.
    ///
    /// # Errors
    ///
    /// [`Error::Db`] when the store has no database or the lock may not be taken (MIT's
    /// `KRB5_KDB_CANTLOCK_DB` text).
    pub fn lock_database(&mut self) -> Result<(), Error> {
        let lock = self.db_lock()?;
        lock.lock(DbLockMode::Exclusive)
            .map_err(|e| Error::from(PersistError::from(e)))
    }

    /// Let go of the lock [`Self::lock_database`] took: kadmin.local's `unlock`.
    /// MIT `kadm5_unlock` (`lib/kadm5/srv/server_init.c:298-309`): `krb5_db_unlock`.
    ///
    /// # Errors
    ///
    /// [`Error::Db`] when no lock is held or the unlock fails.
    pub fn unlock_database(&mut self) -> Result<(), Error> {
        let lock = self.db_lock()?;
        lock.unlock()
            .map_err(|e| Error::from(PersistError::from(e)))
    }

    /// The realm's PKINIT context, when the module initialized.
    #[must_use]
    pub fn pkinit(&self) -> Option<&crate::pkinit::PkinitKdc> {
        self.env.pkinit.as_deref()
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
    /// [`Error::Rng`] when the CSPRNG fails generating the krbtgt key;
    /// [`Error::PasswordPolicy`] when `user_password` or `admin_password` is empty;
    /// [`Error::AlreadyExists`] when `user` and `admin` are the same name.
    pub fn bootstrap(
        realm: &str,
        user: &str,
        user_password: &[u8],
        admin: &str,
        admin_password: &[u8],
    ) -> Result<Self, Error> {
        Self::bootstrap_with_kdc_conf(realm, user, user_password, admin, admin_password, None)
    }

    /// [`Self::bootstrap`] after applying `kdc.conf` so `supported_enctypes`
    /// orders keys like MIT `kdb5_util create` / `addprinc` without `-e`.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when `kdc` sets a `domain_sid` that is not valid SDDL;
    /// [`Error::Rng`] when the CSPRNG fails generating the krbtgt key;
    /// [`Error::PasswordPolicy`] when `user_password` or `admin_password` is empty;
    /// [`Error::AlreadyExists`] when `user` and `admin` are the same name.
    pub fn bootstrap_with_kdc_conf(
        realm: &str,
        user: &str,
        user_password: &[u8],
        admin: &str,
        admin_password: &[u8],
        kdc: Option<&krb5_config::KdcConf>,
    ) -> Result<Self, Error> {
        let mut store = Self::try_new(realm)?;
        // No profile: keep the harness create default (7 d) so `--test-realm`
        // principals match stock `max_renewable_life = 7d`. A supplied
        // kdc.conf with the key omitted then sets create = 0 and the realm
        // cap = 7 d (`kdc/main.c` vs `alt_prof.c`).
        store.policy.max_renewable_life = 7 * 24 * 3600;
        store.policy.spake_preauth_groups = vec![krb5_crypto::SpakeGroup::P256];
        // The test realm's keys: a profile's `supported_enctypes` replaces these.
        store.policy.supported_enctypes = crate::testrealm::TEST_SUPPORTED_ENCTYPES.to_vec();
        if let Some(c) = kdc {
            store.apply_kdc_conf(c)?;
        }
        // MIT `kdb5_util create` (`kdb5_create.c` `add_principal`): the TGS
        // key is random and the entry carries no default flags.
        let tgt = PrincipalName::krbtgt(realm);
        store.create_principal_3_in(
            &tgt,
            realm,
            None,
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

    /// Lookup `name@realm`, following alias stubs like `krb5_db_get_principal`.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Principal> {
        self.map.get(&self.resolve_id(id)?)
    }

    /// The stored record itself, alias stubs included (`kdb5_util dump` view).
    #[must_use]
    pub fn get_raw(&self, id: &str) -> Option<&Principal> {
        self.map.get(id)
    }

    /// Lookup by name components in this realm.
    #[must_use]
    pub fn get_name(&self, name: &PrincipalName) -> Option<&Principal> {
        self.get_in_realm(name, &self.realm)
    }

    /// Lookup `name@princ_realm` (MIT `kdb_get_entry` uses the request realm).
    #[must_use]
    pub fn get_in_realm(&self, name: &PrincipalName, princ_realm: &str) -> Option<&Principal> {
        self.get(&crate::kdb::lookup_principal_id(name, princ_realm))
    }

    /// Principal ids (`name@REALM`), sorted.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.map.keys().cloned().collect();
        v.sort();
        v
    }

    /// Iterate principals (persistence).
    pub(crate) fn debug_principals(&self) -> impl Iterator<Item = &Principal> {
        self.map.values()
    }

    /// Insert a fully-formed principal (persistence / dump load; no ulog).
    pub(crate) fn debug_insert(&mut self, mut p: Principal) {
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
pub use principal::{AdminEnt, AdminFields, KadmData, Principal, TlData, strip_db_args};
pub(crate) use principal::{db_args_put_error, refresh_kadm_tl};
pub use pwqual::{Pwqual, clear_thread_pwqual, register_pwqual, set_thread_pwqual};
pub use rid::{RID_FIRST_USER, RID_KRBTGT};
pub(crate) use transit::walk_realm_instances;
