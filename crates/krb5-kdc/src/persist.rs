//! Persistent principal database: stash + MIT dump version 7 at rest.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::dblock::{
    DbAge, DbLock, DbLockError, DbLockHold, DbLockMode, SUFFIX_LOCK, SUFFIX_POLICY_LOCK, suffixed,
};
use crate::error::Error;
use crate::kdb_dump::{load_dump_mkey, write_dump};
use crate::mkey::master_key_from_password;
use crate::store::{KeyEntry, Principal, PrincipalStore, S2K_ITERS};
use crate::ulog::{Ulog, UlogError, UlogLast};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt};
use krb5_protocol::{
    Keytab, check_secret_file_writable, write_fresh_secret_file, write_secret_file,
};
use krb5_types::pac::RpcSid;
use krb5_types::{PrincipalName, parse_name};

const DUMP_PREFIX: &[u8] = b"kdb5_util load_dump version ";

#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    #[error("persist io: {0}")]
    Io(#[from] std::io::Error),
    #[error("persist crypto: {0}")]
    Crypto(String),
    #[error("persist format: {0}")]
    Format(String),
    #[error("unknown db_library: {0}")]
    UnknownDbLibrary(String),
    #[error(transparent)]
    Lock(#[from] DbLockError),
    #[error("Cannot open DB2 database '{}': {why}", path.display())]
    Unopenable { path: PathBuf, why: Unopenable },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unopenable {
    /// Other formats refused at open; an empty file refused under the lock.
    NotDatabase,
    /// An MIT db2 file is refused at open and left in place.
    MitDb2,
}

impl std::fmt::Display for Unopenable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotDatabase => f.write_str("Invalid argument"),
            Self::MitDb2 => f.write_str(
                "This is an MIT db2 database; dump it with the old installation's kdb5_util, \
                 then kdb5_util load here (docs/install.md, Upgrading an MIT realm)",
            ),
        }
    }
}

impl From<Error> for PersistError {
    fn from(e: Error) -> Self {
        Self::Crypto(e.to_string())
    }
}

impl From<crate::kdb_dump::DumpError> for PersistError {
    fn from(e: crate::kdb_dump::DumpError) -> Self {
        match e {
            crate::kdb_dump::DumpError::Io(e) => Self::Io(e),
            crate::kdb_dump::DumpError::Crypto(s) => Self::Crypto(s),
            crate::kdb_dump::DumpError::Format(s) => Self::Format(s),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DbStamp {
    age: Option<DbAge>,
    dev: u64,
    ino: u64,
    ctime: (i64, i64),
    len: u64,
    pub(crate) records: u64,
    pub(crate) applied: u64,
    tail: u32,
    tail_len: u64,
    pub(crate) dump: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Freshness {
    Same,
    Grown,
    Other,
}

const TAIL: u64 = 64;

impl DbStamp {
    pub(crate) fn now(lock: &DbLock, db: &Path, records: u64) -> Option<Self> {
        let len = fs::metadata(db).ok()?.len();
        Self::holding(lock, db, records, len)
    }

    pub(crate) fn holding(lock: &DbLock, db: &Path, records: u64, applied: u64) -> Option<Self> {
        use std::os::unix::fs::FileExt as _;
        let file = fs::File::open(db).ok()?;
        let meta = file.metadata().ok()?;
        let tail_len = applied.min(TAIL);
        let mut buf = vec![0; usize::try_from(tail_len).ok()?];
        file.read_exact_at(&mut buf, applied - tail_len).ok()?;
        Some(Self {
            age: lock.age(),
            dev: meta.dev(),
            ino: meta.ino(),
            ctime: (meta.ctime(), meta.ctime_nsec()),
            len: meta.len(),
            records,
            applied,
            tail: crate::lockout::crc32(&buf),
            tail_len,
            dump: true,
        })
    }

    pub(crate) fn same(&self, lock: &DbLock, db: &Path) -> bool {
        fs::metadata(db).is_ok_and(|m| self.saw(lock, &m))
    }

    fn saw(&self, lock: &DbLock, m: &fs::Metadata) -> bool {
        (m.dev(), m.ino(), (m.ctime(), m.ctime_nsec()), m.len())
            == (self.dev, self.ino, self.ctime, self.len)
            && lock.age() == self.age
    }

    pub(crate) fn freshness(&self, lock: &DbLock, db: &Path) -> Freshness {
        use std::os::unix::fs::FileExt as _;
        let Ok(m) = fs::metadata(db) else {
            return Freshness::Other;
        };
        if (m.dev(), m.ino()) != (self.dev, self.ino) || m.len() < self.applied {
            return Freshness::Other;
        }
        if self.saw(lock, &m) {
            return Freshness::Same;
        }
        let Ok(file) = fs::File::open(db) else {
            return Freshness::Other;
        };
        let mut buf = vec![0; usize::try_from(self.tail_len).unwrap_or_default()];
        match file.read_exact_at(&mut buf, self.applied - self.tail_len) {
            Ok(()) if crate::lockout::crc32(&buf) == self.tail => Freshness::Grown,
            _ => Freshness::Other,
        }
    }
}

pub(crate) fn read_appended(db: &Path, at: u64) -> std::io::Result<Vec<u8>> {
    use std::io::{Seek as _, SeekFrom};
    let mut file = fs::File::open(db)?;
    file.seek(SeekFrom::Start(at))?;
    let mut out = Vec::new();
    file.read_to_end(&mut out)?;
    Ok(out)
}

pub(crate) fn append_change(
    store: &PrincipalStore,
    db: &Path,
    master: &ProtocolKey,
    at: u64,
    ids: &[String],
) -> Result<u64, PersistError> {
    use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
    check_writable(db, DbWrite::InPlace)?;
    let batch = crate::kdb_dump::journal_batch(store, master, ids)?;
    let file = fs::OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(db)?;
    let len = file.metadata()?.len();
    if len < at {
        return Err(PersistError::Format(format!(
            "{}: shorter than the database read",
            db.display()
        )));
    }
    if len > at {
        file.set_len(at)?;
    }
    file.write_all_at(batch.as_bytes(), at)?;
    file.sync_data()?;
    crate::lockout::reconcile_ids(store, db, ids)?;
    Ok(u64::try_from(batch.len()).unwrap_or(u64::MAX))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DbFormat {
    Empty,
    Dump,
    Kdb(KdbVersion),
    MitDb2,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KdbVersion {
    /// KDB1 omits lock and expiry; KDB2 leads with SPAKE; KDB3 has both.
    V1,
    V2,
    V3,
}

fn db_format(head: &[u8]) -> DbFormat {
    if head.is_empty() {
        DbFormat::Empty
    } else if head.starts_with(DUMP_PREFIX) {
        DbFormat::Dump
    } else if let Some(version) = head.get(..4).and_then(|magic| match magic {
        b"KDB1" => Some(KdbVersion::V1),
        b"KDB2" => Some(KdbVersion::V2),
        b"KDB3" => Some(KdbVersion::V3),
        _ => None,
    }) {
        DbFormat::Kdb(version)
    } else if is_mit_db2(head) {
        DbFormat::MitDb2
    } else {
        DbFormat::Unknown
    }
}

// MIT: `BTREEMAGIC` (plugins/kdb/db2/libdb2/include/db.hin:131-131)
const BTREEMAGIC: u32 = 0x0005_3162;
// MIT: `BTREEVERSION` (plugins/kdb/db2/libdb2/include/db.hin:132-132)
const BTREEVERSION: u32 = 3;
// MIT: `HASHMAGIC` (plugins/kdb/db2/libdb2/include/db.hin:149-149)
const HASHMAGIC: u32 = 0x0006_1561;
// MIT: `HASHVERSION` (plugins/kdb/db2/libdb2/include/db.hin:150-150)
const HASHVERSION: u32 = 3;
// MIT: `OLDHASHVERSION` (plugins/kdb/db2/libdb2/hash/hash.c:155-155)
const OLDHASHVERSION: u32 = 1;

// MIT: `__bt_open` (plugins/kdb/db2/libdb2/btree/bt_open.c:234-246)
// MIT: `hget_header` (plugins/kdb/db2/libdb2/hash/hash.c:397-420)
// MIT: `__kdb2_hash_open` (plugins/kdb/db2/libdb2/hash/hash.c:152-158)
fn is_mit_db2(head: &[u8]) -> bool {
    let word = |at: usize| {
        head.get(at..at + 4)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
    };
    let (Some(magic), Some(version)) = (word(0), word(4)) else {
        return false;
    };
    let btree =
        |order: fn([u8; 4]) -> u32| order(magic) == BTREEMAGIC && order(version) == BTREEVERSION;
    btree(u32::from_le_bytes)
        || btree(u32::from_be_bytes)
        || (u32::from_be_bytes(magic) == HASHMAGIC
            && matches!(u32::from_be_bytes(version), HASHVERSION | OLDHASHVERSION))
}

fn dump_text(blob: &[u8]) -> Result<&str, PersistError> {
    std::str::from_utf8(blob).map_err(|_| PersistError::Format("dump is not utf-8".into()))
}

fn refusal(db: &Path, format: DbFormat) -> Option<PersistError> {
    let why = match format {
        DbFormat::Dump | DbFormat::Kdb(_) => return None,
        DbFormat::MitDb2 => Unopenable::MitDb2,
        DbFormat::Empty | DbFormat::Unknown => Unopenable::NotDatabase,
    };
    Some(PersistError::Unopenable {
        path: db.to_path_buf(),
        why,
    })
}

fn refused(db: &Path, format: DbFormat) -> PersistError {
    refusal(db, format).unwrap_or_else(|| PersistError::Unopenable {
        path: db.to_path_buf(),
        why: Unopenable::NotDatabase,
    })
}

// MIT: `check_openable` (plugins/kdb/db2/kdb_db2.c:545-557)
// MIT: `open_db` (plugins/kdb/db2/kdb_db2.c:386-389)
// MIT: `__bt_open` (plugins/kdb/db2/libdb2/btree/bt_open.c:256-276)
// MIT: `check_openable` (plugins/kdb/db2/kdb_db2.c:545-557)
// MIT: `open_db` (plugins/kdb/db2/kdb_db2.c:386-389)
pub fn check_openable(db: &Path) -> Result<(), PersistError> {
    let mut head = Vec::with_capacity(DUMP_PREFIX.len());
    fs::File::open(db)?
        .take(DUMP_PREFIX.len() as u64)
        .read_to_end(&mut head)?;
    match db_format(&head) {
        DbFormat::Empty => Ok(()),
        format => refusal(db, format).map_or(Ok(()), Err),
    }
}

// MIT: `krb5_db2_open` (plugins/kdb/db2/kdb_db2.c:1194-1198)
pub fn load_store(db_path: &Path, stash_path: &Path) -> Result<PrincipalStore, PersistError> {
    check_openable(db_path)?;
    let lock = Arc::new(DbLock::open(db_path)?);
    let _held = lock.hold(DbLockMode::Shared)?;
    read_store(db_path, stash_path, &lock)
}

// MIT: `open_db_and_mkey` (kadmin/dbutil/kdb5_util.c:378-401)
pub fn check_database(db: &Path) -> Result<(), PersistError> {
    check_openable(db)?;
    let lock = Arc::new(DbLock::open(db)?);
    let _held = lock.hold(DbLockMode::Shared)?;
    let blob = fs::read(db)?;
    refusal(db, db_format(&blob)).map_or(Ok(()), Err)
}

pub(crate) fn read_store(
    db_path: &Path,
    stash_path: &Path,
    lock: &Arc<DbLock>,
) -> Result<PrincipalStore, PersistError> {
    let blob = fs::read(db_path)?;
    let format = db_format(&blob);
    if let Some(e) = refusal(db_path, format) {
        return Err(e);
    }
    let stash = krb5_protocol::read_stash_file(stash_path)?;
    let mut store = match format {
        DbFormat::Kdb(version) => load_kdb_blob(&blob, version, &stash)?,
        _ => load_dump_with_stash(dump_text(&blob)?, &stash)?,
    };
    crate::lockout::merge_lockout_file(&mut store, db_path);
    crate::lockout::ensure_lockout_file(db_path);
    store.persist_paths = Some((db_path.to_path_buf(), stash_path.to_path_buf()));
    store.db_stamp = stamp_read(&mut store, lock, db_path, &blob);
    store.dblock = Some(Arc::clone(lock));
    Ok(store)
}

fn stamp_read(
    store: &mut PrincipalStore,
    lock: &DbLock,
    db: &Path,
    blob: &[u8],
) -> Option<DbStamp> {
    let all = u64::try_from(blob.len()).ok()?;
    let span = store.loaded_span.take();
    let (records, applied) = span.unwrap_or((0, all));
    DbStamp::holding(lock, db, records, applied).map(|s| DbStamp {
        dump: span.is_some(),
        ..s
    })
}

// MIT: `kdb_init_master` (lib/kadm5/srv/server_kdb.c:26-80)
pub fn load_store_with_master(
    db_path: &Path,
    master: &ProtocolKey,
) -> Result<PrincipalStore, PersistError> {
    check_openable(db_path)?;
    let lock = Arc::new(DbLock::open(db_path)?);
    let _held = lock.hold(DbLockMode::Shared)?;
    read_store_with_master(db_path, master, &lock)
}

pub(crate) fn read_store_with_master(
    db_path: &Path,
    master: &ProtocolKey,
    lock: &Arc<DbLock>,
) -> Result<PrincipalStore, PersistError> {
    let blob = fs::read(db_path)?;
    let format = db_format(&blob);
    if let Some(e) = refusal(db_path, format) {
        return Err(e);
    }
    if format != DbFormat::Dump {
        return Err(PersistError::Format("not dump text".into()));
    }
    let mut store = crate::kdb_dump::load_dump_with_key(dump_text(&blob)?, master)?;
    crate::lockout::merge_lockout_file(&mut store, db_path);
    crate::lockout::ensure_lockout_file(db_path);
    store.db_stamp = stamp_read(&mut store, lock, db_path, &blob);
    store.dblock = Some(Arc::clone(lock));
    store.persist_master = Some((db_path.to_path_buf(), master.clone()));
    Ok(store)
}

pub fn read_db_locked(db: &Path) -> Result<Vec<u8>, PersistError> {
    Ok(read_db_and_lockout_locked(db)?.0)
}

pub fn read_db_and_lockout_locked(
    db: &Path,
) -> Result<(Vec<u8>, std::collections::HashMap<String, crate::Lockout>), PersistError> {
    let lock = Arc::new(DbLock::open(db)?);
    let _held = lock.hold(DbLockMode::Shared)?;
    Ok((fs::read(db)?, crate::lockout::lockout_records(db)))
}

/// A replaced database and stash keep their owner, group and mode.
pub fn save_store(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
) -> Result<(), PersistError> {
    let (lock, made) = WriteLock::take(store, db_path)?;
    save_store_as(store, db_path, stash_path, made)?;
    lock.update_age();
    Ok(())
}

// MIT: `load_db` (kadmin/dbutil/dump.c:1490-1508)
pub fn save_store_fresh(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
    merge_lockout: bool,
    log: Option<LoadLog<'_>>,
) -> Result<(), PersistError> {
    let master = master_for_save(store, db_path, stash_path)?;
    Ok(load_store_full(
        store,
        db_path,
        &master,
        merge_lockout,
        log,
    )?)
}

fn save_store_as(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
    made: bool,
) -> Result<(), PersistError> {
    check_writable(db_path, DbWrite::InPlace)?;
    let master = master_for_save(store, db_path, stash_path)?;
    write_store_files(store, db_path, &master, DbWrite::InPlace, made)
}

enum WriteLock {
    Held(Arc<DbLock>),
    Taken(DbLockHold),
}

impl WriteLock {
    fn take(store: &PrincipalStore, db: &Path) -> Result<(Self, bool), PersistError> {
        if let Some(lock) = store.dblock.as_ref()
            && store.db_path() == Some(db)
        {
            if lock.held_exclusive() {
                return Ok((Self::Held(Arc::clone(lock)), false));
            }
            return Ok((Self::Taken(lock.hold(DbLockMode::Exclusive)?), false));
        }
        let (lock, made) = match DbLock::open(db) {
            Ok(lock) => (lock, false),
            Err(_) if !db.exists() => {
                make_lock_files(db)?;
                (DbLock::open(db)?, true)
            }
            Err(e) => return Err(e.into()),
        };
        Ok((
            Self::Taken(Arc::new(lock).hold(DbLockMode::Exclusive)?),
            made,
        ))
    }

    fn update_age(&self) {
        match self {
            Self::Held(lock) => lock.update_age(),
            Self::Taken(hold) => hold.lock().update_age(),
        }
    }
}

// MIT: `ctx_create_db` (plugins/kdb/db2/kdb_db2.c:697-732)
fn make_lock_files(db: &Path) -> Result<(), PersistError> {
    let lock = DbLock::create(db)?;
    if !crate::dblock::suffixed(db, SUFFIX_POLICY_LOCK).exists() {
        lock.create_policy_lock()?;
    }
    lock.unlock()?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbWrite {
    InPlace,
    Fresh,
}

fn check_writable(db_path: &Path, how: DbWrite) -> Result<(), PersistError> {
    if how == DbWrite::InPlace {
        reopen_writable(db_path)?;
    }
    crate::lockout::check_writable(db_path)?;
    Ok(())
}

// MIT: `ctx_lock` (plugins/kdb/db2/kdb_db2.c:450-463)
fn reopen_writable(db_path: &Path) -> std::io::Result<()> {
    check_secret_file_writable(db_path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "Cannot open DB2 database '{}': {}",
                db_path.display(),
                strerror(&e)
            ),
        )
    })
}

fn strerror(e: &std::io::Error) -> String {
    let text = e.to_string();
    match e.raw_os_error() {
        Some(code) => text
            .strip_suffix(&format!(" (os error {code})"))
            .map_or_else(|| text.clone(), str::to_owned),
        None => text,
    }
}

pub fn save_store_with_master(
    store: &PrincipalStore,
    db_path: &Path,
    master: &ProtocolKey,
    how: DbWrite,
) -> Result<(), PersistError> {
    if how == DbWrite::Fresh {
        return Ok(load_store_full(store, db_path, master, false, None)?);
    }
    let (lock, made) = WriteLock::take(store, db_path)?;
    check_writable(db_path, how)?;
    write_store_files(store, db_path, master, how, made)?;
    lock.update_age();
    Ok(())
}

fn write_store_files(
    store: &PrincipalStore,
    db_path: &Path,
    master: &ProtocolKey,
    how: DbWrite,
    make_lockout: bool,
) -> Result<(), PersistError> {
    let text = write_dump(store, master)?;
    write_db(db_path, text.as_bytes(), how)?;
    crate::lockout::reconcile(store, db_path, make_lockout)?;
    Ok(())
}

fn write_db(db: &Path, bytes: &[u8], how: DbWrite) -> std::io::Result<()> {
    destroy_stale_temps(db);
    match how {
        DbWrite::InPlace => write_secret_file(db, bytes),
        DbWrite::Fresh => write_fresh_secret_file(db, bytes),
    }
}

fn destroy_stale_temps(db: &Path) {
    let Some(prefix) = db
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| format!(".{n}.tmp-"))
    else {
        return;
    };
    let dir = db
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with(&prefix))
        {
            destroy_file(&entry.path());
        }
    }
}

pub fn save_dump_text(db_path: &Path, text: &str, how: DbWrite) -> Result<(), PersistError> {
    if how == DbWrite::Fresh {
        return Ok(load_text_full(db_path, text, &[], false, None)?);
    }
    let (lock, _) = WriteLock::take(&PrincipalStore::try_new("")?, db_path)?;
    check_writable(db_path, how)?;
    write_db(db_path, text.as_bytes(), how)?;
    lock.update_age();
    Ok(())
}

/// A failed update releases the permanent lock; MIT leaves it held.
// MIT: `load_db` (kadmin/dbutil/dump.c:1509-1516)
// MIT: `load_db` (kadmin/dbutil/dump.c:1518-1526)
// MIT: `load_db` (kadmin/dbutil/dump.c:1540-1549)
#[derive(Debug)]
pub struct DbUpdate {
    db: PathBuf,
    lock: Arc<DbLock>,
    legacy: bool,
    permanent: bool,
}

impl DbUpdate {
    /// An empty file is an empty database an update fills.
    pub fn open(db: &Path) -> Result<Self, PersistError> {
        check_openable(db)?;
        let lock = Arc::new(DbLock::open(db)?);
        let legacy = {
            let _held = lock.hold(DbLockMode::Shared)?;
            let blob = fs::read(db)?;
            match db_format(&blob) {
                DbFormat::Empty => false,
                DbFormat::Kdb(_) => true,
                DbFormat::Dump => {
                    dump_text(&blob)?;
                    false
                }
                format => return Err(refused(db, format)),
            }
        };
        Ok(Self {
            db: db.to_path_buf(),
            lock,
            legacy,
            permanent: false,
        })
    }

    #[must_use]
    pub fn db(&self) -> &Path {
        &self.db
    }

    #[must_use]
    pub fn legacy(&self) -> bool {
        self.legacy
    }

    /// `principal.kadm5.lock` is removed only after the database reopens.
    pub fn lock_permanently(&mut self) -> Result<(), PersistError> {
        if self.permanent {
            return Ok(());
        }
        let db = &self.db;
        self.lock
            .lock_reopening(DbLockMode::Permanent, &mut || reopen_writable(db))?;
        self.permanent = true;
        Ok(())
    }

    pub fn store(
        &self,
        master: &ProtocolKey,
        legacy_stash: Option<&[u8]>,
    ) -> Result<Option<PrincipalStore>, PersistError> {
        if !self.permanent {
            return Err(DbLockError::NotLocked.into());
        }
        let blob = fs::read(&self.db)?;
        let mut store = match db_format(&blob) {
            DbFormat::Empty => return Ok(None),
            DbFormat::Kdb(version) => load_kdb_blob(&blob, version, legacy_key(legacy_stash)?)?,
            DbFormat::Dump => crate::kdb_dump::load_dump_with_key(dump_text(&blob)?, master)?,
            format => return Err(refused(&self.db, format)),
        };
        crate::lockout::merge_lockout_file(&mut store, &self.db);
        Ok(Some(store))
    }

    pub fn text(&self, legacy_stash: Option<&[u8]>) -> Result<Option<String>, PersistError> {
        if !self.permanent {
            return Err(DbLockError::NotLocked.into());
        }
        let blob = fs::read(&self.db)?;
        match db_format(&blob) {
            DbFormat::Empty => Ok(None),
            DbFormat::Kdb(version) => {
                let stash = legacy_key(legacy_stash)?;
                let store = load_kdb_blob(&blob, version, stash)?;
                Ok(Some(write_dump(&store, &stash_master(stash)?)?))
            }
            DbFormat::Dump => Ok(Some(crate::kdb_dump::parse_dump(dump_text(&blob)?)?.text())),
            format => Err(refused(&self.db, format)),
        }
    }

    pub fn write_store(
        &self,
        store: &PrincipalStore,
        master: &ProtocolKey,
    ) -> Result<(), PersistError> {
        if !self.permanent {
            return Err(DbLockError::NotLocked.into());
        }
        check_writable(&self.db, DbWrite::InPlace)?;
        write_store_files(store, &self.db, master, DbWrite::InPlace, true)?;
        self.lock.update_age();
        Ok(())
    }

    pub fn write_text(&self, text: &str) -> Result<(), PersistError> {
        if !self.permanent {
            return Err(DbLockError::NotLocked.into());
        }
        check_writable(&self.db, DbWrite::InPlace)?;
        write_db(&self.db, text.as_bytes(), DbWrite::InPlace)?;
        crate::lockout::ensure(&self.db)?;
        self.lock.update_age();
        Ok(())
    }

    // MIT: `osa_adb_release_lock` (plugins/kdb/db2/adb_openclose.c:298-307)
    pub fn unlock(mut self) -> Result<(), PersistError> {
        self.permanent = false;
        Ok(self.lock.unlock()?)
    }
}

impl Drop for DbUpdate {
    fn drop(&mut self) {
        if self.permanent {
            let _ = self.lock.unlock();
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error(transparent)]
    Create(PersistError),
    #[error(transparent)]
    Promote(PersistError),
    #[error(transparent)]
    Reinit(UlogError),
    #[error(transparent)]
    SetLast(UlogError),
}

impl From<LoadError> for PersistError {
    fn from(e: LoadError) -> Self {
        let logged = |e: UlogError, context: &str| {
            let kind = match &e {
                UlogError::Io(io) => io.kind(),
                _ => std::io::ErrorKind::Other,
            };
            Self::Io(std::io::Error::new(kind, format!("{e} {context}")))
        };
        match e {
            LoadError::Create(e) | LoadError::Promote(e) => e,
            LoadError::Reinit(e) => logged(e, "while reinitializing update log"),
            LoadError::SetLast(e) => logged(e, "while writing update log header"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LoadLog<'a> {
    pub ulog: &'a Ulog,
    pub last: Option<UlogLast>,
}

pub fn load_store_full(
    store: &PrincipalStore,
    db_path: &Path,
    master: &ProtocolKey,
    merge_lockout: bool,
    log: Option<LoadLog<'_>>,
) -> Result<(), LoadError> {
    FullLoad::create(db_path)?.finish_store(store, master, merge_lockout, log)
}

pub fn load_text_full(
    db_path: &Path,
    text: &str,
    lockout: &[(String, crate::Lockout)],
    merge: bool,
    log: Option<LoadLog<'_>>,
) -> Result<(), LoadError> {
    FullLoad::create(db_path)?.finish(text, lockout, merge, log)
}

#[derive(Debug)]
pub struct FullLoad {
    db: PathBuf,
    tmp: PathBuf,
    temp: Option<(DbLock, fs::File)>,
}

impl FullLoad {
    pub fn create(db: &Path) -> Result<Self, LoadError> {
        let tmp = suffixed(db, "~");
        let temp = create_temporary(&tmp).map_err(LoadError::Create)?;
        Ok(Self {
            db: db.to_path_buf(),
            tmp,
            temp: Some(temp),
        })
    }

    pub fn finish_store(
        self,
        store: &PrincipalStore,
        master: &ProtocolKey,
        merge_lockout: bool,
        log: Option<LoadLog<'_>>,
    ) -> Result<(), LoadError> {
        let text = write_dump(store, master).map_err(|e| LoadError::Create(e.into()))?;
        let lockout = crate::lockout::store_records(store);
        self.finish(&text, &lockout, merge_lockout, log)
    }

    // MIT: `load_db` (kadmin/dbutil/dump.c:1497-1501)
    // MIT: `krb5_db2_promote_db` (plugins/kdb/db2/kdb_db2.c:1497-1513)
    // MIT: `ctx_promote` (plugins/kdb/db2/kdb_db2.c:1434-1448)
    // MIT: `load_db` (kadmin/dbutil/dump.c:1551-1559)
    /// The log starts over before promotion, so a kill leaves no stale log.
    // MIT: `load_db` (kadmin/dbutil/dump.c:1570-1586)
    // MIT: `krb5_db2_promote_db` (plugins/kdb/db2/kdb_db2.c:1497-1513)
    // MIT: `ctx_promote` (plugins/kdb/db2/kdb_db2.c:1434-1448)
    pub fn finish(
        mut self,
        text: &str,
        lockout: &[(String, crate::Lockout)],
        merge: bool,
        log: Option<LoadLog<'_>>,
    ) -> Result<(), LoadError> {
        let Some((temp, mut file)) = self.temp.take() else {
            return Err(LoadError::Create(DbLockError::NotLocked.into()));
        };
        let written =
            std::io::Write::write_all(&mut file, text.as_bytes()).and_then(|()| file.sync_all());
        drop(file);
        let real = match written {
            Ok(()) => log
                .map_or(Ok(()), |l| l.ulog.init_header().map_err(LoadError::Reinit))
                .and_then(|()| {
                    promote(&self.db, &self.tmp, lockout, merge).map_err(LoadError::Promote)
                }),
            Err(e) => Err(LoadError::Create(e.into())),
        };
        let real = match real {
            Ok(real) => real,
            Err(e) => {
                destroy_temporary(&self.tmp);
                let _ = temp.unlock();
                return Err(e);
            }
        };
        let _ = temp.unlock();
        drop(temp);
        real.unlock().map_err(|e| LoadError::Promote(e.into()))?;
        if let Some(l) = log {
            l.ulog.init_header().map_err(LoadError::Reinit)?;
            if let Some(last) = l.last {
                l.ulog.set_last(last).map_err(LoadError::SetLast)?;
            }
        }
        Ok(())
    }
}

impl Drop for FullLoad {
    fn drop(&mut self) {
        if let Some((temp, file)) = self.temp.take() {
            drop(file);
            destroy_temporary(&self.tmp);
            let _ = temp.unlock();
        }
    }
}

fn create_temporary(tmp: &Path) -> Result<(DbLock, fs::File), PersistError> {
    let lock = DbLock::create(tmp)?;
    destroy_file(tmp);
    let _ = fs::remove_file(suffixed(tmp, SUFFIX_POLICY_LOCK));
    let made = (|| -> Result<fs::File, PersistError> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = krb5_protocol::create_labeled(tmp, || opts.open(tmp))?;
        lock.create_policy_lock()?;
        Ok(file)
    })();
    match made {
        Ok(file) => Ok((lock, file)),
        Err(e) => {
            destroy_temporary(tmp);
            let _ = lock.unlock();
            Err(e)
        }
    }
}

fn promote(
    db: &Path,
    tmp: &Path,
    lockout: &[(String, crate::Lockout)],
    merge: bool,
) -> Result<DbLock, PersistError> {
    let created = DbLock::create(db)?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let made = match krb5_protocol::create_labeled(db, || opts.open(db)) {
        Ok(_) => created.create_policy_lock().map_err(PersistError::from),
        Err(e) => Err(PersistError::Io(e)),
    };
    let real = match made {
        Ok(()) => created,
        Err(PersistError::Io(e) | PersistError::Lock(DbLockError::Io(e)))
            if e.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            let _ = created.unlock();
            drop(created);
            let real = DbLock::open(db)?;
            real.lock(DbLockMode::Exclusive)?;
            real
        }
        Err(e) => {
            let _ = created.unlock();
            return Err(e);
        }
    };
    let moved = (|| -> Result<(), PersistError> {
        crate::lockout::check_writable(db)?;
        crate::lockout::write_loaded(db, lockout, merge)?;
        fs::rename(tmp, db)?;
        real.update_age();
        let _ = fs::remove_file(suffixed(tmp, SUFFIX_LOCK));
        let _ = fs::remove_file(suffixed(tmp, SUFFIX_POLICY_LOCK));
        Ok(())
    })();
    if let Err(e) = moved {
        let _ = real.unlock();
        return Err(e);
    }
    Ok(real)
}

fn destroy_temporary(tmp: &Path) {
    destroy_file(tmp);
    let _ = fs::remove_file(suffixed(tmp, SUFFIX_LOCK));
    let _ = fs::remove_file(suffixed(tmp, SUFFIX_POLICY_LOCK));
}

// MIT: `destroy_file` (plugins/kdb/db2/kdb_db2.c:626-676)
fn destroy_file(path: &Path) {
    use std::os::unix::fs::OpenOptionsExt as _;
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.is_file()
        && let Ok(mut f) = fs::OpenOptions::new()
            .write(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
            .open(path)
    {
        let zeros = vec![0u8; usize::try_from(meta.len()).unwrap_or(0)];
        let _ = std::io::Write::write_all(&mut f, &zeros);
        let _ = f.sync_all();
    }
    let _ = fs::remove_file(path);
}

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("{0}")]
    Create(std::io::Error),
    #[error(transparent)]
    Lock(#[from] DbLockError),
    #[error(transparent)]
    Persist(#[from] PersistError),
}

// MIT: `ctx_create_db` (plugins/kdb/db2/kdb_db2.c:697-708)
// MIT: `ctx_create_db` (plugins/kdb/db2/kdb_db2.c:718-720)
// MIT: `ctx_create_db` (plugins/kdb/db2/kdb_db2.c:722-732)
/// A failure creating the policy lock leaves the new database file.
pub fn create_store(
    store: &PrincipalStore,
    db_path: &Path,
    master: &ProtocolKey,
) -> Result<(), CreateError> {
    let lock = DbLock::create(db_path)?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    krb5_protocol::create_labeled(db_path, || opts.open(db_path)).map_err(CreateError::Create)?;
    lock.create_policy_lock()?;
    let written = write_dump(store, master)
        .map_err(PersistError::from)
        .and_then(|text| Ok(write_db(db_path, text.as_bytes(), DbWrite::Fresh)?))
        .and_then(|()| {
            let lockout = crate::lockout::store_records(store);
            Ok(crate::lockout::write_loaded(db_path, &lockout, false)?)
        });
    if let Err(e) = written {
        let _ = fs::remove_file(db_path);
        return Err(e.into());
    }
    lock.update_age();
    lock.unlock()?;
    Ok(())
}

// MIT: `krb5_def_store_mkey_list` (lib/kdb/kdb_default.c:111-213)
pub fn write_stash(
    path: &Path,
    realm: &str,
    master: &ProtocolKey,
    kvno: u32,
) -> Result<(), PersistError> {
    let realm_a = krb5_types::try_ascii(realm).map_err(|e| PersistError::Format(e.to_string()))?;
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, crate::mkey::MASTER_NAME);
    let bytes = Keytab::single(realm_a, name, kvno, master.clone()).to_bytes();
    write_fresh_secret_file(path, &bytes)?;
    Ok(())
}

/// The stash key is the keytab `K/M` entry, else the legacy raw key.
// MIT: `krb5_db_def_fetch_mkey` (lib/kdb/kdb_default.c:356-393)
pub fn read_stash(stash_path: &Path, db_path: &Path) -> Result<ProtocolKey, PersistError> {
    existing_stash_key(db_path, stash_path)
}

pub fn read_stashed_master(path: &Path) -> Result<(ProtocolKey, u32), PersistError> {
    let bytes = krb5_protocol::read_stash_file(path)?;
    let kt = Keytab::parse(&bytes).map_err(|e| PersistError::Format(e.to_string()))?;
    let km = PrincipalName::new(PrincipalName::NT_PRINCIPAL, crate::mkey::MASTER_NAME);
    kt.entries
        .into_iter()
        .find(|e| e.name == km)
        .map(|e| (e.key, e.kvno))
        .ok_or_else(|| PersistError::Crypto("stash is not a usable master key".into()))
}

#[must_use]
pub fn stash_keys(bytes: &[u8]) -> Vec<ProtocolKey> {
    if let Some(k) = stash_keytab_key(bytes) {
        return vec![k];
    }
    stash_etypes()
        .into_iter()
        .filter_map(|etype| ProtocolKey::from_bytes(etype, bytes).ok())
        .collect()
}

pub fn save_store_legacy_kdb3(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
) -> Result<(), PersistError> {
    let master = if stash_path.exists() {
        load_stash_etype(stash_path, EncryptionType::Aes256CtsHmacSha196)?
    } else {
        let m = crate::store::random_key(EncryptionType::Aes256CtsHmacSha196)
            .map_err(|e| PersistError::Crypto(e.to_string()))?;
        write_secret_file(stash_path, m.as_bytes())?;
        m
    };
    let plain = serialize_plain(store);
    let usage = KeyUsage::new(2).map_err(|e| PersistError::Crypto(e.to_string()))?;
    let cipher =
        encrypt(&master, usage, &plain).map_err(|e| PersistError::Crypto(e.to_string()))?;
    let mut out = b"KDB3".to_vec();
    out.extend_from_slice(&cipher);
    let (lock, _) = WriteLock::take(store, db_path)?;
    write_secret_file(db_path, &out)?;
    lock.update_age();
    Ok(())
}

pub(crate) fn stash_keytab_key(bytes: &[u8]) -> Option<ProtocolKey> {
    let kt = Keytab::parse(bytes).ok()?;
    let km = PrincipalName::new(PrincipalName::NT_PRINCIPAL, crate::mkey::MASTER_NAME);
    kt.entries.into_iter().find(|e| e.name == km).map(|e| e.key)
}

fn stash_keytab_bytes(
    realm: &str,
    master: &ProtocolKey,
) -> Result<zeroize::Zeroizing<Vec<u8>>, PersistError> {
    let realm_a = krb5_types::try_ascii(realm).map_err(|e| PersistError::Format(e.to_string()))?;
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, crate::mkey::MASTER_NAME);
    Ok(Keytab::single(realm_a, name, 1, master.clone()).to_bytes())
}

pub fn load_dump_with_stash(text: &str, stash: &[u8]) -> Result<PrincipalStore, PersistError> {
    if let Some(mkey) = stash_keytab_key(stash)
        && let Ok(store) = load_dump_mkey(text, &mkey)
    {
        return Ok(store);
    }
    for etype in stash_etypes() {
        let Ok(mkey) = ProtocolKey::from_bytes(etype, stash) else {
            continue;
        };
        if let Ok(store) = load_dump_mkey(text, &mkey) {
            return Ok(store);
        }
    }
    Err(PersistError::Crypto(
        "stash master key did not decrypt dump key_data".into(),
    ))
}

fn load_kdb_blob(
    blob: &[u8],
    version: KdbVersion,
    stash: &[u8],
) -> Result<PrincipalStore, PersistError> {
    let master = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, stash)
        .map_err(|e| PersistError::Crypto(e.to_string()))?;
    let usage = KeyUsage::new(2).map_err(|e| PersistError::Crypto(e.to_string()))?;
    let body = blob.get(4..).unwrap_or_default();
    let plain = decrypt(&master, usage, body).map_err(|e| PersistError::Crypto(e.to_string()))?;
    parse_plain(&plain, version == KdbVersion::V2, version == KdbVersion::V3)
}

fn master_for_save(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
) -> Result<ProtocolKey, PersistError> {
    if stash_path.exists() {
        let master = existing_stash_key(db_path, stash_path)?;
        if stash_keytab_key(&krb5_protocol::read_stash_file(stash_path)?).is_none()
            && check_secret_file_writable(stash_path).is_ok()
        {
            write_secret_file(stash_path, &stash_keytab_bytes(store.realm(), &master)?)?;
        }
        return Ok(master);
    }
    // MIT: `add_principal` (kadmin/dbutil/kdb5_create.c:409-424)
    // A new stash holds `K/M`'s key.
    let realm = store.realm();
    let km = store
        .get(&format!("K/M@{realm}"))
        .and_then(|km| km.keys.first())
        .map(|k| k.key.clone());
    let master = if let Some(key) = km {
        key
    } else {
        let etype = persist_master_etype(realm)?;
        // MIT: `kdb5_create` (kadmin/dbutil/kdb5_create.c:200-220)
        // The master password is never the environment, except the test hook.
        #[cfg(feature = "test-hooks")]
        #[allow(clippy::disallowed_methods, reason = "a test-hooks build's override")]
        let hooked = std::env::var("KRB5_MASTER_PASSWORD")
            .ok()
            .map(zeroize::Zeroizing::new);
        #[cfg(not(feature = "test-hooks"))]
        let hooked: Option<zeroize::Zeroizing<String>> = None;
        match hooked {
            Some(pw) => master_key_from_password(realm, pw.as_bytes(), etype)?,
            None => crate::store::random_key(etype)?,
        }
    };
    write_secret_file(stash_path, &stash_keytab_bytes(realm, &master)?)?;
    Ok(master)
}

fn existing_stash_key(db_path: &Path, stash_path: &Path) -> Result<ProtocolKey, PersistError> {
    let bytes = krb5_protocol::read_stash_file(stash_path)?;
    if let Some(mkey) = stash_keytab_key(&bytes) {
        return Ok(mkey);
    }
    if let Ok(blob) = fs::read(db_path)
        && blob.starts_with(DUMP_PREFIX)
        && let Ok(text) = std::str::from_utf8(&blob)
    {
        for etype in stash_etypes() {
            let Ok(mkey) = ProtocolKey::from_bytes(etype, &bytes) else {
                continue;
            };
            if load_dump_mkey(text, &mkey).is_ok() {
                return Ok(mkey);
            }
        }
    }
    stash_master(&bytes)
}

fn stash_master(bytes: &[u8]) -> Result<ProtocolKey, PersistError> {
    if let Some(mkey) = stash_keytab_key(bytes) {
        return Ok(mkey);
    }
    stash_etypes()
        .into_iter()
        .find_map(|etype| ProtocolKey::from_bytes(etype, bytes).ok())
        .ok_or_else(|| PersistError::Crypto("stash is not a usable master key".into()))
}

/// A legacy database with no stash bytes cannot be opened.
fn legacy_key(stash: Option<&[u8]>) -> Result<&[u8], PersistError> {
    stash.ok_or_else(|| PersistError::Crypto("a legacy database opens with its stash".into()))
}

#[allow(
    clippy::disallowed_methods,
    reason = "read once, as the database is made"
)]
fn persist_master_etype(realm: &str) -> Result<EncryptionType, PersistError> {
    let paths = krb5_config::KdcPaths::resolve(Some(realm))
        .map_err(|e| PersistError::Format(format!("kdc.conf: {e}")))?;
    crate::mkey::master_etype(paths.master_key_type.as_deref())
        .map_err(|e| PersistError::Crypto(format!("master_key_type {e}")))
}

fn stash_etypes() -> [EncryptionType; 2] {
    [
        EncryptionType::Aes256CtsHmacSha384192,
        EncryptionType::Aes256CtsHmacSha196,
    ]
}

fn load_stash_etype(path: &Path, etype: EncryptionType) -> Result<ProtocolKey, PersistError> {
    let bytes = krb5_protocol::read_stash_file(path)?;
    ProtocolKey::from_bytes(etype, &bytes).map_err(|e| PersistError::Crypto(e.to_string()))
}

fn serialize_plain(store: &PrincipalStore) -> Vec<u8> {
    let mut out = Vec::new();
    let realm = store.realm();
    put_str(&mut out, realm);
    let n = u32::try_from(store_debug_count(store)).unwrap_or(0);
    out.extend_from_slice(&n.to_be_bytes());
    for p in store_iter(store) {
        put_str(&mut out, &p.name.unparse());
        out.extend_from_slice(&p.name.name_type.to_be_bytes());
        put_bytes(&mut out, &p.salt);
        out.push(u8::from(p.requires_preauth()));
        out.extend_from_slice(&p.max_life.to_be_bytes());
        let nk = u32::try_from(p.keys.len()).unwrap_or(0);
        out.extend_from_slice(&nk.to_be_bytes());
        for k in &p.keys {
            out.extend_from_slice(&k.etype.to_iana().to_be_bytes());
            out.extend_from_slice(&k.kvno.to_be_bytes());
            put_bytes(&mut out, k.key.as_bytes());
        }
        out.push(u8::from(p.locked()));
        out.extend_from_slice(&p.pw_expire.to_be_bytes());
    }
    out.extend_from_slice(b"SID1");
    put_str(&mut out, &store.domain_sid().to_sddl());
    out.extend_from_slice(&store.next_rid().to_be_bytes());
    let nr = u32::try_from(store_debug_count(store)).unwrap_or(0);
    out.extend_from_slice(&nr.to_be_bytes());
    for p in store_iter(store) {
        put_str(&mut out, &p.id());
        out.extend_from_slice(&p.rid.to_be_bytes());
    }
    out
}

// MIT: `krb5_decode_princ_entry` (db2/kdb_xdr.c:253-256)
/// A record shorter than the base principal is not loaded.
fn parse_plain(plain: &[u8], v2: bool, v3: bool) -> Result<PrincipalStore, PersistError> {
    let mut i = 0;
    let realm = take_str(plain, &mut i)?;
    let mut store = PrincipalStore::try_new(realm)?;
    let n = take_u32(plain, &mut i)?;
    for _ in 0..n {
        let name_s = take_str(plain, &mut i)?;
        let ntype = take_i32(plain, &mut i)?;
        let salt = take_bytes(plain, &mut i)?;
        let requires_preauth = take_u8(plain, &mut i)? != 0;
        let max_life = take_u64(plain, &mut i)?;
        let nk = take_u32(plain, &mut i)?;
        let mut keys = Vec::new();
        for _ in 0..nk {
            let et = take_i32(plain, &mut i)?;
            let kvno = take_u32(plain, &mut i)?;
            let kb = take_bytes(plain, &mut i)?;
            let etype =
                EncryptionType::known(et).map_err(|e| PersistError::Crypto(e.to_string()))?;
            let key = ProtocolKey::from_bytes(etype, &kb)
                .map_err(|e| PersistError::Crypto(e.to_string()))?;
            keys.push(KeyEntry::new(etype, key, kvno));
        }
        let (comps, _) =
            parse_name(&name_s, "").map_err(|e| PersistError::Format(e.to_string()))?;
        let name = PrincipalName::try_new(ntype, comps)
            .map_err(|e| PersistError::Format(e.to_string()))?;
        if v2 && i < plain.len() {
            let _ = take_bytes(plain, &mut i)?;
        }
        let (locked, pw_expire) = if v2 || v3 {
            (take_u8(plain, &mut i)? != 0, take_u32(plain, &mut i)?)
        } else {
            (false, 0)
        };
        let p = Principal::from_keys(
            name,
            store.realm().to_owned(),
            keys,
            salt,
            crate::store::PrincipalFields {
                requires_preauth,
                max_life,
                locked,
                pw_expire,
            },
        );
        store_insert(&mut store, p);
        let _ = S2K_ITERS;
    }
    if i + 4 <= plain.len() && &plain[i..i + 4] == b"SID1" {
        i += 4;
        let sddl = take_str(plain, &mut i)?;
        let Some(sid) = RpcSid::from_sddl(&sddl) else {
            return Err(PersistError::Format(format!(
                "SID1 trailer is not valid SDDL: {sddl}"
            )));
        };
        store.set_domain_sid(sid);
        let next = take_u32(plain, &mut i)?;
        let nrid = take_u32(plain, &mut i)?;
        for _ in 0..nrid {
            let id = take_str(plain, &mut i)?;
            let rid = take_u32(plain, &mut i)?;
            store.set_principal_rid(&id, rid);
        }
        store.set_next_rid(next);
    }
    Ok(store)
}

fn store_debug_count(store: &PrincipalStore) -> usize {
    store_iter(store).count()
}

fn store_iter(store: &PrincipalStore) -> impl Iterator<Item = &Principal> {
    store.debug_principals()
}

fn store_insert(store: &mut PrincipalStore, p: Principal) {
    store.debug_insert(p);
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_bytes(out, s.as_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    let n = u32::try_from(b.len()).unwrap_or(0);
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(b);
}

fn take_u8(b: &[u8], i: &mut usize) -> Result<u8, PersistError> {
    if *i >= b.len() {
        return Err(PersistError::Format("eof".into()));
    }
    let v = b[*i];
    *i += 1;
    Ok(v)
}

fn take_u32(b: &[u8], i: &mut usize) -> Result<u32, PersistError> {
    if *i + 4 > b.len() {
        return Err(PersistError::Format("eof".into()));
    }
    let v = u32::from_be_bytes(
        b[*i..*i + 4]
            .try_into()
            .map_err(|_| PersistError::Format("u32".into()))?,
    );
    *i += 4;
    Ok(v)
}

fn take_i32(b: &[u8], i: &mut usize) -> Result<i32, PersistError> {
    Ok(i32::from_be_bytes(take_u32(b, i)?.to_be_bytes()))
}

fn take_u64(b: &[u8], i: &mut usize) -> Result<u64, PersistError> {
    if *i + 8 > b.len() {
        return Err(PersistError::Format("eof".into()));
    }
    let v = u64::from_be_bytes(
        b[*i..*i + 8]
            .try_into()
            .map_err(|_| PersistError::Format("u64".into()))?,
    );
    *i += 8;
    Ok(v)
}

fn take_bytes(b: &[u8], i: &mut usize) -> Result<Vec<u8>, PersistError> {
    let n = take_u32(b, i)? as usize;
    if *i + n > b.len() {
        return Err(PersistError::Format("eof".into()));
    }
    let v = b[*i..*i + n].to_vec();
    *i += n;
    Ok(v)
}

fn take_str(b: &[u8], i: &mut usize) -> Result<String, PersistError> {
    let v = take_bytes(b, i)?;
    String::from_utf8(v).map_err(|_| PersistError::Format("utf8".into()))
}

#[cfg(test)]
mod tests {
    use super::{DbFormat, db_format, is_mit_db2};

    use crate::mkey::{default_master_etype, master_etype};
    use krb5_crypto::EncryptionType;

    const MIT_BTREE: [u8; 16] = [
        0x62, 0x31, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ];
    const MIT_HASH: [u8; 16] = [
        0x00, 0x06, 0x15, 0x61, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x04, 0xd2, 0x00, 0x00, 0x10,
        0x00,
    ];

    #[test]
    fn an_mit_db2_header_is_known_in_both_layouts_and_byte_orders() {
        assert!(is_mit_db2(&MIT_BTREE));
        assert!(is_mit_db2(&MIT_HASH));
        assert!(is_mit_db2(&[
            0x00, 0x05, 0x31, 0x62, 0x00, 0x00, 0x00, 0x03
        ]));
        assert!(is_mit_db2(&[
            0x00, 0x06, 0x15, 0x61, 0x00, 0x00, 0x00, 0x01
        ]));
        assert!(!is_mit_db2(&[
            0x62, 0x31, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00
        ]));
        assert!(!is_mit_db2(&[
            0x61, 0x15, 0x06, 0x00, 0x03, 0x00, 0x00, 0x00
        ]));
        assert!(!is_mit_db2(&MIT_BTREE[..7]));
        assert!(!is_mit_db2(b"kdb5_util load_dump version 7\n"));
        assert_eq!(db_format(&MIT_BTREE), DbFormat::MitDb2);
        assert_eq!(db_format(&MIT_HASH), DbFormat::MitDb2);
    }

    #[test]
    fn master_key_type_is_honored_and_defaults_to_mits() {
        assert_eq!(master_etype(None), Ok(default_master_etype()));
        assert_eq!(master_etype(None), Ok(EncryptionType::Aes256CtsHmacSha196));
        assert_eq!(
            master_etype(Some("aes256-cts-hmac-sha1-96")),
            Ok(EncryptionType::Aes256CtsHmacSha196)
        );
        assert_eq!(
            master_etype(Some("aes256-cts-hmac-sha384-192")),
            Ok(EncryptionType::Aes256CtsHmacSha384192)
        );
        assert!(master_etype(Some("no-such-enctype")).is_err());
    }
}
