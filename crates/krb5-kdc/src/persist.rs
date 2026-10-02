//! Persistent principal database: stash + MIT dump version 7 at rest.
//!
//! New writes are dump text (`kdb5_util load_dump version 7`). SID/RID live
//! in dump `tl_data` (`TL_KERBER_SID`). Legacy `KDB1`/`KDB2`/`KDB3`
//! ciphertext still loads for one release. An MIT db2 database is not read: it
//! is refused with a text that names MIT's `kdb5_util dump` and this
//! `kdb5_util load`, MIT's own way between back ends. The stash is a keytab-format
//! `.k5.REALM` (a single `K/M@REALM` entry, MIT `krb5_def_store_mkey_list`);
//! a legacy raw-key stash still loads (`krb5_db_def_fetch_mkey`) and is
//! rewritten in keytab format on the next save the writer may make to it.
//!
//! The database is read holding its lock shared and written holding it exclusively
//! ([`crate::DbLock`]); every write moves the database's age forward.

use std::fmt::Write as _;
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
use crate::store::{KeyEntry, Principal, PrincipalStore, S2K_ITERS, UlogEntry};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt};
use krb5_protocol::{
    Keytab, check_secret_file_writable, write_fresh_secret_file, write_secret_file,
};
use krb5_types::pac::RpcSid;
use krb5_types::{PrincipalName, parse_name};

const DUMP_PREFIX: &[u8] = b"kdb5_util load_dump version ";

/// Persistence failure.
#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    /// I/O.
    #[error("persist io: {0}")]
    Io(#[from] std::io::Error),
    /// Crypto.
    #[error("persist crypto: {0}")]
    Crypto(String),
    /// Format.
    #[error("persist format: {0}")]
    Format(String),
    /// `db_library` is not a supported backend.
    #[error("unknown db_library: {0}")]
    UnknownDbLibrary(String),
    /// The database's lock files are missing, or its lock may not be taken; the text is MIT's.
    #[error(transparent)]
    Lock(#[from] DbLockError),
    /// The database file is no database this store reads: MIT's text, naming the file.
    #[error("Cannot open DB2 database '{}': {why}", path.display())]
    Unopenable {
        /// The database file.
        path: PathBuf,
        /// What the file is.
        why: Unopenable,
    },
}

/// Why a database file does not open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unopenable {
    /// Neither dump text nor a legacy KDB blob: `EINVAL`, the errno MIT's Berkeley DB gives a
    /// file of another format where the platform has no `EFTYPE`.
    NotDatabase,
    /// An MIT db2 database, which only MIT's tools read: it moves over by MIT's `kdb5_util dump`
    /// and this `kdb5_util load`, and is never converted where it lies.
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

/// What a store last read of its database: the database's age and the database file's identity
/// and change time. A writer moves the age (when it may set `principal.ok`'s times) and replaces
/// the file, whose change time is new even when its inode number is a freed one reused, so a
/// different stamp means another read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DbStamp {
    age: Option<DbAge>,
    dev: u64,
    ino: u64,
    ctime: (i64, i64),
}

impl DbStamp {
    /// The stamp of the database at `db` now; read it holding the lock.
    pub(crate) fn now(lock: &DbLock, db: &Path) -> Option<Self> {
        let meta = fs::metadata(db).ok()?;
        Some(Self {
            age: lock.age(),
            dev: meta.dev(),
            ino: meta.ino(),
            ctime: (meta.ctime(), meta.ctime_nsec()),
        })
    }
}

/// What a database file holds, by its first bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DbFormat {
    /// Nothing: a database being created or loaded is empty until it is written.
    Empty,
    /// MIT dump text, the store's format.
    Dump,
    /// A legacy `KDB1` / `KDB2` / `KDB3` ciphertext.
    Kdb,
    /// An MIT db2 database ([`is_mit_db2`]).
    MitDb2,
    /// None of these.
    Unknown,
}

fn db_format(head: &[u8]) -> DbFormat {
    if head.is_empty() {
        DbFormat::Empty
    } else if head.starts_with(DUMP_PREFIX) {
        DbFormat::Dump
    } else if head
        .get(..4)
        .is_some_and(|m| matches!(m, b"KDB1" | b"KDB2" | b"KDB3"))
    {
        DbFormat::Kdb
    } else if is_mit_db2(head) {
        DbFormat::MitDb2
    } else {
        DbFormat::Unknown
    }
}

/// MIT `BTREEMAGIC` (`plugins/kdb/db2/libdb2/include/db.hin:131-131`): the magic a btree's metadata page starts with.
const BTREEMAGIC: u32 = 0x0005_3162;
/// MIT `BTREEVERSION` (`plugins/kdb/db2/libdb2/include/db.hin:132-132`): the one btree version MIT opens.
const BTREEVERSION: u32 = 3;
/// MIT `HASHMAGIC` (`plugins/kdb/db2/libdb2/include/db.hin:149-149`): the magic a hash file's header starts with.
const HASHMAGIC: u32 = 0x0006_1561;
/// MIT `HASHVERSION` (`plugins/kdb/db2/libdb2/include/db.hin:150-150`): the hash version MIT writes.
const HASHVERSION: u32 = 3;
/// MIT `OLDHASHVERSION` (`plugins/kdb/db2/libdb2/hash/hash.c:155-155`): the older hash version MIT still opens.
const OLDHASHVERSION: u32 = 1;

/// Whether `head`, a file's first bytes, begins an MIT db2 database (`principal`, or the policy
/// database `principal.kadm5`): a Berkeley DB btree, whose metadata page starts with its magic
/// and version in the byte order it was made in, or a hash file, whose header holds them
/// big-endian. Settled live on MIT 1.22.2: `kdb5_util create` makes both files btrees
/// (`62 31 05 00 03 00 00 00` on x86-64), and `-x hash=true` makes `principal` a hash file
/// (`00 06 15 61 00 00 00 03`).
/// MIT `__bt_open` (`plugins/kdb/db2/libdb2/btree/bt_open.c:234-246`): a btree's magic and version are read in either byte order.
/// MIT `hget_header` (`plugins/kdb/db2/libdb2/hash/hash.c:397-420`): a hash file's header is read big-endian.
/// MIT `__kdb2_hash_open` (`plugins/kdb/db2/libdb2/hash/hash.c:152-158`): a hash file has its magic and version 3 or 1.
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

/// The refusal of a database file of `format`; `None` for a database the store reads.
fn refusal(db: &Path, format: DbFormat) -> Option<PersistError> {
    let why = match format {
        DbFormat::Dump | DbFormat::Kdb => return None,
        DbFormat::MitDb2 => Unopenable::MitDb2,
        DbFormat::Empty | DbFormat::Unknown => Unopenable::NotDatabase,
    };
    Some(PersistError::Unopenable {
        path: db.to_path_buf(),
        why,
    })
}

/// Open the database file at `db` as MIT's db2 module first opens it, before its lock files and
/// the master key: a file that does not open or read is the system's error, and one whose first
/// bytes are no database this store reads is refused with MIT's text; an MIT db2 database is
/// named as one, with the way over, and left as it is. An empty file passes here, as a database
/// being created or loaded is empty until it is written; the read under the lock judges it.
/// MIT `check_openable` (`plugins/kdb/db2/kdb_db2.c:545-557`): the database is opened before its lock files.
/// MIT `open_db` (`plugins/kdb/db2/kdb_db2.c:384-389`): a database that does not open is named, with its errno.
///
/// # Errors
///
/// [`PersistError::Io`] when the file does not open or read; [`PersistError::Unopenable`] when it
/// is no database this store reads.
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

/// Load a store from `db_path` using the master key in `stash_path`, holding the database's lock
/// shared while it is read; the store keeps the lock files open for its later reads and changes.
///
/// Dump version 6/7 text is the canonical format. `KDB1`/`KDB2`/`KDB3`
/// ciphertext is still accepted.
/// MIT `krb5_db2_open` (`plugins/kdb/db2/kdb_db2.c:1194-1198`): the database must open, then its lock files.
///
/// # Errors
///
/// [`PersistError::Io`] when the database or the stash cannot be read (a missing file included);
/// [`PersistError::Unopenable`] when the database is no database this store reads, before its
/// lock files and the stash are opened ([`check_openable`]);
/// [`PersistError::Lock`] when `principal.ok` or `principal.kadm5.lock` does not open or the
/// lock may not be taken; [`PersistError::Format`] when a dump is not UTF-8, a legacy database
/// has a malformed record, or the `.ulog` file beside it is malformed;
/// [`PersistError::Crypto`] when no key from the stash loads the dump (a malformed dump
/// included) or decrypts a legacy database, or a legacy key is unusable.
pub fn load_store(db_path: &Path, stash_path: &Path) -> Result<PrincipalStore, PersistError> {
    check_openable(db_path)?;
    let lock = Arc::new(DbLock::open(db_path)?);
    let _held = lock.hold(DbLockMode::Shared)?;
    read_store(db_path, stash_path, &lock)
}

/// The store the database at `db_path` holds now, read while the caller holds `lock`: the
/// database is judged before the stash is read, as MIT opens it before the master key.
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
    let stash = fs::read(stash_path)?;
    let mut store = if format == DbFormat::Dump {
        let text = std::str::from_utf8(&blob)
            .map_err(|_| PersistError::Format("dump is not utf-8".into()))?;
        load_dump_with_stash(text, &stash)?
    } else {
        load_kdb_blob(&blob, &stash)?
    };
    store.persist_paths = Some((db_path.to_path_buf(), stash_path.to_path_buf()));
    store.db_stamp = DbStamp::now(lock, db_path);
    store.dblock = Some(Arc::clone(lock));
    load_ulog(&mut store, db_path)?;
    Ok(store)
}

/// Load a store from `db_path` with every key unwrapped under `master`, holding the database's
/// lock shared while it is read as [`load_store`] does; the stash is not read, and a save the
/// store makes itself writes under `master` too.
/// MIT `kdb_init_master` (`lib/kadm5/srv/server_kdb.c:26-80`): a master key typed at the
/// keyboard opens the database, and the stash is never read.
///
/// # Errors
///
/// [`PersistError::Io`] when the database cannot be read; [`PersistError::Unopenable`] when it
/// is no database this store reads ([`check_openable`]); [`PersistError::Lock`] when
/// `principal.ok` or `principal.kadm5.lock` does not open or the lock may not be taken;
/// [`PersistError::Format`] when it is a legacy database (which needs its stash) or the
/// `.ulog` beside it is malformed; [`PersistError::Crypto`] when a key does not decrypt under
/// `master`, a wrong master key included.
pub fn load_store_with_master(
    db_path: &Path,
    master: &ProtocolKey,
) -> Result<PrincipalStore, PersistError> {
    check_openable(db_path)?;
    let lock = Arc::new(DbLock::open(db_path)?);
    let _held = lock.hold(DbLockMode::Shared)?;
    read_store_with_master(db_path, master, &lock)
}

/// The store the database at `db_path` holds now under `master`, read while the caller holds
/// `lock`.
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
    let text =
        std::str::from_utf8(&blob).map_err(|_| PersistError::Format("dump is not utf-8".into()))?;
    let mut store = crate::kdb_dump::load_dump_with_key(text, master)?;
    store.db_stamp = DbStamp::now(lock, db_path);
    store.dblock = Some(Arc::clone(lock));
    load_ulog(&mut store, db_path)?;
    store.persist_master = Some((db_path.to_path_buf(), master.clone()));
    Ok(store)
}

/// Read the database at `db` as dump text holding its lock shared, for a caller that opens the
/// dump itself; the lock files are opened for this read alone.
///
/// # Errors
///
/// [`PersistError::Lock`] when a lock file does not open or the lock may not be taken;
/// [`PersistError::Io`] when the database cannot be read.
pub fn read_db_locked(db: &Path) -> Result<Vec<u8>, PersistError> {
    let lock = Arc::new(DbLock::open(db)?);
    let _held = lock.hold(DbLockMode::Shared)?;
    Ok(fs::read(db)?)
}

/// Save `store` as MIT dump version 7, holding the database's lock exclusively (taking it unless
/// the store already holds it) and moving its age forward. Creates `stash_path` if needed.
///
/// A database not there yet is created, as `krb5-kdb create` creates one: its lock files too.
/// The database, its `.ulog` and a rewritten stash keep the owner, group and mode of the files
/// they replace (`write_secret_file`), so `kadmind` as root and `kadmin.local` as another user
/// can share them. A writer that may not write the database or its `.ulog` changes nothing.
///
/// A new stash holds the store's `K/M` key when the store has one (the master key its dump
/// was loaded with); otherwise a random key of the realm's `master_key_type`
/// ([`crate::master_etype`]), or with the `test-hooks` feature one derived from
/// `KRB5_MASTER_PASSWORD` when that is set.
///
/// # Errors
///
/// [`PersistError::Lock`] when the database's lock files do not open (or cannot be made for a
/// new database) or the lock may not be taken; [`PersistError::Io`] when the stash cannot be
/// read or the stash, database or `.ulog` file cannot be written (an existing one the writer
/// may not open read-write is refused before any file changes); [`PersistError::Crypto`] when
/// an existing stash is not a usable master key, `master_key_type` names no supported enctype, a
/// new master key cannot be derived or generated, or a key cannot be wrapped;
/// [`PersistError::Format`] when a new stash is needed and the KDC profile cannot be read or the
/// realm is not ASCII.
pub fn save_store(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
) -> Result<(), PersistError> {
    let lock = WriteLock::take(store, db_path)?;
    save_store_as(store, db_path, stash_path, DbWrite::InPlace)?;
    lock.update_age();
    Ok(())
}

/// Save `store` as a full load leaves it ([`load_store_full`]): the database is a new 0600 file
/// owned by the writer, whatever it replaces, made live under the database's exclusive lock; the
/// stash is handled as [`save_store`] handles it.
/// MIT `load_db` (`kadmin/dbutil/dump.c:1490-1508`): a full load is written to a temporary database.
/// MIT `load_db` (`kadmin/dbutil/dump.c:1551-1569`): the temporary database is then made live.
///
/// # Errors
///
/// As [`load_store_full`], and the stash's errors as for [`save_store`].
pub fn save_store_fresh(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
) -> Result<(), PersistError> {
    let master = master_for_save(store, db_path, stash_path)?;
    Ok(load_store_full(store, db_path, &master)?)
}

fn save_store_as(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
    how: DbWrite,
) -> Result<(), PersistError> {
    // MIT `ulog_map` (`lib/kdb/kdb_log.c:525-526`): an existing update log is reopened `O_RDWR` as the database is.
    // Both are checked before either changes, so a refused writer leaves no half-saved store.
    check_writable(db_path, how)?;
    let master = master_for_save(store, db_path, stash_path)?;
    write_store_files(store, db_path, &master, how)
}

/// The database's exclusive lock for one write: the store's own when it holds it already, else
/// one taken for the write, the lock files made first for a database not there yet.
enum WriteLock {
    Held(Arc<DbLock>),
    Taken(DbLockHold),
}

impl WriteLock {
    fn take(store: &PrincipalStore, db: &Path) -> Result<Self, PersistError> {
        if let Some(lock) = store.dblock.as_ref()
            && store.db_path() == Some(db)
        {
            if lock.held_exclusive() {
                return Ok(Self::Held(Arc::clone(lock)));
            }
            return Ok(Self::Taken(lock.hold(DbLockMode::Exclusive)?));
        }
        let lock = match DbLock::open(db) {
            Ok(lock) => lock,
            Err(_) if !db.exists() => {
                make_lock_files(db)?;
                DbLock::open(db)?
            }
            Err(e) => return Err(e.into()),
        };
        Ok(Self::Taken(Arc::new(lock).hold(DbLockMode::Exclusive)?))
    }

    fn update_age(&self) {
        match self {
            Self::Held(lock) => lock.update_age(),
            Self::Taken(hold) => hold.lock().update_age(),
        }
    }
}

/// Make the lock files of a database about to be created: `principal.ok` (kept if there), and
/// `principal.kadm5.lock` unless it is there already.
/// MIT `ctx_create_db` (`plugins/kdb/db2/kdb_db2.c:697-732`): a new database's `principal.ok` is created and locked, then its policy lock file.
fn make_lock_files(db: &Path) -> Result<(), PersistError> {
    let lock = DbLock::create(db)?;
    if !crate::dblock::suffixed(db, SUFFIX_POLICY_LOCK).exists() {
        lock.create_policy_lock()?;
    }
    lock.unlock()?;
    Ok(())
}

/// How [`save_store_with_master`] replaces the database file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbWrite {
    /// An update in place: the database keeps its owner, group and mode, and a writer that may
    /// not write it is refused ([`write_secret_file`]).
    InPlace,
    /// A new 0600 file owned by the writer ([`write_fresh_secret_file`]), as a full load leaves.
    Fresh,
}

/// MIT `ctx_lock` (`plugins/kdb/db2/kdb_db2.c:450-463`): the locked database is reopened `O_RDWR`, so a writer that may not write it is refused with the database's name.
fn check_writable(db_path: &Path, how: DbWrite) -> Result<(), PersistError> {
    if how == DbWrite::InPlace
        && let Err(e) = check_secret_file_writable(db_path)
    {
        return Err(PersistError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "Cannot open DB2 database '{}': {}",
                db_path.display(),
                strerror(&e)
            ),
        )));
    }
    check_secret_file_writable(&ulog_path(db_path))?;
    Ok(())
}

/// The system's text for `e`, without Rust's `(os error N)`.
fn strerror(e: &std::io::Error) -> String {
    let text = e.to_string();
    match e.raw_os_error() {
        Some(code) => text
            .strip_suffix(&format!(" (os error {code})"))
            .map_or_else(|| text.clone(), str::to_owned),
        None => text,
    }
}

/// Save `store` with every key wrapped under `master`; the stash is not read or written. The
/// database's lock is held exclusively for the write, as [`save_store`] holds it; a
/// [`DbWrite::Fresh`] write is a full load ([`load_store_full`]).
///
/// The `.ulog` beside the database is always updated in place.
///
/// # Errors
///
/// [`PersistError::Lock`] as for [`save_store`]; [`PersistError::Io`] when the database or
/// `.ulog` cannot be written (for [`DbWrite::InPlace`], an existing database the writer may not
/// open read-write is refused before any file changes); [`PersistError::Crypto`] when a key
/// cannot be wrapped.
pub fn save_store_with_master(
    store: &PrincipalStore,
    db_path: &Path,
    master: &ProtocolKey,
    how: DbWrite,
) -> Result<(), PersistError> {
    if how == DbWrite::Fresh {
        return Ok(load_store_full(store, db_path, master)?);
    }
    let lock = WriteLock::take(store, db_path)?;
    check_writable(db_path, how)?;
    write_store_files(store, db_path, master, how)?;
    lock.update_age();
    Ok(())
}

fn write_store_files(
    store: &PrincipalStore,
    db_path: &Path,
    master: &ProtocolKey,
    how: DbWrite,
) -> Result<(), PersistError> {
    let text = write_dump(store, master)?;
    match how {
        DbWrite::InPlace => write_secret_file(db_path, text.as_bytes())?,
        DbWrite::Fresh => write_fresh_secret_file(db_path, text.as_bytes())?,
    }
    save_ulog(store, db_path)?;
    Ok(())
}

/// Write `text`, dump text with no principal record, as the database: a full load
/// ([`DbWrite::Fresh`]) leaves it as a new file beside an empty `.ulog`, an update
/// ([`DbWrite::InPlace`]) rewrites the database alone. No key is wrapped, so no master key is
/// needed. The database's lock is held exclusively for the write.
///
/// # Errors
///
/// [`PersistError::Lock`] as for [`save_store`]; [`PersistError::Io`] when the database or
/// `.ulog` cannot be written (for [`DbWrite::InPlace`], an existing database the writer may not
/// open read-write is refused before any file changes).
pub fn save_dump_text(db_path: &Path, text: &str, how: DbWrite) -> Result<(), PersistError> {
    if how == DbWrite::Fresh {
        return Ok(load_text_full(db_path, text, "ulog 1\n")?);
    }
    let lock = WriteLock::take(&PrincipalStore::new(""), db_path)?;
    check_writable(db_path, how)?;
    write_secret_file(db_path, text.as_bytes())?;
    lock.update_age();
    Ok(())
}

/// [`save_store_with_master`] in place while the caller holds `lock` on the database at
/// `db_path`, exclusively or permanently (`load -update`); the age moves.
///
/// # Errors
///
/// [`PersistError::Lock`] when `lock` is not held exclusively; otherwise as
/// [`save_store_with_master`].
pub fn save_store_locked(
    store: &PrincipalStore,
    db_path: &Path,
    master: &ProtocolKey,
    lock: &DbLock,
) -> Result<(), PersistError> {
    if !lock.held_exclusive() {
        return Err(DbLockError::NotLocked.into());
    }
    check_writable(db_path, DbWrite::InPlace)?;
    write_store_files(store, db_path, master, DbWrite::InPlace)?;
    lock.update_age();
    Ok(())
}

/// [`save_dump_text`] in place while the caller holds `lock` on the database at `db_path`,
/// exclusively or permanently (`load -update`); the age moves.
///
/// # Errors
///
/// [`PersistError::Lock`] when `lock` is not held exclusively; otherwise as [`save_dump_text`].
pub fn save_dump_text_locked(
    db_path: &Path,
    text: &str,
    lock: &DbLock,
) -> Result<(), PersistError> {
    if !lock.held_exclusive() {
        return Err(DbLockError::NotLocked.into());
    }
    check_writable(db_path, DbWrite::InPlace)?;
    write_secret_file(db_path, text.as_bytes())?;
    lock.update_age();
    Ok(())
}

/// Why a full load did not make its dump the database.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The temporary database could not be made or written; MIT reports it while creating the
    /// database.
    #[error(transparent)]
    Create(PersistError),
    /// The temporary database could not be made live; MIT reports it while making the newly
    /// loaded database live.
    #[error(transparent)]
    Promote(PersistError),
}

impl From<LoadError> for PersistError {
    fn from(e: LoadError) -> Self {
        match e {
            LoadError::Create(e) | LoadError::Promote(e) => e,
        }
    }
}

/// Make `store`, its keys wrapped under `master`, the database at `db_path` as a full load does
/// ([`load_text_full`]), with its update log.
///
/// # Errors
///
/// [`LoadError::Create`] when a key cannot be wrapped; otherwise as [`load_text_full`].
pub fn load_store_full(
    store: &PrincipalStore,
    db_path: &Path,
    master: &ProtocolKey,
) -> Result<(), LoadError> {
    let text = write_dump(store, master).map_err(|e| LoadError::Create(e.into()))?;
    load_text_full(db_path, &text, &ulog_text(store))
}

/// Make the dump `text` the database at `db_path` as MIT's full load does, with `ulog` as its
/// update log. The dump is written to a temporary database, `principal~`, made with its own two
/// lock files and held under its exclusive lock, so readers keep reading the old database
/// meanwhile; then the real database's exclusive lock is taken (waiting for any holder) and the
/// temporary database renamed over it, the age moved, and the temporary lock files removed. When
/// there is no database yet, it and its two lock files are created first; an existing
/// `principal.ok` is kept, and made again only when it is missing. The new database is a 0600
/// file owned by the writer.
/// MIT `load_db` (`kadmin/dbutil/dump.c:1490-1508`): a full load creates a temporary database.
/// MIT `ctx_create_db` (`plugins/kdb/db2/kdb_db2.c:710-716`): a temporary database's remnants are destroyed under its lock.
/// MIT `krb5_db2_promote_db` (`plugins/kdb/db2/kdb_db2.c:1497-1513`): the real database is created when there is none, else opened and locked exclusively.
/// MIT `ctx_promote` (`plugins/kdb/db2/kdb_db2.c:1434-1448`): the temporary database is renamed over the real one, the age moves, and the temporary lock files are removed.
/// MIT `load_db` (`kadmin/dbutil/dump.c:1590-1600`): a failed load destroys the temporary database.
///
/// # Errors
///
/// [`LoadError::Create`] when the temporary database or its lock files cannot be made or
/// written (nothing of it is left); [`LoadError::Promote`] when the real database's lock files
/// do not open (`principal.kadm5.lock` missing: MIT's text), its lock may not be taken, or the
/// update log or the rename fails (the temporary database is removed).
pub fn load_text_full(db_path: &Path, text: &str, ulog: &str) -> Result<(), LoadError> {
    let tmp = suffixed(db_path, "~");
    let temp = create_temporary(&tmp, text).map_err(LoadError::Create)?;
    let real = match promote(db_path, &tmp, ulog) {
        Ok(real) => real,
        Err(e) => {
            destroy_temporary(&tmp);
            let _ = temp.unlock();
            return Err(LoadError::Promote(e));
        }
    };
    let _ = temp.unlock();
    drop(temp);
    real.unlock().map_err(|e| LoadError::Promote(e.into()))
}

/// The temporary database at `tmp` with `text` written to it, under its own lock files, which
/// stay locked exclusively.
fn create_temporary(tmp: &Path, text: &str) -> Result<DbLock, PersistError> {
    let lock = DbLock::create(tmp)?;
    destroy_file(tmp);
    let _ = fs::remove_file(suffixed(tmp, SUFFIX_POLICY_LOCK));
    let made = (|| -> Result<(), PersistError> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(tmp)?;
        lock.create_policy_lock()?;
        std::io::Write::write_all(&mut file, text.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(e) = made {
        destroy_temporary(tmp);
        let _ = lock.unlock();
        return Err(e);
    }
    Ok(lock)
}

/// Make the temporary database at `tmp` the database at `db`, holding `db`'s exclusive lock;
/// the lock is returned still held. A database, or a policy lock file, already there is opened
/// and locked instead of made: a replica whose database file alone is gone loads as MIT's does.
/// MIT `krb5_db2_promote_db` (`plugins/kdb/db2/kdb_db2.c:1498-1510`): `EEXIST` from `ctx_create_db`, for the database or its policy files, opens and locks the real database.
fn promote(db: &Path, tmp: &Path, ulog: &str) -> Result<DbLock, PersistError> {
    let created = DbLock::create(db)?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let made = match opts.open(db) {
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
        write_secret_file(&ulog_path(db), ulog.as_bytes())?;
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

/// Remove the temporary database at `tmp` and its lock files, as a failed load does.
fn destroy_temporary(tmp: &Path) {
    destroy_file(tmp);
    let _ = fs::remove_file(suffixed(tmp, SUFFIX_LOCK));
    let _ = fs::remove_file(suffixed(tmp, SUFFIX_POLICY_LOCK));
}

/// Zero the file at `path` and unlink it; a file that is not there, or that cannot be zeroed, is
/// unlinked or left as it is without an error.
/// MIT `destroy_file` (`plugins/kdb/db2/kdb_db2.c:626-676`): the file is overwritten with zeros, synced and unlinked.
fn destroy_file(path: &Path) {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.is_file()
        && let Ok(mut f) = fs::OpenOptions::new().write(true).open(path)
    {
        let zeros = vec![0u8; usize::try_from(meta.len()).unwrap_or(0)];
        let _ = std::io::Write::write_all(&mut f, &zeros);
        let _ = f.sync_all();
    }
    let _ = fs::remove_file(path);
}

/// Why [`create_store`] wrote nothing.
#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    /// The database path could not be created: it exists (`AlreadyExists`), its directory does
    /// not (`NotFound`), or the OS refused.
    #[error("{0}")]
    Create(std::io::Error),
    /// A lock file could not be made or locked: `principal.ok`, or a `principal.kadm5.lock`
    /// already there (`AlreadyExists`). MIT then leaves the database file it created.
    #[error(transparent)]
    Lock(#[from] DbLockError),
    /// The database was reserved but could not be written.
    #[error(transparent)]
    Persist(#[from] PersistError),
}

/// Write a new database for `store` under `master`, as `kdb5_util create` makes one, with its two
/// lock files.
///
/// `principal.ok` is made (kept and emptied when it is there) and locked exclusively; the
/// database path is then reserved with an exclusive create, so an existing database (or any file
/// there) is never replaced; then `principal.kadm5.lock` is made, which must not exist, and
/// locked; then the dump and its `.ulog` are written as new 0600 files owned by the writer, the
/// age moves and both locks are let go. The lock files are 0600 and owned by the writer, and with
/// SELinux on they take the context the policy gives their paths. The stash is the caller's
/// ([`write_stash`]).
/// MIT `ctx_create_db` (`plugins/kdb/db2/kdb_db2.c:697-708`): `principal.ok` is opened `O_CREAT | O_RDWR | O_TRUNC`, 0600, and locked exclusively first.
/// MIT `ctx_create_db` (`plugins/kdb/db2/kdb_db2.c:718-720`): the database is opened `O_RDWR | O_CREAT | O_EXCL`, mode 0600.
/// MIT `ctx_create_db` (`plugins/kdb/db2/kdb_db2.c:722-732`): the policy lock file is created `O_EXCL` and locked; a failure leaves the database file.
///
/// # Errors
///
/// [`CreateError::Lock`] when `principal.ok` cannot be made or locked (nothing else is written),
/// or `principal.kadm5.lock` cannot be made (the reserved database stays, as MIT's does);
/// [`CreateError::Create`] when the database path cannot be created exclusively;
/// [`CreateError::Persist`] when the dump or `.ulog` cannot be written or a key cannot be
/// wrapped (the reservation is removed again).
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
    opts.open(db_path).map_err(CreateError::Create)?;
    lock.create_policy_lock()?;
    let written = write_dump(store, master)
        .map_err(PersistError::from)
        .and_then(|text| Ok(write_fresh_secret_file(db_path, text.as_bytes())?))
        .and_then(|()| {
            let ulog = ulog_text(store);
            Ok(write_fresh_secret_file(
                &ulog_path(db_path),
                ulog.as_bytes(),
            )?)
        });
    if let Err(e) = written {
        let _ = fs::remove_file(db_path);
        return Err(e.into());
    }
    lock.update_age();
    lock.unlock()?;
    Ok(())
}

/// Write the master-key stash: a FILE keytab with one `K/M@realm` entry at `kvno`, as a new
/// 0600 file owned by the writer, whatever it replaces.
/// MIT `krb5_def_store_mkey_list` (`lib/kdb/kdb_default.c:111-213`): the stash is a keytab holding the master key list.
///
/// # Errors
///
/// [`PersistError::Format`] when `realm` is not ASCII; [`PersistError::Io`] when the file
/// cannot be written.
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

/// The master key a stash holds: its `K/M` entry, else (a legacy raw stash) the raw key that
/// opens the database at `db_path`.
/// MIT `krb5_db_def_fetch_mkey` (`lib/kdb/kdb_default.c:356-393`): the keytab form first, then the old stash form.
///
/// # Errors
///
/// [`PersistError::Io`] when the stash cannot be read (a missing file included);
/// [`PersistError::Crypto`] when it holds no usable master key.
pub fn read_stash(stash_path: &Path, db_path: &Path) -> Result<ProtocolKey, PersistError> {
    existing_stash_key(db_path, stash_path)
}

/// The master keys stash bytes may hold: the `K/M` entry of a keytab stash, else each enctype a
/// legacy raw stash may be. Empty when the bytes are neither.
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

fn ulog_path(db_path: &Path) -> PathBuf {
    let mut s = db_path.as_os_str().to_os_string();
    s.push(".ulog");
    PathBuf::from(s)
}

/// Each entry's serial, time, kind and name; the kind is `1` for a delete, else `0:` and the
/// attribute list its update sends, which a reader from before the list takes as `0`.
fn ulog_text(store: &PrincipalStore) -> String {
    let mut text = String::from("ulog 1\n");
    for e in store.ulog() {
        let kind = if e.deleted {
            "1".to_owned()
        } else {
            format!("0:{}", e.attrs)
        };
        let _ = writeln!(text, "{}\t{}\t{kind}\t{}", e.sno, e.time, e.name);
    }
    text
}

fn save_ulog(store: &PrincipalStore, db_path: &Path) -> Result<(), PersistError> {
    write_secret_file(&ulog_path(db_path), ulog_text(store).as_bytes())?;
    Ok(())
}

/// MIT `ulog_map` (`kdb_log.c:514-518`): a missing update log is not a corrupt log.
/// A file whose first line is not the ulog header is not loaded, and a missing file leaves the
/// store's log empty. An entry written before the attribute list was kept (kind `0`) sends every
/// attribute of a new principal; each entry sends the record as it is now.
fn load_ulog(store: &mut PrincipalStore, db_path: &Path) -> Result<(), PersistError> {
    let path = ulog_path(db_path);
    let Ok(text) = fs::read_to_string(&path) else {
        return Ok(());
    };
    let mut lines = text.lines();
    let Some(hdr) = lines.next() else {
        return Ok(());
    };
    if !hdr.starts_with("ulog ") {
        return Err(PersistError::Format("ulog header".into()));
    }
    let mut entries = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let mut f = line.splitn(4, '\t');
        let sno: u32 = f
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| PersistError::Format("ulog sno".into()))?;
        let time: u32 = f
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| PersistError::Format("ulog time".into()))?;
        let kind = f.next().unwrap_or_default();
        let deleted = kind == "1";
        let attrs = match kind.split_once(':') {
            Some(("0", list)) => list
                .parse()
                .map_err(|_| PersistError::Format("ulog attrs".into()))?,
            _ if deleted => 0,
            _ => crate::ULOG_ADD_ATTRS,
        };
        let name = f
            .next()
            .ok_or_else(|| PersistError::Format("ulog name".into()))?
            .to_owned();
        let princ = if deleted {
            None
        } else {
            store.get(&name).cloned()
        };
        entries.push(UlogEntry {
            sno,
            time,
            name,
            deleted,
            princ,
            attrs,
        });
    }
    store.restore_ulog(entries);
    Ok(())
}

/// Write a KDB3 ciphertext (one-release load tests / migration helper).
///
/// New production writes use [`save_store`] (dump v7). This remains so a
/// generated legacy blob can prove `load_store` still reads KDB3.
///
/// # Errors
///
/// [`PersistError::Io`] when an existing stash cannot be read or the stash or database cannot be
/// written; [`PersistError::Lock`] as for [`save_store`]; [`PersistError::Crypto`] when an
/// existing stash is not a 32-byte key, a new one cannot be generated, or the encryption fails.
pub fn save_store_legacy_kdb3(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
) -> Result<(), PersistError> {
    let master = if stash_path.exists() {
        load_stash_etype(stash_path, EncryptionType::Aes256CtsHmacSha196)?
    } else {
        // The KDB3 stash is a raw aes256-cts-hmac-sha1-96 key by format.
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
    let lock = WriteLock::take(store, db_path)?;
    write_secret_file(db_path, &out)?;
    lock.update_age();
    Ok(())
}

/// Master key from a keytab-format stash (`krb5_db_def_fetch_mkey_keytab`):
/// the `K/M@REALM` entry, etype embedded. `None` for a legacy raw stash.
pub(crate) fn stash_keytab_key(bytes: &[u8]) -> Option<ProtocolKey> {
    let kt = Keytab::parse(bytes).ok()?;
    let km = PrincipalName::new(PrincipalName::NT_PRINCIPAL, crate::mkey::MASTER_NAME);
    kt.entries.into_iter().find(|e| e.name == km).map(|e| e.key)
}

/// Keytab-format stash bytes for `master` (`krb5_def_store_mkey_list`): one
/// `K/M@REALM` entry at kvno 1.
fn stash_keytab_bytes(realm: &str, master: &ProtocolKey) -> Result<Vec<u8>, PersistError> {
    let realm_a = krb5_types::try_ascii(realm).map_err(|e| PersistError::Format(e.to_string()))?;
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, crate::mkey::MASTER_NAME);
    Ok(Keytab::single(realm_a, name, 1, master.clone()).to_bytes())
}

/// Load dump text whose keys the master key in `stash` (stash file bytes) opens: the keytab
/// form's `K/M` entry, else each enctype a legacy raw stash may be.
///
/// # Errors
///
/// [`PersistError::Crypto`] when no key the stash holds loads the dump (a malformed dump
/// included).
pub fn load_dump_with_stash(text: &str, stash: &[u8]) -> Result<PrincipalStore, PersistError> {
    // krb5_db_def_fetch_mkey: keytab format first (etype known, one decrypt),
    // then the legacy raw stash (trial over the two harness etypes).
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

fn load_kdb_blob(blob: &[u8], stash: &[u8]) -> Result<PrincipalStore, PersistError> {
    if blob.len() < 4 {
        return Err(PersistError::Format("missing KDB magic".into()));
    }
    let magic = &blob[..4];
    let v2 = magic == b"KDB2";
    let v3 = magic == b"KDB3";
    if !v2 && !v3 && magic != b"KDB1" {
        return Err(PersistError::Format(
            "missing dump header or KDB1/KDB2/KDB3 magic".into(),
        ));
    }
    let master = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, stash)
        .map_err(|e| PersistError::Crypto(e.to_string()))?;
    let usage = KeyUsage::new(2).map_err(|e| PersistError::Crypto(e.to_string()))?;
    let plain =
        decrypt(&master, usage, &blob[4..]).map_err(|e| PersistError::Crypto(e.to_string()))?;
    parse_plain(&plain, v2, v3)
}

fn master_for_save(
    store: &PrincipalStore,
    db_path: &Path,
    stash_path: &Path,
) -> Result<ProtocolKey, PersistError> {
    if stash_path.exists() {
        let master = existing_stash_key(db_path, stash_path)?;
        // A legacy raw-key stash is rewritten in keytab format when the writer may write it. The
        // rewrite is optional: a stash the writer may only read still serves this save.
        if stash_keytab_key(&fs::read(stash_path)?).is_none()
            && check_secret_file_writable(stash_path).is_ok()
        {
            write_secret_file(stash_path, &stash_keytab_bytes(store.realm(), &master)?)?;
        }
        return Ok(master);
    }
    // MIT `add_principal` (`kadmin/dbutil/kdb5_create.c:409-424`): `K/M`'s key is the master key, so a new stash holds it.
    let realm = store.realm();
    let km = store
        .get(&format!("K/M@{realm}"))
        .and_then(|km| km.keys.first())
        .map(|k| k.key.clone());
    let master = if let Some(key) = km {
        key
    } else {
        let etype = persist_master_etype(realm)?;
        // MIT `kdb5_create` (`kadmin/dbutil/kdb5_create.c:200-220`): the master password is `-P` or typed, never the environment; the gates' variable is a test hook.
        #[cfg(feature = "test-hooks")]
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
    let bytes = fs::read(stash_path)?;
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
    for etype in stash_etypes() {
        if let Ok(mkey) = ProtocolKey::from_bytes(etype, &bytes) {
            return Ok(mkey);
        }
    }
    Err(PersistError::Crypto(
        "stash is not a usable master key".into(),
    ))
}

/// The master key type of a new stash for `realm`: the name
/// [`krb5_config::KdcPaths::master_key_type`] resolves for it (the realm's kdc.conf
/// `master_key_type`, or what overrides that resolver takes), else
/// [`crate::default_master_etype`], as `krb5-kdb` resolves it.
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
    let bytes = fs::read(path)?;
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
        out.push(u8::from(p.requires_preauth));
        out.extend_from_slice(&p.max_life.to_be_bytes());
        let nk = u32::try_from(p.keys.len()).unwrap_or(0);
        out.extend_from_slice(&nk.to_be_bytes());
        for k in &p.keys {
            out.extend_from_slice(&k.etype.to_iana().to_be_bytes());
            out.extend_from_slice(&k.kvno.to_be_bytes());
            put_bytes(&mut out, k.key.as_bytes());
        }
        out.push(u8::from(p.locked));
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

/// MIT `krb5_decode_princ_entry` (`db2/kdb_xdr.c:253-256`): a record shorter than the base
/// principal is truncated and not loaded.
/// An unknown etype or a key of the wrong length fails the whole store, so a partial
/// database is not opened.
fn parse_plain(plain: &[u8], v2: bool, v3: bool) -> Result<PrincipalStore, PersistError> {
    let mut i = 0;
    let realm = take_str(plain, &mut i)?;
    let mut store = PrincipalStore::new(realm);
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
            // KDB2 stored a unused SPAKE `w`; skip the length-prefixed blob.
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
    use super::{
        DbFormat, PersistError, check_openable, db_format, is_mit_db2, load_store,
        load_store_with_master, make_lock_files, save_store,
    };
    use crate::error::Error;
    use crate::mkey::{default_master_etype, master_etype};
    use krb5_crypto::{EncryptionType, ProtocolKey};

    /// The first 16 bytes of MIT 1.22.2's own db2 files, as `od` printed them (settled live):
    /// `principal` and `principal.kadm5` from `kdb5_util create -s` (btrees), and `principal`
    /// from `kdb5_util -x hash=true create -s` (a hash file).
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
        // A btree made on a big-endian host; a hash file of the older version.
        assert!(is_mit_db2(&[
            0x00, 0x05, 0x31, 0x62, 0x00, 0x00, 0x00, 0x03
        ]));
        assert!(is_mit_db2(&[
            0x00, 0x06, 0x15, 0x61, 0x00, 0x00, 0x00, 0x01
        ]));
        // MIT opens neither another btree version nor a hash header in little-endian order.
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

    /// An MIT db2 database where the database should be is refused naming it and the way over,
    /// before its lock files and the stash are opened (here there are none), and is left as it
    /// was; a served store whose database turns into one names it once when it reads it again.
    #[test]
    fn an_mit_db2_database_is_named_with_the_way_over_and_left_as_it_is() {
        let dir = krb5_testkit::scratch_dir("persist-mit-db2");
        let (db, stash) = (dir.join("principal"), dir.join("stash"));
        let master =
            ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[7; 32]).unwrap();
        let refused = |db: &std::path::Path| {
            format!(
                "Cannot open DB2 database '{}': This is an MIT db2 database; dump it with the old \
                 installation's kdb5_util, then kdb5_util load here (docs/install.md, Upgrading \
                 an MIT realm)",
                db.display()
            )
        };
        for head in [MIT_BTREE, MIT_HASH] {
            let mut file = head.to_vec();
            file.resize(8192, 0);
            std::fs::write(&db, &file).unwrap();
            assert_eq!(check_openable(&db).unwrap_err().to_string(), refused(&db));
            assert_eq!(
                load_store(&db, &stash).unwrap_err().to_string(),
                refused(&db)
            );
            assert_eq!(
                load_store_with_master(&db, &master)
                    .unwrap_err()
                    .to_string(),
                refused(&db)
            );
            assert_eq!(std::fs::read(&db).unwrap(), file, "left as it was");
        }
        let served = dir.join("served");
        std::fs::create_dir(&served).unwrap();
        let (db, stash) = (served.join("principal"), served.join("stash"));
        let (store, _) = crate::testrealm::bootstrap_documented().unwrap();
        save_store(&store, &db, &stash).unwrap();
        let mut store = load_store(&db, &stash).unwrap();
        let mut file = MIT_BTREE.to_vec();
        file.resize(8192, 0);
        std::fs::write(&db, &file).unwrap();
        match store.reload() {
            Err(Error::Db { text, .. }) => assert_eq!(text, refused(&db)),
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_database_file_is_judged_by_its_first_bytes() {
        assert_eq!(db_format(b""), DbFormat::Empty);
        assert_eq!(
            db_format(b"kdb5_util load_dump version 7\n"),
            DbFormat::Dump
        );
        assert_eq!(db_format(b"KDB3\x00\x01\x02"), DbFormat::Kdb);
        assert_eq!(db_format(b"not a database\n"), DbFormat::Unknown);
        // A dump header cut short is no dump.
        assert_eq!(db_format(b"kdb5_util load_dump"), DbFormat::Unknown);
    }

    /// A file that is no database is refused with MIT's text (settled live: MIT 1.22.2's db2
    /// module says `Invalid argument`) before its lock files and the stash are opened, here
    /// missing; an empty file passes the open and is refused by the read under the lock.
    #[test]
    fn a_file_that_is_no_database_is_refused_with_mit_s_open_text() {
        let dir = krb5_testkit::scratch_dir("persist-unopenable");
        let (db, stash) = (dir.join("principal"), dir.join("stash"));
        let master =
            ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[7; 32]).unwrap();
        match check_openable(&db) {
            Err(PersistError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            other => panic!("{other:?}"),
        }
        std::fs::write(&db, "not a database\n").unwrap();
        let refused = format!(
            "Cannot open DB2 database '{}': Invalid argument",
            db.display()
        );
        assert_eq!(check_openable(&db).unwrap_err().to_string(), refused);
        assert_eq!(load_store(&db, &stash).unwrap_err().to_string(), refused);
        assert_eq!(
            load_store_with_master(&db, &master)
                .unwrap_err()
                .to_string(),
            refused
        );
        std::fs::write(&db, "").unwrap();
        check_openable(&db).unwrap();
        make_lock_files(&db).unwrap();
        assert_eq!(load_store(&db, &stash).unwrap_err().to_string(), refused);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn master_key_type_is_honored_and_defaults_to_mits() {
        // MIT's DEFAULT_KDC_ENCTYPE (master_key_type unset) is aes256-cts-hmac-sha1-96
        // (settled live: `getprinc K/M` of a realm created with no master_key_type).
        assert_eq!(master_etype(None), Ok(default_master_etype()));
        assert_eq!(master_etype(None), Ok(EncryptionType::Aes256CtsHmacSha196));
        // A configured master_key_type is honored on the persist path and by krb5-kdb.
        assert_eq!(
            master_etype(Some("aes256-cts-hmac-sha1-96")),
            Ok(EncryptionType::Aes256CtsHmacSha196)
        );
        assert_eq!(
            master_etype(Some("aes256-cts-hmac-sha384-192")),
            Ok(EncryptionType::Aes256CtsHmacSha384192)
        );
        // A name that is no enctype makes no master key, as in MIT.
        assert!(master_etype(Some("no-such-enctype")).is_err());
    }
}
