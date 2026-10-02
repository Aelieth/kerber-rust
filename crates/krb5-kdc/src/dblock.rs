//! The database's lock between processes: the two lock files MIT's db2 module keeps beside the
//! database, and `krb5_lock_file`'s whole-file locks on them.
//!
//! `principal.ok` is the principal lock, and its modification time is the database's age;
//! `principal.kadm5.lock` is the policy lock. Only a database's creation (`krb5-kdb create`, a
//! full `load` into an empty directory) makes them, and a database without them does not open.
//! A read holds both shared and a change both exclusive, `principal.ok` first. The locks are
//! open-file-description locks, so they belong to the descriptors a [`DbLock`] opened once, not
//! to a thread or the process: the threads of one process share a [`DbLock`], and the process's
//! own lock (kadmind's store lock) keeps two of its threads from changing the database at once,
//! as MIT's db2 mutex does.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, Flock, FlockArg, fcntl};
use nix::libc;
use nix::sys::stat::{UtimensatFlags, utimensat};
use nix::sys::time::TimeSpec;

/// The principal lock's suffix, `principal.ok`.
pub const SUFFIX_LOCK: &str = ".ok";
/// The policy lock's suffix, `principal.kadm5.lock`.
pub const SUFFIX_POLICY_LOCK: &str = ".kadm5.lock";

/// How a database lock is held, as MIT's `KRB5_DB_LOCKMODE_*` order them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DbLockMode {
    /// Any number of readers.
    Shared,
    /// One writer.
    Exclusive,
    /// One writer, with `principal.kadm5.lock` removed while it is held, so that the database
    /// does not open until it is let go: `krb5-kdb load -update`.
    Permanent,
}

/// Why the database could not be locked.
#[derive(Debug)]
pub enum DbLockError {
    /// `KRB5_KDB_CANTLOCK_DB`: the lock file is open read-only and the lock is exclusive, or the
    /// policy lock file is missing.
    CantLock,
    /// `OSA_ADB_NOLOCKFILE`: `principal.kadm5.lock` does not open.
    NoLockFile,
    /// `KRB5_KDB_NOTLOCKED`: an unlock with no lock held.
    NotLocked,
    /// The system's error: `principal.ok` does not open, a lock call or a lock file's creation
    /// failed.
    Io(io::Error),
}

impl fmt::Display for DbLockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CantLock => f.write_str("Insufficient access to lock database"),
            Self::NoLockFile => f.write_str("KADM5 administration database lock file missing"),
            Self::NotLocked => f.write_str("Database not locked"),
            Self::Io(e) => f.write_str(&strerror(e)),
        }
    }
}

impl std::error::Error for DbLockError {}

impl DbLockError {
    /// The [`io::ErrorKind`] the error stands for: `PermissionDenied` for a lock that may not be
    /// taken, `NotFound` for a missing lock file.
    #[must_use]
    pub fn kind(&self) -> io::ErrorKind {
        match self {
            Self::CantLock => io::ErrorKind::PermissionDenied,
            Self::NoLockFile => io::ErrorKind::NotFound,
            Self::NotLocked => io::ErrorKind::Other,
            Self::Io(e) => e.kind(),
        }
    }
}

/// The system's text for `e`, without Rust's `(os error N)`.
fn strerror(e: &io::Error) -> String {
    let text = e.to_string();
    match e.raw_os_error() {
        Some(code) => text
            .strip_suffix(&format!(" (os error {code})"))
            .map_or_else(|| text.clone(), str::to_owned),
        None => text,
    }
}

/// `path` with `suffix` appended to its last component.
#[must_use]
pub fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// What one [`lock_file`] call asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum FileLock {
    Shared,
    Exclusive,
    Unlock,
}

/// MIT `ofdlock` (`lib/krb5/os/lock_file.c:90-103`): an OFD lock, else on `EINVAL` (a kernel without OFD locks) a classic POSIX lock.
fn ofdlock(file: &File, arg: &libc::flock) -> Result<(), Errno> {
    match fcntl(file, FcntlArg::F_OFD_SETLKW(arg)) {
        Ok(_) => Ok(()),
        Err(Errno::EINVAL) => fcntl(file, FcntlArg::F_SETLKW(arg)).map(drop),
        Err(e) => Err(e),
    }
}

/// Lock, or unlock, the whole of `file`, waiting for a conflicting lock to go: a POSIX lock, and
/// `flock` only where the kernel refuses that with `EINVAL`.
/// MIT `krb5_lock_file` (`lib/krb5/os/lock_file.c:117-162`): whole file, `F_RDLCK` / `F_WRLCK` / `F_UNLCK`, blocking; `EACCES` / `EAGAIN` are `EAGAIN`.
/// MIT `krb5_lock_file` (`lib/krb5/os/lock_file.c:154-170`): only `EINVAL` falls back to `flock`, and the `EINVAL` is still returned when `flock` succeeds.
fn lock_file(file: &File, how: FileLock, flocked: &mut Option<Flock<File>>) -> Result<(), Errno> {
    let l_type = match how {
        FileLock::Shared => libc::F_RDLCK,
        FileLock::Exclusive => libc::F_WRLCK,
        FileLock::Unlock => libc::F_UNLCK,
    };
    let arg = libc::flock {
        l_type: libc::c_short::try_from(l_type).map_err(|_| Errno::EINVAL)?,
        l_whence: libc::c_short::try_from(libc::SEEK_SET).map_err(|_| Errno::EINVAL)?,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    let retval = match ofdlock(file, &arg) {
        Ok(()) => return Ok(()),
        Err(Errno::EACCES | Errno::EAGAIN) => return Err(Errno::EAGAIN),
        Err(Errno::EINVAL) => Errno::EINVAL,
        Err(e) => return Err(e),
    };
    match flock_fallback(file, how, flocked) {
        Ok(()) => Err(retval),
        Err(e) => Err(e),
    }
}

/// `flock(2)` on `file`'s open file description, kept in `flocked` while it is held.
fn flock_fallback(
    file: &File,
    how: FileLock,
    flocked: &mut Option<Flock<File>>,
) -> Result<(), Errno> {
    let arg = match how {
        FileLock::Shared => FlockArg::LockShared,
        FileLock::Exclusive => FlockArg::LockExclusive,
        FileLock::Unlock => {
            return match flocked.take() {
                Some(held) => held.unlock().map(drop).map_err(|(_, e)| e),
                None => Ok(()),
            };
        }
    };
    if let Some(held) = flocked.as_ref() {
        return held.relock(arg);
    }
    let dup = file.try_clone().map_err(|e| errno_of(&e))?;
    let held = Flock::lock(dup, arg).map_err(|(_, e)| e)?;
    *flocked = Some(held);
    Ok(())
}

fn errno_of(e: &io::Error) -> Errno {
    e.raw_os_error().map_or(Errno::EIO, Errno::from_raw)
}

/// An exclusive lock on the whole of a file of the caller's own (`krb5-kdb dump`'s
/// `.dump_ok`), let go when dropped.
#[derive(Debug)]
pub struct FileLockGuard<'a> {
    file: &'a File,
    flocked: Option<Flock<File>>,
}

/// Lock the whole of `file` exclusively, waiting for any other holder, as `krb5_lock_file`
/// does; the lock is let go when the guard is dropped.
/// MIT `prep_ok_file` (`kadmin/dbutil/dump.c:191-195`): the dump's `.dump_ok` file is locked exclusively while the dump is written.
///
/// # Errors
///
/// The system's error of the lock call.
pub fn lock_file_exclusive(file: &File) -> io::Result<FileLockGuard<'_>> {
    let mut flocked = None;
    lock_file(file, FileLock::Exclusive, &mut flocked)?;
    Ok(FileLockGuard { file, flocked })
}

impl Drop for FileLockGuard<'_> {
    /// MIT `update_ok_file` (`kadmin/dbutil/dump.c:214-219`): the `.dump_ok` lock is let go once its byte is written.
    fn drop(&mut self) {
        let _ = lock_file(self.file, FileLock::Unlock, &mut self.flocked);
    }
}

/// Open a lock file read-write, else read-only.
/// MIT `ctx_init` (`plugins/kdb/db2/kdb_db2.c:492-501`): the lock file is opened `O_RDWR` so that write locking can work, else `O_RDONLY`.
fn open_lock_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .or_else(|_| File::open(path))
}

/// Which lock file a create makes, for its SELinux context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LockFileKind {
    Principal,
    Policy,
}

/// Create the lock file at `path`, 0600, labeled as a new file at that path is
/// ([`krb5_protocol::create_labeled`]): `principal.ok` `O_CREAT | O_RDWR | O_TRUNC` (an existing
/// one is kept and emptied), `principal.kadm5.lock` `O_CREAT | O_EXCL`.
/// MIT `ctx_create_db` (`plugins/kdb/db2/kdb_db2.c:697-702`): `principal.ok` is opened `O_CREAT | O_RDWR | O_TRUNC`, mode 0600.
/// MIT `osa_adb_create_db` (`plugins/kdb/db2/adb_openclose.c:42-46`): the policy lock file is created `O_RDWR | O_CREAT | O_EXCL`, mode 0600.
fn create_lock_file(path: &Path, kind: LockFileKind) -> io::Result<File> {
    krb5_protocol::create_labeled(path, || {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).mode(0o600);
        match kind {
            LockFileKind::Principal => opts.create(true).truncate(true),
            LockFileKind::Policy => opts.create_new(true),
        };
        opts.open(path)
    })
}

/// The database's age: `principal.ok`'s modification time, seconds and nanoseconds.
pub type DbAge = (i64, i64);

/// A database's two lock files, opened once, and the locks this process holds on them.
#[derive(Debug)]
pub struct DbLock {
    ok_name: PathBuf,
    pol_name: PathBuf,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    /// `db_lf_file`.
    ok: File,
    ok_flock: Option<Flock<File>>,
    /// `db_locks_held`.
    held: u32,
    /// `db_lock_mode`.
    mode: Option<FileLock>,
    /// The policy lock file; `None` while a permanent lock has removed it, or when it could not
    /// be made again.
    pol: Option<File>,
    pol_flock: Option<Flock<File>>,
    /// `lockcnt`.
    pol_cnt: u32,
    /// `lockmode`.
    pol_mode: Option<DbLockMode>,
}

/// Why the policy lock failed, before `ctx_lock` maps it.
enum PolicyLockError {
    NoExclPerm,
    CantLock,
    NoLockFile,
    NotLocked,
    Io(io::Error),
}

impl PolicyLockError {
    /// MIT `ctx_lock` (`plugins/kdb/db2/kdb_db2.c:469-476`): a policy lock that may not be taken, or whose file is missing, is `KRB5_KDB_CANTLOCK_DB`.
    fn into_db(self) -> DbLockError {
        match self {
            Self::NoExclPerm | Self::CantLock | Self::NoLockFile => DbLockError::CantLock,
            Self::NotLocked => DbLockError::NotLocked,
            Self::Io(e) => DbLockError::Io(e),
        }
    }
}

impl DbLock {
    /// Open the lock files of the database at `db`.
    /// MIT `ctx_init` (`plugins/kdb/db2/kdb_db2.c:488-501`): `principal.ok` must open; no open creates it.
    /// MIT `osa_adb_init_db` (`plugins/kdb/db2/adb_openclose.c:151-165`): the policy lock file is opened "r+", else "r", else `OSA_ADB_NOLOCKFILE`.
    ///
    /// # Errors
    ///
    /// [`DbLockError::Io`] when `principal.ok` opens neither read-write nor read-only (`NotFound`
    /// when it is missing); [`DbLockError::NoLockFile`] when `principal.kadm5.lock` does not open.
    pub fn open(db: &Path) -> Result<Self, DbLockError> {
        let ok_name = suffixed(db, SUFFIX_LOCK);
        let ok = open_lock_file(&ok_name).map_err(DbLockError::Io)?;
        let pol_name = suffixed(db, SUFFIX_POLICY_LOCK);
        let pol = open_lock_file(&pol_name).map_err(|_| DbLockError::NoLockFile)?;
        Ok(Self::from_files(ok_name, ok, pol_name, Some(pol)))
    }

    /// Make the database's `principal.ok` (keeping an existing one, emptied) and lock it
    /// exclusively, before the database file itself is created. The policy lock file comes next,
    /// with [`Self::create_policy_lock`], once the database file was created.
    /// MIT `ctx_create_db` (`plugins/kdb/db2/kdb_db2.c:697-708`): `principal.ok` is created and exclusively locked first.
    ///
    /// # Errors
    ///
    /// [`DbLockError::Io`] when `principal.ok` cannot be created or opened (the error of its
    /// directory), or locked.
    pub fn create(db: &Path) -> Result<Self, DbLockError> {
        let ok_name = suffixed(db, SUFFIX_LOCK);
        let ok = create_lock_file(&ok_name, LockFileKind::Principal).map_err(DbLockError::Io)?;
        let me = Self::from_files(ok_name, ok, suffixed(db, SUFFIX_POLICY_LOCK), None);
        {
            let mut st = me.state();
            let st = &mut *st;
            lock_file(&st.ok, FileLock::Exclusive, &mut st.ok_flock)
                .map_err(|e| DbLockError::Io(e.into()))?;
            st.mode = Some(FileLock::Exclusive);
            st.held = 1;
        }
        Ok(me)
    }

    /// Make the policy lock file of a database [`Self::create`] made the principal lock of, and
    /// take it exclusively, so that the new database is wholly locked.
    /// MIT `ctx_create_db` (`plugins/kdb/db2/kdb_db2.c:722-732`): the policy lock file is created once the database file exists, then locked exclusively.
    ///
    /// # Errors
    ///
    /// [`DbLockError::Io`] when the file cannot be created (`AlreadyExists` for a policy lock file
    /// already there); [`DbLockError::CantLock`] when it cannot be locked.
    pub fn create_policy_lock(&self) -> Result<(), DbLockError> {
        let file =
            create_lock_file(&self.pol_name, LockFileKind::Policy).map_err(DbLockError::Io)?;
        drop(file);
        let reopened = open_lock_file(&self.pol_name).map_err(|_| DbLockError::NoLockFile)?;
        let mut st = self.state();
        st.pol = Some(reopened);
        st.pol_flock = None;
        self.get_policy_lock(&mut st, DbLockMode::Exclusive)
            .map_err(PolicyLockError::into_db)
    }

    fn from_files(ok_name: PathBuf, ok: File, pol_name: PathBuf, pol: Option<File>) -> Self {
        Self {
            ok_name,
            pol_name,
            state: Mutex::new(State {
                ok,
                ok_flock: None,
                held: 0,
                mode: None,
                pol,
                pol_flock: None,
                pol_cnt: 0,
                pol_mode: None,
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `principal.ok`'s path.
    #[must_use]
    pub fn principal_lock_path(&self) -> &Path {
        &self.ok_name
    }

    /// `principal.kadm5.lock`'s path.
    #[must_use]
    pub fn policy_lock_path(&self) -> &Path {
        &self.pol_name
    }

    /// Take the database lock in `mode`, waiting for any conflicting holder: `principal.ok`, then
    /// the policy lock. A lock this process already holds at least as strongly is counted, not
    /// taken again, and a shared one asked for exclusively is upgraded.
    /// MIT `ctx_lock` (`plugins/kdb/db2/kdb_db2.c:431-447`): `principal.ok` is locked (or upgraded), an exclusive lock on a read-only descriptor and a refused lock are `KRB5_KDB_CANTLOCK_DB`.
    /// MIT `ctx_lock` (`plugins/kdb/db2/kdb_db2.c:467-477`): the hold is counted, then the policy lock is taken in the same mode; when that fails, `principal.ok` is let go.
    ///
    /// # Errors
    ///
    /// [`DbLockError::CantLock`] when a lock file is open read-only and the lock is exclusive,
    /// or `principal.kadm5.lock` is gone; [`DbLockError::Io`] for any other lock or unlink
    /// failure.
    pub fn lock(&self, mode: DbLockMode) -> Result<(), DbLockError> {
        let mut st = self.state();
        let kmode = if mode == DbLockMode::Shared {
            FileLock::Shared
        } else {
            FileLock::Exclusive
        };
        if st.held == 0 || st.mode < Some(kmode) {
            let st = &mut *st;
            match lock_file(&st.ok, kmode, &mut st.ok_flock) {
                Ok(()) => {}
                Err(Errno::EBADF) if kmode == FileLock::Exclusive => {
                    return Err(DbLockError::CantLock);
                }
                Err(Errno::EACCES | Errno::EAGAIN) => return Err(DbLockError::CantLock),
                Err(e) => return Err(DbLockError::Io(e.into())),
            }
            st.mode = Some(kmode);
        }
        st.held += 1;
        if let Err(e) = self.get_policy_lock(&mut st, mode) {
            drop(st);
            let _ = self.unlock();
            return Err(e.into_db());
        }
        Ok(())
    }

    /// The policy lock in `mode`: counted when held at least as strongly, else taken; then the
    /// file must still exist, and a permanent lock removes it and closes it.
    /// MIT `osa_adb_get_lock` (`plugins/kdb/db2/adb_openclose.c:220-247`): a held lock is counted; a read-only descriptor refuses an exclusive lock.
    /// MIT `osa_adb_get_lock` (`plugins/kdb/db2/adb_openclose.c:249-261`): a lock file that no longer exists is `OSA_ADB_NOLOCKFILE`, since a permanent lock removed it.
    /// MIT `osa_adb_get_lock` (`plugins/kdb/db2/adb_openclose.c:265-283`): the permanent lock unlinks the file, then closes it, which lets its lock go.
    fn get_policy_lock(&self, st: &mut State, mode: DbLockMode) -> Result<(), PolicyLockError> {
        if st.pol_mode.is_some_and(|held| held >= mode) {
            st.pol_cnt += 1;
            return Ok(());
        }
        let kmode = if mode == DbLockMode::Shared {
            FileLock::Shared
        } else {
            FileLock::Exclusive
        };
        let Some(pol) = st.pol.as_ref() else {
            return Err(PolicyLockError::NoLockFile);
        };
        match lock_file(pol, kmode, &mut st.pol_flock) {
            Ok(()) => {}
            Err(Errno::EBADF) if mode == DbLockMode::Exclusive => {
                return Err(PolicyLockError::NoExclPerm);
            }
            Err(Errno::EACCES | Errno::EAGAIN) => return Err(PolicyLockError::CantLock),
            Err(e) => return Err(PolicyLockError::Io(e.into())),
        }
        if nix::unistd::access(&self.pol_name, nix::unistd::AccessFlags::F_OK).is_err() {
            let _ = lock_file(pol, FileLock::Unlock, &mut st.pol_flock);
            return Err(PolicyLockError::NoLockFile);
        }
        if mode == DbLockMode::Permanent {
            if let Err(e) = std::fs::remove_file(&self.pol_name) {
                let _ = lock_file(pol, FileLock::Unlock, &mut st.pol_flock);
                return Err(PolicyLockError::Io(e));
            }
            st.pol_flock = None;
            st.pol = None;
        }
        st.pol_mode = Some(mode);
        st.pol_cnt += 1;
        Ok(())
    }

    /// Give back one count of the policy lock; the last lets it go, and a permanent lock makes
    /// the file again.
    /// MIT `osa_adb_release_lock` (`plugins/kdb/db2/adb_openclose.c:295-315`): the last release unlocks, or after a permanent lock creates the file `O_RDWR | O_CREAT | O_EXCL`, 0600.
    fn release_policy_lock(&self, st: &mut State) -> Result<(), PolicyLockError> {
        if st.pol_cnt == 0 {
            return Err(PolicyLockError::NotLocked);
        }
        st.pol_cnt -= 1;
        if st.pol_cnt == 0 {
            if st.pol_mode == Some(DbLockMode::Permanent) {
                let file = create_lock_file(&self.pol_name, LockFileKind::Policy)
                    .map_err(|_| PolicyLockError::NoLockFile)?;
                st.pol = Some(file);
            } else if let Some(pol) = st.pol.as_ref() {
                lock_file(pol, FileLock::Unlock, &mut st.pol_flock)
                    .map_err(|e| PolicyLockError::Io(e.into()))?;
            }
            st.pol_mode = None;
        }
        Ok(())
    }

    /// Give back one count of the lock: the policy lock, then `principal.ok`, which the last
    /// count lets go.
    /// MIT `ctx_unlock` (`plugins/kdb/db2/kdb_db2.c:402-422`): the policy lock is released, then the hold count drops and the last one unlocks `principal.ok`.
    ///
    /// # Errors
    ///
    /// [`DbLockError::NotLocked`] when no lock is held; [`DbLockError::Io`] when an unlock
    /// fails; [`DbLockError::CantLock`] when a permanent lock's policy lock file cannot be made
    /// again.
    pub fn unlock(&self) -> Result<(), DbLockError> {
        let mut st = self.state();
        let pol = self.release_policy_lock(&mut st);
        if st.held == 0 {
            return Err(DbLockError::NotLocked);
        }
        st.held -= 1;
        if st.held == 0 {
            st.mode = None;
            let st = &mut *st;
            lock_file(&st.ok, FileLock::Unlock, &mut st.ok_flock)
                .map_err(|e| DbLockError::Io(e.into()))?;
        }
        match pol {
            Ok(()) | Err(PolicyLockError::NotLocked) => Ok(()),
            Err(e) => Err(e.into_db()),
        }
    }

    /// Take the lock in `mode` until the returned hold is dropped.
    ///
    /// # Errors
    ///
    /// As [`Self::lock`].
    pub fn hold(self: &Arc<Self>, mode: DbLockMode) -> Result<DbLockHold, DbLockError> {
        self.lock(mode)?;
        Ok(DbLockHold(Arc::clone(self)))
    }

    /// Whether this process holds the lock exclusively.
    #[must_use]
    pub fn held_exclusive(&self) -> bool {
        let st = self.state();
        st.held > 0 && st.mode == Some(FileLock::Exclusive)
    }

    /// The database's age: `principal.ok`'s modification time, through the descriptor opened
    /// with the database; `None` when it cannot be read.
    /// MIT `krb5_db2_get_age` (`plugins/kdb/db2/kdb_db2.c:573-579`): the age is `principal.ok`'s `st_mtime`, read with `fstat`.
    #[must_use]
    pub fn age(&self) -> Option<DbAge> {
        let st = self.state();
        st.ok.metadata().ok().map(|m| (m.mtime(), m.mtime_nsec()))
    }

    /// Move the database's age strictly forward: `principal.ok`'s times become now, or one second
    /// past the old age when that is not before now. Call it holding the lock exclusively, once
    /// the change is written. A failure is ignored, as MIT ignores it.
    /// MIT `ctx_update_age` (`plugins/kdb/db2/kdb_db2.c:590-598`): `utime` to the old `st_mtime` + 1 when it is not in the past, else to now.
    pub fn update_age(&self) {
        let old = {
            let st = self.state();
            match st.ok.metadata() {
                Ok(m) => m.mtime(),
                Err(_) => return,
            }
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .unwrap_or(0);
        let times = if old >= now {
            let next = TimeSpec::new(old.saturating_add(1), 0);
            (next, next)
        } else {
            (TimeSpec::UTIME_NOW, TimeSpec::UTIME_NOW)
        };
        let _ = utimensat(
            nix::fcntl::AT_FDCWD,
            &self.ok_name,
            &times.0,
            &times.1,
            UtimensatFlags::FollowSymlink,
        );
    }
}

/// A database lock held until it is dropped.
#[derive(Debug)]
pub struct DbLockHold(Arc<DbLock>);

impl DbLockHold {
    /// The lock this holds.
    #[must_use]
    pub fn lock(&self) -> &Arc<DbLock> {
        &self.0
    }
}

impl Drop for DbLockHold {
    fn drop(&mut self) {
        if let Err(e) = self.0.unlock() {
            tracing::error!(
                event = krb5_log::events::ADMIN,
                component = "krb5-kdc",
                outcome = "error",
                error = %e,
                detail = "database unlock",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        krb5_testkit::scratch_dir(&format!("krb5-dblock-{tag}"))
    }

    /// A database directory with both lock files, as `krb5-kdb create` leaves them.
    fn created(tag: &str) -> PathBuf {
        let db = scratch(tag).join("principal");
        let lock = DbLock::create(&db).unwrap();
        std::fs::write(&db, b"").unwrap();
        lock.create_policy_lock().unwrap();
        lock.unlock().unwrap();
        db
    }

    /// An F_OFD_GETLK probe through a separate open file description: the lock another holder
    /// keeps on `path`, or `F_UNLCK`.
    fn probe(path: &Path, want: libc::c_int) -> libc::c_int {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let mut arg = libc::flock {
            l_type: libc::c_short::try_from(want).unwrap(),
            l_whence: 0,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        fcntl(&f, FcntlArg::F_OFD_GETLK(&mut arg)).unwrap();
        libc::c_int::from(arg.l_type)
    }

    #[test]
    fn create_makes_both_lock_files_0600_and_open_needs_both() {
        let db = created("create");
        for p in [
            suffixed(&db, SUFFIX_LOCK),
            suffixed(&db, SUFFIX_POLICY_LOCK),
        ] {
            let m = std::fs::metadata(&p).unwrap();
            assert_eq!(m.len(), 0);
            assert_eq!(m.mode() & 0o777, 0o600, "{}", p.display());
        }
        assert!(DbLock::open(&db).is_ok());
        std::fs::remove_file(suffixed(&db, SUFFIX_POLICY_LOCK)).unwrap();
        assert!(matches!(DbLock::open(&db), Err(DbLockError::NoLockFile)));
        assert_eq!(
            DbLockError::NoLockFile.to_string(),
            "KADM5 administration database lock file missing"
        );
        std::fs::remove_file(suffixed(&db, SUFFIX_LOCK)).unwrap();
        match DbLock::open(&db) {
            Err(e @ DbLockError::Io(_)) => {
                assert_eq!(e.kind(), io::ErrorKind::NotFound);
                assert_eq!(e.to_string(), "No such file or directory");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_stale_policy_lock_file_fails_the_create() {
        let db = scratch("stale").join("principal");
        std::fs::write(suffixed(&db, SUFFIX_POLICY_LOCK), b"").unwrap();
        let lock = DbLock::create(&db).unwrap();
        match lock.create_policy_lock() {
            Err(DbLockError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::AlreadyExists),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn locks_take_principal_ok_then_the_policy_lock_in_the_asked_mode() {
        let db = created("order");
        let ok = suffixed(&db, SUFFIX_LOCK);
        let pol = suffixed(&db, SUFFIX_POLICY_LOCK);
        let lock = Arc::new(DbLock::open(&db).unwrap());
        {
            let _held = lock.hold(DbLockMode::Shared).unwrap();
            assert_eq!(probe(&ok, libc::F_WRLCK), libc::F_RDLCK);
            assert_eq!(probe(&pol, libc::F_WRLCK), libc::F_RDLCK);
            assert_eq!(probe(&ok, libc::F_RDLCK), libc::F_UNLCK);
        }
        assert_eq!(probe(&ok, libc::F_WRLCK), libc::F_UNLCK);
        {
            let _held = lock.hold(DbLockMode::Exclusive).unwrap();
            assert!(lock.held_exclusive());
            assert_eq!(probe(&ok, libc::F_RDLCK), libc::F_WRLCK);
            assert_eq!(probe(&pol, libc::F_RDLCK), libc::F_WRLCK);
            // A nested hold is counted: the outer one still holds after it is dropped.
            drop(lock.hold(DbLockMode::Shared).unwrap());
            assert_eq!(probe(&ok, libc::F_RDLCK), libc::F_WRLCK);
        }
        assert!(!lock.held_exclusive());
        assert_eq!(probe(&ok, libc::F_WRLCK), libc::F_UNLCK);
        assert_eq!(probe(&pol, libc::F_WRLCK), libc::F_UNLCK);
        assert!(matches!(lock.unlock(), Err(DbLockError::NotLocked)));
    }

    #[test]
    fn an_exclusive_lock_on_a_read_only_lock_file_is_cantlock() {
        let db = created("ro");
        let ok = suffixed(&db, SUFFIX_LOCK);
        let ro = File::open(&ok).unwrap();
        let lock = DbLock::from_files(ok, ro, suffixed(&db, SUFFIX_POLICY_LOCK), None);
        assert!(matches!(
            lock.lock(DbLockMode::Exclusive),
            Err(DbLockError::CantLock)
        ));
        assert_eq!(
            DbLockError::CantLock.to_string(),
            "Insufficient access to lock database"
        );
    }

    #[test]
    fn a_permanent_lock_removes_the_policy_lock_file_until_it_is_let_go() {
        let db = created("perm");
        let pol = suffixed(&db, SUFFIX_POLICY_LOCK);
        let lock = Arc::new(DbLock::open(&db).unwrap());
        let other = DbLock::open(&db).unwrap();
        let before = std::fs::metadata(&pol).unwrap().ino();
        lock.lock(DbLockMode::Permanent).unwrap();
        assert!(!pol.exists());
        assert!(matches!(DbLock::open(&db), Err(DbLockError::NoLockFile)));
        // A nested change under the permanent lock is counted, as `load -update`'s puts are.
        lock.lock(DbLockMode::Exclusive).unwrap();
        lock.unlock().unwrap();
        assert!(!pol.exists());
        lock.unlock().unwrap();
        let after = std::fs::metadata(&pol).unwrap();
        assert_ne!(
            after.ino(),
            before,
            "a permanent lock makes a new policy lock file"
        );
        assert_eq!(after.mode() & 0o777, 0o600);
        // A handle opened before keeps the old file: its lock succeeds on the old inode, but
        // the access check sees the new file, so it works again (MIT's daemons after a
        // `load -update`).
        other.lock(DbLockMode::Shared).unwrap();
        other.unlock().unwrap();
    }

    #[test]
    fn a_handle_whose_policy_lock_file_went_away_is_cantlock() {
        let db = created("gone");
        let lock = DbLock::open(&db).unwrap();
        std::fs::remove_file(suffixed(&db, SUFFIX_POLICY_LOCK)).unwrap();
        assert!(matches!(
            lock.lock(DbLockMode::Shared),
            Err(DbLockError::CantLock)
        ));
        // `principal.ok` was let go again.
        assert_eq!(
            probe(&suffixed(&db, SUFFIX_LOCK), libc::F_WRLCK),
            libc::F_UNLCK
        );
    }

    #[test]
    fn the_age_moves_strictly_forward() {
        let db = created("age");
        let lock = DbLock::open(&db).unwrap();
        let mut last = lock.age().unwrap();
        for _ in 0..4 {
            lock.lock(DbLockMode::Exclusive).unwrap();
            lock.update_age();
            lock.unlock().unwrap();
            let now = lock.age().unwrap();
            assert!(now.0 > last.0, "{now:?} after {last:?}");
            last = now;
        }
    }

    #[test]
    fn a_writer_in_another_process_waits_for_a_reader() {
        // Two open file descriptions stand for two processes: OFD locks conflict between them.
        let db = created("wait");
        let reader = Arc::new(DbLock::open(&db).unwrap());
        let writer = Arc::new(DbLock::open(&db).unwrap());
        let held = reader.hold(DbLockMode::Shared).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let w = Arc::clone(&writer);
        let t = std::thread::spawn(move || {
            let _held = w.hold(DbLockMode::Exclusive).unwrap();
            tx.send(()).unwrap();
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(300))
                .is_err()
        );
        drop(held);
        rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        t.join().unwrap();
    }
}
