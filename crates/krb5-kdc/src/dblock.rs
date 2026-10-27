//! The database's two lock files.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) use krb5_protocol::FileLock;
use krb5_protocol::{lock_file, lock_file_how};
use nix::errno::Errno;
use nix::fcntl::Flock;
use nix::libc;
use nix::sys::stat::futimens;
use nix::sys::time::TimeSpec;

pub const SUFFIX_LOCK: &str = ".ok";
pub const SUFFIX_POLICY_LOCK: &str = ".kadm5.lock";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DbLockMode {
    Shared,
    Exclusive,
    /// A permanent lock removes `principal.kadm5.lock` until released.
    Permanent,
}

#[derive(Debug)]
pub enum DbLockError {
    CantLock,
    NoLockFile,
    NotLocked,
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

fn strerror(e: &io::Error) -> String {
    let text = e.to_string();
    match e.raw_os_error() {
        Some(code) => text
            .strip_suffix(&format!(" (os error {code})"))
            .map_or_else(|| text.clone(), str::to_owned),
        None => text,
    }
}

#[must_use]
pub fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

#[derive(Debug)]
pub struct FileLockGuard<'a> {
    file: &'a File,
    flocked: Option<Flock<File>>,
}

// MIT: `prep_ok_file` (kadmin/dbutil/dump.c:191-195)
pub fn lock_file_exclusive(file: &File) -> io::Result<FileLockGuard<'_>> {
    let mut flocked = None;
    lock_file(file, FileLock::Exclusive, &mut flocked)?;
    Ok(FileLockGuard { file, flocked })
}

#[derive(Debug)]
pub struct HeldFileLock {
    flocked: Option<Flock<File>>,
}

// MIT: `open_database` (kprop/kprop.c:356-364)
pub fn lock_file_shared_nowait(file: &File) -> io::Result<HeldFileLock> {
    let mut flocked = None;
    lock_file_how(file, FileLock::Shared, &mut flocked, false)?;
    Ok(HeldFileLock { flocked })
}

impl HeldFileLock {
    // MIT: `close_database` (kprop/kprop.c:388-398)
    pub fn unlock(mut self, file: &File) -> io::Result<()> {
        lock_file(file, FileLock::Unlock, &mut self.flocked).map_err(io::Error::from)
    }
}

// MIT: `lock_ulog` (lib/kdb/kdb_log.c:288-296)
/// `flocked` matches at lock and unlock; threads share a lock: callers count holds.
pub(crate) fn set_file_lock(
    file: &File,
    how: FileLock,
    flocked: &mut Option<Flock<File>>,
) -> io::Result<()> {
    lock_file(file, how, flocked).map_err(io::Error::from)
}

impl Drop for FileLockGuard<'_> {
    // MIT: `update_ok_file` (kadmin/dbutil/dump.c:214-219)
    fn drop(&mut self) {
        let _ = lock_file(self.file, FileLock::Unlock, &mut self.flocked);
    }
}

fn refused_link(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ELOOP)
}

fn named_if_link(path: &Path, e: io::Error) -> io::Error {
    if refused_link(&e) {
        io::Error::new(e.kind(), format!("{}: {}", path.display(), strerror(&e)))
    } else {
        e
    }
}

/// Unlike MIT, never opened through a symlink.
// MIT: `ctx_init` (plugins/kdb/db2/kdb_db2.c:492-501)
fn open_lock_file(path: &Path) -> io::Result<File> {
    let open = |write: bool| {
        OpenOptions::new()
            .read(true)
            .write(write)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
    };
    open(true).or_else(|_| open(false))
}

fn open_policy_lock_file(path: &Path) -> Result<File, DbLockError> {
    open_lock_file(path).map_err(|e| {
        if refused_link(&e) {
            DbLockError::Io(named_if_link(path, e))
        } else {
            DbLockError::NoLockFile
        }
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LockFileKind {
    Principal,
    Policy,
}

// MIT: `ctx_create_db` (plugins/kdb/db2/kdb_db2.c:697-702)
// MIT: `osa_adb_create_db` (plugins/kdb/db2/adb_openclose.c:42-46)
fn create_lock_file(path: &Path, kind: LockFileKind) -> io::Result<File> {
    krb5_protocol::create_labeled(path, || {
        let mut opts = OpenOptions::new();
        opts.read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW);
        match kind {
            LockFileKind::Principal => opts.create(true).truncate(true),
            LockFileKind::Policy => opts.create_new(true),
        };
        opts.open(path)
    })
}

pub type DbAge = (i64, i64);

#[derive(Debug)]
pub struct DbLock {
    ok_name: PathBuf,
    pol_name: PathBuf,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    ok: File,
    ok_flock: Option<Flock<File>>,
    held: u32,
    mode: Option<FileLock>,
    pol: Option<File>,
    pol_flock: Option<Flock<File>>,
    pol_cnt: u32,
    pol_mode: Option<DbLockMode>,
}

enum PolicyLockError {
    NoExclPerm,
    CantLock,
    NoLockFile,
    NotLocked,
    WouldBlock,
    Io(io::Error),
}

impl PolicyLockError {
    // MIT: `ctx_lock` (plugins/kdb/db2/kdb_db2.c:469-476)
    fn into_db(self) -> DbLockError {
        match self {
            Self::NoExclPerm | Self::CantLock | Self::NoLockFile | Self::WouldBlock => {
                DbLockError::CantLock
            }
            Self::NotLocked => DbLockError::NotLocked,
            Self::Io(e) => DbLockError::Io(e),
        }
    }
}

impl DbLock {
    // MIT: `osa_adb_init_db` (plugins/kdb/db2/adb_openclose.c:151-165)
    // MIT: `ctx_init` (plugins/kdb/db2/kdb_db2.c:488-501)
    // MIT: `osa_adb_init_db` (plugins/kdb/db2/adb_openclose.c:151-165)
    pub fn open(db: &Path) -> Result<Self, DbLockError> {
        let ok_name = suffixed(db, SUFFIX_LOCK);
        let ok =
            open_lock_file(&ok_name).map_err(|e| DbLockError::Io(named_if_link(&ok_name, e)))?;
        let pol_name = suffixed(db, SUFFIX_POLICY_LOCK);
        let pol = open_policy_lock_file(&pol_name)?;
        Ok(Self::from_files(ok_name, ok, pol_name, Some(pol)))
    }

    // MIT: `ctx_create_db` (plugins/kdb/db2/kdb_db2.c:697-708)
    pub fn create(db: &Path) -> Result<Self, DbLockError> {
        let ok_name = suffixed(db, SUFFIX_LOCK);
        let ok = create_lock_file(&ok_name, LockFileKind::Principal)
            .map_err(|e| DbLockError::Io(named_if_link(&ok_name, e)))?;
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

    // MIT: `ctx_create_db` (plugins/kdb/db2/kdb_db2.c:722-732)
    pub fn create_policy_lock(&self) -> Result<(), DbLockError> {
        let file =
            create_lock_file(&self.pol_name, LockFileKind::Policy).map_err(DbLockError::Io)?;
        drop(file);
        let reopened = open_policy_lock_file(&self.pol_name)?;
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

    #[must_use]
    pub fn principal_lock_path(&self) -> &Path {
        &self.ok_name
    }

    #[must_use]
    pub fn policy_lock_path(&self) -> &Path {
        &self.pol_name
    }

    /// `principal.ok` is locked first; a failed policy lock releases it.
    // MIT: `ctx_lock` (plugins/kdb/db2/kdb_db2.c:431-447)
    // MIT: `ctx_lock` (plugins/kdb/db2/kdb_db2.c:467-477)
    pub fn lock(&self, mode: DbLockMode) -> Result<(), DbLockError> {
        self.lock_reopening(mode, &mut || Ok(()))
    }

    pub fn lock_reopening(
        &self,
        mode: DbLockMode,
        reopen: &mut dyn FnMut() -> io::Result<()>,
    ) -> Result<(), DbLockError> {
        let mut pause = std::time::Duration::from_millis(1);
        while !self.try_lock(mode, reopen)? {
            std::thread::sleep(pause);
            pause = (pause * 2).min(std::time::Duration::from_millis(64));
        }
        Ok(())
    }

    /// An upgrade never waits, so it cannot hold a lookup behind it.
    fn try_lock(
        &self,
        mode: DbLockMode,
        reopen: &mut dyn FnMut() -> io::Result<()>,
    ) -> Result<bool, DbLockError> {
        let mut st = self.state();
        let kmode = if mode == DbLockMode::Shared {
            FileLock::Shared
        } else {
            FileLock::Exclusive
        };
        let upgrade = st.held > 0 && st.mode < Some(kmode);
        if st.held == 0 || upgrade {
            let st = &mut *st;
            match lock_file_how(&st.ok, kmode, &mut st.ok_flock, !upgrade) {
                Ok(()) => {}
                Err(Errno::EAGAIN) if upgrade => return Ok(false),
                Err(Errno::EBADF) if kmode == FileLock::Exclusive => {
                    return Err(DbLockError::CantLock);
                }
                Err(Errno::EACCES | Errno::EAGAIN) => return Err(DbLockError::CantLock),
                Err(e) => return Err(DbLockError::Io(e.into())),
            }
            if let Err(e) = reopen() {
                let back = if upgrade {
                    st.mode.unwrap_or(FileLock::Unlock)
                } else {
                    FileLock::Unlock
                };
                let _ = lock_file(&st.ok, back, &mut st.ok_flock);
                return Err(DbLockError::Io(e));
            }
            st.mode = Some(kmode);
        }
        st.held += 1;
        match self.get_policy_lock(&mut st, mode) {
            Ok(()) => Ok(true),
            Err(PolicyLockError::WouldBlock) => {
                st.held -= 1;
                if st.held == 0 {
                    st.mode = None;
                    let st = &mut *st;
                    let _ = lock_file(&st.ok, FileLock::Unlock, &mut st.ok_flock);
                }
                Ok(false)
            }
            Err(e) => {
                drop(st);
                let _ = self.unlock();
                Err(e.into_db())
            }
        }
    }

    // MIT: `osa_adb_get_lock` (plugins/kdb/db2/adb_openclose.c:220-247)
    // MIT: `osa_adb_get_lock` (plugins/kdb/db2/adb_openclose.c:249-261)
    // MIT: `osa_adb_get_lock` (plugins/kdb/db2/adb_openclose.c:265-283)
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
        let upgrade = st.pol_cnt > 0;
        let Some(pol) = st.pol.as_ref() else {
            return Err(PolicyLockError::NoLockFile);
        };
        match lock_file_how(pol, kmode, &mut st.pol_flock, !upgrade) {
            Ok(()) => {}
            Err(Errno::EAGAIN) if upgrade => return Err(PolicyLockError::WouldBlock),
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

    // MIT: `osa_adb_release_lock` (plugins/kdb/db2/adb_openclose.c:295-315)
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

    // MIT: `ctx_unlock` (plugins/kdb/db2/kdb_db2.c:402-422)
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
            Err(PolicyLockError::NoLockFile) => Err(DbLockError::NoLockFile),
            Err(e) => Err(e.into_db()),
        }
    }

    pub fn hold(self: &Arc<Self>, mode: DbLockMode) -> Result<DbLockHold, DbLockError> {
        self.lock(mode)?;
        Ok(DbLockHold(Arc::clone(self)))
    }

    #[must_use]
    pub fn held_exclusive(&self) -> bool {
        let st = self.state();
        st.held > 0 && st.mode == Some(FileLock::Exclusive)
    }

    // MIT: `krb5_db2_get_age` (plugins/kdb/db2/kdb_db2.c:573-579)
    #[must_use]
    pub fn age(&self) -> Option<DbAge> {
        let st = self.state();
        st.ok.metadata().ok().map(|m| (m.mtime(), m.mtime_nsec()))
    }

    /// The age is `principal.ok`'s mtime, moved forward.
    // MIT: `ctx_update_age` (plugins/kdb/db2/kdb_db2.c:590-598)
    pub fn update_age(&self) {
        if let Err(e) = self.move_age()
            && refused_link(&e)
        {
            tracing::warn!(
                event = krb5_log::events::ADMIN,
                correlation_id = krb5_log::current_correlation_id(),
                component = "krb5-kdc",
                outcome = "error",
                detail = "the database's age is not moved",
                error = %named_if_link(&self.ok_name, e),
            );
        }
    }

    fn move_age(&self) -> io::Result<()> {
        let old = self.state().ok.metadata()?.mtime();
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
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.ok_name)?;
        futimens(&file, &times.0, &times.1).map_err(io::Error::from)
    }
}

#[derive(Debug)]
pub struct DbLockHold(Arc<DbLock>);

impl DbLockHold {
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

    #[test]
    fn the_age_is_not_moved_through_a_symlink_and_the_refusal_says_so() {
        let db = scratch("age-link").join("principal");
        let lock = DbLock::create(&db).unwrap();
        lock.create_policy_lock().unwrap();
        let ok = suffixed(&db, SUFFIX_LOCK);
        let victim = ok.with_file_name("victim");
        std::fs::write(&victim, b"").unwrap();
        std::fs::remove_file(&ok).unwrap();
        std::os::unix::fs::symlink(&victim, &ok).unwrap();
        let err = lock.move_age().unwrap_err();
        assert!(refused_link(&err), "{err}");
        assert_eq!(
            named_if_link(&ok, err).to_string(),
            format!("{}: Too many levels of symbolic links", ok.display())
        );
    }

    fn scratch(tag: &str) -> PathBuf {
        krb5_testkit::scratch_dir(&format!("krb5-dblock-{tag}"))
    }
}
