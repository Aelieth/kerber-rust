//! Whole-file locks: an OFD lock, else POSIX, else flock.

use std::fs::File;
use std::io;

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, Flock, FlockArg, fcntl};
use nix::libc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileLock {
    Shared,
    Exclusive,
    Unlock,
}

// MIT: `ofdlock` (lib/krb5/os/lock_file.c:90-103)
/// EINVAL, a kernel without OFD locks, uses a POSIX lock.
fn ofdlock(file: &File, arg: &libc::flock, wait: bool) -> Result<(), Errno> {
    let ofd = if wait {
        FcntlArg::F_OFD_SETLKW(arg)
    } else {
        FcntlArg::F_OFD_SETLK(arg)
    };
    match fcntl(file, ofd) {
        Ok(_) => Ok(()),
        Err(Errno::EINVAL) => {
            let posix = if wait {
                FcntlArg::F_SETLKW(arg)
            } else {
                FcntlArg::F_SETLK(arg)
            };
            fcntl(file, posix).map(drop)
        }
        Err(e) => Err(e),
    }
}

// MIT: `krb5_lock_file` (lib/krb5/os/lock_file.c:117-162)
/// The lock covers the whole file.
// MIT: `krb5_lock_file` (lib/krb5/os/lock_file.c:154-170)
/// Only EINVAL falls back to flock, and that error is still returned.
/// A flock taken stays in flocked until the unlock.
/// EACCES is returned as EAGAIN.
pub fn lock_file(
    file: &File,
    how: FileLock,
    flocked: &mut Option<Flock<File>>,
) -> Result<(), Errno> {
    lock_file_how(file, how, flocked, true)
}

/// Without wait, a conflict is EAGAIN.
pub fn lock_file_how(
    file: &File,
    how: FileLock,
    flocked: &mut Option<Flock<File>>,
    wait: bool,
) -> Result<(), Errno> {
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
    let retval = match ofdlock(file, &arg, wait) {
        Ok(()) => return Ok(()),
        Err(Errno::EACCES | Errno::EAGAIN) => return Err(Errno::EAGAIN),
        Err(Errno::EINVAL) => Errno::EINVAL,
        Err(e) => return Err(e),
    };
    match flock_fallback(file, how, flocked, wait) {
        Ok(()) => Err(retval),
        Err(e) => Err(e),
    }
}

fn flock_fallback(
    file: &File,
    how: FileLock,
    flocked: &mut Option<Flock<File>>,
    wait: bool,
) -> Result<(), Errno> {
    let arg = match (how, wait) {
        (FileLock::Shared, true) => FlockArg::LockShared,
        (FileLock::Shared, false) => FlockArg::LockSharedNonblock,
        (FileLock::Exclusive, true) => FlockArg::LockExclusive,
        (FileLock::Exclusive, false) => FlockArg::LockExclusiveNonblock,
        (FileLock::Unlock, _) => {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn two_opens(name: &str) -> (std::path::PathBuf, File, File) {
        let dir = krb5_testkit::scratch_dir(name);
        let path = dir.join("cache");
        std::fs::write(&path, b"x").unwrap();
        let a = File::options().read(true).write(true).open(&path).unwrap();
        let b = File::options().read(true).write(true).open(&path).unwrap();
        (dir, a, b)
    }

    #[test]
    fn an_exclusive_lock_keeps_out_every_other_until_it_is_let_go() {
        let (dir, a, b) = two_opens("krb5-lock-excl");
        let (mut fa, mut fb) = (None, None);
        lock_file(&a, FileLock::Exclusive, &mut fa).unwrap();
        assert_eq!(
            lock_file_how(&b, FileLock::Shared, &mut fb, false),
            Err(Errno::EAGAIN)
        );
        assert_eq!(
            lock_file_how(&b, FileLock::Exclusive, &mut fb, false),
            Err(Errno::EAGAIN)
        );
        lock_file(&a, FileLock::Unlock, &mut fa).unwrap();
        lock_file_how(&b, FileLock::Exclusive, &mut fb, false).unwrap();
        lock_file(&b, FileLock::Unlock, &mut fb).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn shared_locks_share_and_keep_out_an_exclusive_one() {
        let (dir, a, b) = two_opens("krb5-lock-shared");
        let (mut fa, mut fb) = (None, None);
        lock_file(&a, FileLock::Shared, &mut fa).unwrap();
        lock_file_how(&b, FileLock::Shared, &mut fb, false).unwrap();
        lock_file(&b, FileLock::Unlock, &mut fb).unwrap();
        assert_eq!(
            lock_file_how(&b, FileLock::Exclusive, &mut fb, false),
            Err(Errno::EAGAIN)
        );
        lock_file(&a, FileLock::Unlock, &mut fa).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }
}
