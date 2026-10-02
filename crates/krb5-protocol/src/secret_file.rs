//! Atomic writes for the database, stash, keytab and ccache files.
//!
//! The bytes go to a temp file created `O_EXCL` with mode 0600, then
//! rename onto the destination. A partial write is not the path the
//! caller named. [`write_secret_file`] gives the new file the owner, group
//! and permission bits of the file it replaces, as an update in place
//! leaves them; [`write_fresh_secret_file`] always leaves a new 0600 file
//! owned by the writer. With SELinux on, the temp file is created with the
//! SELinux context of the file a [`write_secret_file`] replaces, and any
//! other with the context a new file at the destination takes
//! ([`crate::create_labeled`]); ccaches are not labelled, as MIT's are not.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static SKIP_LSTAT_TYPE: Cell<bool> = const { Cell::new(false) };
}

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

/// What a new file takes from the file it replaces.
#[derive(Clone, Copy)]
enum Replace {
    /// The replaced regular file's owner, group and permission bits.
    Keep,
    /// Nothing: mode 0600, owned by the writer.
    Fresh,
}

/// Write `bytes` to `path` through a temp file + rename, keeping a replaced file's owner, group
/// and permission bits.
///
/// MIT updates the database, its update log and keytabs in place: only a writer that may write
/// the existing file changes it, and the file keeps its owner and mode whoever writes, so one that
/// `kadmind` (root) and `kadmin.local` (a service user) share stays shared:
/// MIT `ctx_lock` (`plugins/kdb/db2/kdb_db2.c:450-455`): the principal database is reopened `O_RDWR`, not recreated.
/// MIT `krb5_ktfileint_open` (`lib/krb5/keytab/kt_file.c:739-746`): an existing keytab is opened "rb+" and written in place.
///
/// A regular file at `path` that the writer may not open read-write is refused before anything is
/// written ([`check_secret_file_writable`]); a missing path, a symlink or another non-regular file
/// is replaced by a new file, and a symlink is not written through.
///
/// On Unix the temp file is created with `O_EXCL` and mode 0600, takes the replaced regular file's
/// uid, gid and permission bits (`fchown`, `fchmod`), and is `fsync`'d before the rename, so
/// `path` never has the wrong owner. A writer that may not give the file to its owner still
/// saves: it keeps the group when it may, drops the group bits when it may not, and logs
/// `protocol.secret_file` at warn. A file another user owns in a shared sticky directory such as
/// `/tmp` is not taken from (Linux `protected_regular`: it may have been planted there). With
/// nothing to take from, the new file is 0600 and the writer's. Off Unix the same exclusive
/// create and rename are used, and the platform default ACL is the permission story.
///
/// # Errors
///
/// The error of [`check_secret_file_writable`] for an existing regular file the writer may not
/// write (`path` is left as it was); the OS error when the temp file beside `path` cannot be
/// created (`O_EXCL`, mode 0600), written, or synced, or cannot be renamed onto `path`. An owner
/// or group that cannot be kept is a warning, not an error.
pub fn write_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic(path, bytes, Replace::Keep, true)
}

/// Fail as MIT's in-place update would when the writer may not write the regular file at `path`.
///
/// MIT `ctx_lock` (`plugins/kdb/db2/kdb_db2.c:453-455`): the update opens the existing database `O_RDWR`, so a writer that may only read it is refused.
///
/// The file is opened `O_RDWR | O_NOFOLLOW`, without creating or truncating it, and closed again;
/// nothing is read or written. The decision comes from `symlink_metadata`: a missing path, a
/// symlink (never followed) or another non-regular file is not opened and passes.
///
/// # Errors
///
/// The OS error of that open, unchanged: `PermissionDenied` for a file the writer may not read
/// and write, `ReadOnlyFilesystem` on a read-only mount.
pub fn check_secret_file_writable(path: &Path) -> io::Result<()> {
    if !fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file()) {
        return Ok(());
    }
    let mut opts = OpenOptions::new();
    opts.read(true).write(true);
    #[cfg(unix)]
    {
        opts.custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits());
    }
    opts.open(path)?;
    Ok(())
}

/// Write `bytes` to `path` as a new file, mode 0600, owned by the writer, whatever it replaces.
///
/// MIT `fcc_initialize` (`lib/krb5/ccache/cc_file.c:481-492`): a FILE ccache is unlinked and created again `O_EXCL`, mode 0600.
/// MIT `create_ofile` (`kadmin/dbutil/dump.c:139-146`): a dump goes to a new `mkstemp` file that is renamed into place.
///
/// Only the directory has to be writable: a file the writer may not write is replaced too.
///
/// # Errors
///
/// The OS error when the temp file beside `path` cannot be created (`O_EXCL`, mode 0600),
/// written, or synced, or cannot be renamed onto `path`.
pub fn write_fresh_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic(path, bytes, Replace::Fresh, true)
}

/// [`write_fresh_secret_file`] for a ccache, whose new file is not given an SELinux context.
/// MIT `fcc_initialize` (`lib/krb5/ccache/cc_file.c:481-492`): a FILE ccache is created with a plain `open`, not one that sets a context.
pub(crate) fn write_fresh_cache_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic(path, bytes, Replace::Fresh, false)
}

fn write_atomic(path: &Path, bytes: &[u8], replace: Replace, labeled: bool) -> io::Result<()> {
    if matches!(replace, Replace::Keep) {
        check_secret_file_writable(path)?;
    }
    let dir = parent_dir(path);
    let (mut f, tmp) = create_temp(path, replace, labeled)?;
    let write = (|| {
        f.write_all(bytes)?;
        #[cfg(unix)]
        {
            set_owner_and_mode(&f, path, dir, replace);
        }
        #[cfg(not(unix))]
        {
            let _ = replace;
        }
        f.sync_all()?;
        Ok::<(), io::Error>(())
    })();
    if let Err(e) = write {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    drop(f);
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    #[cfg(unix)]
    {
        if let Ok(dirf) = fs::File::open(dir) {
            let _ = dirf.sync_all();
        }
    }
    Ok(())
}

/// The directory a write's temp file is made in: `path`'s own.
fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// A new temp file name beside `path`, `.<name>.tmp-<random>`.
fn temp_path(path: &Path) -> PathBuf {
    let mut nonce = [0u8; 8];
    let _ = getrandom::getrandom(&mut nonce);
    parent_dir(path).join(format!(
        ".{}.tmp-{:x}{:x}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("krb5"),
        u32::from_be_bytes(nonce[0..4].try_into().unwrap_or([0; 4])),
        u32::from_be_bytes(nonce[4..8].try_into().unwrap_or([0; 4]))
    ))
}

/// Create the temp file a write renames onto `path`: `O_EXCL | O_NOFOLLOW`, mode 0600, so a
/// link planted at its name is never written through.
pub(crate) fn new_temp(path: &Path) -> io::Result<(fs::File, PathBuf)> {
    let tmp = temp_path(path);
    Ok((create_temp_at(&tmp)?, tmp))
}

/// The temp file at `tmp`: made here (`O_CREAT | O_EXCL | O_NOFOLLOW`), mode 0600.
fn create_temp_at(tmp: &Path) -> io::Result<fs::File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        opts.mode(0o600)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits());
    }
    opts.open(tmp)
}

/// [`new_temp`], labelled for `path` when `labeled` and SELinux is on: with the context of the
/// regular file a [`Replace::Keep`] write replaces, else with the context the policy gives a new
/// file at `path`.
fn create_temp(path: &Path, replace: Replace, labeled: bool) -> io::Result<(fs::File, PathBuf)> {
    #[cfg(target_os = "linux")]
    if labeled && let Some(se) = crate::selabel::SeLinux::system() {
        return se.create_temp(path, matches!(replace, Replace::Keep), || new_temp(path));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (replace, labeled);
    new_temp(path)
}

/// Set the temp file `f`'s mode, and for [`Replace::Keep`] its owner and group, from the file at
/// `path`. `fchmod` is not masked by the umask the `O_EXCL` create was; when it fails the file
/// keeps that create mode, 0600 or narrower.
#[cfg(unix)]
fn set_owner_and_mode(f: &fs::File, path: &Path, dir: &Path, replace: Replace) {
    let mode = match replace {
        Replace::Keep => take_owner(f, path, dir).unwrap_or(0o600),
        Replace::Fresh => 0o600,
    };
    let _ = f.set_permissions(fs::Permissions::from_mode(mode));
}

/// Give `f` the owner and group of the regular file at `path` and return the permission bits it
/// keeps; `None` when there is no such file, or another user's file may have been planted there.
#[cfg(unix)]
fn take_owner(f: &fs::File, path: &Path, dir: &Path) -> Option<u32> {
    let old = fs::symlink_metadata(path)
        .ok()
        .filter(|m| m.file_type().is_file())?;
    let new = f.metadata().ok()?;
    if old.uid() != new.uid() && planted(dir, old.uid()) {
        return None;
    }
    let uid = (old.uid() != new.uid()).then_some(old.uid());
    let gid = (old.gid() != new.gid()).then_some(old.gid());
    if uid.is_none() && gid.is_none() {
        return Some(kept_mode(old.mode(), true));
    }
    let Err(e) = std::os::unix::fs::fchown(f, uid, gid) else {
        return Some(kept_mode(old.mode(), true));
    };
    // MIT's in-place write keeps the owner whoever writes. A writer that may not give the file
    // away (EPERM) keeps what it can and still saves, so an admin's change is not lost.
    let group_kept =
        gid.is_none() || (uid.is_some() && std::os::unix::fs::fchown(f, None, gid).is_ok());
    let detail = match (uid.is_some(), group_kept) {
        (true, true) => "owner not kept",
        (true, false) => "owner and group not kept",
        (false, _) => "group not kept",
    };
    tracing::warn!(
        event = krb5_log::events::PROTOCOL_SECRET_FILE,
        correlation_id = krb5_log::current_correlation_id(),
        component = "krb5-protocol",
        outcome = "ok",
        path = %path.display(),
        uid = old.uid(),
        gid = old.gid(),
        detail,
        error = %e,
    );
    Some(kept_mode(old.mode(), group_kept))
}

/// The permission bits a replacement keeps: the old file's, less the group's when the old group
/// could not be kept, so they are not granted to the writer's group instead.
#[cfg(unix)]
fn kept_mode(old_mode: u32, group_kept: bool) -> u32 {
    let mode = old_mode & 0o777;
    if group_kept { mode } else { mode & !0o070 }
}

/// Whether a file `owner` owns in `dir` may have been planted to receive the secret; a directory
/// that cannot be read counts as one.
#[cfg(unix)]
fn planted(dir: &Path, owner: u32) -> bool {
    let Ok(d) = fs::metadata(dir) else {
        return true;
    };
    shared_sticky(d.mode(), d.uid(), owner)
}

/// Linux `protected_regular` (level 2): a sticky directory that group or others may write, and a
/// file the directory's owner does not own.
#[cfg(unix)]
fn shared_sticky(dir_mode: u32, dir_uid: u32, owner: u32) -> bool {
    dir_mode & 0o1000 != 0 && dir_mode & 0o022 != 0 && owner != dir_uid
}

/// Overwrite `path` with zeros, fsync, then unlink (kdestroy).
///
/// Symlinks and non-regular files are refused. Unix `open` uses
/// `O_NOFOLLOW|O_NONBLOCK` so a swap to a symlink or FIFO does not
/// follow or hang. After open, `(dev, ino)` must match the pre-open
/// `lstat`. Non-Unix: the swap race is not closed (`swapped=false`).
///
/// # Errors
///
/// `io::ErrorKind::InvalidInput` when `path` is not a regular file or is swapped for another
/// file between the `lstat` and the open; the OS error when it cannot be stat'ed (`NotFound`
/// if missing), opened, overwritten, synced, or removed.
pub fn destroy_secret_file(path: &Path) -> io::Result<()> {
    let lmeta = fs::symlink_metadata(path)?;
    #[cfg(test)]
    let skip_type = SKIP_LSTAT_TYPE.with(Cell::get);
    #[cfg(not(test))]
    let skip_type = false;
    if !skip_type && !lmeta.file_type().is_file() {
        return Err(not_regular());
    }
    let mut opts = OpenOptions::new();
    opts.write(true);
    #[cfg(unix)]
    {
        opts.custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits());
    }
    let mut f = opts.open(path)?;
    let meta = f.metadata()?;
    #[cfg(unix)]
    let swapped = meta.dev() != lmeta.dev() || meta.ino() != lmeta.ino();
    #[cfg(not(unix))]
    let swapped = false;
    if swapped || !meta.file_type().is_file() {
        return Err(not_regular());
    }
    let chunk = [0u8; 4096];
    let mut left = meta.len();
    while left > 0 {
        let n = usize::try_from(left.min(chunk.len() as u64)).unwrap_or(chunk.len());
        f.write_all(&chunk[..n])?;
        left -= n as u64;
    }
    f.sync_all()?;
    drop(f);
    fs::remove_file(path)
}

fn not_regular() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "not a regular file")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{chown, symlink};
    use std::time::Instant;

    fn meta(path: &Path) -> (u32, u32, u32) {
        let m = fs::metadata(path).unwrap();
        (m.uid(), m.gid(), m.mode() & 0o7777)
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Give `path` one of this user's supplementary groups (`id -G`) other than its own.
    fn chgrp_to_another_group(path: &Path) -> Option<u32> {
        let own = fs::metadata(path).unwrap().gid();
        nix::unistd::getgroups()
            .unwrap_or_default()
            .into_iter()
            .map(nix::unistd::Gid::as_raw)
            .filter(|&g| g != own)
            .find(|&g| chown(path, None, Some(g)).is_ok())
    }

    fn is_root() -> bool {
        nix::unistd::geteuid().is_root()
    }

    /// Run `f` on a thread whose filesystem identity is `uid` / `gid`: Linux `setfsuid` is per
    /// thread and drops that thread's filesystem capabilities, so a root test can act as another
    /// user. `None` when the switch does not take.
    #[cfg(target_os = "linux")]
    fn as_fs_identity<R: Send>(uid: u32, gid: u32, f: impl FnOnce() -> R + Send) -> Option<R> {
        use nix::unistd::{Gid, Uid, setfsgid, setfsuid};
        std::thread::scope(|s| {
            s.spawn(|| {
                setfsgid(Gid::from_raw(gid));
                setfsuid(Uid::from_raw(uid));
                // Each call returns the previous identity, so a repeat reports whether it took.
                let took = setfsgid(Gid::from_raw(gid)).as_raw() == gid
                    && setfsuid(Uid::from_raw(uid)).as_raw() == uid;
                let out = took.then(f);
                setfsuid(Uid::from_raw(0));
                setfsgid(Gid::from_raw(0));
                out
            })
            .join()
            .ok()
            .flatten()
        })
    }

    /// A root-owned directory and file that group 4243 may write and read as `file_mode` says.
    #[cfg(target_os = "linux")]
    fn group_db(name: &str, file_mode: u32) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
        let dir = krb5_testkit::scratch_dir(name);
        let db = dir.join("db");
        fs::create_dir(&db).unwrap();
        let path = db.join("principal");
        fs::write(&path, b"old").unwrap();
        if chown(&db, Some(0), Some(4243)).is_err() || chown(&path, Some(0), Some(4243)).is_err() {
            eprintln!("skipped: gid 4243 is not mapped in this user namespace");
            let _ = fs::remove_dir_all(&dir);
            return None;
        }
        set_mode(&db, 0o770);
        set_mode(&path, file_mode);
        Some((dir, path))
    }

    #[test]
    fn an_owner_who_may_not_write_its_file_is_refused() {
        if is_root() {
            eprintln!("skipped: root may write a 0400 file");
            return;
        }
        let dir = krb5_testkit::scratch_dir("krb5-secret-readonly");
        let path = dir.join("principal");
        fs::write(&path, b"old").unwrap();
        set_mode(&path, 0o400);
        let before = meta(&path);
        let err = write_secret_file(&path, b"new").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert_eq!(meta(&path), before);
        assert_eq!(
            fs::read_dir(&dir).unwrap().count(),
            1,
            "no temp file is left"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_fresh_write_replaces_a_file_the_writer_may_not_write() {
        let dir = krb5_testkit::scratch_dir("krb5-secret-fresh-readonly");
        let path = dir.join("krb5cc");
        fs::write(&path, b"old").unwrap();
        set_mode(&path, 0o400);
        write_fresh_secret_file(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(meta(&path).2, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_check_opens_only_a_regular_file_and_never_follows_a_symlink() {
        let dir = krb5_testkit::scratch_dir("krb5-secret-check");
        let target = dir.join("target");
        fs::write(&target, b"target").unwrap();
        set_mode(&target, 0o400);
        let link = dir.join("link");
        symlink(&target, &link).unwrap();
        assert!(check_secret_file_writable(&dir.join("missing")).is_ok());
        assert!(check_secret_file_writable(&link).is_ok());
        assert!(check_secret_file_writable(&dir).is_ok());
        if !is_root() {
            let err = check_secret_file_writable(&target).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        }
        assert_eq!(fs::read(&target).unwrap(), b"target");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn root_a_group_reader_may_not_replace_the_file() {
        if !is_root() {
            eprintln!("skipped: acting as a second user needs euid 0");
            return;
        }
        let Some((dir, path)) = group_db("krb5-secret-reader", 0o640) else {
            return;
        };
        let before = (meta(&path), fs::metadata(&path).unwrap().ino());
        let Some((read, write)) = as_fs_identity(4242, 4243, || {
            (fs::read(&path).ok(), write_secret_file(&path, b"new"))
        }) else {
            eprintln!("skipped: setfsuid to 4242 did not take");
            let _ = fs::remove_dir_all(&dir);
            return;
        };
        if read.is_none() {
            eprintln!("skipped: the scratch path is not searchable by uid 4242");
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        let err = write.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        assert_eq!(fs::read(&path).unwrap(), b"old");
        assert_eq!((meta(&path), fs::metadata(&path).unwrap().ino()), before);
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn root_a_group_writer_replaces_the_file_but_cannot_keep_its_owner() {
        if !is_root() {
            eprintln!("skipped: acting as a second user needs euid 0");
            return;
        }
        let Some((dir, path)) = group_db("krb5-secret-writer", 0o660) else {
            return;
        };
        let Some((read, write)) = as_fs_identity(4242, 4243, || {
            (fs::read(&path).ok(), write_secret_file(&path, b"new"))
        }) else {
            eprintln!("skipped: setfsuid to 4242 did not take");
            let _ = fs::remove_dir_all(&dir);
            return;
        };
        if read.is_none() {
            eprintln!("skipped: the scratch path is not searchable by uid 4242");
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        write.unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(meta(&path), (4242, 4243, 0o660));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn replacing_a_file_keeps_its_permission_bits() {
        let dir = krb5_testkit::scratch_dir("krb5-secret-mode");
        let path = dir.join("principal");
        fs::write(&path, b"old").unwrap();
        set_mode(&path, 0o640);
        let (uid, gid, _) = meta(&path);
        write_secret_file(&path, b"new").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(meta(&path), (uid, gid, 0o640));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn replacing_a_file_keeps_its_group() {
        let dir = krb5_testkit::scratch_dir("krb5-secret-gid");
        let path = dir.join("principal");
        fs::write(&path, b"old").unwrap();
        let Some(gid) = chgrp_to_another_group(&path) else {
            eprintln!(
                "skipped: no supplementary group of this user (`id -G`) other than the file's \
                 own can be given to a file here"
            );
            let _ = fs::remove_dir_all(&dir);
            return;
        };
        set_mode(&path, 0o640);
        write_secret_file(&path, b"new").unwrap();
        let (_, new_gid, mode) = meta(&path);
        assert_eq!((new_gid, mode), (gid, 0o640));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_file_is_0600_and_the_writers() {
        let dir = krb5_testkit::scratch_dir("krb5-secret-new");
        let path = dir.join("stash");
        write_secret_file(&path, b"key").unwrap();
        let (uid, _, mode) = meta(&path);
        assert_eq!((uid, mode), (nix::unistd::geteuid().as_raw(), 0o600));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_fresh_write_takes_nothing_from_the_replaced_file() {
        let dir = krb5_testkit::scratch_dir("krb5-secret-fresh");
        let path = dir.join("krb5cc");
        fs::write(&path, b"old").unwrap();
        let (uid, gid, _) = meta(&path);
        let _ = chgrp_to_another_group(&path);
        set_mode(&path, 0o644);
        write_fresh_secret_file(&path, b"new").unwrap();
        assert_eq!(meta(&path), (uid, gid, 0o600));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_symlink_passes_nothing_to_the_new_file() {
        let dir = krb5_testkit::scratch_dir("krb5-secret-link");
        let target = dir.join("target");
        let link = dir.join("krb5.keytab");
        fs::write(&target, b"target").unwrap();
        set_mode(&target, 0o644);
        symlink(&target, &link).unwrap();
        write_secret_file(&link, b"keys").unwrap();
        assert!(fs::symlink_metadata(&link).unwrap().file_type().is_file());
        assert_eq!(meta(&link).2, 0o600);
        assert_eq!(fs::read(&target).unwrap(), b"target");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn root_keeps_the_replaced_files_owner() {
        if !is_root() {
            eprintln!("skipped: giving the new file another user's ownership needs euid 0");
            return;
        }
        let dir = krb5_testkit::scratch_dir("krb5-secret-owner");
        let path = dir.join("principal");
        fs::write(&path, b"old").unwrap();
        if chown(&path, Some(4242), Some(4243)).is_err() {
            eprintln!("skipped: uid 4242 / gid 4243 are not mapped in this user namespace");
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        set_mode(&path, 0o640);
        write_secret_file(&path, b"new").unwrap();
        assert_eq!(meta(&path), (4242, 4243, 0o640));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn root_does_not_give_a_secret_to_a_file_planted_in_a_sticky_directory() {
        if !is_root() {
            eprintln!("skipped: a file planted by another user needs euid 0 to set up");
            return;
        }
        let dir = krb5_testkit::scratch_dir("krb5-secret-sticky");
        let tmp = dir.join("tmp");
        fs::create_dir(&tmp).unwrap();
        set_mode(&tmp, 0o1777);
        let path = tmp.join("krb5.keytab");
        fs::write(&path, b"planted").unwrap();
        if chown(&path, Some(4242), Some(4242)).is_err() {
            eprintln!("skipped: uid 4242 is not mapped in this user namespace");
            let _ = fs::remove_dir_all(&dir);
            return;
        }
        set_mode(&path, 0o644);
        write_secret_file(&path, b"keys").unwrap();
        let (uid, _, mode) = meta(&path);
        assert_eq!((uid, mode), (0, 0o600));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_group_that_is_not_kept_loses_its_bits() {
        assert_eq!(kept_mode(0o100_640, true), 0o640);
        assert_eq!(kept_mode(0o100_660, false), 0o600);
        assert_eq!(kept_mode(0o104_755, true), 0o755);
    }

    #[test]
    fn shared_sticky_is_protected_regular_level_2() {
        assert!(shared_sticky(0o41777, 0, 4242));
        assert!(shared_sticky(0o41770, 0, 4242));
        assert!(!shared_sticky(0o41777, 4242, 4242));
        assert!(!shared_sticky(0o40777, 0, 4242));
        assert!(!shared_sticky(0o41755, 0, 4242));
    }

    struct SkipType;
    impl Drop for SkipType {
        fn drop(&mut self) {
            SKIP_LSTAT_TYPE.with(|c| c.set(false));
        }
    }

    fn with_skip_lstat_type<R>(f: impl FnOnce() -> R) -> R {
        SKIP_LSTAT_TYPE.with(|c| c.set(true));
        let _g = SkipType;
        f()
    }

    /// A link planted at a temp file's name is never written through: the create fails
    /// (`O_CREAT | O_EXCL | O_NOFOLLOW`), the link stays and its target is as it was.
    #[test]
    fn a_temp_file_is_never_made_through_a_symlink() {
        let dir = krb5_testkit::scratch_dir("krb5-temp-link");
        let (tmp, victim) = (dir.join(".principal.tmp-planted"), dir.join("victim"));
        fs::write(&victim, b"keep").unwrap();
        let old = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
        fs::File::options()
            .write(true)
            .open(&victim)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(old).set_accessed(old))
            .unwrap();
        symlink(&victim, &tmp).unwrap();
        let err = create_temp_at(&tmp).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{err}");
        assert!(fs::symlink_metadata(&tmp).unwrap().file_type().is_symlink());
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert_eq!(fs::metadata(&victim).unwrap().modified().unwrap(), old);
    }

    #[test]
    fn open_refuses_symlink_with_nofollow() {
        let dir = krb5_testkit::scratch_dir("krb5-nofollow");
        let pid = std::process::id();
        let target = dir.join(format!("krb5-nofollow-target-{pid}"));
        let link = dir.join(format!("krb5-nofollow-link-{pid}"));
        let _ = fs::remove_file(&target);
        let _ = fs::remove_file(&link);
        fs::write(&target, b"do-not-zero").unwrap();
        symlink(&target, &link).unwrap();
        let err = with_skip_lstat_type(|| destroy_secret_file(&link)).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(nix::libc::ELOOP), "{err}");
        assert_eq!(fs::read(&target).unwrap(), b"do-not-zero");
        let _ = fs::remove_file(&link);
        let _ = fs::remove_file(&target);
    }

    #[test]
    fn open_refuses_fifo_without_hang() {
        let path = krb5_testkit::scratch_dir("krb5-nofollow-fifo").join("fifo");
        let _ = fs::remove_file(&path);
        let st = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(st.success());
        let t0 = Instant::now();
        let err = with_skip_lstat_type(|| destroy_secret_file(&path));
        assert!(err.is_err(), "FIFO open must fail");
        assert!(t0.elapsed() < std::time::Duration::from_secs(2));
        let _ = fs::remove_file(&path);
    }
}
