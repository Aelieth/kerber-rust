//! Atomic 0600 writes for keytab and ccache files.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static SKIP_LSTAT_TYPE: Cell<bool> = const { Cell::new(false) };
}

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

/// Write `bytes` to `path` with mode 0600 using a temp file + rename.
///
/// On Unix the temp file is created with `O_EXCL` and mode 0600, then
/// `fsync`'d before rename. Off Unix the same exclusive-create + rename
/// is used; the platform default ACL is the permission story (documented
/// in README).
///
/// # Errors
///
/// Returns I/O errors from create, write, sync, or rename.
pub fn write_secret_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut nonce = [0u8; 8];
    let _ = getrandom::getrandom(&mut nonce);
    let tmp = dir.join(format!(
        ".{}.tmp-{:x}{:x}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("krb5"),
        u32::from_be_bytes(nonce[0..4].try_into().unwrap_or([0; 4])),
        u32::from_be_bytes(nonce[4..8].try_into().unwrap_or([0; 4]))
    ));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    let write = (|| {
        f.write_all(bytes)?;
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
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        if let Ok(dirf) = fs::File::open(dir) {
            let _ = dirf.sync_all();
        }
    }
    Ok(())
}

/// Open `path` for exclusive create with mode 0600 (ccache TOCTOU-safe create).
///
/// # Errors
///
/// Returns I/O errors. Already-exists is an error (`create_new`).
#[allow(dead_code)]
pub fn create_exclusive_secret(path: &Path) -> io::Result<std::fs::File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    opts.open(path)
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
/// Returns I/O errors from open/write/sync/remove. Missing file is an error.
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
    use std::os::unix::fs::symlink;
    use std::time::Instant;

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

    #[test]
    fn open_refuses_symlink_with_nofollow() {
        let dir = std::env::temp_dir();
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
        let path = std::env::temp_dir().join(format!("krb5-nofollow-fifo-{}", std::process::id()));
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
