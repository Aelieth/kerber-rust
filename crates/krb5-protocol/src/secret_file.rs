//! Atomic 0600 writes for keytab and ccache files.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

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
/// # Errors
///
/// Returns I/O errors from open/write/sync/remove. Missing file is an error.
pub fn destroy_secret_file(path: &Path) -> io::Result<()> {
    let meta = fs::metadata(path)?;
    let mut f = OpenOptions::new().write(true).open(path)?;
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
