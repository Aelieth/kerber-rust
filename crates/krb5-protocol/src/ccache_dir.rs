//! DIR collection (`cc_dir.c`): `DIR:dirname` and `DIR::filepath`.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;

const DEFAULT_SUB: &str = "tkt";

// MIT: `dcc_resolve` (lib/krb5/ccache/cc_dir.c:332-385)
pub fn dir_cache_path(residual: &str) -> io::Result<PathBuf> {
    if let Some(path) = residual.strip_prefix(':') {
        verify_dir(subsidiary(path)?.0)?;
        return Ok(PathBuf::from(path));
    }
    let dir = Path::new(residual);
    verify_dir(dir)?;
    let name = read_primary(dir, true)?;
    Ok(dir.join(name))
}

pub fn dir_display_name(residual: &str) -> io::Result<String> {
    let path = dir_cache_path(residual)?;
    Ok(format!("DIR::{}", path.display()))
}

/// Only a DIR::filepath residual changes the primary.
pub fn dir_switch(residual: &str) -> io::Result<()> {
    let path = residual.strip_prefix(':').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "kswitch needs DIR::subsidiary")
    })?;
    let (dir, name) = subsidiary(path)?;
    verify_dir(dir)?;
    write_primary(dir, name)
}

// MIT: `dcc_ptcursor_new` (cc_dir.c:579-632)
/// No readable primary file means no primary.
#[must_use]
pub fn dir_primary(dir: &Path) -> Option<PathBuf> {
    match read_primary(dir, false) {
        Ok(name) if dir.join("primary").is_file() => Some(dir.join(name)),
        _ => None,
    }
}

/// An existing name is skipped.
// MIT: `dcc_gen_new` (cc_dir.c:387-429)
/// On Unix the mode is 0600.
/// The collection directory is created if it is missing.
pub fn dir_gen_new(dir: &Path) -> io::Result<PathBuf> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    verify_dir(dir)?;
    loop {
        let mut raw = [0u8; 6];
        getrandom::getrandom(&mut raw).map_err(|e| io::Error::other(e.to_string()))?;
        let suffix: String = raw
            .iter()
            .map(|b| char::from(CHARS[usize::from(*b) % CHARS.len()]))
            .collect();
        let path = dir.join(format!("tkt{suffix}"));
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(_) => return Ok(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
}

pub fn dir_subsidiaries(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut v = Vec::new();
    for e in fs::read_dir(dir)? {
        let e = e?;
        let s = e.file_name();
        let name = s.to_string_lossy();
        if name.starts_with("tkt") && e.file_type()?.is_file() {
            v.push(e.path());
        }
    }
    v.sort();
    Ok(v)
}

// MIT: `split_path` (lib/krb5/ccache/cc_dir.c:107-141)
fn subsidiary(path: &str) -> io::Result<(&Path, &str)> {
    let p = Path::new(path);
    let bad = |what: &str| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Subsidiary cache path {path} {what}"),
        )
    };
    let dir = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or_else(|| bad("has no parent directory"))?;
    match p.file_name().and_then(|s| s.to_str()) {
        Some(name) if name.starts_with("tkt") => Ok((dir, name)),
        _ => Err(bad("filename does not begin with \"tkt\"")),
    }
}

// MIT: `verify_dir` (lib/krb5/ccache/cc_dir.c:221-240)
fn verify_dir(dir: &Path) -> io::Result<()> {
    match fs::metadata(dir) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "Credential cache directory {} exists but is not a directory",
                dir.display()
            ),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound && make_dir(dir).is_ok() => Ok(()),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Credential cache directory {} does not exist",
                dir.display()
            ),
        )),
    }
}

fn make_dir(dir: &Path) -> io::Result<()> {
    let mut b = DirBuilder::new();
    #[cfg(unix)]
    b.mode(0o700);
    b.create(dir)
}

// MIT: `read_primary_file` (lib/krb5/ccache/cc_dir.c:146-176)
fn read_primary(dir: &Path, init: bool) -> io::Result<String> {
    let p = dir.join("primary");
    match fs::read_to_string(&p) {
        Ok(s) if s.is_empty() => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Credentials cache I/O operation failed",
        )),
        Ok(s) => {
            let line = s.split_inclusive('\n').next().unwrap_or("");
            match line.strip_suffix('\n') {
                Some(name)
                    if line.len() < 64
                        && name.starts_with("tkt")
                        && !name.contains(['/', '\\']) =>
                {
                    Ok(name.to_owned())
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} contains invalid filename", p.display()),
                )),
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if init {
                write_primary(dir, DEFAULT_SUB)?;
            }
            Ok(DEFAULT_SUB.to_owned())
        }
        Err(e) => Err(e),
    }
}

fn write_primary(dir: &Path, name: &str) -> io::Result<()> {
    let dest = dir.join("primary");
    let mut nonce = [0u8; 4];
    let _ = getrandom::getrandom(&mut nonce);
    let tmp = dir.join(format!("primary.tmp-{:x}", u32::from_be_bytes(nonce)));
    let write = (|| {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        writeln!(f, "{name}")?;
        f.sync_all()?;
        Ok::<(), io::Error>(())
    })();
    if let Err(e) = write {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, dest) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_default_tkt_and_switch() {
        let dir = krb5_testkit::scratch_dir("krb5cc-dir").join("cc");
        let _ = fs::remove_dir_all(&dir);
        let residual = dir.to_string_lossy().into_owned();
        let p = dir_cache_path(&residual).expect("a missing DIR is made");
        assert_eq!(p.file_name().unwrap(), "tkt");
        assert!(dir.join("primary").is_file());
        let sub = dir.join("tktXXXX");
        fs::write(&sub, b"x").unwrap();
        let sub_res = format!(":{}", sub.display());
        dir_switch(&sub_res).expect("switch");
        let p2 = dir_cache_path(&residual).expect("switched");
        assert_eq!(p2.file_name().unwrap(), "tktXXXX");
        let _ = fs::remove_dir_all(&dir);
    }
}
