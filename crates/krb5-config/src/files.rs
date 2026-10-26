use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Default)]
struct Read {
    files: HashMap<PathBuf, Vec<u8>>,
    dirs: HashMap<PathBuf, Vec<OsString>>,
}

thread_local! {
    static READ: RefCell<Option<Read>> = const { RefCell::new(None) };
}

// MIT: `profile_open_file` (util/profile/prof_file.c)
pub struct ReadOnce(Option<Read>);

impl ReadOnce {
    #[must_use]
    pub fn start() -> Self {
        Self(READ.with(|r| r.borrow_mut().replace(Read::default())))
    }
}

impl Drop for ReadOnce {
    fn drop(&mut self) {
        let outer = self.0.take();
        READ.with(|r| *r.borrow_mut() = outer);
    }
}

pub(crate) fn read(path: &Path) -> io::Result<Vec<u8>> {
    READ.with(|r| {
        let mut r = r.borrow_mut();
        let Some(read) = r.as_mut() else {
            return std::fs::read(path);
        };
        let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if let Some(bytes) = read.files.get(&key) {
            return Ok(bytes.clone());
        }
        let bytes = std::fs::read(path)?;
        read.files.insert(key, bytes.clone());
        Ok(bytes)
    })
}

pub(crate) fn dir_names(dir: &Path) -> io::Result<Vec<OsString>> {
    let list = || -> io::Result<Vec<OsString>> {
        std::fs::read_dir(dir)?
            .map(|ent| ent.map(|e| e.file_name()))
            .collect()
    };
    READ.with(|r| {
        let mut r = r.borrow_mut();
        let Some(read) = r.as_mut() else {
            return list();
        };
        if let Some(names) = read.dirs.get(dir) {
            return Ok(names.clone());
        }
        let names = list()?;
        read.dirs.insert(dir.to_path_buf(), names.clone());
        Ok(names)
    })
}
