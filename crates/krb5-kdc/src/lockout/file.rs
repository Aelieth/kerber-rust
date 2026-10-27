//! The KDC updates a record in place and does not create the file.
// MIT: `open_lmdb_env` (plugins/kdb/lmdb/kdb_lmdb.c:265-268)

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use krb5_log::klog::{self, Severity};
use nix::fcntl::OFlag;

use super::{Lockout, LockoutUpdate};
use crate::dblock::{DbLock, DbLockMode, suffixed};
use crate::store::{Principal, PrincipalStore};

/// .lockout is labeled with the database, not as a lock file.
pub const SUFFIX_LOCKOUT: &str = ".lockout";

const HEADER: &[u8] = b"kerber-rust lockout 1\n";
const FIELD: usize = 10;
const VALUES: usize = 3 * FIELD + 2;
const SUM: usize = 8;
const HEAD: usize = VALUES + 1 + SUM;
/// A deleted principal's line, dropped when the file is rewritten.
const DELETED: u8 = b'#';

const CRC_TABLE: [u32; 256] = crc_table();

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    let mut n = 0u32;
    while i < 256 {
        let mut c = n;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 1 == 1 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            bit += 1;
        }
        table[i] = c;
        i += 1;
        n += 1;
    }
    table
}

fn checksum(values: &[u8], name: &[u8]) -> u32 {
    crc32(values.iter().chain(b" ").chain(name))
}

pub(crate) fn crc32<'a>(bytes: impl IntoIterator<Item = &'a u8>) -> u32 {
    let mut c = !0u32;
    for &b in bytes {
        c = CRC_TABLE[usize::from(c.to_le_bytes()[0] ^ b)] ^ (c >> 8);
    }
    !c
}

#[must_use]
pub fn lockout_path(db: &Path) -> PathBuf {
    suffixed(db, SUFFIX_LOCKOUT)
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn named(path: &Path, e: &io::Error) -> io::Error {
    io::Error::new(
        e.kind(),
        format!("{}: {}", path.display(), klog::os_error_text(e)),
    )
}

fn head(id: &str, l: Lockout) -> [u8; HEAD] {
    let values = format!(
        "{:010} {:010} {:010}",
        l.last_success, l.last_failed, l.fail_auth_count
    );
    let text = format!(
        "{values} {:08x}",
        checksum(values.as_bytes(), id.as_bytes())
    );
    let mut out = [b'0'; HEAD];
    for (o, b) in out.iter_mut().zip(text.bytes()) {
        *o = b;
    }
    out
}

fn record_line(id: &str, l: Lockout) -> Vec<u8> {
    let mut line = head(id, l).to_vec();
    line.push(b' ');
    line.extend_from_slice(id.as_bytes());
    line.push(b'\n');
    line
}

fn render(records: &[(String, Lockout)]) -> Vec<u8> {
    let mut text = HEADER.to_vec();
    for (id, l) in records {
        text.extend_from_slice(&record_line(id, *l));
    }
    text
}

/// A bad checksum is no record; an update in place is not synced.
fn parse_line(line: &[u8]) -> Option<(Lockout, &str)> {
    let field = |i: usize| -> Option<u32> {
        let start = i * (FIELD + 1);
        let digits = line.get(start..start + FIELD)?;
        if !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(digits).ok()?.parse().ok()
    };
    for at in [FIELD, 2 * FIELD + 1, VALUES, HEAD] {
        if line.get(at) != Some(&b' ') {
            return None;
        }
    }
    let sum = line.get(VALUES + 1..HEAD)?;
    if !sum.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let name = line.get(HEAD + 1..)?;
    if name.is_empty() {
        return None;
    }
    let want = u32::from_str_radix(std::str::from_utf8(sum).ok()?, 16).ok()?;
    if checksum(line.get(..VALUES)?, name) != want {
        return None;
    }
    let lockout = Lockout {
        last_success: field(0)?,
        last_failed: field(1)?,
        fail_auth_count: field(2)?,
    };
    Some((lockout, std::str::from_utf8(name).ok()?))
}

#[derive(Debug, Default)]
struct Index {
    records: HashMap<String, (u64, Lockout)>,
    dead: usize,
    len: u64,
    whole: bool,
    foreign: bool,
}

fn index(bytes: &[u8]) -> Index {
    let mut ix = Index {
        len: len_u64(bytes.len()),
        whole: bytes.last().is_none_or(|&b| b == b'\n'),
        ..Index::default()
    };
    if bytes.is_empty() {
        return ix;
    }
    let Some(body) = bytes.strip_prefix(HEADER) else {
        ix.foreign = true;
        return ix;
    };
    index_body(&mut ix, body, len_u64(HEADER.len()));
    ix
}

fn index_body(ix: &mut Index, body: &[u8], start: u64) {
    let mut off = start;
    for line in body.split_inclusive(|&b| b == b'\n') {
        let at = off;
        off += len_u64(line.len());
        match line.strip_suffix(b"\n").and_then(parse_line) {
            Some((l, name)) => {
                if ix.records.insert(name.to_owned(), (at, l)).is_some() {
                    ix.dead += 1;
                }
            }
            None => ix.dead += 1,
        }
    }
}

fn read_all(file: &File) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read_at(&mut buf, len_u64(out.len()))?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(buf.get(..n).unwrap_or_default());
    }
}

fn read_full_at(file: &File, buf: &mut [u8], at: u64) -> io::Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        let Some(rest) = buf.get_mut(done..) else {
            break;
        };
        let n = file.read_at(rest, at + len_u64(done))?;
        if n == 0 {
            break;
        }
        done += n;
    }
    Ok(done)
}

fn open_file(path: &Path, write: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(file)
}

#[derive(Debug)]
pub(crate) struct SideFile {
    path: PathBuf,
    file: File,
    writable: bool,
    id: (u64, u64),
    ix: Index,
}

impl SideFile {
    fn open(path: &Path) -> io::Result<Option<Self>> {
        let (file, writable) = match open_file(path, true) {
            Ok(f) => (f, true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => match open_file(path, false) {
                Ok(f) => (f, false),
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e),
            },
        };
        Self::with(path, file, writable).map(Some)
    }

    fn open_read(path: &Path) -> io::Result<Option<Self>> {
        match open_file(path, false) {
            Ok(f) => Self::with(path, f, false).map(Some),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn with(path: &Path, file: File, writable: bool) -> io::Result<Self> {
        let mut side = Self {
            path: path.to_path_buf(),
            file,
            writable,
            id: (0, 0),
            ix: Index::default(),
        };
        side.reindex()?;
        Ok(side)
    }

    fn reindex(&mut self) -> io::Result<()> {
        let meta = self.file.metadata()?;
        self.id = (meta.dev(), meta.ino());
        self.ix = index(&read_all(&self.file)?);
        Ok(())
    }

    fn extend(&mut self, to: u64) -> io::Result<()> {
        let from = self.ix.len;
        let mut buf = vec![0u8; usize::try_from(to.saturating_sub(from)).unwrap_or(0)];
        let n = read_full_at(&self.file, &mut buf, from)?;
        buf.truncate(n);
        index_body(&mut self.ix, &buf, from);
        self.ix.len = from + len_u64(n);
        self.ix.whole = buf.last().is_none_or(|&b| b == b'\n');
        Ok(())
    }

    fn refresh(&mut self) -> io::Result<bool> {
        let meta = match std::fs::symlink_metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        if (meta.dev(), meta.ino()) != self.id {
            let reopened = if self.writable {
                Self::open(&self.path)?
            } else {
                Self::open_read(&self.path)?
            };
            return Ok(match reopened {
                Some(side) => {
                    *self = side;
                    true
                }
                None => false,
            });
        }
        let len = meta.len();
        if len > self.ix.len && self.ix.len > 0 && self.ix.whole && !self.ix.foreign {
            self.extend(len)?;
        } else if len != self.ix.len {
            self.reindex()?;
        }
        Ok(true)
    }

    fn record_at(&self, at: u64, id: &str) -> io::Result<Option<Lockout>> {
        let mut buf = vec![0u8; HEAD + id.len() + 2];
        let n = read_full_at(&self.file, &mut buf, at)?;
        let line = buf.get(..n).and_then(|b| b.strip_suffix(b"\n"));
        Ok(line
            .and_then(parse_line)
            .filter(|(_, name)| *name == id)
            .map(|(l, _)| l))
    }

    fn locate(&mut self, id: &str) -> io::Result<Option<(u64, Lockout)>> {
        if let Some(&(at, _)) = self.ix.records.get(id) {
            if let Some(l) = self.record_at(at, id)? {
                return Ok(Some((at, l)));
            }
            self.reindex()?;
            if let Some(&(at, _)) = self.ix.records.get(id) {
                return Ok(self.record_at(at, id)?.map(|l| (at, l)));
            }
        }
        Ok(None)
    }

    fn get(&mut self, id: &str) -> io::Result<Option<Lockout>> {
        Ok(self.locate(id)?.map(|(_, l)| l))
    }

    fn put(&mut self, id: &str, l: Lockout) -> io::Result<()> {
        if let Some((at, have)) = self.locate(id)? {
            if have != l {
                self.file.write_all_at(&head(id, l), at)?;
            }
            self.ix.records.insert(id.to_owned(), (at, l));
            return Ok(());
        }
        let mut at = self.ix.len;
        if at == 0 {
            self.file.write_all_at(HEADER, 0)?;
            at = len_u64(HEADER.len());
        } else if !self.ix.whole {
            self.file.write_all_at(b"\n", at)?;
            at += 1;
            self.ix.dead += 1;
        }
        let line = record_line(id, l);
        self.file.write_all_at(&line, at)?;
        self.ix.len = at + len_u64(line.len());
        self.ix.whole = true;
        self.ix.records.insert(id.to_owned(), (at, l));
        Ok(())
    }

    fn delete(&mut self, id: &str) -> io::Result<()> {
        if let Some((at, _)) = self.locate(id)? {
            self.file.write_all_at(&[DELETED], at)?;
            self.ix.records.remove(id);
            self.ix.dead += 1;
        }
        Ok(())
    }

    /// Whole-file write renamed over the old: a short write leaves it.
    fn rewrite(&mut self, records: &[(String, Lockout)]) -> io::Result<()> {
        krb5_protocol::write_secret_file(&self.path, &render(records))
            .map_err(|e| named(&self.path, &e))?;
        *self = Self::open(&self.path)
            .map_err(|e| named(&self.path, &e))?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        Ok(())
    }

    fn records(&self) -> HashMap<String, Lockout> {
        self.ix
            .records
            .iter()
            .map(|(id, &(_, l))| (id.clone(), l))
            .collect()
    }

    fn compact(&mut self) -> io::Result<()> {
        let ats: Vec<(String, u64)> = self
            .ix
            .records
            .iter()
            .map(|(id, &(at, _))| (id.clone(), at))
            .collect();
        let mut live = Vec::with_capacity(ats.len());
        for (id, at) in ats {
            if let Some(l) = self.record_at(at, &id)? {
                live.push((id, l));
            }
        }
        self.rewrite(&live)
    }
}

fn make(db: &Path, records: &[(String, Lockout)]) -> io::Result<()> {
    let path = lockout_path(db);
    krb5_protocol::write_fresh_secret_file(&path, &render(records)).map_err(|e| named(&path, &e))
}

fn make_beside(db: &Path, records: &[(String, Lockout)]) -> io::Result<()> {
    let path = lockout_path(db);
    krb5_protocol::write_secret_file_like(&path, db, &render(records)).map_err(|e| named(&path, &e))
}

fn db_writable(db: &Path) -> bool {
    OpenOptions::new().read(true).write(true).open(db).is_ok()
}

pub(crate) fn ensure_lockout_file(db: &Path) {
    let path = lockout_path(db);
    if path.symlink_metadata().is_ok() || !db_writable(db) {
        return;
    }
    let _ = make(db, &[]);
}

fn open_for_writing(db: &Path) -> io::Result<Option<SideFile>> {
    let path = lockout_path(db);
    match SideFile::open(&path).map_err(|e| named(&path, &e))? {
        Some(side) if side.writable => Ok(Some(side)),
        Some(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{}: Permission denied", path.display()),
        )),
        None => Ok(None),
    }
}

// MIT: `fetch_lockout` (plugins/kdb/lmdb/kdb_lmdb.c:329-344)
#[must_use]
pub fn lockout_records(db: &Path) -> HashMap<String, Lockout> {
    match SideFile::open_read(&lockout_path(db)) {
        Ok(Some(side)) if !side.ix.foreign => side.records(),
        _ => HashMap::new(),
    }
}

// MIT: `klmdb_iterate` (plugins/kdb/lmdb/kdb_lmdb.c:841-888)
pub fn merge_lockout_file(store: &mut PrincipalStore, db: &Path) {
    let records = lockout_records(db);
    if !records.is_empty() {
        store.merge_lockout_records(&records);
    }
}

pub(crate) fn store_records(store: &PrincipalStore) -> Vec<(String, Lockout)> {
    let mut out: Vec<(String, Lockout)> = store
        .debug_principals()
        .map(|p| (p.id(), Lockout::of(p)))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

// MIT: `klmdb_create` (plugins/kdb/lmdb/kdb_lmdb.c:575-661)
// MIT: `klmdb_put_principal` (plugins/kdb/lmdb/kdb_lmdb.c:781-809)
/// Merge keeps an existing record, as an iprop load keeps the replica's.
pub(crate) fn write_loaded(
    db: &Path,
    records: &[(String, Lockout)],
    merge: bool,
) -> io::Result<()> {
    let Some(mut side) = open_for_writing(db)? else {
        return make(db, records);
    };
    let content: Vec<(String, Lockout)> = if merge && !side.ix.foreign {
        records
            .iter()
            .map(|(id, l)| {
                let kept = side.ix.records.get(id).map_or(*l, |&(_, have)| have);
                (id.clone(), kept)
            })
            .collect()
    } else {
        records.to_vec()
    };
    side.rewrite(&content)
}

pub(crate) fn ensure(db: &Path) -> io::Result<()> {
    match open_for_writing(db)? {
        Some(_) => Ok(()),
        None => make_beside(db, &[]),
    }
}

// MIT: `klmdb_delete_principal` (plugins/kdb/lmdb/kdb_lmdb.c:819-838)
pub(crate) fn reconcile_ids(store: &PrincipalStore, db: &Path, ids: &[String]) -> io::Result<()> {
    let gone: Vec<String> = ids
        .iter()
        .filter(|id| store.principal_by_id(id).is_none())
        .cloned()
        .collect();
    store.reconcile_lockout_deletes(db, &gone)
}

pub(crate) fn reconcile(store: &PrincipalStore, db: &Path, make_missing: bool) -> io::Result<()> {
    let Some(mut side) = open_for_writing(db)? else {
        return if make_missing {
            make_beside(db, &store_records(store))
        } else {
            Ok(())
        };
    };
    if side.ix.foreign {
        return if make_missing {
            side.rewrite(&store_records(store))
        } else {
            Ok(())
        };
    }
    if make_missing {
        // A load or fresh create owns the records: write memory.
        let want = store_records(store);
        for (id, l) in &want {
            if side.ix.records.get(id).map(|&(_, have)| have) != Some(*l) {
                side.put(id, *l)?;
            }
        }
        let keep: HashSet<&str> = want.iter().map(|(id, _)| id.as_str()).collect();
        let gone: Vec<String> = side
            .ix
            .records
            .keys()
            .filter(|id| !keep.contains(id.as_str()))
            .cloned()
            .collect();
        for id in gone {
            side.delete(&id)?;
        }
        if side.ix.dead > side.ix.records.len() {
            side.rewrite(&want)?;
        }
        return Ok(());
    }
    // A running store's full save keeps the lockout the KDC wrote.
    let gone: Vec<String> = side
        .ix
        .records
        .keys()
        .filter(|id| store.principal_by_id(id).is_none())
        .cloned()
        .collect();
    for id in &gone {
        side.delete(id)?;
    }
    if side.ix.dead > side.ix.records.len() {
        side.compact()?;
    }
    Ok(())
}

pub(crate) fn check_writable(db: &Path) -> io::Result<()> {
    let path = lockout_path(db);
    match open_file(&path, true) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(named(&path, &e)),
    }
}

fn record(
    side: &mut SideFile,
    id: &str,
    p: &Principal,
    stamp: u32,
    update: LockoutUpdate,
) -> io::Result<()> {
    let base = side.get(id)?.unwrap_or_else(|| Lockout::of(p));
    side.put(id, update.apply(base, stamp))
}

#[derive(Debug, Default)]
pub(crate) struct LockoutState {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    side: Option<SideFile>,
    overlay: HashMap<String, Lockout>,
    told_absent: bool,
    told_unwritable: bool,
}

impl Inner {
    fn side(&mut self, db: &Path) -> Option<&mut SideFile> {
        let path = lockout_path(db);
        if self.side.as_ref().is_none_or(|s| s.path != path) {
            self.side = SideFile::open(&path).ok().flatten();
            if self
                .side
                .as_ref()
                .is_some_and(|s| s.writable && !s.ix.foreign)
            {
                self.overlay.clear();
            }
        }
        let fresh = self.side.as_mut()?.refresh().unwrap_or(false);
        if !fresh {
            self.side = None;
        }
        self.side.as_mut().filter(|s| !s.ix.foreign)
    }

    fn tell_once(flag: &mut bool, msg: &str) {
        if !*flag {
            *flag = true;
            tracing::warn!(
                event = krb5_log::events::KDC_ISSUE,
                correlation_id = krb5_log::current_correlation_id(),
                component = "krb5-kdc",
                outcome = "error",
                detail = msg,
            );
            klog::syslog(Severity::Warning, msg);
        }
    }
}

impl LockoutState {
    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn reconcile_deletes(&self, db: &Path, gone: &[String]) -> io::Result<()> {
        if gone.is_empty() {
            return Ok(());
        }
        let mut inner = self.inner();
        for id in gone {
            inner.overlay.remove(id);
        }
        let Some(side) = inner.side(db) else {
            return Ok(());
        };
        for id in gone {
            side.delete(id)?;
        }
        if side.ix.dead > side.ix.records.len() {
            side.compact()?;
        }
        Ok(())
    }

    pub(crate) fn lookup(
        &self,
        db: Option<&Path>,
        lock: Option<&Arc<DbLock>>,
        p: &Principal,
    ) -> Lockout {
        let mut inner = self.inner();
        let id = p.id();
        let mut stored = None;
        let mut writable = false;
        if let (Some(db), Some(lock)) = (db, lock)
            && let Ok(_held) = lock.hold(DbLockMode::Shared)
            && let Some(side) = inner.side(db)
        {
            writable = side.writable;
            stored = side.get(&id).ok().flatten();
        }
        if writable {
            inner.overlay.remove(&id);
        }
        inner
            .overlay
            .get(&id)
            .copied()
            .or(stored)
            .unwrap_or_else(|| Lockout::of(p))
    }

    pub(crate) fn update(
        &self,
        db: Option<&Path>,
        lock: Option<&Arc<DbLock>>,
        p: &Principal,
        stamp: u32,
        update: LockoutUpdate,
    ) {
        let id = p.id();
        let held = db
            .zip(lock)
            .map(|(db, lock)| (db, lock.hold(DbLockMode::Exclusive)));
        let mut inner = self.inner();
        if let Some((db, held)) = held {
            let written = match held {
                Err(e) => Some(Err(io::Error::new(e.kind(), e.to_string()))),
                Ok(_held) => match inner.side(db) {
                    Some(side) if side.writable => Some(record(side, &id, p, stamp, update)),
                    Some(_) => Some(Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Permission denied",
                    ))),
                    None => None,
                },
            };
            match written {
                Some(Ok(())) => {
                    inner.overlay.remove(&id);
                    return;
                }
                Some(Err(e)) => {
                    let msg = format!(
                        "{}: {e}: lockout counting is off",
                        lockout_path(db).display()
                    );
                    Inner::tell_once(&mut inner.told_unwritable, &msg);
                    return;
                }
                None => {
                    if db_writable(db)
                        && lockout_path(db).symlink_metadata().is_err()
                        && make(db, &[]).is_ok()
                        && let Some(side) = inner.side(db)
                        && side.writable
                        && record(side, &id, p, stamp, update).is_ok()
                    {
                        inner.overlay.remove(&id);
                        return;
                    }
                    if !inner.told_absent {
                        let path = lockout_path(db);
                        let why = match SideFile::open(&path) {
                            Err(e) => klog::os_error_text(&e),
                            Ok(Some(_)) => "no lockout file".to_owned(),
                            Ok(None) => "does not exist".to_owned(),
                        };
                        let msg = format!(
                            "{path}: {why}: lockout counting is off",
                            path = path.display()
                        );
                        Inner::tell_once(&mut inner.told_absent, &msg);
                    }
                    return;
                }
            }
        }
        let base = inner
            .overlay
            .get(&id)
            .copied()
            .unwrap_or_else(|| Lockout::of(p));
        inner.overlay.insert(id, update.apply(base, stamp));
    }

    pub(crate) fn rename_row(
        &self,
        db: Option<&Path>,
        lock: Option<&Arc<DbLock>>,
        old_id: &str,
        new: &Principal,
    ) {
        let new_id = new.id();
        let mut inner = self.inner();
        let overlaid = inner.overlay.remove(old_id);
        let held = db
            .zip(lock)
            .map(|(db, lock)| (db, lock.hold(DbLockMode::Exclusive)));
        if let Some((db, Ok(_held))) = held {
            let moved = match inner.side(db) {
                Some(side) if side.writable => match side.get(old_id).ok().flatten().or(overlaid) {
                    Some(v) => side
                        .put(&new_id, v)
                        .and_then(|()| side.delete(old_id))
                        .is_ok(),
                    None => true,
                },
                _ => false,
            };
            if moved {
                inner.overlay.remove(&new_id);
                return;
            }
        }
        if let Some(v) = overlaid {
            inner.overlay.insert(new_id, v);
        }
    }

    pub(crate) fn overlay_get(&self, id: &str) -> Option<Lockout> {
        self.inner().overlay.get(id).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db(tag: &str) -> PathBuf {
        krb5_testkit::scratch_dir(&format!("krb5-lockout-{tag}")).join("principal")
    }

    fn lo(last_success: u32, last_failed: u32, fail_auth_count: u32) -> Lockout {
        Lockout {
            last_success,
            last_failed,
            fail_auth_count,
        }
    }

    fn recs(pairs: &[(&str, Lockout)]) -> Vec<(String, Lockout)> {
        pairs.iter().map(|(id, l)| ((*id).to_owned(), *l)).collect()
    }

    #[test]
    fn an_update_torn_by_a_crash_reads_as_no_record() {
        let db = db("tear");
        let path = lockout_path(&db);
        write_loaded(&db, &recs(&[("a@R", lo(1, 2, 3))]), false).unwrap();
        let at = len_u64(HEADER.len());
        let old = head("a@R", lo(1, 2, 3));
        let new = head("a@R", lo(1, 999, 4));
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        // A write cut short keeps the new bytes on one side of the cut and the old on the other.
        for cut in 1..HEAD {
            for (first, rest) in [(&new, &old), (&old, &new)] {
                let mut torn = *first;
                torn[cut..].copy_from_slice(&rest[cut..]);
                if torn == old || torn == new {
                    continue;
                }
                file.write_all_at(&torn, at).unwrap();
                assert!(!lockout_records(&db).contains_key("a@R"), "cut at {cut}");
            }
        }
        file.write_all_at(&new, at).unwrap();
        assert_eq!(lockout_records(&db)["a@R"], lo(1, 999, 4));
    }
}
