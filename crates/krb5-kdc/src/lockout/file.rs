//! `principal.lockout`: the database's lockout attributes beside it, MIT klmdb's lockout split
//! for a dump store. `kdb5_util create` and `load` make it; the KDC updates a record in place
//! under the database's exclusive lock, with no temporary file, rename or sync, and never makes
//! the file; every reader merges it over the database's own values, which stay the fallback for
//! a principal it has no record of. A tool that writes the whole file writes a new one and
//! renames it over the old, as a database save does, so a rewrite cut short leaves the old file
//! whole. No open follows a symlink, so a link planted as the file is never written through.
//!
//! The file is text: a header line, then one line per principal holding its three attributes as
//! ten-digit fields, a CRC-32 of them and its name, and its name, so a record keeps its offset
//! and an update rewrites only its digits and checksum, in one write. A deleted principal's
//! line is marked with `#` and dropped when the file is next rewritten. A line that does not
//! parse or whose checksum fails, an update torn by a crash included, is no record: that
//! principal's values are the database's again, the loss MIT accepts for lockout records it
//! never syncs, and never a value no write made.
//! MIT `open_lmdb_env` (`plugins/kdb/lmdb/kdb_lmdb.c:265-268`): the lockout environment is never synced, durability not being worth it.

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

/// The side file's suffix: `principal.lockout`, which Fedora's `file_contexts` labels as it
/// labels the database (`principal.*`), never as a lock file (`principal.*.ok`).
pub const SUFFIX_LOCKOUT: &str = ".lockout";

const HEADER: &[u8] = b"kerber-rust lockout 1\n";
/// The digits of one attribute.
const FIELD: usize = 10;
/// The three attributes and the spaces between them.
const VALUES: usize = 3 * FIELD + 2;
/// The record's checksum, eight hex digits.
const SUM: usize = 8;
/// The attributes, a space and their checksum: what an update rewrites, in one write.
const HEAD: usize = VALUES + 1 + SUM;
const DELETED: u8 = b'#';

/// CRC-32 (IEEE 802.3), the table of its reflected polynomial.
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

/// The checksum a record carries: the CRC-32 of its attributes' digits, a space and its name.
fn checksum(values: &[u8], name: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in values.iter().chain(b" ").chain(name) {
        c = CRC_TABLE[usize::from(c.to_le_bytes()[0] ^ b)] ^ (c >> 8);
    }
    !c
}

/// The side file of the database at `db`.
#[must_use]
pub fn lockout_path(db: &Path) -> PathBuf {
    suffixed(db, SUFFIX_LOCKOUT)
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// `e` with `path` in its text, as a tool reports it.
fn named(path: &Path, e: &io::Error) -> io::Error {
    io::Error::new(
        e.kind(),
        format!("{}: {}", path.display(), klog::os_error_text(e)),
    )
}

/// A record's attributes and checksum, as an update writes them.
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

/// The whole text of a side file holding `records`.
fn render(records: &[(String, Lockout)]) -> Vec<u8> {
    let mut text = HEADER.to_vec();
    for (id, l) in records {
        text.extend_from_slice(&record_line(id, *l));
    }
    text
}

/// A line's attributes and principal, its newline taken off; `None` for a line that is no
/// record: a deleted one's `#`, a torn one, one whose checksum fails.
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

/// What one read of the whole file found.
#[derive(Debug, Default)]
struct Index {
    /// Each principal's record: its line's offset and its attributes when read.
    records: HashMap<String, (u64, Lockout)>,
    /// Lines that are no live record: deleted, superseded or unreadable.
    dead: usize,
    /// The file's length when read.
    len: u64,
    /// Whether the file ends with a whole line, so a record can be added after it.
    whole: bool,
    /// The file is not empty and does not start with this format's header: it is left alone.
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
    let mut off = HEADER.len();
    for line in body.split_inclusive(|&b| b == b'\n') {
        let at = len_u64(off);
        off += line.len();
        match line.strip_suffix(b"\n").and_then(parse_line) {
            Some((l, name)) => {
                if ix.records.insert(name.to_owned(), (at, l)).is_some() {
                    ix.dead += 1;
                }
            }
            None => ix.dead += 1,
        }
    }
    ix
}

/// Read the whole of `file`, however short its reads.
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

/// Read up to `buf.len()` bytes at `at`; the count read, short only at the end of the file.
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

/// Open the regular file at `path`, read-write or read-only: never through a symlink
/// (`O_NOFOLLOW`, so a planted one fails the open with `ELOOP`), and never waiting on a FIFO.
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

/// The side file, open, with what the last read of it found.
#[derive(Debug)]
pub(crate) struct SideFile {
    path: PathBuf,
    file: File,
    writable: bool,
    /// The file's device and inode when opened.
    id: (u64, u64),
    ix: Index,
}

impl SideFile {
    /// Open the side file at `path` read-write, else read-only; `None` when there is none.
    /// Nothing is created.
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

    /// Open the side file at `path` to read it alone; `None` when there is none.
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

    /// Read the file again when it is no longer as this handle read it: another file at its
    /// path (a symlink included, which then fails to open), or another length. `false` when it
    /// is gone.
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
        if meta.len() != self.ix.len {
            self.reindex()?;
        }
        Ok(true)
    }

    /// The record at `at` when it still is `id`'s.
    fn record_at(&self, at: u64, id: &str) -> io::Result<Option<Lockout>> {
        let mut buf = vec![0u8; HEAD + id.len() + 2];
        let n = read_full_at(&self.file, &mut buf, at)?;
        let line = buf.get(..n).and_then(|b| b.strip_suffix(b"\n"));
        Ok(line
            .and_then(parse_line)
            .filter(|(_, name)| *name == id)
            .map(|(l, _)| l))
    }

    /// Where `id`'s record is now, read again when the file was rewritten under the index.
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

    /// `id`'s attributes as stored now; `None` when the file has no record of it.
    fn get(&mut self, id: &str) -> io::Result<Option<Lockout>> {
        Ok(self.locate(id)?.map(|(_, l)| l))
    }

    /// Store `l` as `id`'s record: its digits and checksum rewritten where the record is, in one
    /// write, else a line added at the end of the file (after the header in an empty file, after
    /// a newline when the last line is torn).
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

    /// Mark `id`'s record deleted.
    fn delete(&mut self, id: &str) -> io::Result<()> {
        if let Some((at, _)) = self.locate(id)? {
            self.file.write_all_at(&[DELETED], at)?;
            self.ix.records.remove(id);
            self.ix.dead += 1;
        }
        Ok(())
    }

    /// Replace the file with one holding `records` alone: a new file written beside it and
    /// renamed over it, keeping its owner, mode and SELinux context, as a database save does
    /// ([`krb5_protocol::write_secret_file`]); the old file stays whole until the new one is in
    /// place. Only a tool rewrites; the KDC never does.
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
}

/// Make the side file of `db` holding `records`: a new 0600 file of the writer's, written beside
/// its path and renamed onto it, with the SELinux context a new file at its path takes
/// ([`krb5_protocol::write_fresh_secret_file`]).
fn make(db: &Path, records: &[(String, Lockout)]) -> io::Result<()> {
    let path = lockout_path(db);
    krb5_protocol::write_fresh_secret_file(&path, &render(records)).map_err(|e| named(&path, &e))
}

/// Make the side file of `db` holding `records` beside a database that stays where it is (a
/// `load -update`, a save that makes the database): a new file with the database's owner, group
/// and permission bits and the SELinux context a new file at its path takes
/// ([`krb5_protocol::write_secret_file_like`]), as install.md's upgrade step makes it by hand, so
/// a root `load -update` of a realm a service user owns leaves that user's saves writable.
fn make_beside(db: &Path, records: &[(String, Lockout)]) -> io::Result<()> {
    let path = lockout_path(db);
    krb5_protocol::write_secret_file_like(&path, db, &render(records)).map_err(|e| named(&path, &e))
}

/// The side file of `db` for a writer, opened read-write; `None` when there is none.
///
/// # Errors
///
/// The error of the open, the file named in its text: one the writer may only read is
/// `PermissionDenied`, a symlink `ELOOP`.
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

/// Each principal's record in `db`'s side file, read now; empty when there is none, or it
/// cannot be read or is no side file. Read it holding the database's lock.
/// MIT `fetch_lockout` (`plugins/kdb/lmdb/kdb_lmdb.c:329-344`): a reader takes the lockout record when there is one and ignores a failure to read it.
#[must_use]
pub fn lockout_records(db: &Path) -> HashMap<String, Lockout> {
    match SideFile::open_read(&lockout_path(db)) {
        Ok(Some(side)) if !side.ix.foreign => side.records(),
        _ => HashMap::new(),
    }
}

/// Give each principal of `store` its record in `db`'s side file, when it has one: what a read
/// of the database gives every reader. Read it holding the database's lock.
/// MIT `klmdb_iterate` (`plugins/kdb/lmdb/kdb_lmdb.c:841-888`): every entry read takes its lockout record.
pub fn merge_lockout_file(store: &mut PrincipalStore, db: &Path) {
    let records = lockout_records(db);
    if !records.is_empty() {
        store.merge_lockout_records(&records);
    }
}

/// The records a load or a create writes: each principal's attributes as `store` holds them.
pub(crate) fn store_records(store: &PrincipalStore) -> Vec<(String, Lockout)> {
    let mut out: Vec<(String, Lockout)> = store
        .debug_principals()
        .map(|p| (p.id(), Lockout::of(p)))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// After a full load or a create, holding the database's exclusive lock: `records` become the
/// side file of `db`, made when it is not there; with `merge`, a principal it already has a
/// record of keeps that record, as an iprop load keeps a replica's own. A principal the load
/// left out loses its record.
/// MIT `klmdb_create` (`plugins/kdb/lmdb/kdb_lmdb.c:575-661`): a create or load makes the lockout environment when there is none and does not empty it.
/// MIT `klmdb_put_principal` (`plugins/kdb/lmdb/kdb_lmdb.c:781-809`): each loaded entry's lockout attributes are written, kept under `merge_nra` when a record exists.
///
/// # Errors
///
/// The I/O error of opening, making or writing the side file, the file named in its text; one
/// the writer may only read is `PermissionDenied`.
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

/// Make `db`'s side file when it is not there, holding the database's exclusive lock, owned and
/// moded as the database ([`make_beside`]): a load whose dump has no principal record.
///
/// # Errors
///
/// As [`write_loaded`].
pub(crate) fn ensure(db: &Path) -> io::Result<()> {
    match open_for_writing(db)? {
        Some(_) => Ok(()),
        None => make_beside(db, &[]),
    }
}

/// After a change written to the database `db` holding its exclusive lock, with the store read
/// again under that lock: bring the side file in line with `store`. A principal whose
/// attributes the change set (an unlock, a key change, a load's update) gets them as its record,
/// a new one a record, a deleted one's record is marked, a renamed one's moves with it; a file
/// with more marked lines than records is rewritten. With `make_missing` a missing side file
/// is made, owned and moded as the database ([`make_beside`]); without it nothing is made. One
/// that is no side file is left as it is.
/// MIT `klmdb_put_principal` (`plugins/kdb/lmdb/kdb_lmdb.c:781-809`): a put whose mask names a lockout attribute, or a new entry, writes the lockout record.
/// MIT `klmdb_delete_principal` (`plugins/kdb/lmdb/kdb_lmdb.c:819-838`): a delete removes the lockout record too.
///
/// # Errors
///
/// As [`write_loaded`].
pub(crate) fn reconcile(store: &PrincipalStore, db: &Path, make_missing: bool) -> io::Result<()> {
    let want = store_records(store);
    let Some(mut side) = open_for_writing(db)? else {
        return if make_missing {
            make_beside(db, &want)
        } else {
            Ok(())
        };
    };
    if side.ix.foreign {
        return if make_missing {
            side.rewrite(&want)
        } else {
            Ok(())
        };
    }
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
    Ok(())
}

/// Whether a writer may change `db`'s side file: there is none, or it is a regular file that
/// opens read-write. A symlink there is refused (`ELOOP`), never followed.
///
/// # Errors
///
/// The error of opening an existing side file read-write, the file named in its text.
pub(crate) fn check_writable(db: &Path) -> io::Result<()> {
    let path = lockout_path(db);
    match open_file(&path, true) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(named(&path, &e)),
    }
}

/// Apply `update` at `stamp` to `id`'s record as `side` holds it now (else to `p`'s attributes)
/// and write it.
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

/// What a process keeps of the lockout attributes: the database's side file, open, and the
/// attributes it records in memory while the database has none it may write. Shared by every
/// copy of a store and kept across its reads of the database.
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
    /// The side file of `db`, opened when this process has none open for it; on the first
    /// opening of one it may write, the attributes kept in memory give way to it.
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

    /// `p`'s lockout attributes now: its record in the side file of `db`, opened and read
    /// holding `lock` shared, else what the store read; while this process has no side file it
    /// may write, what it records for `p` in memory comes first. Once it has one, what it kept
    /// in memory for `p` is dropped, so an update it could not write is lost, as MIT's KDC
    /// loses a lockout write that fails.
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

    /// Record `update` for `p` at `stamp`: in its side-file record, holding `lock` exclusively,
    /// starting from the record as it is then (else from `p`'s attributes), which drops what
    /// was kept in memory for `p`; without a side file this process may write, or when the
    /// write fails, in memory, which is said once for each cause in the log. The database's lock
    /// is taken before this state's mutex, so lookups go on while an update waits for the lock.
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
                        "{}: {e}: lockout attributes are kept in memory",
                        lockout_path(db).display()
                    );
                    Inner::tell_once(&mut inner.told_unwritable, &msg);
                }
                None if !inner.told_absent => {
                    let path = lockout_path(db);
                    let why = match SideFile::open(&path) {
                        Err(e) => klog::os_error_text(&e),
                        Ok(Some(_)) => "no lockout file".to_owned(),
                        Ok(None) => "does not exist".to_owned(),
                    };
                    let msg = format!(
                        "{}: {why}: lockout attributes are kept in memory until it is made",
                        path.display()
                    );
                    Inner::tell_once(&mut inner.told_absent, &msg);
                }
                None => {}
            }
        }
        let base = inner
            .overlay
            .get(&id)
            .copied()
            .unwrap_or_else(|| Lockout::of(p));
        inner.overlay.insert(id, update.apply(base, stamp));
    }

    /// Zero the failed authentication count kept in memory for `id`, when one is kept.
    pub(crate) fn overlay_zero(&self, id: &str) {
        if let Some(l) = self.inner().overlay.get_mut(id) {
            l.fail_auth_count = 0;
        }
    }

    /// The attributes kept in memory for `id`, if any.
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
    fn a_record_is_rewritten_in_place_and_a_new_one_added_at_the_end() {
        let db = db("put");
        write_loaded(
            &db,
            &recs(&[("a@R", lo(1, 2, 3)), ("b@R", lo(0, 0, 0))]),
            false,
        )
        .unwrap();
        let path = lockout_path(&db);
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        let before = std::fs::read(&path).unwrap();
        assert!(before.starts_with(HEADER));
        let mut side = SideFile::open(&path).unwrap().unwrap();
        side.put("a@R", lo(1, 4_294_967_295, 4)).unwrap();
        let after = std::fs::read(&path).unwrap();
        assert_eq!(
            after.len(),
            before.len(),
            "an update rewrites digits and checksum only"
        );
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), meta.ino());
        let changed = before.iter().zip(&after).filter(|(x, y)| x != y).count();
        assert!(changed <= HEAD, "{changed} bytes changed");
        side.put("c@R", lo(5, 6, 7)).unwrap();
        let got = lockout_records(&db);
        assert_eq!(got["a@R"], lo(1, 4_294_967_295, 4));
        assert_eq!(got["b@R"], lo(0, 0, 0));
        assert_eq!(got["c@R"], lo(5, 6, 7));
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), meta.ino());
    }

    #[test]
    fn a_torn_or_unreadable_line_is_no_record_and_a_new_one_follows_a_newline() {
        let db = db("torn");
        let path = lockout_path(&db);
        let mut text = HEADER.to_vec();
        text.extend_from_slice(&record_line("a@R", lo(1, 1, 1)));
        text.extend_from_slice(b"0000000001 zz 0000000001 b@R\n");
        text.extend_from_slice(b"00000000");
        std::fs::write(&path, &text).unwrap();
        assert_eq!(lockout_records(&db).len(), 1);
        let mut side = SideFile::open(&path).unwrap().unwrap();
        side.put("c@R", lo(2, 2, 2)).unwrap();
        let got = lockout_records(&db);
        assert_eq!(got.len(), 2);
        assert_eq!(got["c@R"], lo(2, 2, 2));
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

    #[test]
    fn a_rewrite_renames_a_new_file_over_the_old_and_keeps_its_mode() {
        use std::os::unix::fs::PermissionsExt as _;
        let db = db("rename");
        let path = lockout_path(&db);
        write_loaded(&db, &recs(&[("a@R", lo(1, 1, 1))]), false).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let before = std::fs::metadata(&path).unwrap();
        write_loaded(&db, &recs(&[("b@R", lo(2, 2, 2))]), false).unwrap();
        let after = std::fs::metadata(&path).unwrap();
        assert_ne!(
            after.ino(),
            before.ino(),
            "a new file, never emptied in place"
        );
        assert_eq!(after.mode() & 0o777, 0o640);
        let got = lockout_records(&db);
        assert_eq!((got.len(), got["b@R"]), (1, lo(2, 2, 2)));
    }

    #[test]
    fn no_open_follows_a_symlink_planted_as_the_side_file() {
        let db = db("symlink");
        let path = lockout_path(&db);
        let victim = path.with_file_name("victim");
        let content = render(&recs(&[("a@R", lo(1, 1, 7))]));
        std::fs::write(&victim, &content).unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        assert!(SideFile::open(&path).is_err());
        assert!(lockout_records(&db).is_empty(), "never read through it");
        let refused = check_writable(&db).unwrap_err();
        assert!(
            refused
                .to_string()
                .contains("principal.lockout: Too many levels of symbolic links"),
            "{refused}"
        );
        assert!(write_loaded(&db, &recs(&[("a@R", lo(0, 0, 0))]), false).is_err());
        assert!(ensure(&db).is_err());
        let state = LockoutState::default();
        let lock = Arc::new(DbLock::create(&db).unwrap());
        lock.create_policy_lock().unwrap();
        lock.unlock().unwrap();
        let (store, _) = crate::testrealm::bootstrap_documented().unwrap();
        let p = store.debug_principals().next().unwrap().clone();
        let update = LockoutUpdate {
            set_last_failure: true,
            ..LockoutUpdate::default()
        };
        state.update(Some(&db), Some(&lock), &p, 100, update);
        assert_eq!(state.overlay_get(&p.id()).unwrap().fail_auth_count, 1);
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            content,
            "never written through"
        );
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn an_empty_file_made_by_hand_takes_the_kdcs_records() {
        let db = db("empty");
        let path = lockout_path(&db);
        std::fs::write(&path, b"").unwrap();
        let mut side = SideFile::open(&path).unwrap().unwrap();
        assert!(side.writable && !side.ix.foreign);
        side.put("a@R", lo(0, 5, 1)).unwrap();
        assert!(std::fs::read(&path).unwrap().starts_with(HEADER));
        assert_eq!(lockout_records(&db)["a@R"], lo(0, 5, 1));
    }

    #[test]
    fn a_file_of_another_format_is_read_as_none_and_rewritten_only_by_a_load() {
        let db = db("foreign");
        let path = lockout_path(&db);
        std::fs::write(&path, b"not a lockout file\n").unwrap();
        assert!(lockout_records(&db).is_empty());
        let (store, _) = crate::testrealm::bootstrap_documented().unwrap();
        reconcile(&store, &db, false).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"not a lockout file\n");
        write_loaded(&db, &recs(&[("a@R", lo(1, 2, 3))]), true).unwrap();
        assert_eq!(lockout_records(&db)["a@R"], lo(1, 2, 3));
    }

    #[test]
    fn a_deleted_record_is_marked_and_dropped_by_the_next_rewrite() {
        let db = db("delete");
        let path = lockout_path(&db);
        write_loaded(
            &db,
            &recs(&[("a@R", lo(1, 1, 1)), ("b@R", lo(2, 2, 2))]),
            false,
        )
        .unwrap();
        let mut side = SideFile::open(&path).unwrap().unwrap();
        side.delete("a@R").unwrap();
        assert!(std::fs::read(&path).unwrap().contains(&DELETED));
        assert_eq!(lockout_records(&db).len(), 1);
        side.rewrite(&recs(&[("b@R", lo(2, 2, 2))])).unwrap();
        assert!(!std::fs::read(&path).unwrap().contains(&DELETED));
        assert_eq!(lockout_records(&db)["b@R"], lo(2, 2, 2));
    }

    #[test]
    fn a_handle_follows_another_writers_rewrite() {
        let db = db("follow");
        let path = lockout_path(&db);
        write_loaded(
            &db,
            &recs(&[("a@R", lo(1, 1, 1)), ("b@R", lo(2, 2, 2))]),
            false,
        )
        .unwrap();
        let mut side = SideFile::open(&path).unwrap().unwrap();
        assert_eq!(side.get("b@R").unwrap(), Some(lo(2, 2, 2)));
        write_loaded(
            &db,
            &recs(&[("b@R", lo(9, 9, 9)), ("a@R", lo(8, 8, 8))]),
            false,
        )
        .unwrap();
        assert!(side.refresh().unwrap());
        assert_eq!(side.get("b@R").unwrap(), Some(lo(9, 9, 9)));
        side.put("a@R", lo(7, 7, 7)).unwrap();
        assert_eq!(lockout_records(&db)["a@R"], lo(7, 7, 7));
        assert_eq!(lockout_records(&db)["b@R"], lo(9, 9, 9));
    }

    #[test]
    fn a_merging_load_keeps_existing_records_and_drops_absent_principals() {
        let db = db("merge");
        write_loaded(
            &db,
            &recs(&[("a@R", lo(1, 1, 1)), ("gone@R", lo(3, 3, 3))]),
            false,
        )
        .unwrap();
        write_loaded(
            &db,
            &recs(&[("a@R", lo(0, 0, 0)), ("new@R", lo(0, 5, 5))]),
            true,
        )
        .unwrap();
        let got = lockout_records(&db);
        assert_eq!(got.len(), 2);
        assert_eq!(got["a@R"], lo(1, 1, 1));
        assert_eq!(got["new@R"], lo(0, 5, 5));
    }
}
