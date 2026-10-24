//! MIT's iprop log; lock the database first or the two deadlock.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use nix::fcntl::Flock;

use crate::dblock::{FileLock, set_file_lock};

use crate::store::iprop_xdr::{UlogTime, encode_incr_update, walk_incr_update};
use crate::store::{IPROP_FULL_RESYNC, IPROP_NIL, IPROP_OK};

// MIT: `KDB_ULOG_HDR_MAGIC` (include/kdb_log.h:37-37)
pub const KDB_ULOG_HDR_MAGIC: u32 = 0x0666_2323;
// MIT: `KDB_ULOG_MAGIC` (include/kdb_log.h:36-36)
pub const KDB_ULOG_MAGIC: u32 = 0x0666_1212;
// MIT: `KDB_VERSION` (include/kdb_log.h:24-24)
pub const KDB_VERSION: u16 = 1;
// MIT: `KDB_STABLE` (include/kdb_log.h:29-29)
pub const KDB_STABLE: u16 = 1;
// MIT: `KDB_UNSTABLE` (include/kdb_log.h:30-30)
pub const KDB_UNSTABLE: u16 = 2;
// MIT: `ULOG_BLOCK` (include/kdb_log.h:48-48)
pub const ULOG_BLOCK: u16 = 2048;
// MIT: `MAXLOGLEN` (include/kdb_log.h:50-50)
pub const MAXLOGLEN: u64 = 0x1000_0000;

const HDR_LEN: u64 = 40;
const ENT_HDR_LEN: usize = 28;
const ENT_DATA_AT: usize = 24;
const STATE_AT: u64 = 36;

#[derive(Debug, thiserror::Error)]
pub enum UlogError {
    #[error("{}", strerror(.0))]
    Io(#[from] io::Error),
    #[error("Update log is corrupt")]
    Corrupt,
    #[error("Update log conversion error")]
    Conv,
    #[error("Generic update log error")]
    Error,
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UlogLast {
    pub sno: u32,
    pub time: UlogTime,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UlogHeader {
    pub hmagic: u32,
    pub db_version_num: u16,
    pub num: u32,
    pub first_time: UlogTime,
    pub last_time: UlogTime,
    pub first_sno: u32,
    pub last_sno: u32,
    pub state: u16,
    pub block: u16,
}

fn ne32(b: &[u8], at: usize) -> u32 {
    let mut w = [0u8; 4];
    w.copy_from_slice(&b[at..at + 4]);
    u32::from_ne_bytes(w)
}

fn ne16(b: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([b[at], b[at + 1]])
}

impl UlogHeader {
    fn decode(b: &[u8; 40]) -> Self {
        Self {
            hmagic: ne32(b, 0),
            db_version_num: ne16(b, 4),
            num: ne32(b, 8),
            first_time: UlogTime {
                seconds: ne32(b, 12),
                useconds: ne32(b, 16),
            },
            last_time: UlogTime {
                seconds: ne32(b, 20),
                useconds: ne32(b, 24),
            },
            first_sno: ne32(b, 28),
            last_sno: ne32(b, 32),
            state: ne16(b, 36),
            block: ne16(b, 38),
        }
    }

    fn encode(&self) -> [u8; 40] {
        let mut b = [0u8; 40];
        b[0..4].copy_from_slice(&self.hmagic.to_ne_bytes());
        b[4..6].copy_from_slice(&self.db_version_num.to_ne_bytes());
        b[8..12].copy_from_slice(&self.num.to_ne_bytes());
        b[12..16].copy_from_slice(&self.first_time.seconds.to_ne_bytes());
        b[16..20].copy_from_slice(&self.first_time.useconds.to_ne_bytes());
        b[20..24].copy_from_slice(&self.last_time.seconds.to_ne_bytes());
        b[24..28].copy_from_slice(&self.last_time.useconds.to_ne_bytes());
        b[28..32].copy_from_slice(&self.first_sno.to_ne_bytes());
        b[32..36].copy_from_slice(&self.last_sno.to_ne_bytes());
        b[36..38].copy_from_slice(&self.state.to_ne_bytes());
        b[38..40].copy_from_slice(&self.block.to_ne_bytes());
        b
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct EntHeader {
    umagic: u32,
    sno: u32,
    time: UlogTime,
    commit: bool,
    size: u32,
}

impl EntHeader {
    fn decode(b: &[u8]) -> Self {
        Self {
            umagic: ne32(b, 0),
            sno: ne32(b, 4),
            time: UlogTime {
                seconds: ne32(b, 8),
                useconds: ne32(b, 12),
            },
            commit: ne32(b, 16) != 0,
            size: ne32(b, 20),
        }
    }

    fn encode(&self) -> [u8; ENT_HDR_LEN] {
        let mut b = [0u8; ENT_HDR_LEN];
        b[0..4].copy_from_slice(&self.umagic.to_ne_bytes());
        b[4..8].copy_from_slice(&self.sno.to_ne_bytes());
        b[8..12].copy_from_slice(&self.time.seconds.to_ne_bytes());
        b[12..16].copy_from_slice(&self.time.useconds.to_ne_bytes());
        b[16..20].copy_from_slice(&u32::from(self.commit).to_ne_bytes());
        b[20..24].copy_from_slice(&self.size.to_ne_bytes());
        b
    }
}

#[cfg(any(test, feature = "test-hooks"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UlogEntry {
    pub sno: u32,
    pub time: UlogTime,
    pub commit: bool,
    pub size: u32,
    pub name: String,
    pub deleted: bool,
    pub attrs: u32,
    pub update: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UlogUpdates {
    pub status: u32,
    pub last: UlogLast,
    pub updates: Vec<Vec<u8>>,
}

#[derive(Debug)]
enum Backing {
    File(File),
    #[cfg(any(test, feature = "test-hooks"))]
    Memory(Mutex<Vec<u8>>),
}

pub struct UlogBatch<'a> {
    ulog: &'a Ulog,
    hdr: UlogHeader,
    appended: bool,
    _held: Held<'a>,
}

impl UlogBatch<'_> {
    pub fn add_update(
        &mut self,
        name: &str,
        deleted: bool,
        kdbe: &[u8],
    ) -> Result<UlogLast, UlogError> {
        self.appended = true;
        if self.hdr.last_sno == u32::MAX {
            self.hdr = self.ulog.reset()?;
            self.hdr.state = KDB_UNSTABLE;
        }
        let last = UlogLast {
            sno: self.hdr.last_sno.wrapping_add(1),
            time: UlogTime::now(),
        };
        let update = encode_incr_update(name, last.sno, last.time, kdbe, deleted, false);
        self.ulog.put_entry(&mut self.hdr, &update)?;
        Ok(last)
    }

    pub fn replay_update(&mut self, update: &[u8]) -> Result<(), UlogError> {
        let layout = walk_incr_update(update).map_err(|_| UlogError::Conv)?;
        self.appended = true;
        if self.hdr.num != 0 && layout.sno != self.hdr.last_sno.wrapping_add(1) {
            self.hdr = self.ulog.reset()?;
            self.hdr.state = KDB_UNSTABLE;
        }
        self.ulog.put_entry(&mut self.hdr, update)
    }

    pub fn init_header(&mut self) -> Result<(), UlogError> {
        self.appended = true;
        self.hdr = self.ulog.reset()?;
        self.hdr.state = KDB_UNSTABLE;
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), UlogError> {
        self.ulog.backing.sync()?;
        self.hdr.state = KDB_STABLE;
        self.ulog.sync_header(&self.hdr)
    }

    pub fn abandon(mut self) -> Result<(), UlogError> {
        if self.appended {
            return Ok(());
        }
        self.hdr.state = KDB_STABLE;
        self.ulog.sync_header(&self.hdr)
    }
}

#[derive(Debug, Default)]
struct Holds {
    gate: RwLock<()>,
    file: Mutex<FileHold>,
}

#[derive(Debug, Default)]
struct FileHold {
    shared: usize,
    flocked: Option<Flock<File>>,
}

struct Held<'a> {
    ulog: &'a Ulog,
    exclusive: bool,
    _gate: Gate<'a>,
}

enum Gate<'a> {
    Shared(#[expect(dead_code, reason = "held for its drop")] RwLockReadGuard<'a, ()>),
    Exclusive(#[expect(dead_code, reason = "held for its drop")] RwLockWriteGuard<'a, ()>),
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if let Some(f) = self.ulog.backing.file() {
            let mut h = self
                .ulog
                .holds
                .file
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if !self.exclusive {
                h.shared = h.shared.saturating_sub(1);
            }
            if self.exclusive || h.shared == 0 {
                let _ = set_file_lock(f, FileLock::Unlock, &mut h.flocked);
            }
        }
    }
}

impl Backing {
    #[cfg_attr(
        not(any(test, feature = "test-hooks")),
        expect(
            clippy::unnecessary_wraps,
            reason = "only a test log in memory has no file"
        )
    )]
    fn file(&self) -> Option<&File> {
        match self {
            Self::File(f) => Some(f),
            #[cfg(any(test, feature = "test-hooks"))]
            Self::Memory(_) => None,
        }
    }

    fn read_at(&self, buf: &mut [u8], at: u64) -> io::Result<()> {
        buf.fill(0);
        match self {
            Self::File(f) => {
                let mut done = 0;
                while done < buf.len() {
                    match f.read_at(&mut buf[done..], at + done as u64) {
                        Ok(0) => break,
                        Ok(n) => done += n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(e),
                    }
                }
                Ok(())
            }
            #[cfg(any(test, feature = "test-hooks"))]
            Self::Memory(m) => {
                let v = m.lock().unwrap_or_else(PoisonError::into_inner);
                let start = usize::try_from(at).unwrap_or(usize::MAX).min(v.len());
                let end = start.saturating_add(buf.len()).min(v.len());
                buf[..end - start].copy_from_slice(&v[start..end]);
                Ok(())
            }
        }
    }

    fn write_at(&self, buf: &[u8], at: u64) -> io::Result<()> {
        match self {
            Self::File(f) => f.write_all_at(buf, at),
            #[cfg(any(test, feature = "test-hooks"))]
            Self::Memory(m) => {
                let mut v = m.lock().unwrap_or_else(PoisonError::into_inner);
                let start = usize::try_from(at).map_err(|_| io::ErrorKind::InvalidInput)?;
                let end = start + buf.len();
                if v.len() < end {
                    v.resize(end, 0);
                }
                v[start..end].copy_from_slice(buf);
                Ok(())
            }
        }
    }

    fn len(&self) -> io::Result<u64> {
        match self {
            Self::File(f) => Ok(f.metadata()?.len()),
            #[cfg(any(test, feature = "test-hooks"))]
            Self::Memory(m) => Ok(m.lock().unwrap_or_else(PoisonError::into_inner).len() as u64),
        }
    }

    fn sync(&self) -> io::Result<()> {
        match self {
            Self::File(f) => f.sync_data(),
            #[cfg(any(test, feature = "test-hooks"))]
            Self::Memory(_) => Ok(()),
        }
    }
}

#[derive(Debug)]
pub struct Ulog {
    backing: Backing,
    path: Option<PathBuf>,
    entries: u32,
    holds: Holds,
}

impl Ulog {
    // MIT: `ulog_map` (lib/kdb/kdb_log.c:500-577)
    // MIT: `ulog_map` (lib/kdb/kdb_log.c:547-553)
    // MIT: `ulog_map` (lib/kdb/kdb_log.c:555-569)
    /// Past `MAXLOGLEN` this open refuses; MIT maps that much and faults.
    /// A kerber-rust 1.0 `ulog ` file is emptied; MIT calls it corrupt.
    pub fn map(path: &Path, entries: u32) -> Result<Self, UlogError> {
        let entries = entries.max(1);
        if HDR_LEN + u64::from(entries) * u64::from(ULOG_BLOCK) > MAXLOGLEN {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        let mut opts = OpenOptions::new();
        opts.read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW);
        let missing = std::fs::symlink_metadata(path).is_err();
        let file = if missing {
            opts.create(true);
            krb5_protocol::create_labeled(path, || opts.open(path))?
        } else {
            opts.open(path)?
        };
        let ulog = Self {
            backing: Backing::File(file),
            path: Some(path.to_path_buf()),
            entries,
            holds: Holds::default(),
        };
        if missing {
            ulog.extend_to(u64::from(ULOG_BLOCK))?;
        }
        ulog.check_mapped()?;
        Ok(ulog)
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn memory(entries: u32) -> Result<Self, UlogError> {
        let ulog = Self {
            backing: Backing::Memory(Mutex::new(Vec::new())),
            path: None,
            entries: entries.max(1),
            holds: Holds::default(),
        };
        ulog.extend_to(u64::from(ULOG_BLOCK))?;
        ulog.check_mapped()?;
        Ok(ulog)
    }

    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.entries
    }

    // MIT: `lock_ulog` (lib/kdb/kdb_log.c:288-296)
    fn lock(&self, exclusive: bool) -> io::Result<Held<'_>> {
        let gate = if exclusive {
            Gate::Exclusive(
                self.holds
                    .gate
                    .write()
                    .unwrap_or_else(PoisonError::into_inner),
            )
        } else {
            Gate::Shared(
                self.holds
                    .gate
                    .read()
                    .unwrap_or_else(PoisonError::into_inner),
            )
        };
        if let Some(f) = self.backing.file() {
            let mut h = self
                .holds
                .file
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if exclusive {
                set_file_lock(f, FileLock::Exclusive, &mut h.flocked)?;
            } else {
                if h.shared == 0 {
                    set_file_lock(f, FileLock::Shared, &mut h.flocked)?;
                }
                h.shared += 1;
            }
        }
        Ok(Held {
            ulog: self,
            exclusive,
            _gate: gate,
        })
    }

    fn check_mapped(&self) -> Result<(), UlogError> {
        let _held = self.lock(true)?;
        let mut head = [0u8; 40];
        if self.backing.len()? < HDR_LEN {
            head.fill(0);
        } else {
            self.backing.read_at(&mut head, 0)?;
        }
        let mut hdr = UlogHeader::decode(&head);
        if hdr.hmagic != KDB_ULOG_HDR_MAGIC {
            if hdr.hmagic != 0 {
                if !head.starts_with(b"ulog ") {
                    return Err(UlogError::Corrupt);
                }
                if let Some(f) = self.backing.file() {
                    f.set_len(0)?;
                }
                tracing::warn!(
                    event = krb5_log::events::ADMIN,
                    component = "krb5-kdc",
                    outcome = "ok",
                    detail = "update log reinitialized from kerber-rust 1.0's text log",
                );
            }
            hdr = self.reset()?;
        }
        if hdr.state != KDB_STABLE
            || (hdr.num != 0
                && (hdr.num > self.entries
                    || !self.check_sno(&hdr, hdr.first_sno, hdr.first_time)?
                    || !self.check_sno(&hdr, hdr.last_sno, hdr.last_time)?))
        {
            hdr = self.reset()?;
        }
        if hdr.num != self.entries {
            self.extend_to(u64::from(hdr.block))?;
        }
        Ok(())
    }

    // MIT: `extend_file_to` (lib/kdb/kdb_log.c:168-194)
    fn extend_to(&self, block: u64) -> Result<(), UlogError> {
        static ZEROS: [u8; 65536] = [0; 65536];
        let size = HDR_LEN + u64::from(self.entries) * block;
        if size > MAXLOGLEN {
            return Err(io::Error::from(io::ErrorKind::InvalidInput).into());
        }
        let mut at = self.backing.len()?;
        while at < size {
            let n = usize::try_from(size - at).map_or(ZEROS.len(), |n| n.min(ZEROS.len()));
            self.backing.write_at(&ZEROS[..n], at)?;
            at += n as u64;
        }
        Ok(())
    }

    fn header(&self) -> Result<UlogHeader, UlogError> {
        let mut head = [0u8; 40];
        self.backing.read_at(&mut head, 0)?;
        Ok(UlogHeader::decode(&head))
    }

    // MIT: `sync_header` (lib/kdb/kdb_log.c:93-104)
    /// A failed sync is an error; MIT aborts.
    fn sync_header(&self, hdr: &UlogHeader) -> Result<(), UlogError> {
        self.backing.write_at(&hdr.encode(), 0)?;
        self.backing.sync()?;
        Ok(())
    }

    fn ent_at(index: u32, block: u16) -> u64 {
        HDR_LEN + u64::from(index) * u64::from(block)
    }

    fn ent_header(&self, index: u32, block: u16) -> Result<EntHeader, UlogError> {
        let mut b = [0u8; ENT_HDR_LEN];
        self.backing.read_at(&mut b, Self::ent_at(index, block))?;
        Ok(EntHeader::decode(&b))
    }

    // MIT: `check_sno` (lib/kdb/kdb_log.c:125-133)
    fn check_sno(&self, hdr: &UlogHeader, sno: u32, time: UlogTime) -> Result<bool, UlogError> {
        let index = sno.wrapping_sub(1) % self.entries;
        let ent = self.ent_header(index, hdr.block)?;
        Ok(ent.sno == sno && ent.time == time)
    }

    // MIT: `get_sno_status` (lib/kdb/kdb_log.c:141-165)
    fn sno_status(&self, hdr: &UlogHeader, last: UlogLast) -> Result<u32, UlogError> {
        if last.sno == hdr.last_sno && last.time == hdr.last_time {
            return Ok(IPROP_NIL);
        }
        if hdr.num == 0 || last.sno > hdr.last_sno || last.sno < hdr.first_sno {
            return Ok(IPROP_FULL_RESYNC);
        }
        if !self.check_sno(hdr, last.sno, last.time)? {
            return Ok(IPROP_FULL_RESYNC);
        }
        Ok(IPROP_OK)
    }

    // MIT: `set_dummy` (lib/kdb/kdb_log.c:247-262)
    fn set_dummy(&self, hdr: &mut UlogHeader, sno: u32, time: UlogTime) -> Result<(), UlogError> {
        let index = sno.wrapping_sub(1) % self.entries;
        let ent = EntHeader {
            umagic: KDB_ULOG_MAGIC,
            sno,
            time,
            ..EntHeader::default()
        };
        self.backing
            .write_at(&ent.encode(), Self::ent_at(index, hdr.block))?;
        self.backing.sync()?;
        hdr.num = 1;
        hdr.first_sno = sno;
        hdr.last_sno = sno;
        hdr.first_time = time;
        hdr.last_time = time;
        Ok(())
    }

    // MIT: `reset_ulog` (lib/kdb/kdb_log.c:265-281)
    fn reset(&self) -> Result<UlogHeader, UlogError> {
        let mut hdr = UlogHeader {
            hmagic: KDB_ULOG_HDR_MAGIC,
            db_version_num: KDB_VERSION,
            block: ULOG_BLOCK,
            ..UlogHeader::default()
        };
        self.set_dummy(&mut hdr, 1, UlogTime::now())?;
        hdr.state = KDB_STABLE;
        self.sync_header(&hdr)?;
        Ok(hdr)
    }

    // MIT: `resize` (lib/kdb/kdb_log.c:198-243)
    fn resize(&self, hdr: &mut UlogHeader, recsize: usize, name: &str) -> Result<(), UlogError> {
        let old_block = usize::from(hdr.block);
        let new_block = (recsize / usize::from(ULOG_BLOCK) + 1) * usize::from(ULOG_BLOCK);
        let Ok(new_block16) = u16::try_from(new_block) else {
            tracing::error!(
                event = krb5_log::events::ADMIN,
                component = "krb5-kdc",
                outcome = "error",
                detail = format!("ulog overflow caused by principal {name}"),
            );
            return Err(UlogError::Error);
        };
        if HDR_LEN + u64::from(self.entries) * u64::from(new_block16) > MAXLOGLEN {
            return Err(UlogError::Error);
        }
        self.extend_to(u64::from(new_block16))?;
        let mut buf = vec![0u8; new_block];
        for i in (0..self.entries).rev() {
            buf.fill(0);
            self.backing
                .read_at(&mut buf[..old_block], Self::ent_at(i, hdr.block))?;
            self.backing.write_at(&buf, Self::ent_at(i, new_block16))?;
        }
        tracing::debug!(
            event = krb5_log::events::ADMIN,
            component = "krb5-kdc",
            outcome = "ok",
            detail = format!("ulog block size has been resized from {old_block} to {new_block}"),
        );
        hdr.block = new_block16;
        self.sync_header(hdr)
    }

    // MIT: `store_update` (lib/kdb/kdb_log.c:310-372)
    fn store_update(&self, hdr: &mut UlogHeader, update: &[u8]) -> Result<(), UlogError> {
        hdr.state = KDB_UNSTABLE;
        self.backing
            .write_at(&KDB_UNSTABLE.to_ne_bytes(), STATE_AT)?;
        self.put_entry(hdr, update)?;
        self.backing.sync()?;
        hdr.state = KDB_STABLE;
        self.sync_header(hdr)
    }

    fn put_entry(&self, hdr: &mut UlogHeader, update: &[u8]) -> Result<(), UlogError> {
        let layout = walk_incr_update(update).map_err(|_| UlogError::Conv)?;
        let size = u32::try_from(update.len()).map_err(|_| UlogError::Error)?;
        let recsize = ENT_HDR_LEN + update.len();
        if recsize > usize::from(hdr.block) {
            self.resize(hdr, recsize, &layout.name)?;
        }
        let index = layout.sno.wrapping_sub(1) % self.entries;
        let mut block = vec![0u8; usize::from(hdr.block)];
        let ent = EntHeader {
            umagic: KDB_ULOG_MAGIC,
            sno: layout.sno,
            time: layout.time,
            commit: true,
            size,
        };
        block[..ENT_HDR_LEN].copy_from_slice(&ent.encode());
        block[ENT_DATA_AT..ENT_DATA_AT + update.len()].copy_from_slice(update);
        self.backing
            .write_at(&block, Self::ent_at(index, hdr.block))?;
        hdr.last_sno = layout.sno;
        hdr.last_time = layout.time;
        if hdr.num == 0 {
            hdr.num = 1;
            hdr.first_sno = layout.sno;
            hdr.first_time = layout.time;
        } else if hdr.num < self.entries {
            hdr.num += 1;
        } else {
            let next = self.ent_header(layout.sno % self.entries, hdr.block)?;
            hdr.first_sno = next.sno;
            hdr.first_time = next.time;
        }
        Ok(())
    }

    // MIT: `ulog_add_update` (lib/kdb/kdb_log.c:375-397)
    /// An unstable log is reset; MIT overwrites that header.
    pub fn add_update(
        &self,
        name: &str,
        deleted: bool,
        kdbe: &[u8],
    ) -> Result<UlogLast, UlogError> {
        let _held = self.lock(true)?;
        let mut hdr = self.header()?;
        if hdr.state != KDB_STABLE || hdr.last_sno == u32::MAX {
            hdr = self.reset()?;
        }
        let last = UlogLast {
            sno: hdr.last_sno.wrapping_add(1),
            time: UlogTime::now(),
        };
        let update = encode_incr_update(name, last.sno, last.time, kdbe, deleted, false);
        self.store_update(&mut hdr, &update)?;
        Ok(last)
    }

    // MIT: `ulog_replay` (lib/kdb/kdb_log.c:456-469)
    pub fn replay_update(&self, update: &[u8]) -> Result<(), UlogError> {
        let layout = walk_incr_update(update).map_err(|_| UlogError::Conv)?;
        let _held = self.lock(true)?;
        let mut hdr = self.header()?;
        if hdr.state != KDB_STABLE || (hdr.num != 0 && layout.sno != hdr.last_sno.wrapping_add(1)) {
            hdr = self.reset()?;
        }
        self.store_update(&mut hdr, update)
    }

    // MIT: `krb5_db_put_principal` (lib/kdb/kdb5.c:1002-1007)
    /// Unstable before the write; MIT logs after the put and a crash skips it.
    pub fn begin(&self) -> Result<UlogBatch<'_>, UlogError> {
        let held = self.lock(true)?;
        let mut hdr = self.header()?;
        if hdr.state != KDB_STABLE {
            hdr = self.reset()?;
        }
        hdr.state = KDB_UNSTABLE;
        self.sync_header(&hdr)?;
        Ok(UlogBatch {
            ulog: self,
            hdr,
            appended: false,
            _held: held,
        })
    }

    // MIT: `ulog_init_header` (lib/kdb/kdb_log.c:483-497)
    pub fn init_header(&self) -> Result<(), UlogError> {
        let _held = self.lock(true)?;
        self.reset()?;
        Ok(())
    }

    // MIT: `ulog_get_entries` (lib/kdb/kdb_log.c:580-649)
    // MIT: `ulog_get_entries` (lib/kdb/kdb_log.c:580-649)
    // MIT: `ulog_get_entries` (lib/kdb/kdb_log.c:601-604)
    /// Exclusive lock to reset; MIT uses the shared lock.
    /// A slot without the next serial is an error; MIT would send it.
    pub fn get_entries(&self, last: UlogLast) -> Result<UlogUpdates, UlogError> {
        let shared = self.lock(false)?;
        let mut hdr = self.header()?;
        let _held = if hdr.state == KDB_STABLE {
            shared
        } else {
            drop(shared);
            let exclusive = self.lock(true)?;
            hdr = self.header()?;
            if hdr.state != KDB_STABLE {
                hdr = self.reset()?;
            }
            exclusive
        };
        let status = self.sno_status(&hdr, last)?;
        if status != IPROP_OK {
            return Ok(UlogUpdates {
                status,
                ..UlogUpdates::default()
            });
        }
        let room = usize::from(hdr.block).saturating_sub(ENT_DATA_AT);
        let mut updates = Vec::new();
        let mut sno = last.sno;
        while sno < hdr.last_sno {
            let at = Self::ent_at(sno % self.entries, hdr.block);
            let ent = self.ent_header(sno % self.entries, hdr.block)?;
            if ent.sno != sno.wrapping_add(1) {
                return Err(UlogError::Corrupt);
            }
            let size = usize::try_from(ent.size).map_err(|_| UlogError::Conv)?;
            if size > room {
                return Err(UlogError::Conv);
            }
            let mut update = vec![0u8; size];
            self.backing
                .read_at(&mut update, at + ENT_DATA_AT as u64)
                .map_err(|_| UlogError::Conv)?;
            let layout = walk_incr_update(&update).map_err(|_| UlogError::Conv)?;
            update[layout.commit_at..layout.commit_at + 4]
                .copy_from_slice(&u32::from(ent.commit).to_be_bytes());
            updates.push(update);
            sno += 1;
        }
        Ok(UlogUpdates {
            status: IPROP_OK,
            last: UlogLast {
                sno: hdr.last_sno,
                time: hdr.last_time,
            },
            updates,
        })
    }

    // MIT: `ulog_get_sno_status` (lib/kdb/kdb_log.c:660-670)
    #[must_use]
    pub fn sno_status_of(&self, last: UlogLast) -> u32 {
        let Ok(_held) = self.lock(false) else {
            return crate::store::IPROP_ERROR;
        };
        self.header()
            .and_then(|hdr| self.sno_status(&hdr, last))
            .unwrap_or(crate::store::IPROP_ERROR)
    }

    // MIT: `ulog_get_last` (lib/kdb/kdb_log.c:672-687)
    pub fn get_last(&self) -> Result<UlogLast, UlogError> {
        let _held = self.lock(false)?;
        let hdr = self.header()?;
        Ok(UlogLast {
            sno: hdr.last_sno,
            time: hdr.last_time,
        })
    }

    // MIT: `ulog_set_last` (lib/kdb/kdb_log.c:689-705)
    pub fn set_last(&self, last: UlogLast) -> Result<(), UlogError> {
        let _held = self.lock(true)?;
        let mut hdr = self.header()?;
        self.set_dummy(&mut hdr, last.sno, last.time)?;
        self.sync_header(&hdr)
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub fn header_now(&self) -> Result<UlogHeader, UlogError> {
        let _held = self.lock(false)?;
        self.header()
    }

    // MIT: `print_update` (kprop/kproplog.c:316-360)
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn entries(&self) -> Result<Vec<UlogEntry>, UlogError> {
        let _held = self.lock(false)?;
        let hdr = self.header()?;
        let mut out = Vec::new();
        if hdr.num == 0 {
            return Ok(out);
        }
        let room = usize::from(hdr.block).saturating_sub(ENT_DATA_AT);
        for i in hdr.first_sno.wrapping_sub(1)..hdr.last_sno {
            let index = i % self.entries;
            let ent = self.ent_header(index, hdr.block)?;
            if ent.umagic != KDB_ULOG_MAGIC {
                return Err(UlogError::Corrupt);
            }
            let size = usize::try_from(ent.size).map_err(|_| UlogError::Conv)?;
            if size > room {
                return Err(UlogError::Conv);
            }
            let mut update = vec![0u8; size];
            self.backing.read_at(
                &mut update,
                Self::ent_at(index, hdr.block) + ENT_DATA_AT as u64,
            )?;
            let (name, deleted, attrs) = if update.is_empty() {
                (String::new(), false, 0)
            } else {
                let l = walk_incr_update(&update).map_err(|_| UlogError::Conv)?;
                (l.name, l.deleted, l.attrs)
            };
            out.push(UlogEntry {
                sno: ent.sno,
                time: ent.time,
                commit: ent.commit,
                size: ent.size,
                name,
                deleted,
                attrs,
                update,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::KdbeVal;
    use crate::store::iprop_xdr::encode_kdbe;

    fn kdbe(vals: &[KdbeVal]) -> Vec<u8> {
        encode_kdbe::<()>(vals, &|_| Ok(Vec::new())).unwrap()
    }

    fn add(log: &Ulog, name: &str) -> UlogLast {
        log.add_update(name, false, &kdbe(&[KdbeVal::MaxLife(3600)]))
            .unwrap()
    }

    /// MIT 1.22.2's header right after `kdb5_util create` (settled live, `od -t x4`): every field at MIT's offset, the padding after the version zero.
    #[test]
    fn the_header_is_mits_forty_bytes() {
        let words: [u32; 10] = [
            0x0666_2323,
            0x0000_0001,
            0x0000_0001,
            0x6ac3_aaa7,
            0x0003_6fd6,
            0x6ac3_aaa7,
            0x0003_6fd6,
            0x0000_0001,
            0x0000_0001,
            0x0800_0001,
        ];
        let mut mit = [0u8; 40];
        for (i, w) in words.iter().enumerate() {
            mit[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        if cfg!(target_endian = "little") {
            let hdr = UlogHeader::decode(&mit);
            let t = UlogTime {
                seconds: 0x6ac3_aaa7,
                useconds: 0x0003_6fd6,
            };
            assert_eq!(
                hdr,
                UlogHeader {
                    hmagic: KDB_ULOG_HDR_MAGIC,
                    db_version_num: 1,
                    num: 1,
                    first_time: t,
                    last_time: t,
                    first_sno: 1,
                    last_sno: 1,
                    state: KDB_STABLE,
                    block: ULOG_BLOCK,
                }
            );
            assert_eq!(hdr.encode(), mit);
        }
    }

    /// Settled live: a new log is 40 + 1000 × 2048 bytes, 0600, holding one dummy entry at serial 1 (magic, serial and time; not committed; size 0).
    #[test]
    fn a_new_log_is_mits_size_with_a_dummy_entry_at_serial_one() {
        let dir = krb5_testkit::scratch_dir("ulog-new");
        let path = dir.join("principal.ulog");
        let log = Ulog::map(&path, 1000).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), 2_048_040);
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777,
            0o600
        );
        let hdr = log.header_now().unwrap();
        assert_eq!(
            (hdr.num, hdr.first_sno, hdr.last_sno, hdr.state, hdr.block),
            (1, 1, 1, KDB_STABLE, ULOG_BLOCK)
        );
        assert_eq!(hdr.first_time, hdr.last_time);
        let entries = log.entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            (entries[0].sno, entries[0].size, entries[0].commit),
            (1, 0, false)
        );
        drop(log);
        let again = Ulog::map(&path, 1000).unwrap();
        assert_eq!(again.header_now().unwrap(), hdr);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Settled live with `iprop_ulogsize = 4`: after seven updates the log holds four, serials 5 to 8, the oldest dropped as the ring wraps.
    #[test]
    fn each_update_takes_the_next_serial_and_the_ring_wraps() {
        let log = Ulog::memory(4).unwrap();
        for i in 1..=7 {
            let last = add(&log, &format!("w{i}@R"));
            assert_eq!(last.sno, i + 1);
        }
        let hdr = log.header_now().unwrap();
        assert_eq!((hdr.num, hdr.first_sno, hdr.last_sno), (4, 5, 8));
        let entries = log.entries().unwrap();
        let snos: Vec<u32> = entries.iter().map(|e| e.sno).collect();
        assert_eq!(snos, [5, 6, 7, 8]);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["w4@R", "w5@R", "w6@R", "w7@R"]);
        assert!(entries.iter().all(|e| e.commit));
    }

    /// Settled live: 4 → 6 entries puts serial 5 where 6 expects serial 1, so the log starts over; 6 → 8 with serials 1–2 keeps it, and the file grows.
    #[test]
    fn a_new_size_keeps_the_log_only_where_its_entries_still_lie() {
        let dir = krb5_testkit::scratch_dir("ulog-size");
        let path = dir.join("principal.ulog");
        let log = Ulog::map(&path, 4).unwrap();
        for i in 1..=7 {
            add(&log, &format!("w{i}@R"));
        }
        drop(log);
        let log = Ulog::map(&path, 6).unwrap();
        let hdr = log.header_now().unwrap();
        assert_eq!((hdr.num, hdr.first_sno, hdr.last_sno), (1, 1, 1));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 40 + 6 * 2048);
        add(&log, "w8@R");
        drop(log);
        let log = Ulog::map(&path, 8).unwrap();
        let hdr = log.header_now().unwrap();
        assert_eq!((hdr.num, hdr.first_sno, hdr.last_sno), (2, 1, 2));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 40 + 8 * 2048);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Settled live: an update past the block makes every block 4096 bytes, the file 40 + 4 × 4096, and keeps the serials.
    #[test]
    fn an_update_past_the_block_grows_every_block() {
        let dir = krb5_testkit::scratch_dir("ulog-resize");
        let path = dir.join("principal.ulog");
        let log = Ulog::map(&path, 4).unwrap();
        add(&log, "small@R");
        let big = kdbe(&[KdbeVal::ModWhere(vec![b'v'; 2100])]);
        let last = log.add_update("big@R", false, &big).unwrap();
        assert_eq!(last.sno, 3);
        let hdr = log.header_now().unwrap();
        assert_eq!(
            (hdr.block, hdr.num, hdr.first_sno, hdr.last_sno),
            (4096, 3, 1, 3)
        );
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 40 + 4 * 4096);
        let entries = log.entries().unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["", "small@R", "big@R"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Settled live: a header of another magic is "Update log is corrupt"; an all-zero one starts over. kerber-rust 1.0's text log, which MIT also calls corrupt, starts over here.
    #[test]
    fn a_foreign_header_is_corrupt_and_a_zero_or_text_one_starts_over() {
        let dir = krb5_testkit::scratch_dir("ulog-magic");
        let path = dir.join("principal.ulog");
        std::fs::write(&path, [0x12u8; 40]).unwrap();
        let err = Ulog::map(&path, 4).unwrap_err();
        assert_eq!(err.to_string(), "Update log is corrupt");
        std::fs::write(&path, [0u8; 40]).unwrap();
        let log = Ulog::map(&path, 4).unwrap();
        assert_eq!(log.header_now().unwrap().last_sno, 1);
        drop(log);
        std::fs::write(&path, "ulog 1\n7\t1790000000\t0\tp@R\n").unwrap();
        let log = Ulog::map(&path, 4).unwrap();
        let hdr = log.header_now().unwrap();
        assert_eq!(
            (hdr.hmagic, hdr.num, hdr.last_sno),
            (KDB_ULOG_HDR_MAGIC, 1, 1)
        );
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 40 + 4 * 2048);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// MIT `get_sno_status`: the replica's exact last is NIL, a serial past the log's or before its first, or one whose time differs, a full resync; otherwise the updates after it, marked committed.
    #[test]
    fn get_entries_answers_as_mits_get_sno_status() {
        let log = Ulog::memory(10).unwrap();
        let first = add(&log, "a@R");
        let second = add(&log, "b@R");
        let third = log.add_update("a@R", true, &kdbe(&[])).unwrap();
        let at = |last| log.get_entries(last).unwrap();
        assert_eq!(at(third).status, IPROP_NIL);
        let ahead = UlogLast {
            sno: third.sno + 1,
            ..third
        };
        assert_eq!(at(ahead).status, IPROP_FULL_RESYNC);
        assert_eq!(at(UlogLast::default()).status, IPROP_FULL_RESYNC);
        let skewed = UlogLast {
            sno: first.sno,
            time: UlogTime {
                seconds: first.time.seconds.wrapping_add(1),
                ..first.time
            },
        };
        assert_eq!(at(skewed).status, IPROP_FULL_RESYNC);
        let got = at(first);
        assert_eq!(got.status, IPROP_OK);
        assert_eq!(got.last, third);
        let walked: Vec<_> = got
            .updates
            .iter()
            .map(|u| walk_incr_update(u).unwrap())
            .collect();
        assert_eq!(
            walked
                .iter()
                .map(|l| (l.name.as_str(), l.sno, l.deleted, l.commit))
                .collect::<Vec<_>>(),
            [
                ("b@R", second.sno, false, true),
                ("a@R", third.sno, true, true)
            ]
        );
        let stored = log.entries().unwrap();
        assert!(!walk_incr_update(&stored[1].update).unwrap().commit);
    }

    /// Settled live (`kdb5_util load -i`): the log holds one dummy entry at the dump's serial and time, and the next update follows it.
    #[test]
    fn set_last_leaves_one_dummy_entry_at_the_given_serial() {
        let log = Ulog::memory(50).unwrap();
        add(&log, "x@R");
        let dumped = UlogLast {
            sno: 4,
            time: UlogTime {
                seconds: 1_791_208_296,
                useconds: 779_547,
            },
        };
        log.set_last(dumped).unwrap();
        let hdr = log.header_now().unwrap();
        assert_eq!((hdr.num, hdr.first_sno, hdr.last_sno), (1, 4, 4));
        assert_eq!((hdr.first_time, hdr.last_time), (dumped.time, dumped.time));
        assert_eq!(log.get_last().unwrap(), dumped);
        assert_eq!(add(&log, "y@R").sno, 5);
        let hdr = log.header_now().unwrap();
        assert_eq!((hdr.num, hdr.first_sno, hdr.last_sno), (2, 4, 5));
    }

    /// Settled live (an MIT kpropd replica): an applied update is kept with the primary's serial and time; one that does not follow the last starts the log over first.
    #[test]
    fn a_replica_keeps_the_primarys_serials_and_starts_over_on_a_gap() {
        let primary = Ulog::memory(20).unwrap();
        let replica = Ulog::memory(20).unwrap();
        for i in 0..6 {
            add(&primary, &format!("p{i}@R"));
        }
        replica.set_last(primary.get_last().unwrap()).unwrap();
        let since = primary.get_last().unwrap();
        add(&primary, "n1@R");
        add(&primary, "n2@R");
        for u in primary.get_entries(since).unwrap().updates {
            replica.replay_update(&u).unwrap();
        }
        assert_eq!(replica.get_last().unwrap(), primary.get_last().unwrap());
        let hdr = replica.header_now().unwrap();
        assert_eq!((hdr.num, hdr.first_sno, hdr.last_sno), (3, 7, 9));
        let gap = encode_incr_update("g@R", 20, UlogTime::now(), &kdbe(&[]), true, true);
        replica.replay_update(&gap).unwrap();
        let hdr = replica.header_now().unwrap();
        assert_eq!((hdr.num, hdr.first_sno, hdr.last_sno), (2, 1, 20));
    }

    /// MIT `ulog_add_update`: past the last serial a `u32` holds the log starts over, so the update takes serial 2 after the dummy at 1.
    #[test]
    fn the_last_serial_starts_the_log_over() {
        let log = Ulog::memory(8).unwrap();
        log.set_last(UlogLast {
            sno: u32::MAX,
            time: UlogTime::now(),
        })
        .unwrap();
        assert_eq!(add(&log, "z@R").sno, 2);
    }

    /// Settled live (`settle-s9-maxloglen.txt`): MIT makes a 200000-entry log 409600040 bytes long but maps only [`MAXLOGLEN`] of it, and `load -i` of a dump at serial 150000 faults. Here such a log is refused before any file is made.
    #[test]
    fn a_log_past_maxloglen_is_refused() {
        let err = Ulog::memory(200_000).unwrap_err();
        assert!(matches!(err, UlogError::Io(e) if e.kind() == io::ErrorKind::InvalidInput));
        let dir = krb5_testkit::scratch_dir("ulog-maxloglen");
        let path = dir.join("principal.ulog");
        let err = Ulog::map(&path, 200_000).unwrap_err();
        assert!(matches!(err, UlogError::Io(e) if e.kind() == io::ErrorKind::InvalidInput));
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Settled live (`settle-s8-ulog-symlink.txt`): MIT's `ulog_map` follows a link planted at the log's name (a dangling one's target is created as the log). This map refuses any link and leaves its target as it was.
    #[test]
    fn a_symlink_planted_as_the_log_is_never_followed() {
        let dir = krb5_testkit::scratch_dir("ulog-symlink");
        let path = dir.join("principal.ulog");
        let target = dir.join("elsewhere");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(Ulog::map(&path, 4).is_err(), "a dangling link");
        assert!(!target.exists());
        std::fs::write(&target, b"").unwrap();
        assert!(Ulog::map(&path, 4).is_err(), "a link to an empty file");
        assert_eq!(std::fs::metadata(&target).unwrap().len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The lock a separate open file description sees on `path` when it asks for a write lock (`F_OFD_GETLK`): a conflicting lock's type, or `F_UNLCK`.
    fn lock_seen_from_elsewhere(path: &Path) -> nix::libc::c_int {
        use nix::fcntl::{FcntlArg, fcntl};
        use nix::libc;
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let mut arg = libc::flock {
            l_type: libc::c_short::try_from(libc::F_WRLCK).unwrap(),
            l_whence: 0,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        fcntl(&f, FcntlArg::F_OFD_GETLK(&mut arg)).unwrap();
        libc::c_int::from(arg.l_type)
    }

    /// The threads of a process share the log file's one open file description: one thread's shared hold ending keeps the lock another thread's hold still needs, and an exclusive hold waits for this process's readers, so a reset never runs under a reader.
    #[test]
    fn a_threads_hold_ending_keeps_the_lock_its_neighbours_still_need() {
        let dir = krb5_testkit::scratch_dir("ulog-holds");
        let path = dir.join("principal.ulog");
        let log = Ulog::map(&path, 4).unwrap();
        let a = log.lock(false).unwrap();
        let b = log.lock(false).unwrap();
        drop(b);
        assert_eq!(lock_seen_from_elsewhere(&path), nix::libc::F_RDLCK);
        let (tx, rx) = std::sync::mpsc::channel();
        let shared = &log;
        std::thread::scope(|s| {
            s.spawn(move || {
                shared.init_header().unwrap();
                tx.send(()).unwrap();
            });
            assert!(
                rx.recv_timeout(std::time::Duration::from_millis(200))
                    .is_err(),
                "the reset waits for this process's reader"
            );
            drop(a);
            rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        });
        assert_eq!(lock_seen_from_elsewhere(&path), nix::libc::F_UNLCK);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A process stopped between its database write and the last append of its run (simulated: the run is dropped unfinished, two of its updates written) leaves the log unstable on disk. The next process to map it, or the next poll answered, starts it over, so a replica at the serial before the run gets a full resync instead of an answer that skips what the log never took. Stricter than MIT, whose next update writes over an unstable header.
    #[test]
    fn a_run_stopped_before_its_last_append_sends_replicas_to_a_full_resync() {
        let dir = krb5_testkit::scratch_dir("ulog-run-stopped");
        let path = dir.join("principal.ulog");
        let log = Ulog::map(&path, 16).unwrap();
        let replica = add(&log, "a@R");
        let mut run = log.begin().unwrap();
        run.add_update("b@R", false, &kdbe(&[KdbeVal::MaxLife(1)]))
            .unwrap();
        run.add_update("c@R", false, &kdbe(&[KdbeVal::MaxLife(2)]))
            .unwrap();
        drop(run);
        assert_eq!(log.header_now().unwrap().state, KDB_UNSTABLE);
        let restarted = Ulog::map(&path, 16).unwrap();
        assert_eq!(restarted.get_last().unwrap().sno, 1, "mapped: started over");
        assert_eq!(
            restarted.get_entries(replica).unwrap().status,
            IPROP_FULL_RESYNC
        );
        let polled = Ulog::memory(16).unwrap();
        let before = add(&polled, "a@R");
        drop(polled.begin().unwrap());
        assert_eq!(
            polled.get_entries(before).unwrap().status,
            IPROP_FULL_RESYNC,
            "a poll answered over an unstable log starts it over"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A finished run is stable and holds each update, as the same updates added one by one; a run whose database write failed (nothing appended) leaves the log as it was; and an update added over an unstable header starts the log over first.
    #[test]
    fn a_finished_run_holds_each_update_and_an_abandoned_one_nothing() {
        let log = Ulog::memory(8).unwrap();
        let start = log.get_last().unwrap();
        let mut run = log.begin().unwrap();
        run.add_update("a@R", false, &kdbe(&[KdbeVal::MaxLife(1)]))
            .unwrap();
        let b = run.add_update("b@R", true, &kdbe(&[])).unwrap();
        run.finish().unwrap();
        let hdr = log.header_now().unwrap();
        assert_eq!((hdr.state, hdr.num, hdr.last_sno), (KDB_STABLE, 3, b.sno));
        let got = log.get_entries(start).unwrap();
        assert_eq!((got.status, got.updates.len()), (IPROP_OK, 2));
        log.begin().unwrap().abandon().unwrap();
        assert_eq!(log.header_now().unwrap(), hdr);
        drop(log.begin().unwrap());
        assert_eq!(add(&log, "c@R").sno, 2, "over an unstable header");
    }

    /// Hardening beyond MIT: an entry that is not the serial asked for (a torn ring) answers an error, where MIT's `ulog_get_entries` would send what the slot holds.
    #[test]
    fn a_torn_ring_is_an_error_not_a_wrong_entry() {
        let log = Ulog::memory(8).unwrap();
        let first = add(&log, "a@R");
        add(&log, "b@R");
        add(&log, "c@R");
        let hdr = log.header_now().unwrap();
        let slot = Ulog::ent_at(first.sno % log.capacity(), hdr.block);
        log.backing
            .write_at(&99u32.to_ne_bytes(), slot + 4)
            .unwrap();
        assert!(matches!(log.get_entries(first), Err(UlogError::Corrupt)));
        let last = log.get_last().unwrap();
        assert_eq!(log.get_entries(last).unwrap().status, IPROP_NIL);
    }
}
