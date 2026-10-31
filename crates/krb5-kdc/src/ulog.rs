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
            self.restart()?;
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
            self.restart()?;
        }
        self.ulog.put_entry(&mut self.hdr, update)
    }

    pub fn init_header(&mut self) -> Result<(), UlogError> {
        self.appended = true;
        self.restart()
    }

    fn restart(&mut self) -> Result<(), UlogError> {
        self.hdr = self.ulog.reset()?;
        self.ulog.set_state(&mut self.hdr, KDB_UNSTABLE)
    }

    /// Unstable before the write; MIT logs after the put and a crash skips it.
    pub fn stage(&mut self) -> Result<(), UlogError> {
        self.ulog.sync_header(&self.hdr)
    }

    pub fn finish(mut self) -> Result<(), UlogError> {
        self.hdr.state = KDB_STABLE;
        self.ulog.sync_header(&self.hdr)
    }

    pub fn abandon(mut self) -> Result<(), UlogError> {
        if self.appended {
            return self.ulog.reset().map(drop);
        }
        self.ulog.set_state(&mut self.hdr, KDB_STABLE)
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
        self.set_state(hdr, KDB_UNSTABLE)?;
        self.put_entry(hdr, update)?;
        self.backing.sync()?;
        hdr.state = KDB_STABLE;
        self.sync_header(hdr)
    }

    fn set_state(&self, hdr: &mut UlogHeader, state: u16) -> Result<(), UlogError> {
        hdr.state = state;
        self.backing.write_at(&state.to_ne_bytes(), STATE_AT)?;
        Ok(())
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
    pub fn begin(&self) -> Result<UlogBatch<'_>, UlogError> {
        let held = self.lock(true)?;
        let mut hdr = self.header()?;
        if hdr.state != KDB_STABLE {
            hdr = self.reset()?;
        }
        self.set_state(&mut hdr, KDB_UNSTABLE)?;
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
}
