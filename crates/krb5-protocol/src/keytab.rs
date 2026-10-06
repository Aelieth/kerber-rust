//! MIT keytab v1 (`0x0501`) and v2 (`0x0502`). Unknown etypes are skipped.
//!
//! A skipped etype stays in file order as an unparsed slot. A rewrite
//! can put that slot back. It is not dropped on the floor.

use std::io;
use std::path::Path;

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_types::{PrincipalName, Realm, kerberos_string_from_bytes};
use zeroize::Zeroizing;

use crate::secret_file::write_secret_file;

/// One file-order keytab slot (parsed entry or unknown-etype blob).
#[derive(Debug)]
pub enum KeytabSlot<'a> {
    /// Known etype.
    Entry(&'a KeytabEntry),
    /// Raw record (length prefix included), unknown etype.
    Unparsed(&'a [u8]),
}

/// One keytab entry.
#[derive(Debug)]
pub struct KeytabEntry {
    /// Realm.
    pub realm: Realm,
    /// Principal name.
    pub name: PrincipalName,
    /// POSIX timestamp.
    pub timestamp: u32,
    /// Key version number.
    pub kvno: u32,
    /// Protocol key.
    pub key: ProtocolKey,
}

/// MIT keytab (v1 or v2). `Debug` shows an unparsed record's length, never its octets, which
/// hold its key.
#[derive(Default)]
pub struct Keytab {
    /// File version (`0x0501` or `0x0502`).
    pub version: u16,
    /// Entries in file order (unknown etypes omitted).
    pub entries: Vec<KeytabEntry>,
    /// Count of entries skipped because the etype is unknown / refused.
    pub skipped_unknown_etype: usize,
    /// Unknown-etype records (parsed-entry count before each raw blob), key included, each wiped
    /// when it drops.
    /// MIT `krb5_free_keytab_entry_contents` (`ktfr_entry.c:38-41`): every entry's key is zeroed
    /// when it is freed.
    pub unparsed: Vec<(usize, Zeroizing<Vec<u8>>)>,
}

impl std::fmt::Debug for Keytab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        struct Redacted(usize);
        impl std::fmt::Debug for Redacted {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "<redacted, {} octets>", self.0)
            }
        }
        let unparsed: Vec<_> = self
            .unparsed
            .iter()
            .map(|(at, raw)| (at, Redacted(raw.len())))
            .collect();
        f.debug_struct("Keytab")
            .field("version", &self.version)
            .field("entries", &self.entries)
            .field("skipped_unknown_etype", &self.skipped_unknown_etype)
            .field("unparsed", &unparsed)
            .finish()
    }
}

impl Keytab {
    /// A single-entry v2 keytab.
    #[must_use]
    pub fn single(realm: Realm, name: PrincipalName, kvno: u32, key: ProtocolKey) -> Self {
        let timestamp = time_of_day();
        Self {
            version: 0x0502,
            entries: vec![KeytabEntry {
                realm,
                name,
                timestamp,
                kvno,
                key,
            }],
            skipped_unknown_etype: 0,
            unparsed: Vec::new(),
        }
    }

    /// Serialize as MIT keytab v2 (`0x0502`) unless [`Self::version`] is v1, into a buffer sized
    /// for the whole keytab before the first byte (no reallocation leaves a copy of a key behind)
    /// and wiped when it drops.
    /// MIT `krb5_ktfileint_write_entry` (`lib/krb5/keytab/kt_file.c:1127-1269`): a version-1 record leaves unwritten the four bytes `krb5_ktfileint_size_entry` counts for its name type; `krb5_ktfileint_find_slot` zero-fills them when another record follows, and after the last they are absent.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let ver = if self.version == 0x0501 {
            0x0501u16
        } else {
            0x0502
        };
        let size = 2
            + self
                .unparsed
                .iter()
                .map(|(_, raw)| raw.len())
                .sum::<usize>()
            + self.entries.iter().map(|e| 4 + entry_len(e)).sum::<usize>();
        let mut out = Zeroizing::new(Vec::with_capacity(size));
        out.extend_from_slice(&ver.to_be_bytes());
        let mut ei = 0;
        let mut ui = 0;
        let mut last_marshalled = false;
        loop {
            if ui < self.unparsed.len() && (ei >= self.entries.len() || self.unparsed[ui].0 <= ei) {
                out.extend_from_slice(&self.unparsed[ui].1);
                ui += 1;
                last_marshalled = false;
                continue;
            }
            let Some(e) = self.entries.get(ei) else {
                break;
            };
            let len = u32::try_from(entry_len(e)).unwrap_or(0);
            put_u32(&mut out, len, ver);
            marshal_entry(&mut out, e, ver);
            ei += 1;
            last_marshalled = true;
        }
        if is_v1(ver) && last_marshalled {
            let n = out.len().saturating_sub(4);
            out.truncate(n);
        }
        out
    }

    /// Atomic write: a new keytab is 0600; one it replaces keeps its owner, group and mode, and
    /// one the writer may not write is refused, as MIT's in-place keytab writes are
    /// (`write_secret_file`).
    ///
    /// # Errors
    ///
    /// Create, write, sync, or rename failed.
    pub fn write_file(&self, path: impl AsRef<Path>) -> Result<(), io::Error> {
        write_secret_file(path.as_ref(), &self.to_bytes())
    }

    /// Principal / kvno / etype from an unknown-etype record (length prefix included).
    #[must_use]
    pub fn unparsed_meta(raw: &[u8], version: u16) -> Option<(u32, String, u32, i32)> {
        let body = raw.get(4..)?;
        parse_unparsed_meta(body, version)
            .ok()
            .map(|(kvno, princ, ts, etype, _)| (kvno, princ, ts, etype))
    }

    /// The key bytes of an unknown-etype record (length prefix included), borrowed from it.
    #[must_use]
    pub fn unparsed_key(raw: &[u8], version: u16) -> Option<&[u8]> {
        let body = raw.get(4..)?;
        let key = parse_unparsed_meta(body, version).ok()?.4;
        body.get(key)
    }

    /// File-order slots: parsed entries interleaved with unknown-etype blobs.
    #[must_use]
    pub fn slots(&self) -> Vec<KeytabSlot<'_>> {
        let mut ei = 0;
        let mut ui = 0;
        let mut out = Vec::new();
        loop {
            if ui < self.unparsed.len() && (ei >= self.entries.len() || self.unparsed[ui].0 <= ei) {
                out.push(KeytabSlot::Unparsed(&self.unparsed[ui].1));
                ui += 1;
                continue;
            }
            let Some(e) = self.entries.get(ei) else {
                break;
            };
            out.push(KeytabSlot::Entry(e));
            ei += 1;
        }
        out
    }

    /// Remove the 1-based file-order slot (parsed or unparsed).
    ///
    /// # Errors
    ///
    /// `io::ErrorKind::InvalidInput` when `slot` is 0 or past the last slot.
    pub fn remove_slot(&mut self, slot: usize) -> io::Result<()> {
        let n = self.slots().len();
        if slot == 0 || slot > n {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "no such slot"));
        }
        let mut ei = 0;
        let mut ui = 0;
        let mut seen = 0;
        loop {
            if ui < self.unparsed.len() && (ei >= self.entries.len() || self.unparsed[ui].0 <= ei) {
                seen += 1;
                if seen == slot {
                    self.unparsed.remove(ui);
                    return Ok(());
                }
                ui += 1;
                continue;
            }
            if ei >= self.entries.len() {
                break;
            }
            seen += 1;
            if seen == slot {
                self.entries.remove(ei);
                for (idx, _) in &mut self.unparsed {
                    if *idx > ei {
                        *idx = idx.saturating_sub(1);
                    }
                }
                return Ok(());
            }
            ei += 1;
        }
        Err(io::Error::new(io::ErrorKind::InvalidInput, "no such slot"))
    }

    /// Append `other` entries (ktadd / merge). A record `other` keeps raw is laid out again in
    /// this keytab's version when the two differ, so every raw record is in [`Self::version`].
    pub fn merge(&mut self, other: Keytab) {
        let n = self.entries.len();
        let (from, to) = (other.version, self.version);
        self.entries.extend(other.entries);
        self.skipped_unknown_etype += other.skipped_unknown_etype;
        self.unparsed
            .extend(other.unparsed.into_iter().map(|(i, raw)| {
                let again = (is_v1(from) != is_v1(to))
                    .then(|| Fields::of_raw(&raw, from).map(|f| f.record(to)))
                    .flatten();
                (i.saturating_add(n), again.unwrap_or(raw))
            }));
    }

    /// Add every slot to the keytab file at `path` as MIT's `ktutil` `wkt` does, each with
    /// `krb5_kt_add_entry` ([`add_to_keytab_file`]): a missing file is made (0600, version 2), an
    /// existing one keeps its version, owner and mode; with no slot nothing is opened. Each slot
    /// is first given the time of day, here as in the file.
    /// MIT `ktutil_write_keytab` (`kadmin/ktutil/ktutil_funcs.c:336-358`): every entry of the list is added to `WRFILE:<name>`, one `krb5_kt_add_entry` each.
    /// MIT `krb5_ktfileint_write_entry` (`lib/krb5/keytab/kt_file.c:1127-1269`): the entry's timestamp becomes the time of day it is written, in the caller's entry too.
    ///
    /// # Errors
    ///
    /// Reading or writing the file failed, or [`add_to_keytab_file`] refused it (before any
    /// slot's timestamp changes, as MIT's open fails before its write).
    pub fn add_to_file(&mut self, path: impl AsRef<Path>) -> Result<(), io::Error> {
        let path = path.as_ref();
        if self.slots().is_empty() {
            return Ok(());
        }
        let existing = match crate::read_secret_file(path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        if let Some(b) = &existing {
            file_version(b)?;
        }
        for e in &mut self.entries {
            e.timestamp = time_of_day();
        }
        let ver = self.version;
        for (_, raw) in &mut self.unparsed {
            let stamped = Fields::of_raw(raw, ver).map(|mut f| {
                f.timestamp = time_of_day();
                f.record(ver)
            });
            if let Some(stamped) = stamped {
                *raw = stamped;
            }
        }
        let bytes = add_to_keytab_file(existing.as_ref().map(|b| b.as_slice()), self)?;
        write_secret_file(path, &bytes)
    }

    /// Parse v1 or v2. Unknown etypes skip that entry rather than failing.
    /// MIT `krb5_ktfileint_internal_read_entry` (`lib/krb5/keytab/kt_file.c:890-1116`): record by record, a negative size is a hole; a size of 0, a short field, or a count or length that is not positive ends the keytab (`KRB5_KT_END`), its entries so far being the keytab; a record is read up to its size or the file's end, whichever is first (MIT's version-1 writer leaves its last record four bytes short).
    /// A record whose fields run past its own size ends the keytab here, where MIT reads them
    /// from the bytes after it.
    ///
    /// # Errors
    ///
    /// `io::ErrorKind::InvalidData` for a missing version or one other than `0x0501` /
    /// `0x0502`, a hole size of `i32::MIN`, a key whose length does not match its enctype, or a
    /// realm or name component that is not ASCII GeneralString.
    pub fn parse(bytes: &[u8]) -> Result<Self, io::Error> {
        let version = file_version(bytes)?;
        let mut i = 2;
        let mut entries = Vec::new();
        let mut unparsed = Vec::new();
        while i + 4 <= bytes.len() {
            let size = take_i32(bytes, &mut i, version)?;
            if size < 0 {
                let skip = match size.checked_neg() {
                    Some(n) => usize::try_from(n).unwrap_or(0),
                    None => return Err(bad_format()),
                };
                i = i.saturating_add(skip);
                continue;
            }
            if size == 0 {
                break;
            }
            let size = usize::try_from(size).unwrap_or(0);
            let end = i.saturating_add(size);
            let body = &bytes[i..end.min(bytes.len())];
            match parse_entry(body, size, version) {
                Ok(e) => entries.push(e),
                Err(EntryErr::UnsupportedEtype) => {
                    // The record as read, its size the bytes it has (fewer than it claimed only
                    // when it ran past the file's end), in a buffer that is never reallocated.
                    let mut raw = Zeroizing::new(Vec::with_capacity(4 + body.len()));
                    put_u32(&mut raw, u32::try_from(body.len()).unwrap_or(0), version);
                    raw.extend_from_slice(body);
                    unparsed.push((entries.len(), raw));
                }
                Err(EntryErr::End) => break,
                Err(EntryErr::Io(e)) => return Err(e),
            }
            i = end;
        }
        Ok(Self {
            version,
            skipped_unknown_etype: unparsed.len(),
            unparsed,
            entries,
        })
    }
}

/// The keytab file `existing` (`None`: there is none) with each of `kt`'s slots added, in file
/// order, as MIT's `krb5_kt_add_entry` adds an entry to a FILE keytab: in the file's version, a
/// missing file being made at version 2, each slot with the timestamp it has ([`Keytab::add_to_file`]
/// gives each the time of day first). The bytes already there stay as they are but where a
/// record takes a hole, a size of 0 or the space after the last record.
/// MIT `krb5_ktfileint_open` (`lib/krb5/keytab/kt_file.c:731-808`): a missing file is made at version 2, and an existing one keeps its version, which must be 1 or 2 (`KRB5_KEYTAB_BADVNO` for an empty file too).
/// MIT `krb5_ktfileint_write_entry` (`lib/krb5/keytab/kt_file.c:1127-1269`): the record's bytes go after its size field, the size last.
///
/// # Errors
///
/// `io::ErrorKind::InvalidData` with MIT's text when `existing` does not start with keytab
/// version 1 or 2, or when a hole's size is `i32::MIN`; and when the records run more than four
/// bytes past the file's end (MIT's version-1 writer leaves four off its last record), where MIT
/// extends the file to that end.
pub fn add_to_keytab_file(
    existing: Option<&[u8]>,
    kt: &Keytab,
) -> Result<Zeroizing<Vec<u8>>, io::Error> {
    let records: Vec<Fields<'_>> = kt
        .slots()
        .into_iter()
        .filter_map(|slot| match slot {
            KeytabSlot::Entry(e) => Some(Fields::of_entry(e)),
            KeytabSlot::Unparsed(raw) => Fields::of_raw(raw, kt.version),
        })
        .collect();
    let ver = match existing {
        None => 0x0502,
        Some(b) => file_version(b)?,
    };
    let room: usize = records.iter().map(|f| 12 + f.size_needed()).sum();
    let mut out = Zeroizing::new(Vec::with_capacity(
        existing.map_or(2, <[u8]>::len).saturating_add(room),
    ));
    match existing {
        Some(b) => out.extend_from_slice(b),
        None => out.extend_from_slice(&ver.to_be_bytes()),
    }
    for f in &records {
        let needed = f.size_needed();
        let (commit, size) = find_slot(&mut out, needed, ver)?;
        let mut body = Zeroizing::new(Vec::with_capacity(needed));
        f.write(&mut body, ver);
        let end = commit + 4 + body.len();
        if out.len() < end {
            out.resize(end, 0);
        }
        out[commit + 4..end].copy_from_slice(&body);
        let mut size_field = Vec::with_capacity(4);
        put_u32(&mut size_field, u32::try_from(size).unwrap_or(0), ver);
        out[commit..commit + 4].copy_from_slice(&size_field);
    }
    Ok(out)
}

/// Where the next record of `needed` bytes goes in the keytab file `out`, and the size it is
/// given: the first hole as large (at the hole's size), else a size of 0 (a 0 then written after
/// the record), else after the last record (the file extended with zeros to it).
/// MIT `krb5_ktfileint_find_slot` (`lib/krb5/keytab/kt_file.c:1314-1382`): the walk from the version on, a cut-short size field read to the file's end; a hole of size `INT32_MIN` is `KRB5_KT_FORMAT`.
fn find_slot(out: &mut Vec<u8>, needed: usize, ver: u16) -> Result<(usize, usize), io::Error> {
    let mut pos = 2usize;
    loop {
        if pos.saturating_add(4) > out.len() {
            let commit = pos.max(out.len());
            if commit > out.len() + 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "keytab record runs past the end of the file",
                ));
            }
            out.resize(commit + 4, 0);
            return Ok((commit, needed));
        }
        let mut at = pos;
        let size = take_i32(out, &mut at, ver)?;
        if size > 0 {
            pos = at.saturating_add(usize::try_from(size).unwrap_or(0));
            continue;
        }
        if size < 0 {
            let Some(hole) = size.checked_neg().and_then(|n| usize::try_from(n).ok()) else {
                return Err(bad_format());
            };
            if hole >= needed {
                return Ok((pos, hole));
            }
            pos = at.saturating_add(hole);
            continue;
        }
        let zero_at = at + needed;
        if out.len() < zero_at + 4 {
            out.resize(zero_at + 4, 0);
        }
        out[zero_at..zero_at + 4].fill(0);
        return Ok((pos, needed));
    }
}

/// A keytab file's version, 1 or 2, else MIT's `KRB5_KEYTAB_BADVNO` (an empty file included).
fn file_version(b: &[u8]) -> Result<u16, io::Error> {
    match b {
        [0x05, v @ (0x01 | 0x02), ..] => Ok(u16::from_be_bytes([0x05, *v])),
        _ => Err(bad_version()),
    }
}

/// The time of day in POSIX seconds, 0 when the clock cannot say.
/// MIT `krb5_ktfileint_write_entry` (`lib/krb5/keytab/kt_file.c:1127-1269`): a failing `krb5_timeofday` leaves the timestamp 0.
fn time_of_day() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(0))
}

/// MIT `KRB5_KEYTAB_BADVNO`'s text.
fn bad_version() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Unsupported key table format version number",
    )
}

/// MIT `KRB5_KT_FORMAT`'s text.
fn bad_format() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "Bad format in keytab")
}

/// One entry's fields as MIT's `krb5_keytab_entry` holds them, whatever its enctype; the names
/// and the key are borrowed, from an entry or from a record kept raw.
struct Fields<'a> {
    realm: &'a [u8],
    comps: Vec<&'a [u8]>,
    name_type: i32,
    timestamp: u32,
    kvno: u32,
    enctype: u16,
    key: &'a [u8],
}

impl<'a> Fields<'a> {
    fn of_entry(e: &'a KeytabEntry) -> Self {
        Self {
            realm: e.realm.as_bytes(),
            comps: e
                .name
                .name_string
                .iter()
                .map(krb5_types::KerberosString::as_bytes)
                .collect(),
            name_type: e.name.name_type,
            timestamp: e.timestamp,
            kvno: e.kvno,
            enctype: u16::try_from(e.key.etype().to_iana()).unwrap_or(0),
            key: e.key.as_bytes(),
        }
    }

    /// The fields of a record kept raw (its size first), read as version `ver` lays it out, its
    /// kvno taken as MIT's reader takes it.
    fn of_raw(raw: &'a [u8], ver: u16) -> Option<Self> {
        let body = raw.get(4..)?;
        let mut i = 0;
        let ncomp = take_count(body, &mut i, ver).ok()?;
        let realm = take_counted16_range(body, &mut i, ver).ok()?;
        let mut comps = Vec::with_capacity(usize::from(ncomp));
        for _ in 0..ncomp {
            comps.push(body.get(take_counted16_range(body, &mut i, ver).ok()?)?);
        }
        let name_type = take_name_type(body, &mut i, ver).ok()?;
        let timestamp = take_u32(body, &mut i, ver).ok()?;
        let kvno8 = *body.get(i)?;
        i += 1;
        let enctype = take_u16(body, &mut i, ver).ok()?;
        let key = take_counted16_range(body, &mut i, ver).ok()?;
        let kvno = entry_kvno(body, &mut i, ver, kvno8, body.len()).ok()?;
        Some(Self {
            realm: body.get(realm)?,
            comps,
            name_type,
            timestamp,
            kvno,
            enctype,
            key: body.get(key)?,
        })
    }

    /// The record's size, in either version.
    /// MIT `krb5_ktfileint_size_entry` (`lib/krb5/keytab/kt_file.c:1282-1295`): every counted field, the name type, the fixed fields and the 32-bit kvno, whatever the version.
    fn size_needed(&self) -> usize {
        let counted = |d: &[u8]| 2 + d.len().min(usize::from(u16::MAX));
        2 + counted(self.realm)
            + self.comps.iter().map(|c| counted(c)).sum::<usize>()
            + 4
            + 4
            + 1
            + 2
            + counted(self.key)
            + 4
    }

    /// The record's bytes after its size, appended to `b`: version 2 in network byte order;
    /// version 1 in this host's, its count one more for the realm and without the name type, so
    /// four bytes short of its size.
    /// MIT `krb5_ktfileint_write_entry` (`lib/krb5/keytab/kt_file.c:1155-1244`): a version-1 entry is written in host byte order, its count one more for the realm, with no name type, the 32-bit kvno last in either version.
    fn write(&self, b: &mut Vec<u8>, ver: u16) {
        let ncomp = u16::try_from(self.comps.len()).unwrap_or(0);
        let count = if is_v1(ver) {
            ncomp.saturating_add(1)
        } else {
            ncomp
        };
        put_u16(b, count, ver);
        put16(b, self.realm, ver);
        for c in &self.comps {
            put16(b, c, ver);
        }
        if !is_v1(ver) {
            b.extend_from_slice(&self.name_type.to_be_bytes());
        }
        put_u32(b, self.timestamp, ver);
        #[allow(clippy::cast_possible_truncation)]
        b.push((self.kvno & 0xff) as u8);
        put_u16(b, self.enctype, ver);
        put16(b, self.key, ver);
        put_u32(b, self.kvno, ver);
    }

    /// The whole record as it lies between others in a version-`ver` file: its size, its bytes,
    /// and for version 1 the four zero bytes its size counts.
    fn record(&self, ver: u16) -> Zeroizing<Vec<u8>> {
        let size = self.size_needed();
        let mut out = Zeroizing::new(Vec::with_capacity(4 + size));
        put_u32(&mut out, u32::try_from(size).unwrap_or(0), ver);
        self.write(&mut out, ver);
        if is_v1(ver) {
            out.extend_from_slice(&[0; 4]);
        }
        out
    }
}

/// The length of the record [`marshal_entry`] writes for `e`, in either version.
fn entry_len(e: &KeytabEntry) -> usize {
    Fields::of_entry(e).size_needed()
}

/// One entry's record, appended to `b` (sized by the caller, [`entry_len`]): [`Fields::write`]'s
/// bytes, a version-1 record's four bytes of fill after them.
fn marshal_entry(b: &mut Vec<u8>, e: &KeytabEntry, ver: u16) {
    Fields::of_entry(e).write(b, ver);
    if is_v1(ver) {
        b.extend_from_slice(&[0; 4]);
    }
}

enum EntryErr {
    UnsupportedEtype,
    /// MIT `KRB5_KT_END`: a short field, or a count or length that is not positive.
    End,
    Io(io::Error),
}

impl From<io::Error> for EntryErr {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            Self::End
        } else {
            Self::Io(e)
        }
    }
}

/// An unknown-etype record's kvno, principal, timestamp and enctype, and where its key lies in it
/// (no copy of the key is made).
type UnparsedMeta = (u32, String, u32, i32, std::ops::Range<usize>);

fn parse_unparsed_meta(body: &[u8], ver: u16) -> Result<UnparsedMeta, io::Error> {
    let mut i = 0;
    let ncomp = take_count(body, &mut i, ver)?;
    let realm = take_counted16(body, &mut i, ver)?;
    let mut parts = Vec::new();
    for _ in 0..ncomp {
        parts.push(take_counted16(body, &mut i, ver)?);
    }
    let nametype = take_name_type(body, &mut i, ver)?;
    let timestamp = take_u32(body, &mut i, ver)?;
    if i >= body.len() {
        return Err(eof());
    }
    let kvno8 = body[i];
    i += 1;
    let enctype = i32::from(take_u16(body, &mut i, ver)?);
    let keybytes = take_counted16_range(body, &mut i, ver)?;
    let kvno = entry_kvno(body, &mut i, ver, kvno8, body.len())?;
    let realm_s = kerberos_string_from_bytes(&realm)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let name = PrincipalName::try_from_bytes(nametype, parts)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok((
        kvno,
        format!(
            "{}@{}",
            name.components_joined(),
            String::from_utf8_lossy(realm_s.as_bytes())
        ),
        timestamp,
        enctype,
        keybytes,
    ))
}

/// One record's entry from `body`, the record's bytes up to its `size` or the file's end. A key
/// whose bytes are not that etype's length is not an entry; the kvno is [`entry_kvno`]'s.
/// MIT `krb5_ktfileint_internal_read_entry` (`lib/krb5/keytab/kt_file.c:942-1095`): a version-1 entry is in host byte order, its count includes the realm, and it has no name type; a short field, or a count or length that is not positive, ends the keytab.
fn parse_entry(body: &[u8], size: usize, ver: u16) -> Result<KeytabEntry, EntryErr> {
    let mut i = 0;
    let ncomp = take_count(body, &mut i, ver)?;
    let realm = take_counted16(body, &mut i, ver)?;
    let mut parts = Vec::new();
    for _ in 0..ncomp {
        parts.push(take_counted16(body, &mut i, ver)?);
    }
    let nametype = take_name_type(body, &mut i, ver)?;
    let timestamp = take_u32(body, &mut i, ver)?;
    if i >= body.len() {
        return Err(eof().into());
    }
    let kvno8 = body[i];
    i += 1;
    let enctype = i32::from(take_u16(body, &mut i, ver)?);
    let keybytes = Zeroizing::new(take_counted16(body, &mut i, ver)?);
    let kvno = entry_kvno(body, &mut i, ver, kvno8, size)?;
    let etype = match EncryptionType::known(enctype) {
        Ok(e) => e,
        Err(krb5_crypto::Error::UnsupportedEtype(_)) => {
            return Err(EntryErr::UnsupportedEtype);
        }
        Err(e) => {
            return Err(EntryErr::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                e.to_string(),
            )));
        }
    };
    let key = ProtocolKey::from_bytes(etype, &keybytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let realm_s = kerberos_string_from_bytes(&realm)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let name = PrincipalName::try_from_bytes(nametype, parts)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(KeytabEntry {
        realm: realm_s,
        name,
        timestamp,
        kvno,
        key,
    })
}

/// Whether `ver` is keytab version 1, whose integers are in host byte order (version 2: network
/// byte order).
const fn is_v1(ver: u16) -> bool {
    ver == 0x0501
}

fn put_u16(b: &mut Vec<u8>, v: u16, ver: u16) {
    b.extend_from_slice(&if is_v1(ver) {
        v.to_ne_bytes()
    } else {
        v.to_be_bytes()
    });
}

fn put_u32(b: &mut Vec<u8>, v: u32, ver: u16) {
    b.extend_from_slice(&if is_v1(ver) {
        v.to_ne_bytes()
    } else {
        v.to_be_bytes()
    });
}

fn put16(b: &mut Vec<u8>, data: &[u8], ver: u16) {
    let n = u16::try_from(data.len()).unwrap_or(u16::MAX);
    put_u16(b, n, ver);
    b.extend_from_slice(&data[..usize::from(n)]);
}

fn take_u16(b: &[u8], i: &mut usize, ver: u16) -> Result<u16, io::Error> {
    if *i + 2 > b.len() {
        return Err(eof());
    }
    let raw: [u8; 2] = b[*i..*i + 2].try_into().map_err(|_| eof())?;
    *i += 2;
    Ok(if is_v1(ver) {
        u16::from_ne_bytes(raw)
    } else {
        u16::from_be_bytes(raw)
    })
}

/// An entry's component count: in version 1 it counts the realm too.
/// MIT `krb5_ktfileint_internal_read_entry` (`lib/krb5/keytab/kt_file.c:942-950`): a version-1 count is one less for the realm; a count that is not positive ends the keytab.
fn take_count(b: &[u8], i: &mut usize, ver: u16) -> Result<u16, io::Error> {
    #[allow(clippy::cast_possible_wrap)]
    let count = take_u16(b, i, ver)? as i16;
    let count = if is_v1(ver) {
        count.wrapping_sub(1)
    } else {
        count
    };
    u16::try_from(count).ok().filter(|&n| n > 0).ok_or_else(eof)
}

/// An entry's name type: version 1 has none.
/// MIT `krb5_ktfileint_internal_read_entry` (`lib/krb5/keytab/kt_file.c:1023-1030`): only a version-2 entry carries the name type.
fn take_name_type(b: &[u8], i: &mut usize, ver: u16) -> Result<i32, io::Error> {
    if is_v1(ver) {
        Ok(PrincipalName::NT_UNKNOWN)
    } else {
        take_i32(b, i, ver)
    }
}

/// An entry's kvno: the 32-bit kvno after the key, when the record's `size` leaves four bytes for
/// it and it is not 0, else the one-byte kvno (zero bytes are fill).
/// MIT `krb5_ktfileint_internal_read_entry` (`lib/krb5/keytab/kt_file.c:1084-1095`): four bytes left after the key are a 32-bit kvno, in host byte order for version 1, which replaces the 8-bit one unless it is 0; a file that ends before them ends the keytab.
fn entry_kvno(
    body: &[u8],
    i: &mut usize,
    ver: u16,
    kvno8: u8,
    size: usize,
) -> Result<u32, io::Error> {
    if *i + 4 <= size {
        let kvno32 = take_u32(body, i, ver)?;
        if kvno32 != 0 {
            return Ok(kvno32);
        }
    }
    Ok(u32::from(kvno8))
}

fn take_u32(b: &[u8], i: &mut usize, ver: u16) -> Result<u32, io::Error> {
    if *i + 4 > b.len() {
        return Err(eof());
    }
    let raw: [u8; 4] = b[*i..*i + 4].try_into().map_err(|_| eof())?;
    *i += 4;
    Ok(if is_v1(ver) {
        u32::from_ne_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    })
}

fn take_i32(b: &[u8], i: &mut usize, ver: u16) -> Result<i32, io::Error> {
    Ok(i32::from_ne_bytes(take_u32(b, i, ver)?.to_ne_bytes()))
}

/// A counted field's length.
/// MIT `krb5_ktfileint_internal_read_entry` (`lib/krb5/keytab/kt_file.c:973-1068`): a realm, component or key length that is not positive as a 16-bit signed integer ends the keytab.
fn take_len16(b: &[u8], i: &mut usize, ver: u16) -> Result<usize, io::Error> {
    #[allow(clippy::cast_possible_wrap)]
    let n = take_u16(b, i, ver)? as i16;
    usize::try_from(n).ok().filter(|&n| n > 0).ok_or_else(eof)
}

fn take_counted16(b: &[u8], i: &mut usize, ver: u16) -> Result<Vec<u8>, io::Error> {
    let n = take_len16(b, i, ver)?;
    if *i + n > b.len() {
        return Err(eof());
    }
    let v = b[*i..*i + n].to_vec();
    *i += n;
    Ok(v)
}

fn take_counted16_range(
    b: &[u8],
    i: &mut usize,
    ver: u16,
) -> Result<std::ops::Range<usize>, io::Error> {
    let n = take_len16(b, i, ver)?;
    if *i + n > b.len() {
        return Err(eof());
    }
    let r = *i..*i + n;
    *i += n;
    Ok(r)
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "keytab truncated")
}

/// MIT `lookup_etypes_for_keytab` (`gic_keytab.c:84-143`): lists the etypes of the client's
/// highest-kvno entries, skipping invalid enctypes.
///
/// Only the highest kvno for `name` in `realm` (name-type ignored).
/// Returns those keys and their etype list, or `None` if none match.
#[must_use]
pub fn keytab_init_creds_keys(
    kt: &Keytab,
    name: &PrincipalName,
    realm: &str,
) -> Option<(Vec<ProtocolKey>, Vec<i32>)> {
    let realm_b = realm.as_bytes();
    let mut max_kvno = 0u32;
    let mut keys = Vec::new();
    let mut etypes = Vec::new();
    for e in &kt.entries {
        if e.name.name_string != name.name_string || e.realm.as_bytes() != realm_b {
            continue;
        }
        if e.kvno < max_kvno {
            continue;
        }
        if e.kvno > max_kvno {
            max_kvno = e.kvno;
            keys.clear();
            etypes.clear();
        }
        keys.push(e.key.clone());
        let t = e.key.etype().to_iana();
        if !etypes.contains(&t) {
            etypes.push(t);
        }
    }
    if keys.is_empty() {
        None
    } else {
        Some((keys, etypes))
    }
}

/// MIT `sort_enctypes` (`gic_keytab.c:149-174`): moves the keytab's etypes to the front of the
/// request list, preserving order otherwise.
///
/// Moves etypes that appear in `keytab` to the front of `req`, preserving
/// relative order in each group.
pub fn sort_etypes_keytab_first(req: &mut [i32], keytab: &[i32]) {
    let mut front = Vec::with_capacity(req.len());
    let mut back = Vec::with_capacity(req.len());
    for &e in req.iter() {
        if keytab.contains(&e) {
            front.push(e);
        } else {
            back.push(e);
        }
    }
    for (slot, v) in req.iter_mut().zip(front.into_iter().chain(back)) {
        *slot = v;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_types::{PrincipalName, ascii};

    fn sample_entry() -> KeytabEntry {
        let key = ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &[9u8; 16]).unwrap();
        KeytabEntry {
            realm: ascii("KERBER.TEST"),
            name: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
            timestamp: 1_700_000_000,
            kvno: 1,
            key,
        }
    }

    fn patch_etype(body: &mut [u8], etype: u16) {
        let mut i = 0;
        let ncomp = u16::from_be_bytes([body[0], body[1]]);
        i += 2;
        let rlen = usize::from(u16::from_be_bytes([body[i], body[i + 1]]));
        i += 2 + rlen;
        for _ in 0..ncomp {
            let n = usize::from(u16::from_be_bytes([body[i], body[i + 1]]));
            i += 2 + n;
        }
        i += 4 + 4 + 1;
        body[i..i + 2].copy_from_slice(&etype.to_be_bytes());
    }

    /// MIT `krb5_ktfileint_internal_read_entry` (`lib/krb5/keytab/kt_file.c:1084-1095`): a 32-bit kvno of 0 is fill, and the 8-bit kvno stands; any other replaces it.
    #[test]
    fn a_zero_32_bit_kvno_keeps_the_8_bit_one() {
        let record = |kvno: u32, zero_fill: bool, etype: Option<u16>| {
            let mut e = sample_entry();
            e.kvno = kvno;
            let mut body = Vec::new();
            marshal_entry(&mut body, &e, 0x0502);
            if zero_fill {
                let n = body.len();
                body[n - 4..].fill(0);
            }
            if let Some(et) = etype {
                patch_etype(&mut body, et);
            }
            let mut bytes = vec![0x05, 0x02];
            bytes.extend_from_slice(&i32::try_from(body.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(&body);
            Keytab::parse(&bytes).unwrap()
        };
        assert_eq!(record(300, false, None).entries[0].kvno, 300);
        assert_eq!(
            record(300, true, None).entries[0].kvno,
            44,
            "300 cut to 8 bits"
        );
        assert_eq!(record(5, true, None).entries[0].kvno, 5);
        let unknown = record(7, true, Some(99));
        let meta = Keytab::unparsed_meta(&unknown.unparsed[0].1, 0x0502).unwrap();
        assert_eq!(meta.0, 7);
    }

    /// MIT `krb5_ktfileint_internal_read_entry` (`lib/krb5/keytab/kt_file.c:942-1095`): a version-1 entry is in host byte order, counts its realm, has no name type, and carries its 32-bit kvno in host byte order too. MIT's writer (`krb5_ktfileint_write_entry`, `krb5_ktfileint_size_entry`, `krb5_ktfileint_find_slot`) sizes each record for a name type it does not write: the four bytes are zero fill before the next record and absent after the last, as `ktadd` onto a version-1 file leaves them (settled live).
    #[test]
    fn a_version_1_keytab_is_mits_host_order_layout() {
        let ne16 = |b: &mut Vec<u8>, v: u16| b.extend_from_slice(&v.to_ne_bytes());
        let record = |out: &mut Vec<u8>, kvno32: u32, last: bool| {
            let mut body = Vec::new();
            ne16(&mut body, 2);
            ne16(&mut body, 11);
            body.extend_from_slice(b"KERBER.TEST");
            ne16(&mut body, 4);
            body.extend_from_slice(b"user");
            body.extend_from_slice(&1_700_000_000u32.to_ne_bytes());
            body.push(44);
            ne16(&mut body, 17);
            ne16(&mut body, 16);
            body.extend_from_slice(&[9u8; 16]);
            body.extend_from_slice(&kvno32.to_ne_bytes());
            let size = body.len() + 4;
            out.extend_from_slice(&i32::try_from(size).unwrap().to_ne_bytes());
            out.extend_from_slice(&body);
            if !last {
                out.extend_from_slice(&[0; 4]);
            }
        };
        let mut bytes = vec![0x05, 0x01];
        record(&mut bytes, 300, false);
        record(&mut bytes, 0, true);
        let kt = Keytab::parse(&bytes).unwrap();
        assert_eq!(kt.version, 0x0501);
        assert_eq!(
            kt.entries.len(),
            2,
            "the last record, four bytes short, is read"
        );
        let e = &kt.entries[0];
        assert_eq!(e.kvno, 300);
        assert_eq!(e.timestamp, 1_700_000_000);
        assert_eq!(e.realm.as_bytes(), b"KERBER.TEST");
        assert_eq!(e.name.components_joined(), "user");
        assert_eq!(e.name.name_type, PrincipalName::NT_UNKNOWN);
        assert_eq!(
            kt.entries[1].kvno, 44,
            "a zero 32-bit kvno leaves the 8-bit one"
        );
        let mut again = vec![0x05, 0x01];
        record(&mut again, 300, false);
        record(&mut again, 44, true);
        assert_eq!(
            &*kt.to_bytes(),
            &again[..],
            "MIT's writer makes the same file"
        );
    }

    /// MIT `krb5_ktfileint_internal_read_entry` (`lib/krb5/keytab/kt_file.c:890-1116`): a size of
    /// 0, a short field, or a count or length that is not positive ends the keytab
    /// (`KRB5_KT_END`), its entries so far being the keytab; a record whose size runs past the
    /// file's end is read from the bytes there.
    #[test]
    fn a_record_ends_the_keytab_where_mits_reader_stops() {
        let whole = || {
            let mut body = Vec::new();
            marshal_entry(&mut body, &sample_entry(), 0x0502);
            let mut rec = i32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
            rec.extend_from_slice(&body);
            rec
        };
        // After the record's 4-byte size: count at 4, realm length at 6, the component's length
        // at 19, key length at 36 (`sample_entry`: realm KERBER.TEST, one component "user").
        let with = |edit: &dyn Fn(&mut Vec<u8>)| {
            let mut bytes = vec![0x05, 0x02];
            bytes.extend_from_slice(&whole());
            let mut second = whole();
            edit(&mut second);
            bytes.extend_from_slice(&second);
            bytes.extend_from_slice(&whole());
            let kt = Keytab::parse(&bytes).unwrap();
            (kt.entries.len(), kt.unparsed.len())
        };
        assert_eq!(with(&|_| {}), (3, 0));
        assert_eq!(with(&|r| r[..4].fill(0)), (1, 0), "a size of 0");
        assert_eq!(with(&|r| r[4..6].fill(0)), (1, 0), "a count of 0");
        assert_eq!(with(&|r| r[6..8].fill(0)), (1, 0), "a realm length of 0");
        assert_eq!(
            with(&|r| r[19..21].copy_from_slice(&0x8000u16.to_be_bytes())),
            (1, 0),
            "a component length negative as MIT's int16"
        );
        assert_eq!(with(&|r| r[36..38].fill(0)), (1, 0), "a key length of 0");
        assert_eq!(
            with(&|r| r[..4].copy_from_slice(&40i32.to_be_bytes())),
            (1, 0),
            "fields past the record's own size"
        );
        let mut cut = vec![0x05, 0x02];
        cut.extend_from_slice(&whole());
        let mut short = whole();
        short.truncate(short.len() - 2);
        cut.extend_from_slice(&short);
        assert_eq!(
            Keytab::parse(&cut).unwrap().entries.len(),
            1,
            "its 32-bit kvno cut short"
        );
        let mut past = vec![0x05, 0x02];
        let mut long = whole();
        long[..4].copy_from_slice(&80i32.to_be_bytes());
        past.extend_from_slice(&long);
        let kt = Keytab::parse(&past).unwrap();
        assert_eq!(kt.entries.len(), 1, "a size past the file's end");
        assert_eq!(kt.entries[0].kvno, 1);
        assert!(
            Keytab::parse(&[0x05, 0x02, 0, 0, 0, 20, 1])
                .unwrap()
                .entries
                .is_empty()
        );
    }

    #[test]
    fn merge_keeps_unknown_etype_bytes() {
        let known = Keytab::single(
            ascii("KERBER.TEST"),
            PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
            1,
            ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &[9u8; 16]).unwrap(),
        );
        let mut body = Vec::new();
        marshal_entry(&mut body, &sample_entry(), 0x0502);
        patch_etype(&mut body, 99);
        let mut rec = i32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        rec.extend_from_slice(&body);
        let mut bytes = known.to_bytes().to_vec();
        bytes.extend_from_slice(&rec);
        let parsed = Keytab::parse(&bytes).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.unparsed.len(), 1);
        assert_eq!(*parsed.unparsed[0].1, rec);
        let extra = Keytab::single(
            ascii("KERBER.TEST"),
            PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["host"]),
            2,
            ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &[8u8; 16]).unwrap(),
        );
        let mut merged = parsed;
        merged.merge(extra);
        let out = merged.to_bytes();
        let again = Keytab::parse(&out).unwrap();
        assert_eq!(again.entries.len(), 2);
        assert_eq!(again.unparsed.len(), 1);
        assert_eq!(*again.unparsed[0].1, rec);
        assert!(out.windows(rec.len()).any(|w| w == rec.as_slice()));
    }

    #[test]
    fn slots_number_unparsed_and_delent() {
        let known = Keytab::single(
            ascii("KERBER.TEST"),
            PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
            1,
            ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &[9u8; 16]).unwrap(),
        );
        let mut body = Vec::new();
        marshal_entry(&mut body, &sample_entry(), 0x0502);
        patch_etype(&mut body, 99);
        let mut rec = i32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        rec.extend_from_slice(&body);
        let mut bytes = known.to_bytes().to_vec();
        bytes.extend_from_slice(&rec);
        let extra = Keytab::single(
            ascii("KERBER.TEST"),
            PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["host"]),
            2,
            ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &[8u8; 16]).unwrap(),
        );
        bytes.extend_from_slice(&extra.to_bytes()[2..]);
        let mut parsed = Keytab::parse(&bytes).unwrap();
        assert_eq!(parsed.slots().len(), 3);
        assert!(matches!(parsed.slots()[1], KeytabSlot::Unparsed(_)));
        parsed.remove_slot(2).unwrap();
        assert_eq!(parsed.slots().len(), 2);
        assert!(matches!(parsed.slots()[0], KeytabSlot::Entry(_)));
        assert!(matches!(parsed.slots()[1], KeytabSlot::Entry(_)));
        assert_eq!(parsed.unparsed, [] as [(usize, Zeroizing<Vec<u8>>); 0]);
    }

    /// The key of a record kept raw is a slice of that record, not a copy, so the record's own
    /// wipe (it is `Zeroizing`) is the wipe of the only copy of the key.
    #[test]
    fn an_unparsed_records_key_is_a_slice_of_the_record() {
        use zeroize::Zeroize as _;
        let mut body = Vec::new();
        marshal_entry(&mut body, &sample_entry(), 0x0502);
        patch_etype(&mut body, 99);
        let mut bytes = 0x0502u16.to_be_bytes().to_vec();
        bytes.extend_from_slice(&i32::try_from(body.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(&body);
        let mut kt = Keytab::parse(&bytes).unwrap();
        let raw = &kt.unparsed[0].1;
        let key = Keytab::unparsed_key(raw, kt.version).unwrap();
        assert_eq!(key, [9u8; 16]);
        let (start, at) = (raw.as_ptr().addr(), key.as_ptr().addr());
        assert!(
            start <= at && at + key.len() <= start + raw.len(),
            "the key was copied out of its record"
        );
        let (off, n) = (at - start, key.len());
        kt.unparsed[0].1.as_mut_slice().zeroize();
        assert!(kt.unparsed[0].1[off..off + n].iter().all(|&b| b == 0));
    }

    /// The buffer `to_bytes` writes a keytab into is sized for the whole keytab before the first
    /// byte, so no reallocation copied a key into a block left unwiped.
    #[test]
    fn to_bytes_sizes_its_buffer_before_the_first_key() {
        let mut kt = Keytab::single(
            ascii("KERBER.TEST"),
            PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
            1,
            ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[7u8; 32]).unwrap(),
        );
        for (kvno, name) in [(2, "host"), (3, "nfs")] {
            kt.entries.push(KeytabEntry {
                realm: ascii("KERBER.TEST"),
                name: PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]),
                timestamp: 1,
                kvno,
                key: ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[8u8; 32])
                    .unwrap(),
            });
        }
        let bytes = kt.to_bytes();
        assert_eq!(bytes.capacity(), bytes.len());
        assert_eq!(Keytab::parse(&bytes).unwrap().entries.len(), 3);
    }

    fn entry(name: &str, kvno: u32, key: u8) -> KeytabEntry {
        KeytabEntry {
            realm: ascii("KERBER.TEST"),
            name: PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]),
            timestamp: 1_700_000_000,
            kvno,
            key: ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &[key; 16]).unwrap(),
        }
    }

    fn keytab(version: u16, entries: Vec<KeytabEntry>) -> Keytab {
        Keytab {
            version,
            entries,
            ..Keytab::default()
        }
    }

    /// MIT `krb5_ktfileint_open` (`lib/krb5/keytab/kt_file.c:731-808`): `wkt` makes a missing file at version 2 and adds to an existing one in its own version, refusing one that is no keytab with `KRB5_KEYTAB_BADVNO`'s text; MIT's `ktutil` and this one leave the same bytes (settled live).
    #[test]
    fn wkt_adds_entries_as_mits_krb5_kt_add_entry() {
        let both = || vec![entry("a", 300, 1), entry("b", 2, 2)];
        let new = add_to_keytab_file(None, &keytab(0x0501, both())).unwrap();
        assert_eq!(
            &*new,
            &*keytab(0x0502, both()).to_bytes(),
            "a new file is version 2"
        );
        let v1 = keytab(0x0501, vec![entry("a", 300, 1)]).to_bytes();
        let added = add_to_keytab_file(Some(&v1), &keytab(0x0502, vec![entry("b", 2, 2)])).unwrap();
        assert_eq!(
            &*added,
            &*keytab(0x0501, both()).to_bytes(),
            "a version-1 file gains a version-1 record, the last one's fill written first"
        );
        for bad in [&b""[..], b"\x05", b"\x05\x03", b"hello"] {
            let e = add_to_keytab_file(Some(bad), &keytab(0x0502, both())).unwrap_err();
            assert_eq!(e.to_string(), "Unsupported key table format version number");
        }
        let mut past = vec![0x05, 0x02];
        past.extend_from_slice(&100i32.to_be_bytes());
        past.extend_from_slice(&[0; 20]);
        assert!(add_to_keytab_file(Some(&past), &keytab(0x0502, both())).is_err());
    }

    /// MIT `krb5_ktfileint_find_slot` (`lib/krb5/keytab/kt_file.c:1314-1382`): a record takes the first hole as large at the hole's size, else a size of 0 with a 0 written after it, else the end of the file.
    #[test]
    fn wkt_fills_a_hole_and_a_zero_size_as_mits_find_slot() {
        let b = entry("b", 2, 2);
        let need = entry_len(&b);
        let record = |e: &KeytabEntry| {
            let mut r = Vec::new();
            r.extend_from_slice(&i32::try_from(entry_len(e)).unwrap().to_be_bytes());
            marshal_entry(&mut r, e, 0x0502);
            r
        };
        let mut file = vec![0x05, 0x02];
        file.extend_from_slice(&(-i32::try_from(need - 1).unwrap()).to_be_bytes());
        file.extend_from_slice(&vec![0; need - 1]);
        let small = need + 12;
        file.extend_from_slice(&(-i32::try_from(small).unwrap()).to_be_bytes());
        file.extend_from_slice(&vec![0; small]);
        let out = add_to_keytab_file(Some(&file), &keytab(0x0502, vec![entry("b", 2, 2)])).unwrap();
        let at = 2 + 4 + need - 1;
        assert_eq!(out.len(), file.len(), "the record is in the second hole");
        assert_eq!(out[at..at + 4], i32::try_from(small).unwrap().to_be_bytes());
        assert_eq!(out[at + 4..at + 4 + need], record(&b)[4..]);
        assert!(out[at + 4 + need..].iter().all(|&x| x == 0));
        let kt = Keytab::parse(&out).unwrap();
        assert_eq!((kt.entries.len(), kt.entries[0].kvno), (1, 2));

        let mut zero = vec![0x05, 0x02];
        zero.extend_from_slice(&record(&entry("a", 1, 1)));
        zero.extend_from_slice(&[0; 4]);
        zero.extend_from_slice(b"junk");
        let out = add_to_keytab_file(Some(&zero), &keytab(0x0502, vec![b])).unwrap();
        let at = zero.len() - 8;
        assert_eq!(out[at..at + 4 + need], record(&entry("b", 2, 2))[..]);
        assert_eq!(out[at + 4 + need..at + 8 + need], [0; 4], "a 0 after it");
        assert_eq!(Keytab::parse(&out).unwrap().entries.len(), 2);
    }

    /// MIT `krb5_ktfileint_write_entry` (`lib/krb5/keytab/kt_file.c:1127-1269`): an entry written to a keytab gets the time of day, in the file and in the caller's entry (settled live: MIT `ktutil`'s `wkt` stamps every entry it writes); an open that fails changes nothing.
    #[test]
    fn wkt_stamps_each_entry_with_the_time_it_is_written() {
        let dir = krb5_testkit::scratch_dir("keytab-stamp");
        let path = dir.join("kt");
        let mut kt = keytab(0x0502, vec![entry("a", 1, 1)]);
        let before = time_of_day();
        kt.add_to_file(&path).unwrap();
        let after = time_of_day();
        let stamp = kt.entries[0].timestamp;
        assert!(
            before <= stamp && stamp <= after,
            "{before} {stamp} {after}"
        );
        let back = Keytab::parse(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(back.entries[0].timestamp, stamp);
        let junk = dir.join("junk");
        std::fs::write(&junk, b"hello").unwrap();
        let mut old = keytab(0x0502, vec![entry("b", 1, 1)]);
        assert!(old.add_to_file(&junk).is_err());
        assert_eq!(
            old.entries[0].timestamp, 1_700_000_000,
            "a refused file stamps nothing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A raw record moves between versions as MIT reads and writes it, so a keytab merged from
    /// files of both versions keeps every raw record in its own version.
    #[test]
    fn merge_lays_a_raw_record_out_in_the_keytabs_version() {
        let mut body = Vec::new();
        marshal_entry(&mut body, &sample_entry(), 0x0502);
        patch_etype(&mut body, 99);
        let mut bytes = 0x0502u16.to_be_bytes().to_vec();
        bytes.extend_from_slice(&i32::try_from(body.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(&body);
        let v2 = Keytab::parse(&bytes).unwrap();
        let mut v1 = keytab(0x0501, vec![entry("a", 300, 1)]);
        v1.merge(v2);
        let raw = &v1.unparsed[0].1;
        let meta = Keytab::unparsed_meta(raw, 0x0501).unwrap();
        assert_eq!(
            (meta.0, meta.1.as_str(), meta.3),
            (1, "user@KERBER.TEST", 99)
        );
        let again = Keytab::parse(&v1.to_bytes()).unwrap();
        assert_eq!((again.entries.len(), again.unparsed.len()), (1, 1));
        let file = add_to_keytab_file(None, &v1).unwrap();
        let back = Keytab::parse(&file).unwrap();
        assert_eq!(back.version, 0x0502);
        assert_eq!(
            Keytab::unparsed_meta(&back.unparsed[0].1, 0x0502)
                .unwrap()
                .1,
            "user@KERBER.TEST"
        );
    }

    #[test]
    fn truncated_entry_is_not_unparsed() {
        let kt = Keytab::parse(&[0x05, 0x02, 0, 0, 0, 20, 1]).unwrap();
        assert!(kt.entries.is_empty() && kt.unparsed.is_empty());
    }

    /// An unknown-etype record whose size runs past the file's end is kept with the size it has,
    /// so a keytab written back with more records after it stays readable.
    #[test]
    fn an_unparsed_record_cut_by_the_files_end_keeps_the_size_it_has() {
        let mut body = Vec::new();
        marshal_entry(&mut body, &sample_entry(), 0x0502);
        patch_etype(&mut body, 99);
        let mut bytes = 0x0502u16.to_be_bytes().to_vec();
        bytes.extend_from_slice(&i32::try_from(body.len() + 4).unwrap().to_be_bytes());
        bytes.extend_from_slice(&body);
        let mut kt = Keytab::parse(&bytes).unwrap();
        assert_eq!(kt.unparsed.len(), 1);
        assert_eq!(
            kt.unparsed[0].1[..4],
            i32::try_from(body.len()).unwrap().to_be_bytes()
        );
        kt.merge(Keytab::single(
            ascii("KERBER.TEST"),
            PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["host"]),
            2,
            ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &[8u8; 16]).unwrap(),
        ));
        let again = Keytab::parse(&kt.to_bytes()).unwrap();
        assert_eq!((again.unparsed.len(), again.entries.len()), (1, 1));
        assert_eq!(again.entries[0].kvno, 2);
    }

    #[test]
    fn a_keytabs_debug_shows_an_unparsed_records_length_not_its_octets() {
        let kt = Keytab {
            version: 0x0502,
            entries: Vec::new(),
            skipped_unknown_etype: 1,
            unparsed: vec![(0, Zeroizing::new(vec![0x13, 0x37, 0xc0, 0xde]))],
        };
        assert_eq!(
            format!("{kt:?}"),
            "Keytab { version: 1282, entries: [], skipped_unknown_etype: 1, \
             unparsed: [(0, <redacted, 4 octets>)] }"
        );
    }
}
