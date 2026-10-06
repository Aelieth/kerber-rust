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
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(0));
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
            + self
                .entries
                .iter()
                .map(|e| 4 + entry_len(e, ver))
                .sum::<usize>();
        let mut out = Zeroizing::new(Vec::with_capacity(size));
        out.extend_from_slice(&ver.to_be_bytes());
        let mut ei = 0;
        let mut ui = 0;
        loop {
            if ui < self.unparsed.len() && (ei >= self.entries.len() || self.unparsed[ui].0 <= ei) {
                out.extend_from_slice(&self.unparsed[ui].1);
                ui += 1;
                continue;
            }
            let Some(e) = self.entries.get(ei) else {
                break;
            };
            let len = i32::try_from(entry_len(e, ver)).unwrap_or(0);
            out.extend_from_slice(&len.to_be_bytes());
            marshal_entry(&mut out, e, ver);
            ei += 1;
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

    /// Append `other` entries (ktadd / merge).
    pub fn merge(&mut self, other: Keytab) {
        let n = self.entries.len();
        self.entries.extend(other.entries);
        self.skipped_unknown_etype += other.skipped_unknown_etype;
        self.unparsed.extend(
            other
                .unparsed
                .into_iter()
                .map(|(i, b)| (i.saturating_add(n), b)),
        );
    }

    /// Parse v1 or v2. Unknown etypes skip that entry rather than failing.
    ///
    /// # Errors
    ///
    /// `io::ErrorKind::InvalidData` for a missing version or one other than `0x0501` /
    /// `0x0502`, a hole size of `i32::MIN`, a key whose length does not match its enctype, or a
    /// realm or name component that is not ASCII GeneralString; `io::ErrorKind::UnexpectedEof`
    /// when an entry is truncated.
    pub fn parse(bytes: &[u8]) -> Result<Self, io::Error> {
        if bytes.len() < 2 || bytes[0] != 0x05 || (bytes[1] != 0x01 && bytes[1] != 0x02) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not keytab v1/v2",
            ));
        }
        let version = u16::from_be_bytes([bytes[0], bytes[1]]);
        let mut i = 2;
        let mut entries = Vec::new();
        let mut unparsed = Vec::new();
        while i + 4 <= bytes.len() {
            let rec = i;
            let size = i32::from_be_bytes(bytes[i..i + 4].try_into().map_err(|_| eof())?);
            i += 4;
            if size <= 0 {
                let skip = match size.checked_neg() {
                    Some(n) => usize::try_from(n).unwrap_or(0),
                    None => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "keytab hole size is i32::MIN",
                        ));
                    }
                };
                i = i.saturating_add(skip);
                continue;
            }
            let size = usize::try_from(size).unwrap_or(0);
            if i.saturating_add(size) > bytes.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "keytab entry"));
            }
            match parse_entry(&bytes[i..i + size], version) {
                Ok(e) => entries.push(e),
                Err(EntryErr::UnsupportedEtype) => {
                    unparsed.push((entries.len(), Zeroizing::new(bytes[rec..i + size].to_vec())));
                }
                Err(EntryErr::Io(e)) => return Err(e),
            }
            i += size;
        }
        Ok(Self {
            version,
            skipped_unknown_etype: unparsed.len(),
            unparsed,
            entries,
        })
    }
}

/// The length of the record [`marshal_entry`] writes for `e`.
/// MIT `krb5_ktfileint_size_entry` (`kt_file.c:1276-1299`): every counted field, the fixed ones,
/// and the version-2 kvno.
fn entry_len(e: &KeytabEntry, ver: u16) -> usize {
    let counted = |d: &[u8]| 2 + d.len().min(usize::from(u16::MAX));
    2 + counted(e.realm.as_bytes())
        + e.name
            .name_string
            .iter()
            .map(|c| counted(c.as_bytes()))
            .sum::<usize>()
        + 4
        + 4
        + 1
        + 2
        + counted(e.key.as_bytes())
        + if ver == 0x0502 { 4 } else { 0 }
}

/// One entry's record, appended to `b` (sized by the caller, [`entry_len`]).
/// MIT `krb5_ktfileint_write_entry` (`kt_file.c:1127-1269`): the record a keytab file entry is,
/// the version-2 kvno after the key.
fn marshal_entry(b: &mut Vec<u8>, e: &KeytabEntry, ver: u16) {
    let ncomp = u16::try_from(e.name.name_string.len()).unwrap_or(0);
    b.extend_from_slice(&ncomp.to_be_bytes());
    put16(b, e.realm.as_bytes());
    for c in &e.name.name_string {
        put16(b, c.as_bytes());
    }
    b.extend_from_slice(&e.name.name_type.to_be_bytes());
    b.extend_from_slice(&e.timestamp.to_be_bytes());
    #[allow(clippy::cast_possible_truncation)]
    b.push((e.kvno & 0xff) as u8);
    let enctype = u16::try_from(e.key.etype().to_iana()).unwrap_or(0);
    b.extend_from_slice(&enctype.to_be_bytes());
    put16(b, e.key.as_bytes());
    if ver == 0x0502 {
        b.extend_from_slice(&e.kvno.to_be_bytes());
    }
}

enum EntryErr {
    UnsupportedEtype,
    Io(io::Error),
}

impl From<io::Error> for EntryErr {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// An unknown-etype record's kvno, principal, timestamp and enctype, and where its key lies in it
/// (no copy of the key is made).
type UnparsedMeta = (u32, String, u32, i32, std::ops::Range<usize>);

fn parse_unparsed_meta(body: &[u8], ver: u16) -> Result<UnparsedMeta, io::Error> {
    let mut i = 0;
    let ncomp = take_u16(body, &mut i)?;
    let realm = take_counted16(body, &mut i)?;
    let mut parts = Vec::new();
    for _ in 0..ncomp {
        parts.push(take_counted16(body, &mut i)?);
    }
    let nametype = take_i32(body, &mut i)?;
    let timestamp = take_u32(body, &mut i)?;
    if i >= body.len() {
        return Err(eof());
    }
    let kvno8 = body[i];
    i += 1;
    let enctype = i32::from(take_u16(body, &mut i)?);
    let keybytes = take_counted16_range(body, &mut i)?;
    let kvno = if ver == 0x0502 && i + 4 <= body.len() {
        take_u32(body, &mut i)?
    } else {
        u32::from(kvno8)
    };
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

/// MIT `krb5_ktfileint_internal_read_entry` (`kt_file.c:1091-1095`): a version-2 entry's 32-bit
/// kvno replaces the one-byte kvno. A key whose bytes are not that etype's length is not an
/// entry.
fn parse_entry(body: &[u8], ver: u16) -> Result<KeytabEntry, EntryErr> {
    let mut i = 0;
    let ncomp = take_u16(body, &mut i)?;
    let realm = take_counted16(body, &mut i)?;
    let mut parts = Vec::new();
    for _ in 0..ncomp {
        parts.push(take_counted16(body, &mut i)?);
    }
    let nametype = take_i32(body, &mut i)?;
    let timestamp = take_u32(body, &mut i)?;
    if i >= body.len() {
        return Err(eof().into());
    }
    let kvno8 = body[i];
    i += 1;
    let enctype = i32::from(take_u16(body, &mut i)?);
    let keybytes = Zeroizing::new(take_counted16(body, &mut i)?);
    let kvno = if ver == 0x0502 && i + 4 <= body.len() {
        take_u32(body, &mut i)?
    } else {
        u32::from(kvno8)
    };
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

fn put16(b: &mut Vec<u8>, data: &[u8]) {
    let n = u16::try_from(data.len()).unwrap_or(u16::MAX);
    b.extend_from_slice(&n.to_be_bytes());
    b.extend_from_slice(&data[..usize::from(n)]);
}

fn take_u16(b: &[u8], i: &mut usize) -> Result<u16, io::Error> {
    if *i + 2 > b.len() {
        return Err(eof());
    }
    let v = u16::from_be_bytes(b[*i..*i + 2].try_into().map_err(|_| eof())?);
    *i += 2;
    Ok(v)
}

fn take_u32(b: &[u8], i: &mut usize) -> Result<u32, io::Error> {
    if *i + 4 > b.len() {
        return Err(eof());
    }
    let v = u32::from_be_bytes(b[*i..*i + 4].try_into().map_err(|_| eof())?);
    *i += 4;
    Ok(v)
}

fn take_i32(b: &[u8], i: &mut usize) -> Result<i32, io::Error> {
    Ok(i32::from_be_bytes(take_u32(b, i)?.to_be_bytes()))
}

fn take_counted16(b: &[u8], i: &mut usize) -> Result<Vec<u8>, io::Error> {
    let n = usize::from(take_u16(b, i)?);
    if *i + n > b.len() {
        return Err(eof());
    }
    let v = b[*i..*i + n].to_vec();
    *i += n;
    Ok(v)
}

fn take_counted16_range(b: &[u8], i: &mut usize) -> Result<std::ops::Range<usize>, io::Error> {
    let n = usize::from(take_u16(b, i)?);
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

    #[test]
    fn truncated_entry_is_not_unparsed() {
        let err = Keytab::parse(&[0x05, 0x02, 0, 0, 0, 20, 1]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
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
