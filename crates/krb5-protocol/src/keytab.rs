//! MIT keytab v1 (`0x0501`) and v2 (`0x0502`). Unknown etypes are skipped.

use std::io;
use std::path::Path;

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_types::{PrincipalName, Realm, kerberos_string_from_bytes};

use crate::secret_file::write_secret_file;

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

/// MIT keytab (v1 or v2).
#[derive(Debug, Default)]
pub struct Keytab {
    /// File version (`0x0501` or `0x0502`).
    pub version: u16,
    /// Entries in file order (unknown etypes omitted).
    pub entries: Vec<KeytabEntry>,
    /// Count of entries skipped because the etype is unknown / refused.
    pub skipped_unknown_etype: usize,
    /// Unknown-etype records (parsed-entry count before each raw blob).
    pub unparsed: Vec<(usize, Vec<u8>)>,
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

    /// Serialize as MIT keytab v2 (`0x0502`) unless [`Self::version`] is v1.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let ver = if self.version == 0x0501 {
            0x0501u16
        } else {
            0x0502
        };
        let mut out = ver.to_be_bytes().to_vec();
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
            let body = marshal_entry(e, ver);
            let len = i32::try_from(body.len()).unwrap_or(0);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&body);
            ei += 1;
        }
        out
    }

    /// Atomic 0600 write.
    ///
    /// # Errors
    ///
    /// Returns I/O errors.
    pub fn write_file(&self, path: impl AsRef<Path>) -> Result<(), io::Error> {
        write_secret_file(path.as_ref(), &self.to_bytes())
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
    /// Truncation, `i32::MIN` hole size, or a non-keytab header.
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
                Err(err)
                    if err.kind() == io::ErrorKind::InvalidData
                        && err.to_string().contains("etype") =>
                {
                    unparsed.push((entries.len(), bytes[rec..i + size].to_vec()));
                }
                Err(e) => return Err(e),
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

fn marshal_entry(e: &KeytabEntry, ver: u16) -> Vec<u8> {
    let mut b = Vec::new();
    let ncomp = u16::try_from(e.name.name_string.len()).unwrap_or(0);
    b.extend_from_slice(&ncomp.to_be_bytes());
    put16(&mut b, e.realm.as_bytes());
    for c in &e.name.name_string {
        put16(&mut b, c.as_bytes());
    }
    b.extend_from_slice(&e.name.name_type.to_be_bytes());
    b.extend_from_slice(&e.timestamp.to_be_bytes());
    #[allow(clippy::cast_possible_truncation)]
    b.push((e.kvno & 0xff) as u8);
    let enctype = u16::try_from(e.key.etype().to_iana()).unwrap_or(0);
    b.extend_from_slice(&enctype.to_be_bytes());
    put16(&mut b, e.key.as_bytes());
    if ver == 0x0502 {
        b.extend_from_slice(&e.kvno.to_be_bytes());
    }
    b
}

fn parse_entry(body: &[u8], ver: u16) -> Result<KeytabEntry, io::Error> {
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
    let keybytes = take_counted16(body, &mut i)?;
    let kvno = if ver == 0x0502 && i + 4 <= body.len() {
        take_u32(body, &mut i)?
    } else {
        u32::from(kvno8)
    };
    let etype = EncryptionType::known(enctype)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("etype {enctype}")))?;
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

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "keytab truncated")
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
        let mut body = marshal_entry(&sample_entry(), 0x0502);
        patch_etype(&mut body, 99);
        let mut rec = i32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        rec.extend_from_slice(&body);
        let mut bytes = known.to_bytes();
        bytes.extend_from_slice(&rec);
        let parsed = Keytab::parse(&bytes).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.unparsed.len(), 1);
        assert_eq!(parsed.unparsed[0].1, rec);
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
        assert_eq!(again.unparsed[0].1, rec);
        assert!(out.windows(rec.len()).any(|w| w == rec.as_slice()));
    }
}
