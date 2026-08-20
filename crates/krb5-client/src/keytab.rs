//! MIT keytab version 0x0502 (see MIT 1.22.2 keytab file format).

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use krb5_crypto::ProtocolKey;
use krb5_types::{PrincipalName, Realm};

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

/// Version 0x0502 keytab.
#[derive(Debug)]
pub struct Keytab {
    /// Entries in file order.
    pub entries: Vec<KeytabEntry>,
}

impl Keytab {
    /// A single-entry keytab for tests and `ktadd`-like dumps.
    #[must_use]
    pub fn single(realm: Realm, name: PrincipalName, kvno: u32, key: ProtocolKey) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| u32::try_from(d.as_secs()).unwrap_or(0))
            .unwrap_or(0);
        Self {
            entries: vec![KeytabEntry {
                realm,
                name,
                timestamp,
                kvno,
                key,
            }],
        }
    }

    /// Serialize as MIT keytab v2.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![0x05, 0x02];
        for e in &self.entries {
            let body = marshal_entry(e);
            let len = i32::try_from(body.len()).unwrap_or(0);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&body);
        }
        out
    }

    /// Write to `path`.
    ///
    /// # Errors
    ///
    /// Returns I/O errors.
    pub fn write_file(&self, path: impl AsRef<Path>) -> Result<(), io::Error> {
        let mut f = File::create(path.as_ref())?;
        f.write_all(&self.to_bytes())?;
        Ok(())
    }

    /// Parse a v0x0502 keytab.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] when the file is truncated or not v2.
    pub fn parse(bytes: &[u8]) -> Result<Self, io::Error> {
        if bytes.len() < 2 || bytes[0] != 0x05 || bytes[1] != 0x02 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not keytab v2"));
        }
        let mut i = 2;
        let mut entries = Vec::new();
        while i + 4 <= bytes.len() {
            let size = i32::from_be_bytes(bytes[i..i + 4].try_into().unwrap());
            i += 4;
            if size <= 0 {
                let skip = (-size) as usize;
                i = i.saturating_add(skip);
                continue;
            }
            let size = size as usize;
            if i + size > bytes.len() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "keytab entry"));
            }
            let entry = parse_entry(&bytes[i..i + size])?;
            entries.push(entry);
            i += size;
        }
        Ok(Self { entries })
    }
}

fn marshal_entry(e: &KeytabEntry) -> Vec<u8> {
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
    b.extend_from_slice(&e.kvno.to_be_bytes());
    b
}

fn parse_entry(body: &[u8]) -> Result<KeytabEntry, io::Error> {
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
    let kvno = if i + 4 <= body.len() {
        take_u32(body, &mut i)?
    } else {
        u32::from(kvno8)
    };
    let etype = krb5_crypto::EncryptionType::from_iana(enctype)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let key = ProtocolKey::from_bytes(etype, &keybytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let realm_s = String::from_utf8(realm)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let part_s: Result<Vec<String>, _> = parts.into_iter().map(String::from_utf8).collect();
    let part_s = part_s.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(KeytabEntry {
        realm: krb5_types::ascii(&realm_s),
        name: PrincipalName::new(nametype, part_s),
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
    let v = u16::from_be_bytes(b[*i..*i + 2].try_into().unwrap());
    *i += 2;
    Ok(v)
}

fn take_u32(b: &[u8], i: &mut usize) -> Result<u32, io::Error> {
    if *i + 4 > b.len() {
        return Err(eof());
    }
    let v = u32::from_be_bytes(b[*i..*i + 4].try_into().unwrap());
    *i += 4;
    Ok(v)
}

fn take_i32(b: &[u8], i: &mut usize) -> Result<i32, io::Error> {
    Ok(take_u32(b, i)? as i32)
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
