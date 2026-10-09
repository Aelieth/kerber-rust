//! MIT FILE credential cache version 4: write, read, list, X-CACHECONF, and one credential
//! appended under the file's lock.

use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::path::Path;

use krb5_asn1::encode;
use krb5_crypto::ProtocolKey;
use krb5_types::{PrincipalName, Realm, Ticket};
use nix::errno::Errno;
use nix::fcntl::Flock;
use zeroize::Zeroizing;

use crate::ccmarshal::{
    FCC_TAG_DELTATIME, Writer, cred_len, marshal_cred, marshal_princ, take_u16, unmarshal_cred,
    unmarshal_princ,
};
use crate::lock_file::{FileLock, lock_file};
use crate::secret_file::write_fresh_cache_file;

pub use crate::ccmarshal::{CcacheCred, CcacheKeyblock};

/// MIT FILE ccache (version 4, big-endian).
#[derive(Clone)]
pub struct FileCcache {
    /// Default client principal.
    pub primary: (Realm, PrincipalName),
    /// Parsed credentials, including config and tombstones.
    pub creds: Vec<CcacheCred>,
    /// Tagged header fields (`FCC_TAG_DELTATIME` is tag 1, 8 bytes).
    pub header_tags: Vec<(u16, Vec<u8>)>,
    /// Unparsed records with how many parsed creds preceded each blob.
    pub unparsed: Vec<(usize, Vec<u8>)>,
}

impl FileCcache {
    /// New cache with a zero `DELTATIME` header.
    #[must_use]
    pub fn new(primary: (Realm, PrincipalName), creds: Vec<CcacheCred>) -> Self {
        Self {
            primary,
            creds,
            header_tags: vec![(FCC_TAG_DELTATIME, vec![0u8; 8])],
            unparsed: Vec::new(),
        }
    }

    /// Serialize to MIT FILE ccache version 4.
    ///
    /// # Errors
    ///
    /// None: every field is written into memory, so this is always `Ok`.
    pub fn to_bytes(&self) -> Result<Vec<u8>, io::Error> {
        let mut w = Writer::default();
        w.u16(0x0504);
        let mut hdr = Writer::default();
        for (tag, val) in &self.header_tags {
            hdr.u16(*tag);
            hdr.u16(u16::try_from(val.len()).unwrap_or(0));
            hdr.buf.extend_from_slice(val);
        }
        w.u16(u16::try_from(hdr.buf.len()).unwrap_or(0));
        w.buf.extend_from_slice(&hdr.buf);
        marshal_princ(&mut w, &self.primary.0, &self.primary.1);
        let mut cred_i = 0;
        let mut unp = 0;
        loop {
            if unp < self.unparsed.len()
                && (cred_i >= self.creds.len() || self.unparsed[unp].0 <= cred_i)
            {
                w.buf.extend_from_slice(&self.unparsed[unp].1);
                unp += 1;
                continue;
            }
            let Some(c) = self.creds.get(cred_i) else {
                break;
            };
            marshal_cred(&mut w, c);
            cred_i += 1;
        }
        Ok(w.buf)
    }

    /// Atomic exclusive write: always a new file, mode 0600, owned by the writer and given no
    /// SELinux context of its own, as MIT `fcc_initialize` leaves a cache.
    ///
    /// # Errors
    ///
    /// Create, write, sync, or rename failed.
    pub fn write_file(&self, path: impl AsRef<Path>) -> Result<(), io::Error> {
        let bytes = self.to_bytes()?;
        write_fresh_cache_file(path.as_ref(), &bytes)
    }

    /// Parse a FILE ccache v4.
    ///
    /// Principals and realms must be ASCII GeneralString (RFC 4120). A MIT
    /// cache with non-ASCII name octets fails parse; identity is lossless
    /// only inside that alphabet.
    ///
    /// # Errors
    ///
    /// `io::ErrorKind::InvalidData` when `bytes` is under 4 bytes or not version `0x0504`, a
    /// header tag overruns the header, a count exceeds the bytes left, or a realm or name
    /// component is not ASCII GeneralString; `io::ErrorKind::UnexpectedEof` when the header or
    /// a record is truncated.
    pub fn parse(bytes: &[u8]) -> Result<Self, io::Error> {
        if bytes.len() < 4 || bytes[0] != 0x05 || bytes[1] != 0x04 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not FILE ccache v4",
            ));
        }
        let mut i = 2;
        let hdr_len = usize::from(take_u16(bytes, &mut i)?);
        let hdr_end = i.saturating_add(hdr_len);
        if hdr_end > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "ccache header truncated",
            ));
        }
        let mut header_tags = Vec::new();
        while i + 4 <= hdr_end {
            let tag = take_u16(bytes, &mut i)?;
            let flen = usize::from(take_u16(bytes, &mut i)?);
            if i + flen > hdr_end {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ccache header tag overruns",
                ));
            }
            header_tags.push((tag, bytes[i..i + flen].to_vec()));
            i += flen;
        }
        i = hdr_end;
        let primary = unmarshal_princ(bytes, &mut i)?;
        let mut creds = Vec::new();
        while i < bytes.len() {
            creds.push(unmarshal_cred(bytes, &mut i)?);
        }
        Ok(Self {
            primary,
            creds,
            header_tags,
            unparsed: Vec::new(),
        })
    }

    /// Non-config, non-tombstone credentials (list).
    #[must_use]
    pub fn list(&self) -> Vec<&CcacheCred> {
        self.creds
            .iter()
            .filter(|c| !c.is_config() && !c.is_removed())
            .collect()
    }

    /// `user@REALM` as MIT klist prints it.
    #[must_use]
    pub fn format_principal(realm: &Realm, name: &PrincipalName) -> String {
        format!(
            "{}@{}",
            name.components_joined(),
            String::from_utf8_lossy(realm.as_bytes())
        )
    }

    /// Tombstone credentials whose server principal matches `server`.
    ///
    /// Length is unchanged (`X-CACHECONF:` → `X-RMED-CONF:` is 12 bytes).
    pub fn remove_cred(&mut self, realm: &Realm, server: &PrincipalName) {
        for c in &mut self.creds {
            if c.is_removed() {
                continue;
            }
            if c.server.0.as_bytes() == realm.as_bytes()
                && c.server.1.name_string == server.name_string
            {
                c.tombstone();
            }
        }
    }

    /// The value of the configuration entry `key` (for `principal` when one is named) that the
    /// cache's principal holds, if any.
    /// MIT `krb5_cc_get_config` (`lib/krb5/ccache/ccfns.c:263-292`): the entry `X-CACHECONF:` `krb5_ccache_conf_data/<key>[/<principal>]` of the cache's principal is retrieved with no other field matched, and its ticket field is the value.
    #[must_use]
    pub fn get_config(&self, principal: Option<&str>, key: &str) -> Option<&[u8]> {
        let mut comps: Vec<&[u8]> = vec![b"krb5_ccache_conf_data", key.as_bytes()];
        if let Some(p) = principal {
            comps.push(p.as_bytes());
        }
        self.creds
            .iter()
            .find(|c| {
                c.server.0.as_bytes() == b"X-CACHECONF:"
                    && c.client.0.as_bytes() == self.primary.0.as_bytes()
                    && c.client.1.name_string == self.primary.1.name_string
                    && c.server.1.name_string.len() == comps.len()
                    && c.server
                        .1
                        .name_string
                        .iter()
                        .zip(&comps)
                        .all(|(have, want)| have.as_bytes() == *want)
            })
            .map(|c| c.ticket.as_slice())
    }

    /// MIT `krb5_cc_set_config` (`ccfns.c k5_build_conf_principals`): an
    /// `X-CACHECONF:` entry named `krb5_ccache_conf_data/{key}[/{principal}]`
    /// (etype 0, the value in the ticket field), replacing an existing one.
    pub fn set_config(&mut self, principal: Option<&str>, key: &str, value: &[u8]) {
        let mut comps = vec!["krb5_ccache_conf_data", key];
        if let Some(p) = principal {
            comps.push(p);
        }
        let name = PrincipalName::new(PrincipalName::NT_UNKNOWN, comps.clone());
        self.creds
            .retain(|c| !(c.is_config() && c.server.1.name_string == name.name_string));
        let Ok(conf_realm) = krb5_types::kerberos_string_from_bytes(b"X-CACHECONF:") else {
            return;
        };
        self.creds.push(CcacheCred {
            client: self.primary.clone(),
            server: (conf_realm, name),
            key: CcacheKeyblock {
                etype: 0,
                contents: Vec::new(),
            },
            authtime: 0,
            starttime: 0,
            endtime: 0,
            renew_till: 0,
            is_skey: 0,
            ticket_flags: 0,
            addresses: Vec::new(),
            authdata: Vec::new(),
            ticket: value.to_vec(),
            second_ticket: Vec::new(),
        });
    }
}

/// Parse `user@REALM` into (PrincipalName, realm string).
///
/// # Errors
///
/// An error message when `spec` has no `@REALM`, an empty name or realm, a trailing `\`, a `/`
/// or an unquoted `@` inside the realm, or a component that is not ASCII GeneralString.
pub fn parse_principal(spec: &str) -> Result<(PrincipalName, String), String> {
    parse_principal_ex(spec, false)
}

/// Parse `name@REALM`. `enterprise` uses NT-ENTERPRISE (one component).
/// MIT krb/parse.c: first `@` is the UPN; only a later `@` is the realm.
///
/// # Errors
///
/// An error message when `spec` has an empty name, a trailing `\`, an unquoted `@` inside the
/// realm, or a component that is not ASCII GeneralString; unless `enterprise`, also when it
/// has no `@REALM`, an empty realm, or a `/` inside the realm.
pub fn parse_principal_ex(spec: &str, enterprise: bool) -> Result<(PrincipalName, String), String> {
    let p = krb5_types::parse_name_ex(spec, "", enterprise).map_err(|e| e.to_string())?;
    if p.components.first().is_some_and(String::is_empty) && p.components.len() == 1 {
        return Err("empty principal component".into());
    }
    if !enterprise && !p.has_realm {
        return Err(format!("principal must be name@REALM, got {spec}"));
    }
    if !enterprise && p.realm.is_empty() {
        return Err("empty principal component".into());
    }
    let ntype = if enterprise {
        PrincipalName::NT_ENTERPRISE
    } else {
        krb5_types::infer_name_type(&p.components)
    };
    PrincipalName::try_new(ntype, p.components)
        .map(|n| (n, p.realm))
        .map_err(|e| e.to_string())
}

/// Helper so tests can name a realm without importing `ascii` everywhere.
#[must_use]
pub fn realm(s: &str) -> Realm {
    krb5_types::ascii(s)
}

/// Build a TGT credential from an AS/TGS outcome.
///
/// # Errors
///
/// [`krb5_asn1::Error::Encode`] when `ticket` does not DER-encode.
pub fn tgt_cred(
    crealm: &Realm,
    cname: &PrincipalName,
    ticket: &Ticket,
    session: &ProtocolKey,
    enc: &krb5_types::EncKdcRepPart,
) -> Result<CcacheCred, krb5_asn1::Error> {
    let ticket_der = encode(ticket)?;
    let start = enc
        .starttime
        .as_ref()
        .unwrap_or(&enc.authtime)
        .unix_seconds();
    Ok(CcacheCred {
        client: (crealm.clone(), cname.clone()),
        server: (enc.srealm.clone(), enc.sname.clone()),
        key: CcacheKeyblock::from_protocol(session),
        authtime: enc.authtime.unix_seconds(),
        starttime: start,
        endtime: enc.endtime.unix_seconds(),
        renew_till: enc
            .renew_till
            .as_ref()
            .map_or(0, krb5_types::KerberosTime::unix_seconds),
        is_skey: 0,
        ticket_flags: enc.flags.to_u32(),
        addresses: enc.caddr.as_ref().map_or_else(Vec::new, |hs| {
            hs.iter()
                .map(|h| {
                    (
                        u16::try_from(h.addr_type).unwrap_or(0),
                        h.address.as_ref().to_vec(),
                    )
                })
                .collect()
        }),
        authdata: Vec::new(),
        ticket: ticket_der,
        second_ticket: Vec::new(),
    })
}

/// A FILE cache failure MIT reports under its own code, or as the lock call's errno, rather than
/// through `interpret_errno`; it travels inside the `io::Error` that [`read_cache_file`] and
/// [`fcc_store`] return ([`FccFailure::of`] finds it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FccFailure {
    /// `krb5_lock_file`'s errno, which MIT returns as it is.
    Lock(Errno),
    /// `KRB5_CC_FORMAT`: the header does not read.
    Format,
    /// `KRB5_CCACHE_BADVNO`: a format version outside 1–4, or one this port does not write.
    BadVersion,
    /// `KRB5_CC_IO`: a write shorter than the record.
    ShortWrite,
}

impl std::fmt::Display for FccFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lock(errno) => {
                let text = io::Error::from(*errno).to_string();
                let text = text
                    .rsplit_once(" (os error ")
                    .map_or(text.as_str(), |(t, _)| t);
                f.write_str(text)
            }
            Self::Format => f.write_str("Bad format in credentials cache"),
            Self::BadVersion => f.write_str("Unsupported credentials cache format version number"),
            Self::ShortWrite => f.write_str("Credentials cache I/O operation failed"),
        }
    }
}

impl std::error::Error for FccFailure {}

impl FccFailure {
    /// The failure `e` carries, when it is one of these rather than a system error.
    #[must_use]
    pub fn of(e: &io::Error) -> Option<Self> {
        e.get_ref()?.downcast_ref::<Self>().copied()
    }

    fn into_io(self) -> io::Error {
        io::Error::other(self)
    }
}

/// MIT's `FVNO_BASE`: a cache file's first two bytes are this plus its format version.
const FVNO_BASE: u16 = 0x0500;

/// An existing cache file, open and locked; [`CacheFile::close`] lets the lock go.
struct CacheFile {
    file: File,
    flocked: Option<Flock<File>>,
}

/// MIT `open_cache_file` (`cc_file.c:331-363`): an existing cache file, read-only under a shared lock or `O_RDWR | O_APPEND` under an exclusive one, the lock waiting for its holder; a lock failure closes the file and is the lock's errno.
fn open_cache_file(path: &Path, writable: bool) -> io::Result<CacheFile> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .append(writable)
        .open(path)?;
    let mut flocked = None;
    let how = if writable {
        FileLock::Exclusive
    } else {
        FileLock::Shared
    };
    lock_file(&file, how, &mut flocked).map_err(|e| FccFailure::Lock(e).into_io())?;
    Ok(CacheFile { file, flocked })
}

impl CacheFile {
    /// MIT `close_cache_file` (`cc_file.c:366-379`): the lock let go, then the file closed; the unlock's errno first, else the close's error.
    fn close(self) -> io::Result<()> {
        let Self { file, mut flocked } = self;
        let unlocked = lock_file(&file, FileLock::Unlock, &mut flocked);
        drop(flocked);
        let closed = nix::unistd::close(file);
        unlocked.map_err(|e| FccFailure::Lock(e).into_io())?;
        closed.map_err(io::Error::from)
    }
}

/// A big-endian 16-bit field of a version 4 header; a short read is `KRB5_CC_FORMAT`.
fn read16(file: &mut impl io::Read) -> io::Result<u16> {
    let mut b = [0u8; 2];
    file.read_exact(&mut b)
        .map_err(|_| FccFailure::Format.into_io())?;
    Ok(u16::from_be_bytes(b))
}

/// MIT `read_header` (`cc_file.c:383-440`): the format version; `KRB5_CC_FORMAT` when it does not read, `KRB5_CCACHE_BADVNO` outside 1–4, and for version 4 the tagged fields read through with each length checked.
fn read_header(file: &mut impl io::Read) -> io::Result<u16> {
    let format = || FccFailure::Format.into_io();
    let mut two = [0u8; 2];
    file.read_exact(&mut two).map_err(|_| format())?;
    let version = u16::from_be_bytes(two).wrapping_sub(FVNO_BASE);
    if !(1..=4).contains(&version) {
        return Err(FccFailure::BadVersion.into_io());
    }
    if version < 4 {
        return Ok(version);
    }
    let mut fields_len = read16(file)?;
    while fields_len > 0 {
        if fields_len < 4 {
            return Err(format());
        }
        let tag = read16(file)?;
        let flen = read16(file)?;
        if flen > fields_len - 4 || (tag == FCC_TAG_DELTATIME && flen != 8) {
            return Err(format());
        }
        let mut skip = vec![0u8; usize::from(flen)];
        file.read_exact(&mut skip).map_err(|_| format())?;
        fields_len -= 4 + flen;
    }
    Ok(version)
}

/// The bytes of the existing cache file at `path`, read under its shared lock, so that a store
/// another process is appending is never seen half written.
/// MIT `open_cache_file` (`cc_file.c:331-363`): a reader holds the file's shared lock.
///
/// # Errors
///
/// The open's or the read's system error (`NotFound` for a missing file), or an [`FccFailure`]
/// `Lock` when the lock is refused.
pub fn read_cache_file(path: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut cf = open_cache_file(path, false)?;
    // Sized from the file's length before the first byte, so that no reallocation leaves a copy
    // of a key behind; one byte more lets the read see the end without growing.
    let len = cf.file.metadata().map_or(0, |m| m.len());
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        usize::try_from(len).unwrap_or(0).saturating_add(1),
    ));
    let read = cf.file.read_to_end(&mut bytes).map(drop);
    let closed = cf.close();
    read.and(closed)?;
    Ok(bytes)
}

/// `cred` appended to the existing cache file at `path` in one write, under the file's
/// exclusive lock, after its header gives the format version; the record's bytes are wiped once
/// written. A version 1–3 file, which [`FileCcache::parse`] does not read, is refused as
/// `KRB5_CCACHE_BADVNO` rather than written in its own format.
/// MIT `fcc_store` (`cc_file.c:987-1026`): open for append and lock, read the header, one append write of the marshalled credential, a short write `KRB5_CC_IO`; the first error, else the close's.
///
/// # Errors
///
/// The open's, write's or close's system error (`NotFound` for a missing file: nothing is
/// created), or an [`FccFailure`]: `Lock`, `Format`, `BadVersion` or `ShortWrite`.
pub fn fcc_store(path: &Path, cred: &CcacheCred) -> io::Result<()> {
    let mut cf = open_cache_file(path, true)?;
    let stored = append_cred(&mut cf.file, cred);
    let closed = cf.close();
    stored.and(closed)
}

fn append_cred(file: &mut File, cred: &CcacheCred) -> io::Result<()> {
    if read_header(file)? != 4 {
        return Err(FccFailure::BadVersion.into_io());
    }
    let mut w = Writer {
        buf: Vec::with_capacity(cred_len(cred)),
    };
    marshal_cred(&mut w, cred);
    let record = Zeroizing::new(w.buf);
    if file.write(&record)? != record.len() {
        return Err(FccFailure::ShortWrite.into_io());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_types::PrincipalName;

    fn put_data(buf: &mut Vec<u8>, d: &[u8]) {
        buf.extend_from_slice(&(u32::try_from(d.len()).unwrap()).to_be_bytes());
        buf.extend_from_slice(d);
    }

    fn put_princ(buf: &mut Vec<u8>, realm: &[u8], parts: &[&[u8]]) {
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&(u32::try_from(parts.len()).unwrap()).to_be_bytes());
        put_data(buf, realm);
        for p in parts {
            put_data(buf, p);
        }
    }

    #[test]
    fn parse_to_bytes_keeps_header_skey_addrs_authdata_second_and_config() {
        let mut b = vec![0x05, 0x04];
        // DELTATIME tag 1, len 8, sec=7, usec=9
        b.extend_from_slice(&12u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&8u16.to_be_bytes());
        b.extend_from_slice(&7i32.to_be_bytes());
        b.extend_from_slice(&9i32.to_be_bytes());
        put_princ(&mut b, b"KERBER.TEST", &[b"user"]);
        // Config etype 0.
        put_princ(&mut b, b"KERBER.TEST", &[b"user"]);
        put_princ(
            &mut b,
            b"X-CACHECONF:",
            &[b"krb5_ccache_conf_data", b"pa_type", b"krbtgt/KERBER.TEST"],
        );
        b.extend_from_slice(&0u16.to_be_bytes());
        put_data(&mut b, &[]);
        for _ in 0..4 {
            b.extend_from_slice(&0u32.to_be_bytes());
        }
        b.push(0);
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        put_data(&mut b, &[1]);
        put_data(&mut b, &[]);
        // Ticket with is_skey, one address, one authdata, second_ticket.
        put_princ(&mut b, b"KERBER.TEST", &[b"user"]);
        put_princ(&mut b, b"KERBER.TEST", &[b"host", b"svc"]);
        b.extend_from_slice(&18u16.to_be_bytes());
        put_data(&mut b, &[0u8; 32]);
        for _ in 0..4 {
            b.extend_from_slice(&1u32.to_be_bytes());
        }
        b.push(1); // is_skey
        b.extend_from_slice(&0x4000_0000u32.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes()); // naddr
        b.extend_from_slice(&2u16.to_be_bytes());
        put_data(&mut b, &[127, 0, 0, 1]);
        b.extend_from_slice(&1u32.to_be_bytes()); // nauth
        b.extend_from_slice(&1u16.to_be_bytes());
        put_data(&mut b, &[9, 9]);
        put_data(&mut b, b"ticket-der");
        put_data(&mut b, b"second");
        let cc = FileCcache::parse(&b).expect("parse");
        assert_eq!(
            cc.header_tags,
            vec![(1, {
                let mut v = Vec::new();
                v.extend_from_slice(&7i32.to_be_bytes());
                v.extend_from_slice(&9i32.to_be_bytes());
                v
            })]
        );
        assert_eq!(cc.creds.len(), 2);
        assert!(cc.creds[0].is_config());
        assert!(!cc.creds[0].is_removed());
        assert_eq!(cc.list().len(), 1);
        let t = &cc.creds[1];
        assert_eq!(t.is_skey, 1);
        assert_eq!(t.addresses, vec![(2, vec![127, 0, 0, 1])]);
        assert_eq!(t.authdata, vec![(1, vec![9, 9])]);
        assert_eq!(t.second_ticket, b"second");
        let out = cc.to_bytes().expect("rewrite");
        assert_eq!(out, b, "parse → to_bytes must be identity");
    }

    #[test]
    fn remove_cred_tombstones_ticket_and_config() {
        let mut b = vec![0x05, 0x04, 0x00, 0x00];
        put_princ(&mut b, b"KERBER.TEST", &[b"user"]);
        put_princ(&mut b, b"KERBER.TEST", &[b"user"]);
        put_princ(
            &mut b,
            b"X-CACHECONF:",
            &[b"krb5_ccache_conf_data", b"pa_type"],
        );
        b.extend_from_slice(&0u16.to_be_bytes());
        put_data(&mut b, &[]);
        for _ in 0..4 {
            b.extend_from_slice(&0u32.to_be_bytes());
        }
        b.push(0);
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        put_data(&mut b, &[1]);
        put_data(&mut b, &[]);
        put_princ(&mut b, b"KERBER.TEST", &[b"user"]);
        put_princ(&mut b, b"KERBER.TEST", &[b"krbtgt", b"KERBER.TEST"]);
        b.extend_from_slice(&18u16.to_be_bytes());
        put_data(&mut b, &[0u8; 32]);
        for _ in 0..4 {
            b.extend_from_slice(&1u32.to_be_bytes());
        }
        b.push(0);
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        put_data(&mut b, b"tkt");
        put_data(&mut b, &[]);
        let mut cc = FileCcache::parse(&b).expect("parse");
        assert_eq!(cc.list().len(), 1);
        let before = cc.to_bytes().expect("before");
        cc.remove_cred(&realm("KERBER.TEST"), &PrincipalName::krbtgt("KERBER.TEST"));
        assert!(cc.list().is_empty());
        assert!(cc.creds[1].is_removed());
        assert_eq!(cc.creds[1].endtime, 0);
        assert_eq!(cc.creds[1].authtime, u32::MAX);
        let after_tkt = cc.to_bytes().expect("tombstone tkt");
        assert_eq!(after_tkt.len(), before.len());
        let conf = PrincipalName::new(
            PrincipalName::NT_UNKNOWN,
            ["krb5_ccache_conf_data", "pa_type"],
        );
        cc.remove_cred(&krb5_types::ascii("X-CACHECONF:"), &conf);
        assert!(cc.creds[0].is_removed());
        assert_eq!(cc.creds[0].server.0.as_bytes(), b"X-RMED-CONF:");
        let after = cc.to_bytes().expect("tombstone conf");
        assert_eq!(after.len(), before.len());
        let again = FileCcache::parse(&after).expect("reparse");
        assert!(again.list().is_empty());
        assert!(again.creds.iter().all(CcacheCred::is_removed));
    }

    /// MIT `krb5_cc_get_config` (`lib/krb5/ccache/ccfns.c:263-292`): the entry `X-CACHECONF:` `krb5_ccache_conf_data/<key>[/<principal>]` of the cache's principal is retrieved with no other field matched, and its ticket field is the value.
    #[test]
    fn a_configuration_entry_is_the_caches_principals_by_key_and_principal() {
        let me = (
            realm("KERBER.TEST"),
            PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
        );
        let mut cc = FileCcache::new(me, Vec::new());
        assert_eq!(cc.get_config(None, "start_realm"), None);
        cc.set_config(None, "start_realm", b"OTHER.TEST");
        cc.set_config(Some("krbtgt/KERBER.TEST@KERBER.TEST"), "pa_type", b"2");
        assert_eq!(cc.get_config(None, "start_realm"), Some(&b"OTHER.TEST"[..]));
        assert_eq!(
            cc.get_config(Some("krbtgt/KERBER.TEST@KERBER.TEST"), "pa_type"),
            Some(&b"2"[..])
        );
        assert_eq!(cc.get_config(None, "pa_type"), None);
        assert_eq!(cc.get_config(Some("krbtgt/X@X"), "pa_type"), None);
        cc.primary.1 = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["other"]);
        assert_eq!(cc.get_config(None, "start_realm"), None);
    }

    #[test]
    fn mit_addr_u2u_golden_is_identity() {
        let bytes = include_bytes!("../../../tests/traces/ccache-mit-addr-u2u.bin");
        let cc = FileCcache::parse(bytes).expect("parse MIT golden");
        assert!(
            cc.creds.iter().any(|c| !c.addresses.is_empty()),
            "kinit -a addresses"
        );
        assert!(cc.creds.iter().any(|c| !c.authdata.is_empty()), "authdata");
        assert!(
            cc.creds.iter().any(|c| !c.second_ticket.is_empty()),
            "second_ticket"
        );
        let out = cc.to_bytes().expect("to_bytes");
        assert_eq!(out.as_slice(), &bytes[..]);
    }

    #[test]
    fn parse_rejects_non_ascii_realm() {
        let mut b = vec![0x05, 0x04, 0x00, 0x00];
        put_princ(&mut b, b"K\x80R", &[b"user"]);
        let Err(err) = FileCcache::parse(&b) else {
            panic!("non-ASCII realm parsed");
        };
        let msg = err.to_string();
        assert!(
            msg.contains("GeneralString") || msg.contains("UTF-8") || msg.contains("principal"),
            "{msg}"
        );
    }

    /// fcc_store's record is one allocation: `cred_len` is each credential's marshalled length
    /// exactly (MIT's cache with addresses, authdata and a second ticket), so its buffer never
    /// grows.
    #[test]
    fn a_stored_record_is_sized_before_its_key() {
        let cc = FileCcache::parse(GOLDEN).unwrap();
        for c in &cc.creds {
            let n = cred_len(c);
            let mut w = Writer {
                buf: Vec::with_capacity(n),
            };
            marshal_cred(&mut w, c);
            assert_eq!(w.buf.len(), n, "cred_len is the record's length");
            assert_eq!(w.buf.capacity(), n, "the record's buffer grew");
        }
    }

    const GOLDEN: &[u8] = include_bytes!("../../../tests/traces/ccache-mit-addr-u2u.bin");

    /// A scratch cache file holding `bytes`.
    fn cache_file(name: &str, bytes: &[u8]) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = krb5_testkit::scratch_dir(name);
        let path = dir.join("cc");
        std::fs::write(&path, bytes).unwrap();
        (dir, path)
    }

    #[test]
    fn a_store_appends_one_record_after_the_bytes_already_there() {
        let (dir, path) = cache_file("krb5-fcc-append", GOLDEN);
        let cc = FileCcache::parse(GOLDEN).unwrap();
        let cred = cc.creds.last().unwrap().clone();
        fcc_store(&path, &cred).unwrap();
        let after = std::fs::read(&path).unwrap();
        let mut w = Writer::default();
        marshal_cred(&mut w, &cred);
        assert_eq!(&after[..GOLDEN.len()], GOLDEN);
        assert_eq!(&after[GOLDEN.len()..], w.buf.as_slice());
        let again = FileCcache::parse(&after).unwrap();
        assert_eq!(again.creds.len(), cc.creds.len() + 1);
        assert_eq!(read_cache_file(&path).unwrap().as_slice(), after.as_slice());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_store_waits_for_the_files_lock() {
        let (dir, path) = cache_file("krb5-fcc-lock", GOLDEN);
        let cred = FileCcache::parse(GOLDEN).unwrap().creds[0].clone();
        let holder = File::options().read(true).write(true).open(&path).unwrap();
        let mut held = None;
        lock_file(&holder, FileLock::Exclusive, &mut held).unwrap();
        let store_path = path.clone();
        let store = std::thread::spawn(move || fcc_store(&store_path, &cred));
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(std::fs::read(&path).unwrap().as_slice(), GOLDEN);
        lock_file(&holder, FileLock::Unlock, &mut held).unwrap();
        store.join().unwrap().unwrap();
        assert!(std::fs::read(&path).unwrap().len() > GOLDEN.len());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_store_neither_makes_a_missing_file_nor_writes_another_format() {
        let cred = FileCcache::parse(GOLDEN).unwrap().creds[0].clone();
        let dir = krb5_testkit::scratch_dir("krb5-fcc-missing");
        let missing = dir.join("cc");
        let e = fcc_store(&missing, &cred).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert!(!missing.exists());
        assert_eq!(
            read_cache_file(&missing).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        let _ = std::fs::remove_dir_all(dir);
        for (bytes, want) in [
            (&[0x05, 0x03, 0, 0][..], FccFailure::BadVersion),
            (&[0x05, 0x09][..], FccFailure::BadVersion),
            (&[0x05][..], FccFailure::Format),
            (&[0x05, 0x04, 0x00, 0x03, 0, 1, 0][..], FccFailure::Format),
            (
                &[0x05, 0x04, 0x00, 0x08, 0, 1, 0, 4, 0, 0, 0, 0][..],
                FccFailure::Format,
            ),
        ] {
            let (dir, path) = cache_file("krb5-fcc-format", bytes);
            let e = fcc_store(&path, &cred).unwrap_err();
            assert_eq!(FccFailure::of(&e), Some(want), "{bytes:02x?}");
            assert_eq!(std::fs::read(&path).unwrap().as_slice(), bytes);
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}
