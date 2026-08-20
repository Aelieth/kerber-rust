//! MIT FILE credential cache version 4: write, read, list, X-CACHECONF.

use std::io;
use std::path::Path;

use krb5_asn1::encode;
use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_types::{kerberos_string_from_bytes, PrincipalName, Realm, Ticket};

use crate::secret_file::write_secret_file;

/// One FILE ccache credential.
pub struct CcacheCred {
    /// Client principal.
    pub client: (Realm, PrincipalName),
    /// Server principal.
    pub server: (Realm, PrincipalName),
    /// Session key.
    pub key: ProtocolKey,
    /// Unix authtime.
    pub authtime: u32,
    /// Unix starttime.
    pub starttime: u32,
    /// Unix endtime.
    pub endtime: u32,
    /// Unix renew_till (0 if none).
    pub renew_till: u32,
    /// Ticket flags as a 32-bit MIT integer (MSB is RFC bit 0).
    pub ticket_flags: u32,
    /// DER-encoded Ticket.
    pub ticket: Vec<u8>,
}

impl CcacheCred {
    /// Whether this is an `X-CACHECONF:` config entry.
    #[must_use]
    pub fn is_config(&self) -> bool {
        self.server
            .1
            .name_string
            .first()
            .is_some_and(|s| s.as_bytes() == b"X-CACHECONF:")
    }
}

/// MIT FILE ccache (version 4, big-endian, empty tagged header).
pub struct FileCcache {
    /// Default client principal.
    pub primary: (Realm, PrincipalName),
    /// Credentials in file order.
    pub creds: Vec<CcacheCred>,
}

impl FileCcache {
    /// Serialize to MIT FILE ccache version 4.
    ///
    /// # Errors
    ///
    /// Returns I/O errors (length overflow).
    pub fn to_bytes(&self) -> Result<Vec<u8>, io::Error> {
        let mut w = Writer::default();
        w.u16(0x0504);
        w.u16(0);
        write_principal(&mut w, &self.primary.0, &self.primary.1);
        for c in &self.creds {
            write_principal(&mut w, &c.client.0, &c.client.1);
            write_principal(&mut w, &c.server.0, &c.server.1);
            w.u16(u16::try_from(c.key.etype().to_iana()).unwrap_or(0));
            w.data(c.key.as_bytes());
            w.u32(c.authtime);
            w.u32(c.starttime);
            w.u32(c.endtime);
            w.u32(c.renew_till);
            w.u8(0);
            w.u32(c.ticket_flags);
            w.u32(0);
            w.u32(0);
            w.data(&c.ticket);
            w.data(&[]);
        }
        Ok(w.buf)
    }

    /// Atomic exclusive write with mode 0600.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from create/write/rename.
    pub fn write_file(&self, path: impl AsRef<Path>) -> Result<(), io::Error> {
        let bytes = self.to_bytes()?;
        write_secret_file(path.as_ref(), &bytes)
    }

    /// Parse a FILE ccache v4.
    ///
    /// # Errors
    ///
    /// Truncation or invalid version / principal / etype.
    pub fn parse(bytes: &[u8]) -> Result<Self, io::Error> {
        if bytes.len() < 4 || bytes[0] != 0x05 || bytes[1] != 0x04 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not FILE ccache v4",
            ));
        }
        let mut i = 2;
        let hdr_len = take_u16(bytes, &mut i)?;
        i = i.saturating_add(usize::from(hdr_len));
        let primary = read_principal(bytes, &mut i)?;
        let mut creds = Vec::new();
        while i < bytes.len() {
            let client = read_principal(bytes, &mut i)?;
            let server = read_principal(bytes, &mut i)?;
            let etype_n = i32::from(take_u16(bytes, &mut i)?);
            let keybytes = take_data(bytes, &mut i)?;
            let authtime = take_u32(bytes, &mut i)?;
            let starttime = take_u32(bytes, &mut i)?;
            let endtime = take_u32(bytes, &mut i)?;
            let renew_till = take_u32(bytes, &mut i)?;
            let _is_skey = take_u8(bytes, &mut i)?;
            let ticket_flags = take_u32(bytes, &mut i)?;
            let naddr = take_u32(bytes, &mut i)?;
            for _ in 0..naddr {
                let _ = take_u16(bytes, &mut i)?;
                let _ = take_data(bytes, &mut i)?;
            }
            let nauth = take_u32(bytes, &mut i)?;
            for _ in 0..nauth {
                let _ = take_u16(bytes, &mut i)?;
                let _ = take_data(bytes, &mut i)?;
            }
            let ticket = take_data(bytes, &mut i)?;
            let _second = take_data(bytes, &mut i)?;
            let etype = EncryptionType::known(etype_n)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let key = ProtocolKey::from_bytes(etype, &keybytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            creds.push(CcacheCred {
                client,
                server,
                key,
                authtime,
                starttime,
                endtime,
                renew_till,
                ticket_flags,
                ticket,
            });
        }
        Ok(Self { primary, creds })
    }

    /// Non-config credentials (list).
    #[must_use]
    pub fn list(&self) -> Vec<&CcacheCred> {
        self.creds.iter().filter(|c| !c.is_config()).collect()
    }

    /// Insert an `X-CACHECONF:krb5_ccache_conf_data/{key}` entry.
    pub fn set_config(&mut self, key: &str, value: &[u8]) {
        let name = PrincipalName::new(
            PrincipalName::NT_UNKNOWN,
            ["X-CACHECONF:", "krb5_ccache_conf_data", key],
        );
        self.creds.retain(|c| {
            !(c.is_config()
                && c.server
                    .1
                    .name_string
                    .get(2)
                    .is_some_and(|s| s.as_bytes() == key.as_bytes()))
        });
        if let Ok(dummy) = ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &[0u8; 16])
        {
            self.creds.push(CcacheCred {
                client: self.primary.clone(),
                server: (self.primary.0.clone(), name),
                key: dummy,
                authtime: 0,
                starttime: 0,
                endtime: 0,
                renew_till: 0,
                ticket_flags: 0,
                ticket: value.to_vec(),
            });
        }
    }
}

/// Parse `user@REALM` into (PrincipalName, realm string).
///
/// # Errors
///
/// Returns a message when the spec has no `@` or a component is not IA5.
pub fn parse_principal(spec: &str) -> Result<(PrincipalName, String), String> {
    let (user, realm) = spec
        .rsplit_once('@')
        .ok_or_else(|| format!("principal must be name@REALM, got {spec}"))?;
    if user.is_empty() || realm.is_empty() {
        return Err("empty principal component".into());
    }
    if !user.is_ascii() || !realm.is_ascii() {
        return Err("non-ASCII principal".into());
    }
    let parts: Vec<&str> = user.split('/').collect();
    let ntype = if parts.len() > 1 {
        PrincipalName::NT_SRV_INST
    } else {
        PrincipalName::NT_PRINCIPAL
    };
    PrincipalName::try_new(ntype, parts)
        .map(|n| (n, realm.to_owned()))
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
/// Returns DER encode failures.
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
        key: session.clone(),
        authtime: enc.authtime.unix_seconds(),
        starttime: start,
        endtime: enc.endtime.unix_seconds(),
        renew_till: enc
            .renew_till
            .as_ref()
            .map_or(0, krb5_types::KerberosTime::unix_seconds),
        ticket_flags: enc.flags.to_u32(),
        ticket: ticket_der,
    })
}

fn write_principal(w: &mut Writer, realm: &Realm, name: &PrincipalName) {
    w.i32(name.name_type);
    w.u32(u32::try_from(name.name_string.len()).unwrap_or(0));
    w.data(realm.as_bytes());
    for c in &name.name_string {
        w.data(c.as_bytes());
    }
}

fn read_principal(b: &[u8], i: &mut usize) -> Result<(Realm, PrincipalName), io::Error> {
    let ntype = take_i32(b, i)?;
    let ncomp = take_u32(b, i)? as usize;
    let realm_b = take_data(b, i)?;
    let mut parts = Vec::new();
    for _ in 0..ncomp {
        parts.push(take_data(b, i)?);
    }
    let realm = kerberos_string_from_bytes(&realm_b)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let name = PrincipalName::try_from_bytes(ntype, parts)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok((realm, name))
}

#[derive(Default)]
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn data(&mut self, b: &[u8]) {
        self.u32(u32::try_from(b.len()).unwrap_or(0));
        self.buf.extend_from_slice(b);
    }
}

fn take_u8(b: &[u8], i: &mut usize) -> Result<u8, io::Error> {
    if *i >= b.len() {
        return Err(eof());
    }
    let v = b[*i];
    *i += 1;
    Ok(v)
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
    Ok(take_u32(b, i)? as i32)
}

fn take_data(b: &[u8], i: &mut usize) -> Result<Vec<u8>, io::Error> {
    let n = take_u32(b, i)? as usize;
    if *i + n > b.len() {
        return Err(eof());
    }
    let v = b[*i..*i + n].to_vec();
    *i += n;
    Ok(v)
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "ccache truncated")
}
