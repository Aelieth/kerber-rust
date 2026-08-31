//! MIT FILE v4 credential marshal (`ccmarshal.c`). Shared by FILE, and later KCM.

use std::io;

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_types::{PrincipalName, Realm, kerberos_string_from_bytes};

/// FILE v4 header tag: KDC time offset (`sec`, `usec`).
pub const FCC_TAG_DELTATIME: u16 = 1;

/// MIT FILE/KCM/KEYRING v4 keyblock. Enctype 0 is a config entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CcacheKeyblock {
    /// Enctype as stored (16-bit, sign-extended on read).
    pub etype: i16,
    /// Key octets.
    pub contents: Vec<u8>,
}

impl CcacheKeyblock {
    /// Copy a protocol session key.
    #[must_use]
    pub fn from_protocol(key: &ProtocolKey) -> Self {
        Self {
            etype: i16::try_from(key.etype().to_iana()).unwrap_or(0),
            contents: key.as_bytes().to_vec(),
        }
    }

    /// Parse as a [`ProtocolKey`] when the enctype is implemented.
    ///
    /// # Errors
    ///
    /// Unknown enctype or wrong key length.
    pub fn protocol_key(&self) -> Result<ProtocolKey, io::Error> {
        let et = EncryptionType::known(i32::from(self.etype))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        ProtocolKey::from_bytes(et, &self.contents)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}

/// One FILE v4 credential, including config and tombstones.
#[derive(Clone)]
pub struct CcacheCred {
    /// Client principal.
    pub client: (Realm, PrincipalName),
    /// Server principal.
    pub server: (Realm, PrincipalName),
    /// Session key (etype 0 + empty for MIT config).
    pub key: CcacheKeyblock,
    /// Unix authtime (`u32::MAX` is MIT tombstone `-1`).
    pub authtime: u32,
    /// Unix starttime.
    pub starttime: u32,
    /// Unix endtime (0 with nonzero authtime is a tombstone).
    pub endtime: u32,
    /// Unix renew_till (0 if none).
    pub renew_till: u32,
    /// `is_skey` (0 or 1).
    pub is_skey: u8,
    /// Ticket flags as a 32-bit MIT integer (MSB is RFC bit 0).
    pub ticket_flags: u32,
    /// Addresses: (addrtype, value).
    pub addresses: Vec<(u16, Vec<u8>)>,
    /// Authdata: (ad_type, value). `ad_type` is signed.
    pub authdata: Vec<(i16, Vec<u8>)>,
    /// DER-encoded Ticket.
    pub ticket: Vec<u8>,
    /// Second ticket (user-to-user).
    pub second_ticket: Vec<u8>,
}

impl CcacheCred {
    /// Whether this is an `X-CACHECONF:` config entry (server realm).
    #[must_use]
    pub fn is_config(&self) -> bool {
        self.server.0.as_bytes() == b"X-CACHECONF:"
    }

    /// MIT `cred_removed`: `endtime == 0 && authtime != 0`.
    #[must_use]
    pub fn is_removed(&self) -> bool {
        self.endtime == 0 && self.authtime != 0
    }

    /// Session key when the enctype is implemented.
    ///
    /// # Errors
    ///
    /// Unknown enctype or wrong key length.
    pub fn session_key(&self) -> Result<ProtocolKey, io::Error> {
        self.key.protocol_key()
    }
}

#[derive(Default)]
pub(crate) struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub fn i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    pub fn data(&mut self, b: &[u8]) {
        self.u32(u32::try_from(b.len()).unwrap_or(0));
        self.buf.extend_from_slice(b);
    }
}

pub(crate) fn marshal_princ(w: &mut Writer, realm: &Realm, name: &PrincipalName) {
    w.i32(name.name_type);
    w.u32(u32::try_from(name.name_string.len()).unwrap_or(0));
    w.data(realm.as_bytes());
    for c in &name.name_string {
        w.data(c.as_bytes());
    }
}

pub(crate) fn unmarshal_princ(
    b: &[u8],
    i: &mut usize,
) -> Result<(Realm, PrincipalName), io::Error> {
    let ntype = take_i32(b, i)?;
    let ncomp = take_u32(b, i)? as usize;
    if ncomp > b.len().saturating_sub(*i) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ccache principal component count",
        ));
    }
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

pub(crate) fn marshal_cred(w: &mut Writer, c: &CcacheCred) {
    marshal_princ(w, &c.client.0, &c.client.1);
    marshal_princ(w, &c.server.0, &c.server.1);
    w.u16(c.key.etype.cast_unsigned());
    w.data(&c.key.contents);
    w.u32(c.authtime);
    w.u32(c.starttime);
    w.u32(c.endtime);
    w.u32(c.renew_till);
    w.u8(c.is_skey);
    w.u32(c.ticket_flags);
    w.u32(u32::try_from(c.addresses.len()).unwrap_or(0));
    for (ty, val) in &c.addresses {
        w.u16(*ty);
        w.data(val);
    }
    w.u32(u32::try_from(c.authdata.len()).unwrap_or(0));
    for (ty, val) in &c.authdata {
        w.u16(ty.cast_unsigned());
        w.data(val);
    }
    w.data(&c.ticket);
    w.data(&c.second_ticket);
}

pub(crate) fn unmarshal_cred(b: &[u8], i: &mut usize) -> Result<CcacheCred, io::Error> {
    let client = unmarshal_princ(b, i)?;
    let server = unmarshal_princ(b, i)?;
    let etype = take_u16(b, i)?.cast_signed();
    let contents = take_data(b, i)?;
    let authtime = take_u32(b, i)?;
    let starttime = take_u32(b, i)?;
    let endtime = take_u32(b, i)?;
    let renew_till = take_u32(b, i)?;
    let is_skey = take_u8(b, i)?;
    let ticket_flags = take_u32(b, i)?;
    let naddr = take_u32(b, i)? as usize;
    if naddr > b.len().saturating_sub(*i) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ccache address count",
        ));
    }
    let mut addresses = Vec::with_capacity(naddr.min(32));
    for _ in 0..naddr {
        let ty = take_u16(b, i)?;
        let val = take_data(b, i)?;
        addresses.push((ty, val));
    }
    let nauth = take_u32(b, i)? as usize;
    if nauth > b.len().saturating_sub(*i) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ccache authdata count",
        ));
    }
    let mut authdata = Vec::with_capacity(nauth.min(32));
    for _ in 0..nauth {
        let ty = take_u16(b, i)?.cast_signed();
        let val = take_data(b, i)?;
        authdata.push((ty, val));
    }
    let ticket = take_data(b, i)?;
    let second_ticket = take_data(b, i)?;
    Ok(CcacheCred {
        client,
        server,
        key: CcacheKeyblock { etype, contents },
        authtime,
        starttime,
        endtime,
        renew_till,
        is_skey,
        ticket_flags,
        addresses,
        authdata,
        ticket,
        second_ticket,
    })
}

pub(crate) fn take_u8(b: &[u8], i: &mut usize) -> Result<u8, io::Error> {
    if *i >= b.len() {
        return Err(eof());
    }
    let v = b[*i];
    *i += 1;
    Ok(v)
}

pub(crate) fn take_u16(b: &[u8], i: &mut usize) -> Result<u16, io::Error> {
    if *i + 2 > b.len() {
        return Err(eof());
    }
    let v = u16::from_be_bytes(b[*i..*i + 2].try_into().map_err(|_| eof())?);
    *i += 2;
    Ok(v)
}

pub(crate) fn take_u32(b: &[u8], i: &mut usize) -> Result<u32, io::Error> {
    if *i + 4 > b.len() {
        return Err(eof());
    }
    let v = u32::from_be_bytes(b[*i..*i + 4].try_into().map_err(|_| eof())?);
    *i += 4;
    Ok(v)
}

pub(crate) fn take_i32(b: &[u8], i: &mut usize) -> Result<i32, io::Error> {
    Ok(i32::from_be_bytes(take_u32(b, i)?.to_be_bytes()))
}

pub(crate) fn take_data(b: &[u8], i: &mut usize) -> Result<Vec<u8>, io::Error> {
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
