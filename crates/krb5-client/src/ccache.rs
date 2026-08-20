//! MIT FILE credential cache version 4 (RFC-adjacent format documented by MIT 1.22.2).

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use krb5_asn1::encode;
use krb5_crypto::ProtocolKey;
use krb5_types::{ascii, PrincipalName, Realm, Ticket};

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

/// MIT FILE ccache (version 4, big-endian, empty tagged header).
pub struct FileCcache {
    /// Default client principal.
    pub primary: (Realm, PrincipalName),
    /// Credentials in file order.
    pub creds: Vec<CcacheCred>,
}

impl FileCcache {
    /// Serialize to MIT FILE ccaches version 4.
    pub fn to_bytes(&self) -> Result<Vec<u8>, io::Error> {
        let mut w = Writer::default();
        w.u16(0x0504);
        w.u16(0); // no tagged header fields
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
            w.u8(0); // is_skey
            w.u32(c.ticket_flags);
            w.u32(0); // addresses
            w.u32(0); // authdata
            w.data(&c.ticket);
            w.data(&[]); // second_ticket
        }
        Ok(w.buf)
    }

    /// Write the cache to `path` with mode 0600.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from create/write.
    pub fn write_file(&self, path: impl AsRef<Path>) -> Result<(), io::Error> {
        let bytes = self.to_bytes()?;
        let mut f = File::create(path.as_ref())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(&bytes)?;
        Ok(())
    }
}

/// Build a TGT credential from an AS outcome.
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

/// Parse `user@REALM` into (PrincipalName, realm string).
///
/// # Errors
///
/// Returns a message when the spec has no `@`.
pub fn parse_principal(spec: &str) -> Result<(PrincipalName, String), String> {
    let (user, realm) = spec
        .rsplit_once('@')
        .ok_or_else(|| format!("principal must be name@REALM, got {spec}"))?;
    if user.is_empty() || realm.is_empty() {
        return Err("empty principal component".into());
    }
    // Slash-separated instances: host/foo -> NT-SRV-HST-ish NT-SRV-INST.
    let parts: Vec<&str> = user.split('/').collect();
    let ntype = if parts.len() > 1 {
        PrincipalName::NT_SRV_INST
    } else {
        PrincipalName::NT_PRINCIPAL
    };
    Ok((PrincipalName::new(ntype, parts), realm.to_owned()))
}

/// Helper so tests can name a realm without importing `ascii` everywhere.
#[must_use]
pub fn realm(s: &str) -> Realm {
    ascii(s)
}
