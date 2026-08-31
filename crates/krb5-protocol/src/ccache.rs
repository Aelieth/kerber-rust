//! MIT FILE credential cache version 4: write, read, list, X-CACHECONF.

use std::io;
use std::path::Path;

use krb5_asn1::encode;
use krb5_crypto::ProtocolKey;
use krb5_types::{PrincipalName, Realm, Ticket};

use crate::ccmarshal::{
    FCC_TAG_DELTATIME, Writer, marshal_cred, marshal_princ, take_u16, unmarshal_cred,
    unmarshal_princ,
};
use crate::secret_file::write_secret_file;

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
    /// Returns I/O errors (length overflow).
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
    /// Principals and realms must be ASCII GeneralString (RFC 4120). A MIT
    /// cache with non-ASCII name octets fails parse; identity is lossless
    /// only inside that alphabet.
    ///
    /// # Errors
    ///
    /// Truncation or invalid version / principal.
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

    /// Insert an `X-CACHECONF:krb5_ccache_conf_data/{key}` entry (etype 0).
    pub fn set_config(&mut self, key: &str, value: &[u8]) {
        self.creds.retain(|c| {
            !(c.is_config()
                && c.server
                    .1
                    .name_string
                    .get(1)
                    .is_some_and(|s| s.as_bytes() == key.as_bytes()))
        });
        let Ok(conf_realm) = krb5_types::kerberos_string_from_bytes(b"X-CACHECONF:") else {
            return;
        };
        let name = PrincipalName::new(PrincipalName::NT_UNKNOWN, ["krb5_ccache_conf_data", key]);
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
/// Returns a message when the spec has no `@` or a component is not IA5.
pub fn parse_principal(spec: &str) -> Result<(PrincipalName, String), String> {
    parse_principal_ex(spec, false)
}

/// Parse `name@REALM`. `enterprise` uses NT-ENTERPRISE (one component).
///
/// # Errors
///
/// Returns a message when the spec has no `@` or a component is not IA5.
pub fn parse_principal_ex(spec: &str, enterprise: bool) -> Result<(PrincipalName, String), String> {
    let (user, realm) = spec
        .rsplit_once('@')
        .ok_or_else(|| format!("principal must be name@REALM, got {spec}"))?;
    if user.is_empty() || realm.is_empty() {
        return Err("empty principal component".into());
    }
    if !user.is_ascii() || !realm.is_ascii() {
        return Err("non-ASCII principal".into());
    }
    if enterprise {
        return PrincipalName::try_new(PrincipalName::NT_ENTERPRISE, [user])
            .map(|n| (n, realm.to_owned()))
            .map_err(|e| e.to_string());
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
        addresses: Vec::new(),
        authdata: Vec::new(),
        ticket: ticket_der,
        second_ticket: Vec::new(),
    })
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
}
