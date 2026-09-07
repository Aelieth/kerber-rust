//! MIT `KRB5_TL_KADM_DATA`: the XDR `osa_princ_ent_rec` kadm5 keeps in every
//! principal (`lib/kadm5/srv/adb_xdr.c`) — the bound policy, `aux_attributes`,
//! and the password history: `old_keys` holds one entry per old password, its
//! key data encrypted under the `kadmin/history` key of `admin_history_kvno`
//! (`svr_principal.c create_history_entry`, `add_to_history`, `check_pw_reuse`).

use krb5_crypto::{EncryptionType, ProtocolKey, kdb_decrypt_key, kdb_encrypt_key};

use crate::kdb_dump::TL_KADM_DATA;
use crate::store::{KeyEntry, TlData};

/// `OSA_ADB_PRINC_VERSION_1`.
pub const OSA_ADB_PRINC_VERSION_1: u32 = 0x1234_5c01;
/// `KADM5_POLICY` in `aux_attributes`: a policy is bound.
pub const KADM5_POLICY: u32 = 0x0000_0800;
/// `INITIAL_HIST_KVNO` (`server_internal.h`): the history kvno a new record starts at.
pub const INITIAL_HIST_KVNO: u32 = 2;

/// One `krb5_key_data` as stored in an `osa_pw_hist_ent`: slot 0 is the key
/// (`kdb_encrypt_key` form) under the history key, slot 1 the salt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OsaKeyData {
    /// `key_data_ver`: 1 (key only) or 2 (key + salt).
    pub ver: u16,
    /// `key_data_kvno`.
    pub kvno: u16,
    /// `key_data_type[0..2]`: enctype, salt type.
    pub types: [i16; 2],
    /// `key_data_contents[0..2]`.
    pub contents: [Vec<u8>; 2],
}

/// `osa_princ_ent_rec`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OsaPrincEnt {
    /// Bound policy name (meaningful with [`KADM5_POLICY`] in `aux_attributes`).
    pub policy: Option<String>,
    /// `aux_attributes`.
    pub aux_attributes: u32,
    /// `old_key_next`: the ring slot the next history entry overwrites.
    pub old_key_next: u32,
    /// `admin_history_kvno`: kvno of the history key that encrypted `old_keys`.
    pub admin_history_kvno: u32,
    /// `old_keys`: one entry per remembered old password.
    pub old_keys: Vec<Vec<OsaKeyData>>,
}

impl Default for OsaPrincEnt {
    fn default() -> Self {
        Self {
            policy: None,
            aux_attributes: 0,
            old_key_next: 0,
            admin_history_kvno: INITIAL_HIST_KVNO,
            old_keys: Vec::new(),
        }
    }
}

/// Malformed `KRB5_TL_KADM_DATA`.
#[derive(Debug, thiserror::Error)]
pub enum OsaError {
    /// Not `OSA_ADB_PRINC_VERSION_1`.
    #[error("osa_princ_ent version {0:#x}")]
    Version(u32),
    /// Truncated or mis-sized XDR.
    #[error("osa_princ_ent xdr: {0}")]
    Xdr(&'static str),
}

struct Xdr<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Xdr<'a> {
    fn u32(&mut self) -> Result<u32, OsaError> {
        let end = self.i.checked_add(4).ok_or(OsaError::Xdr("length"))?;
        let s = self.b.get(self.i..end).ok_or(OsaError::Xdr("short int"))?;
        self.i = end;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn bytes(&mut self) -> Result<&'a [u8], OsaError> {
        let n = self.u32()? as usize;
        let end = self.i.checked_add(n).ok_or(OsaError::Xdr("length"))?;
        let s = self
            .b
            .get(self.i..end)
            .ok_or(OsaError::Xdr("short opaque"))?;
        self.i = end + ((4 - n % 4) % 4);
        if self.i > self.b.len() {
            return Err(OsaError::Xdr("short padding"));
        }
        Ok(s)
    }

    /// `xdr_nullstring`: size 0 is NULL; else `size` counts the NUL.
    fn nullstring(&mut self) -> Result<Option<String>, OsaError> {
        let s = self.bytes()?;
        match s.split_last() {
            None => Ok(None),
            Some((0, body)) if !body.contains(&0) => Ok(Some(
                std::str::from_utf8(body)
                    .map_err(|_| OsaError::Xdr("policy utf-8"))?
                    .to_owned(),
            )),
            Some(_) => Err(OsaError::Xdr("policy not a C string")),
        }
    }
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, u32::try_from(b.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(b);
    out.resize(out.len() + (4 - b.len() % 4) % 4, 0);
}

fn put_i16(out: &mut Vec<u8>, v: i16) {
    put_u32(out, i32::from(v).cast_unsigned());
}

impl OsaKeyData {
    fn decode(x: &mut Xdr<'_>) -> Result<Self, OsaError> {
        let ver = u16::try_from(x.u32()?).map_err(|_| OsaError::Xdr("key_data_ver"))?;
        let kvno = u16::try_from(x.u32()?).map_err(|_| OsaError::Xdr("key_data_kvno"))?;
        let t0 = i16::try_from(x.u32()?.cast_signed()).map_err(|_| OsaError::Xdr("type"))?;
        let t1 = i16::try_from(x.u32()?.cast_signed()).map_err(|_| OsaError::Xdr("type"))?;
        let l0 = x.u32()? as usize;
        let l1 = x.u32()? as usize;
        let c0 = x.bytes()?.to_vec();
        let c1 = x.bytes()?.to_vec();
        if c0.len() != l0 || c1.len() != l1 {
            return Err(OsaError::Xdr("key_data_length"));
        }
        Ok(Self {
            ver,
            kvno,
            types: [t0, t1],
            contents: [c0, c1],
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        put_u32(out, u32::from(self.ver));
        put_u32(out, u32::from(self.kvno));
        put_i16(out, self.types[0]);
        put_i16(out, self.types[1]);
        put_u32(out, u32::try_from(self.contents[0].len()).unwrap_or(0));
        put_u32(out, u32::try_from(self.contents[1].len()).unwrap_or(0));
        put_bytes(out, &self.contents[0]);
        put_bytes(out, &self.contents[1]);
    }
}

impl OsaPrincEnt {
    /// Decode a `KRB5_TL_KADM_DATA` value.
    ///
    /// # Errors
    ///
    /// [`OsaError`] on a wrong version or malformed XDR.
    pub fn decode(b: &[u8]) -> Result<Self, OsaError> {
        let mut x = Xdr { b, i: 0 };
        let version = x.u32()?;
        if version != OSA_ADB_PRINC_VERSION_1 {
            return Err(OsaError::Version(version));
        }
        let policy = x.nullstring()?;
        let aux_attributes = x.u32()?;
        let old_key_next = x.u32()?;
        let admin_history_kvno = x.u32()?;
        let n = x.u32()? as usize;
        let mut old_keys = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            let nk = x.u32()? as usize;
            let mut entry = Vec::with_capacity(nk.min(16));
            for _ in 0..nk {
                entry.push(OsaKeyData::decode(&mut x)?);
            }
            old_keys.push(entry);
        }
        Ok(Self {
            policy,
            aux_attributes,
            old_key_next,
            admin_history_kvno,
            old_keys,
        })
    }

    /// Encode as `xdr_osa_princ_ent_rec` does.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        put_u32(&mut out, OSA_ADB_PRINC_VERSION_1);
        match &self.policy {
            Some(p) => {
                let mut s = p.as_bytes().to_vec();
                s.push(0);
                put_bytes(&mut out, &s);
            }
            None => put_u32(&mut out, 0),
        }
        put_u32(&mut out, self.aux_attributes);
        put_u32(&mut out, self.old_key_next);
        put_u32(&mut out, self.admin_history_kvno);
        put_u32(&mut out, u32::try_from(self.old_keys.len()).unwrap_or(0));
        for entry in &self.old_keys {
            put_u32(&mut out, u32::try_from(entry.len()).unwrap_or(0));
            for k in entry {
                k.encode(&mut out);
            }
        }
        out
    }

    /// The record inside `tl`, if present.
    ///
    /// # Errors
    ///
    /// [`OsaError`] when the `KRB5_TL_KADM_DATA` value is malformed.
    pub fn from_tl(tl: &[TlData]) -> Result<Option<Self>, OsaError> {
        tl.iter()
            .find(|t| t.ty == TL_KADM_DATA)
            .map(|t| Self::decode(&t.contents))
            .transpose()
    }

    /// The bound policy name (`kadm5_get_principal`: only with [`KADM5_POLICY`]).
    #[must_use]
    pub fn bound_policy(&self) -> Option<&str> {
        if self.aux_attributes & KADM5_POLICY != 0 {
            self.policy.as_deref().filter(|s| !s.is_empty())
        } else {
            None
        }
    }

    /// `old_keys` oldest first: the ring's next slot is the oldest entry.
    #[must_use]
    pub fn old_keys_oldest_first(&self) -> Vec<&Vec<OsaKeyData>> {
        let n = self.old_keys.len();
        if n == 0 {
            return Vec::new();
        }
        let start = (self.old_key_next as usize) % n;
        (0..n).map(|i| &self.old_keys[(start + i) % n]).collect()
    }
}

/// `create_history_entry`: the keys of one password (their own kvno and salt)
/// re-encrypted under the history key.
///
/// # Errors
///
/// Encryption failures from the history key's etype.
pub fn history_entry(
    keys: &[KeyEntry],
    hist_key: &ProtocolKey,
) -> Result<Vec<OsaKeyData>, krb5_crypto::Error> {
    let mut entry = Vec::with_capacity(keys.len());
    for k in keys {
        let enc = kdb_encrypt_key(hist_key, k.key.as_bytes())?;
        let (ver, salt_ty, salt) = match (k.salt_type, &k.kdb_salt) {
            (Some(t), Some(s)) if t > 0 => (2, t, s.clone()),
            _ => (1, 0, Vec::new()),
        };
        entry.push(OsaKeyData {
            ver,
            kvno: u16::try_from(k.kvno).unwrap_or(u16::MAX),
            types: [
                i16::try_from(k.etype.to_iana()).unwrap_or(0),
                i16::try_from(salt_ty).unwrap_or(0),
            ],
            contents: [enc, salt],
        });
    }
    Ok(entry)
}

/// `check_pw_reuse`'s reading side: an entry's keys decrypted with the
/// history key; a key that does not decrypt is skipped like MIT's `continue`.
#[must_use]
pub fn decrypt_entry(entry: &[OsaKeyData], hist_key: &ProtocolKey) -> Vec<KeyEntry> {
    entry
        .iter()
        .filter_map(|k| {
            let etype = EncryptionType::known(i32::from(k.types[0])).ok()?;
            let raw = kdb_decrypt_key(hist_key, &k.contents[0]).ok()?;
            let key = ProtocolKey::from_bytes(etype, &raw).ok()?;
            let mut e = KeyEntry::new(etype, key, u32::from(k.kvno));
            if k.ver >= 2 {
                e.salt_type = Some(i32::from(k.types[1]));
                e.kdb_salt = Some(k.contents[1].clone());
            }
            Some(e)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zeroed_record_is_the_24_byte_alias_stub_record() {
        let rec = OsaPrincEnt {
            admin_history_kvno: 0,
            ..OsaPrincEnt::default()
        };
        let mut want = OSA_ADB_PRINC_VERSION_1.to_be_bytes().to_vec();
        want.resize(24, 0);
        assert_eq!(rec.encode(), want);
        assert_eq!(OsaPrincEnt::decode(&want).unwrap(), rec);
    }

    #[test]
    fn policy_and_history_round_trip_through_xdr() {
        let rec = OsaPrincEnt {
            policy: Some("hp".into()),
            aux_attributes: KADM5_POLICY,
            old_key_next: 1,
            admin_history_kvno: 2,
            old_keys: vec![
                vec![OsaKeyData {
                    ver: 2,
                    kvno: 1,
                    types: [20, 0],
                    contents: [vec![1, 2, 3], vec![b'K', b'E', b'R', b'B', b'u']],
                }],
                vec![OsaKeyData {
                    ver: 1,
                    kvno: 2,
                    types: [18, 0],
                    contents: [vec![9; 7], Vec::new()],
                }],
            ],
        };
        let bytes = rec.encode();
        assert_eq!(bytes.len() % 4, 0, "XDR is 4-byte aligned");
        assert_eq!(OsaPrincEnt::decode(&bytes).unwrap(), rec);
        // "hp\0" is 3 bytes padded to 4 after the u32 size.
        assert_eq!(&bytes[4..12], &[0, 0, 0, 3, b'h', b'p', 0, 0]);
        assert_eq!(rec.bound_policy(), Some("hp"));
        let order: Vec<u16> = rec
            .old_keys_oldest_first()
            .iter()
            .map(|e| e[0].kvno)
            .collect();
        assert_eq!(order, [2, 1], "next slot 1 holds the oldest entry");
    }

    #[test]
    fn truncated_records_are_errors_not_panics() {
        let rec = OsaPrincEnt {
            policy: Some("p".into()),
            ..OsaPrincEnt::default()
        };
        let bytes = rec.encode();
        for n in 0..bytes.len() {
            assert!(OsaPrincEnt::decode(&bytes[..n]).is_err(), "prefix {n}");
        }
        assert!(matches!(
            OsaPrincEnt::decode(&[0, 0, 0, 1, 0, 0, 0, 0]),
            Err(OsaError::Version(1))
        ));
    }
}
