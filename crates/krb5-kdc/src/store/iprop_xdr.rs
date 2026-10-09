//! An iprop update in XDR (`lib/kdb/iprop_xdr.c`): `kdb_incr_update_t` as the update log stores
//! it and as `IPROP_GET_UPDATES` sends it. Keys go wrapped under the master key: a record is
//! encoded with a wrap, and read back with the master key that opens it, or walked without one.

use krb5_crypto::{EncryptionType, ProtocolKey, kdb_decrypt_key};
use krb5_types::PrincipalName;

use super::kdb_convert::{
    AT_ATTRFLAGS, AT_EXP, AT_FAIL_AUTH_COUNT, AT_KEYDATA, AT_LAST_FAILED, AT_LAST_SUCCESS, AT_LEN,
    AT_MAX_LIFE, AT_MAX_RENEW_LIFE, AT_MOD_PRINC, AT_MOD_TIME, AT_MOD_WHERE, AT_PRINC, AT_PW_EXP,
    AT_PW_HIST, AT_PW_HIST_KVNO, AT_PW_LAST_CHANGE, AT_PW_POLICY, AT_PW_POLICY_SWITCH, AT_TL_DATA,
    IpropUpdate, KdbeVal,
};
use super::keys::KeyEntry;
use super::principal::TlData;
use crate::osa::OsaKeyData;

/// How a key is wrapped as it is encoded: under the master key, or refused, so that no key is
/// ever encoded in the clear.
pub type KeyWrap<'a, E> = dyn Fn(&[u8]) -> Result<Vec<u8>, E> + 'a;

/// Why an update does not read.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum XdrError {
    /// The bytes end inside a value.
    #[error("XDR value cut short")]
    Short,
    /// A value that reads is not one an update may hold.
    #[error("{0}")]
    Invalid(String),
}

/// MIT `kdbe_time_t` (`include/iprop.h`): seconds and microseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UlogTime {
    /// `seconds`.
    pub seconds: u32,
    /// `useconds`.
    pub useconds: u32,
}

impl UlogTime {
    /// The time now, to the microsecond.
    /// MIT `time_current` (`lib/kdb/kdb_log.c:60-68`): `gettimeofday`, seconds and microseconds.
    #[must_use]
    pub fn now() -> Self {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            seconds: u32::try_from(d.as_secs()).unwrap_or(u32::MAX),
            useconds: d.subsec_micros(),
        }
    }
}

/// A big-endian XDR writer.
#[derive(Default)]
pub(crate) struct XdrOut(pub(crate) Vec<u8>);

impl XdrOut {
    pub(crate) fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    /// `xdr_bytes`: the length, the bytes, zero padding to four.
    pub(crate) fn opaque(&mut self, b: &[u8]) {
        self.u32(u32::try_from(b.len()).unwrap_or(u32::MAX));
        self.0.extend_from_slice(b);
        let pad = (4 - b.len() % 4) % 4;
        self.0.extend(std::iter::repeat_n(0, pad));
    }

    fn count(&mut self, n: usize) {
        self.u32(u32::try_from(n).unwrap_or(u32::MAX));
    }
}

/// A big-endian XDR reader over one record.
pub(crate) struct XdrIn<'a> {
    b: &'a [u8],
    pub(crate) at: usize,
}

impl<'a> XdrIn<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self { b, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], XdrError> {
        let end = self.at.checked_add(n).ok_or(XdrError::Short)?;
        let s = self.b.get(self.at..end).ok_or(XdrError::Short)?;
        self.at = end;
        Ok(s)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, XdrError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// `xdr_bool`: a nonzero word is true.
    pub(crate) fn bool(&mut self) -> Result<bool, XdrError> {
        Ok(self.u32()? != 0)
    }

    /// `xdr_bytes`, its padding skipped.
    pub(crate) fn opaque(&mut self) -> Result<&'a [u8], XdrError> {
        let n = usize::try_from(self.u32()?).map_err(|_| XdrError::Short)?;
        let s = self.take(n)?;
        self.take((4 - n % 4) % 4)?;
        Ok(s)
    }

    /// An array's count, refused when the bytes left cannot hold that many items of at least
    /// `min` bytes each, so a hostile count allocates nothing.
    fn count(&mut self, min: usize) -> Result<usize, XdrError> {
        let n = usize::try_from(self.u32()?).map_err(|_| XdrError::Short)?;
        let left = self.b.len().saturating_sub(self.at);
        if n.saturating_mul(min.max(1)) > left {
            return Err(XdrError::Short);
        }
        Ok(n)
    }
}

/// MIT `xdr_kdbe_key_t` (`lib/kdb/iprop_xdr.c:75-90`): each key's version, kvno, then as many types and contents as its version.
/// MIT `ulog_conv_2logentry` (`lib/kdb/kdb_convert.c:415-462`): each key goes as stored, its version deciding how many types and contents follow.
/// A key is stored at version 2 when it has a salt type and salt, as the dump writes it.
fn encode_keydata<E>(w: &mut XdrOut, keys: &[KeyEntry], wrap: &KeyWrap<'_, E>) -> Result<(), E> {
    w.count(keys.len());
    for k in keys {
        let enc = wrap(k.key.as_bytes())?;
        let etype = u32::try_from(k.etype.to_iana()).unwrap_or(0);
        if let (Some(salt_type), Some(salt)) = (k.salt_type, k.kdb_salt.as_ref()) {
            w.u32(2);
            w.u32(k.kvno);
            w.u32(2);
            w.u32(etype);
            w.u32(salt_type.cast_unsigned());
            w.u32(2);
            w.opaque(&enc);
            w.opaque(salt);
        } else {
            w.u32(1);
            w.u32(k.kvno);
            w.u32(1);
            w.u32(etype);
            w.u32(1);
            w.opaque(&enc);
        }
    }
    Ok(())
}

/// `kdbe_key_t` of stored key data (history entries stay under the history key, as MIT ships
/// them).
fn encode_keydata_raw(w: &mut XdrOut, keys: &[OsaKeyData]) {
    w.count(keys.len());
    for k in keys {
        let slots = usize::from(k.ver.clamp(1, 2));
        w.u32(u32::from(k.ver));
        w.u32(u32::from(k.kvno));
        w.count(slots);
        for t in &k.types[..slots] {
            w.u32(i32::from(*t).cast_unsigned());
        }
        w.count(slots);
        for c in &k.contents[..slots] {
            w.opaque(c);
        }
    }
}

/// MIT `xdr_kdbe_princ_t` (`lib/kdb/iprop_xdr.c:105-117`): the realm, each component with MIT's `KV5M_DATA` magic, the name type.
fn encode_princ(w: &mut XdrOut, name: &PrincipalName, realm: &str) {
    w.opaque(realm.as_bytes());
    w.count(name.name_string.len());
    for c in &name.name_string {
        // MIT `KV5M_DATA` (`krb5_data.magic`).
        w.u32((-1_760_647_422i32).cast_unsigned());
        w.opaque(c.as_bytes());
    }
    w.u32(name.name_type.cast_unsigned());
}

/// MIT `xdr_kdbe_t` (`lib/kdb/iprop_xdr.c:252-260`): the update's values, counted, each in its type's shape; keys wrapped by `wrap`.
/// MIT `xdr_kdbe_val_t` (`lib/kdb/iprop_xdr.c:153-249`): each attribute's type, then its value in that type's shape.
///
/// # Errors
///
/// A key `wrap` refuses.
pub fn encode_kdbe<E>(vals: &[KdbeVal], wrap: &KeyWrap<'_, E>) -> Result<Vec<u8>, E> {
    let mut w = XdrOut::default();
    w.count(vals.len());
    for v in vals {
        w.u32(v.attr());
        match v {
            KdbeVal::AttrFlags(n)
            | KdbeVal::MaxLife(n)
            | KdbeVal::MaxRenewLife(n)
            | KdbeVal::Exp(n)
            | KdbeVal::PwExp(n)
            | KdbeVal::LastSuccess(n)
            | KdbeVal::LastFailed(n)
            | KdbeVal::FailAuthCount(n)
            | KdbeVal::Len(n)
            | KdbeVal::ModTime(n)
            | KdbeVal::PwLastChange(n)
            | KdbeVal::PwHistKvno(n) => w.u32(*n),
            KdbeVal::Princ(name, realm) | KdbeVal::ModPrinc(name, realm) => {
                encode_princ(&mut w, name, realm);
            }
            KdbeVal::KeyData(keys) => encode_keydata(&mut w, keys, wrap)?,
            KdbeVal::TlData(tl) => {
                w.count(tl.len());
                for t in tl {
                    w.u32(t.ty.cast_unsigned());
                    w.opaque(&t.contents);
                }
            }
            KdbeVal::ModWhere(b) | KdbeVal::PwPolicy(b) | KdbeVal::Extension(_, b) => w.opaque(b),
            KdbeVal::PwPolicySwitch(on) => w.u32(u32::from(*on)),
            KdbeVal::PwHist(hist) => {
                w.count(hist.len());
                for entry in hist {
                    encode_keydata_raw(&mut w, entry);
                }
            }
        }
    }
    Ok(w.0)
}

/// One update as the log stores it and the wire carries it: the principal's name, its serial,
/// its time, the encoded values `kdbe` ([`encode_kdbe`]), whether it deletes, whether it is
/// committed, and no KDCs seen and no futures.
/// MIT `xdr_kdb_incr_update_t` (`lib/kdb/iprop_xdr.c:263-285`): the name, serial, time, the update, the deleted and committed flags, the KDCs seen and the futures.
#[must_use]
pub fn encode_incr_update(
    name: &str,
    sno: u32,
    time: UlogTime,
    kdbe: &[u8],
    deleted: bool,
    commit: bool,
) -> Vec<u8> {
    let mut w = XdrOut::default();
    w.opaque(name.as_bytes());
    w.u32(sno);
    w.u32(time.seconds);
    w.u32(time.useconds);
    w.0.extend_from_slice(kdbe);
    w.u32(u32::from(deleted));
    w.u32(u32::from(commit));
    w.u32(0);
    w.u32(0);
    w.0
}

/// What [`walk_incr_update`] finds in a stored update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncrLayout {
    /// `kdb_princ_name`.
    pub name: String,
    /// `kdb_entry_sno`.
    pub sno: u32,
    /// `kdb_time`.
    pub time: UlogTime,
    /// `kdb_deleted`.
    pub deleted: bool,
    /// `kdb_commit` as encoded.
    pub commit: bool,
    /// The byte offset of `kdb_commit`'s word, which a reader sets from the entry's header.
    pub commit_at: usize,
    /// The attributes the update carries (bit `n` is `kdbe_attr_type_t` `n`; past 31 none).
    pub attrs: u32,
    /// How many values the update carries.
    pub nvals: usize,
    /// The encoded length.
    pub len: usize,
}

/// Skip one `kdbe_key_t`.
fn skip_key(r: &mut XdrIn<'_>) -> Result<(), XdrError> {
    r.u32()?;
    r.u32()?;
    let n = r.count(4)?;
    for _ in 0..n {
        r.u32()?;
    }
    let n = r.count(4)?;
    for _ in 0..n {
        r.opaque()?;
    }
    Ok(())
}

/// Skip one `kdbe_princ_t`.
fn skip_princ(r: &mut XdrIn<'_>) -> Result<(), XdrError> {
    r.opaque()?;
    let n = r.count(8)?;
    for _ in 0..n {
        r.u32()?;
        r.opaque()?;
    }
    r.u32()?;
    Ok(())
}

/// Walk an encoded `kdb_incr_update_t` without opening its keys: its name, serial, time, flags,
/// where its commit flag lies and which attributes it carries. An update that does not read to
/// its end, or with bytes past it, is refused, as `xdr_kdb_incr_update_t` failing to decode is
/// `KRB5_LOG_CONV`.
/// MIT `xdr_kdbe_val_t` (`lib/kdb/iprop_xdr.c:153-249`): a type MIT does not name is one opaque value.
/// MIT `ulog_get_entries` (`lib/kdb/kdb_log.c:625-631`): an update that does not decode is a conversion error.
///
/// # Errors
///
/// [`XdrError::Short`] when the bytes end inside it; [`XdrError::Invalid`] when its name is not
/// UTF-8 or bytes follow it.
pub fn walk_incr_update(b: &[u8]) -> Result<IncrLayout, XdrError> {
    let mut r = XdrIn::new(b);
    let name = std::str::from_utf8(r.opaque()?)
        .map_err(|_| XdrError::Invalid("update name is not UTF-8".into()))?
        .to_owned();
    let sno = r.u32()?;
    let time = UlogTime {
        seconds: r.u32()?,
        useconds: r.u32()?,
    };
    let nvals = r.count(8)?;
    let mut attrs = 0u32;
    for _ in 0..nvals {
        let at = r.u32()?;
        attrs |= 1u32.checked_shl(at).unwrap_or(0);
        match at {
            AT_ATTRFLAGS | AT_MAX_LIFE | AT_MAX_RENEW_LIFE | AT_EXP | AT_PW_EXP
            | AT_LAST_SUCCESS | AT_LAST_FAILED | AT_FAIL_AUTH_COUNT | AT_LEN | AT_MOD_TIME
            | AT_PW_LAST_CHANGE | AT_PW_POLICY_SWITCH | AT_PW_HIST_KVNO => {
                r.u32()?;
            }
            AT_PRINC | AT_MOD_PRINC => skip_princ(&mut r)?,
            AT_KEYDATA => {
                let n = r.count(16)?;
                for _ in 0..n {
                    skip_key(&mut r)?;
                }
            }
            AT_TL_DATA => {
                let n = r.count(8)?;
                for _ in 0..n {
                    r.u32()?;
                    r.opaque()?;
                }
            }
            AT_PW_HIST => {
                let n = r.count(4)?;
                for _ in 0..n {
                    let k = r.count(16)?;
                    for _ in 0..k {
                        skip_key(&mut r)?;
                    }
                }
            }
            _ => {
                r.opaque()?;
            }
        }
    }
    let deleted = r.bool()?;
    let commit_at = r.at;
    let commit = r.bool()?;
    let seen = r.count(4)?;
    for _ in 0..seen {
        r.opaque()?;
    }
    r.opaque()?;
    if r.at != b.len() {
        return Err(XdrError::Invalid("bytes past the update".into()));
    }
    Ok(IncrLayout {
        name,
        sno,
        time,
        deleted,
        commit,
        commit_at,
        attrs,
        nvals,
        len: r.at,
    })
}

fn decode_keydata_raw(r: &mut XdrIn<'_>) -> Result<Vec<OsaKeyData>, XdrError> {
    let n = r.count(16)?;
    let mut keys = Vec::with_capacity(n);
    for _ in 0..n {
        let ver = u16::try_from(r.u32()?).unwrap_or(u16::MAX);
        let kvno = u16::try_from(r.u32()?).unwrap_or(u16::MAX);
        let n_enc = r.count(4)?;
        let mut all_types = Vec::with_capacity(n_enc);
        for _ in 0..n_enc {
            all_types.push(i16::try_from(r.u32()?.cast_signed()).unwrap_or(0));
        }
        let n_cont = r.count(4)?;
        let mut all_contents = Vec::with_capacity(n_cont);
        for _ in 0..n_cont {
            all_contents.push(r.opaque()?.to_vec());
        }
        let mut types = [0i16; 2];
        for (slot, t) in types.iter_mut().zip(&all_types) {
            *slot = *t;
        }
        let mut contents: [Vec<u8>; 2] = [Vec::new(), Vec::new()];
        for (slot, c) in contents.iter_mut().zip(all_contents) {
            *slot = c;
        }
        keys.push(OsaKeyData {
            ver,
            kvno,
            types,
            contents,
        });
    }
    Ok(keys)
}

fn decode_princ(r: &mut XdrIn<'_>) -> Result<(PrincipalName, String), XdrError> {
    let realm = String::from_utf8_lossy(r.opaque()?).into_owned();
    let n = r.count(8)?;
    let mut comps = Vec::with_capacity(n);
    for _ in 0..n {
        let _magic = r.u32()?;
        comps.push(String::from_utf8_lossy(r.opaque()?).into_owned());
    }
    let ntype = r.u32()?.cast_signed();
    let refs: Vec<&str> = comps.iter().map(String::as_str).collect();
    let name = PrincipalName::try_new(ntype, refs).map_err(|e| XdrError::Invalid(e.to_string()))?;
    Ok((name, realm))
}

/// MIT `krb5_dbe_def_decrypt_key_data` (`lib/kdb/decrypt_key.c:91-93`): a master-key decrypt failure is not a usable key.
/// MIT `ulog_conv_2dbentry` (`lib/kdb/kdb_convert.c:678-683`): a key of a version past 2 is not a key, and the update does not apply.
/// An etype this build does not know, or a plaintext of the wrong length, is omitted and the other
/// keys in the entry are kept.
fn decode_keydata(
    r: &mut XdrIn<'_>,
    mkey: Option<&ProtocolKey>,
) -> Result<Vec<KeyEntry>, XdrError> {
    let n = r.count(16)?;
    let mut keys = Vec::with_capacity(n);
    for _ in 0..n {
        let ver = r.u32()?;
        let kvno = r.u32()?;
        let n_enc = r.count(4)?;
        let mut enctypes = Vec::with_capacity(n_enc);
        for _ in 0..n_enc {
            enctypes.push(r.u32()?.cast_signed());
        }
        let n_cont = r.count(4)?;
        let mut contents = Vec::with_capacity(n_cont);
        for _ in 0..n_cont {
            contents.push(r.opaque()?.to_vec());
        }
        if ver > 2 {
            return Err(XdrError::Invalid(format!("iprop key data version {ver}")));
        }
        let Some(et) = enctypes.first().copied() else {
            continue;
        };
        let Ok(etype) = EncryptionType::from_iana(et).or_else(|_| EncryptionType::known(et)) else {
            continue;
        };
        let Some(raw_enc) = contents.first() else {
            continue;
        };
        let raw = if let Some(m) = mkey {
            kdb_decrypt_key(m, raw_enc).map_err(|e| XdrError::Invalid(e.to_string()))?
        } else {
            raw_enc.clone()
        };
        let Ok(key) = ProtocolKey::from_bytes(etype, &raw) else {
            continue;
        };
        let (salt_type, kdb_salt) = if ver >= 2 {
            (enctypes.get(1).copied(), contents.get(1).cloned())
        } else {
            (None, None)
        };
        keys.push(KeyEntry {
            etype,
            key,
            kvno,
            salt_type,
            kdb_salt,
        });
    }
    Ok(keys)
}

/// MIT `xdr_kdbe_val_t` (`lib/kdb/iprop_xdr.c:153-249`): each attribute's value is read in its type's shape, and a type MIT does not name is one opaque value.
/// The update keeps which attributes it carried; none stands in for one it did not. Keys open
/// under `mkey`, or stay as they came without one.
///
/// # Errors
///
/// [`XdrError::Short`] when the bytes end inside a value; [`XdrError::Invalid`] when a name does
/// not parse, a key's version is past 2 or a key does not open under `mkey`.
pub(crate) fn decode_kdbe(
    r: &mut XdrIn<'_>,
    mkey: Option<&ProtocolKey>,
) -> Result<Vec<KdbeVal>, XdrError> {
    let n = r.count(8)?;
    let mut vals = Vec::with_capacity(n);
    for _ in 0..n {
        let tag = r.u32()?;
        vals.push(match tag {
            AT_ATTRFLAGS => KdbeVal::AttrFlags(r.u32()?),
            AT_MAX_LIFE => KdbeVal::MaxLife(r.u32()?),
            AT_MAX_RENEW_LIFE => KdbeVal::MaxRenewLife(r.u32()?),
            AT_EXP => KdbeVal::Exp(r.u32()?),
            AT_PW_EXP => KdbeVal::PwExp(r.u32()?),
            AT_LAST_SUCCESS => KdbeVal::LastSuccess(r.u32()?),
            AT_LAST_FAILED => KdbeVal::LastFailed(r.u32()?),
            AT_FAIL_AUTH_COUNT => KdbeVal::FailAuthCount(r.u32()?),
            AT_PRINC => {
                let (name, realm) = decode_princ(r)?;
                KdbeVal::Princ(name, realm)
            }
            AT_KEYDATA => KdbeVal::KeyData(decode_keydata(r, mkey)?),
            AT_TL_DATA => {
                let nt = r.count(8)?;
                let mut tl = Vec::with_capacity(nt);
                for _ in 0..nt {
                    let ty = r.u32()?.cast_signed();
                    let contents = r.opaque()?.to_vec();
                    tl.push(TlData { ty, contents });
                }
                KdbeVal::TlData(tl)
            }
            AT_LEN => KdbeVal::Len(r.u32()?),
            AT_MOD_PRINC => {
                let (name, realm) = decode_princ(r)?;
                KdbeVal::ModPrinc(name, realm)
            }
            AT_MOD_TIME => KdbeVal::ModTime(r.u32()?),
            AT_MOD_WHERE => KdbeVal::ModWhere(r.opaque()?.to_vec()),
            AT_PW_LAST_CHANGE => KdbeVal::PwLastChange(r.u32()?),
            AT_PW_POLICY => KdbeVal::PwPolicy(r.opaque()?.to_vec()),
            AT_PW_POLICY_SWITCH => KdbeVal::PwPolicySwitch(r.bool()?),
            AT_PW_HIST_KVNO => KdbeVal::PwHistKvno(r.u32()?),
            AT_PW_HIST => {
                let nh = r.count(4)?;
                let mut hist = Vec::with_capacity(nh);
                for _ in 0..nh {
                    hist.push(decode_keydata_raw(r)?);
                }
                KdbeVal::PwHist(hist)
            }
            other => KdbeVal::Extension(other, r.opaque()?.to_vec()),
        });
    }
    Ok(vals)
}

/// One `kdb_incr_update_t` read at the start of `b`, its keys opened under `mkey`: the update, and
/// how many bytes it took.
///
/// # Errors
///
/// [`XdrError::Short`] when the bytes end inside the update; [`XdrError::Invalid`] when a name
/// does not parse, a key's version is past 2 or a key does not open under `mkey`.
pub fn decode_incr_update(
    b: &[u8],
    mkey: Option<&ProtocolKey>,
) -> Result<(IpropUpdate, usize), XdrError> {
    let mut r = XdrIn::new(b);
    let name = String::from_utf8_lossy(r.opaque()?).into_owned();
    let sno = r.u32()?;
    let time = r.u32()?;
    let _usec = r.u32()?;
    let vals = decode_kdbe(&mut r, mkey)?;
    let deleted = r.bool()?;
    let commit = r.bool()?;
    let seen = r.count(4)?;
    for _ in 0..seen {
        r.opaque()?;
    }
    r.opaque()?;
    let len = r.at;
    Ok((
        IpropUpdate {
            sno,
            time,
            name,
            deleted,
            commit,
            vals,
            raw: b.get(..len).map(<[u8]>::to_vec).unwrap_or_default(),
        },
        len,
    ))
}

/// The values of an encoded `kdbe_t` (as [`encode_kdbe`] writes it), keys opened under `mkey`.
///
/// # Errors
///
/// [`XdrError::Short`] when the bytes end inside a value; [`XdrError::Invalid`] when a name does
/// not parse, a key's version is past 2, a key does not open under `mkey`, or bytes follow the
/// values.
pub fn decode_kdbe_bytes(b: &[u8], mkey: Option<&ProtocolKey>) -> Result<Vec<KdbeVal>, XdrError> {
    let mut r = XdrIn::new(b);
    let vals = decode_kdbe(&mut r, mkey)?;
    if r.at != b.len() {
        return Err(XdrError::Invalid("bytes past the values".into()));
    }
    Ok(vals)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes of MIT 1.22.2's delete entry for `u1@P18U.TEST` (settled live, `kproplog -v`:
    /// "Update size : 48"): name, serial, time, no values, deleted, not committed in the record,
    /// no KDCs seen, no futures.
    #[test]
    fn a_delete_is_mits_48_bytes() {
        let t = UlogTime {
            seconds: 0x6ac3_aadb,
            useconds: 0x0009_4258,
        };
        let kdbe = encode_kdbe::<()>(&[], &|_| Ok(Vec::new())).unwrap();
        let b = encode_incr_update("u1@P18U.TEST", 9, t, &kdbe, true, false);
        assert_eq!(b.len(), 48);
        let l = walk_incr_update(&b).unwrap();
        assert_eq!(
            (l.name.as_str(), l.sno, l.time, l.deleted, l.commit, l.attrs),
            ("u1@P18U.TEST", 9, t, true, false, 0)
        );
        assert_eq!(&b[l.commit_at..l.commit_at + 4], &[0, 0, 0, 0]);
    }

    /// The head of MIT 1.22.2's entry 2 (`addprinc admin/admin`, settled live with `od`): the
    /// name's length and bytes padded to four, the serial, the time, the count of values (MIT's
    /// twelve, two here), then `AT_ATTRFLAGS` 0 as MIT's first value.
    #[test]
    fn an_add_starts_as_mits_does() {
        let t = UlogTime {
            seconds: 0x6ac3_aadb,
            useconds: 0x0009_4258,
        };
        let vals = [KdbeVal::AttrFlags(0), KdbeVal::MaxLife(86_400)];
        let kdbe = encode_kdbe::<()>(&vals, &|_| Ok(Vec::new())).unwrap();
        let b = encode_incr_update("admin/admin@P18U.TEST", 2, t, &kdbe, false, false);
        let mit_head: [u8; 52] = [
            0x00, 0x00, 0x00, 0x15, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2f, 0x61, 0x64, 0x6d, 0x69,
            0x6e, 0x40, 0x50, 0x31, 0x38, 0x55, 0x2e, 0x54, 0x45, 0x53, 0x54, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x6a, 0xc3, 0xaa, 0xdb, 0x00, 0x09, 0x42, 0x58, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(&b[..52], &mit_head[..]);
        let l = walk_incr_update(&b).unwrap();
        assert_eq!(l.attrs, (1 << AT_ATTRFLAGS) | (1 << AT_MAX_LIFE));
        assert_eq!(l.nvals, 2);
    }

    #[test]
    fn a_cut_or_padded_update_does_not_walk() {
        let kdbe = encode_kdbe::<()>(&[KdbeVal::Len(3)], &|_| Ok(Vec::new())).unwrap();
        let b = encode_incr_update("x@R", 1, UlogTime::default(), &kdbe, false, false);
        assert_eq!(walk_incr_update(&b[..b.len() - 1]), Err(XdrError::Short));
        let mut long = b.clone();
        long.extend_from_slice(&[0; 4]);
        assert!(matches!(walk_incr_update(&long), Err(XdrError::Invalid(_))));
        let mut hostile = XdrOut::default();
        hostile.opaque(b"x@R");
        hostile.u32(1);
        hostile.u32(0);
        hostile.u32(0);
        hostile.u32(u32::MAX);
        assert_eq!(walk_incr_update(&hostile.0), Err(XdrError::Short));
    }

    #[test]
    fn the_decode_caps_hostile_counts() {
        let mut princ = XdrOut::default();
        princ.u32(1);
        princ.u32(AT_PRINC);
        princ.opaque(b"KERBER.TEST");
        princ.u32(u32::MAX);
        assert_eq!(
            decode_kdbe_bytes(&princ.0, None).err(),
            Some(XdrError::Short)
        );
        let mut keys = XdrOut::default();
        keys.u32(1);
        keys.u32(AT_KEYDATA);
        keys.u32(1);
        keys.u32(2);
        keys.u32(1);
        keys.u32(u32::MAX);
        assert_eq!(
            decode_kdbe_bytes(&keys.0, None).err(),
            Some(XdrError::Short)
        );
    }
}
