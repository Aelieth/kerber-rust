//! A principal record as an iprop update and back (`lib/kdb/kdb_convert.c`): a primary records
//! which attributes of a record a change touched and sends only those, and a replica applies to
//! its own record only the attributes an update carries.

use krb5_types::PrincipalName;

use super::flags::{KDB_DISALLOW_ALL_TIX, KDB_REQUIRES_PRE_AUTH};
use super::keys::KeyEntry;
use super::principal::{KadmData, Principal, TlData};
use crate::error::Error;
use crate::kdb_dump::{
    TL_DB_ARGS, TL_KADM_DATA, TL_LAST_PWD_CHANGE, TL_MKVNO, TL_MOD_PRINC, TL_STRING_ATTRS,
    attrs_from_tl, dump_attributes, merge_kadm_tl, mkvno_from_tl, salt_of_keys, tl_mod_princ,
};
use crate::osa::{OsaKeyData, OsaPrincEnt};

/// `AT_ATTRFLAGS` (`include/iprop.h` `kdbe_attr_type_t`).
pub const AT_ATTRFLAGS: u32 = 0;
/// `AT_MAX_LIFE`.
pub const AT_MAX_LIFE: u32 = 1;
/// `AT_MAX_RENEW_LIFE`.
pub const AT_MAX_RENEW_LIFE: u32 = 2;
/// `AT_EXP`.
pub const AT_EXP: u32 = 3;
/// `AT_PW_EXP`.
pub const AT_PW_EXP: u32 = 4;
/// `AT_LAST_SUCCESS`, not replicated.
pub const AT_LAST_SUCCESS: u32 = 5;
/// `AT_LAST_FAILED`, not replicated.
pub const AT_LAST_FAILED: u32 = 6;
/// `AT_FAIL_AUTH_COUNT`, not replicated.
pub const AT_FAIL_AUTH_COUNT: u32 = 7;
/// `AT_PRINC`.
pub const AT_PRINC: u32 = 8;
/// `AT_KEYDATA`.
pub const AT_KEYDATA: u32 = 9;
/// `AT_TL_DATA`.
pub const AT_TL_DATA: u32 = 10;
/// `AT_LEN`.
pub const AT_LEN: u32 = 11;
/// `AT_MOD_PRINC`.
pub const AT_MOD_PRINC: u32 = 12;
/// `AT_MOD_TIME`.
pub const AT_MOD_TIME: u32 = 13;
/// `AT_MOD_WHERE`.
pub const AT_MOD_WHERE: u32 = 14;
/// `AT_PW_LAST_CHANGE`.
pub const AT_PW_LAST_CHANGE: u32 = 15;
/// `AT_PW_POLICY`.
pub const AT_PW_POLICY: u32 = 16;
/// `AT_PW_POLICY_SWITCH`.
pub const AT_PW_POLICY_SWITCH: u32 = 17;
/// `AT_PW_HIST_KVNO`.
pub const AT_PW_HIST_KVNO: u32 = 18;
/// `AT_PW_HIST`.
pub const AT_PW_HIST: u32 = 19;

/// MIT `ulog_conv_2logentry` (`lib/kdb/kdb_convert.c:338-355`): a new principal lists every attribute up to `AT_LEN`, one bit each here.
pub const ULOG_ADD_ATTRS: u32 = (1 << (AT_LEN + 1)) - 1;

/// The bit of attribute `at` in an attribute list.
#[must_use]
pub const fn attr_bit(at: u32) -> u32 {
    1 << at
}

/// One attribute of an iprop update with its value (MIT `kdbe_val_t`); keys are plaintext here,
/// wrapped under the master key on the wire.
#[derive(Clone, Debug)]
pub enum KdbeVal {
    /// `AT_ATTRFLAGS`.
    AttrFlags(u32),
    /// `AT_MAX_LIFE`.
    MaxLife(u32),
    /// `AT_MAX_RENEW_LIFE`.
    MaxRenewLife(u32),
    /// `AT_EXP`.
    Exp(u32),
    /// `AT_PW_EXP`.
    PwExp(u32),
    /// `AT_LAST_SUCCESS`.
    LastSuccess(u32),
    /// `AT_LAST_FAILED`.
    LastFailed(u32),
    /// `AT_FAIL_AUTH_COUNT`.
    FailAuthCount(u32),
    /// `AT_PRINC`: the name and its realm.
    Princ(PrincipalName, String),
    /// `AT_KEYDATA`: every key of the record.
    KeyData(Vec<KeyEntry>),
    /// `AT_TL_DATA`.
    TlData(Vec<TlData>),
    /// `AT_LEN`.
    Len(u32),
    /// `AT_MOD_PRINC`: the name and its realm.
    ModPrinc(PrincipalName, String),
    /// `AT_MOD_TIME`.
    ModTime(u32),
    /// `AT_MOD_WHERE`.
    ModWhere(Vec<u8>),
    /// `AT_PW_LAST_CHANGE`.
    PwLastChange(u32),
    /// `AT_PW_POLICY`.
    PwPolicy(Vec<u8>),
    /// `AT_PW_POLICY_SWITCH`.
    PwPolicySwitch(bool),
    /// `AT_PW_HIST_KVNO`.
    PwHistKvno(u32),
    /// `AT_PW_HIST`: the old passwords' keys as stored.
    PwHist(Vec<Vec<OsaKeyData>>),
    /// Any other type: MIT's `av_extension` bytes.
    Extension(u32, Vec<u8>),
}

impl KdbeVal {
    /// The `kdbe_attr_type_t` this value carries.
    #[must_use]
    pub fn attr(&self) -> u32 {
        match self {
            Self::AttrFlags(_) => AT_ATTRFLAGS,
            Self::MaxLife(_) => AT_MAX_LIFE,
            Self::MaxRenewLife(_) => AT_MAX_RENEW_LIFE,
            Self::Exp(_) => AT_EXP,
            Self::PwExp(_) => AT_PW_EXP,
            Self::LastSuccess(_) => AT_LAST_SUCCESS,
            Self::LastFailed(_) => AT_LAST_FAILED,
            Self::FailAuthCount(_) => AT_FAIL_AUTH_COUNT,
            Self::Princ(..) => AT_PRINC,
            Self::KeyData(_) => AT_KEYDATA,
            Self::TlData(_) => AT_TL_DATA,
            Self::Len(_) => AT_LEN,
            Self::ModPrinc(..) => AT_MOD_PRINC,
            Self::ModTime(_) => AT_MOD_TIME,
            Self::ModWhere(_) => AT_MOD_WHERE,
            Self::PwLastChange(_) => AT_PW_LAST_CHANGE,
            Self::PwPolicy(_) => AT_PW_POLICY,
            Self::PwPolicySwitch(_) => AT_PW_POLICY_SWITCH,
            Self::PwHistKvno(_) => AT_PW_HIST_KVNO,
            Self::PwHist(_) => AT_PW_HIST,
            Self::Extension(at, _) => *at,
        }
    }
}

/// One update as a replica receives it (MIT `kdb_incr_update_t`).
#[derive(Clone, Debug)]
pub struct IpropUpdate {
    /// `kdb_entry_sno`.
    pub sno: u32,
    /// `kdb_time.seconds`.
    pub time: u32,
    /// `kdb_princ_name`, unparsed.
    pub name: String,
    /// `kdb_deleted`.
    pub deleted: bool,
    /// `kdb_update`: the attributes it carries, in its order.
    pub vals: Vec<KdbeVal>,
}

/// The record's `tl_data` as MIT's database holds it, which an update compares and carries: the
/// database arguments and kerber-rust's own `0x4B00`–`0x4BFF` types stay out, the kadm5 record is
/// there whenever a policy or a history is, and the string attributes are the current ones,
/// kept, once present, where they are and even when empty, as MIT's `krb5_dbe_set_string` does.
#[must_use]
pub(crate) fn mit_tl(p: &Principal) -> Vec<TlData> {
    let mut tl: Vec<TlData> = p
        .tl_data
        .iter()
        .filter(|t| t.ty != TL_DB_ARGS && !(0x4B00..=0x4BFF).contains(&t.ty))
        .cloned()
        .collect();
    merge_kadm_tl(&mut tl, p);
    let strings = encode_string_attrs(&p.string_attrs);
    if let Some(t) = tl.iter_mut().find(|t| t.ty == TL_STRING_ATTRS) {
        t.contents = strings;
    } else if !p.string_attrs.is_empty() {
        tl.push(TlData {
            ty: TL_STRING_ATTRS,
            contents: strings,
        });
    }
    tl
}

/// MIT `krb5_dbe_set_string` (`lib/kdb/kdb5.c:2197-2245`): each key and value NUL-terminated, in order.
#[must_use]
pub(crate) fn encode_string_attrs(attrs: &[(String, String)]) -> Vec<u8> {
    let mut contents = Vec::new();
    for (k, v) in attrs {
        contents.extend_from_slice(k.as_bytes());
        contents.push(0);
        contents.extend_from_slice(v.as_bytes());
        contents.push(0);
    }
    contents
}

/// MIT `krb5_db_update_tl_data` (`lib/kdb/kdb5.c:2285-2334`): a record replaces the one of its type where it is; a new type, or any database argument, goes first.
pub(crate) fn update_tl_data(tl: &mut Vec<TlData>, new: TlData) {
    if new.ty != TL_DB_ARGS
        && let Some(t) = tl.iter_mut().find(|t| t.ty == new.ty)
    {
        t.contents = new.contents;
        return;
    }
    tl.insert(0, new);
}

/// The lifetimes as the database holds them: an alias stub has none (`write_princ_record`).
fn mit_lifetimes(p: &Principal) -> (u64, u64) {
    if p.alias_target().is_some() {
        (0, 0)
    } else {
        (p.max_life, p.max_renewable_life)
    }
}

/// MIT `find_changed_attrs` (`lib/kdb/kdb_convert.c:46-144`): the attributes in which `new` differs from `current`, as a list in MIT's order.
/// MIT `find_changed_attrs` (`lib/kdb/kdb_convert.c:69-78`): with `exclude_nra` the three lockout attributes are never listed.
#[must_use]
pub(crate) fn find_changed_attrs(current: &Principal, new: &Principal, exclude_nra: bool) -> u32 {
    let mut attrs = 0;
    let (cur_life, new_life) = (mit_lifetimes(current), mit_lifetimes(new));
    if dump_attributes(current) != dump_attributes(new) {
        attrs |= attr_bit(AT_ATTRFLAGS);
    }
    if cur_life.0 != new_life.0 {
        attrs |= attr_bit(AT_MAX_LIFE);
    }
    if cur_life.1 != new_life.1 {
        attrs |= attr_bit(AT_MAX_RENEW_LIFE);
    }
    if current.expiration != new.expiration {
        attrs |= attr_bit(AT_EXP);
    }
    if current.pw_expire != new.pw_expire {
        attrs |= attr_bit(AT_PW_EXP);
    }
    if !exclude_nra {
        if current.last_success != new.last_success {
            attrs |= attr_bit(AT_LAST_SUCCESS);
        }
        if current.last_failed != new.last_failed {
            attrs |= attr_bit(AT_LAST_FAILED);
        }
        if current.fail_auth_count != new.fail_auth_count {
            attrs |= attr_bit(AT_FAIL_AUTH_COUNT);
        }
    }
    if princ_listed(current, new) {
        attrs |= attr_bit(AT_PRINC);
    }
    if current.keys.len() != new.keys.len()
        || current
            .keys
            .iter()
            .zip(&new.keys)
            .any(|(c, n)| c.kvno != n.kvno)
    {
        attrs |= attr_bit(AT_KEYDATA);
    }
    if mit_tl(current) != mit_tl(new) {
        attrs |= attr_bit(AT_TL_DATA);
    }
    if current.db_entry_len != new.db_entry_len {
        attrs |= attr_bit(AT_LEN);
    }
    attrs
}

/// MIT `find_changed_attrs` (`lib/kdb/kdb_convert.c:80-101`): the realm test is inverted, so a principal whose realm is the same is always listed.
/// Only a realm of the same length that differs has its components compared, each by its
/// current length.
fn princ_listed(current: &Principal, new: &Principal) -> bool {
    let (c, n) = (&current.name.name_string, &new.name.name_string);
    if current.name.name_type != new.name.name_type || c.len() != n.len() {
        return true;
    }
    if current.realm.len() != new.realm.len() || current.realm == new.realm {
        return true;
    }
    c.iter()
        .zip(n.iter())
        .any(|(a, b)| !b.as_bytes().starts_with(a.as_bytes()))
}

/// MIT `krb5_dbe_lookup_last_pwd_change` (`lib/kdb/kdb5.c:1505-1527`): a missing record, or one not four bytes long, reads as 0.
fn last_pwd_change(tl: &[TlData]) -> u32 {
    tl.iter()
        .find(|t| t.ty == TL_LAST_PWD_CHANGE)
        .and_then(|t| <[u8; 4]>::try_from(t.contents.as_slice()).ok())
        .map_or(0, u32::from_le_bytes)
}

/// MIT `krb5_dbe_lookup_mod_princ_data` (`lib/kdb/kdb5.c:1637-1663`): a record shorter than five bytes, not NUL-terminated or whose name does not parse is not there.
fn mod_princ_data(tl: &[TlData]) -> Option<(u32, PrincipalName, String)> {
    let (time, name) = tl
        .iter()
        .find(|t| t.ty == TL_MOD_PRINC)
        .and_then(|t| tl_mod_princ(&t.contents))?;
    let (princ, realm) = krb5_types::principal_from_unparsed(&name, "").ok()?;
    Some((time, princ, realm))
}

/// MIT `ulog_conv_2logentry` (`lib/kdb/kdb_convert.c:362-535`): the listed attributes of `p`, each in MIT's shape, in the list's order.
/// MIT `ulog_conv_2logentry` (`lib/kdb/kdb_convert.c:464-525`): a listed `AT_TL_DATA` is the password-change time, the modifier and its time when the record has one, then every other record.
/// MIT `ulog_conv_2logentry` (`lib/kdb/kdb_convert.c:364-387`): the flags and both lifetimes go only when they are not negative as 32-bit values.
/// MIT `ulog_conv_2logentry` (`lib/kdb/kdb_convert.c:389-402`): an expiration or password expiration past 2038 is negative as a 32-bit value and is not sent.
/// Here both go whenever listed: settled live, MIT's own replica otherwise keeps the expiration
/// it had while its primary expires the principal (`docs/mit-deviations.md`).
/// The three non-replicated attributes have no case in MIT's switch and are never sent.
#[must_use]
pub fn conv_2logentry(p: &Principal, attrs: u32) -> Vec<KdbeVal> {
    let (max_life, max_rlife) = mit_lifetimes(p);
    let mut out = Vec::new();
    for at in AT_ATTRFLAGS..=AT_PW_HIST {
        if attrs & attr_bit(at) == 0 {
            continue;
        }
        match at {
            AT_ATTRFLAGS => {
                let flags = dump_attributes(p);
                if flags.cast_signed() >= 0 {
                    out.push(KdbeVal::AttrFlags(flags));
                }
            }
            AT_MAX_LIFE => {
                if let Ok(v) = i32::try_from(max_life) {
                    out.push(KdbeVal::MaxLife(v.cast_unsigned()));
                }
            }
            AT_MAX_RENEW_LIFE => {
                if let Ok(v) = i32::try_from(max_rlife) {
                    out.push(KdbeVal::MaxRenewLife(v.cast_unsigned()));
                }
            }
            AT_EXP => out.push(KdbeVal::Exp(p.expiration)),
            AT_PW_EXP => out.push(KdbeVal::PwExp(p.pw_expire)),
            AT_PRINC => {
                if !p.name.name_string.is_empty() {
                    out.push(KdbeVal::Princ(p.name.clone(), p.realm.clone()));
                }
            }
            AT_KEYDATA => out.push(KdbeVal::KeyData(p.keys.clone())),
            AT_TL_DATA => {
                let tl = mit_tl(p);
                out.push(KdbeVal::PwLastChange(last_pwd_change(&tl)));
                if let Some((time, princ, realm)) = mod_princ_data(&tl) {
                    out.push(KdbeVal::ModPrinc(princ, realm));
                    out.push(KdbeVal::ModTime(time));
                }
                let rest: Vec<TlData> = tl
                    .into_iter()
                    .filter(|t| t.ty != TL_LAST_PWD_CHANGE && t.ty != TL_MOD_PRINC)
                    .collect();
                if !rest.is_empty() {
                    out.push(KdbeVal::TlData(rest));
                }
            }
            AT_LEN => out.push(KdbeVal::Len(p.db_entry_len)),
            _ => {}
        }
    }
    out
}

/// A record with nothing in it but `name` (MIT's `calloc` for an update to a principal the replica
/// does not have).
fn empty_entry(name: &str) -> Result<Principal, Error> {
    let (princ, realm) = krb5_types::principal_from_unparsed(name, "")
        .map_err(|e| Error::InvalidArgument(format!("iprop update for {name}: {e}")))?;
    Ok(Principal {
        salt: princ.default_salt(&realm),
        name: princ,
        realm,
        keys: Vec::new(),
        key_history: Vec::new(),
        requires_preauth: false,
        max_life: 0,
        locked: false,
        pw_expire: 0,
        attributes: 0,
        max_renewable_life: 0,
        expiration: 0,
        last_success: 0,
        last_failed: 0,
        fail_auth_count: 0,
        mkvno: 1,
        db_entry_len: 0,
        tl_data: Vec::new(),
        e_data: Vec::new(),
        rid: 0,
        s4u_allowed_from: Vec::new(),
        s4u_allowed_to: Vec::new(),
        pw_policy: None,
        kadm: KadmData::default(),
        string_attrs: Vec::new(),
    })
}

/// MIT `ulog_conv_2dbentry` (`lib/kdb/kdb_convert.c:550-765`): the replica's own record (an empty one for a new principal) with only the attributes the update carries applied, in its order.
/// MIT `ulog_conv_2dbentry` (`lib/kdb/kdb_convert.c:626-639`): a replica applies none of the three lockout attributes.
/// MIT `ulog_conv_2dbentry` (`lib/kdb/kdb_convert.c:651-703`): `AT_KEYDATA` replaces every key.
/// MIT `ulog_conv_2dbentry` (`lib/kdb/kdb_convert.c:705-715`): each `AT_TL_DATA` record replaces the one of its type, and none is removed.
/// MIT `ulog_conv_2dbentry` (`lib/kdb/kdb_convert.c:748-756`): the modifier is recorded after every attribute, when both it and a nonzero time came.
/// The policy, the password history and the attributes MIT's switch ignores travel only in
/// `KRB5_TL_KADM_DATA`; the record's views of its flags, strings, kadm5 record and master key
/// version are read again from what changed, and its salt from new keys or a new name as a dump
/// load reads it.
///
/// # Errors
///
/// [`Error::InvalidArgument`] when the update is for a principal the replica does not have and
/// its name does not parse; [`Error::Crypto`] when a carried `KRB5_TL_KADM_DATA` does not decode.
pub fn conv_2dbentry(
    existing: Option<&Principal>,
    name: &str,
    vals: &[KdbeVal],
    replica: bool,
) -> Result<Principal, Error> {
    let mut ent = match existing {
        Some(p) => {
            let mut p = p.clone();
            p.attributes = dump_attributes(&p);
            p
        }
        None => empty_entry(name)?,
    };
    let mut mod_princ: Option<(&PrincipalName, &String)> = None;
    let mut mod_time = 0;
    let mut renamed = false;
    for v in vals {
        match v {
            KdbeVal::AttrFlags(a) => ent.attributes = *a,
            KdbeVal::MaxLife(t) => ent.max_life = u64::from(*t),
            KdbeVal::MaxRenewLife(t) => ent.max_renewable_life = u64::from(*t),
            KdbeVal::Exp(t) => ent.expiration = *t,
            KdbeVal::PwExp(t) => ent.pw_expire = *t,
            KdbeVal::LastSuccess(t) if !replica => ent.last_success = *t,
            KdbeVal::LastFailed(t) if !replica => ent.last_failed = *t,
            KdbeVal::FailAuthCount(n) if !replica => ent.fail_auth_count = *n,
            KdbeVal::Princ(n, r) => {
                renamed = *n != ent.name || *r != ent.realm;
                ent.name = n.clone();
                ent.realm.clone_from(r);
            }
            KdbeVal::KeyData(keys) => ent.keys.clone_from(keys),
            KdbeVal::TlData(tl) => {
                for t in tl {
                    update_tl_data(&mut ent.tl_data, t.clone());
                }
            }
            KdbeVal::PwLastChange(t) => update_tl_data(
                &mut ent.tl_data,
                TlData {
                    ty: TL_LAST_PWD_CHANGE,
                    contents: t.to_le_bytes().to_vec(),
                },
            ),
            KdbeVal::ModPrinc(n, r) => mod_princ = Some((n, r)),
            KdbeVal::ModTime(t) => mod_time = *t,
            KdbeVal::Len(l) => ent.db_entry_len = *l,
            _ => {}
        }
    }
    if mod_time != 0
        && let Some((n, r)) = mod_princ
    {
        let mut contents = mod_time.to_le_bytes().to_vec();
        contents.extend_from_slice(crate::kdb::lookup_principal_id(n, r).as_bytes());
        contents.push(0);
        update_tl_data(
            &mut ent.tl_data,
            TlData {
                ty: TL_MOD_PRINC,
                contents,
            },
        );
    }
    let carried = |ty: i32| {
        vals.iter()
            .any(|v| matches!(v, KdbeVal::TlData(tl) if tl.iter().any(|t| t.ty == ty)))
    };
    ent.requires_preauth = ent.attributes & KDB_REQUIRES_PRE_AUTH != 0;
    ent.locked = ent.attributes & KDB_DISALLOW_ALL_TIX != 0;
    let rekeyed = vals.iter().any(|v| matches!(v, KdbeVal::KeyData(_)));
    if rekeyed || renamed || existing.is_none() {
        ent.salt = salt_of_keys(&ent.keys, &ent.name, &ent.realm);
    }
    if carried(TL_STRING_ATTRS) {
        ent.string_attrs = attrs_from_tl(&ent.tl_data);
    }
    if carried(TL_KADM_DATA) {
        let osa = OsaPrincEnt::from_tl(&ent.tl_data).map_err(|e| Error::Crypto(e.to_string()))?;
        ent.pw_policy = osa
            .as_ref()
            .and_then(|o| o.bound_policy().map(str::to_owned));
        ent.kadm = osa.as_ref().map(KadmData::from_osa).unwrap_or_default();
        ent.key_history.clear();
    }
    if carried(TL_MKVNO) {
        ent.mkvno = mkvno_from_tl(&ent.tl_data);
    }
    Ok(ent)
}
