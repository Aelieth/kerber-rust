//! Principal argument and reply codecs (`kadm_rpc_xdr.c` `xdr_cprinc_arg`,
//! `xdr_mprinc_arg`, `xdr_gprinc_ret`, ...) and the `svr_principal.c`
//! mask checks (`KADM5_BAD_MASK`, `KADM5_BAD_TL_TYPE`), with the ACL
//! `auth_restrict` caps of `kadmin/server/auth.c` applied to a parsed
//! modify request.

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_kdc::{AdminEnt, KeyEntry, TL_DB_ARGS, TL_LAST_PWD_CHANGE, TL_MOD_PRINC, TlData};
use krb5_types::PrincipalName;

use super::codes::{
    ALL_PRINC_MASK, API_V2, EINVAL, KADM5_AUX_ATTRIBUTES, KADM5_BAD_KEYSALTS, KADM5_BAD_MASK,
    KADM5_FAIL_AUTH_COUNT, KADM5_KEY_DATA, KADM5_LAST_FAILED, KADM5_LAST_PWD_CHANGE,
    KADM5_LAST_SUCCESS, KADM5_MKVNO, KADM5_MOD_NAME, KADM5_MOD_TIME, KADM5_POLICY,
    KADM5_POLICY_CLR, KADM5_PRINCIPAL, SETKEY_PRINCIPAL, SETKEY_PRINCIPAL3, SETKEY_PRINCIPAL4,
};
use super::dispatch::generic_ret;
use super::iprop::tl_u32;
use super::xdr::{XdrR, XdrW, xdr_tl_type};
use crate::Error;

/// `krb5_timeofday` for `impose_restrictions`' `-expire`/`-pwexpire` caps.
pub(super) fn unix_now() -> u32 {
    u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(u32::MAX)
}

/// `auth_restrict` for a modify request: the actor's ACL restrictions, if
/// any, imposed on the parsed `(mask, fields)` (`auth.c`).
pub(super) fn impose_request_restrictions(
    acl: &krb5_kdc::Acl,
    actor: &str,
    tid: &str,
    mask: u32,
    mut fields: ModFields,
) -> (u32, ModFields) {
    let Some(rs) = acl.restrictions(actor, Some(tid)) else {
        return (mask, fields);
    };
    let mut ent = fields.admin_ent(mask);
    rs.impose(&mut ent, unix_now());
    let mask = fields.take_admin_ent(ent);
    (mask, fields)
}

const MAX_SELF_KEEPOLD: u32 = 5;

pub(super) fn clamp_self_keepold(self_change: bool, keepold: bool) -> u32 {
    if !keepold {
        0
    } else if self_change {
        MAX_SELF_KEEPOLD
    } else {
        1
    }
}

/// MIT `kadm5_create_principal_3` (`svr_principal.c:313-326`): kadm5_create_principal mask checks.
pub(super) fn create_princ_mask_err(
    mask: u32,
    policy: Option<&str>,
    n_key_data: u32,
) -> Option<u32> {
    if mask & KADM5_PRINCIPAL == 0
        || mask
            & (KADM5_MOD_NAME
                | KADM5_MOD_TIME
                | KADM5_LAST_PWD_CHANGE
                | KADM5_MKVNO
                | KADM5_AUX_ATTRIBUTES
                | KADM5_LAST_SUCCESS
                | KADM5_LAST_FAILED
                | KADM5_FAIL_AUTH_COUNT)
            != 0
    {
        return Some(KADM5_BAD_MASK);
    }
    if mask & KADM5_KEY_DATA != 0 && n_key_data != 0 {
        return Some(KADM5_BAD_MASK);
    }
    if mask & KADM5_POLICY != 0 && policy.is_none() {
        return Some(KADM5_BAD_MASK);
    }
    if mask & KADM5_POLICY != 0 && mask & KADM5_POLICY_CLR != 0 {
        return Some(KADM5_BAD_MASK);
    }
    if mask & !ALL_PRINC_MASK != 0 {
        return Some(KADM5_BAD_MASK);
    }
    None
}

/// MIT `kadm5_modify_principal` (`svr_principal.c:569-580`): mask checks.
pub(super) fn modify_princ_mask_err(mask: u32, policy: Option<&str>) -> Option<u32> {
    if mask
        & (KADM5_PRINCIPAL
            | KADM5_LAST_PWD_CHANGE
            | KADM5_MOD_TIME
            | KADM5_MOD_NAME
            | KADM5_MKVNO
            | KADM5_AUX_ATTRIBUTES
            | KADM5_KEY_DATA
            | KADM5_LAST_SUCCESS
            | KADM5_LAST_FAILED)
        != 0
    {
        return Some(KADM5_BAD_MASK);
    }
    if mask & !ALL_PRINC_MASK != 0 {
        return Some(KADM5_BAD_MASK);
    }
    if mask & KADM5_POLICY != 0 && policy.is_none() {
        return Some(KADM5_BAD_MASK);
    }
    if mask & KADM5_POLICY != 0 && mask & KADM5_POLICY_CLR != 0 {
        return Some(KADM5_BAD_MASK);
    }
    None
}

pub(super) fn db_args_code(tls: &[TlData]) -> Option<u32> {
    tls.iter().any(|t| t.ty == TL_DB_ARGS).then_some(EINVAL)
}

pub(super) struct CreateFields {
    pub(super) name: PrincipalName,
    pub(super) prealm: String,
    /// `None` is the XDR NULL `passwd` of `kadmin addprinc -randkey`
    /// MIT `kadm5_create_principal_3` (`svr_principal.c:463-470`): (1.8+): creates with a random key and
    /// `:369` skips `passwd_check`.
    pub(super) pass: Option<String>,
    /// The `kadm5_principal_ent_rec` fields `kadm5_create_principal_3`
    /// MIT `kadm5_create_principal_3` (`svr_principal.c:376-420`): applies under `mask`, as sent.
    pub(super) ent: AdminEnt,
    pub(super) tl_data: Vec<TlData>,
    pub(super) n_key_data: u32,
    /// v3 `ks_tuple` (`xdr_cprinc3_arg`); empty on v2 and when the
    /// client omitted `-e`.
    pub(super) ks: Vec<EncryptionType>,
}

/// `xdr_cprinc_arg` / `xdr_cprinc3_arg`: api_version, the whole
/// `kadm5_principal_ent_rec`, mask, (v3: ks_tuple array), passwd.
pub(super) fn parse_create(args: &[u8], v3: bool) -> Result<CreateFields, Error> {
    let mut r = XdrR::new(args);
    let _ = r.u32()?;
    let (name, prealm) = r.principal_realm()?;
    let (fields, n_key_data) = parse_principal_ent_rest(&mut r)?;
    let mask = r.u32()?;
    let ks = if v3 { r.key_salt_tuples()? } else { Vec::new() };
    let pass = r.nullstring()?;
    let ent = AdminEnt {
        mask,
        attributes: fields.attributes,
        max_life: fields.max_life,
        max_renewable_life: fields.max_rlife,
        princ_expire_time: fields.expire,
        pw_expiration: fields.pw_expire,
        kvno: fields.kvno,
        policy: fields.policy,
    };
    Ok(CreateFields {
        name,
        prealm,
        pass,
        ent,
        tl_data: fields.tl_data,
        n_key_data,
        ks,
    })
}

/// Unknown v3 `ks_tuple` etypes are `KADM5_BAD_KEYSALTS` in the stub
/// reply, not ONC RPC `SYSTEM_ERR` (`svr_principal.c` `apply_keysalt_policy`).
pub(super) fn parse_ks<T>(r: Result<T, Error>) -> Result<T, Result<Vec<u8>, Error>> {
    match r {
        Ok(v) => Ok(v),
        Err(Error::Inner(s)) if s == "Invalid key/salt tuples" => {
            Err(Ok(generic_ret(API_V2, KADM5_BAD_KEYSALTS)))
        }
        Err(e) => Err(Err(e)),
    }
}

pub(super) fn parse_chpass(
    args: &[u8],
    v3: bool,
) -> Result<(PrincipalName, String, String, bool, Vec<EncryptionType>), Error> {
    let mut r = XdrR::new(args);
    let _ = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let (keepold, ks) = if v3 {
        let k = r.u32()? != 0;
        (k, r.key_salt_tuples()?)
    } else {
        (false, Vec::new())
    };
    let pass = r.nullstring()?.unwrap_or_default();
    Ok((princ, prealm, pass, keepold, ks))
}

pub(super) fn parse_get(args: &[u8]) -> Result<(PrincipalName, String, u32), Error> {
    let mut r = XdrR::new(args);
    let _ = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let mask = r.u32().unwrap_or(u32::MAX);
    Ok((princ, prealm, mask))
}

pub(super) fn parse_gprincs(args: &[u8]) -> Result<Option<String>, Error> {
    let mut r = XdrR::new(args);
    let _ = r.u32()?;
    r.nullstring()
}

pub(super) fn parse_one_princ(args: &[u8]) -> Result<(PrincipalName, String), Error> {
    let mut r = XdrR::new(args);
    let _ = r.u32()?;
    r.principal_realm()
}

pub(super) fn parse_rename(
    args: &[u8],
) -> Result<(PrincipalName, String, PrincipalName, String), Error> {
    let mut r = XdrR::new(args);
    let _ = r.u32()?;
    let (old, old_realm) = r.principal_realm()?;
    let (new, new_realm) = r.principal_realm()?;
    Ok((old, old_realm, new, new_realm))
}

/// MIT `xdr_calias_arg` (`kadm_rpc_xdr.c:1214-1226`): `xdr_calias_arg` : api version, alias, target.
pub(super) fn parse_alias(
    args: &[u8],
) -> Result<(PrincipalName, String, PrincipalName, String), Error> {
    parse_rename(args)
}

pub(super) fn parse_purgekeys(args: &[u8]) -> Result<(u32, PrincipalName, String, i32), Error> {
    let mut r = XdrR::new(args);
    let api = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let keep = i32::from_be_bytes(r.u32().unwrap_or(u32::MAX).to_be_bytes());
    Ok((api, princ, prealm, keep))
}

/// MIT `xdr_kadm5_key_data` (`kadm_rpc_xdr.c:1166-1174`): a version-4 key carries kvno, keyblock, and salt, with no key-data version word in front.
/// Older setkey procedures omit that kvno and salt, so reading them on a version-3 body would steal the next key's etype.
pub(super) fn parse_setkey(
    args: &[u8],
    proc: u32,
) -> Result<(u32, PrincipalName, String, Vec<krb5_kdc::KeyEntry>, bool), Error> {
    let mut r = XdrR::new(args);
    let api = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let keepold = if proc == SETKEY_PRINCIPAL {
        false
    } else {
        r.u32()? != 0
    };
    if proc == SETKEY_PRINCIPAL3 {
        r.skip_array_i32_pairs()?;
    }
    let n = r.u32()?;
    let mut keys = Vec::new();
    for _ in 0..n {
        // SETKEY4 is MIT xdr_kadm5_key_data (kvno, keyblock, salt), not
        // xdr_krb5_key_data (no leading key_data_ver).
        let kvno = if proc == SETKEY_PRINCIPAL4 {
            r.u32()?
        } else {
            0
        };
        let et = i32::from_be_bytes(r.u32()?.to_be_bytes());
        let etype = EncryptionType::known(et).map_err(|e| Error::Inner(e.to_string()))?;
        let bytes = r.opaque()?;
        let key =
            ProtocolKey::from_bytes(etype, &bytes).map_err(|e| Error::Inner(e.to_string()))?;
        let mut ke = KeyEntry::new(etype, key, kvno);
        if proc == SETKEY_PRINCIPAL4 {
            let st = i32::from_be_bytes(r.u32()?.to_be_bytes());
            let salt = r.opaque()?;
            if st != 0 {
                ke.salt_type = Some(st);
            }
            if !salt.is_empty() {
                ke.kdb_salt = Some(salt);
            }
        }
        keys.push(ke);
    }
    Ok((api, princ, prealm, keys, keepold))
}

pub(super) fn parse_gstrings(args: &[u8]) -> Result<(u32, PrincipalName, String), Error> {
    let mut r = XdrR::new(args);
    let api = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    Ok((api, princ, prealm))
}

pub(super) fn parse_sstring(
    args: &[u8],
) -> Result<(u32, PrincipalName, String, String, Option<String>), Error> {
    let mut r = XdrR::new(args);
    let api = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let key = r.nullstring()?.unwrap_or_default();
    let value = r.nullstring()?;
    Ok((api, princ, prealm, key, value))
}

pub(super) fn encode_gstrings(api: u32, attrs: &[(String, String)]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(api);
    w.u32(0);
    let n = u32::try_from(attrs.len()).unwrap_or(0);
    w.u32(n);
    w.u32(n);
    for (k, v) in attrs {
        w.nullstring(Some(k));
        w.nullstring(Some(v));
    }
    w.b
}

pub(super) fn parse_extract(args: &[u8]) -> Result<(u32, PrincipalName, String, u32), Error> {
    let mut r = XdrR::new(args);
    let api = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let kvno = r.u32().unwrap_or(0);
    Ok((api, princ, prealm, kvno))
}

pub(super) fn parse_chrand(
    args: &[u8],
    v3: bool,
) -> Result<(PrincipalName, String, bool, Vec<EncryptionType>), Error> {
    let mut r = XdrR::new(args);
    let _ = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let (keepold, ks) = if v3 {
        let k = r.u32()? != 0;
        (k, r.key_salt_tuples()?)
    } else {
        (false, Vec::new())
    };
    Ok((princ, prealm, keepold, ks))
}

pub(super) struct ModFields {
    pub(super) expire: u32,
    pub(super) pw_expire: u32,
    pub(super) max_life: u32,
    pub(super) max_rlife: u32,
    pub(super) attributes: u32,
    pub(super) kvno: u32,
    pub(super) policy: Option<String>,
    pub(super) fail_auth_count: u32,
    pub(super) tl_data: Vec<TlData>,
}

impl ModFields {
    /// The restriction-bearing subset as an [`AdminEnt`] under `mask`.
    fn admin_ent(&self, mask: u32) -> AdminEnt {
        AdminEnt {
            mask,
            attributes: self.attributes,
            max_life: self.max_life,
            max_renewable_life: self.max_rlife,
            princ_expire_time: self.expire,
            pw_expiration: self.pw_expire,
            kvno: self.kvno,
            policy: self.policy.clone(),
        }
    }

    /// Write an imposed [`AdminEnt`] back (`impose_restrictions` modifies
    /// `*ent` and `*mask` in place).
    fn take_admin_ent(&mut self, ent: AdminEnt) -> u32 {
        self.attributes = ent.attributes;
        self.max_life = ent.max_life;
        self.max_rlife = ent.max_renewable_life;
        self.expire = ent.princ_expire_time;
        self.pw_expire = ent.pw_expiration;
        self.policy = ent.policy;
        ent.mask
    }
}

/// MIT `_xdr_kadm5_principal_ent_rec` (`kadm_rpc_xdr.c:410-416`): a null mod-principal pointer is not followed by a principal encoding.
/// The attribute mask is the word after the key and typed-data lists, so skipping that optional principal is what keeps the mask aligned.
pub(super) fn parse_modify(args: &[u8]) -> Result<(PrincipalName, String, u32, ModFields), Error> {
    let mut r = XdrR::new(args);
    let _ = r.u32()?;
    let (princ, prealm) = r.principal_realm()?;
    let expire = r.u32()?;
    let _last_pwd = r.u32()?;
    let pw_expire = r.u32()?;
    let max_life = r.u32()?;
    let mod_null = r.u32()?;
    if mod_null == 0 {
        let _ = r.principal()?;
    }
    let _mod_date = r.u32()?;
    let attributes = r.u32()?;
    let kvno = r.u32()?;
    r.u32()?; // mkvno
    let policy = r.nullstring()?;
    r.u32()?; // aux
    let max_rlife = r.u32()?;
    r.u32()?; // last_success
    r.u32()?; // last_failed
    let fail_auth_count = r.u32()?;
    let n_key = r.u32()?;
    let _n_tl = r.u32()?;
    let tl_null = r.u32()?;
    let mut tl_data = Vec::new();
    if tl_null == 0 {
        loop {
            let more = r.u32()?;
            if more == 0 {
                break;
            }
            let ty = xdr_tl_type(r.u32()?);
            let contents = r.opaque()?;
            tl_data.push(TlData { ty, contents });
        }
    }
    let n = r.u32().unwrap_or(0);
    let walk = if n == 0 { n_key } else { n };
    for _ in 0..walk {
        let ver = r.u32()?;
        r.u32()?;
        r.u32()?;
        if ver > 1 {
            r.u32()?;
        }
    }
    let mask = r.u32().unwrap_or(0);
    Ok((
        princ,
        prealm,
        mask,
        ModFields {
            expire,
            pw_expire,
            max_life,
            max_rlife,
            attributes,
            kvno,
            policy,
            fail_auth_count,
            tl_data,
        },
    ))
}

pub(super) fn encode_gprinc(p: &krb5_kdc::Principal) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.u32(0);
    encode_principal_ent(&mut w, p);
    w.b
}

/// MIT `kadm5_get_principal` (`svr_principal.c:809-822`): a mod-principal lookup failure fails the get, and the name is cleared when that mask bit is off.
/// This encoder never sends the null pointer; a missing mod-princ record is written as kadmin/admin in the entry realm.
fn encode_principal_ent(w: &mut XdrW, p: &krb5_kdc::Principal) {
    let id = p.id();
    w.nullstring(Some(&id));
    w.u32(p.expiration);
    w.u32(tl_u32(&p.tl_data, TL_LAST_PWD_CHANGE).unwrap_or(0));
    w.u32(p.pw_expire);
    w.u32(u32::try_from(p.max_life).unwrap_or(0));
    // MIT kadmin always unparses `mod_name`; a NULL pointer is
    // KRB5_PARSE_MALFORMED ("while unparsing principal").
    let mod_name = krb5_kdc::tl_mod_princ_name(&p.tl_data)
        .unwrap_or_else(|| format!("kadmin/admin@{}", p.realm));
    w.u32(0); // xdr_nulltype FALSE → encode principal
    w.nullstring(Some(&mod_name));
    w.u32(tl_u32(&p.tl_data, TL_MOD_PRINC).unwrap_or(0));
    w.u32(p.attributes);
    let kvno = p.keys.iter().map(|k| k.kvno).max().unwrap_or(1);
    w.u32(kvno);
    w.u32(u32::from(p.mkvno));
    match p.pw_policy.as_deref() {
        Some(n) if !n.is_empty() => {
            w.nullstring(Some(n));
            w.u32(KADM5_POLICY);
        }
        _ => {
            w.u32(0);
            w.u32(0);
        }
    }
    w.u32(u32::try_from(p.max_renewable_life).unwrap_or(0));
    w.u32(p.last_success);
    w.u32(p.last_failed);
    w.u32(p.fail_auth_count);
    let n_key = u32::try_from(p.keys.len()).unwrap_or(0);
    let n_tl = u32::try_from(p.tl_data.len()).unwrap_or(0);
    w.u32(n_key);
    w.u32(n_tl);
    if p.tl_data.is_empty() {
        w.u32(1);
    } else {
        w.u32(0);
        for tl in &p.tl_data {
            w.u32(1);
            w.u32(u32::try_from(tl.ty).unwrap_or(0));
            w.opaque(&tl.contents);
        }
        w.u32(0);
    }
    w.u32(n_key);
    for k in &p.keys {
        let ver = if k.salt_type.is_some() { 2 } else { 1 };
        w.u32(ver);
        w.u32(k.kvno);
        w.u32(u32::try_from(k.etype.to_iana()).unwrap_or(0));
        if ver > 1 {
            w.u32(u32::try_from(k.salt_type.unwrap_or(0)).unwrap_or(0));
        }
    }
}

pub(super) fn encode_gprincs(ids: &[String]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.u32(0);
    let n = u32::try_from(ids.len()).unwrap_or(0);
    // MIT `xdr_gprincs_ret` (`kadm_rpc_xdr.c:658-678`): `xdr_int count` then `xdr_array` of
    // `xdr_nullstring` (the array writes count again).
    w.u32(n);
    w.u32(n);
    for id in ids {
        w.nullstring(Some(id));
    }
    w.b
}

pub(super) fn encode_chrand(keys: &[krb5_kdc::KeyEntry]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.u32(0);
    w.u32(u32::try_from(keys.len()).unwrap_or(0));
    for k in keys {
        w.u32(u32::try_from(k.etype.to_iana()).unwrap_or(0));
        w.opaque(k.key.as_bytes());
    }
    w.b
}

pub(super) fn encode_extract_keys(api: u32, p: &krb5_kdc::Principal, kvno: u32) -> Vec<u8> {
    let keys: Vec<&krb5_kdc::KeyEntry> = p
        .keys
        .iter()
        .filter(|k| kvno == 0 || k.kvno == kvno)
        .collect();
    let mut w = XdrW::default();
    w.u32(api);
    w.u32(0);
    w.u32(u32::try_from(keys.len()).unwrap_or(0));
    for k in keys {
        w.u32(k.kvno);
        w.u32(u32::try_from(k.etype.to_iana()).unwrap_or(0));
        w.opaque(k.key.as_bytes());
        w.u32(u32::try_from(k.salt_type.unwrap_or(0)).unwrap_or(0));
        w.opaque(k.kdb_salt.as_deref().unwrap_or(p.salt.as_slice()));
    }
    w.b
}

/// After the leading principal, skip the rest of `kadm5_principal_ent_rec`.
/// `xdr_kadm5_principal_ent_rec` after the principal: every scalar the
/// server reads (`kadm_rpc_xdr.c:xdr_kadm5_principal_ent_rec_v1`), the TL
/// list and the key_data-nocontents array (walked, not kept). Returns the
/// fields and `n_key_data`.
fn parse_principal_ent_rest(r: &mut XdrR<'_>) -> Result<(ModFields, u32), Error> {
    let expire = r.u32()?;
    let _last_pwd = r.u32()?;
    let pw_expire = r.u32()?;
    let max_life = r.u32()?;
    let mod_null = r.u32()?; // xdr_bool: TRUE means NULL
    if mod_null == 0 {
        let _ = r.principal()?;
    }
    r.u32()?; // mod_date
    let attributes = r.u32()?;
    let kvno = r.u32()?;
    r.u32()?; // mkvno
    let policy = r.nullstring()?;
    r.u32()?; // aux_attributes (xdr_long)
    let max_rlife = r.u32()?;
    r.u32()?; // last_success
    r.u32()?; // last_failed
    let fail_auth_count = r.u32()?;
    let n_key = r.u32()?; // int16 via xdr_int
    let _n_tl = r.u32()?;
    let tl_null = r.u32()?;
    let mut tl_data = Vec::new();
    if tl_null == 0 {
        loop {
            let more = r.u32()?;
            if more == 0 {
                break;
            }
            let ty = xdr_tl_type(r.u32()?);
            let contents = r.opaque()?;
            tl_data.push(TlData { ty, contents });
        }
    }
    // xdr_array of key_data_nocontents
    let n = r.u32()?;
    for _ in 0..n {
        let ver = r.u32()?;
        r.u32()?; // kvno ui_2
        r.u32()?; // type[0]
        if ver > 1 {
            r.u32()?; // type[1]
        }
    }
    Ok((
        ModFields {
            expire,
            pw_expire,
            max_life,
            max_rlife,
            attributes,
            kvno,
            policy,
            fail_auth_count,
            tl_data,
        },
        n_key,
    ))
}
