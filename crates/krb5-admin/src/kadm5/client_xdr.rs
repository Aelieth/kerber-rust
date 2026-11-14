use zeroize::Zeroizing;

use super::xdr::{XdrR, XdrW, xdr_tl_type};
use crate::Error;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TlView {
    pub(crate) ty: i32,
    pub(crate) contents: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct KeyDataView {
    pub(crate) ver: i32,
    pub(crate) kvno: u32,
    pub(crate) enctype: i32,
    pub(crate) salttype: i32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PrincView {
    pub(crate) principal: String,
    pub(crate) princ_expire_time: u32,
    pub(crate) last_pwd_change: u32,
    pub(crate) pw_expiration: u32,
    pub(crate) max_life: u32,
    pub(crate) mod_name: Option<String>,
    pub(crate) mod_date: u32,
    pub(crate) attributes: u32,
    pub(crate) kvno: u32,
    pub(crate) mkvno: u32,
    pub(crate) policy: Option<String>,
    pub(crate) aux_attributes: u32,
    pub(crate) max_renewable_life: u32,
    pub(crate) last_success: u32,
    pub(crate) last_failed: u32,
    pub(crate) fail_auth_count: u32,
    pub(crate) key_data: Vec<KeyDataView>,
    pub(crate) tl_data: Vec<TlView>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PolicyView {
    pub(crate) name: String,
    pub(crate) pw_min_life: u32,
    pub(crate) pw_max_life: u32,
    pub(crate) pw_min_length: u32,
    pub(crate) pw_min_classes: u32,
    pub(crate) pw_history_num: u32,
    pub(crate) policy_refcnt: u32,
    pub(crate) pw_max_fail: u32,
    pub(crate) pw_failcnt_interval: u32,
    pub(crate) pw_lockout_duration: u32,
    pub(crate) attributes: u32,
    pub(crate) max_life: u32,
    pub(crate) max_renewable_life: u32,
    pub(crate) allowed_keysalts: Option<String>,
    pub(crate) tl_data: Vec<TlView>,
}

pub(crate) struct KeyBlock {
    pub(crate) enctype: i32,
    pub(crate) key: Zeroizing<Vec<u8>>,
}

pub(crate) struct ExtractedKey {
    pub(crate) kvno: u32,
    pub(crate) enctype: i32,
    pub(crate) key: Zeroizing<Vec<u8>>,
}

#[derive(Debug)]
pub(crate) struct Reply<T> {
    pub(crate) code: u32,
    pub(crate) body: Option<T>,
}

fn head(api: u32) -> XdrW {
    let mut w = XdrW::default();
    w.u32(api);
    w
}

fn put_len(w: &mut XdrW, n: usize) {
    w.u32(u32::try_from(n).unwrap_or(u32::MAX));
}

fn put_ks(w: &mut XdrW, ks: &[(i32, i32)]) {
    put_len(w, ks.len());
    for &(etype, salt) in ks {
        w.u32(etype.cast_unsigned());
        w.u32(salt.cast_unsigned());
    }
}

fn put_tl(w: &mut XdrW, tl: &[TlView]) {
    put_len(w, tl.len());
    if tl.is_empty() {
        w.u32(1);
        return;
    }
    w.u32(0);
    for t in tl {
        w.u32(1);
        w.u32(t.ty.cast_unsigned());
        w.opaque(&t.contents);
    }
    w.u32(0);
}

// MIT: `_xdr_kadm5_principal_ent_rec` (kadm_rpc_xdr.c:389-467)
fn put_princ_ent(w: &mut XdrW, p: &PrincView) {
    w.nullstring(Some(&p.principal));
    w.u32(p.princ_expire_time);
    w.u32(p.last_pwd_change);
    w.u32(p.pw_expiration);
    w.u32(p.max_life);
    match &p.mod_name {
        None => w.u32(1),
        Some(n) => {
            w.u32(0);
            w.nullstring(Some(n));
        }
    }
    w.u32(p.mod_date);
    w.u32(p.attributes);
    w.u32(p.kvno);
    w.u32(p.mkvno);
    w.nullstring(p.policy.as_deref());
    w.u32(p.aux_attributes);
    w.u32(p.max_renewable_life);
    w.u32(p.last_success);
    w.u32(p.last_failed);
    w.u32(p.fail_auth_count);
    put_len(w, p.key_data.len());
    put_tl(w, &p.tl_data);
    put_len(w, p.key_data.len());
    for k in &p.key_data {
        w.u32(k.ver.cast_unsigned());
        w.u32(k.kvno);
        w.u32(k.enctype.cast_unsigned());
        if k.ver > 1 {
            w.u32(k.salttype.cast_unsigned());
        }
    }
}

// MIT: `_xdr_kadm5_policy_ent_rec` (kadm_rpc_xdr.c:470-537)
fn put_policy(w: &mut XdrW, api: u32, p: &PolicyView) {
    w.nullstring(Some(&p.name));
    w.u32(p.pw_min_life);
    w.u32(p.pw_max_life);
    w.u32(p.pw_min_length);
    w.u32(p.pw_min_classes);
    w.u32(p.pw_history_num);
    w.u32(p.policy_refcnt);
    if api >= super::codes::API_V3 {
        w.u32(p.pw_max_fail);
        w.u32(p.pw_failcnt_interval);
        w.u32(p.pw_lockout_duration);
    }
    if api >= super::codes::API_V4 {
        w.u32(p.attributes);
        w.u32(p.max_life);
        w.u32(p.max_renewable_life);
        w.nullstring(p.allowed_keysalts.as_deref());
        put_tl(w, &p.tl_data);
    }
}

fn name_args(api: u32, name: &str) -> Vec<u8> {
    let mut w = head(api);
    w.nullstring(Some(name));
    w.b
}

fn secret(w: XdrW) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(w.b)
}

// MIT: `xdr_cprinc_arg` (kadm_rpc_xdr.c:546-562)
pub(crate) fn encode_create_principal(
    api: u32,
    rec: &PrincView,
    mask: u32,
    pass: Option<&[u8]>,
) -> Zeroizing<Vec<u8>> {
    let mut w = head(api);
    put_princ_ent(&mut w, rec);
    w.u32(mask);
    w.cstring_bytes(pass);
    secret(w)
}

// MIT: `xdr_cprinc3_arg` (kadm_rpc_xdr.c:565-587)
pub(crate) fn encode_create_principal3(
    api: u32,
    rec: &PrincView,
    mask: u32,
    ks: &[(i32, i32)],
    pass: Option<&[u8]>,
) -> Zeroizing<Vec<u8>> {
    let mut w = head(api);
    put_princ_ent(&mut w, rec);
    w.u32(mask);
    put_ks(&mut w, ks);
    w.cstring_bytes(pass);
    secret(w)
}

// MIT: `xdr_dprinc_arg` (kadm_rpc_xdr.c:603-612)
pub(crate) fn encode_delete_principal(api: u32, name: &str) -> Vec<u8> {
    name_args(api, name)
}

// MIT: `xdr_mprinc_arg` (kadm_rpc_xdr.c:615-628)
pub(crate) fn encode_modify_principal(api: u32, rec: &PrincView, mask: u32) -> Vec<u8> {
    let mut w = head(api);
    put_princ_ent(&mut w, rec);
    w.u32(mask);
    w.b
}

// MIT: `xdr_rprinc_arg` (kadm_rpc_xdr.c:631-643)
pub(crate) fn encode_rename_principal(api: u32, src: &str, dest: &str) -> Vec<u8> {
    let mut w = head(api);
    w.nullstring(Some(src));
    w.nullstring(Some(dest));
    w.b
}

// MIT: `xdr_calias_arg` (kadm_rpc_xdr.c:1214-1226)
pub(crate) fn encode_create_alias(api: u32, alias: &str, target: &str) -> Vec<u8> {
    encode_rename_principal(api, alias, target)
}

// MIT: `xdr_gprinc_arg` (kadm_rpc_xdr.c:837-850)
pub(crate) fn encode_get_principal(api: u32, name: &str, mask: u32) -> Vec<u8> {
    let mut w = head(api);
    w.nullstring(Some(name));
    w.u32(mask);
    w.b
}

// MIT: `xdr_gprincs_arg` (kadm_rpc_xdr.c:646-655)
pub(crate) fn encode_get_principals(api: u32, glob: Option<&str>) -> Vec<u8> {
    let mut w = head(api);
    w.nullstring(glob);
    w.b
}

// MIT: `xdr_chpass_arg` (kadm_rpc_xdr.c:681-693)
pub(crate) fn encode_chpass(api: u32, name: &str, pass: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut w = head(api);
    w.nullstring(Some(name));
    w.cstring_bytes(Some(pass));
    secret(w)
}

// MIT: `xdr_chpass3_arg` (kadm_rpc_xdr.c:696-717)
pub(crate) fn encode_chpass3(
    api: u32,
    name: &str,
    keepold: bool,
    ks: &[(i32, i32)],
    pass: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut w = head(api);
    w.nullstring(Some(name));
    w.u32(u32::from(keepold));
    put_ks(&mut w, ks);
    w.cstring_bytes(Some(pass));
    secret(w)
}

// MIT: `xdr_chrand_arg` (kadm_rpc_xdr.c:784-793)
pub(crate) fn encode_chrand(api: u32, name: &str) -> Vec<u8> {
    name_args(api, name)
}

// MIT: `xdr_chrand3_arg` (kadm_rpc_xdr.c:796-814)
pub(crate) fn encode_chrand3(api: u32, name: &str, keepold: bool, ks: &[(i32, i32)]) -> Vec<u8> {
    let mut w = head(api);
    w.nullstring(Some(name));
    w.u32(u32::from(keepold));
    put_ks(&mut w, ks);
    w.b
}

// MIT: `xdr_purgekeys_arg` (kadm_rpc_xdr.c:993-1006)
pub(crate) fn encode_purgekeys(api: u32, name: &str, keepkvno: i32) -> Vec<u8> {
    let mut w = head(api);
    w.nullstring(Some(name));
    w.u32(keepkvno.cast_unsigned());
    w.b
}

// MIT: `xdr_gstrings_arg` (kadm_rpc_xdr.c:1009-1019)
pub(crate) fn encode_get_strings(api: u32, name: &str) -> Vec<u8> {
    name_args(api, name)
}

// MIT: `xdr_sstring_arg` (kadm_rpc_xdr.c:1046-1062)
pub(crate) fn encode_set_string(api: u32, name: &str, key: &str, value: Option<&str>) -> Vec<u8> {
    let mut w = head(api);
    w.nullstring(Some(name));
    w.nullstring(Some(key));
    w.nullstring(value);
    w.b
}

// MIT: `xdr_getpkeys_arg` (kadm_rpc_xdr.c:1179-1191)
pub(crate) fn encode_extract_keys(api: u32, name: &str, kvno: u32) -> Vec<u8> {
    let mut w = head(api);
    w.nullstring(Some(name));
    w.u32(kvno);
    w.b
}

pub(crate) fn encode_get_privs(api: u32) -> Vec<u8> {
    head(api).b
}

pub(crate) fn encode_init(api: u32) -> Vec<u8> {
    head(api).b
}

// MIT: `xdr_cpol_arg` (kadm_rpc_xdr.c:872-885)
pub(crate) fn encode_create_policy(api: u32, rec: &PolicyView, mask: u32) -> Vec<u8> {
    let mut w = head(api);
    put_policy(&mut w, api, rec);
    w.u32(mask);
    w.b
}

// MIT: `xdr_mpol_arg` (kadm_rpc_xdr.c:900-913)
pub(crate) fn encode_modify_policy(api: u32, rec: &PolicyView, mask: u32) -> Vec<u8> {
    encode_create_policy(api, rec, mask)
}

// MIT: `xdr_dpol_arg` (kadm_rpc_xdr.c:888-897)
pub(crate) fn encode_delete_policy(api: u32, name: &str) -> Vec<u8> {
    name_args(api, name)
}

// MIT: `xdr_gpol_arg` (kadm_rpc_xdr.c:916-925)
pub(crate) fn encode_get_policy(api: u32, name: &str) -> Vec<u8> {
    name_args(api, name)
}

// MIT: `xdr_gpols_arg` (kadm_rpc_xdr.c:946-955)
pub(crate) fn encode_get_policies(api: u32, glob: Option<&str>) -> Vec<u8> {
    encode_get_principals(api, glob)
}

fn get_tl(r: &mut XdrR<'_>) -> Result<Vec<TlView>, Error> {
    let _n_tl = r.u32()?;
    let mut out = Vec::new();
    if r.u32()? == 0 {
        while r.u32()? != 0 {
            let ty = xdr_tl_type(r.u32()?);
            out.push(TlView {
                ty,
                contents: r.opaque()?,
            });
        }
    }
    Ok(out)
}

fn get_u32(r: &mut XdrR<'_>) -> Result<u32, Error> {
    r.u32()
}

fn get_names(r: &mut XdrR<'_>) -> Result<Vec<String>, Error> {
    let _count = r.u32()?;
    let n = r.u32()?;
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(r.nullstring()?.unwrap_or_default());
    }
    Ok(out)
}

fn reply<T>(
    b: &[u8],
    body: impl FnOnce(&mut XdrR<'_>) -> Result<T, Error>,
) -> Result<Reply<T>, Error> {
    let mut r = XdrR::new(b);
    let _api = r.u32()?;
    let code = r.u32()?;
    let body = if code == 0 { Some(body(&mut r)?) } else { None };
    Ok(Reply { code, body })
}

// MIT: `xdr_generic_ret` (kadm_rpc_xdr.c:590-600)
pub(crate) fn decode_generic(b: &[u8]) -> Result<Reply<()>, Error> {
    reply(b, |_| Ok(()))
}

// MIT: `xdr_gprinc_ret` (kadm_rpc_xdr.c:853-869)
pub(crate) fn decode_get_principal(b: &[u8]) -> Result<Reply<PrincView>, Error> {
    reply(b, get_princ_ent)
}

// MIT: `_xdr_kadm5_principal_ent_rec` (kadm_rpc_xdr.c:389-467)
fn get_princ_ent(r: &mut XdrR<'_>) -> Result<PrincView, Error> {
    let mut p = PrincView {
        principal: r.nullstring()?.unwrap_or_default(),
        princ_expire_time: r.u32()?,
        last_pwd_change: r.u32()?,
        pw_expiration: r.u32()?,
        max_life: r.u32()?,
        ..PrincView::default()
    };
    if r.u32()? == 0 {
        p.mod_name = r.nullstring()?;
    }
    p.mod_date = r.u32()?;
    p.attributes = r.u32()?;
    p.kvno = r.u32()?;
    p.mkvno = r.u32()?;
    p.policy = r.nullstring()?;
    p.aux_attributes = r.u32()?;
    p.max_renewable_life = r.u32()?;
    p.last_success = r.u32()?;
    p.last_failed = r.u32()?;
    p.fail_auth_count = r.u32()?;
    if r.u32()?.cast_signed() < 0 {
        return Err(Error::GarbageArgs);
    }
    // MIT: `xdr_krb5_tl_data` (kadm_rpc_xdr.c:302-363)
    p.tl_data = get_tl(r)?;
    p.tl_data.reverse();
    let n = r.u32()?;
    for _ in 0..n {
        let ver = xdr_tl_type(r.u32()?);
        let kvno = r.u32()?;
        let enctype = xdr_tl_type(r.u32()?);
        let salttype = if ver > 1 { xdr_tl_type(r.u32()?) } else { 0 };
        p.key_data.push(KeyDataView {
            ver,
            kvno,
            enctype,
            salttype,
        });
    }
    Ok(p)
}

// MIT: `xdr_gprincs_ret` (kadm_rpc_xdr.c:658-678)
pub(crate) fn decode_get_principals(b: &[u8]) -> Result<Reply<Vec<String>>, Error> {
    reply(b, get_names)
}

// MIT: `xdr_gpols_ret` (kadm_rpc_xdr.c:958-978)
pub(crate) fn decode_get_policies(b: &[u8]) -> Result<Reply<Vec<String>>, Error> {
    reply(b, get_names)
}

// MIT: `xdr_chrand_ret` (kadm_rpc_xdr.c:817-834)
pub(crate) fn decode_chrand(b: &[u8]) -> Result<Reply<Vec<KeyBlock>>, Error> {
    reply(b, |r| {
        let n = r.u32()?;
        let mut keys = Vec::new();
        for _ in 0..n {
            let enctype = r.u32()?.cast_signed();
            keys.push(KeyBlock {
                enctype,
                key: Zeroizing::new(r.opaque()?),
            });
        }
        Ok(keys)
    })
}

// MIT: `xdr_getpkeys_ret` (kadm_rpc_xdr.c:1194-1211)
pub(crate) fn decode_extract_keys(b: &[u8]) -> Result<Reply<Vec<ExtractedKey>>, Error> {
    reply(b, |r| {
        let n = r.u32()?;
        let mut keys = Vec::new();
        for _ in 0..n {
            let kvno = r.u32()?;
            let enctype = r.u32()?.cast_signed();
            let key = Zeroizing::new(r.opaque()?);
            let _salttype = r.u32()?;
            let _salt = r.opaque()?;
            keys.push(ExtractedKey { kvno, enctype, key });
        }
        Ok(keys)
    })
}

// MIT: `xdr_gstrings_ret` (kadm_rpc_xdr.c:1022-1043)
pub(crate) fn decode_get_strings(b: &[u8]) -> Result<Reply<Vec<(String, String)>>, Error> {
    reply(b, |r| {
        let _count = r.u32()?;
        let n = r.u32()?;
        let mut out = Vec::new();
        for _ in 0..n {
            let (Some(k), Some(v)) = (r.nullstring()?, r.nullstring()?) else {
                return Err(Error::GarbageArgs);
            };
            out.push((k, v));
        }
        Ok(out)
    })
}

// MIT: `xdr_gpol_ret` (kadm_rpc_xdr.c:928-943)
pub(crate) fn decode_get_policy(b: &[u8], api: u32) -> Result<Reply<PolicyView>, Error> {
    reply(b, |r| {
        let mut p = PolicyView {
            name: r.nullstring()?.unwrap_or_default(),
            pw_min_life: r.u32()?,
            pw_max_life: r.u32()?,
            pw_min_length: r.u32()?,
            pw_min_classes: r.u32()?,
            pw_history_num: r.u32()?,
            policy_refcnt: r.u32()?,
            ..PolicyView::default()
        };
        if api >= super::codes::API_V3 {
            p.pw_max_fail = r.u32()?;
            p.pw_failcnt_interval = r.u32()?;
            p.pw_lockout_duration = r.u32()?;
        }
        if api >= super::codes::API_V4 {
            p.attributes = r.u32()?;
            p.max_life = r.u32()?;
            p.max_renewable_life = r.u32()?;
            p.allowed_keysalts = r.nullstring()?;
            p.tl_data = get_tl(r)?;
            p.tl_data.reverse();
        }
        Ok(p)
    })
}

// MIT: `xdr_getprivs_ret` (kadm_rpc_xdr.c:980-989)
pub(crate) fn decode_get_privs(b: &[u8]) -> Result<Reply<u32>, Error> {
    reply(b, get_u32)
}
