//! The kadm5 procedure switch (`kadmin/server/server_stubs.c`): one arm per
//! procedure, the store write path (`reload_if_stale` before every
//! mutation), the `KADM5_AUTH_*` code each procedure denies with, and the
//! `Error` -> `kadm_err.et` mapping behind `generic_ret`.

use krb5_kdc::{Acl, KDB_LOCKDOWN_KEYS, SharedDump as SharedStore};
use krb5_types::PrincipalName;

use super::codes::{
    API_V2, CHPASS_PRINCIPAL, CHPASS_PRINCIPAL3, CHRAND_PRINCIPAL, CHRAND_PRINCIPAL3, CREATE_ALIAS,
    CREATE_POLICY, CREATE_PRINCIPAL, CREATE_PRINCIPAL3, DELETE_POLICY, DELETE_PRINCIPAL, EINVAL,
    EXTRACT_KEYS, GET_POLICY, GET_POLS, GET_PRINCIPAL, GET_PRINCS, GET_PRIVS, GET_STRINGS, INIT,
    IPROP_FULL_RESYNC, IPROP_FULL_RESYNC_EXT, IPROP_GET_UPDATES, KADM5_ALIAS_REALM,
    KADM5_ATTRIBUTES, KADM5_AUTH_ADD, KADM5_AUTH_CHANGEPW, KADM5_AUTH_DELETE, KADM5_AUTH_EXTRACT,
    KADM5_AUTH_GET, KADM5_AUTH_INITIAL, KADM5_AUTH_INSUFFICIENT, KADM5_AUTH_LIST,
    KADM5_AUTH_MODIFY, KADM5_AUTH_SETKEY, KADM5_BAD_KEYSALTS, KADM5_BAD_SERVER_PARAMS,
    KADM5_BAD_TL_TYPE, KADM5_DUP, KADM5_FAIL_AUTH_COUNT, KADM5_FAILURE, KADM5_MAX_LIFE,
    KADM5_MAX_RLIFE, KADM5_PASS_Q_CLASS, KADM5_PASS_Q_DICT, KADM5_PASS_Q_TOOSHORT,
    KADM5_PASS_REUSE, KADM5_PASS_TOOSOON, KADM5_POLICY, KADM5_POLICY_ALLOWED_KEYSALTS,
    KADM5_POLICY_CLR, KADM5_PRINC_EXPIRE_TIME, KADM5_PW_EXPIRATION, KADM5_PW_MAX_LIFE,
    KADM5_PW_MIN_LIFE, KADM5_SETKEY_BAD_KVNO, KADM5_TL_DATA, KADM5_UNK_POLICY, KADM5_UNK_PRINC,
    KRB5_KDB_ALIAS_UNSUPPORTED, MODIFY_POLICY, MODIFY_PRINCIPAL, PURGEKEYS, RENAME_PRINCIPAL,
    SET_STRING, SETKEY_PRINCIPAL, SETKEY_PRINCIPAL3, SETKEY_PRINCIPAL4,
};
use super::glob::{glob_expand, glob_is_match, glob_pattern_ok};
use super::iprop::dispatch_iprop;
use super::policy::{
    apply_policy_floors, encode_policy, encode_pols, merge_policy, parse_gpols, parse_policy_arg,
    parse_policy_name, policy_floor_err, policy_mask_err, policy_name_err,
    validate_allowed_keysalts,
};
use super::principal::{
    clamp_self_keepold, create_princ_mask_err, db_args_code, encode_chrand, encode_extract_keys,
    encode_gprinc, encode_gprincs, encode_gstrings, impose_request_restrictions,
    modify_princ_mask_err, parse_alias, parse_chpass, parse_chrand, parse_create, parse_extract,
    parse_get, parse_gprincs, parse_gstrings, parse_ks, parse_modify, parse_one_princ,
    parse_purgekeys, parse_rename, parse_setkey, parse_sstring, unix_now,
};
use super::xdr::XdrW;
use crate::Error;

#[allow(clippy::too_many_arguments)]
pub(super) fn kadm5_or_iprop(
    store: &SharedStore,
    acl: &Acl,
    actor: &str,
    proc: u32,
    args: &[u8],
    initial: bool,
    changepw: bool,
    iprop: bool,
) -> Result<Vec<u8>, Error> {
    if proc == 0 {
        return Ok(Vec::new());
    }
    if iprop {
        if !matches!(
            proc,
            IPROP_GET_UPDATES | IPROP_FULL_RESYNC | IPROP_FULL_RESYNC_EXT
        ) {
            return Err(Error::ProcUnavail);
        }
        return Ok(dispatch_iprop(store, acl, actor, proc, args));
    }
    dispatch_kadm5_ticket(store, acl, actor, proc, args, initial, changepw)
}

fn write_store(
    store: &SharedStore,
    proc: u32,
    api: u32,
) -> Result<std::sync::RwLockWriteGuard<'_, krb5_kdc::PrincipalStore>, Vec<u8>> {
    let mut g = store
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Reload then mutate then save. Two processes can still interleave
    // that window; a dump file lock is deferred with db2/LMDB.
    if let Err(e) = g.reload_if_stale() {
        return Err(generic_ret(api, kadm5_code(proc, &Error::from(e))));
    }
    Ok(g)
}

fn acl_id(name: &PrincipalName, realm: &str) -> String {
    name.unparse_with_realm(realm)
}

fn parse_actor(actor: &str) -> Option<(PrincipalName, String)> {
    krb5_types::principal_from_unparsed(actor, "").ok()
}

fn is_self(actor: &str, name: &PrincipalName, realm: &str) -> bool {
    let Some((actor_name, arealm)) = parse_actor(actor) else {
        return false;
    };
    krb5_types::principal_compare(name, realm, &actor_name, &arealm)
}

fn changepw_not_self(changepw: bool, actor: &str, name: &PrincipalName, realm: &str) -> bool {
    changepw && !is_self(actor, name, realm)
}

pub(super) fn store_realm(store: &SharedStore) -> String {
    store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .realm()
        .to_owned()
}

fn req_realm(prealm: &str, store_realm: &str) -> String {
    if prealm.is_empty() {
        store_realm.to_owned()
    } else {
        prealm.to_owned()
    }
}

#[cfg(test)]
pub(super) fn dispatch_kadm5(
    store: &SharedStore,
    acl: &Acl,
    actor: &str,
    proc: u32,
    args: &[u8],
) -> Result<Vec<u8>, Error> {
    dispatch_kadm5_ticket(store, acl, actor, proc, args, true, false)
}

pub(super) fn dispatch_kadm5_ticket(
    store: &SharedStore,
    acl: &Acl,
    actor: &str,
    proc: u32,
    args: &[u8],
    initial: bool,
    changepw: bool,
) -> Result<Vec<u8>, Error> {
    let realm = store_realm(store);
    match proc {
        INIT => Ok(generic_ret(API_V2, 0)),
        GET_PRIVS => {
            let mut w = XdrW::default();
            w.u32(API_V2);
            w.u32(0);
            w.u32(!0);
            Ok(w.b)
        }
        GET_PRINCIPAL => {
            let (name, prealm, _mask) = parse_get(args)?;
            let req = req_realm(&prealm, &realm);
            let g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            match g.get_in_realm(&name, &req) {
                None => Ok(generic_ret(API_V2, KADM5_UNK_PRINC)),
                Some(p) => {
                    let tid = acl_id(&name, &req);
                    if changepw_not_self(changepw, actor, &name, &req)
                        || (acl
                            .check(actor, krb5_kdc::AdminOp::Inquire, Some(&tid))
                            .is_err()
                            && !is_self(actor, &name, &req))
                    {
                        return Ok(generic_ret(API_V2, KADM5_AUTH_GET));
                    }
                    tracing::info!(
                        event = krb5_log::events::ADMIN,
                        component = "krb5-admin",
                        outcome = "ok",
                        detail = "getprinc",
                        principal = p.id(),
                    );
                    Ok(encode_gprinc(p))
                }
            }
        }
        GET_PRINCS => {
            if changepw || acl.check(actor, krb5_kdc::AdminOp::List, None).is_err() {
                return Ok(generic_ret(API_V2, KADM5_AUTH_LIST));
            }
            let expr = parse_gprincs(args)?;
            let g = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let glob = expr.as_deref().unwrap_or("*");
            if !glob_pattern_ok(glob) {
                return Ok(generic_ret(API_V2, EINVAL));
            }
            let mut ids = g.ids();
            if glob != "*" && !glob.is_empty() {
                let pat = glob_expand(glob, true);
                ids.retain(|id| glob_is_match(pat.as_bytes(), id.as_bytes()));
            }
            Ok(encode_gprincs(&ids))
        }
        DELETE_PRINCIPAL => {
            let (name, prealm) = parse_one_princ(args)?;
            let req = req_realm(&prealm, &realm);
            if changepw
                || acl
                    .check(actor, krb5_kdc::AdminOp::Delete, Some(&acl_id(&name, &req)))
                    .is_err()
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_DELETE));
            }
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.get_in_realm(&name, &req)
                .is_some_and(|p| p.attributes & KDB_LOCKDOWN_KEYS != 0)
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_DELETE));
            }
            match g.remove_in(&name, &req) {
                Ok(()) => Ok(generic_ret(API_V2, 0)),
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e)))),
            }
        }
        MODIFY_PRINCIPAL => {
            let (name, prealm, mask, fields) = parse_modify(args)?;
            let req = req_realm(&prealm, &realm);
            let tid = acl_id(&name, &req);
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            // stub_setup rec_out, then ACL, then check_lockdown, then mask
            // (server_stubs.c:296-301,621-638).
            if g.get_in_realm(&name, &req).is_none() {
                return Ok(generic_ret(API_V2, KADM5_UNK_PRINC));
            }
            if changepw
                || acl
                    .check(actor, krb5_kdc::AdminOp::Modify, Some(&tid))
                    .is_err()
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_MODIFY));
            }
            // stub_auth_restrict → auth_restrict → impose_restrictions on
            // the request (`auth.c:205-272`) before check_lockdown and the
            // library's mask validation (`server_stubs.c:630-638`).
            let (mask, fields) = impose_request_restrictions(acl, actor, &tid, mask, fields);
            if mask & KADM5_ATTRIBUTES != 0
                && fields.attributes & KDB_LOCKDOWN_KEYS == 0
                && g.get_in_realm(&name, &req)
                    .is_some_and(|p| p.attributes & KDB_LOCKDOWN_KEYS != 0)
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_MODIFY));
            }
            if let Some(code) = modify_princ_mask_err(mask, fields.policy.as_deref()) {
                return Ok(generic_ret(API_V2, code));
            }
            if mask & KADM5_TL_DATA != 0 && fields.tl_data.iter().any(|t| t.ty < 256) {
                return Ok(generic_ret(API_V2, KADM5_BAD_TL_TYPE));
            }
            if mask & KADM5_FAIL_AUTH_COUNT != 0 && fields.fail_auth_count != 0 {
                return Ok(generic_ret(API_V2, KADM5_BAD_SERVER_PARAMS));
            }
            if mask & KADM5_TL_DATA != 0 && db_args_code(&fields.tl_data).is_some() {
                return Ok(generic_ret(API_V2, EINVAL));
            }
            let attributes = (mask & KADM5_ATTRIBUTES != 0).then_some(fields.attributes);
            let max_life = (mask & KADM5_MAX_LIFE != 0).then_some(u64::from(fields.max_life));
            let max_renewable_life =
                (mask & KADM5_MAX_RLIFE != 0).then_some(u64::from(fields.max_rlife));
            let expiration = (mask & KADM5_PRINC_EXPIRE_TIME != 0).then_some(fields.expire);
            let pw_expire = (mask & KADM5_PW_EXPIRATION != 0).then_some(fields.pw_expire);
            let clear_policy = mask & KADM5_POLICY_CLR != 0;
            let policy = if clear_policy {
                None
            } else if mask & KADM5_POLICY != 0 {
                fields.policy
            } else {
                None
            };
            match g.apply_admin_fields_in(
                &name,
                &req,
                krb5_kdc::AdminFields {
                    attributes,
                    max_life,
                    expiration,
                    pw_expire,
                    policy,
                    clear_policy,
                    max_renewable_life,
                },
                actor,
            ) {
                Ok(()) => {
                    if mask & KADM5_TL_DATA != 0
                        && let Err(e) = g.merge_tl_data_in(&name, &req, &fields.tl_data)
                    {
                        return Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e))));
                    }
                    if mask & KADM5_FAIL_AUTH_COUNT != 0
                        && let Err(e) = g.clear_fail_auth_count_in(&name, &req)
                    {
                        return Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e))));
                    }
                    Ok(generic_ret(API_V2, 0))
                }
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e)))),
            }
        }
        CREATE_PRINCIPAL | CREATE_PRINCIPAL3 => {
            let mut c = match parse_ks(parse_create(args, proc == CREATE_PRINCIPAL3)) {
                Ok(c) => c,
                Err(rep) => return rep,
            };
            let req = req_realm(&c.prealm, &realm);
            let tid = acl_id(&c.name, &req);
            if changepw
                || acl
                    .check(actor, krb5_kdc::AdminOp::Create, Some(&tid))
                    .is_err()
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_ADD));
            }
            // stub_auth_restrict (`server_stubs.c:478,519`): the ACL line's
            // restrictions rewrite the request (`auth.c:205-272`) before
            // kadm5_create_principal_3 validates the mask, loads the policy
            // and runs passwd_check — so a `-policy P` restriction is
            // enforced by P's floors and the quality modules.
            if let Some(rs) = acl.restrictions(actor, Some(&tid)) {
                rs.impose(&mut c.ent, unix_now());
            }
            if let Some(code) =
                create_princ_mask_err(c.ent.mask, c.ent.policy.as_deref(), c.n_key_data)
            {
                return Ok(generic_ret(API_V2, code));
            }
            if c.ent.mask & KADM5_TL_DATA != 0 && c.tl_data.iter().any(|t| t.ty < 256) {
                return Ok(generic_ret(API_V2, KADM5_BAD_TL_TYPE));
            }
            if c.ent.mask & KADM5_TL_DATA != 0 && db_args_code(&c.tl_data).is_some() {
                return Ok(generic_ret(API_V2, EINVAL));
            }
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            // NULL password: random key (`krb5_dbe_crk`), no quality check.
            // `-nokey` (KADM5_KEY_DATA) also lands here — MIT would create a
            // keyless entry (ledger deviation).
            let created = g.create_principal_3_in(
                &c.name,
                &req,
                c.pass.as_deref().map(str::as_bytes),
                &c.ks,
                &c.ent,
                actor,
            );
            match created {
                Ok(()) => {
                    if c.ent.mask & KADM5_TL_DATA != 0
                        && let Err(e) = g.merge_tl_data_in(&c.name, &req, &c.tl_data)
                    {
                        return Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e))));
                    }
                    Ok(generic_ret(API_V2, 0))
                }
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e)))),
            }
        }
        RENAME_PRINCIPAL => {
            let (old, old_realm, new, new_realm) = parse_rename(args)?;
            let old_req = req_realm(&old_realm, &realm);
            let new_req = req_realm(&new_realm, &realm);
            // MIT server_stubs.c:700-712: ACL (AUTH_INSUFFICIENT) then lockdown (AUTH_DELETE).
            // auth_acl.c:638-648: delete on src and add on dest without restrictions.
            if changepw
                || acl
                    .check_rename(actor, &acl_id(&old, &old_req), &acl_id(&new, &new_req))
                    .is_err()
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_INSUFFICIENT));
            }
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.get_in_realm(&old, &old_req)
                .is_some_and(|p| p.attributes & KDB_LOCKDOWN_KEYS != 0)
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_DELETE));
            }
            match g.rename_unchecked(&old, &old_req, &new, &new_req, actor) {
                Ok(()) => Ok(generic_ret(API_V2, 0)),
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e)))),
            }
        }
        CHPASS_PRINCIPAL | CHPASS_PRINCIPAL3 => {
            let (name, prealm, pass, keepold, ks) =
                match parse_ks(parse_chpass(args, proc == CHPASS_PRINCIPAL3)) {
                    Ok(v) => v,
                    Err(rep) => return rep,
                };
            let req = req_realm(&prealm, &realm);
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            let lockdown = match g.get_in_realm(&name, &req) {
                None => return Ok(generic_ret(API_V2, KADM5_UNK_PRINC)),
                Some(p) => p.attributes & KDB_LOCKDOWN_KEYS != 0,
            };
            if lockdown {
                return Ok(generic_ret(API_V2, KADM5_AUTH_CHANGEPW));
            }
            let self_change = is_self(actor, &name, &req);
            if !self_change
                && (changepw
                    || acl
                        .check(
                            actor,
                            krb5_kdc::AdminOp::ChangePassword,
                            Some(&acl_id(&name, &req)),
                        )
                        .is_err())
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_CHANGEPW));
            }
            if self_change && !initial {
                return Ok(generic_ret(API_V2, KADM5_AUTH_INITIAL));
            }
            if self_change && let Err(e) = g.check_min_life_in(&name, &req) {
                return Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e))));
            }
            let n = clamp_self_keepold(self_change, keepold);
            match g.set_password_etypes_keepold_n_in(&name, &req, pass.as_bytes(), n, actor, &ks) {
                Ok(()) => Ok(generic_ret(API_V2, 0)),
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e)))),
            }
        }
        CREATE_POLICY => {
            let (api, mut pol, mask) = parse_policy_arg(args)?;
            if changepw || acl.check(actor, krb5_kdc::AdminOp::Create, None).is_err() {
                return Ok(generic_ret(api, KADM5_AUTH_ADD));
            }
            if let Some(code) = policy_mask_err(mask, true) {
                return Ok(generic_ret(api, code));
            }
            if mask & KADM5_POLICY_ALLOWED_KEYSALTS != 0
                && let Some(code) = validate_allowed_keysalts(pol.allowed_keysalts.as_deref())
            {
                return Ok(generic_ret(api, code));
            }
            let mut g = match write_store(store, proc, api) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.policies().contains_key(&pol.name) {
                return Ok(generic_ret(api, KADM5_DUP));
            }
            if let Some(code) = policy_name_err(&pol.name) {
                return Ok(generic_ret(api, code));
            }
            if mask & KADM5_PW_MAX_LIFE == 0 {
                pol.pw_max_life = 0;
            }
            if mask & KADM5_PW_MIN_LIFE == 0 {
                pol.pw_min_life = 0;
            }
            if mask & KADM5_POLICY_ALLOWED_KEYSALTS == 0 {
                pol.allowed_keysalts = None;
            }
            if let Some(code) = policy_floor_err(&pol, mask) {
                return Ok(generic_ret(api, code));
            }
            apply_policy_floors(&mut pol, mask);
            g.put_policy(pol);
            Ok(generic_ret(api, 0))
        }
        DELETE_POLICY => {
            let (api, name) = parse_policy_name(args)?;
            if changepw || acl.check(actor, krb5_kdc::AdminOp::Delete, None).is_err() {
                return Ok(generic_ret(api, KADM5_AUTH_DELETE));
            }
            let mut g = match write_store(store, proc, api) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            match g.delete_policy(&name) {
                Ok(()) => Ok(generic_ret(api, 0)),
                Err(krb5_kdc::Error::NotFound) => Ok(generic_ret(api, KADM5_UNK_POLICY)),
                Err(e) => Ok(generic_ret(api, kadm5_code(proc, &Error::from(e)))),
            }
        }
        MODIFY_POLICY => {
            let (api, rec, mask) = parse_policy_arg(args)?;
            if changepw || acl.check(actor, krb5_kdc::AdminOp::Modify, None).is_err() {
                return Ok(generic_ret(api, KADM5_AUTH_MODIFY));
            }
            if let Some(code) = policy_name_err(&rec.name) {
                return Ok(generic_ret(api, code));
            }
            if let Some(code) = policy_mask_err(mask, false) {
                return Ok(generic_ret(api, code));
            }
            if mask & KADM5_POLICY_ALLOWED_KEYSALTS != 0
                && let Some(code) = validate_allowed_keysalts(rec.allowed_keysalts.as_deref())
            {
                return Ok(generic_ret(api, code));
            }
            let mut g = match write_store(store, proc, api) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            let Some(existing) = g.policies().get(&rec.name).cloned() else {
                return Ok(generic_ret(api, KADM5_UNK_POLICY));
            };
            let merged = merge_policy(existing, &rec, mask);
            if let Some(code) = policy_floor_err(&merged, mask) {
                return Ok(generic_ret(api, code));
            }
            g.put_policy(merged);
            Ok(generic_ret(api, 0))
        }
        GET_POLICY => {
            let (api, name) = parse_policy_name(args)?;
            let g = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let own_pol = parse_actor(actor)
                .and_then(|(n, _)| g.get_name(&n).and_then(|p| p.pw_policy.clone()));
            if (changepw || acl.check(actor, krb5_kdc::AdminOp::Inquire, None).is_err())
                && own_pol.as_deref() != Some(name.as_str())
            {
                return Ok(generic_ret(api, KADM5_AUTH_GET));
            }
            match g.policies().get(&name) {
                Some(p) => Ok(encode_policy(api, p)),
                None => Ok(generic_ret(api, KADM5_UNK_POLICY)),
            }
        }
        GET_POLS => {
            let (api, expr) = parse_gpols(args);
            if changepw || acl.check(actor, krb5_kdc::AdminOp::List, None).is_err() {
                return Ok(generic_ret(api, KADM5_AUTH_LIST));
            }
            let g = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut names: Vec<_> = g.policies().keys().cloned().collect();
            let glob = expr.as_deref().unwrap_or("*");
            if !glob_pattern_ok(glob) {
                return Ok(generic_ret(api, EINVAL));
            }
            if glob != "*" && !glob.is_empty() {
                let pat = glob_expand(glob, false);
                names.retain(|n| glob_is_match(pat.as_bytes(), n.as_bytes()));
            }
            names.sort();
            Ok(encode_pols(api, &names))
        }
        CHRAND_PRINCIPAL | CHRAND_PRINCIPAL3 => {
            let (name, prealm, keepold, ks) =
                match parse_ks(parse_chrand(args, proc == CHRAND_PRINCIPAL3)) {
                    Ok(v) => v,
                    Err(rep) => return rep,
                };
            let req = req_realm(&prealm, &realm);
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.get_in_realm(&name, &req).is_none() {
                return Ok(generic_ret(API_V2, KADM5_UNK_PRINC));
            }
            let self_change = is_self(actor, &name, &req);
            if changepw_not_self(changepw, actor, &name, &req)
                || (acl
                    .check(
                        actor,
                        krb5_kdc::AdminOp::ChangePassword,
                        Some(&acl_id(&name, &req)),
                    )
                    .is_err()
                    && !self_change)
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_CHANGEPW));
            }
            if self_change && !initial {
                return Ok(generic_ret(API_V2, KADM5_AUTH_INITIAL));
            }
            if self_change && let Err(e) = g.check_min_life_in(&name, &req) {
                return Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e))));
            }
            let n = clamp_self_keepold(self_change, keepold);
            match g.chrand_etypes_keepold_in(&name, &req, &ks, n, actor) {
                Ok(keys) => {
                    let hide = g
                        .get_in_realm(&name, &req)
                        .is_some_and(|p| p.attributes & KDB_LOCKDOWN_KEYS != 0);
                    Ok(encode_chrand(if hide { &[] } else { &keys }))
                }
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e)))),
            }
        }
        EXTRACT_KEYS => {
            let (api, name, prealm, kvno) = parse_extract(args)?;
            let req = req_realm(&prealm, &realm);
            let g = match write_store(store, proc, api) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            let Some(p) = g.get_in_realm(&name, &req) else {
                return Ok(generic_ret(api, KADM5_UNK_PRINC));
            };
            if changepw
                || acl
                    .check(
                        actor,
                        krb5_kdc::AdminOp::Extract,
                        Some(&acl_id(&name, &req)),
                    )
                    .is_err()
            {
                return Ok(generic_ret(api, KADM5_AUTH_EXTRACT));
            }
            if p.attributes & KDB_LOCKDOWN_KEYS != 0 {
                return Ok(generic_ret(api, KADM5_AUTH_EXTRACT));
            }
            tracing::info!(
                event = krb5_log::events::ADMIN,
                component = "krb5-admin",
                outcome = "ok",
                detail = "extract",
                principal = p.id(),
            );
            Ok(encode_extract_keys(api, p, kvno))
        }
        PURGEKEYS => {
            let (api, name, prealm, keepkvno) = parse_purgekeys(args)?;
            let req = req_realm(&prealm, &realm);
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.get_in_realm(&name, &req).is_none() {
                return Ok(generic_ret(api, KADM5_UNK_PRINC));
            }
            if changepw
                || (acl
                    .check(actor, krb5_kdc::AdminOp::Modify, Some(&acl_id(&name, &req)))
                    .is_err()
                    && !is_self(actor, &name, &req))
            {
                return Ok(generic_ret(api, KADM5_AUTH_MODIFY));
            }
            match g.purgekeys_in(&name, &req, keepkvno, actor) {
                Ok(()) => {
                    tracing::info!(
                        event = krb5_log::events::ADMIN,
                        component = "krb5-admin",
                        outcome = "ok",
                        detail = "purgekeys",
                    );
                    Ok(generic_ret(api, 0))
                }
                Err(e) => Ok(generic_ret(api, kadm5_code(proc, &Error::from(e)))),
            }
        }
        SETKEY_PRINCIPAL | SETKEY_PRINCIPAL3 | SETKEY_PRINCIPAL4 => {
            let (api, name, prealm, keys, keepold) = parse_setkey(args, proc)?;
            let req = req_realm(&prealm, &realm);
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.get_in_realm(&name, &req).is_none() {
                return Ok(generic_ret(api, KADM5_UNK_PRINC));
            }
            let lockdown = g
                .get_in_realm(&name, &req)
                .is_some_and(|p| p.attributes & KDB_LOCKDOWN_KEYS != 0);
            if lockdown {
                return Ok(generic_ret(api, KADM5_AUTH_SETKEY));
            }
            if changepw
                || acl
                    .check(actor, krb5_kdc::AdminOp::SetKey, Some(&acl_id(&name, &req)))
                    .is_err()
            {
                return Ok(generic_ret(api, KADM5_AUTH_SETKEY));
            }
            let n = clamp_self_keepold(is_self(actor, &name, &req), keepold);
            match g.set_keys_in(&name, &req, keys, n, actor) {
                Ok(()) => Ok(generic_ret(api, 0)),
                Err(e) => Ok(generic_ret(api, kadm5_code(proc, &Error::from(e)))),
            }
        }
        GET_STRINGS => {
            let (api, name, prealm) = parse_gstrings(args)?;
            let req = req_realm(&prealm, &realm);
            let g = match write_store(store, proc, api) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.get_in_realm(&name, &req).is_none() {
                return Ok(generic_ret(api, KADM5_UNK_PRINC));
            }
            if changepw
                || (acl
                    .check(
                        actor,
                        krb5_kdc::AdminOp::Inquire,
                        Some(&acl_id(&name, &req)),
                    )
                    .is_err()
                    && !is_self(actor, &name, &req))
            {
                return Ok(generic_ret(api, KADM5_AUTH_GET));
            }
            match g.get_strings_in(&name, &req) {
                Ok(attrs) => Ok(encode_gstrings(api, &attrs)),
                Err(e) => Ok(generic_ret(api, kadm5_code(proc, &Error::from(e)))),
            }
        }
        SET_STRING => {
            let (api, name, prealm, key, value) = parse_sstring(args)?;
            let req = req_realm(&prealm, &realm);
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            if g.get_in_realm(&name, &req).is_none() {
                return Ok(generic_ret(api, KADM5_UNK_PRINC));
            }
            if changepw
                || acl
                    .check(actor, krb5_kdc::AdminOp::Modify, Some(&acl_id(&name, &req)))
                    .is_err()
            {
                return Ok(generic_ret(api, KADM5_AUTH_MODIFY));
            }
            if key.is_empty() {
                return Ok(generic_ret(api, KADM5_FAILURE));
            }
            match g.set_string_in(&name, &req, &key, value.as_deref(), actor) {
                Ok(()) => Ok(generic_ret(api, 0)),
                Err(e) => Ok(generic_ret(api, kadm5_code(proc, &Error::from(e)))),
            }
        }
        CREATE_ALIAS => {
            let (alias, alias_realm, target, target_realm) = parse_alias(args)?;
            let alias_req = req_realm(&alias_realm, &realm);
            let target_req = req_realm(&target_realm, &realm);
            // server_stubs.c:1727-1758: CHANGEPW deny, acl_addalias, no lockdown check.
            if changepw
                || acl
                    .check_addalias(
                        actor,
                        &acl_id(&alias, &alias_req),
                        &acl_id(&target, &target_req),
                    )
                    .is_err()
            {
                return Ok(generic_ret(API_V2, KADM5_AUTH_INSUFFICIENT));
            }
            let mut g = match write_store(store, proc, API_V2) {
                Ok(g) => g,
                Err(rep) => return Ok(rep),
            };
            match g.create_alias_in(&alias, &alias_req, &target, &target_req, actor) {
                Ok(()) => Ok(generic_ret(API_V2, 0)),
                Err(e) => Ok(generic_ret(API_V2, kadm5_code(proc, &Error::from(e)))),
            }
        }
        _ => Err(Error::ProcUnavail),
    }
}

/// The `KADM5_AUTH_*` code a stub denies with (`server_stubs.c`, the
/// `ret->code = KADM5_AUTH_…` of each `*_2_svc`): ADD for the creates
/// (`:480,521,1268`), DELETE for the deletes (`:582,1311`), MODIFY for
/// modify/purgekeys/set_string/modify_policy (`:633,1515,1594,1352`),
/// INSUFFICIENT for rename and create_alias (`:702,1743`), GET for the gets
/// (`:772,1400,1553`), LIST for the lists (`:816,1445`), CHANGEPW for
/// chpass/chrand (`:860,915,1150,1210`), SETKEY for setkey (`:971,1023,1077`),
/// EXTRACT for get_principal_keys (`:1691`).
fn auth_code_for(proc: u32) -> u32 {
    match proc {
        CREATE_PRINCIPAL | CREATE_PRINCIPAL3 | CREATE_POLICY => KADM5_AUTH_ADD,
        DELETE_PRINCIPAL | DELETE_POLICY => KADM5_AUTH_DELETE,
        MODIFY_PRINCIPAL | MODIFY_POLICY | PURGEKEYS | SET_STRING => KADM5_AUTH_MODIFY,
        RENAME_PRINCIPAL | CREATE_ALIAS => KADM5_AUTH_INSUFFICIENT,
        GET_PRINCS | GET_POLS => KADM5_AUTH_LIST,
        CHPASS_PRINCIPAL | CHPASS_PRINCIPAL3 | CHRAND_PRINCIPAL | CHRAND_PRINCIPAL3 => {
            KADM5_AUTH_CHANGEPW
        }
        SETKEY_PRINCIPAL | SETKEY_PRINCIPAL3 | SETKEY_PRINCIPAL4 => KADM5_AUTH_SETKEY,
        EXTRACT_KEYS => KADM5_AUTH_EXTRACT,
        _ => KADM5_AUTH_GET,
    }
}

/// kadm5 return code for a store error surfacing from the `proc` stub. A
/// store-level `AclDenied` takes the stub's own `KADM5_AUTH_*` (no in-tree
/// store path returns it today — the ACL is checked inline in each arm —
/// so this is latent hygiene, `working/w1-sweep/plan-w1z-0913-1915.md` Z1b.3).
pub(super) fn kadm5_code(proc: u32, e: &Error) -> u32 {
    let s = match e {
        Error::AclDenied | Error::KpropUnauthorized(_) => return auth_code_for(proc),
        Error::NotFound => return KADM5_UNK_PRINC,
        Error::PassTooSoon { .. } => return KADM5_PASS_TOOSOON,
        Error::GarbageArgs | Error::ProcUnavail => return KADM5_FAILURE,
        Error::PasswordPolicy(s) | Error::Inner(s) => s.as_str(),
    };
    if s.starts_with("Unsupported argument") || s == "Invalid argument" {
        return EINVAL;
    }
    if s.contains("min_length") || s == krb5_kdc::PWQUAL_EMPTY {
        KADM5_PASS_Q_TOOSHORT
    } else if s.contains("min_classes") {
        KADM5_PASS_Q_CLASS
    } else if s == krb5_kdc::PWQUAL_DICT || s == krb5_kdc::PWQUAL_PRINC {
        KADM5_PASS_Q_DICT
    } else if s.contains("history") {
        KADM5_PASS_REUSE
    } else if s.contains("setkey kvno") {
        KADM5_SETKEY_BAD_KVNO
    } else if s == "Invalid key/salt tuples" {
        KADM5_BAD_KEYSALTS
    } else if s.contains("principal exists") {
        KADM5_DUP
    } else if s == "Alias target must be within the same realm" {
        KADM5_ALIAS_REALM
    } else if s == "Operation unsupported on alias principal name" {
        KRB5_KDB_ALIAS_UNSUPPORTED
    } else {
        KADM5_FAILURE
    }
}

pub(super) fn generic_ret(api: u32, code: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(api);
    w.u32(code);
    w.b
}
