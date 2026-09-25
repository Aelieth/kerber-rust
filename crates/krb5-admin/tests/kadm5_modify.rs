//! `kadm5_modify_principal` validates TL type and fail_auth_count before
//! the store write (`svr_principal.c:581-588,671-675`).
//! `KADM5_BAD_MASK`, int16 TL types, create-path TL guard
//! (`svr_principal.c:310-326,565-580`, `kadm_rpc_xdr.c:349`).
//! ACL before mask on an existing principal; `KEY_DATA`+`n_key_data`;
//! `0x7fff` is EINVAL 22. Lookup-before-ACL is the GET-before-ACL tests below.
//! MIT `stub_setup` GETs the principal before ACL or mask on modify.
//! kadm5 modify honours `KADM5_MAX_RLIFE` (`svr_principal.c:642-643`).
//! `get_principal` unparses `mod_name` from `KRB5_TL_MOD_PRINC`
//! (`kadmin.c:1476`, `kdb5.c:1637-1663`). Compiles at the parent: CREATE
//! and GET already exist; the parent hard-codes `kadmin/admin@REALM` on
//! the wire regardless of the GSS client.

#[path = "common/mod.rs"]
mod common;
use common::*;

use krb5_kdc::principals::kadmin_admin;
use krb5_kdc::testrealm::{
    TEST_ADMIN, TEST_REALM, TEST_USER, bootstrap_documented, documented_admin_id,
};
use krb5_kdc::{Acl, load_store, save_store, shared_dump};

use krb5_testkit::scratch_dir;
use krb5_types::PrincipalName;

const MODIFY_PRINCIPAL: u32 = 3;

const KADM5_MAX_LIFE: u32 = 0x0000_0020;

const KADM5_FAIL_AUTH_COUNT: u32 = 0x0001_0000;

const KADM5_TL_DATA: u32 = 0x0004_0000;

const KADM5_BAD_SERVER_PARAMS: u32 = 43_787_563;

const KADM5_BAD_TL_TYPE: u32 = 43_787_567;

fn modify_args(
    princ: &str,
    max_life: u32,
    fail_auth_count: u32,
    tl: Option<(i32, &[u8])>,
    mask: u32,
) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, princ);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, max_life);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    for _ in 0..4 {
        push_u32(&mut w, 0);
    }
    push_u32(&mut w, fail_auth_count);
    push_u32(&mut w, 0);
    push_u32(&mut w, u32::from(tl.is_some()));
    if let Some((ty, contents)) = tl {
        push_u32(&mut w, 0);
        push_u32(&mut w, 1);
        push_u32(&mut w, u32::try_from(ty).unwrap());
        push_opaque(&mut w, contents);
        push_u32(&mut w, 0);
    } else {
        push_u32(&mut w, 1);
    }
    push_u32(&mut w, 0);
    push_u32(&mut w, mask);
    w
}

#[test]
fn modify_nonzero_failcount_does_not_write() {
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let orig_life = store.get_name(&user).unwrap().max_life;
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(
        &store,
        &acl,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]),
        &kadmin_admin(),
        GSS_INTEGRITY,
    );
    let want_life = u32::try_from(orig_life.saturating_add(60)).unwrap_or(60);
    let args = modify_args(
        &format!("{TEST_USER}@{TEST_REALM}"),
        want_life,
        1,
        None,
        KADM5_MAX_LIFE | KADM5_FAIL_AUTH_COUNT,
    );
    let (stat, body) = data_call(&mut c, &store, &acl, MODIFY_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_BAD_SERVER_PARAMS);
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let p = g.get_name(&user).unwrap();
    assert_eq!(p.max_life, orig_life);
    assert_eq!(p.fail_auth_count, 0);
}

#[test]
fn modify_reserved_tl_type_does_not_write() {
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let orig_life = store.get_name(&user).unwrap().max_life;
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(
        &store,
        &acl,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]),
        &kadmin_admin(),
        GSS_INTEGRITY,
    );
    let want_life = u32::try_from(orig_life.saturating_add(60)).unwrap_or(60);
    let args = modify_args(
        &format!("{TEST_USER}@{TEST_REALM}"),
        want_life,
        0,
        Some((3, b"osa")),
        KADM5_MAX_LIFE | KADM5_TL_DATA,
    );
    let (stat, body) = data_call(&mut c, &store, &acl, MODIFY_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_BAD_TL_TYPE);
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let p = g.get_name(&user).unwrap();
    assert_eq!(p.max_life, orig_life);
    assert!(!p.tl_data.iter().any(|t| t.ty == 3));
}

const CREATE_PRINCIPAL: u32 = 1;

const KADM5_POLICY: u32 = 0x0000_0800;

const KADM5_POLICY_CLR: u32 = 0x0000_1000;

const KADM5_PRINCIPAL: u32 = 0x0000_0001;

const KADM5_BAD_MASK: u32 = 43_787_534;

fn modify_args_r9_kadm5_validate(
    princ: &str,
    max_life: u32,
    fail_auth_count: u32,
    tl: Option<(u32, &[u8])>,
    mask: u32,
) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, princ);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, max_life);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    for _ in 0..4 {
        push_u32(&mut w, 0);
    }
    push_u32(&mut w, fail_auth_count);
    push_u32(&mut w, 0);
    push_u32(&mut w, u32::from(tl.is_some()));
    if let Some((ty, contents)) = tl {
        push_u32(&mut w, 0);
        push_u32(&mut w, 1);
        push_u32(&mut w, ty);
        push_opaque(&mut w, contents);
        push_u32(&mut w, 0);
    } else {
        push_u32(&mut w, 1);
    }
    push_u32(&mut w, 0);
    push_u32(&mut w, mask);
    w
}

#[test]
fn modify_policy_and_policy_clr_is_bad_mask() {
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let orig_life = store.get_name(&user).unwrap().max_life;
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(
        &store,
        &acl,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]),
        &kadmin_admin(),
        GSS_INTEGRITY,
    );
    let args = modify_args_r9_kadm5_validate(
        &format!("{TEST_USER}@{TEST_REALM}"),
        60,
        0,
        None,
        KADM5_MAX_LIFE | KADM5_POLICY | KADM5_POLICY_CLR,
    );
    let (stat, body) = data_call(&mut c, &store, &acl, MODIFY_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_BAD_MASK);
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(g.get_name(&user).unwrap().max_life, orig_life);
}

#[test]
fn modify_tl_type_0x10003_is_bad_tl_type() {
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let orig_life = store.get_name(&user).unwrap().max_life;
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(
        &store,
        &acl,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]),
        &kadmin_admin(),
        GSS_INTEGRITY,
    );
    let args = modify_args_r9_kadm5_validate(
        &format!("{TEST_USER}@{TEST_REALM}"),
        60,
        0,
        Some((0x0001_0003, b"x")),
        KADM5_MAX_LIFE | KADM5_TL_DATA,
    );
    let (stat, body) = data_call(&mut c, &store, &acl, MODIFY_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_BAD_TL_TYPE);
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let p = g.get_name(&user).unwrap();
    assert_eq!(p.max_life, orig_life);
    assert!(!p.tl_data.iter().any(|t| t.ty == 3 || t.ty == 0x0001_0003));
}

#[test]
fn create_fail_auth_count_mask_is_bad_mask() {
    let (store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(
        &store,
        &acl,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]),
        &kadmin_admin(),
        GSS_INTEGRITY,
    );
    let name = format!("r9create@{TEST_REALM}");
    // Layout matches kadm5/tests/mod.rs create_rec; mask = PRINCIPAL|FAIL_AUTH_COUNT.
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, &name);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 3600);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 1);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, KADM5_PRINCIPAL | KADM5_FAIL_AUTH_COUNT);
    push_nullstring(&mut w, "password");
    let (stat, body) = data_call(&mut c, &store, &acl, CREATE_PRINCIPAL, &w);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_BAD_MASK);
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        g.get_name(&PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            ["r9create"]
        ))
        .is_none()
    );
}

fn create_args(name: &str, tl: Option<(u32, &[u8])>, mask: u32) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, name);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 3600);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 1);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    // n_key_data
    push_u32(&mut w, 0);
    // n_tl_data + optional linked list (`skip_principal_ent_rest`)
    if let Some((ty, contents)) = tl {
        push_u32(&mut w, 1);
        push_u32(&mut w, 0);
        push_u32(&mut w, 1);
        push_u32(&mut w, ty);
        push_opaque(&mut w, contents);
        push_u32(&mut w, 0);
    } else {
        push_u32(&mut w, 0);
        push_u32(&mut w, 1);
    }
    // key_data array length
    push_u32(&mut w, 0);
    push_u32(&mut w, mask);
    push_nullstring(&mut w, "password");
    w
}

#[test]
fn create_tl_type_0x10003_is_bad_tl_type() {
    let (store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(
        &store,
        &acl,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]),
        &kadmin_admin(),
        GSS_INTEGRITY,
    );
    let args = create_args(
        &format!("r9tlhi@{TEST_REALM}"),
        Some((0x0001_0003, b"x")),
        KADM5_PRINCIPAL | KADM5_TL_DATA,
    );
    let (stat, body) = data_call(&mut c, &store, &acl, CREATE_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_BAD_TL_TYPE);
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        g.get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["r9tlhi"]))
            .is_none()
    );
}

#[test]
fn modify_policy_clr_with_policy_name_is_bad_mask() {
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let orig_life = store.get_name(&user).unwrap().max_life;
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(
        &store,
        &acl,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]),
        &kadmin_admin(),
        GSS_INTEGRITY,
    );
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, &format!("{TEST_USER}@{TEST_REALM}"));
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 60);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_nullstring(&mut w, "default");
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, KADM5_MAX_LIFE | KADM5_POLICY | KADM5_POLICY_CLR);
    let (stat, body) = data_call(&mut c, &store, &acl, MODIFY_PRINCIPAL, &w);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_BAD_MASK, "body code");
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(g.get_name(&user).unwrap().max_life, orig_life);
}

const KADM5_KEY_DATA: u32 = 0x0002_0000;

const KADM5_AUTH_MODIFY: u32 = 43_787_523;

const KADM5_UNK_PRINC: u32 = 43_787_532;

const EINVAL: u32 = 22;

fn modify_args_r12_kadm5_order(
    princ: &str,
    max_life: u32,
    tls: &[(u32, &[u8])],
    mask: u32,
) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, princ);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, max_life);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    for _ in 0..4 {
        push_u32(&mut w, 0);
    }
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, u32::from(!tls.is_empty()));
    if tls.is_empty() {
        push_u32(&mut w, 1);
    } else {
        push_u32(&mut w, 0);
        for (ty, contents) in tls {
            push_u32(&mut w, 1);
            push_u32(&mut w, *ty);
            push_opaque(&mut w, contents);
        }
        push_u32(&mut w, 0);
    }
    push_u32(&mut w, 0);
    push_u32(&mut w, mask);
    w
}

fn admin_client(store: &krb5_kdc::SharedDump, acl: &Acl) -> common::Client {
    init_client(
        store,
        acl,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]),
        &kadmin_admin(),
        GSS_INTEGRITY,
    )
}

#[test]
fn modify_one_db_args_is_einval_and_unchanged() {
    let dir = scratch_dir("krb5-r12-kadm5");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, _) = bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    let store = load_store(&db, &stash).unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let orig = store.get_name(&user).unwrap().clone();
    let file_before = std::fs::read(&db).unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = admin_client(&store, &acl);
    let args = modify_args_r12_kadm5_order(
        &format!("{TEST_USER}@{TEST_REALM}"),
        60,
        &[(0x7fff, b"foo=bar\0")],
        KADM5_MAX_LIFE | KADM5_TL_DATA,
    );
    let (stat, body) = data_call(&mut c, &store, &acl, MODIFY_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), EINVAL);
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let p = g.get_name(&user).unwrap();
    assert_eq!(p.attributes, orig.attributes);
    assert_eq!(p.max_life, orig.max_life);
    assert_eq!(p.tl_data, orig.tl_data);
    assert_eq!(std::fs::read(&db).unwrap(), file_before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn modify_three_db_args_is_einval() {
    let (store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = admin_client(&store, &acl);
    let args = modify_args_r12_kadm5_order(
        &format!("{TEST_USER}@{TEST_REALM}"),
        60,
        &[
            (0x7fff, b"foo=bar\0"),
            (0x7fff, b"foo=bar\0"),
            (0x7fff, b"foo=bar\0"),
        ],
        KADM5_MAX_LIFE | KADM5_TL_DATA,
    );
    let (stat, body) = data_call(&mut c, &store, &acl, MODIFY_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), EINVAL);
}

#[test]
fn modify_db_args_without_nul_is_einval() {
    let (store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = admin_client(&store, &acl);
    let args = modify_args_r12_kadm5_order(
        &format!("{TEST_USER}@{TEST_REALM}"),
        60,
        &[(0x7fff, b"foo=bar")],
        KADM5_MAX_LIFE | KADM5_TL_DATA,
    );
    let (stat, body) = data_call(&mut c, &store, &acl, MODIFY_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), EINVAL);
}

#[test]
fn ro_policy_and_policy_clr_is_auth_modify() {
    let (mut store, admin_acl) = bootstrap_documented().unwrap();
    let ro = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["ro"]);
    store
        .create_password(&admin_acl, &documented_admin_id(), &ro, b"ro-secret")
        .unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\nro@KERBER.TEST i\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(&store, &acl, &ro, &kadmin_admin(), GSS_INTEGRITY);
    let args = modify_args_r12_kadm5_order(
        &format!("{TEST_USER}@{TEST_REALM}"),
        60,
        &[],
        KADM5_POLICY | KADM5_POLICY_CLR,
    );
    let (stat, body) = data_call(&mut c, &store, &acl, MODIFY_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_AUTH_MODIFY);
    assert_ne!(ret_code(&body), KADM5_BAD_MASK);
    let mut admin = admin_client(&store, &acl);
    let unk = modify_args_r12_kadm5_order(&format!("nosuch@{TEST_REALM}"), 60, &[], KADM5_MAX_LIFE);
    let (stat, body) = data_call(&mut admin, &store, &acl, MODIFY_PRINCIPAL, &unk);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_UNK_PRINC);
}

#[test]
fn create_key_data_mask_with_one_key_is_bad_mask() {
    let (store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = admin_client(&store, &acl);
    let name = format!("r12key@{TEST_REALM}");
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, &name);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 3600);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 1);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, 1);
    push_u32(&mut w, 1);
    push_u32(&mut w, 1);
    push_u32(&mut w, 1);
    push_u32(&mut w, 18);
    push_u32(&mut w, KADM5_PRINCIPAL | KADM5_KEY_DATA);
    push_nullstring(&mut w, "password");
    let (stat, body) = data_call(&mut c, &store, &acl, CREATE_PRINCIPAL, &w);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_BAD_MASK);
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        g.get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["r12key"]))
            .is_none()
    );
}

fn modify_args_r12_kadm5_lookup(princ: &str, max_life: u32, mask: u32) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, princ);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, max_life);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    for _ in 0..4 {
        push_u32(&mut w, 0);
    }
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 0);
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, mask);
    w
}

#[test]
fn ro_modify_nosuch_is_unk_princ() {
    let (mut store, admin_acl) = bootstrap_documented().unwrap();
    let ro = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["ro"]);
    store
        .create_password(&admin_acl, &documented_admin_id(), &ro, b"ro-secret")
        .unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\nro@KERBER.TEST i\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(&store, &acl, &ro, &kadmin_admin(), GSS_INTEGRITY);
    let args = modify_args_r12_kadm5_lookup(&format!("nosuch@{TEST_REALM}"), 60, KADM5_MAX_LIFE);
    let (stat, body) = data_call(&mut c, &store, &acl, MODIFY_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_UNK_PRINC);
    assert_ne!(ret_code(&body), KADM5_AUTH_MODIFY);
}

#[test]
fn admin_bad_mask_on_nosuch_is_unk_princ() {
    let (store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(
        &store,
        &acl,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]),
        &kadmin_admin(),
        GSS_INTEGRITY,
    );
    let args = modify_args_r12_kadm5_lookup(
        &format!("nosuch@{TEST_REALM}"),
        60,
        KADM5_POLICY | KADM5_POLICY_CLR,
    );
    let (stat, body) = data_call(&mut c, &store, &acl, MODIFY_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_UNK_PRINC);
    assert_ne!(ret_code(&body), KADM5_BAD_MASK);
}

#[test]
fn stub_setup_unk_before_acl_on_modify() {
    let (store, _) = bootstrap_documented().unwrap();
    let none = Acl::parse("nobody@KERBER.TEST a\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(
        &store,
        &none,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]),
        &kadmin_admin(),
        GSS_INTEGRITY,
    );
    let args = modify_args_r12_kadm5_lookup(&format!("nosuch@{TEST_REALM}"), 60, KADM5_MAX_LIFE);
    let (stat, body) = data_call(&mut c, &store, &none, MODIFY_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_UNK_PRINC);
    assert_ne!(ret_code(&body), KADM5_AUTH_MODIFY);
}

const KADM5_MAX_RLIFE: u32 = 0x0000_2000;

fn modify_rlife_args(princ: &str, max_rlife: u32, mask: u32) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, princ);
    for _ in 0..4 {
        push_u32(&mut w, 0);
    }
    push_u32(&mut w, 1);
    for _ in 0..5 {
        push_u32(&mut w, 0);
    }
    push_u32(&mut w, 0);
    push_u32(&mut w, max_rlife);
    for _ in 0..5 {
        push_u32(&mut w, 0);
    }
    push_u32(&mut w, 1);
    push_u32(&mut w, 0);
    push_u32(&mut w, mask);
    w
}

#[test]
fn kadm5_modify_sets_max_rlife() {
    let (store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut c = init_client(
        &store,
        &acl,
        &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]),
        &kadmin_admin(),
        GSS_INTEGRITY,
    );
    let args = modify_rlife_args(
        &format!("{TEST_USER}@{TEST_REALM}"),
        86_400,
        KADM5_MAX_RLIFE,
    );
    let (stat, body) = data_call(&mut c, &store, &acl, MODIFY_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), 0);
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(g.get_name(&user).unwrap().max_renewable_life, 86_400);
}

const GET_PRINCIPAL: u32 = 5;

fn n(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

fn push_create(name: &str, password: &str) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, name);
    push_u32(&mut w, 0); // expire
    push_u32(&mut w, 0); // last_pwd
    push_u32(&mut w, 0); // pw_expire
    push_u32(&mut w, 0); // max_life
    push_u32(&mut w, 1); // mod_name NULL
    push_u32(&mut w, 0); // mod_date
    push_u32(&mut w, 0); // attributes
    push_u32(&mut w, 0); // kvno
    push_u32(&mut w, 0); // mkvno
    push_u32(&mut w, 0); // policy NULL
    push_u32(&mut w, 0); // aux
    push_u32(&mut w, 0); // max_rlife
    push_u32(&mut w, 0); // last_success
    push_u32(&mut w, 0); // last_failed
    push_u32(&mut w, 0); // fail_auth_count
    push_u32(&mut w, 0); // n_key_data
    push_u32(&mut w, 0); // n_tl_data
    push_u32(&mut w, 1); // tl_data NULL
    push_u32(&mut w, 0); // key_data
    push_u32(&mut w, KADM5_PRINCIPAL);
    push_nullstring(&mut w, password);
    w
}

fn get_args(name: &str) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, name);
    push_u32(&mut w, u32::MAX);
    w
}

fn take_nullstring(b: &[u8], i: &mut usize) -> Option<String> {
    let raw = take_opaque(b, i);
    if raw.is_empty() {
        return None;
    }
    let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    Some(String::from_utf8_lossy(&raw[..end]).into_owned())
}

fn gprinc_mod_name(body: &[u8]) -> String {
    let mut i = 0;
    assert_eq!(take_u32(body, &mut i), API_V2);
    assert_eq!(take_u32(body, &mut i), 0);
    let _princ = take_nullstring(body, &mut i);
    let _ = take_u32(body, &mut i);
    let _ = take_u32(body, &mut i);
    let _ = take_u32(body, &mut i);
    let _ = take_u32(body, &mut i);
    assert_eq!(take_u32(body, &mut i), 0, "mod_name present");
    take_nullstring(body, &mut i).expect("mod_name")
}

#[test]
fn getprinc_mod_name_is_the_rpc_caller() {
    let (store, _) = bootstrap_documented().unwrap();
    let acl = Acl::parse("admin@KERBER.TEST *\n").unwrap();
    let store = shared_dump(store);
    let mut client = init_client(&store, &acl, &n(TEST_ADMIN), &kadmin_admin(), GSS_INTEGRITY);
    let (stat, body) = data_call(
        &mut client,
        &store,
        &acl,
        CREATE_PRINCIPAL,
        &push_create("z64g@KERBER.TEST", "z64-secret"),
    );
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), 0);
    let (stat, body) = data_call(
        &mut client,
        &store,
        &acl,
        GET_PRINCIPAL,
        &get_args("z64g@KERBER.TEST"),
    );
    assert_eq!(stat, SUCCESS);
    let want = format!("{TEST_ADMIN}@{TEST_REALM}");
    let got = gprinc_mod_name(&body);
    assert_eq!(
        got, want,
        "getprinc mod_name is the GSS client, not the kadmind acceptor"
    );
}
