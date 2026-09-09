//! R9: `KADM5_BAD_MASK`, int16 TL types, create-path TL guard
//! (`svr_principal.c:310-326,565-580`, `kadm_rpc_xdr.c:349`).

mod common;

use common::{
    API_V2, GSS_INTEGRITY, SUCCESS, data_call, init_client, push_nullstring, push_opaque, push_u32,
    ret_code,
};
use krb5_kdc::{
    Acl, TEST_ADMIN, TEST_REALM, TEST_USER, bootstrap_documented, documented_kadmin, shared_dump,
};
use krb5_types::PrincipalName;

const MODIFY_PRINCIPAL: u32 = 3;
const CREATE_PRINCIPAL: u32 = 1;
const KADM5_MAX_LIFE: u32 = 0x0000_0020;
const KADM5_TL_DATA: u32 = 0x0004_0000;
const KADM5_POLICY: u32 = 0x0000_0800;
const KADM5_POLICY_CLR: u32 = 0x0000_1000;
const KADM5_FAIL_AUTH_COUNT: u32 = 0x0001_0000;
const KADM5_PRINCIPAL: u32 = 0x0000_0001;
const KADM5_BAD_MASK: u32 = 43_787_534;
const KADM5_BAD_TL_TYPE: u32 = 43_787_567;

fn modify_args(
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
        &documented_kadmin(),
        GSS_INTEGRITY,
    );
    let args = modify_args(
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
        &documented_kadmin(),
        GSS_INTEGRITY,
    );
    let args = modify_args(
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
        &documented_kadmin(),
        GSS_INTEGRITY,
    );
    let name = format!("r9create@{TEST_REALM}");
    // Layout matches kadm5.rs create_rec; mask = PRINCIPAL|FAIL_AUTH_COUNT.
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
        &documented_kadmin(),
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
