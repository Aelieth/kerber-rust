//! `kadm5_modify_principal` validates TL type and fail_auth_count before
//! the store write (`svr_principal.c:581-588,671-675`).

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
        &documented_kadmin(),
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
        &documented_kadmin(),
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
