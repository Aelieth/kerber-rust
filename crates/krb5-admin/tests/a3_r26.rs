//! A′-3 R26: kadm5 modify honours `KADM5_MAX_RLIFE` (`svr_principal.c:642-643`).

mod common;

use common::{
    API_V2, GSS_INTEGRITY, SUCCESS, data_call, init_client, push_nullstring, push_u32, ret_code,
};
use krb5_kdc::{
    Acl, TEST_ADMIN, TEST_REALM, TEST_USER, bootstrap_documented, documented_kadmin, shared_dump,
};
use krb5_types::PrincipalName;

const MODIFY_PRINCIPAL: u32 = 3;
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
        &documented_kadmin(),
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
