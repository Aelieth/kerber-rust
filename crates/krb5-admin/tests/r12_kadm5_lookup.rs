//! MIT `stub_setup` GETs the principal before ACL or mask on modify.

mod common;

use common::{
    API_V2, GSS_INTEGRITY, SUCCESS, data_call, init_client, push_nullstring, push_u32, ret_code,
};
use krb5_kdc::{
    Acl, TEST_ADMIN, TEST_REALM, TEST_USER, bootstrap_documented, documented_admin_id,
    documented_kadmin, shared_dump,
};
use krb5_types::PrincipalName;

const MODIFY_PRINCIPAL: u32 = 3;
const KADM5_MAX_LIFE: u32 = 0x0000_0020;
const KADM5_POLICY: u32 = 0x0000_0800;
const KADM5_POLICY_CLR: u32 = 0x0000_1000;
const KADM5_AUTH_MODIFY: u32 = 43_787_523;
const KADM5_BAD_MASK: u32 = 43_787_534;
const KADM5_UNK_PRINC: u32 = 43_787_532;

fn modify_args(princ: &str, max_life: u32, mask: u32) -> Vec<u8> {
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
    let mut c = init_client(&store, &acl, &ro, &documented_kadmin(), GSS_INTEGRITY);
    let args = modify_args(&format!("nosuch@{TEST_REALM}"), 60, KADM5_MAX_LIFE);
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
        &documented_kadmin(),
        GSS_INTEGRITY,
    );
    let args = modify_args(
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
        &documented_kadmin(),
        GSS_INTEGRITY,
    );
    let args = modify_args(&format!("nosuch@{TEST_REALM}"), 60, KADM5_MAX_LIFE);
    let (stat, body) = data_call(&mut c, &store, &none, MODIFY_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_UNK_PRINC);
    assert_ne!(ret_code(&body), KADM5_AUTH_MODIFY);
}
