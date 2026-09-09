//! R9 green-only: create reserved TL (already at Round 2 parent) + dump TL width.

mod common;

use common::{
    API_V2, GSS_INTEGRITY, SUCCESS, data_call, init_client, push_nullstring, push_opaque, push_u32,
    ret_code,
};
use krb5_kdc::{
    Acl, PrincipalRead, TEST_ADMIN, TEST_REALM, bootstrap_documented, documented_kadmin,
    shared_dump,
};
use krb5_types::PrincipalName;

const CREATE_PRINCIPAL: u32 = 1;
const KADM5_TL_DATA: u32 = 0x0004_0000;
const KADM5_PRINCIPAL: u32 = 0x0000_0001;
const KADM5_BAD_TL_TYPE: u32 = 43_787_567;

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
    push_u32(&mut w, 0);
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
    push_u32(&mut w, 0);
    push_u32(&mut w, mask);
    push_nullstring(&mut w, "password");
    w
}

#[test]
fn create_reserved_tl_does_not_write() {
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
        &format!("r9tlbad@{TEST_REALM}"),
        Some((3, b"x")),
        KADM5_PRINCIPAL | KADM5_TL_DATA,
    );
    let (stat, body) = data_call(&mut c, &store, &acl, CREATE_PRINCIPAL, &args);
    assert_eq!(stat, SUCCESS);
    assert_eq!(ret_code(&body), KADM5_BAD_TL_TYPE);
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        g.get_name(&PrincipalName::new(
            PrincipalName::NT_PRINCIPAL,
            ["r9tlbad"]
        ))
        .is_none()
    );
}

#[test]
fn documented_dump_has_no_tl_type_ge_0x10000() {
    let (store, _) = bootstrap_documented().unwrap();
    for p in store.list_principals().unwrap() {
        assert!(
            !p.tl_data.iter().any(|t| t.ty >= 0x1_0000),
            "{:?} has TL type >= 0x10000",
            p.name
        );
    }
}
