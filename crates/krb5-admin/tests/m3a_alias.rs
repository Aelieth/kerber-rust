//! kadmind `CREATE_ALIAS` (proc 27) like `create_alias_2_svc`
//! (`server_stubs.c:1727-1758`) over `acl_addalias` (`auth_acl.c:723-734`),
//! with the ACL matrix of MIT `tests/t_kadmin_acl.py` and the codes settled in
//! `working/logs/audit-polish-0902/w1k/m3a-settle-mit-alias.log` §D.

mod common;

use common::{
    API_V2, GSS_INTEGRITY, PROC_UNAVAIL, SUCCESS, data_call, init_client, push_nullstring,
    push_u32, ret_code, take_opaque, take_u32,
};
use krb5_kdc::{
    Acl, TEST_REALM, TEST_USER, bootstrap_documented, documented_changepw, documented_host,
    documented_kadmin, shared_dump,
};
use krb5_types::PrincipalName;

const CREATE_ALIAS: u32 = 27;
const RENAME_PRINCIPAL: u32 = 4;
const GET_PRINCIPAL: u32 = 5;
const KADM5_AUTH_INSUFFICIENT: u32 = 43_787_525;
const KADM5_DUP: u32 = 43_787_527;
const KADM5_ALIAS_REALM: u32 = 43_787_583;
const KRB5_KDB_ALIAS_UNSUPPORTED: u32 = 2_514_958_894;

fn name(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

fn alias_args(alias: &str, target: &str) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, alias);
    push_nullstring(&mut w, target);
    w
}

fn get_args(princ: &str) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_nullstring(&mut w, princ);
    push_u32(&mut w, u32::MAX);
    w
}

fn t_kadmin_acl() -> (krb5_kdc::SharedDump, Acl) {
    let (mut store, _) = bootstrap_documented().unwrap();
    for p in ["some_alias", "restricted_alias", "none"] {
        store
            .insert_new_password(&name(p), TEST_REALM, b"pw", &[])
            .unwrap();
    }
    let acl = Acl::parse(
        "admin@KERBER.TEST *\n\
         some_alias@KERBER.TEST a aliasname@KERBER.TEST\n\
         some_alias@KERBER.TEST m user@KERBER.TEST\n\
         restricted_alias@KERBER.TEST ai *@KERBER.TEST +requires_preauth\n",
    )
    .unwrap();
    (shared_dump(store), acl)
}

#[test]
fn create_alias_then_getprinc_returns_the_target() {
    let (store, acl) = t_kadmin_acl();
    let mut c = init_client(
        &store,
        &acl,
        &name("admin"),
        &documented_kadmin(),
        GSS_INTEGRITY,
    );
    let (stat, body) = data_call(
        &mut c,
        &store,
        &acl,
        CREATE_ALIAS,
        &alias_args("a1@KERBER.TEST", "user@KERBER.TEST"),
    );
    assert_eq!((stat, ret_code(&body)), (SUCCESS, 0));
    let (stat, body) = data_call(
        &mut c,
        &store,
        &acl,
        GET_PRINCIPAL,
        &get_args("a1@KERBER.TEST"),
    );
    assert_eq!((stat, ret_code(&body)), (SUCCESS, 0));
    let mut i = 8;
    assert_eq!(take_opaque(&body, &mut i), b"user@KERBER.TEST\0");
    let (_, body) = data_call(
        &mut c,
        &store,
        &acl,
        CREATE_ALIAS,
        &alias_args("a1@KERBER.TEST", "user@KERBER.TEST"),
    );
    assert_eq!(ret_code(&body), KADM5_DUP);
    let (_, body) = data_call(
        &mut c,
        &store,
        &acl,
        CREATE_ALIAS,
        &alias_args("x@KERBER.TEST", "y@OTHER.REALM"),
    );
    assert_eq!(ret_code(&body), KADM5_ALIAS_REALM);
    let mut ren = Vec::new();
    push_u32(&mut ren, API_V2);
    push_nullstring(&mut ren, "a1@KERBER.TEST");
    push_nullstring(&mut ren, "b1@KERBER.TEST");
    let (_, body) = data_call(&mut c, &store, &acl, RENAME_PRINCIPAL, &ren);
    assert_eq!(ret_code(&body), KRB5_KDB_ALIAS_UNSUPPORTED);
    let g = store.read().unwrap();
    assert_eq!(
        g.get_raw("a1@KERBER.TEST")
            .unwrap()
            .alias_target()
            .as_deref(),
        Some("user@KERBER.TEST")
    );
    assert!(g.get_raw("x@KERBER.TEST").is_none());
}

#[test]
fn acl_addalias_needs_unrestricted_add_on_alias_and_modify_on_target() {
    let (store, acl) = t_kadmin_acl();
    let cases: [(&str, &str, &str, u32); 5] = [
        ("some_alias", "aliasname@KERBER.TEST", "user@KERBER.TEST", 0),
        (
            "some_alias",
            "other@KERBER.TEST",
            "user@KERBER.TEST",
            KADM5_AUTH_INSUFFICIENT,
        ),
        (
            "some_alias",
            "aliasname2@KERBER.TEST",
            &format!("{}@KERBER.TEST", documented_host().unparse()),
            KADM5_AUTH_INSUFFICIENT,
        ),
        (
            "restricted_alias",
            "r1@KERBER.TEST",
            "user@KERBER.TEST",
            KADM5_AUTH_INSUFFICIENT,
        ),
        (
            "none",
            "n1@KERBER.TEST",
            "user@KERBER.TEST",
            KADM5_AUTH_INSUFFICIENT,
        ),
    ];
    for (actor, alias, target, want) in cases {
        let mut c = init_client(
            &store,
            &acl,
            &name(actor),
            &documented_kadmin(),
            GSS_INTEGRITY,
        );
        let (stat, body) = data_call(
            &mut c,
            &store,
            &acl,
            CREATE_ALIAS,
            &alias_args(alias, target),
        );
        assert_eq!(stat, SUCCESS);
        assert_eq!(ret_code(&body), want, "{actor}: {alias} -> {target}");
        let exists = store.read().unwrap().get_raw(alias).is_some();
        assert_eq!(exists, want == 0, "{actor}: {alias}");
    }
}

#[test]
fn changepw_service_denies_create_alias() {
    let (store, acl) = t_kadmin_acl();
    let mut c = init_client(
        &store,
        &acl,
        &name("admin"),
        &documented_changepw(),
        GSS_INTEGRITY,
    );
    let (stat, body) = data_call(
        &mut c,
        &store,
        &acl,
        CREATE_ALIAS,
        &alias_args("cp1@KERBER.TEST", "user@KERBER.TEST"),
    );
    assert_eq!((stat, ret_code(&body)), (SUCCESS, KADM5_AUTH_INSUFFICIENT));
    assert!(store.read().unwrap().get_raw("cp1@KERBER.TEST").is_none());
}

#[test]
fn proc_28_is_still_proc_unavail() {
    let (store, acl) = t_kadmin_acl();
    let mut c = init_client(
        &store,
        &acl,
        &name(TEST_USER),
        &documented_kadmin(),
        GSS_INTEGRITY,
    );
    let (stat, _) = data_call(
        &mut c,
        &store,
        &acl,
        28,
        &alias_args("z@KERBER.TEST", "user@KERBER.TEST"),
    );
    assert_eq!(stat, PROC_UNAVAIL);
    let _ = take_u32;
}
