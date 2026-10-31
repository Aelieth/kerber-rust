//! kadmind's `CREATE_ALIAS` (proc 27) refuses the changepw service, and proc 28 is not served.
// MIT: `create_alias_2_svc` (kadmin/server/server_stubs.c:1727-1758)

#[path = "common/mod.rs"]
mod common;
use common::*;

use krb5_kdc::principals::{kadmin_admin, kadmin_changepw};
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented};
use krb5_kdc::{Acl, shared_dump};

use krb5_types::PrincipalName;

const CREATE_ALIAS: u32 = 27;

const KADM5_AUTH_INSUFFICIENT: u32 = 43_787_525;

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

fn t_kadmin_acl() -> (krb5_kdc::SharedDump, Acl) {
    let (mut store, _) = bootstrap_documented().unwrap();
    for p in ["some_alias", "restricted_alias", "none"] {
        store
            .insert_new_password(&name(p), TEST_REALM, b"pw", &[], "kadmin/admin@KERBER.TEST")
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
fn changepw_service_denies_create_alias() {
    let (store, acl) = t_kadmin_acl();
    let mut c = init_client(
        &store,
        &acl,
        &name("admin"),
        &kadmin_changepw(),
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
        &kadmin_admin(),
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
