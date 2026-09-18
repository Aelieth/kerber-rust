//! kadm5 changepw tests (private-bound; regrouped in place).

use super::*;

#[test]
fn changepw_service_listprincs_is_auth_list() {
    let (store, acl, actor) = setup();
    let out = cpw_dispatch(&store, &acl, &actor, GET_PRINCS, &list_args());
    assert_eq!(ret_code(&out), KADM5_AUTH_LIST);
}

#[test]
fn changepw_service_denies_non_self_ops() {
    let (store, acl, _actor) = setup();
    let user = "user@KERBER.TEST";
    let other = "admin@KERBER.TEST";
    let mut rename = XdrW::default();
    rename.u32(API_V2);
    rename.nullstring(Some(user));
    rename.nullstring(Some("renamed@KERBER.TEST"));
    let cases: &[(u32, Vec<u8>, u32)] = &[
        (GET_PRINCS, list_args(), KADM5_AUTH_LIST),
        (GET_POLS, list_args(), KADM5_AUTH_LIST),
        (GET_PRINCIPAL, getprinc_args(user), KADM5_AUTH_GET),
        (DELETE_PRINCIPAL, encode_named(user), KADM5_AUTH_DELETE),
        (MODIFY_PRINCIPAL, modify_args(user), KADM5_AUTH_MODIFY),
        (RENAME_PRINCIPAL, rename.b.clone(), KADM5_AUTH_INSUFFICIENT),
        (
            CHPASS_PRINCIPAL,
            chpass_args(user, "nope"),
            KADM5_AUTH_CHANGEPW,
        ),
        (CHRAND_PRINCIPAL, encode_named(user), KADM5_AUTH_CHANGEPW),
        (CREATE_POLICY, encode_named("cpwpol"), KADM5_AUTH_ADD),
        (DELETE_POLICY, encode_named("cpwpol"), KADM5_AUTH_DELETE),
        (MODIFY_POLICY, encode_named("cpwpol"), KADM5_AUTH_MODIFY),
        (GET_POLICY, encode_named("cpwpol"), KADM5_AUTH_GET),
        (PURGEKEYS, encode_named(user), KADM5_AUTH_MODIFY),
        (GET_STRINGS, encode_named(user), KADM5_AUTH_GET),
        (
            SET_STRING,
            setstr_args(user, "note", "x"),
            KADM5_AUTH_MODIFY,
        ),
        (EXTRACT_KEYS, extract_args(user, 0), KADM5_AUTH_EXTRACT),
    ];
    for (proc, args, want) in cases {
        let out = cpw_dispatch(&store, &acl, other, *proc, args);
        assert_eq!(ret_code(&out), *want, "changepw proc {proc} want {want}");
    }
}

#[test]
fn changepw_service_self_getprinc_is_ok() {
    let (store, acl, _actor) = setup();
    let out = cpw_dispatch(
        &store,
        &acl,
        "user@KERBER.TEST",
        GET_PRINCIPAL,
        &getprinc_args("user@KERBER.TEST"),
    );
    assert_eq!(ret_code(&out), 0);
}

#[test]
fn changepw_service_self_getstrs_is_auth_get() {
    let (store, acl, _actor) = setup();
    let out = cpw_dispatch(
        &store,
        &acl,
        "user@KERBER.TEST",
        GET_STRINGS,
        &encode_named("user@KERBER.TEST"),
    );
    assert_eq!(ret_code(&out), KADM5_AUTH_GET);
}

#[test]
fn changepw_service_self_purgekeys_is_auth_modify() {
    let (store, acl, _actor) = setup();
    let out = cpw_dispatch(
        &store,
        &acl,
        "user@KERBER.TEST",
        PURGEKEYS,
        &encode_named("user@KERBER.TEST"),
    );
    assert_eq!(ret_code(&out), KADM5_AUTH_MODIFY);
}

#[test]
fn changepw_service_own_policy_getpol_is_ok() {
    let (store, acl, actor) = setup();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    {
        let mut g = store.write().unwrap();
        g.put_policy(krb5_kdc::NamedPolicy::new("userpol"));
        g.set_principal_policy(&user, Some("userpol".into()))
            .unwrap();
    }
    let out = cpw_dispatch(
        &store,
        &acl,
        "user@KERBER.TEST",
        GET_POLICY,
        &encode_named("userpol"),
    );
    assert_eq!(ret_code(&out), 0);
    let denied = cpw_dispatch(&store, &acl, &actor, GET_POLICY, &encode_named("userpol"));
    assert_eq!(ret_code(&denied), KADM5_AUTH_GET);
}

#[test]
fn changepw_service_getprivs_is_ok() {
    let (store, acl, actor) = setup();
    let out = cpw_dispatch(&store, &acl, &actor, GET_PRIVS, &[]);
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), API_V2);
    assert_eq!(r.u32().unwrap(), 0);
    assert_eq!(r.u32().unwrap(), !0);
}

#[test]
fn changepw_acceptor_requires_store_realm() {
    let cpw = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "changepw"]);
    let realm = "KERBER.TEST";
    assert!(acceptor_realm_ok(
        Some(&cpw),
        Some(realm),
        realm,
        kadm5_changepw_ok
    ));
    assert!(!acceptor_realm_ok(
        Some(&cpw),
        Some("OTHER.REALM"),
        realm,
        kadm5_changepw_ok
    ));
    assert!(!acceptor_realm_ok(
        Some(&cpw),
        None,
        realm,
        kadm5_changepw_ok
    ));
}
