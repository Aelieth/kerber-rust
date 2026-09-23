//! kadm5 lockdown tests (private-bound; regrouped in place).

use super::*;

#[test]
fn chpass_lockdown_self_is_auth_changepw_before_initial() {
    let (store, acl, actor) = setup();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["lockedself"]);
    {
        let mut g = store.write().unwrap();
        g.create_password(&acl, &actor, &name, b"lock-secret")
            .unwrap();
        g.apply_admin_fields(
            &name,
            krb5_kdc::AdminFields {
                attributes: Some(krb5_kdc::KDB_LOCKDOWN_KEYS),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    }
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("lockedself@KERBER.TEST"));
    w.nullstring(Some("new-secret"));
    let out = dispatch_kadm5_ticket(
        &store,
        &acl,
        "lockedself@KERBER.TEST",
        CHPASS_PRINCIPAL,
        &w.b,
        false,
        false,
    )
    .unwrap();
    assert_eq!(ret_code(&out), KADM5_AUTH_CHANGEPW);
}

#[test]
fn extract_keys_lockdown_is_protect_keys() {
    let (store, acl, actor) = setup();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    {
        let mut g = store.write().unwrap();
        g.apply_admin_fields(
            &user,
            krb5_kdc::AdminFields {
                attributes: Some(KDB_LOCKDOWN_KEYS),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    }
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        EXTRACT_KEYS,
        &extract_args("user@KERBER.TEST", 0),
    )
    .unwrap();
    assert_eq!(ret_code(&out), KADM5_AUTH_EXTRACT);
}

#[test]
fn chpass_lockdown_is_protect_keys() {
    let (store, acl, actor) = setup();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let before = {
        let g = store.read().unwrap();
        g.get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.key.as_bytes().to_vec())
            .collect::<Vec<_>>()
    };
    {
        let mut g = store.write().unwrap();
        g.apply_admin_fields(
            &user,
            krb5_kdc::AdminFields {
                attributes: Some(KDB_LOCKDOWN_KEYS),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    }
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("user@KERBER.TEST"));
    w.nullstring(Some("lock-rotated-secret"));
    let out = dispatch_kadm5(&store, &acl, &actor, CHPASS_PRINCIPAL, &w.b).unwrap();
    assert_eq!(ret_code(&out), KADM5_AUTH_CHANGEPW);
    let after = {
        let g = store.read().unwrap();
        g.get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.key.as_bytes().to_vec())
            .collect::<Vec<_>>()
    };
    assert_eq!(after, before, "lockdown chpass must not rewrite keys");
}

#[test]
fn chrand_lockdown_returns_empty_keys() {
    let (store, acl, actor) = setup();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let before = {
        let g = store.read().unwrap();
        g.get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.key.as_bytes().to_vec())
            .collect::<Vec<_>>()
    };
    {
        let mut g = store.write().unwrap();
        g.apply_admin_fields(
            &user,
            krb5_kdc::AdminFields {
                attributes: Some(KDB_LOCKDOWN_KEYS),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    }
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        CHRAND_PRINCIPAL,
        &encode_named("user@KERBER.TEST"),
    )
    .unwrap();
    assert_eq!(ret_code(&out), 0);
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), API_V2);
    assert_eq!(r.u32().unwrap(), 0);
    assert_eq!(
        r.u32().unwrap(),
        0,
        "MIT chrand under lockdown returns no keys"
    );
    let after = {
        let g = store.read().unwrap();
        g.get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.key.as_bytes().to_vec())
            .collect::<Vec<_>>()
    };
    assert_ne!(after, before, "lockdown chrand still rotates stored keys");
}

#[test]
fn purgekeys_locked_down_target_is_allowed() {
    let (store, acl, actor) = setup();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    {
        let mut g = store.write().unwrap();
        g.apply_admin_fields(
            &user,
            krb5_kdc::AdminFields {
                attributes: Some(KDB_LOCKDOWN_KEYS),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    }
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        PURGEKEYS,
        &purgekeys_args("user@KERBER.TEST", -1),
    )
    .unwrap();
    assert_eq!(ret_code(&out), 0);
}

#[test]
fn setkey_lockdown_is_auth_setkey() {
    let (store, acl, actor) = setup();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    {
        let mut g = store.write().unwrap();
        g.apply_admin_fields(
            &user,
            krb5_kdc::AdminFields {
                attributes: Some(KDB_LOCKDOWN_KEYS),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    }
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        SETKEY_PRINCIPAL,
        &setkey16_args("user@KERBER.TEST", 18, &[0xABu8; 32]),
    )
    .unwrap();
    assert_eq!(ret_code(&out), KADM5_AUTH_SETKEY);
}

#[test]
fn delete_lockdown_is_auth_delete() {
    let (store, acl, actor) = setup();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    {
        let mut g = store.write().unwrap();
        g.apply_admin_fields(
            &user,
            krb5_kdc::AdminFields {
                attributes: Some(KDB_LOCKDOWN_KEYS),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    }
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        DELETE_PRINCIPAL,
        &encode_named("user@KERBER.TEST"),
    )
    .unwrap();
    assert_eq!(ret_code(&out), KADM5_AUTH_DELETE);
    assert!(store.read().unwrap().get_name(&user).is_some());
}

#[test]
fn modify_clear_lockdown_is_auth_modify() {
    let (store, acl, actor) = setup();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    {
        let mut g = store.write().unwrap();
        g.apply_admin_fields(
            &user,
            krb5_kdc::AdminFields {
                attributes: Some(KDB_LOCKDOWN_KEYS),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    }
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("user@KERBER.TEST"));
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(3600);
    w.u32(1);
    w.u32(0);
    w.u32(0);
    w.u32(1);
    w.u32(1);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(1);
    w.u32(0);
    w.u32(KADM5_ATTRIBUTES);
    let out = dispatch_kadm5(&store, &acl, &actor, MODIFY_PRINCIPAL, &w.b).unwrap();
    assert_eq!(ret_code(&out), KADM5_AUTH_MODIFY);
    let g = store.read().unwrap();
    assert_eq!(
        g.get_name(&user).unwrap().attributes & KDB_LOCKDOWN_KEYS,
        KDB_LOCKDOWN_KEYS
    );
}

#[test]
fn modprinc_keeping_lockdown_bit_is_allowed() {
    let (store, acl, actor) = setup();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    {
        let mut g = store.write().unwrap();
        g.apply_admin_fields(
            &user,
            krb5_kdc::AdminFields {
                attributes: Some(KDB_LOCKDOWN_KEYS),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    }
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("user@KERBER.TEST"));
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(3600);
    w.u32(1);
    w.u32(0);
    w.u32(KDB_LOCKDOWN_KEYS);
    w.u32(1);
    w.u32(1);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(1);
    w.u32(0);
    w.u32(KADM5_ATTRIBUTES);
    let out = dispatch_kadm5(&store, &acl, &actor, MODIFY_PRINCIPAL, &w.b).unwrap();
    assert_eq!(ret_code(&out), 0);
    let g = store.read().unwrap();
    assert_eq!(
        g.get_name(&user).unwrap().attributes & KDB_LOCKDOWN_KEYS,
        KDB_LOCKDOWN_KEYS
    );
}

#[test]
fn rename_lockdown_source_is_auth_delete() {
    let (store, acl, actor) = setup();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    {
        let mut g = store.write().unwrap();
        g.apply_admin_fields(
            &user,
            krb5_kdc::AdminFields {
                attributes: Some(KDB_LOCKDOWN_KEYS),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    }
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("user@KERBER.TEST"));
    w.nullstring(Some("renamed@KERBER.TEST"));
    let out = dispatch_kadm5(&store, &acl, &actor, RENAME_PRINCIPAL, &w.b).unwrap();
    assert_eq!(ret_code(&out), KADM5_AUTH_DELETE);
    assert!(store.read().unwrap().get_name(&user).is_some());
}

#[test]
fn rename_unauthorised_lockdown_is_auth_insufficient() {
    let (store, _acl, actor) = setup();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    {
        let mut g = store.write().unwrap();
        g.apply_admin_fields(
            &user,
            krb5_kdc::AdminFields {
                attributes: Some(KDB_LOCKDOWN_KEYS),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    }
    let add_only = Acl::parse("admin@KERBER.TEST a\n").expect("acl");
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("user@KERBER.TEST"));
    w.nullstring(Some("renamed@KERBER.TEST"));
    let out = dispatch_kadm5(&store, &add_only, &actor, RENAME_PRINCIPAL, &w.b).unwrap();
    assert_eq!(ret_code(&out), KADM5_AUTH_INSUFFICIENT);
    assert!(store.read().unwrap().get_name(&user).is_some());
}
