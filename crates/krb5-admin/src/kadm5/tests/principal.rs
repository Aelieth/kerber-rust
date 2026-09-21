//! kadm5 principal tests (private-bound; regrouped in place).

use super::*;

#[test]
fn parse_rename_reads_two_principals() {
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("old@KERBER.TEST"));
    w.nullstring(Some("new@KERBER.TEST"));
    let (old, old_realm, new, new_realm) = parse_rename(&w.b).unwrap();
    assert_eq!(old.components_joined(), "old");
    assert_eq!(old_realm, "KERBER.TEST");
    assert_eq!(new.components_joined(), "new");
    assert_eq!(new_realm, "KERBER.TEST");
}

#[test]
fn rename_dispatch_keeps_rid_and_requires_add_delete() {
    use krb5_kdc::shared_dump as shared_store;
    use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented, documented_admin_id};

    let (mut store, acl) = bootstrap_documented().unwrap();
    let actor = documented_admin_id();
    let old = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["renamefrom"]);
    let new = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["renameto"]);
    store
        .create_password(&acl, &actor, &old, b"rename-secret")
        .unwrap();
    let rid = store.get_name(&old).unwrap().rid;
    let key = store
        .get_name(&old)
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .as_bytes()
        .to_vec();
    let shared = shared_store(store);
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some(&format!("renamefrom@{TEST_REALM}")));
    w.nullstring(Some(&format!("renameto@{TEST_REALM}")));
    let ret = dispatch_kadm5(&shared, &acl, &actor, RENAME_PRINCIPAL, &w.b).unwrap();
    assert_eq!(&ret[4..8], &0u32.to_be_bytes());
    {
        let g = shared.read().unwrap();
        assert!(g.get_name(&old).is_none());
        let p = g.get_name(&new).unwrap();
        assert_eq!(p.rid, rid);
        assert_eq!(p.best_key().unwrap().key.as_bytes(), key.as_slice());
    }
    let add_only = Acl::parse("admin@KERBER.TEST a\n").expect("acl");
    let mut w2 = XdrW::default();
    w2.u32(API_V2);
    w2.nullstring(Some(&format!("renameto@{TEST_REALM}")));
    w2.nullstring(Some(&format!("renamefrom@{TEST_REALM}")));
    let denied = dispatch_kadm5(&shared, &add_only, &actor, RENAME_PRINCIPAL, &w2.b).unwrap();
    assert_eq!(ret_code(&denied), KADM5_AUTH_INSUFFICIENT);
    let g = shared.read().unwrap();
    assert!(g.get_name(&new).is_some());
    assert!(g.get_name(&old).is_none());
}

#[test]
fn modify_foreign_realm_existing_user_is_unk_princ() {
    let (store, acl, actor) = setup();
    let before = {
        let g = store.read().unwrap();
        g.get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
            .unwrap()
            .attributes
    };
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        MODIFY_PRINCIPAL,
        &modify_rec("user@OTHER.REALM"),
    )
    .unwrap();
    assert_eq!(ret_code(&out), KADM5_UNK_PRINC);
    let after = {
        let g = store.read().unwrap();
        g.get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
            .unwrap()
            .attributes
    };
    assert_eq!(after, before);
    let local = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        MODIFY_PRINCIPAL,
        &modify_rec("user@KERBER.TEST"),
    )
    .unwrap();
    assert_eq!(ret_code(&local), 0);
}

/// MIT `kadm5_create_principal_3` `passwd_check` (`svr_principal.c:370`):
/// `empty` rejects without a policy as `KADM5_PASS_Q_TOOSHORT`; `princ`
/// rejects a component match under a policy as `KADM5_PASS_Q_DICT`; a
/// rejected create leaves no entry.
#[test]
fn create_runs_pwqual_modules_before_the_entry_exists() {
    let (store, acl, actor) = setup();
    store
        .write()
        .unwrap()
        .put_policy(krb5_kdc::NamedPolicy::new("pq"));
    let empty = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        CREATE_PRINCIPAL,
        &create_rec("nopol@KERBER.TEST", ""),
    )
    .unwrap();
    assert_eq!(ret_code(&empty), KADM5_PASS_Q_TOOSHORT);
    let princ = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        CREATE_PRINCIPAL,
        &create_rec_policy("pqu@KERBER.TEST", "PQU", "pq"),
    )
    .unwrap();
    assert_eq!(ret_code(&princ), KADM5_PASS_Q_DICT);
    let realm = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        CREATE_PRINCIPAL,
        &create_rec_policy("pqu@KERBER.TEST", "kerber.test", "pq"),
    )
    .unwrap();
    assert_eq!(ret_code(&realm), KADM5_PASS_Q_DICT);
    // Without a policy the princ module does not run.
    let nopol = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        CREATE_PRINCIPAL,
        &create_rec("pqfree@KERBER.TEST", "PQFREE"),
    )
    .unwrap();
    assert_eq!(ret_code(&nopol), 0);
    let g = store.read().unwrap();
    let n = |s: &str| PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s]);
    assert!(g.get_name(&n("nopol")).is_none());
    assert!(g.get_name(&n("pqu")).is_none());
    assert!(g.get_name(&n("pqfree")).is_some());
}

#[test]
fn create_foreign_realm_authorises_first() {
    let (store, _acl, _actor) = setup();
    let none = Acl::parse("nobody@KERBER.TEST a\n").expect("acl");
    let out = dispatch_kadm5(
        &store,
        &none,
        "user@KERBER.TEST",
        CREATE_PRINCIPAL,
        &create_rec("user@OTHER.REALM", "x"),
    )
    .unwrap();
    assert_eq!(ret_code(&out), KADM5_AUTH_ADD);
    assert_ne!(ret_code(&out), KADM5_UNK_PRINC);
    let del = dispatch_kadm5(
        &store,
        &none,
        "user@KERBER.TEST",
        DELETE_PRINCIPAL,
        &encode_named("user@OTHER.REALM"),
    )
    .unwrap();
    assert_eq!(ret_code(&del), KADM5_AUTH_DELETE);
    assert_ne!(ret_code(&del), KADM5_UNK_PRINC);
    let mut ren_args = XdrW::default();
    ren_args.u32(API_V2);
    ren_args.nullstring(Some("user@OTHER.REALM"));
    ren_args.nullstring(Some("x@OTHER.REALM"));
    let ren = dispatch_kadm5(
        &store,
        &none,
        "user@KERBER.TEST",
        RENAME_PRINCIPAL,
        &ren_args.b,
    )
    .unwrap();
    assert_eq!(ret_code(&ren), KADM5_AUTH_INSUFFICIENT);
    assert_ne!(ret_code(&ren), KADM5_UNK_PRINC);
}

#[test]
fn create_foreign_realm_then_getprinc() {
    let (store, acl, actor) = setup();
    let created = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        CREATE_PRINCIPAL,
        &create_rec("user@OTHER.REALM", "x"),
    )
    .unwrap();
    assert_eq!(ret_code(&created), 0);
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("user@OTHER.REALM"));
    w.u32(u32::MAX);
    let got = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &w.b).unwrap();
    assert_eq!(ret_code(&got), 0);
    let mut r = XdrR::new(&got);
    assert_eq!(r.u32().unwrap(), API_V2);
    assert_eq!(r.u32().unwrap(), 0);
    assert_eq!(r.nullstring().unwrap().as_deref(), Some("user@OTHER.REALM"));
    let local = {
        let g = store.read().unwrap();
        g.get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
            .map(krb5_kdc::Principal::id)
    };
    assert_eq!(local.as_deref(), Some("user@KERBER.TEST"));
}

#[test]
fn stub_setup_unk_before_acl_on_modify_setkey_purge_extract_setstr() {
    stub_unk_before_acl(
        MODIFY_PRINCIPAL,
        &modify_rec("nosuch@KERBER.TEST"),
        KADM5_AUTH_MODIFY,
    );
    stub_unk_before_acl(
        EXTRACT_KEYS,
        &extract_args("nosuch@KERBER.TEST", 0),
        KADM5_AUTH_EXTRACT,
    );
    let mut pk = XdrW::default();
    pk.u32(API_V2);
    pk.nullstring(Some("nosuch@KERBER.TEST"));
    pk.u32(0);
    stub_unk_before_acl(PURGEKEYS, &pk.b, KADM5_AUTH_MODIFY);
    let mut sk = XdrW::default();
    sk.u32(API_V2);
    sk.nullstring(Some("nosuch@KERBER.TEST"));
    sk.u32(0);
    sk.u32(0);
    sk.u32(1);
    sk.u32(18);
    sk.opaque(&[0xEFu8; 32]);
    stub_unk_before_acl(SETKEY_PRINCIPAL3, &sk.b, KADM5_AUTH_SETKEY);
    stub_unk_before_acl(
        SETKEY_PRINCIPAL,
        &setkey16_args("nosuch@KERBER.TEST", 18, &[0xEFu8; 32]),
        KADM5_AUTH_SETKEY,
    );
    stub_unk_before_acl(
        SETKEY_PRINCIPAL4,
        &setkey4_args("nosuch@KERBER.TEST", false, 1, 18, &[0xEFu8; 32], 0, &[]),
        KADM5_AUTH_SETKEY,
    );
    let mut ss = XdrW::default();
    ss.u32(API_V2);
    ss.nullstring(Some("nosuch@KERBER.TEST"));
    ss.nullstring(Some("k"));
    ss.nullstring(Some("v"));
    stub_unk_before_acl(SET_STRING, &ss.b, KADM5_AUTH_MODIFY);
}

#[test]
fn listprincs_names_documented_principals() {
    let (store, acl, actor) = setup();
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.u32(0);
    let out = dispatch_kadm5(&store, &acl, &actor, GET_PRINCS, &w.b).unwrap();
    assert_eq!(ret_code(&out), 0);
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), API_V2);
    assert_eq!(r.u32().unwrap(), 0);
    let n = r.u32().unwrap();
    assert_eq!(r.u32().unwrap(), n, "xdr_array repeats count");
    assert!(n >= 2);
    let mut names = Vec::new();
    for _ in 0..n {
        names.push(r.nullstring().unwrap().unwrap());
    }
    assert!(names.iter().any(|s| s == "user@KERBER.TEST"));
    assert!(names.iter().any(|s| s == "admin@KERBER.TEST"));
}

#[test]
fn delprinc_then_getprinc_is_unk_princ() {
    let (store, acl, actor) = setup();
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["extra"]);
    {
        let mut g = store.write().unwrap();
        g.create_password(&acl, &actor, &extra, b"extra-secret")
            .unwrap();
    }
    let del = encode_named("extra@KERBER.TEST");
    let out = dispatch_kadm5(&store, &acl, &actor, DELETE_PRINCIPAL, &del).unwrap();
    assert_eq!(ret_code(&out), 0);
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("extra@KERBER.TEST"));
    w.u32(u32::MAX);
    let got = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &w.b).unwrap();
    assert_eq!(ret_code(&got), KADM5_UNK_PRINC);
}

#[test]
fn modprinc_sets_requires_preauth_bit() {
    let (store, acl, actor) = setup();
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["modme"]);
    {
        let mut g = store.write().unwrap();
        g.create_password(&acl, &actor, &extra, b"mod-secret")
            .unwrap();
    }
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("modme@KERBER.TEST"));
    w.u32(0); // expire
    w.u32(0);
    w.u32(0); // pw_expire
    w.u32(3600); // max_life
    w.u32(1); // mod_name NULL
    w.u32(0);
    w.u32(krb5_kdc::KDB_REQUIRES_PRE_AUTH);
    w.u32(1); // kvno
    w.u32(1);
    w.u32(0); // policy
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0); // n_key
    w.u32(0); // n_tl
    w.u32(1); // tl null
    w.u32(0); // key_data array
    w.u32(KADM5_ATTRIBUTES | KADM5_MAX_LIFE);
    let out = dispatch_kadm5(&store, &acl, &actor, MODIFY_PRINCIPAL, &w.b).unwrap();
    assert_eq!(ret_code(&out), 0);
    let g = store.read().unwrap();
    let p = g.get_name(&extra).unwrap();
    assert!(p.requires_preauth);
    assert_eq!(p.max_life, 3600);
}

#[test]
fn modprinc_sets_max_rlife() {
    let (store, acl, actor) = setup();
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["rlife"]);
    {
        let mut g = store.write().unwrap();
        g.create_password(&acl, &actor, &extra, b"rlife-secret")
            .unwrap();
    }
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("rlife@KERBER.TEST"));
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(1);
    w.u32(0);
    w.u32(0);
    w.u32(1);
    w.u32(1);
    w.u32(0);
    w.u32(0);
    w.u32(86_400);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(1);
    w.u32(0);
    w.u32(KADM5_MAX_RLIFE);
    let out = dispatch_kadm5(&store, &acl, &actor, MODIFY_PRINCIPAL, &w.b).unwrap();
    assert_eq!(ret_code(&out), 0);
    let g = store.read().unwrap();
    assert_eq!(g.get_name(&extra).unwrap().max_renewable_life, 86_400);
}
