//! kadm5 principal tests (private-bound; regrouped in place).

use super::*;

#[test]
fn create_runs_pwqual_modules_before_the_entry_exists() {
    let (store, acl, actor) = setup();
    store
        .write()
        .unwrap()
        .put_policy(krb5_kdc::NamedPolicy::new("pq"))
        .unwrap();
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
