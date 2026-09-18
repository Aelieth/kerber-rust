//! kadm5 getprinc tests (private-bound; regrouped in place).

use super::*;

#[test]
fn getprinc_returns_documented_user_not_unk_princ() {
    let (store, acl, actor) = setup();
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("user@KERBER.TEST"));
    w.u32(u32::MAX);
    let out = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &w.b).unwrap();
    assert_ne!(ret_code(&out), KADM5_UNK_PRINC);
    assert_eq!(ret_code(&out), 0);
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), API_V2);
    assert_eq!(r.u32().unwrap(), 0);
    assert_eq!(
        r.nullstring().unwrap().as_deref(),
        Some("user@KERBER.TEST"),
        "gprinc_ret.rec.principal is xdr_nullstring of name@REALM"
    );
    r.u32().unwrap(); // expire
    r.u32().unwrap();
    r.u32().unwrap();
    r.u32().unwrap();
    assert_eq!(r.u32().unwrap(), 0, "mod_name present");
    assert_eq!(
        r.nullstring().unwrap().as_deref(),
        Some("db_creation@KERBER.TEST")
    );
    r.u32().unwrap(); // mod_date
    r.u32().unwrap(); // attributes
    r.u32().unwrap(); // kvno
    r.u32().unwrap(); // mkvno
    let _ = r.nullstring().unwrap();
    r.u32().unwrap(); // aux
    r.u32().unwrap(); // max_renewable
    r.u32().unwrap(); // last_success
    r.u32().unwrap(); // last_failed
    r.u32().unwrap(); // fail_auth_count
    let n_key = r.u32().unwrap();
    assert!(n_key >= 1, "getprinc n_key_data, got {n_key}");
    let n_tl = r.u32().unwrap();
    let tl_null = r.u32().unwrap();
    if tl_null == 0 {
        loop {
            let more = r.u32().unwrap();
            if more == 0 {
                break;
            }
            r.u32().unwrap();
            let _ = r.opaque().unwrap();
        }
    } else {
        assert_eq!(n_tl, 0);
    }
    let n = r.u32().unwrap();
    assert_eq!(n, n_key);
    for _ in 0..n {
        let ver = r.u32().unwrap();
        let kvno = r.u32().unwrap();
        let etype = r.u32().unwrap();
        assert!(kvno >= 1);
        assert!(etype > 0);
        if ver > 1 {
            r.u32().unwrap();
        }
    }
}

#[test]
fn getprinc_dates_from_create_cpw_mod() {
    let (store, acl, actor) = setup();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["dated"]);
    {
        let mut g = store.write().unwrap();
        g.create_password(&acl, &actor, &name, b"date-secret")
            .unwrap();
    }
    let created = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &{
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("dated@KERBER.TEST"));
        w.u32(u32::MAX);
        w.b
    })
    .unwrap();
    let (pwd0, mod0) = gprinc_pwd_and_mod(&created);
    assert_ne!(pwd0, 0, "create must stamp last_pwd_change, not [never]");
    assert_ne!(mod0, 0, "create must stamp mod_date, not Unix epoch");
    {
        let mut g = store.write().unwrap();
        g.set_password(&name, b"date-rotated").unwrap();
    }
    let after_cpw = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &{
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("dated@KERBER.TEST"));
        w.u32(u32::MAX);
        w.b
    })
    .unwrap();
    let (pwd1, mod1) = gprinc_pwd_and_mod(&after_cpw);
    assert!(pwd1 >= pwd0, "cpw must keep a real last_pwd_change");
    assert_ne!(mod1, 0);
    {
        let mut g = store.write().unwrap();
        g.apply_admin_fields(&name, None, None, Some(u32::MAX), None, None, false, None)
            .unwrap();
    }
    let after_mod = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &{
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("dated@KERBER.TEST"));
        w.u32(u32::MAX);
        w.b
    })
    .unwrap();
    let (pwd2, mod2) = gprinc_pwd_and_mod(&after_mod);
    assert_eq!(pwd2, pwd1, "modprinc must not clear last_pwd_change");
    assert_ne!(mod2, 0);
}

#[test]
fn getprinc_omits_password_history_kvnos() {
    let (store, acl, actor) = setup();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["histuser"]);
    {
        let mut g = store.write().unwrap();
        let mut pol = krb5_kdc::NamedPolicy::new("e3hist");
        pol.history = 2;
        g.put_policy(pol);
        g.create_password(&acl, &actor, &name, b"hist-secret")
            .unwrap();
        g.set_principal_policy(&name, Some("e3hist".into()))
            .unwrap();
        g.set_password(&name, b"hist-rotated").unwrap();
        let p = g.get_name(&name).unwrap();
        assert!(!p.key_history.is_empty());
    }
    let out = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &{
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("histuser@KERBER.TEST"));
        w.u32(u32::MAX);
        w.b
    })
    .unwrap();
    assert_eq!(ret_code(&out), 0);
    let (n_key, kvnos) = gprinc_key_kvnos(&out);
    let g = store.read().unwrap();
    let p = g.get_name(&name).unwrap();
    assert_eq!(n_key as usize, p.keys.len());
    let current = p.keys[0].kvno;
    assert!(
        kvnos.iter().all(|v| *v == current),
        "history kvnos in getprinc: {kvnos:?}"
    );
    assert!(!p.key_history.is_empty());
    assert!(p.key_history.iter().any(|k| k.kvno != current));
}

#[test]
fn getprinc_missing_is_unk_princ() {
    let (store, acl, actor) = setup();
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("no-such@KERBER.TEST"));
    w.u32(u32::MAX);
    let out = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &w.b).unwrap();
    assert_eq!(ret_code(&out), KADM5_UNK_PRINC);
}

#[test]
fn getprinc_missing_unauthorised_is_unk_princ() {
    let (store, _acl, _actor) = setup();
    let none = Acl::parse("nobody@KERBER.TEST a\n").expect("acl");
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("nosuch@KERBER.TEST"));
    w.u32(u32::MAX);
    let out = dispatch_kadm5(&store, &none, "user@KERBER.TEST", GET_PRINCIPAL, &w.b).unwrap();
    assert_eq!(ret_code(&out), KADM5_UNK_PRINC);
    assert_ne!(ret_code(&out), KADM5_AUTH_GET);
}

#[test]
fn getprinc_foreign_realm_is_unk_princ() {
    let (store, acl, actor) = setup();
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("user@OTHER.REALM"));
    w.u32(u32::MAX);
    let out = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &w.b).unwrap();
    assert_eq!(ret_code(&out), KADM5_UNK_PRINC);
    let mut loc = XdrW::default();
    loc.u32(API_V2);
    loc.nullstring(Some("user@KERBER.TEST"));
    loc.u32(u32::MAX);
    let ok = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &loc.b).unwrap();
    assert_eq!(ret_code(&ok), 0);
}
