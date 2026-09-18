//! kadm5 keysalt tests (private-bound; regrouped in place).

use super::*;

#[test]
fn extract_keys_returns_key_bytes() {
    let (store, acl, actor) = setup();
    let expected = {
        let g = store.read().unwrap();
        let p = g
            .get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
            .unwrap();
        (
            p.keys.len(),
            p.keys[0].kvno,
            p.keys[0].etype.to_iana(),
            p.keys[0].key.as_bytes().to_vec(),
            p.salt.clone(),
        )
    };
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        EXTRACT_KEYS,
        &extract_args("user@KERBER.TEST", 0),
    )
    .unwrap();
    assert_eq!(ret_code(&out), 0);
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), API_V2);
    assert_eq!(r.u32().unwrap(), 0);
    let n = r.u32().unwrap();
    assert_eq!(n as usize, expected.0);
    assert_eq!(r.u32().unwrap(), expected.1);
    assert_eq!(r.u32().unwrap(), u32::try_from(expected.2).unwrap());
    assert_eq!(r.opaque().unwrap(), expected.3);
    assert_eq!(r.u32().unwrap(), 0);
    assert_eq!(r.opaque().unwrap(), expected.4);
}

#[test]
fn extract_keys_omits_password_history() {
    let (store, acl, actor) = setup();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["exhist"]);
    let (n_cur, hist_kvno) = {
        let mut g = store.write().unwrap();
        let mut pol = krb5_kdc::NamedPolicy::new("exhistpol");
        pol.history = 2;
        g.put_policy(pol);
        g.create_password(&acl, &actor, &name, b"ex-secret")
            .unwrap();
        g.set_principal_policy(&name, Some("exhistpol".into()))
            .unwrap();
        g.set_password(&name, b"ex-rotated").unwrap();
        let p = g.get_name(&name).unwrap();
        let hist = p.key_history.iter().map(|k| k.kvno).max().unwrap();
        (u32::try_from(p.keys.len()).unwrap_or(0), hist)
    };
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        EXTRACT_KEYS,
        &extract_args("exhist@KERBER.TEST", 0),
    )
    .unwrap();
    assert_eq!(ret_code(&out), 0);
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), API_V2);
    assert_eq!(r.u32().unwrap(), 0);
    let n = r.u32().unwrap();
    assert_eq!(n, n_cur);
    for _ in 0..n {
        let kvno = r.u32().unwrap();
        assert_ne!(
            kvno, hist_kvno,
            "EXTRACT kvno=0 must not return osa history"
        );
        let _ = r.u32().unwrap();
        let _ = r.opaque().unwrap();
        let _ = r.u32().unwrap();
        let _ = r.opaque().unwrap();
    }
}

#[test]
fn chpass3_keepold_retains_prior_keys() {
    let (store, acl, actor) = setup();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["keepu"]);
    let old_kvno = {
        let mut g = store.write().unwrap();
        g.create_password(&acl, &actor, &name, b"keep-secret")
            .unwrap();
        g.get_name(&name).unwrap().keys[0].kvno
    };
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("keepu@KERBER.TEST"));
    w.u32(1);
    w.u32(0);
    w.nullstring(Some("keep-rotated"));
    let out = dispatch_kadm5(&store, &acl, &actor, CHPASS_PRINCIPAL3, &w.b).unwrap();
    assert_eq!(ret_code(&out), 0);
    let n_keys = {
        let g = store.read().unwrap();
        let p = g.get_name(&name).unwrap();
        assert!(p.keys.iter().any(|k| k.kvno == old_kvno));
        assert!(p.keys.iter().any(|k| k.kvno != old_kvno));
        p.keys.len()
    };
    let got = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &{
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("keepu@KERBER.TEST"));
        w.u32(u32::MAX);
        w.b
    })
    .unwrap();
    let (n_key, kvnos) = gprinc_key_kvnos(&got);
    assert_eq!(n_key as usize, n_keys);
    assert!(kvnos.contains(&old_kvno));
}

#[test]
fn chrand3_self_keepold_clamps_to_five() {
    let (store, acl, actor) = setup();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["selfchrand"]);
    {
        let mut g = store.write().unwrap();
        g.create_password(&acl, &actor, &name, b"keep-0").unwrap();
    }
    for i in 1..=6 {
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("selfchrand@KERBER.TEST"));
        w.u32(1);
        w.u32(0);
        let out = dispatch_kadm5(
            &store,
            &acl,
            "selfchrand@KERBER.TEST",
            CHRAND_PRINCIPAL3,
            &w.b,
        )
        .unwrap();
        assert_eq!(ret_code(&out), 0, "chrand {i}");
    }
    let g = store.read().unwrap();
    let p = g.get_name(&name).unwrap();
    let mut kvnos: Vec<u32> = p.keys.iter().map(|k| k.kvno).collect();
    kvnos.sort_unstable();
    kvnos.dedup();
    assert_eq!(kvnos.len(), 5, "self chrand keepold cap: {kvnos:?}");
}

#[test]
fn self_keepold_clamps_to_five() {
    let (store, acl, actor) = setup();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["selfkeep"]);
    {
        let mut g = store.write().unwrap();
        g.create_password(&acl, &actor, &name, b"keep-0").unwrap();
    }
    for i in 1..=6 {
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("selfkeep@KERBER.TEST"));
        w.u32(1);
        w.u32(0);
        w.nullstring(Some(&format!("keep-{i}")));
        let out = dispatch_kadm5(
            &store,
            &acl,
            "selfkeep@KERBER.TEST",
            CHPASS_PRINCIPAL3,
            &w.b,
        )
        .unwrap();
        assert_eq!(ret_code(&out), 0, "cpw {i}");
    }
    let g = store.read().unwrap();
    let p = g.get_name(&name).unwrap();
    let mut kvnos: Vec<u32> = p.keys.iter().map(|k| k.kvno).collect();
    kvnos.sort_unstable();
    kvnos.dedup();
    assert_eq!(kvnos.len(), 5, "self keepold cap: {kvnos:?}");
}

#[test]
fn setkey_self_keepold_clamps_to_five() {
    let (store, acl, actor) = setup();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["selfset"]);
    {
        let mut g = store.write().unwrap();
        g.create_password(&acl, &actor, &name, b"set-0").unwrap();
    }
    let self_acl = Acl::parse("selfset@KERBER.TEST s\n").unwrap();
    for i in 1..=6u8 {
        let out = dispatch_kadm5(
            &store,
            &self_acl,
            "selfset@KERBER.TEST",
            SETKEY_PRINCIPAL4,
            &setkey4_args("selfset@KERBER.TEST", true, 0, 18, &[i; 32], 0, &[]),
        )
        .unwrap();
        assert_eq!(ret_code(&out), 0, "setkey {i}");
    }
    let g = store.read().unwrap();
    let mut kvnos: Vec<u32> = g
        .get_name(&name)
        .unwrap()
        .keys
        .iter()
        .map(|k| k.kvno)
        .collect();
    kvnos.sort_unstable();
    kvnos.dedup();
    assert_eq!(kvnos.len(), 5, "self setkey keepold cap: {kvnos:?}");
}

#[test]
fn purgekeys_drops_old_kvnos() {
    let (store, acl, actor) = setup();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["purgee"]);
    {
        let mut g = store.write().unwrap();
        let mut pol = krb5_kdc::NamedPolicy::new("g3bhist");
        pol.history = 2;
        g.put_policy(pol);
        g.create_password(&acl, &actor, &name, b"purge-secret")
            .unwrap();
        g.set_principal_policy(&name, Some("g3bhist".into()))
            .unwrap();
        g.set_password(&name, b"purge-rotated").unwrap();
        let p = g.get_name(&name).unwrap();
        assert!(!p.key_history.is_empty());
    }
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        PURGEKEYS,
        &purgekeys_args("purgee@KERBER.TEST", -1),
    )
    .unwrap();
    assert_eq!(ret_code(&out), 0);
    {
        let g = store.read().unwrap();
        let p = g.get_name(&name).unwrap();
        assert!(!p.key_history.is_empty());
        assert!(p.keys.iter().all(|k| k.kvno != 1));
        assert!(!p.keys.is_empty());
    }
    let got = dispatch_kadm5(&store, &acl, &actor, GET_PRINCIPAL, &{
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("purgee@KERBER.TEST"));
        w.u32(u32::MAX);
        w.b
    })
    .unwrap();
    assert_eq!(ret_code(&got), 0);
}

#[test]
fn setkey3_empty_ks_tuple() {
    let (store, acl, actor) = setup();
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("user@KERBER.TEST"));
    w.u32(0);
    w.u32(0);
    w.u32(1);
    w.u32(18);
    w.opaque(&[0xEFu8; 32]);
    let out = dispatch_kadm5(&store, &acl, &actor, SETKEY_PRINCIPAL3, &w.b).unwrap();
    assert_eq!(ret_code(&out), 0);
    let g = store.read().unwrap();
    let p = g
        .get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
        .unwrap();
    assert_eq!(p.keys[0].key.as_bytes(), &[0xEFu8; 32]);
    assert!(p.key_history.is_empty());
}

#[test]
fn setkey_replaces_keys() {
    let (store, acl, actor) = setup();
    let key = [0xABu8; 32];
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        SETKEY_PRINCIPAL,
        &setkey16_args("user@KERBER.TEST", 18, &key),
    )
    .unwrap();
    assert_eq!(ret_code(&out), 0);
    let g = store.read().unwrap();
    let p = g
        .get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
        .unwrap();
    assert_eq!(p.keys.len(), 1);
    assert_eq!(p.keys[0].etype.to_iana(), 18);
    assert_eq!(p.keys[0].key.as_bytes(), key);
    assert!(p.key_history.is_empty());
}

#[test]
fn setkey4_keepold_retains_history() {
    let (store, acl, actor) = setup();
    let n_old = {
        let g = store.read().unwrap();
        g.get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
            .unwrap()
            .keys
            .len()
    };
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        SETKEY_PRINCIPAL4,
        &setkey4_args("user@KERBER.TEST", true, 0, 18, &[0xCDu8; 32], 0, &[]),
    )
    .unwrap();
    assert_eq!(ret_code(&out), 0);
    let g = store.read().unwrap();
    let p = g
        .get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
        .unwrap();
    assert_eq!(p.keys.len(), 1 + n_old);
    assert!(p.keys.iter().any(|k| k.key.as_bytes() == [0xCDu8; 32]));
    assert!(p.key_history.is_empty());
}

#[test]
fn setkey4_kadm5_key_data_kvno_and_salt() {
    let (store, acl, actor) = setup();
    let key = [0x11u8; 32];
    let salt = b"special-salt";
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        SETKEY_PRINCIPAL4,
        &setkey4_args("user@KERBER.TEST", false, 5, 18, &key, 4, salt),
    )
    .unwrap();
    assert_eq!(ret_code(&out), 0);
    let g = store.read().unwrap();
    let p = g
        .get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
        .unwrap();
    assert_eq!(p.keys.len(), 1);
    assert_eq!(p.keys[0].kvno, 5);
    assert_eq!(p.keys[0].etype.to_iana(), 18);
    assert_eq!(p.keys[0].key.as_bytes(), key);
    assert_eq!(p.keys[0].salt_type, Some(4));
    assert_eq!(p.keys[0].kdb_salt.as_deref(), Some(salt.as_slice()));
    assert!(p.key_history.is_empty());
}

#[test]
fn setkey4_krb5_key_data_ver_first_does_not_decode() {
    let (store, acl, actor) = setup();
    let mut w = XdrW::default();
    w.u32(API_V2);
    w.nullstring(Some("user@KERBER.TEST"));
    w.u32(0);
    w.u32(1);
    w.u32(2);
    w.u32(5);
    w.u32(18);
    w.opaque(&[0xABu8; 32]);
    w.u32(4);
    w.opaque(b"s");
    assert!(
        dispatch_kadm5(&store, &acl, &actor, SETKEY_PRINCIPAL4, &w.b).is_err(),
        "xdr_krb5_key_data (key_data_ver first) is not SETKEY4"
    );
}

#[test]
fn extract_keys_missing_is_unk_princ() {
    let (store, acl, actor) = setup();
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        EXTRACT_KEYS,
        &extract_args("no-such@KERBER.TEST", 0),
    )
    .unwrap();
    assert_eq!(ret_code(&out), KADM5_UNK_PRINC);
}

#[test]
fn setkey_keepold_kvno_collision_is_bad_kvno() {
    let (store, acl, actor) = setup();
    let kvno = {
        let g = store.read().unwrap();
        g.get_name(&PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]))
            .unwrap()
            .keys[0]
            .kvno
    };
    let out = dispatch_kadm5(
        &store,
        &acl,
        &actor,
        SETKEY_PRINCIPAL4,
        &setkey4_args("user@KERBER.TEST", true, kvno, 18, &[0xABu8; 32], 0, &[]),
    )
    .unwrap();
    assert_eq!(ret_code(&out), KADM5_SETKEY_BAD_KVNO);
}

#[test]
fn chrand_bumps_kvno() {
    let (store, acl, actor) = setup();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
    let kvno_before = {
        let g = store.read().unwrap();
        g.get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap()
    };
    let args = encode_named("user@KERBER.TEST");
    let out = dispatch_kadm5(&store, &acl, &actor, CHRAND_PRINCIPAL, &args).unwrap();
    assert_eq!(ret_code(&out), 0);
    let kvno_after = {
        let g = store.read().unwrap();
        g.get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap()
    };
    assert!(kvno_after > kvno_before);
}

#[test]
fn non_self_keepold_is_unbounded() {
    let (store, acl, actor) = setup();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    for i in 1..=6 {
        let mut w = XdrW::default();
        w.u32(API_V2);
        w.nullstring(Some("user@KERBER.TEST"));
        w.u32(1);
        w.u32(0);
        w.nullstring(Some(&format!("admin-keep-{i}")));
        let out = dispatch_kadm5(&store, &acl, &actor, CHPASS_PRINCIPAL3, &w.b).unwrap();
        assert_eq!(ret_code(&out), 0, "admin keepold {i}");
    }
    let g = store.read().unwrap();
    let p = g.get_name(&name).unwrap();
    let mut kvnos: Vec<u32> = p.keys.iter().map(|k| k.kvno).collect();
    kvnos.sort_unstable();
    kvnos.dedup();
    assert!(
        kvnos.len() > 5,
        "non-self keepold=1 is unbounded: {kvnos:?}"
    );
}
