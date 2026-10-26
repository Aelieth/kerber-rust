//! kadm5 keysalt tests (private-bound; regrouped in place).

use super::*;

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
