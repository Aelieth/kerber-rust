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

/// Each hook call's operation, stage and principal.
#[derive(Default)]
struct Named(std::sync::Mutex<Vec<String>>);

impl Named {
    fn note(&self, op: &str, stage: krb5_kdc::HookStage, princ: &PrincipalName, realm: &str) {
        let stage = match stage {
            krb5_kdc::HookStage::Precommit => "pre",
            krb5_kdc::HookStage::Postcommit => "post",
        };
        let line = format!("{op}:{stage}:{}", princ.unparse_with_realm_lossy(realm));
        self.0.lock().unwrap().push(line);
    }
}

impl krb5_kdc::Kadm5Hook for Named {
    fn name(&self) -> &'static str {
        "named"
    }

    fn chpass(
        &self,
        stage: krb5_kdc::HookStage,
        princ: &PrincipalName,
        realm: &str,
        _keepold: u32,
        _password: Option<&[u8]>,
        _etypes: &[krb5_crypto::EncryptionType],
    ) -> Result<(), krb5_kdc::Error> {
        self.note("chpass", stage, princ, realm);
        Ok(())
    }

    fn modify(
        &self,
        stage: krb5_kdc::HookStage,
        princ: &PrincipalName,
        realm: &str,
        _mask: u32,
    ) -> Result<(), krb5_kdc::Error> {
        self.note("modify", stage, princ, realm);
        Ok(())
    }
}

#[test]
fn kadmind_hooks_name_an_aliass_target() {
    let (store, acl, actor) = setup();
    let mut alias = XdrW::default();
    alias.u32(API_V2);
    alias.nullstring(Some("nick@KERBER.TEST"));
    alias.nullstring(Some("user@KERBER.TEST"));
    let out = dispatch_kadm5(&store, &acl, &actor, CREATE_ALIAS, &alias.b).unwrap();
    assert_eq!(ret_code(&out), 0);
    let module = std::sync::Arc::new(Named::default());
    krb5_kdc::set_thread_kadm5_hook(vec![module.clone()]);
    let mut chpass3 = XdrW::default();
    chpass3.u32(API_V2);
    chpass3.nullstring(Some("nick@KERBER.TEST"));
    chpass3.u32(0);
    chpass3.u32(0);
    chpass3.nullstring(Some("another-password"));
    let mut chrand3 = XdrW::default();
    chrand3.u32(API_V2);
    chrand3.nullstring(Some("nick@KERBER.TEST"));
    chrand3.u32(0);
    chrand3.u32(0);
    for (proc, args) in [
        (CHPASS_PRINCIPAL3, chpass3.b),
        (CHRAND_PRINCIPAL3, chrand3.b),
        (MODIFY_PRINCIPAL, modify_rec("nick@KERBER.TEST")),
    ] {
        let out = dispatch_kadm5(&store, &acl, &actor, proc, &args).unwrap();
        assert_eq!(ret_code(&out), 0, "proc {proc}");
    }
    krb5_kdc::clear_thread_kadm5_hook();
    let user = "user@KERBER.TEST";
    assert_eq!(
        *module.0.lock().unwrap(),
        [
            format!("chpass:pre:{user}"),
            format!("chpass:post:{user}"),
            format!("chpass:pre:{user}"),
            format!("chpass:post:{user}"),
            format!("modify:pre:{user}"),
            format!("modify:post:{user}"),
        ]
    );
}
