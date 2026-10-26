//! kadm5 iprop tests (private-bound; regrouped in place).

use super::*;

// Shim: build the acl+self auth config the real `dispatch_iprop` now takes.
fn dispatch_iprop(
    store: &krb5_kdc::SharedDump,
    acl: &Acl,
    actor: &str,
    proc: u32,
    args: &[u8],
) -> Vec<u8> {
    crate::kadm5::iprop::dispatch_iprop(
        store,
        &crate::kadm5::Kadm5AuthConfig::from_acl(acl.clone()),
        None,
        actor,
        proc,
        args,
    )
}

#[cfg(feature = "test-hooks")]
fn logging_setup() -> (krb5_kdc::SharedDump, Acl, String) {
    let (store, acl, actor) = setup();
    seed_master_key(&store);
    store.write().unwrap().set_ulog(
        krb5_kdc::Ulog::memory(1000).unwrap(),
        krb5_kdc::IpropRole::Primary,
    );
    (store, acl, actor)
}

#[cfg(feature = "test-hooks")]
fn get_updates_args(last: krb5_kdc::UlogLast) -> Vec<u8> {
    let mut args = XdrW::default();
    args.u32(last.sno);
    args.u32(last.time.seconds);
    args.u32(last.time.useconds);
    args.b
}

// logged; a store with no master key (no stash, no `KRB5_MASTER_PASSWORD`, no `K/M`: the in-memory bootstrap) cannot log a keyed change at all, so no key reaches the log or the wire.
#[cfg(feature = "test-hooks")]
#[test]
fn iprop_get_updates_refuses_plaintext_keys_without_master_key() {
    let (store, acl, actor) = setup();
    assert!(
        store.read().unwrap().iprop_master_key().is_none(),
        "the bootstrap store must have no master key for this test"
    );
    store.write().unwrap().set_ulog(
        krb5_kdc::Ulog::memory(100).unwrap(),
        krb5_kdc::IpropRole::Primary,
    );
    let last = store.read().unwrap().ulog_last().unwrap();
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["plainkey"]);
    let made = store
        .write()
        .unwrap()
        .create_password(&acl, &actor, &extra, b"plain-secret");
    assert!(
        made.is_err(),
        "a keyed change with no master key is not logged"
    );
    assert_eq!(store.read().unwrap().ulog_last(), Some(last));
    let out = dispatch_iprop(
        &store,
        &acl,
        &actor,
        IPROP_GET_UPDATES,
        &get_updates_args(last),
    );
    let (st, _, _, _, entries) = decode_incr_result(&out, None).unwrap();
    assert_eq!(st, krb5_kdc::IPROP_NIL);
    assert!(entries.is_empty());
    assert!(
        !out.windows(b"plainkey".len()).any(|w| w == b"plainkey"),
        "the reply must not name the keyed principal"
    );
}

#[test]
fn check_rpcsec_auth_rejects_kiprop_history_and_one_component() {
    let admin = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "admin"]);
    let cpw = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "changepw"]);
    let hist = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "history"]);
    let kip = PrincipalName::new(
        PrincipalName::NT_SRV_HST,
        ["kiprop", "testhost.kerber.test"],
    );
    let one = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["kadmin"]);
    assert!(kadm5_rpcsec_ok(&admin));
    assert!(kadm5_rpcsec_ok(&cpw));
    assert!(!kadm5_rpcsec_ok(&hist));
    assert!(!kadm5_rpcsec_ok(&kip));
    assert!(!kadm5_rpcsec_ok(&one));
    assert!(kadm5_auth_gssapi_ok(&admin));
    assert!(kadm5_auth_gssapi_ok(&cpw));
    assert!(!kadm5_auth_gssapi_ok(&hist));
    assert!(!kadm5_auth_gssapi_ok(&kip));
    assert!(iprop_rpcsec_ok(&kip));
    assert!(!iprop_rpcsec_ok(&admin));
    assert!(!iprop_rpcsec_ok(&one));
    let realm = "KERBER.TEST";
    let ctx = GssContext::for_kadm5_acceptor(admin, realm).unwrap();
    assert!(check_rpcsec_auth(&ctx, realm));
    let ctx = GssContext::for_kadm5_acceptor(hist, realm).unwrap();
    assert!(!check_rpcsec_auth(&ctx, realm));
    let ctx = GssContext::for_kadm5_acceptor(kip, realm).unwrap();
    assert!(check_iprop_rpcsec_auth(&ctx, realm));
    assert!(!check_rpcsec_auth(&ctx, realm));
}

#[test]
fn kiprop_acceptor_requires_store_realm() {
    let kip = PrincipalName::new(
        PrincipalName::NT_SRV_HST,
        ["kiprop", "testhost.kerber.test"],
    );
    let realm = "KERBER.TEST";
    assert!(acceptor_realm_ok(
        Some(&kip),
        Some(realm),
        realm,
        iprop_rpcsec_ok
    ));
    assert!(!acceptor_realm_ok(
        Some(&kip),
        Some("OTHER.REALM"),
        realm,
        iprop_rpcsec_ok
    ));
}

#[test]
fn iprop_fullresync_deny_is_fullresync_result() {
    let (store, _acl, _actor) = setup();
    let limited = Acl::parse("admin@KERBER.TEST *\nuser@KERBER.TEST i\n").expect("acl");
    let denied = dispatch_iprop(&store, &limited, "user@KERBER.TEST", IPROP_FULL_RESYNC, &[]);
    let want = encode_fullresync_status(krb5_kdc::UlogLast::default(), krb5_kdc::IPROP_PERM_DENIED);
    assert_eq!(denied, want);
    let incr = encode_incr_status(krb5_kdc::IPROP_PERM_DENIED);
    assert_ne!(denied, incr);
    let ok = dispatch_iprop(
        &store,
        &limited,
        "admin@KERBER.TEST",
        IPROP_FULL_RESYNC,
        &[],
    );
    assert_eq!(
        ok,
        encode_fullresync_status(krb5_kdc::UlogLast::default(), krb5_kdc::IPROP_OK)
    );
}

/// the history and the strings ride in `AT_TL_DATA`, without the password-change and modifier records, which go as `AT_PW_LAST_CHANGE`, `AT_MOD_PRINC` and `AT_MOD_TIME`.
#[test]
fn iprop_add_sends_mits_attributes_with_policy_history_and_strings_in_tl_data() {
    let (store, acl, actor) = setup();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["g4user"]);
    {
        let mut g = store.write().unwrap();
        let mut pol = krb5_kdc::NamedPolicy::new("g4apol");
        pol.history = 2;
        g.put_policy(pol).unwrap();
        g.create_password(&acl, &actor, &name, b"g4-secret")
            .unwrap();
        g.set_principal_policy(&name, Some("g4apol".into()))
            .unwrap();
        g.set_password(&name, b"g4-rotated").unwrap();
        g.set_string(&name, "note", Some("hello-g4a")).unwrap();
    }
    let mut p = {
        let g = store.read().unwrap();
        g.get_name(&name).unwrap().clone()
    };
    assert!(!p.key_history.is_empty());
    assert_eq!(p.string_attrs, vec![("note".into(), "hello-g4a".into())]);
    p.last_success = 111;
    p.last_failed = 222;
    p.fail_auth_count = 3;
    p.tl_data.retain(|t| t.ty != TL_LAST_PWD_CHANGE);
    p.tl_data.push(TlData {
        ty: TL_LAST_PWD_CHANGE,
        contents: 1_234u32.to_le_bytes().to_vec(),
    });
    let mk = test_master_key();
    let wrap = |raw: &[u8]| krb5_crypto::kdb_encrypt_key(&mk, raw);
    let w = krb5_kdc::encode_kdbe(
        &krb5_kdc::conv_2logentry(&p, krb5_kdc::ULOG_ADD_ATTRS),
        &wrap,
    )
    .unwrap();
    let got = krb5_kdc::decode_kdbe_bytes(&w, Some(&mk)).unwrap();
    let attrs: Vec<u32> = got.iter().map(krb5_kdc::KdbeVal::attr).collect();
    assert_eq!(
        attrs,
        [
            AT_ATTRFLAGS,
            AT_MAX_LIFE,
            AT_MAX_RENEW_LIFE,
            AT_EXP,
            AT_PW_EXP,
            AT_PRINC,
            AT_KEYDATA,
            AT_PW_LAST_CHANGE,
            AT_MOD_PRINC,
            AT_MOD_TIME,
            AT_TL_DATA,
            AT_LEN
        ]
    );
    let tl = got
        .iter()
        .find_map(|v| match v {
            krb5_kdc::KdbeVal::TlData(tl) => Some(tl.clone()),
            _ => None,
        })
        .unwrap();
    assert!(tl.iter().any(|t| t.ty == krb5_kdc::TL_KADM_DATA));
    assert!(tl.iter().any(|t| t.ty == krb5_kdc::TL_STRING_ATTRS));
    assert!(
        !tl.iter()
            .any(|t| t.ty == TL_LAST_PWD_CHANGE || t.ty == krb5_kdc::TL_MOD_PRINC)
    );
    assert!(
        got.iter()
            .any(|v| matches!(v, krb5_kdc::KdbeVal::PwLastChange(1_234)))
    );
    let mut g = store.write().unwrap();
    g.remove_in(&name, "KERBER.TEST").unwrap();
    let next = g.serial() + 1;
    g.apply_updates(&[krb5_kdc::IpropUpdate {
        sno: next,
        time: 0,
        name: p.id(),
        deleted: false,
        commit: true,
        vals: got,
        raw: Vec::new(),
    }])
    .unwrap();
    let applied = g.get_name(&name).unwrap();
    assert_eq!(applied.key_history.len(), p.key_history.len());
    assert_eq!(applied.keys[0].key.as_bytes(), p.keys[0].key.as_bytes());
    assert_eq!(applied.pw_policy.as_deref(), Some("g4apol"));
    assert_eq!(applied.kadm, p.kadm);
    assert_eq!(applied.string_attrs, p.string_attrs);
    assert_eq!(applied.fail_auth_count, 0);
    assert_eq!(applied.last_success, 0);
    assert_eq!(tl_u32(&applied.tl_data, TL_LAST_PWD_CHANGE), Some(1_234));
}

#[test]
fn kadm5_log_op_fields_match_mit_stubs() {
    assert_eq!(
        kadm5_op_name(CREATE_PRINCIPAL),
        Some("kadm5_create_principal")
    );
    assert_eq!(kadm5_op_name(GET_POLICY), Some("kadm5_get_policy"));
    assert_eq!(kadm5_op_name(INIT), None);
    let create = create_rec("newp1@KERBER.TEST", "pw");
    assert_eq!(
        kadm5_prime_arg(CREATE_PRINCIPAL, &create, "admin@KERBER.TEST"),
        "newp1@KERBER.TEST"
    );
    let mut pol = XdrW::default();
    pol.u32(API_V2);
    pol.nullstring(Some("gpol"));
    assert_eq!(
        kadm5_prime_arg(GET_POLICY, &pol.b, "admin@KERBER.TEST"),
        "gpol"
    );
    let mut nopol = XdrW::default();
    nopol.u32(API_V2);
    nopol.nullstring(None);
    assert_eq!(kadm5_prime_arg(GET_POLICY, &nopol.b, "a@R"), "(null)");
    assert_eq!(kadm5_prime_arg(GET_POLS, &nopol.b, "a@R"), "*");
}

fn test_master_key() -> ProtocolKey {
    ProtocolKey::from_bytes(krb5_crypto::EncryptionType::Aes256CtsHmacSha196, &[7; 32]).unwrap()
}

#[cfg(feature = "test-hooks")]
#[test]
fn a_key_that_does_not_wrap_is_never_sent_in_the_clear() {
    let refuse = |_: &[u8]| -> Result<Vec<u8>, ()> { Err(()) };
    let (store, acl, actor) = logging_setup();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["wrapfail"]);
    let last = store.read().unwrap().ulog_last().unwrap();
    store
        .write()
        .unwrap()
        .change(|s| s.create_password(&acl, &actor, &name, b"wrap-secret"))
        .unwrap()
        .unwrap();
    let g = store.read().unwrap();
    let p = g.get_name(&name).unwrap().clone();
    let key = p.keys[0].key.as_bytes().to_vec();
    assert!(
        krb5_kdc::encode_kdbe(
            &krb5_kdc::conv_2logentry(&p, krb5_kdc::ULOG_ADD_ATTRS),
            &refuse
        )
        .is_err()
    );
    let mk = g.iprop_master_key().unwrap();
    drop(g);
    let ok = dispatch_iprop(
        &store,
        &acl,
        &actor,
        IPROP_GET_UPDATES,
        &get_updates_args(last),
    );
    let (st, _, _, _, got) = decode_incr_result(&ok, Some(&mk)).unwrap();
    assert_eq!(st, krb5_kdc::IPROP_OK);
    assert!(!got.is_empty());
    assert!(!ok.windows(key.len()).any(|w| w == key.as_slice()));
}

#[cfg(feature = "test-hooks")]
#[test]
fn the_iprop_program_is_served_only_with_the_update_log_mapped() {
    let (store, acl, _) = setup();
    let ask = |store: &krb5_kdc::SharedDump| {
        let rec = rpc_call(5, IPROP_PROG, IPROP_VERS, IPROP_GET_UPDATES, FLAVOR_NONE);
        handle_rpc(
            RpcCtx {
                store,
                authcfg: &crate::kadm5::Kadm5AuthConfig::from_acl(acl.clone()),
                expected_realm: "KERBER.TEST",
                conf: &AcceptorConfig::default(),
                programs: Programs::BOTH,
                iprop_resync: None,
            },
            &[],
            &mut None,
            &mut None,
            &krb5_protocol::ReplayCache::new(),
            &rec,
            &peer(),
        )
        .unwrap()
    };
    let off = ask(&store);
    let mut r = XdrR::new(&off);
    assert_eq!(r.u32().unwrap(), 5);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_NONE);
    assert_eq!(r.opaque().unwrap().len(), 0);
    assert_eq!(r.u32().unwrap(), PROG_UNAVAIL, "not served with iprop off");
    store.write().unwrap().set_ulog(
        krb5_kdc::Ulog::memory(10).unwrap(),
        krb5_kdc::IpropRole::Primary,
    );
    let on = ask(&store);
    let mut r = XdrR::new(&on);
    assert_eq!(r.u32().unwrap(), 5);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_DENIED);
    assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
    assert_eq!(r.u32().unwrap(), AUTH_TOOWEAK, "dispatched with iprop on");
    let (replica, _, _) = setup();
    replica.write().unwrap().set_ulog(
        krb5_kdc::Ulog::memory(10).unwrap(),
        krb5_kdc::IpropRole::Replica,
    );
    let rep = ask(&replica);
    let mut r = XdrR::new(&rep);
    let _ = (r.u32(), r.u32(), r.u32(), r.u32(), r.opaque());
    assert_eq!(r.u32().unwrap(), PROG_UNAVAIL);
}
