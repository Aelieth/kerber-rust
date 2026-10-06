//! kadm5 iprop tests (private-bound; regrouped in place).

use super::*;

/// A store whose process maps the update log as a primary's, its keys wrapped under the stash
/// `seed_master_key` writes.
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

/// MIT `ulog_get_entries` (settled live): a replica that is not in the log is sent to a full
/// resync; one at the log's dummy entry gets the update after it, as the log stores it, keys
/// wrapped.
#[cfg(feature = "test-hooks")]
#[test]
fn iprop_get_updates_full_resync_then_delta() {
    let (store, acl, actor) = logging_setup();
    let dummy = store.read().unwrap().ulog_last().unwrap();
    assert_eq!(dummy.sno, 1);
    let first = dispatch_iprop(
        &store,
        &acl,
        &actor,
        IPROP_GET_UPDATES,
        &get_updates_args(krb5_kdc::UlogLast::default()),
    );
    let (st, last, sec, usec, entries) = decode_incr_result(&first, None).unwrap();
    assert_eq!(st, krb5_kdc::IPROP_FULL_RESYNC);
    assert_eq!((last, sec, usec), (0, 0, 0), "no last entry with a resync");
    assert!(entries.is_empty());

    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["iproprpc"]);
    {
        let mut g = store.write().unwrap();
        g.change(|s| s.create_password(&acl, &actor, &extra, b"iprop-rpc-secret"))
            .unwrap()
            .unwrap();
    }
    let out = dispatch_iprop(
        &store,
        &acl,
        &actor,
        IPROP_GET_UPDATES,
        &get_updates_args(dummy),
    );
    assert!(
        out.windows(b"iproprpc".len()).any(|w| w == b"iproprpc"),
        "GET_UPDATES delta must name the new principal"
    );
    assert!(
        out.windows(4).any(|w| w == AT_KEYDATA.to_be_bytes()),
        "kdb_incr_update_t must carry AT_KEYDATA for MIT ulog_replay"
    );
    let now = store.read().unwrap().ulog_last().unwrap();
    let (st, last2, sec2, usec2, entries) = decode_incr_result(&out, None).unwrap();
    assert_eq!(st, krb5_kdc::IPROP_OK);
    assert_eq!(
        (last2, sec2, usec2),
        (now.sno, now.time.seconds, now.time.useconds)
    );
    assert_eq!(entries.len(), 1, "one create is one update");
    assert!(entries[0].name.contains("iproprpc") && !entries[0].vals.is_empty());
    assert_eq!(entries[0].sno, now.sno);
    // Up to date: NIL.
    let nil = dispatch_iprop(
        &store,
        &acl,
        &actor,
        IPROP_GET_UPDATES,
        &get_updates_args(now),
    );
    assert_eq!(
        decode_incr_result(&nil, None).unwrap().0,
        krb5_kdc::IPROP_NIL
    );
}

// A key leaves only wrapped under the master key, which the log wraps it under as the change is
// logged; a store with no master key (no stash, no `KRB5_MASTER_PASSWORD`, no `K/M`: the
// in-memory bootstrap) cannot log a keyed change at all, so no key reaches the log or the wire.
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
fn iprop_get_updates_denies_actor_without_propagate() {
    let (store, _acl, _actor) = setup();
    let limited = Acl::parse("admin@KERBER.TEST *\nuser@KERBER.TEST i\n").expect("acl");
    let mut args = XdrW::default();
    args.u32(0);
    args.u32(0);
    args.u32(0);
    let out = dispatch_iprop(
        &store,
        &limited,
        "user@KERBER.TEST",
        IPROP_GET_UPDATES,
        &args.b,
    );
    let (st, _, _, _, entries) = decode_incr_result(&out, None).unwrap();
    assert_eq!(st, krb5_kdc::IPROP_PERM_DENIED);
    assert!(
        entries.is_empty(),
        "unauthorized GET_UPDATES must not leak ulog: {entries:?}"
    );
    let ok = dispatch_iprop(
        &store,
        &limited,
        "admin@KERBER.TEST",
        IPROP_GET_UPDATES,
        &args.b,
    );
    let (st_ok, _, _, _, _) = decode_incr_result(&ok, None).unwrap();
    assert_ne!(st_ok, krb5_kdc::IPROP_PERM_DENIED);
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
    // MIT `ipropx_resync`: granted, with a zero last entry; the dump comes by kprop.
    assert_eq!(
        ok,
        encode_fullresync_status(krb5_kdc::UlogLast::default(), krb5_kdc::IPROP_OK)
    );
}

/// MIT `ulog_conv_2logentry`: a new principal is sent as MIT sends one (settled live, kproplog
/// `-v` of an MIT `addprinc`): no lockout counters, no `AT_PW_POLICY` / `AT_PW_HIST*`; the policy,
/// the history and the strings ride in `AT_TL_DATA`, without the password-change and modifier
/// records, which go as `AT_PW_LAST_CHANGE`, `AT_MOD_PRINC` and `AT_MOD_TIME`.
#[test]
fn iprop_add_sends_mits_attributes_with_policy_history_and_strings_in_tl_data() {
    let (store, acl, actor) = setup();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["g4user"]);
    {
        let mut g = store.write().unwrap();
        let mut pol = krb5_kdc::NamedPolicy::new("g4apol");
        pol.history = 2;
        g.put_policy(pol);
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
    // A replica decrypts the history under its own kadmin/history once the update is applied.
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
fn iprop_decode_caps_hostile_wire_counts() {
    let mut princ = XdrW::default();
    princ.u32(1);
    princ.u32(AT_PRINC);
    princ.opaque(b"KERBER.TEST");
    princ.u32(u32::MAX);
    assert!(
        krb5_kdc::decode_kdbe_bytes(&princ.b, None).is_err(),
        "huge principal-component count must not pre-alloc"
    );
    let mut keys = XdrW::default();
    keys.u32(1);
    keys.u32(AT_KEYDATA);
    keys.u32(1);
    keys.u32(2);
    keys.u32(1);
    keys.u32(u32::MAX);
    assert!(
        krb5_kdc::decode_kdbe_bytes(&keys.b, None).is_err(),
        "huge keydata slot count must not pre-alloc"
    );
}

#[test]
fn iprop_kdbe_omits_internal_kerber_tl() {
    let (store, _, _) = setup();
    let mut p = {
        let g = store.read().unwrap();
        g.krbtgt().unwrap().clone()
    };
    p.tl_data.push(TlData {
        ty: krb5_kdc::TL_KERBER_SID,
        contents: vec![1, 2, 3, 4],
    });
    p.tl_data.push(TlData {
        ty: krb5_kdc::TL_KERBER_SERIAL,
        contents: 9u32.to_be_bytes().to_vec(),
    });
    let mk = test_master_key();
    let wrap = |raw: &[u8]| krb5_crypto::kdb_encrypt_key(&mk, raw);
    let w = krb5_kdc::encode_kdbe(
        &krb5_kdc::conv_2logentry(&p, krb5_kdc::ULOG_ADD_ATTRS),
        &wrap,
    )
    .unwrap();
    assert!(
        !w.windows(4).any(|w| w == 0x4B01u32.to_be_bytes()),
        "incremental kdbe must not emit TL_KERBER_SID"
    );
    assert!(
        !w.windows(4).any(|w| w == 0x4B03u32.to_be_bytes()),
        "incremental kdbe must not emit TL_KERBER_SERIAL"
    );
    let got = krb5_kdc::decode_kdbe_bytes(&w, Some(&mk)).unwrap();
    assert!(!got.iter().any(|v| matches!(
        v,
        krb5_kdc::KdbeVal::TlData(tl)
            if tl.iter().any(|t| t.ty == krb5_kdc::TL_KERBER_SID || t.ty == krb5_kdc::TL_KERBER_SERIAL)
    )));
}

#[test]
fn kadm5_log_op_fields_match_mit_stubs() {
    // MIT server_stubs.c op strings and prime_arg: the unparsed principal for a create, the
    // name for a policy.
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

/// The lines MIT 1.22.2 kadmind wrote in the live settle, for the same requests.
#[test]
fn kadm5_log_lines_match_mit_live() {
    let admin = Caller {
        client: "admin/admin@SETTLE.TEST",
        service: "kadmin/admin@SETTLE.TEST",
        addr: "127.0.0.1",
        flavor: FLAVOR_GSS,
    };
    let alice = Caller {
        client: "alice@SETTLE.TEST",
        ..admin
    };
    let tail = "service=kadmin/admin@SETTLE.TEST, addr=127.0.0.1";
    let ret = |code: u32| generic_ret(API_V2, code);
    let mut init = XdrW::default();
    init.u32(API_V4);
    assert_eq!(
        kadm5_log_lines(INIT, &init.b, &admin, &ret(0)),
        [format!(
            "Request: kadm5_init, admin/admin@SETTLE.TEST, success, \
             client=admin/admin@SETTLE.TEST, {tail}, vers=4, flavor=6"
        )]
    );
    let bob = create_rec("bob@SETTLE.TEST", "pw");
    assert_eq!(
        kadm5_log_lines(CREATE_PRINCIPAL, &bob, &admin, &ret(0)),
        [format!(
            "Request: kadm5_create_principal, bob@SETTLE.TEST, success, \
             client=admin/admin@SETTLE.TEST, {tail}"
        )]
    );
    assert_eq!(
        kadm5_log_lines(CREATE_PRINCIPAL, &bob, &admin, &ret(KADM5_DUP)),
        [format!(
            "Request: kadm5_create_principal, bob@SETTLE.TEST, Principal or policy already \
             exists, client=admin/admin@SETTLE.TEST, {tail}"
        )]
    );
    assert_eq!(
        kadm5_log_lines(CREATE_PRINCIPAL, &bob, &admin, &ret(KRB5_KDB_CANTLOCK_DB)),
        [format!(
            "Request: kadm5_create_principal, bob@SETTLE.TEST, Insufficient access to lock \
             database, client=admin/admin@SETTLE.TEST, {tail}"
        )]
    );
    let dave = create_rec("dave@SETTLE.TEST", "pw");
    assert_eq!(
        kadm5_log_lines(CREATE_PRINCIPAL, &dave, &alice, &ret(KADM5_AUTH_ADD)),
        [format!(
            "Unauthorized request: kadm5_create_principal, dave@SETTLE.TEST, \
             client=alice@SETTLE.TEST, {tail}"
        )]
    );
    let mut default_pol = XdrW::default();
    default_pol.u32(API_V2);
    default_pol.nullstring(Some("default"));
    assert_eq!(
        kadm5_log_lines(GET_POLICY, &default_pol.b, &alice, &ret(KADM5_AUTH_GET)),
        [format!(
            "Unauthorized request: kadm5_get_policy, default, client=alice@SETTLE.TEST, {tail}"
        )]
    );
    assert_eq!(
        kadm5_log_lines(GET_POLICY, &default_pol.b, &admin, &ret(KADM5_UNK_POLICY)),
        [format!(
            "Request: kadm5_get_policy, default, Policy does not exist, \
             client=admin/admin@SETTLE.TEST, {tail}"
        )]
    );
    // A get of a missing principal fails in stub_setup and logs nothing.
    assert_eq!(
        kadm5_log_lines(
            GET_PRINCIPAL,
            &getprinc_args("nosuch@SETTLE.TEST"),
            &admin,
            &ret(KADM5_UNK_PRINC)
        ),
        Vec::<String>::new()
    );
    let mut list = XdrW::default();
    list.u32(API_V2);
    list.nullstring(Some("b*"));
    assert_eq!(
        kadm5_log_lines(GET_PRINCS, &list.b, &admin, &ret(0)),
        [format!(
            "Request: kadm5_get_principals, b*, success, client=admin/admin@SETTLE.TEST, {tail}"
        )]
    );
    let mut privs = XdrW::default();
    privs.u32(API_V2);
    assert_eq!(
        kadm5_log_lines(GET_PRIVS, &privs.b, &admin, &ret(0)),
        [format!(
            "Request: kadm5_get_privs, admin/admin@SETTLE.TEST, success, \
             client=admin/admin@SETTLE.TEST, {tail}"
        )]
    );
    let mut rename = XdrW::default();
    rename.u32(API_V2);
    rename.nullstring(Some("bob@SETTLE.TEST"));
    rename.nullstring(Some("carol@SETTLE.TEST"));
    assert_eq!(
        kadm5_log_lines(RENAME_PRINCIPAL, &rename.b, &admin, &ret(0)),
        [format!(
            "Request: kadm5_rename_principal, bob@SETTLE.TEST to carol@SETTLE.TEST, success, \
             client=admin/admin@SETTLE.TEST, {tail}"
        )]
    );
    assert_eq!(
        kadm5_log_lines(
            RENAME_PRINCIPAL,
            &rename.b,
            &alice,
            &ret(KADM5_AUTH_INSUFFICIENT)
        ),
        [
            format!(
                "Unauthorized request: kadm5_rename_principal, bob@SETTLE.TEST, \
                 client=alice@SETTLE.TEST, {tail}"
            ),
            format!(
                "Unauthorized request: kadm5_rename_principal, bob@SETTLE.TEST to \
                 carol@SETTLE.TEST, client=alice@SETTLE.TEST, {tail}"
            ),
        ]
    );
    // A self password change without an initial ticket is a Request line, not Unauthorized.
    assert_eq!(
        kadm5_log_lines(
            CHPASS_PRINCIPAL,
            &chpass_args("alice@SETTLE.TEST", "x"),
            &alice,
            &ret(KADM5_AUTH_INITIAL)
        ),
        [format!(
            "Request: kadm5_chpass_principal, alice@SETTLE.TEST, Operation requires initial \
             ticket, client=alice@SETTLE.TEST, {tail}"
        )]
    );
    assert_eq!(kadm5_error_text(13), "Permission denied");
    assert_eq!(kadm5_error_text(EINVAL), "Invalid argument");
}

fn test_master_key() -> ProtocolKey {
    ProtocolKey::from_bytes(krb5_crypto::EncryptionType::Aes256CtsHmacSha196, &[7; 32]).unwrap()
}

/// A key leaves only wrapped under the master key: an update whose key does not wrap is not
/// encoded at all, and a logged update's key bytes are nowhere in the GET_UPDATES reply.
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

/// MIT `setup_loop`: the iprop program is registered only with `iprop_enable` (MIT 1.22.2 answers
/// PROG_UNAVAIL on the kadmind port while it is off, and dispatches once it is on, where an
/// AUTH_NONE call is AUTH_TOOWEAK); here it is served only while the update log is mapped as a
/// primary's. AUTH_GSSAPI's own INIT is answered either way (auth before the program lookup).
#[cfg(feature = "test-hooks")]
#[test]
fn the_iprop_program_is_served_only_with_the_update_log_mapped() {
    let (store, acl, _) = setup();
    let ask = |store: &krb5_kdc::SharedDump| {
        let rec = rpc_call(5, IPROP_PROG, IPROP_VERS, IPROP_GET_UPDATES, FLAVOR_NONE);
        handle_rpc(
            RpcCtx {
                store,
                acl: &acl,
                service_keys: &[],
                expected_realm: "KERBER.TEST",
            },
            &[],
            &mut None,
            &mut None,
            &krb5_protocol::ReplayCache::new(),
            &rec,
            "127.0.0.1",
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
    // A replica's log does not serve the program: only a primary's does.
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
