//! kadm5 iprop tests (private-bound; regrouped in place).

use super::*;

#[test]
fn iprop_get_updates_full_resync_then_delta() {
    let (store, acl, actor) = setup();
    seed_master_key(&store);
    let last = {
        let g = store.read().unwrap();
        g.serial()
    };
    let mut args = XdrW::default();
    args.u32(0);
    args.u32(0);
    args.u32(0);
    let first = dispatch_iprop(&store, &acl, &actor, IPROP_GET_UPDATES, &args.b);
    let mut r = XdrR::new(&first);
    let sno = r.u32().unwrap();
    assert!(sno >= last);
    r.u32().unwrap();
    r.u32().unwrap();
    let n = r.u32().unwrap();
    for _ in 0..n {
        let _ = r.opaque();
        let _ = r.u32();
        let _ = r.u32();
        let _ = r.u32();
        let _ = r.u32();
        let _ = r.u32();
        let _ = r.u32();
        let _ = r.u32();
        let _ = r.u32();
    }
    assert_eq!(r.u32().unwrap(), krb5_kdc::IPROP_FULL_RESYNC);

    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["iproprpc"]);
    {
        let mut g = store.write().unwrap();
        g.create_password(&acl, &actor, &extra, b"iprop-rpc-secret")
            .unwrap();
    }
    let mut delta = XdrW::default();
    delta.u32(last);
    delta.u32(0);
    delta.u32(0);
    let out = dispatch_iprop(&store, &acl, &actor, IPROP_GET_UPDATES, &delta.b);
    assert!(
        out.windows(b"iproprpc".len()).any(|w| w == b"iproprpc"),
        "GET_UPDATES delta must name the new principal"
    );
    assert!(
        out.windows(4).any(|w| w == AT_KEYDATA.to_be_bytes()),
        "kdb_incr_update_t must carry AT_KEYDATA for MIT ulog_replay"
    );
    let mut d = XdrR::new(&out);
    let _ = d.u32().unwrap();
    let _ = d.u32().unwrap();
    let _ = d.u32().unwrap();
    assert!(d.u32().unwrap() >= 1);

    let (st, last2, _, _, entries) = decode_incr_result(&out, None).unwrap();
    assert_eq!(st, krb5_kdc::IPROP_OK);
    assert!(last2 >= last);
    assert!(
        entries
            .iter()
            .any(|e| e.name.contains("iproprpc") && e.princ.is_some()),
        "decode must recover the new principal: {entries:?}"
    );
}

// MIT ships each key as the master-key ciphertext it already stores
// (`kdb_convert.c`); the Rust store holds plaintext, so with no master key
// the GET_UPDATES encoder must answer UPDATE_ERROR rather than send the
// keys in the clear. A store with no stash, no `KRB5_MASTER_PASSWORD` and
// no `K/M` principal (the default in-memory bootstrap) is exactly that.
#[test]
fn iprop_get_updates_refuses_plaintext_keys_without_master_key() {
    let (store, acl, actor) = setup();
    assert!(
        store.read().unwrap().iprop_master_key().is_none(),
        "the bootstrap store must have no master key for this test"
    );
    let last = store.read().unwrap().serial();
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["plainkey"]);
    {
        let mut g = store.write().unwrap();
        g.create_password(&acl, &actor, &extra, b"plain-secret")
            .unwrap();
    }
    let mut delta = XdrW::default();
    delta.u32(last);
    delta.u32(0);
    delta.u32(0);
    let out = dispatch_iprop(&store, &acl, &actor, IPROP_GET_UPDATES, &delta.b);
    let (st, _, _, _, entries) = decode_incr_result(&out, None).unwrap();
    assert_eq!(
        st,
        krb5_kdc::IPROP_ERROR,
        "no master key must yield UPDATE_ERROR, not a keyed reply"
    );
    assert!(entries.is_empty(), "the error reply ships no entries");
    assert!(
        !out.windows(4).any(|w| w == AT_KEYDATA.to_be_bytes()),
        "the reply must carry no AT_KEYDATA"
    );
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
    let want = encode_fullresync_status(0, krb5_kdc::IPROP_PERM_DENIED);
    assert_eq!(denied, want);
    let incr = encode_incr_result(krb5_kdc::IPROP_PERM_DENIED, 0, &[], None);
    assert_ne!(denied, incr);
    let ok = dispatch_iprop(
        &store,
        &limited,
        "admin@KERBER.TEST",
        IPROP_FULL_RESYNC,
        &[],
    );
    assert_eq!(ok, encode_fullresync(store.read().unwrap().serial()));
}

#[test]
fn iprop_kdbe_round_trips_string_attrs_history_policy_lockout() {
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
    let mut w = XdrW::default();
    encode_kdbe(&mut w, &p, None);
    let mut r = XdrR::new(&w.b);
    let got = decode_kdbe(&mut r, None, &p.id()).unwrap().unwrap();
    assert_eq!(got.string_attrs, p.string_attrs);
    // History travels as the stored entries under the history key
    // (AT_PW_HIST / AT_PW_HIST_KVNO); the replica decrypts them once the
    // update is applied beside its kadmin/history.
    assert_eq!(got.kadm, p.kadm);
    assert!(got.key_history.is_empty());
    {
        let mut g = store.write().unwrap();
        let next = g.serial() + 1;
        g.apply_updates(&[krb5_kdc::UlogEntry {
            sno: next,
            time: 0,
            name: p.id(),
            deleted: false,
            princ: Some(got.clone()),
        }]);
        let applied = g.get_name(&name).unwrap();
        assert_eq!(applied.key_history.len(), p.key_history.len());
    }
    assert_eq!(got.keys[0].key.as_bytes(), p.keys[0].key.as_bytes());
    assert_eq!(got.pw_policy.as_deref(), Some("g4apol"));
    assert_eq!(got.last_success, 111);
    assert_eq!(got.last_failed, 222);
    assert_eq!(got.fail_auth_count, 3);
    assert_eq!(tl_u32(&got.tl_data, TL_LAST_PWD_CHANGE), Some(1_234));
    assert!(
        !got.string_attrs.is_empty(),
        "incremental kdbe must carry string_attrs"
    );
}

#[test]
fn iprop_decode_caps_hostile_wire_counts() {
    let mut princ = XdrW::default();
    princ.u32(1);
    princ.u32(AT_PRINC);
    princ.opaque(b"KERBER.TEST");
    princ.u32(u32::MAX);
    let mut r = XdrR::new(&princ.b);
    assert!(
        decode_kdbe(&mut r, None, "hostile@KERBER.TEST").is_err(),
        "huge principal-component count must not pre-alloc"
    );
    let mut keys = XdrW::default();
    keys.u32(1);
    keys.u32(AT_KEYDATA);
    keys.u32(1);
    keys.u32(2);
    keys.u32(1);
    keys.u32(u32::MAX);
    let mut r = XdrR::new(&keys.b);
    assert!(
        decode_kdbe(&mut r, None, "hostile@KERBER.TEST").is_err(),
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
    let mut w = XdrW::default();
    encode_kdbe(&mut w, &p, None);
    assert!(
        !w.b.windows(4).any(|w| w == 0x4B01u32.to_be_bytes()),
        "incremental kdbe must not emit TL_KERBER_SID"
    );
    assert!(
        !w.b.windows(4).any(|w| w == 0x4B03u32.to_be_bytes()),
        "incremental kdbe must not emit TL_KERBER_SERIAL"
    );
    let mut r = XdrR::new(&w.b);
    let got = decode_kdbe(&mut r, None, &p.id()).unwrap().unwrap();
    assert!(
        !got.tl_data
            .iter()
            .any(|t| t.ty == krb5_kdc::TL_KERBER_SID || t.ty == krb5_kdc::TL_KERBER_SERIAL)
    );
}

#[test]
fn kadm5_log_op_fields_match_mit_stubs() {
    // MIT server_stubs.c op strings and the ACL-denial classification.
    assert_eq!(
        kadm5_op_name(CREATE_PRINCIPAL),
        Some("kadm5_create_principal")
    );
    assert_eq!(kadm5_op_name(GET_POLICY), Some("kadm5_get_policy"));
    assert_eq!(kadm5_op_name(INIT), None);
    assert!(kadm5_auth_denied(KADM5_AUTH_ADD));
    assert!(!kadm5_auth_denied(0));
    // prime_arg is the unparsed principal for a create, the name for a policy.
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
}
