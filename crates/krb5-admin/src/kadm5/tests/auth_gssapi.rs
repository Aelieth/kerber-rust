//! kadm5 auth_gssapi tests (private-bound; regrouped in place).

use super::*;

#[test]
fn auth_gssapi_on_iprop_data_is_auth_failed() {
    let (store, acl, _) = setup();
    let mut cred = XdrW::default();
    cred.u32(AUTH_GSSAPI_CREDS_VERS);
    cred.u32(0);
    cred.opaque(&[]);
    let mut w = XdrW::default();
    w.u32(11);
    w.u32(MSG_CALL);
    w.u32(RPC_VERSION);
    w.u32(IPROP_PROG);
    w.u32(IPROP_VERS);
    w.u32(IPROP_GET_UPDATES);
    w.u32(FLAVOR_AUTH_GSSAPI);
    w.opaque(&cred.b);
    w.u32(FLAVOR_NONE);
    w.opaque(&[]);
    let mut gss = None;
    let mut agss = None;
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            acl: &acl,
            service_keys: &[],
            expected_realm: "KERBER.TEST",
        },
        &[],
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &w.b,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 11);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_DENIED);
    assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
    assert_eq!(r.u32().unwrap(), AUTH_FAILED);
}

#[test]
fn auth_gssapi_on_iprop_init_is_success() {
    let (store, acl, _) = setup();
    let mut cred = XdrW::default();
    cred.u32(AUTH_GSSAPI_CREDS_VERS);
    cred.u32(1);
    cred.opaque(&[]);
    let mut args = XdrW::default();
    args.u32(2);
    args.opaque(&[]);
    let mut w = XdrW::default();
    w.u32(12);
    w.u32(MSG_CALL);
    w.u32(RPC_VERSION);
    w.u32(IPROP_PROG);
    w.u32(IPROP_VERS);
    w.u32(AUTH_GSSAPI_INIT);
    w.u32(FLAVOR_AUTH_GSSAPI);
    w.opaque(&cred.b);
    w.u32(FLAVOR_NONE);
    w.opaque(&[]);
    w.b.extend_from_slice(&args.b);
    let mut gss = None;
    let mut agss = None;
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            acl: &acl,
            service_keys: &[],
            expected_realm: "KERBER.TEST",
        },
        &[],
        &mut gss,
        &mut agss,
        &krb5_protocol::ReplayCache::new(),
        &w.b,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 12);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_NONE);
    let _verf = r.opaque().unwrap();
    assert_eq!(r.u32().unwrap(), SUCCESS);
}

#[test]
fn auth_gssapi_destroy_on_iprop_is_auth_layer() {
    use krb5_kdc::testrealm::TEST_REALM;

    let (store, acl, _ctx, token, kadm_key, _session) = admin_gss_token();
    let mut cred = XdrW::default();
    cred.u32(AUTH_GSSAPI_CREDS_VERS);
    cred.u32(1);
    cred.opaque(&[]);
    let mut args = XdrW::default();
    args.u32(2);
    args.opaque(&token);
    let mut w = XdrW::default();
    w.u32(13);
    w.u32(MSG_CALL);
    w.u32(RPC_VERSION);
    w.u32(IPROP_PROG);
    w.u32(IPROP_VERS);
    w.u32(AUTH_GSSAPI_INIT);
    w.u32(FLAVOR_AUTH_GSSAPI);
    w.opaque(&cred.b);
    w.u32(FLAVOR_NONE);
    w.opaque(&[]);
    w.b.extend_from_slice(&args.b);
    let mut gss = None;
    let mut agss = None;
    let keys = [kadm_key];
    let rc = krb5_protocol::ReplayCache::new();
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            acl: &acl,
            service_keys: &keys,
            expected_realm: TEST_REALM,
        },
        b"hdl",
        &mut gss,
        &mut agss,
        &rc,
        &w.b,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 13);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert!(agss.is_some());
    let mut dcred = XdrW::default();
    dcred.u32(AUTH_GSSAPI_CREDS_VERS);
    dcred.u32(1);
    dcred.opaque(&1u32.to_le_bytes());
    let mut d = XdrW::default();
    d.u32(14);
    d.u32(MSG_CALL);
    d.u32(RPC_VERSION);
    d.u32(IPROP_PROG);
    d.u32(IPROP_VERS);
    d.u32(AUTH_GSSAPI_DESTROY);
    d.u32(FLAVOR_AUTH_GSSAPI);
    d.opaque(&dcred.b);
    d.u32(FLAVOR_NONE);
    d.opaque(&[]);
    let out = handle_rpc(
        RpcCtx {
            store: &store,
            acl: &acl,
            service_keys: &keys,
            expected_realm: TEST_REALM,
        },
        b"hdl",
        &mut gss,
        &mut agss,
        &rc,
        &d.b,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 14);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert!(agss.is_none());
}

#[test]
fn auth_gssapi_creds_and_init_res_xdr() {
    let mut w = XdrW::default();
    w.u32(2);
    w.u32(1); // auth_msg TRUE
    w.opaque(&[]);
    let mut r = XdrR::new(&w.b);
    assert_eq!(r.u32().unwrap(), 2);
    assert!(r.bool().unwrap());
    assert_eq!(r.opaque().unwrap(), [] as [u8; 0]);

    let mut body = XdrW::default();
    encode_init_res(&mut body, 4, &1u32.to_le_bytes(), 0, 0, b"tok", b"isn");
    let mut r = XdrR::new(&body.b);
    assert_eq!(r.u32().unwrap(), 4);
    assert_eq!(r.opaque().unwrap(), 1u32.to_le_bytes());
    assert_eq!(r.u32().unwrap(), 0);
    assert_eq!(r.u32().unwrap(), 0);
    assert_eq!(r.opaque().unwrap(), b"tok");
    assert_eq!(r.opaque().unwrap(), b"isn");
}

#[test]
fn kadm5_auth_gssapi_ok_requires_store_realm() {
    let admin = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "admin"]);
    let realm = "KERBER.TEST";
    assert!(acceptor_realm_ok(
        Some(&admin),
        Some(realm),
        realm,
        kadm5_auth_gssapi_ok
    ));
    assert!(!acceptor_realm_ok(
        Some(&admin),
        Some("OTHER.REALM"),
        realm,
        kadm5_auth_gssapi_ok
    ));
}

/// An established AUTH_GSSAPI call on the iprop program is authenticated first: without iprop
/// the program is not registered, so the call is PROG_UNAVAIL under its verifier (MIT
/// `svc_do_xprt`); once the update log is mapped the iprop dispatcher refuses the flavor.
#[cfg(feature = "test-hooks")]
#[test]
fn an_established_auth_gssapi_call_on_iprop_is_prog_unavail_until_iprop_is_on() {
    use krb5_kdc::testrealm::TEST_REALM;

    let (store, acl, mut ctx, token, kadm_key, session) = admin_gss_token();
    let keys = [kadm_key];
    let rc = krb5_protocol::ReplayCache::new();
    let mut gss = None;
    let mut agss = None;
    let call = |xid: u32, proc: u32, cred: &[u8], verf: (u32, &[u8]), args: &[u8]| {
        let mut w = XdrW::default();
        w.u32(xid);
        w.u32(MSG_CALL);
        w.u32(RPC_VERSION);
        w.u32(IPROP_PROG);
        w.u32(IPROP_VERS);
        w.u32(proc);
        w.u32(FLAVOR_AUTH_GSSAPI);
        w.opaque(cred);
        w.u32(verf.0);
        w.opaque(verf.1);
        w.b.extend_from_slice(args);
        w.b
    };
    let mut init_cred = XdrW::default();
    init_cred.u32(AUTH_GSSAPI_CREDS_VERS);
    init_cred.u32(1);
    init_cred.opaque(&[]);
    let mut init_args = XdrW::default();
    init_args.u32(2);
    init_args.opaque(&token);
    let rec = call(
        21,
        AUTH_GSSAPI_INIT,
        &init_cred.b,
        (FLAVOR_NONE, &[]),
        &init_args.b,
    );
    let ctx_for = |store| RpcCtx {
        store,
        acl: &acl,
        service_keys: &keys,
        expected_realm: TEST_REALM,
    };
    let out = handle_rpc(
        ctx_for(&store),
        b"hdl",
        &mut gss,
        &mut agss,
        &rc,
        &rec,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 21);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_NONE);
    let _ = r.opaque().unwrap();
    assert_eq!(r.u32().unwrap(), SUCCESS);
    let _version = r.u32().unwrap();
    let handle = r.opaque().unwrap();
    assert_eq!((r.u32().unwrap(), r.u32().unwrap()), (0, 0));
    let out_tok = r.opaque().unwrap();
    let signed_isn = r.opaque().unwrap();
    if !out_tok.is_empty() {
        ctx.process_ap_rep(&out_tok, &session).unwrap();
    }
    let isn = ctx.unwrap(&signed_isn).unwrap();
    let seq = u32::from_be_bytes(isn[..4].try_into().unwrap());
    let mut data_cred = XdrW::default();
    data_cred.u32(AUTH_GSSAPI_CREDS_VERS);
    data_cred.u32(0);
    data_cred.opaque(&handle);
    let mut data_args = XdrW::default();
    data_args.opaque(b"not read");
    let verf = ctx.wrap_integ(&seq.wrapping_add(1).to_be_bytes()).unwrap();
    let rec = call(
        22,
        IPROP_GET_UPDATES,
        &data_cred.b,
        (FLAVOR_AUTH_GSSAPI, &verf),
        &data_args.b,
    );
    let out = handle_rpc(
        ctx_for(&store),
        b"hdl",
        &mut gss,
        &mut agss,
        &rc,
        &rec,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 22);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_ACCEPTED);
    assert_eq!(r.u32().unwrap(), FLAVOR_AUTH_GSSAPI);
    let reply_verf = r.opaque().unwrap();
    assert_eq!(
        ctx.unwrap(&reply_verf).unwrap(),
        seq.wrapping_add(2).to_be_bytes()
    );
    assert_eq!(r.u32().unwrap(), PROG_UNAVAIL, "not served with iprop off");
    store.write().unwrap().set_ulog(
        krb5_kdc::Ulog::memory(10).unwrap(),
        krb5_kdc::IpropRole::Primary,
    );
    let verf = ctx.wrap_integ(&seq.wrapping_add(3).to_be_bytes()).unwrap();
    let rec = call(
        23,
        IPROP_GET_UPDATES,
        &data_cred.b,
        (FLAVOR_AUTH_GSSAPI, &verf),
        &data_args.b,
    );
    let out = handle_rpc(
        ctx_for(&store),
        b"hdl",
        &mut gss,
        &mut agss,
        &rc,
        &rec,
        "127.0.0.1",
    )
    .unwrap();
    let mut r = XdrR::new(&out);
    assert_eq!(r.u32().unwrap(), 23);
    assert_eq!(r.u32().unwrap(), MSG_REPLY);
    assert_eq!(r.u32().unwrap(), MSG_DENIED);
    assert_eq!(r.u32().unwrap(), REJECT_AUTH_ERROR);
    assert_eq!(r.u32().unwrap(), AUTH_TOOWEAK, "dispatched with iprop on");
}
