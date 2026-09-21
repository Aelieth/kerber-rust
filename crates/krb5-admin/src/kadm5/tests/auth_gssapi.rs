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
        &store,
        &acl,
        &[],
        "KERBER.TEST",
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
        &store,
        &acl,
        &[],
        "KERBER.TEST",
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
        &store,
        &acl,
        &keys,
        TEST_REALM,
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
        &store,
        &acl,
        &keys,
        TEST_REALM,
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
    assert!(r.opaque().unwrap().is_empty());

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
