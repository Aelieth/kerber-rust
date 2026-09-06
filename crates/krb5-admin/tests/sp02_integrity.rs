//! RPCSEC_GSS integrity is databody_integ + checksum (`authgss_prot.c:203-225`).

mod common;

use common::{
    API_V2, FLAVOR_GSS, GARBAGE_ARGS, GET_PRINCS, GSS_INTEGRITY, GSS_NONE, KADM_PROG, KADM_VERS,
    MSG_ACCEPTED, MSG_CALL, MSG_REPLY, RPC_VERSION, RPG_DATA, SUCCESS, call, cred, init_client,
    list_args, push_opaque, push_u32, take_opaque, take_u32,
};
use krb5_admin::{Kadm5RpcSession, kadm5_handle_rpc};
use krb5_gss::GssContext;
use krb5_kdc::{TEST_REALM, bootstrap_documented, documented_kadmin, shared_dump};
use krb5_protocol::ReplayCache;
use krb5_types::PrincipalName;

fn init_svc(
    svc: u32,
) -> (
    krb5_kdc::SharedDump,
    krb5_kdc::Acl,
    GssContext,
    Vec<u8>,
    Kadm5RpcSession,
) {
    let (store, acl) = bootstrap_documented().unwrap();
    let store = shared_dump(store);
    let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
    let c = init_client(&store, &acl, &admin, &documented_kadmin(), svc);
    (store, acl, c.ctx, c.handle, c.sess)
}

fn integ_rec(
    ctx: &mut GssContext,
    xid: u32,
    seq: u32,
    handle: &[u8],
    args: &[u8],
    tamper: bool,
) -> Vec<u8> {
    common::integ_rec(ctx, xid, seq, handle, GET_PRINCS, args, tamper)
}

#[test]
fn rpcsec_integrity_request_is_databody_plus_mic() {
    let (store, acl, mut ctx, handle, mut sess) = init_svc(GSS_INTEGRITY);
    let rec = integ_rec(&mut ctx, 40, 1, &handle, &list_args(), false);
    let out = kadm5_handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut sess,
        &ReplayCache::new(),
        &rec,
    )
    .unwrap();
    let mut i = 0;
    assert_eq!(take_u32(&out, &mut i), 40);
    assert_eq!(take_u32(&out, &mut i), MSG_REPLY);
    assert_eq!(take_u32(&out, &mut i), MSG_ACCEPTED);
    assert_eq!(take_u32(&out, &mut i), FLAVOR_GSS);
    let _ = take_opaque(&out, &mut i);
    assert_eq!(take_u32(&out, &mut i), SUCCESS);
}

#[test]
fn rpcsec_integrity_reply_is_databody_plus_mic() {
    let (store, acl, mut ctx, handle, mut sess) = init_svc(GSS_INTEGRITY);
    let rec = integ_rec(&mut ctx, 40, 1, &handle, &list_args(), false);
    let out = kadm5_handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut sess,
        &ReplayCache::new(),
        &rec,
    )
    .unwrap();
    let mut i = 0;
    assert_eq!(take_u32(&out, &mut i), 40);
    assert_eq!(take_u32(&out, &mut i), MSG_REPLY);
    assert_eq!(take_u32(&out, &mut i), MSG_ACCEPTED);
    assert_eq!(take_u32(&out, &mut i), FLAVOR_GSS);
    let verf = take_opaque(&out, &mut i);
    assert_eq!(take_u32(&out, &mut i), SUCCESS);
    ctx.verify_mic(&1u32.to_be_bytes(), verf).unwrap();
    let databody = take_opaque(&out, &mut i);
    let checksum = take_opaque(&out, &mut i);
    ctx.verify_mic(databody, checksum).unwrap();
    assert_eq!(&databody[..4], 1u32.to_be_bytes());
    assert_eq!(
        u32::from_be_bytes(databody[4..8].try_into().unwrap()),
        API_V2
    );
    assert_eq!(u32::from_be_bytes(databody[8..12].try_into().unwrap()), 0);
}

#[test]
fn rpcsec_none_service_body_is_plain() {
    let (store, acl, mut ctx, handle, mut sess) = init_svc(GSS_NONE);
    let cred = cred(RPG_DATA, 1, GSS_NONE, &handle);
    let mut header = Vec::new();
    push_u32(&mut header, 43);
    push_u32(&mut header, MSG_CALL);
    push_u32(&mut header, RPC_VERSION);
    push_u32(&mut header, KADM_PROG);
    push_u32(&mut header, KADM_VERS);
    push_u32(&mut header, GET_PRINCS);
    push_u32(&mut header, FLAVOR_GSS);
    push_opaque(&mut header, &cred);
    let mic = ctx.get_mic(&header).unwrap();
    let rec = call(43, GET_PRINCS, &cred, FLAVOR_GSS, &mic, &list_args());
    let out = kadm5_handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut sess,
        &ReplayCache::new(),
        &rec,
    )
    .unwrap();
    let mut i = 0;
    assert_eq!(take_u32(&out, &mut i), 43);
    assert_eq!(take_u32(&out, &mut i), MSG_REPLY);
    assert_eq!(take_u32(&out, &mut i), MSG_ACCEPTED);
    assert_eq!(take_u32(&out, &mut i), FLAVOR_GSS);
    let verf = take_opaque(&out, &mut i);
    assert_eq!(take_u32(&out, &mut i), SUCCESS);
    ctx.verify_mic(&1u32.to_be_bytes(), verf).unwrap();
    assert_eq!(take_u32(&out, &mut i), API_V2);
    assert_eq!(take_u32(&out, &mut i), 0);
}

#[test]
fn rpcsec_integrity_bad_checksum_is_garbage_args() {
    let (store, acl, mut ctx, handle, mut sess) = init_svc(GSS_INTEGRITY);
    let rec = integ_rec(&mut ctx, 41, 1, &handle, &list_args(), true);
    let out = kadm5_handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut sess,
        &ReplayCache::new(),
        &rec,
    )
    .unwrap();
    let mut i = 0;
    assert_eq!(take_u32(&out, &mut i), 41);
    assert_eq!(take_u32(&out, &mut i), MSG_REPLY);
    assert_eq!(take_u32(&out, &mut i), MSG_ACCEPTED);
    assert_eq!(take_u32(&out, &mut i), FLAVOR_GSS);
    let _ = take_opaque(&out, &mut i);
    assert_eq!(take_u32(&out, &mut i), GARBAGE_ARGS);
}

#[test]
fn rpcsec_wrong_handle_with_valid_mic_dispatches() {
    let (store, acl, mut ctx, _handle, mut sess) = init_svc(GSS_INTEGRITY);
    let rec = integ_rec(&mut ctx, 42, 1, b"not-the-handle", &list_args(), false);
    let out = kadm5_handle_rpc(
        &store,
        &acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut sess,
        &ReplayCache::new(),
        &rec,
    )
    .unwrap();
    let mut i = 0;
    assert_eq!(take_u32(&out, &mut i), 42);
    assert_eq!(take_u32(&out, &mut i), MSG_REPLY);
    assert_eq!(take_u32(&out, &mut i), MSG_ACCEPTED);
    assert_eq!(take_u32(&out, &mut i), FLAVOR_GSS);
    let _ = take_opaque(&out, &mut i);
    assert_eq!(take_u32(&out, &mut i), SUCCESS);
}
