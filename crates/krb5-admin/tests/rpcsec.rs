//! RPCSEC DATA without a context is MIT `CREDPROBLEM` (connection kept).
//! RPCSEC_GSS `gc_v` mismatch is MIT `AUTH_BADCRED` (connection kept).
//! RPCSEC_GSS integrity is databody_integ + checksum (`authgss_prot.c:203-225`).
//! AUTH_NONE unknown program is MIT `svcerr_prog_unavail` (connection kept).
//! AUTH_GSSAPI INIT on IPROP_PROG is auth-layer SUCCESS (`no_dispatch`).
//! the AUTH_GSSAPI `GSSAPI_INIT` arg-version switch
//! (`lib/rpc/svc_auth_gssapi.c:326-341`): versions 1 and 2 are answered with
//! `call_res.version` 1 (the OpenVision compat downgrade), 3 and 4 are
//! echoed, anything else is `AUTH_BADCRED` before the token is looked at.
//! Compiles at `59c363b` (parent-red): the parent echoed every version and
//! answered version 5 with an accepted `init_res`.

#[path = "common/mod.rs"]
mod common;
use common::*;

use krb5_admin::{Kadm5RpcSession, kadm5_handle_rpc, serve_kadm5_conn};
use krb5_gss::GssContext;
use krb5_kdc::principals::kadmin_admin;
use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented};
use krb5_kdc::{Acl, shared_dump};

use krb5_protocol::ReplayCache;
use krb5_types::PrincipalName;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

const LAST_FRAG: u32 = 0x8000_0000;

const MSG_DENIED: u32 = 1;

const REJECT_AUTH_ERROR: u32 = 1;

const GSS_PRIVACY: u32 = 3;

const RPCSEC_GSS_CREDPROBLEM: u32 = 13;

fn words(buf: &[u8]) -> Vec<u32> {
    buf.as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_be_bytes(*c))
        .collect()
}

#[test]
fn rpcsec_data_without_context_is_credproblem() {
    let (store, acl) = bootstrap_documented().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let store = shared_dump(store);
    thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        let _ = serve_kadm5_conn(
            store,
            acl,
            Vec::new(),
            "KERBER.TEST".into(),
            ReplayCache::new(),
            s,
        );
    });
    let mut cred = Vec::new();
    push_u32(&mut cred, RPCSEC_GSS_VERS);
    push_u32(&mut cred, RPG_DATA);
    push_u32(&mut cred, 1);
    push_u32(&mut cred, GSS_PRIVACY);
    push_u32(&mut cred, 0);
    let mut body = Vec::new();
    push_u32(&mut body, 14);
    push_u32(&mut body, MSG_CALL);
    push_u32(&mut body, RPC_VERSION);
    push_u32(&mut body, KADM_PROG);
    push_u32(&mut body, KADM_VERS);
    push_u32(&mut body, 12);
    push_u32(&mut body, FLAVOR_GSS);
    push_u32(&mut body, u32::try_from(cred.len()).unwrap());
    body.extend_from_slice(&cred);
    push_u32(&mut body, 0);
    push_u32(&mut body, 0);
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let n = u32::try_from(body.len()).unwrap() | LAST_FRAG;
    c.write_all(&n.to_be_bytes()).unwrap();
    c.write_all(&body).unwrap();
    let mut hdr = [0u8; 4];
    c.read_exact(&mut hdr)
        .expect("CREDPROBLEM reply kept the connection");
    let len = (u32::from_be_bytes(hdr) & !LAST_FRAG) as usize;
    let mut rec = vec![0u8; len];
    c.read_exact(&mut rec).unwrap();
    let w = words(&rec);
    assert_eq!(w[0], 14);
    assert_eq!(w[1], MSG_REPLY);
    assert_eq!(w[2], MSG_DENIED);
    assert_eq!(w[3], REJECT_AUTH_ERROR);
    assert_eq!(w[4], RPCSEC_GSS_CREDPROBLEM);
}

const AUTH_BADCRED: u32 = 1;

#[test]
fn rpcsec_bad_version_is_auth_badcred() {
    let (store, acl) = bootstrap_documented().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let store = shared_dump(store);
    thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        let _ = serve_kadm5_conn(
            store,
            acl,
            Vec::new(),
            "KERBER.TEST".into(),
            ReplayCache::new(),
            s,
        );
    });
    let mut cred = Vec::new();
    push_u32(&mut cred, 99);
    push_u32(&mut cred, 1);
    push_u32(&mut cred, 0);
    push_u32(&mut cred, 0);
    let mut body = Vec::new();
    push_u32(&mut body, 42);
    push_u32(&mut body, MSG_CALL);
    push_u32(&mut body, RPC_VERSION);
    push_u32(&mut body, KADM_PROG);
    push_u32(&mut body, KADM_VERS);
    push_u32(&mut body, 0);
    push_u32(&mut body, FLAVOR_GSS);
    push_u32(&mut body, u32::try_from(cred.len()).unwrap());
    body.extend_from_slice(&cred);
    push_u32(&mut body, 0);
    push_u32(&mut body, 0);
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let n = u32::try_from(body.len()).unwrap() | LAST_FRAG;
    c.write_all(&n.to_be_bytes()).unwrap();
    c.write_all(&body).unwrap();
    let mut hdr = [0u8; 4];
    c.read_exact(&mut hdr)
        .expect("AUTH_BADCRED reply kept the connection");
    let len = (u32::from_be_bytes(hdr) & !LAST_FRAG) as usize;
    let mut rec = vec![0u8; len];
    c.read_exact(&mut rec).unwrap();
    let w = words(&rec);
    assert_eq!(w[0], 42);
    assert_eq!(w[1], MSG_REPLY);
    assert_eq!(w[2], MSG_DENIED);
    assert_eq!(w[3], REJECT_AUTH_ERROR);
    assert_eq!(w[4], AUTH_BADCRED);
}

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
    let c = init_client(&store, &acl, &admin, &kadmin_admin(), svc);
    (store, acl, c.ctx, c.handle, c.sess)
}

fn integ_rec_rpcsec(
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
    let rec = integ_rec_rpcsec(&mut ctx, 40, 1, &handle, &list_args(), false);
    let out = kadm5_handle_rpc(
        krb5_admin::RpcCtx {
            store: &store,
            acl: &acl,
            service_keys: &[],
            expected_realm: TEST_REALM,
        },
        b"hdl",
        &mut sess,
        &ReplayCache::new(),
        &rec,
        "127.0.0.1",
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
    let rec = integ_rec_rpcsec(&mut ctx, 40, 1, &handle, &list_args(), false);
    let out = kadm5_handle_rpc(
        krb5_admin::RpcCtx {
            store: &store,
            acl: &acl,
            service_keys: &[],
            expected_realm: TEST_REALM,
        },
        b"hdl",
        &mut sess,
        &ReplayCache::new(),
        &rec,
        "127.0.0.1",
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
        krb5_admin::RpcCtx {
            store: &store,
            acl: &acl,
            service_keys: &[],
            expected_realm: TEST_REALM,
        },
        b"hdl",
        &mut sess,
        &ReplayCache::new(),
        &rec,
        "127.0.0.1",
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
    let rec = integ_rec_rpcsec(&mut ctx, 41, 1, &handle, &list_args(), true);
    let out = kadm5_handle_rpc(
        krb5_admin::RpcCtx {
            store: &store,
            acl: &acl,
            service_keys: &[],
            expected_realm: TEST_REALM,
        },
        b"hdl",
        &mut sess,
        &ReplayCache::new(),
        &rec,
        "127.0.0.1",
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
    let rec = integ_rec_rpcsec(&mut ctx, 42, 1, b"not-the-handle", &list_args(), false);
    let out = kadm5_handle_rpc(
        krb5_admin::RpcCtx {
            store: &store,
            acl: &acl,
            service_keys: &[],
            expected_realm: TEST_REALM,
        },
        b"hdl",
        &mut sess,
        &ReplayCache::new(),
        &rec,
        "127.0.0.1",
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

const PROG_UNAVAIL: u32 = 1;

fn be(words: &[u32]) -> Vec<u8> {
    let mut b = Vec::with_capacity(words.len() * 4);
    for w in words {
        b.extend_from_slice(&w.to_be_bytes());
    }
    b
}

#[test]
fn unknown_program_auth_none_is_prog_unavail() {
    let (store, acl) = bootstrap_documented().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let store = shared_dump(store);
    thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        let _ = serve_kadm5_conn(
            store,
            acl,
            Vec::new(),
            "KERBER.TEST".into(),
            ReplayCache::new(),
            s,
        );
    });
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let body = be(&[7, MSG_CALL, RPC_VERSION, 99_999, 1, 0, 0, 0, 0, 0]);
    let n = u32::try_from(body.len()).unwrap() | LAST_FRAG;
    c.write_all(&n.to_be_bytes()).unwrap();
    c.write_all(&body).unwrap();
    let mut hdr = [0u8; 4];
    c.read_exact(&mut hdr)
        .expect("PROG_UNAVAIL reply kept the connection");
    let len = (u32::from_be_bytes(hdr) & !LAST_FRAG) as usize;
    let mut rec = vec![0u8; len];
    c.read_exact(&mut rec).unwrap();
    let w = words(&rec);
    assert_eq!(w[0], 7);
    assert_eq!(w[1], MSG_REPLY);
    assert_eq!(w[2], MSG_ACCEPTED);
    assert_eq!(w[3], 0);
    assert_eq!(w[4], 0);
    assert_eq!(w[5], PROG_UNAVAIL);
}

const IPROP_PROG: u32 = 100_423;

const IPROP_VERS: u32 = 1;

const AUTH_GSSAPI_INIT: u32 = 1;

const FLAVOR_AUTH_GSSAPI: u32 = 300_001;

const AUTH_GSSAPI_CREDS_VERS: u32 = 2;

#[test]
fn auth_gssapi_on_iprop_init_is_success() {
    let (store, acl) = bootstrap_documented().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let store = shared_dump(store);
    thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        let _ = serve_kadm5_conn(
            store,
            acl,
            Vec::new(),
            "KERBER.TEST".into(),
            ReplayCache::new(),
            s,
        );
    });
    let mut cred = Vec::new();
    push_u32(&mut cred, AUTH_GSSAPI_CREDS_VERS);
    push_u32(&mut cred, 1);
    push_u32(&mut cred, 0);
    let mut args = Vec::new();
    push_u32(&mut args, 2);
    push_u32(&mut args, 0);
    let mut body = Vec::new();
    push_u32(&mut body, 12);
    push_u32(&mut body, MSG_CALL);
    push_u32(&mut body, RPC_VERSION);
    push_u32(&mut body, IPROP_PROG);
    push_u32(&mut body, IPROP_VERS);
    push_u32(&mut body, AUTH_GSSAPI_INIT);
    push_u32(&mut body, FLAVOR_AUTH_GSSAPI);
    push_u32(&mut body, u32::try_from(cred.len()).unwrap());
    body.extend_from_slice(&cred);
    push_u32(&mut body, 0);
    push_u32(&mut body, 0);
    body.extend_from_slice(&args);
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let n = u32::try_from(body.len()).unwrap() | LAST_FRAG;
    c.write_all(&n.to_be_bytes()).unwrap();
    c.write_all(&body).unwrap();
    let mut hdr = [0u8; 4];
    c.read_exact(&mut hdr)
        .expect("AUTH_GSSAPI INIT reply kept the connection");
    let len = (u32::from_be_bytes(hdr) & !LAST_FRAG) as usize;
    let mut rec = vec![0u8; len];
    c.read_exact(&mut rec).unwrap();
    let w = words(&rec);
    assert_eq!(w[0], 12);
    assert_eq!(w[1], MSG_REPLY);
    assert_eq!(w[2], MSG_ACCEPTED);
    assert_eq!(w[w.len() - 1], SUCCESS);
}

fn init_call(xid: u32, version: u32) -> Vec<u8> {
    let mut cred = Vec::new();
    push_u32(&mut cred, AUTH_GSSAPI_CREDS_VERS);
    push_u32(&mut cred, 1); // auth_msg TRUE
    push_opaque(&mut cred, &[]); // client_handle
    let mut w = Vec::new();
    push_u32(&mut w, xid);
    push_u32(&mut w, MSG_CALL);
    push_u32(&mut w, RPC_VERSION);
    push_u32(&mut w, KADM_PROG);
    push_u32(&mut w, KADM_VERS);
    push_u32(&mut w, AUTH_GSSAPI_INIT);
    push_u32(&mut w, FLAVOR_AUTH_GSSAPI);
    push_opaque(&mut w, &cred);
    push_u32(&mut w, FLAVOR_NONE);
    push_opaque(&mut w, &[]);
    push_u32(&mut w, version);
    push_opaque(&mut w, &[]);
    w
}

fn reply_words(version: u32) -> Vec<u32> {
    let (store, _) = bootstrap_documented().unwrap();
    let store = shared_dump(store);
    let acl = Acl::parse("*/admin@KERBER.TEST *\n").unwrap();
    let mut sess = Kadm5RpcSession::default();
    let out = kadm5_handle_rpc(
        krb5_admin::RpcCtx {
            store: &store,
            acl: &acl,
            service_keys: &[],
            expected_realm: TEST_REALM,
        },
        b"hdl",
        &mut sess,
        &ReplayCache::new(),
        &init_call(77, version),
        "127.0.0.1",
    )
    .unwrap();
    out.as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_be_bytes(*c))
        .collect()
}

fn accepted_res_version(w: &[u32]) -> u32 {
    assert_eq!(
        &w[..6],
        &[77, MSG_REPLY, MSG_ACCEPTED, FLAVOR_NONE, 0, SUCCESS]
    );
    w[6]
}

#[test]
fn init_arg_version_2_is_answered_with_version_1() {
    // 3 and 4 are echoed (`:333-336`) …
    assert_eq!(accepted_res_version(&reply_words(4)), 4);
    assert_eq!(accepted_res_version(&reply_words(3)), 3);
    // … 1 and 2 are the OpenVision protocol and get `call_res.version = 1`
    // (`:328-331`); the parent echoed 2.
    assert_eq!(accepted_res_version(&reply_words(2)), 1);
    assert_eq!(accepted_res_version(&reply_words(1)), 1);
}

#[test]
fn init_arg_version_5_is_auth_badcred() {
    // `:337-341` default: "unsupported GSSAPI_INIT version" → AUTH_BADCRED,
    // an RPC MSG_DENIED / AUTH_ERROR; the parent accepted it and echoed 5.
    let w = reply_words(5);
    assert_eq!(
        &w[..5],
        &[77, MSG_REPLY, MSG_DENIED, REJECT_AUTH_ERROR, AUTH_BADCRED],
        "reply words {w:?}"
    );
    let w = reply_words(0);
    assert_eq!(
        &w[..5],
        &[77, MSG_REPLY, MSG_DENIED, REJECT_AUTH_ERROR, AUTH_BADCRED]
    );
}
