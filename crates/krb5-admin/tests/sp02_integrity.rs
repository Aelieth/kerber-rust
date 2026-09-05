//! RPCSEC_GSS integrity is databody_integ + checksum (`authgss_prot.c:203-225`).

use krb5_admin::{Kadm5RpcSession, kadm5_handle_rpc};
use krb5_crypto::EncryptionType;
use krb5_gss::GssContext;
use krb5_kdc::{TEST_REALM, bootstrap_documented, documented_kadmin, issue_as, shared_dump};
use krb5_protocol::{ReplayCache, as_req_sname, pa_enc_timestamp};
use krb5_types::{PrincipalName, ascii};

const MSG_CALL: u32 = 0;
const MSG_REPLY: u32 = 1;
const MSG_ACCEPTED: u32 = 0;
const RPC_VERSION: u32 = 2;
const KADM_PROG: u32 = 2112;
const KADM_VERS: u32 = 2;
const FLAVOR_GSS: u32 = 6;
const FLAVOR_NONE: u32 = 0;
const RPCSEC_GSS_VERS: u32 = 1;
const RPG_DATA: u32 = 0;
const RPG_INIT: u32 = 1;
const GSS_NONE: u32 = 1;
const GSS_INTEGRITY: u32 = 2;
const GET_PRINCS: u32 = 14;
const API_V2: u32 = 0x1234_5702;
const SUCCESS: u32 = 0;
const GARBAGE_ARGS: u32 = 4;

fn push_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_be_bytes());
}

fn push_opaque(b: &mut Vec<u8>, v: &[u8]) {
    push_u32(b, u32::try_from(v.len()).unwrap());
    b.extend_from_slice(v);
    b.resize(b.len() + (4 - v.len() % 4) % 4, 0);
}

fn take_u32(b: &[u8], i: &mut usize) -> u32 {
    let v = u32::from_be_bytes(b[*i..*i + 4].try_into().unwrap());
    *i += 4;
    v
}

fn take_opaque<'a>(b: &'a [u8], i: &mut usize) -> &'a [u8] {
    let n = take_u32(b, i) as usize;
    let s = &b[*i..*i + n];
    *i += n + (4 - n % 4) % 4;
    s
}

fn cred(proc: u32, seq: u32, svc: u32, handle: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    push_u32(&mut c, RPCSEC_GSS_VERS);
    push_u32(&mut c, proc);
    push_u32(&mut c, seq);
    push_u32(&mut c, svc);
    push_opaque(&mut c, handle);
    c
}

fn call(xid: u32, proc: u32, cred: &[u8], verf_flavor: u32, verf: &[u8], args: &[u8]) -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, xid);
    push_u32(&mut w, MSG_CALL);
    push_u32(&mut w, RPC_VERSION);
    push_u32(&mut w, KADM_PROG);
    push_u32(&mut w, KADM_VERS);
    push_u32(&mut w, proc);
    push_u32(&mut w, FLAVOR_GSS);
    push_opaque(&mut w, cred);
    push_u32(&mut w, verf_flavor);
    push_opaque(&mut w, verf);
    w.extend_from_slice(args);
    w
}

fn list_args() -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_opaque(&mut w, b"*\0");
    w
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
    let kadm = documented_kadmin();
    let (admin_key, kadm_key) = {
        let g = store.read().unwrap();
        (
            g.get_name(&admin).unwrap().best_key().unwrap().key.clone(),
            g.get_name(&kadm).unwrap().best_key().unwrap().key.clone(),
        )
    };
    let as_req = as_req_sname(
        admin.clone(),
        TEST_REALM,
        7,
        Some(vec![pa_enc_timestamp(&admin_key).unwrap()]),
        kadm.clone(),
        EncryptionType::preferred()
            .iter()
            .map(|e| e.to_iana())
            .collect(),
    )
    .unwrap();
    let as_out = {
        let g = store.read().unwrap();
        issue_as(&*g, &as_req).unwrap()
    };
    let (mut ctx, token) = GssContext::init_sec_context(
        as_out.rep.0.ticket.clone(),
        &as_out.session_key,
        &ascii(TEST_REALM),
        &admin,
        true,
        None,
        None,
    )
    .unwrap();
    let cred = cred(RPG_INIT, 0, svc, &[]);
    let mut arg = Vec::new();
    push_opaque(&mut arg, &token);
    let rec = call(1, 0, &cred, FLAVOR_NONE, &[], &arg);
    let mut sess = Kadm5RpcSession::default();
    let out = kadm5_handle_rpc(
        &store,
        &acl,
        &[kadm_key],
        TEST_REALM,
        b"hdl",
        &mut sess,
        &ReplayCache::new(),
        &rec,
    )
    .unwrap();
    let mut i = 0;
    assert_eq!(take_u32(&out, &mut i), 1);
    assert_eq!(take_u32(&out, &mut i), MSG_REPLY);
    assert_eq!(take_u32(&out, &mut i), MSG_ACCEPTED);
    assert_eq!(take_u32(&out, &mut i), FLAVOR_GSS);
    let verf = take_opaque(&out, &mut i);
    assert_eq!(take_u32(&out, &mut i), SUCCESS);
    let handle = take_opaque(&out, &mut i).to_vec();
    let _maj = take_u32(&out, &mut i);
    let _min = take_u32(&out, &mut i);
    let win = take_u32(&out, &mut i);
    let _tok = take_opaque(&out, &mut i);
    ctx.verify_mic(&win.to_be_bytes(), verf).unwrap();
    (store, acl, ctx, handle, sess)
}

fn integ_rec(
    ctx: &mut GssContext,
    xid: u32,
    seq: u32,
    handle: &[u8],
    args: &[u8],
    tamper: bool,
) -> Vec<u8> {
    let cred = cred(RPG_DATA, seq, GSS_INTEGRITY, handle);
    let mut header = Vec::new();
    push_u32(&mut header, xid);
    push_u32(&mut header, MSG_CALL);
    push_u32(&mut header, RPC_VERSION);
    push_u32(&mut header, KADM_PROG);
    push_u32(&mut header, KADM_VERS);
    push_u32(&mut header, GET_PRINCS);
    push_u32(&mut header, FLAVOR_GSS);
    push_opaque(&mut header, &cred);
    let mic = ctx.get_mic(&header).unwrap();
    let mut databody = Vec::new();
    databody.extend_from_slice(&seq.to_be_bytes());
    databody.extend_from_slice(args);
    let mut checksum = ctx.get_mic(&databody).unwrap();
    if tamper {
        *checksum.last_mut().unwrap() ^= 0xFF;
    }
    let mut arg = Vec::new();
    push_opaque(&mut arg, &databody);
    push_opaque(&mut arg, &checksum);
    call(xid, GET_PRINCS, &cred, FLAVOR_GSS, &mic, &arg)
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
