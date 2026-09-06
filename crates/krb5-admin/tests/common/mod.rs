//! In-process kadm5 RPCSEC_GSS client: one `RPG_INIT`, then `RPG_DATA` calls
//! with `databody_integ` + checksum (`authgss_prot.c:203-225`).

#![allow(dead_code)]

use krb5_admin::{Kadm5RpcSession, kadm5_handle_rpc};
use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_gss::GssContext;
use krb5_kdc::{Acl, SharedDump, TEST_REALM, issue_as};
use krb5_protocol::{ReplayCache, as_req_sname, pa_enc_timestamp};
use krb5_types::{PrincipalName, ascii};

pub const MSG_CALL: u32 = 0;
pub const MSG_REPLY: u32 = 1;
pub const MSG_ACCEPTED: u32 = 0;
pub const RPC_VERSION: u32 = 2;
pub const KADM_PROG: u32 = 2112;
pub const KADM_VERS: u32 = 2;
pub const FLAVOR_GSS: u32 = 6;
pub const FLAVOR_NONE: u32 = 0;
pub const RPCSEC_GSS_VERS: u32 = 1;
pub const RPG_DATA: u32 = 0;
pub const RPG_INIT: u32 = 1;
pub const GSS_NONE: u32 = 1;
pub const GSS_INTEGRITY: u32 = 2;
pub const GET_PRINCS: u32 = 14;
pub const API_V2: u32 = 0x1234_5702;
pub const SUCCESS: u32 = 0;
pub const PROC_UNAVAIL: u32 = 3;
pub const GARBAGE_ARGS: u32 = 4;

pub fn push_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_be_bytes());
}

pub fn push_opaque(b: &mut Vec<u8>, v: &[u8]) {
    push_u32(b, u32::try_from(v.len()).unwrap());
    b.extend_from_slice(v);
    b.resize(b.len() + (4 - v.len() % 4) % 4, 0);
}

pub fn push_nullstring(b: &mut Vec<u8>, s: &str) {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    push_opaque(b, &v);
}

pub fn take_u32(b: &[u8], i: &mut usize) -> u32 {
    let v = u32::from_be_bytes(b[*i..*i + 4].try_into().unwrap());
    *i += 4;
    v
}

pub fn take_opaque<'a>(b: &'a [u8], i: &mut usize) -> &'a [u8] {
    let n = take_u32(b, i) as usize;
    let s = &b[*i..*i + n];
    *i += n + (4 - n % 4) % 4;
    s
}

pub fn cred(proc: u32, seq: u32, svc: u32, handle: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    push_u32(&mut c, RPCSEC_GSS_VERS);
    push_u32(&mut c, proc);
    push_u32(&mut c, seq);
    push_u32(&mut c, svc);
    push_opaque(&mut c, handle);
    c
}

pub fn call(
    xid: u32,
    proc: u32,
    cred: &[u8],
    verf_flavor: u32,
    verf: &[u8],
    args: &[u8],
) -> Vec<u8> {
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

pub fn list_args() -> Vec<u8> {
    let mut w = Vec::new();
    push_u32(&mut w, API_V2);
    push_opaque(&mut w, b"*\0");
    w
}

/// One authenticated kadm5 client (`kadmin -p client`) against `service`.
pub struct Client {
    pub ctx: GssContext,
    pub handle: Vec<u8>,
    pub sess: Kadm5RpcSession,
    pub seq: u32,
    pub xid: u32,
}

pub fn init_client(
    store: &SharedDump,
    acl: &Acl,
    client: &PrincipalName,
    service: &PrincipalName,
    svc: u32,
) -> Client {
    let (client_key, service_key): (ProtocolKey, ProtocolKey) = {
        let g = store.read().unwrap();
        (
            g.get_name(client).unwrap().best_key().unwrap().key.clone(),
            g.get_name(service).unwrap().best_key().unwrap().key.clone(),
        )
    };
    let as_req = as_req_sname(
        client.clone(),
        TEST_REALM,
        7,
        Some(vec![pa_enc_timestamp(&client_key).unwrap()]),
        service.clone(),
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
        client,
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
        store,
        acl,
        &[service_key],
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
    Client {
        ctx,
        handle,
        sess,
        seq: 0,
        xid: 40,
    }
}

pub fn integ_rec(
    ctx: &mut GssContext,
    xid: u32,
    seq: u32,
    handle: &[u8],
    proc: u32,
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
    push_u32(&mut header, proc);
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
    call(xid, proc, &cred, FLAVOR_GSS, &mic, &arg)
}

/// Accept status and the verified reply databody (sequence word stripped).
pub fn data_call(
    c: &mut Client,
    store: &SharedDump,
    acl: &Acl,
    proc: u32,
    args: &[u8],
) -> (u32, Vec<u8>) {
    c.seq += 1;
    c.xid += 1;
    let rec = integ_rec(&mut c.ctx, c.xid, c.seq, &c.handle, proc, args, false);
    let out = kadm5_handle_rpc(
        store,
        acl,
        &[],
        TEST_REALM,
        b"hdl",
        &mut c.sess,
        &ReplayCache::new(),
        &rec,
    )
    .unwrap();
    let mut i = 0;
    assert_eq!(take_u32(&out, &mut i), c.xid);
    assert_eq!(take_u32(&out, &mut i), MSG_REPLY);
    assert_eq!(take_u32(&out, &mut i), MSG_ACCEPTED);
    assert_eq!(take_u32(&out, &mut i), FLAVOR_GSS);
    let verf = take_opaque(&out, &mut i);
    let stat = take_u32(&out, &mut i);
    if stat != SUCCESS {
        return (stat, Vec::new());
    }
    c.ctx.verify_mic(&c.seq.to_be_bytes(), verf).unwrap();
    let databody = take_opaque(&out, &mut i);
    let checksum = take_opaque(&out, &mut i);
    c.ctx.verify_mic(databody, checksum).unwrap();
    assert_eq!(&databody[..4], c.seq.to_be_bytes());
    (stat, databody[4..].to_vec())
}

/// `generic_ret` code of a reply databody.
pub fn ret_code(databody: &[u8]) -> u32 {
    u32::from_be_bytes(databody[4..8].try_into().unwrap())
}
