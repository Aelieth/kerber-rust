//! ONC RPC over TCP for kadmind: record marking (`lib/rpc/xdr_rec.c`), the
//! call header and flavor routing of `svc.c` / `svc_tcp.c`, the reply
//! builders (`rpc_prot.c` `MSG_ACCEPTED` / `MSG_DENIED`) and the RPCSEC_GSS
//! credential (`svc_auth_gss.c` `rpc_gss_cred`). `serve_kadm5_conn` is the
//! per-connection loop of `kadm_rpc_svc.c`; the accumulated record is
//! capped at MIT's 1 MiB before anything is parsed.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use krb5_crypto::ProtocolKey;
use krb5_kdc::{Acl, SharedDump as SharedStore};
use krb5_protocol::ReplayCache;

use super::auth::{Agss, RpcsecGss, handle_auth_gssapi, handle_rpcsec_gss};
use super::codes::{
    AUTH_TOOWEAK, FLAVOR_AUTH_GSSAPI, FLAVOR_GSS, FLAVOR_NONE, IPROP_PROG, IPROP_VERS, KADM_PROG,
    KADM_VERS, LAST_FRAG, MSG_ACCEPTED, MSG_CALL, MSG_DENIED, MSG_REPLY, PROG_MISMATCH,
    PROG_UNAVAIL, REJECT_AUTH_ERROR, RPC_VERSION, SUCCESS,
};
use super::xdr::{XdrR, XdrW};
use crate::Error;

/// Kadmind server handle: the store, ACL, service keys, and realm.
///
/// kadm5_server_handle_rec (`lib/kadm5/server_internal.h`).
#[derive(Clone, Copy)]
pub struct RpcCtx<'a> {
    /// KDC store the procedure reads and writes.
    pub store: &'a SharedStore,
    /// Kadm5 ACL.
    pub acl: &'a Acl,
    /// Keys that accept an AP-REQ for this service.
    pub service_keys: &'a [ProtocolKey],
    /// Realm the acceptor name must belong to.
    pub expected_realm: &'a str,
}

/// Serve one TCP connection until EOF.
///
/// # Errors
///
/// I/O or GSS/RPC failures.
#[allow(clippy::needless_pass_by_value)]
pub fn serve_kadm5_conn(
    store: SharedStore,
    acl: Acl,
    service_keys: Vec<ProtocolKey>,
    expected_realm: String,
    rcache: ReplayCache,
    mut stream: TcpStream,
) -> io::Result<()> {
    let mut gss: Option<RpcsecGss> = None;
    let mut agss: Option<Agss> = None;
    let handle = random_handle();
    let addr = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    let ctx = RpcCtx {
        store: &store,
        acl: &acl,
        service_keys: &service_keys,
        expected_realm: &expected_realm,
    };
    loop {
        let rec = match read_record(&mut stream) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let reply = match handle_rpc(ctx, &handle, &mut gss, &mut agss, &rcache, &rec, &addr) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    event = krb5_log::events::ADMIN,
                    component = "krb5-admin",
                    outcome = "error",
                    error = %e,
                );
                eprintln!("kadm5: {e}");
                return Err(io::Error::other(e.to_string()));
            }
        };
        if reply.is_empty() {
            continue;
        }
        write_record(&mut stream, &reply)?;
    }
}

fn random_handle() -> Vec<u8> {
    let mut h = [0u8; 8];
    let _ = getrandom::getrandom(&mut h);
    h.to_vec()
}

/// Total accumulated record cap. MIT drives kadmind over the net-server's fixed
/// MIT `accept_stream_connection` (`net-server.c:1278-1278`): 1 MiB per-connection buffer and processes the RPC as it
/// streams; Rust buffers the whole record, so it bounds the accumulated total to
/// the same size rather than letting a pre-auth client chain fragments without
/// limit.
const MAX_KADM5_RECORD: usize = 1024 * 1024;

pub(super) fn read_record(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut hdr = [0u8; 4];
        stream.read_exact(&mut hdr)?;
        let n = u32::from_be_bytes(hdr);
        let last = n & LAST_FRAG != 0;
        let len = (n & !LAST_FRAG) as usize;
        if len > MAX_KADM5_RECORD || out.len().saturating_add(len) > MAX_KADM5_RECORD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "rpc record"));
        }
        let mut chunk = vec![0u8; len];
        stream.read_exact(&mut chunk)?;
        out.extend_from_slice(&chunk);
        if last {
            return Ok(out);
        }
    }
}

pub(super) fn write_record(stream: &mut TcpStream, body: &[u8]) -> io::Result<()> {
    let n = u32::try_from(body.len()).unwrap_or(0) | LAST_FRAG;
    stream.write_all(&n.to_be_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// RPCSEC/AUTH_GSSAPI session for [`kadm5_handle_rpc`].
#[derive(Default)]
pub struct Kadm5RpcSession {
    gss: Option<RpcsecGss>,
    agss: Option<Agss>,
}

/// One ONC RPC record through `handle_rpc`.
///
/// # Errors
///
/// Truncated record or I/O.
pub fn kadm5_handle_rpc(
    ctx: RpcCtx<'_>,
    handle: &[u8],
    sess: &mut Kadm5RpcSession,
    rcache: &ReplayCache,
    rec: &[u8],
    addr: &str,
) -> Result<Vec<u8>, Error> {
    let RpcCtx {
        store,
        acl,
        service_keys,
        expected_realm,
    } = ctx;
    handle_rpc(
        RpcCtx {
            store,
            acl,
            service_keys,
            expected_realm,
        },
        handle,
        &mut sess.gss,
        &mut sess.agss,
        rcache,
        rec,
        addr,
    )
}

/// MIT `kadm_1` (`kadm_rpc_svc.c:80-88`): a flavor other than AUTH_GSSAPI or RPCSEC_GSS is weak auth and is not dispatched.
/// RPCSEC_GSS is authenticated before the program version is checked, so a bad sequence is not reported as a version mismatch.
pub(super) fn handle_rpc(
    ctx: RpcCtx<'_>,
    handle: &[u8],
    gss: &mut Option<RpcsecGss>,
    agss: &mut Option<Agss>,
    rcache: &ReplayCache,
    rec: &[u8],
    addr: &str,
) -> Result<Vec<u8>, Error> {
    let RpcCtx {
        store,
        acl,
        service_keys,
        expected_realm,
    } = ctx;
    let mut r = XdrR::new(rec);
    let xid = r.u32()?;
    let mtype = r.u32()?;
    if mtype != MSG_CALL {
        return Ok(Vec::new());
    }
    let rpcvers = r.u32()?;
    if rpcvers != RPC_VERSION {
        return Ok(Vec::new());
    }
    let prog = r.u32()?;
    let vers = r.u32()?;
    let proc = r.u32()?;
    let cred_flavor = r.u32()?;
    let cred = r.opaque()?;
    let header_end = r.i;
    let verf_flavor = r.u32()?;
    let verf = r.opaque()?;

    tracing::info!(
        event = krb5_log::events::ADMIN,
        component = "krb5-admin",
        outcome = "ok",
        detail = "rpc.flavor",
        rpc_flavor = if cred_flavor == FLAVOR_GSS {
            "RPCSEC_GSS"
        } else if cred_flavor == FLAVOR_AUTH_GSSAPI {
            "AUTH_GSSAPI"
        } else {
            "OTHER"
        },
        prog,
    );

    let kadm = prog == KADM_PROG;
    let iprop = prog == IPROP_PROG;
    if cred_flavor == FLAVOR_GSS {
        return handle_rpcsec_gss(
            RpcCtx {
                store,
                acl,
                service_keys,
                expected_realm,
            },
            handle,
            gss,
            xid,
            proc,
            kadm,
            iprop,
            vers,
            &cred,
            verf_flavor,
            &verf,
            rec,
            header_end,
            r.rest(),
            rcache,
            addr,
        );
    }

    // MIT `svc_do_xprt` (`svc.c:486-520`): AUTH_NONE is AUTH_OK, then program/version.
    if kadm && vers != KADM_VERS {
        return Ok(rpc_reply_mismatch(xid, KADM_VERS, KADM_VERS));
    }
    if iprop && vers != IPROP_VERS {
        return Ok(rpc_reply_mismatch(xid, IPROP_VERS, IPROP_VERS));
    }
    if !kadm && !iprop {
        return Ok(rpc_reply_accepted(xid, PROG_UNAVAIL));
    }

    if cred_flavor == FLAVOR_AUTH_GSSAPI {
        return handle_auth_gssapi(
            RpcCtx {
                store,
                acl,
                service_keys,
                expected_realm,
            },
            agss,
            xid,
            proc,
            iprop,
            &cred,
            &verf,
            r.rest(),
            rcache,
        );
    }

    // MIT `kadm_1` (`kadm_rpc_svc.c:80-87`): only AUTH_GSSAPI / RPCSEC_GSS.
    Ok(rpc_reply_weakauth(xid))
}

pub(super) fn rpc_reply_weakauth(xid: u32) -> Vec<u8> {
    rpc_reply_auth_error(xid, AUTH_TOOWEAK)
}

pub(super) fn rpc_reply_auth_error(xid: u32, stat: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_REPLY);
    w.u32(MSG_DENIED);
    w.u32(REJECT_AUTH_ERROR);
    w.u32(stat);
    w.b
}

pub(super) fn rpc_reply_accepted(xid: u32, stat: u32) -> Vec<u8> {
    rpc_reply_accepted_verf(xid, None, stat)
}

fn write_rpc_verf(w: &mut XdrW, verf: Option<&[u8]>) {
    if let Some(mic) = verf {
        w.u32(FLAVOR_GSS);
        w.opaque(mic);
    } else {
        w.u32(FLAVOR_NONE);
        w.opaque(&[]);
    }
}

pub(super) fn rpc_reply_accepted_verf(xid: u32, verf: Option<&[u8]>, stat: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_REPLY);
    w.u32(MSG_ACCEPTED);
    write_rpc_verf(&mut w, verf);
    w.u32(stat);
    w.b
}

fn rpc_reply_mismatch(xid: u32, low: u32, high: u32) -> Vec<u8> {
    rpc_reply_mismatch_verf(xid, None, low, high)
}

pub(super) fn rpc_reply_mismatch_verf(
    xid: u32,
    verf: Option<&[u8]>,
    low: u32,
    high: u32,
) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_REPLY);
    w.u32(MSG_ACCEPTED);
    write_rpc_verf(&mut w, verf);
    w.u32(PROG_MISMATCH);
    w.u32(low);
    w.u32(high);
    w.b
}

pub(super) fn rpc_reply_clear(xid: u32, body: &[u8]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_REPLY);
    w.u32(MSG_ACCEPTED);
    w.u32(FLAVOR_NONE);
    w.opaque(&[]);
    w.u32(SUCCESS);
    w.b.extend_from_slice(body);
    w.b
}

pub(super) fn rpc_reply_gss_verf(xid: u32, mic: &[u8], body: &[u8]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_REPLY);
    w.u32(MSG_ACCEPTED);
    w.u32(FLAVOR_GSS);
    w.opaque(mic);
    w.u32(SUCCESS);
    w.b.extend_from_slice(body);
    w.b
}

pub(super) fn rpc_reply_gss(xid: u32, mic: &[u8], wrap: &[u8]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_REPLY);
    w.u32(MSG_ACCEPTED);
    w.u32(FLAVOR_GSS);
    w.opaque(mic);
    w.u32(SUCCESS);
    w.opaque(wrap);
    w.b
}

pub(super) fn rpc_reply_agss(xid: u32, verf: &[u8], body: &[u8]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_REPLY);
    w.u32(MSG_ACCEPTED);
    w.u32(FLAVOR_AUTH_GSSAPI);
    w.opaque(verf);
    w.u32(SUCCESS);
    w.b.extend_from_slice(body);
    w.b
}

pub(super) struct Gcred {
    pub(super) version: u32,
    pub(super) proc: u32,
    pub(super) seq_num: u32,
    pub(super) service: u32,
}

pub(super) fn parse_gcred(data: &[u8]) -> Result<Gcred, Error> {
    let mut r = XdrR::new(data);
    Ok(Gcred {
        version: r.u32()?,
        proc: r.u32()?,
        seq_num: r.u32()?,
        service: r.u32()?,
    })
}

/// ONC RPC call identity: transaction id plus the call-body triple.
///
/// RFC 5531 §9 `rpc_msg.xid` and `call_body` (`prog`, `vers`, `proc`).
/// MIT `struct rpc_msg` and `struct call_body`
/// (`include/gssrpc/rpc_msg.h`).
#[derive(Clone, Copy)]
pub(crate) struct RpcCallId {
    /// Transaction id (`rpc_msg.xid`).
    pub xid: u32,
    /// Remote program number.
    pub prog: u32,
    /// Remote program version.
    pub vers: u32,
    /// Remote procedure number.
    pub proc: u32,
}

pub(super) fn rpc_call_bytes(
    id: RpcCallId,
    cred_flavor: u32,
    cred: &[u8],
    verf_flavor: u32,
    verf: &[u8],
    args: &[u8],
) -> Vec<u8> {
    let RpcCallId {
        xid,
        prog,
        vers,
        proc,
    } = id;
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_CALL);
    w.u32(RPC_VERSION);
    w.u32(prog);
    w.u32(vers);
    w.u32(proc);
    w.u32(cred_flavor);
    w.opaque(cred);
    w.u32(verf_flavor);
    w.opaque(verf);
    w.b.extend_from_slice(args);
    w.b
}
