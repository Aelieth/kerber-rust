//! ONC RPC over TCP for kadmind: record marking (`lib/rpc/xdr_rec.c`), the
//! call header and flavor routing of `svc.c` / `svc_tcp.c`, the reply
//! builders (`rpc_prot.c` `MSG_ACCEPTED` / `MSG_DENIED`) and the RPCSEC_GSS
//! credential (`svc_auth_gss.c` `rpc_gss_cred`). `Kadm5Conn` is one
//! connection's server side, which kadmind's loop calls for each record and
//! `serve_kadm5_conn` drives over a socket of its own; a record is capped at
//! 1 MiB, its marks counted, before anything is parsed. Records and replies
//! are wiped once used: they can carry passwords and keys.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use krb5_crypto::ProtocolKey;
use krb5_kdc::net_server::{RpcReply, RpcSession, read_rpc_record_with};
use krb5_kdc::{Acl, SharedDump as SharedStore};
use krb5_protocol::ReplayCache;
use zeroize::Zeroizing;

use super::auth::{Agss, AgssAuth, RpcsecGss, agss_dispatch, handle_rpcsec_gss, svcauth_gssapi};
use super::codes::{
    AUTH_BADCRED, AUTH_REJECTEDCRED, AUTH_TOOWEAK, FLAVOR_AUTH_GSSAPI, FLAVOR_GSS, FLAVOR_NONE,
    FLAVOR_UNIX, IPROP_PROG, IPROP_VERS, KADM_PROG, KADM_VERS, LAST_FRAG, MAX_AUTH_BYTES,
    MAX_MACHINE_NAME, MSG_ACCEPTED, MSG_CALL, MSG_DENIED, MSG_REPLY, NGRPS, PROG_MISMATCH,
    PROG_UNAVAIL, REJECT_AUTH_ERROR, RPC_VERSION, SUCCESS,
};
use super::log::rpc_log_flavor_refused;
use super::xdr::{XdrR, XdrW, opaque_len};
use crate::Error;

/// Kadmind server handle: the store, ACL, service keys, and realm.
///
/// MIT `kadm5_server_handle_rec` (`lib/kadm5/server_internal.h:53-53`): the kadmind server
/// handle record (context, current caller, config params with the realm).
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

/// Serve one TCP connection until EOF, each record on this socket in turn; a call that does not
/// decode gets no reply, and the connection goes on (see [`kadm5_handle_rpc`]).
///
/// # Errors
///
/// An `ErrorKind::InvalidData` error when a record exceeds the 1 MiB cap, its marks counted; the
/// `io::Error` of any other failed read (EOF ends the loop with `Ok`) or of a failed reply write.
pub fn serve_kadm5_conn(
    store: SharedStore,
    acl: Acl,
    service_keys: Vec<ProtocolKey>,
    expected_realm: String,
    rcache: ReplayCache,
    mut stream: TcpStream,
) -> io::Result<()> {
    let peer = RpcPeer::new(stream.peer_addr().ok(), stream.local_addr().ok());
    let mut conn = Kadm5Conn::new(store, acl, service_keys, expected_realm, rcache, peer, None);
    loop {
        let rec = match read_record(&mut stream) {
            Ok(r) => r,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        match conn.call(&rec) {
            RpcReply::Send(reply) => write_record(&mut stream, &Zeroizing::new(reply))?,
            RpcReply::Nothing => {}
            RpcReply::Close => return Ok(()),
        }
    }
}

/// What a server does with the message of a kadm5 call that does not decode, which gets no
/// reply: `krb5-kadmind` prints it as `kadm5: <message>`. It may be called from the thread that
/// runs kadmind's loop, whichever that is.
pub type UnhandledRpc = Arc<dyn Fn(&str) + Send + Sync>;

/// A kadm5 connection's two ends: the client's address, also as the log prints it, and the
/// connection's own, as MIT's RPC transport keeps them (`xp_raddr`, `xp_laddr`).
#[derive(Clone, Debug)]
pub struct RpcPeer {
    addr: String,
    remote: Option<SocketAddr>,
    local: Option<SocketAddr>,
}

impl RpcPeer {
    /// The connection from `remote` to `local`; an end that is not known is `None`.
    #[must_use]
    pub fn new(remote: Option<SocketAddr>, local: Option<SocketAddr>) -> Self {
        Self {
            addr: remote.map_or_else(String::new, |a| crate::listen::client_addr(a.ip())),
            remote,
            local,
        }
    }

    /// The client's address as the log prints it.
    #[must_use]
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// The four octets MIT's RPC transport reads as the client's IPv4 address (see
    /// [`sockaddr_in_addr`]).
    pub(super) fn remote_inet(&self) -> [u8; 4] {
        self.remote.as_ref().map_or([0; 4], sockaddr_in_addr)
    }

    /// The four octets of the connection's own address, or none when it is not known.
    pub(super) fn local_inet(&self) -> Option<[u8; 4]> {
        self.local.as_ref().map(sockaddr_in_addr)
    }
}

/// The four octets MIT's RPC transport reads as an end's IPv4 address.
/// MIT `rendezvous_request` (`lib/rpc/svc_tcp.c:280-307`): `accept` and `getsockname` fill
/// `sockaddr_in` buffers, so an IPv6 end's flow information lies where an IPv4 address does;
/// std keeps `sin6_flowinfo` as the kernel stored it, so its native bytes are the buffer's.
fn sockaddr_in_addr(a: &SocketAddr) -> [u8; 4] {
    match a {
        SocketAddr::V4(v4) => v4.ip().octets(),
        SocketAddr::V6(v6) => v6.flowinfo().to_ne_bytes(),
    }
}

/// One kadm5 connection's server side: its handle, its GSS state and its peer, over kadmind's
/// store, ACL, acceptor keys and replay cache.
pub(crate) struct Kadm5Conn {
    store: SharedStore,
    acl: Acl,
    service_keys: Vec<ProtocolKey>,
    realm: String,
    rcache: ReplayCache,
    handle: Vec<u8>,
    sess: Kadm5RpcSession,
    peer: RpcPeer,
    report: Option<UnhandledRpc>,
}

impl Kadm5Conn {
    /// The connection `peer` accepted with `service_keys` for `realm`; `report` takes the
    /// message of each call that does not decode.
    pub(crate) fn new(
        store: SharedStore,
        acl: Acl,
        service_keys: Vec<ProtocolKey>,
        realm: String,
        rcache: ReplayCache,
        peer: RpcPeer,
        report: Option<UnhandledRpc>,
    ) -> Self {
        Self {
            store,
            acl,
            service_keys,
            realm,
            rcache,
            handle: random_handle(),
            sess: Kadm5RpcSession::default(),
            peer,
            report,
        }
    }

    /// The reply to one record, empty for none.
    fn handle(&mut self, rec: &[u8]) -> Result<Vec<u8>, Error> {
        let ctx = RpcCtx {
            store: &self.store,
            acl: &self.acl,
            service_keys: &self.service_keys,
            expected_realm: &self.realm,
        };
        let Kadm5RpcSession { gss, agss } = &mut self.sess;
        handle_rpc(ctx, &self.handle, gss, agss, &self.rcache, rec, &self.peer)
    }
}

impl RpcSession for Kadm5Conn {
    /// One record of the connection: its reply, or none. A call that does not decode gets no
    /// reply and the connection waits for its next record, as MIT's does; its message goes to
    /// the JSON log and to the server's reporter.
    /// MIT `svc_do_xprt` (`lib/rpc/svc.c:473-474`): a call that does not decode is not answered.
    /// MIT `svc_do_xprt` (`lib/rpc/svc.c:523-531`): only a transport that died is destroyed; the connection otherwise stays for the next call.
    fn call(&mut self, record: &[u8]) -> RpcReply {
        match self.handle(record) {
            Ok(reply) if reply.is_empty() => RpcReply::Nothing,
            Ok(reply) => RpcReply::Send(reply),
            Err(e) => {
                tracing::error!(
                    event = krb5_log::events::ADMIN,
                    component = "krb5-admin",
                    outcome = "error",
                    error = %e,
                );
                if let Some(report) = &self.report {
                    report(&e.to_string());
                }
                RpcReply::Nothing
            }
        }
    }
}

fn random_handle() -> Vec<u8> {
    let mut h = [0u8; 8];
    let _ = getrandom::getrandom(&mut h);
    h.to_vec()
}

/// One record from a socket that blocks for it, read as kadmind's loop reads one
/// ([`read_rpc_record_with`]): at most 1 MiB, its marks counted, in one buffer wiped when dropped.
pub(super) fn read_record(stream: &mut TcpStream) -> io::Result<Zeroizing<Vec<u8>>> {
    read_rpc_record_with(|buf| stream.read_exact(buf))
}

/// One ONC RPC record: the record mark (the length with the last-fragment bit) and the body in one
/// write, so a reply leaves in one segment rather than waiting on the client's delayed ACK. The
/// record is one fragment whatever its length.
/// MIT `flush_out` (`lib/rpc/xdr_rec.c:475-489`): the record mark is set ahead of the body in
/// xdrrec's buffer, and the buffer goes out in one write.
/// MIT `fix_buf_size` (`lib/rpc/xdr_rec.c:566-571`): kadmind's listener asks for no size
/// (`svctcp_create(sock, 0, 0)`), so that buffer is 4000 bytes and a longer record leaves as
/// several fragments.
pub(super) fn write_record(stream: &mut impl Write, body: &[u8]) -> io::Result<()> {
    let n = u32::try_from(body.len()).unwrap_or(0) | LAST_FRAG;
    let mut rec = Zeroizing::new(Vec::with_capacity(4 + body.len()));
    rec.extend_from_slice(&n.to_be_bytes());
    rec.extend_from_slice(body);
    stream.write_all(&rec)?;
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
/// [`Error::GarbageArgs`] when the call header does not decode or carries a credential or
/// verifier past 400 bytes (MIT `xdr_callmsg`). That call, like a record that is not an RPC
/// version 2 call (`Ok` and empty), gets no reply; every other call gets one.
pub fn kadm5_handle_rpc(
    ctx: RpcCtx<'_>,
    handle: &[u8],
    sess: &mut Kadm5RpcSession,
    rcache: &ReplayCache,
    rec: &[u8],
    peer: &RpcPeer,
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
        peer,
    )
}

/// One record of a kadmind connection, as MIT's RPC layer takes a call.
/// MIT `svc_do_xprt` (`lib/rpc/svc.c:472-473`): a call that does not decode is not answered.
/// MIT `xdr_callmsg` (`lib/rpc/rpc_callmsg.c:101-193`): a record that is not an RPC version 2 call,
/// or whose credential or verifier is past `MAX_AUTH_BYTES`, does not decode.
/// MIT `gssrpc__authenticate` (`lib/rpc/svc_auth.c:84-106`): the flavor's authenticator comes
/// first: AUTH_NONE passes, AUTH_UNIX once its credential decodes (AUTH_BADCRED else), AUTH_GSSAPI
/// and RPCSEC_GSS decide for themselves, and AUTH_SHORT and any other flavor are AUTH_REJECTEDCRED.
/// MIT `svc_do_xprt` (`lib/rpc/svc.c:487-493`): a refusal is answered with its `auth_stat`
/// (`svcerr_auth`), and the connection waits for the next call.
/// MIT `svc_do_xprt` (`lib/rpc/svc.c:495-520`): an authentic call goes to its program and version,
/// answered under the call's verifier: a version not served is PROG_MISMATCH, a program not served
/// PROG_UNAVAIL (iprop is served with its update log).
/// MIT `kadm_1` (`kadmin/server/kadm_rpc_svc.c:80-88`): kadm5 takes AUTH_GSSAPI and RPCSEC_GSS and
/// answers another flavor AUTH_TOOWEAK.
/// MIT `krb5_iprop_prog_1` (`kadmin/server/ipropd_svc.c:542-548`): iprop takes RPCSEC_GSS alone.
pub(super) fn handle_rpc(
    ctx: RpcCtx<'_>,
    handle: &[u8],
    gss: &mut Option<RpcsecGss>,
    agss: &mut Option<Agss>,
    rcache: &ReplayCache,
    rec: &[u8],
    peer: &RpcPeer,
) -> Result<Vec<u8>, Error> {
    let addr = peer.addr();
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
    if cred.len() > MAX_AUTH_BYTES || verf.len() > MAX_AUTH_BYTES {
        return Err(Error::GarbageArgs);
    }

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
    // MIT `setup_loop` (`kadmin/server/ovsec_kadmd.c:164-171`): the iprop program is registered only with `iprop_enable`, which maps the update log.
    let iprop = prog == IPROP_PROG
        && ctx
            .store
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .logging();
    if cred_flavor == FLAVOR_GSS {
        return handle_rpcsec_gss(
            ctx,
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
    let reply_verf = match cred_flavor {
        FLAVOR_AUTH_GSSAPI => {
            match svcauth_gssapi(ctx, agss, xid, proc, &cred, &verf, r.rest(), rcache, peer) {
                AgssAuth::Denied(why) => return Ok(rpc_reply_auth_error(xid, why)),
                AgssAuth::Replied(reply) => return Ok(reply),
                AgssAuth::Dispatch(reply_verf) => Some(reply_verf),
            }
        }
        FLAVOR_NONE => None,
        FLAVOR_UNIX if authunix_parms_decode(&cred) => None,
        FLAVOR_UNIX => return Ok(rpc_reply_auth_error(xid, AUTH_BADCRED)),
        _ => return Ok(rpc_reply_auth_error(xid, AUTH_REJECTEDCRED)),
    };
    let at = reply_verf
        .as_deref()
        .map_or(ReplyVerf::None, ReplyVerf::AuthGssapi);
    if kadm && vers != KADM_VERS {
        return Ok(rpc_reply_mismatch_at(xid, at, KADM_VERS, KADM_VERS));
    }
    if iprop && vers != IPROP_VERS {
        return Ok(rpc_reply_mismatch_at(xid, at, IPROP_VERS, IPROP_VERS));
    }
    if !kadm && !iprop {
        return Ok(rpc_reply_status(xid, at, PROG_UNAVAIL));
    }
    match (agss.as_mut(), reply_verf) {
        (Some(st), Some(reply_verf)) if kadm => Ok(agss_dispatch(
            ctx,
            st,
            xid,
            proc,
            r.rest(),
            &reply_verf,
            addr,
        )),
        _ => {
            rpc_log_flavor_refused(iprop, addr, cred_flavor);
            Ok(rpc_reply_weakauth(xid))
        }
    }
}

/// MIT `gssrpc__svcauth_unix` (`lib/rpc/svc_auth_unix.c:55-126`): a stamp, a machine name of at
/// most 255 bytes, a uid, a gid and at most 16 groups, all inside the credential.
fn authunix_parms_decode(cred: &[u8]) -> bool {
    fn parse(r: &mut XdrR<'_>) -> Result<bool, Error> {
        r.u32()?;
        if r.opaque()?.len() > MAX_MACHINE_NAME {
            return Ok(false);
        }
        r.u32()?;
        r.u32()?;
        let groups = r.u32()?;
        if groups > NGRPS {
            return Ok(false);
        }
        for _ in 0..groups {
            r.u32()?;
        }
        Ok(true)
    }
    parse(&mut XdrR::new(cred)).unwrap_or(false)
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

/// The verifier a reply carries, the server's `xp_verf`: none, an RPCSEC_GSS MIC of the sequence
/// number, or an AUTH_GSSAPI sealed sequence number.
#[derive(Clone, Copy)]
pub(super) enum ReplyVerf<'a> {
    None,
    Gss(&'a [u8]),
    AuthGssapi(&'a [u8]),
}

/// An accepted reply under `verf` whose status is `stat`, as MIT's `svcerr_noprog`,
/// `svcerr_decode` and `svcerr_systemerr` answer.
/// MIT `svcerr_noproc` (`lib/rpc/svc.c:265-275`): the status under the call's `xp_verf`.
pub(super) fn rpc_reply_status(xid: u32, verf: ReplyVerf<'_>, stat: u32) -> Vec<u8> {
    let (flavor, body) = match verf {
        ReplyVerf::None => (FLAVOR_NONE, &[][..]),
        ReplyVerf::Gss(b) => (FLAVOR_GSS, b),
        ReplyVerf::AuthGssapi(b) => (FLAVOR_AUTH_GSSAPI, b),
    };
    let mut w = XdrW::default();
    w.u32(xid);
    w.u32(MSG_REPLY);
    w.u32(MSG_ACCEPTED);
    w.u32(flavor);
    w.opaque(body);
    w.u32(stat);
    w.b
}

pub(super) fn rpc_reply_accepted_verf(xid: u32, verf: Option<&[u8]>, stat: u32) -> Vec<u8> {
    rpc_reply_status(xid, verf.map_or(ReplyVerf::None, ReplyVerf::Gss), stat)
}

/// PROG_MISMATCH with the lowest and highest version served, under `verf`.
/// MIT `svcerr_progvers` (`lib/rpc/svc.c:352-367`): the versions follow the status, under the
/// call's `xp_verf`.
pub(super) fn rpc_reply_mismatch_at(xid: u32, verf: ReplyVerf<'_>, low: u32, high: u32) -> Vec<u8> {
    let mut w = rpc_reply_status(xid, verf, PROG_MISMATCH);
    w.extend_from_slice(&low.to_be_bytes());
    w.extend_from_slice(&high.to_be_bytes());
    w
}

pub(super) fn rpc_reply_mismatch_verf(
    xid: u32,
    verf: Option<&[u8]>,
    low: u32,
    high: u32,
) -> Vec<u8> {
    rpc_reply_mismatch_at(xid, verf.map_or(ReplyVerf::None, ReplyVerf::Gss), low, high)
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

/// A reply whose body may carry keys in the clear, built in one buffer of its size.
pub(super) fn rpc_reply_gss_verf(xid: u32, mic: &[u8], body: &[u8]) -> Vec<u8> {
    let mut w = XdrW::with_capacity(20 + opaque_len(mic.len()) + body.len());
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
    let mut w = rpc_reply_agss_status(xid, verf, SUCCESS);
    w.extend_from_slice(body);
    w
}

/// An accepted reply under the AUTH_GSSAPI verifier `verf` whose status is `stat`.
pub(super) fn rpc_reply_agss_status(xid: u32, verf: &[u8], stat: u32) -> Vec<u8> {
    rpc_reply_status(xid, ReplyVerf::AuthGssapi(verf), stat)
}

pub(super) struct Gcred {
    pub(super) version: u32,
    pub(super) proc: u32,
    pub(super) seq_num: u32,
    pub(super) service: u32,
}

/// MIT `xdr_rpc_gss_cred` (`lib/rpc/authgss_prot.c:72-90`): the credential closes with its
/// context handle, which must decode too.
pub(super) fn parse_gcred(data: &[u8]) -> Result<Gcred, Error> {
    let mut r = XdrR::new(data);
    let gcred = Gcred {
        version: r.u32()?,
        proc: r.u32()?,
        seq_num: r.u32()?,
        service: r.u32()?,
    };
    r.opaque()?;
    Ok(gcred)
}

/// ONC RPC call identity: transaction id plus the call-body triple.
///
/// RFC 5531 §9 `rpc_msg.xid` and `call_body` (`prog`, `vers`, `proc`).
/// MIT `struct rpc_msg` and `struct call_body`.
/// MIT `struct call_body` (`include/gssrpc/rpc_msg.h:138-138`): the call body carries
/// `cb_prog`, `cb_vers`, and `cb_proc`.
/// MIT `struct rpc_msg` (`include/gssrpc/rpc_msg.h:150-150`): the message's `rm_xid` is the
/// transaction id.
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
