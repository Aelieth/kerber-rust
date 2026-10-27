//! Record buffers can carry passwords and keys.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use krb5_kdc::SharedDump as SharedStore;
use krb5_kdc::net_server::{RpcReply, RpcSession, read_rpc_record_with};
use krb5_protocol::{AcceptorConfig, ReplayCache};
use zeroize::Zeroizing;

use super::auth::{Agss, AgssAuth, RpcsecGss, agss_dispatch, handle_rpcsec_gss, svcauth_gssapi};
use super::auth_plugin::Kadm5AuthConfig;
use super::codes::{
    AUTH_BADCRED, AUTH_REJECTEDCRED, AUTH_TOOWEAK, FLAVOR_AUTH_GSSAPI, FLAVOR_GSS, FLAVOR_NONE,
    FLAVOR_UNIX, IPROP_PROG, IPROP_VERS, KADM_PROG, KADM_VERS, LAST_FRAG, MAX_AUTH_BYTES,
    MAX_MACHINE_NAME, MSG_ACCEPTED, MSG_CALL, MSG_DENIED, MSG_REPLY, NGRPS, PROG_MISMATCH,
    PROG_UNAVAIL, REJECT_AUTH_ERROR, RPC_VERSION, SUCCESS,
};
use super::iprop::IpropResync;
use super::log::rpc_log_flavor_refused;
use super::xdr::{XdrR, XdrW, opaque_len};
use crate::Error;

// MIT: `kadm5_server_handle_rec` (lib/kadm5/server_internal.h:53-53)
#[derive(Clone, Copy)]
pub struct RpcCtx<'a> {
    pub store: &'a SharedStore,
    pub authcfg: &'a Kadm5AuthConfig,
    pub expected_realm: &'a str,
    pub conf: &'a AcceptorConfig,
    pub programs: Programs,
    #[doc(hidden)]
    pub iprop_resync: Option<&'a Arc<IpropResync>>,
}

// MIT: `svc_register` (lib/rpc/svc.c:161-191)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Programs {
    pub kadm: bool,
    pub iprop: bool,
}

impl Programs {
    pub const BOTH: Self = Self {
        kadm: true,
        iprop: true,
    };
}

/// Undecoded call: no reply; connection goes on.
#[cfg(feature = "test-hooks")]
pub fn serve_kadm5_conn(
    store: SharedStore,
    authcfg: Arc<Kadm5AuthConfig>,
    expected_realm: String,
    rcache: ReplayCache,
    conf: Arc<AcceptorConfig>,
    mut stream: TcpStream,
) -> io::Result<()> {
    let peer = RpcPeer::new(stream.peer_addr().ok(), stream.local_addr().ok());
    let Some(mut conn) = Kadm5Conn::new(
        store,
        authcfg,
        expected_realm,
        rcache,
        conf,
        Programs::BOTH,
        peer,
        None,
        None,
    ) else {
        return Err(io::Error::other(
            "CSPRNG failure generating the kadm5 RPC handle",
        ));
    };
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

pub type UnhandledRpc = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Clone, Debug)]
pub struct RpcPeer {
    addr: String,
    remote: Option<SocketAddr>,
    local: Option<SocketAddr>,
}

impl RpcPeer {
    #[must_use]
    pub fn new(remote: Option<SocketAddr>, local: Option<SocketAddr>) -> Self {
        Self {
            addr: remote.map_or_else(String::new, |a| crate::listen::client_addr(a.ip())),
            remote,
            local,
        }
    }

    #[must_use]
    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub(super) fn remote_inet(&self) -> [u8; 4] {
        self.remote.as_ref().map_or([0; 4], sockaddr_in_addr)
    }

    pub(super) fn local_inet(&self) -> Option<[u8; 4]> {
        self.local.as_ref().map(sockaddr_in_addr)
    }
}

// MIT: `rendezvous_request` (lib/rpc/svc_tcp.c:280-307)
/// IPv6 flow info is read where IPv4 octets lie.
fn sockaddr_in_addr(a: &SocketAddr) -> [u8; 4] {
    match a {
        SocketAddr::V4(v4) => v4.ip().octets(),
        SocketAddr::V6(v6) => v6.flowinfo().to_ne_bytes(),
    }
}

pub(crate) struct Kadm5Conn {
    store: SharedStore,
    authcfg: Arc<Kadm5AuthConfig>,
    realm: String,
    rcache: ReplayCache,
    conf: Arc<AcceptorConfig>,
    programs: Programs,
    handle: Vec<u8>,
    sess: Kadm5RpcSession,
    peer: RpcPeer,
    report: Option<UnhandledRpc>,
    iprop_resync: Option<Arc<IpropResync>>,
}

impl Kadm5Conn {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        store: SharedStore,
        authcfg: Arc<Kadm5AuthConfig>,
        realm: String,
        rcache: ReplayCache,
        conf: Arc<AcceptorConfig>,
        programs: Programs,
        peer: RpcPeer,
        report: Option<UnhandledRpc>,
        iprop_resync: Option<Arc<IpropResync>>,
    ) -> Option<Self> {
        Some(Self {
            store,
            authcfg,
            realm,
            rcache,
            conf,
            programs,
            handle: random_handle()?,
            sess: Kadm5RpcSession::default(),
            peer,
            report,
            iprop_resync,
        })
    }

    fn handle(&mut self, rec: &[u8]) -> Result<Vec<u8>, Error> {
        let ctx = RpcCtx {
            store: &self.store,
            authcfg: &self.authcfg,
            expected_realm: &self.realm,
            conf: &self.conf,
            programs: self.programs,
            iprop_resync: self.iprop_resync.as_ref(),
        };
        let Kadm5RpcSession { gss, agss } = &mut self.sess;
        handle_rpc(ctx, &self.handle, gss, agss, &self.rcache, rec, &self.peer)
    }
}

impl RpcSession for Kadm5Conn {
    // MIT: `svc_do_xprt` (lib/rpc/svc.c:473-474)
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

    fn authenticated(&self) -> bool {
        self.sess.gss.is_some() || self.sess.agss.as_ref().is_some_and(|a| a.ctx.is_some())
    }
}

fn random_handle() -> Option<Vec<u8>> {
    let mut h = [0u8; 8];
    getrandom::getrandom(&mut h).ok()?;
    Some(h.to_vec())
}

/// At most 1 MiB.
pub(super) fn read_record(stream: &mut TcpStream) -> io::Result<Zeroizing<Vec<u8>>> {
    read_rpc_record_with(|buf| stream.read_exact(buf))
}

// MIT: `flush_out` (lib/rpc/xdr_rec.c:475-489)
// MIT: `fix_buf_size` (lib/rpc/xdr_rec.c:566-571)
/// One fragment, one write: no delayed-ACK stall. MIT fragments past 4000 B.
pub(super) fn write_record(stream: &mut impl Write, body: &[u8]) -> io::Result<()> {
    let n = u32::try_from(body.len()).unwrap_or(0) | LAST_FRAG;
    let mut rec = Zeroizing::new(Vec::with_capacity(4 + body.len()));
    rec.extend_from_slice(&n.to_be_bytes());
    rec.extend_from_slice(body);
    stream.write_all(&rec)?;
    stream.flush()
}

#[derive(Default)]
pub struct Kadm5RpcSession {
    gss: Option<RpcsecGss>,
    agss: Option<Agss>,
}

pub fn kadm5_handle_rpc(
    ctx: RpcCtx<'_>,
    handle: &[u8],
    sess: &mut Kadm5RpcSession,
    rcache: &ReplayCache,
    rec: &[u8],
    peer: &RpcPeer,
) -> Result<Vec<u8>, Error> {
    handle_rpc(
        ctx,
        handle,
        &mut sess.gss,
        &mut sess.agss,
        rcache,
        rec,
        peer,
    )
}

// MIT: `xdr_callmsg` (lib/rpc/rpc_callmsg.c:101-193)
// MIT: `gssrpc__authenticate` (lib/rpc/svc_auth.c:84-106)
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

    tracing::debug!(
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

    let kadm = prog == KADM_PROG && ctx.programs.kadm;
    let iprop = prog == IPROP_PROG
        && ctx.programs.iprop
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

// MIT: `gssrpc__svcauth_unix` (lib/rpc/svc_auth_unix.c:55-126)
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

#[derive(Clone, Copy)]
pub(super) enum ReplyVerf<'a> {
    None,
    Gss(&'a [u8]),
    AuthGssapi(&'a [u8]),
}

// MIT: `svcerr_noproc` (lib/rpc/svc.c:265-275)
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

// MIT: `svcerr_progvers` (lib/rpc/svc.c:352-367)
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

/// Reply body may carry keys in the clear.
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

pub(super) fn rpc_reply_agss_status(xid: u32, verf: &[u8], stat: u32) -> Vec<u8> {
    rpc_reply_status(xid, ReplyVerf::AuthGssapi(verf), stat)
}

pub(super) struct Gcred {
    pub(super) version: u32,
    pub(super) proc: u32,
    pub(super) seq_num: u32,
    pub(super) service: u32,
}

// MIT: `xdr_rpc_gss_cred` (lib/rpc/authgss_prot.c:72-90)
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

#[derive(Clone, Copy)]
pub(crate) struct RpcCallId {
    pub xid: u32,
    pub prog: u32,
    pub vers: u32,
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
