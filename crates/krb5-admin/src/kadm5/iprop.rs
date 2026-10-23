//! Incremental propagation (`kadmin/server/ipropd_svc.c`): the `IPROP_GET_UPDATES` / `IPROP_FULL_RESYNC` server side, answered from the update log ([`krb5_kdc::Ulog`]), and a replica's client of it ([`IpropClient`], kpropd's RPCSEC_GSS handle). The `kdb_incr_update_t` codec is `krb5_kdc`'s (`lib/kdb/iprop_xdr.c`): updates leave as the log stores them, keys wrapped under the master key.

use std::io;
use std::net::TcpStream;
use std::time::Duration;

use krb5_crypto::ProtocolKey;
use krb5_gss::GssContext;
use krb5_kdc::{IpropUpdate, SharedDump as SharedStore, TlData, UlogLast, UlogTime, UlogUpdates};
use krb5_log::klog::os_error_text;
use krb5_types::{PrincipalName, Ticket};
use nix::errno::Errno;
use zeroize::Zeroizing;

use super::auth_plugin::Kadm5AuthConfig;
use super::codes::{
    AUTH_INVALIDRESP, FLAVOR_GSS, FLAVOR_NONE, GARBAGE_ARGS, GSS_PRIVACY, GSS_S_COMPLETE,
    GSS_S_CONTINUE_NEEDED, IPROP_FULL_RESYNC, IPROP_FULL_RESYNC_EXT, IPROP_GET_UPDATES, IPROP_NULL,
    IPROP_PROG, IPROP_VERS, MSG_ACCEPTED, MSG_CALL, MSG_DENIED, MSG_REPLY, PROC_UNAVAIL,
    PROG_MISMATCH, PROG_UNAVAIL, REJECT_AUTH_ERROR, REJECT_RPC_MISMATCH, RPC_VERSION,
    RPCSEC_GSS_VERS, RPG_DATA, RPG_INIT, SUCCESS, SYSTEM_ERR,
};
use super::rpc::{read_record, rpc_call_bytes, write_record};
use super::xdr::{XdrR, XdrW};
use crate::Error;

// MIT: `iprop_get_updates_1_svc` (kadmin/server/ipropd_svc.c:191-200)
/// a caller who fails the iprop ACL gets permission denied and no entries.
// MIT: `ipropx_resync` (kadmin/server/ipropd_svc.c:400-424)
/// a granted full resync answers `UPDATE_OK` with a zero last entry; the dump comes by kprop.
pub(super) fn dispatch_iprop(
    store: &SharedStore,
    authcfg: &Kadm5AuthConfig,
    actor: &str,
    proc: u32,
    args: &[u8],
) -> Vec<u8> {
    if proc != IPROP_NULL && !authcfg.stack().iprop(actor) {
        return if proc == IPROP_FULL_RESYNC || proc == IPROP_FULL_RESYNC_EXT {
            encode_fullresync_status(UlogLast::default(), krb5_kdc::IPROP_PERM_DENIED)
        } else {
            encode_incr_status(krb5_kdc::IPROP_PERM_DENIED)
        };
    }
    match proc {
        IPROP_NULL => Vec::new(),
        IPROP_GET_UPDATES => {
            let mut r = XdrR::new(args);
            let last = UlogLast {
                sno: r.u32().unwrap_or(0),
                time: UlogTime {
                    seconds: r.u32().unwrap_or(0),
                    useconds: r.u32().unwrap_or(0),
                },
            };
            let g = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            encode_incr_result(&g.ulog_get_entries(last))
        }
        IPROP_FULL_RESYNC | IPROP_FULL_RESYNC_EXT => {
            encode_fullresync_status(UlogLast::default(), krb5_kdc::IPROP_OK)
        }
        _ => encode_incr_status(krb5_kdc::IPROP_FULL_RESYNC),
    }
}

// MIT: `xdr_kdb_last_t` (lib/kdb/iprop_xdr.c:309-318)
/// the serial, then the time's seconds and microseconds.
fn encode_kdb_last(w: &mut XdrW, last: UlogLast) {
    w.u32(last.sno);
    w.u32(last.time.seconds);
    w.u32(last.time.useconds);
}

pub(super) fn tl_u32(tl: &[TlData], ty: i32) -> Option<u32> {
    let t = tl.iter().find(|t| t.ty == ty)?;
    let b: [u8; 4] = t.contents.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

/// A `kdb_incr_result_t` with no updates and a zero last entry: what MIT's reply holds before any update was sent.
pub(super) fn encode_incr_status(status: u32) -> Vec<u8> {
    encode_incr_result(&UlogUpdates {
        status,
        ..UlogUpdates::default()
    })
}

/// A `kdb_incr_result_t`: the last entry, the updates as the log holds them, the status.
// MIT: `xdr_kdb_incr_result_t` (lib/kdb/iprop_xdr.c:321-332)
/// the last entry, the updates, then the status.
pub(super) fn encode_incr_result(got: &UlogUpdates) -> Vec<u8> {
    let mut w = XdrW::default();
    encode_kdb_last(&mut w, got.last);
    w.u32(u32::try_from(got.updates.len()).unwrap_or(0));
    for u in &got.updates {
        w.b.extend_from_slice(u);
    }
    w.u32(got.status);
    w.b
}

/// A `kdb_fullresync_result_t`: the last entry and the status.
pub(super) fn encode_fullresync_status(last: UlogLast, status: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    encode_kdb_last(&mut w, last);
    w.u32(status);
    w.b
}

// MIT: `IPROPX_VERSION_1` (include/iprop_hdr.h:43-43)
/// the highest dump version a replica loads.
const IPROPX_VERSION_1: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RpcFailure {
    CantEncodeArgs,
    CantSend(String),
    CantRecv(String),
    TimedOut,
    CantDecodeRes,
    VersMismatch(u32, u32),
    AuthError(u32),
    ProgUnavail,
    ProgVersMismatch(u32, u32),
    ProcUnavail,
    CantDecodeArgs,
    SystemError,
    Failed,
}

impl RpcFailure {
    // MIT: `clnt_sperror` (lib/rpc/clnt_perror.c:76-175)
    /// `s`, the status's text, then the system's error, why, or the versions.
    // MIT: `clnt_sperrno` (lib/rpc/clnt_perror.c:233-243)
    /// each status's text is `rpc_errlist`'s.
    #[must_use]
    pub fn sperror(&self, s: &str) -> String {
        let versions = |lo: &u32, hi: &u32| format!("; low version = {lo}, high version = {hi}");
        let (text, detail) = match self {
            Self::CantEncodeArgs => ("Can't encode arguments", String::new()),
            Self::CantSend(e) => ("Unable to send", format!("; errno = {e}")),
            Self::CantRecv(e) => ("Unable to receive", format!("; errno = {e}")),
            Self::TimedOut => ("Timed out", String::new()),
            Self::CantDecodeRes => ("Can't decode result", String::new()),
            Self::VersMismatch(lo, hi) => ("Incompatible versions of RPC", versions(lo, hi)),
            Self::AuthError(why) => (
                "Authentication error",
                format!("; why = {}", auth_errmsg(*why)),
            ),
            Self::ProgUnavail => ("Program unavailable", String::new()),
            Self::ProgVersMismatch(lo, hi) => ("Program/version mismatch", versions(lo, hi)),
            Self::ProcUnavail => ("Procedure unavailable", String::new()),
            Self::CantDecodeArgs => ("Server can't decode arguments", String::new()),
            Self::SystemError => ("Remote system error", String::new()),
            Self::Failed => ("Failed (unspecified error)", String::new()),
        };
        format!("{s}: RPC: {text}{detail}")
    }
}

// MIT: `auth_errmsg` (lib/rpc/clnt_perror.c:339-349)
/// an `auth_stat`'s text, and one the table lacks named by its number.
fn auth_errmsg(why: u32) -> String {
    const TEXTS: [&str; 8] = [
        "Authentication OK",
        "Invalid client credential",
        "Server rejected credential",
        "Invalid client verifier",
        "Server rejected verifier",
        "Client credential too weak",
        "Invalid server verifier",
        "Failed (unspecified error)",
    ];
    usize::try_from(why)
        .ok()
        .and_then(|i| TEXTS.get(i))
        .map_or_else(
            || format!("(unknown authentication error - {})", why.cast_signed()),
            |t| (*t).to_owned(),
        )
}

// MIT: `readtcp` (lib/rpc/clnt_tcp.c:434-490)
/// no reply within the call's timeout is `RPC_TIMEDOUT`, an early end of stream `ECONNRESET`, any other failure the system's error.
fn recv_failure(e: &io::Error) -> RpcFailure {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => RpcFailure::TimedOut,
        io::ErrorKind::UnexpectedEof => {
            RpcFailure::CantRecv(os_error_text(&io::Error::from(Errno::ECONNRESET)))
        }
        _ => RpcFailure::CantRecv(os_error_text(e)),
    }
}

enum ReplyStat {
    Success { verf: Vec<u8>, results: usize },
    Failed(RpcFailure),
}

// MIT: `gssrpc__seterr_reply` (lib/rpc/rpc_prot.c:238-295)
/// an accepted status other than success, and a denial, are the failure they name.
// MIT: `accepted` (lib/rpc/rpc_prot.c:179-212)
/// an accepted status no table names is `RPC_FAILED`.
// MIT: `rejected` (lib/rpc/rpc_prot.c:215-232)
/// a version mismatch carries the versions, an authentication error why.
fn read_reply(rec: &[u8]) -> Option<(u32, ReplyStat)> {
    let mut r = XdrR::new(rec);
    let xid = r.u32().ok()?;
    if r.u32().ok()? != MSG_REPLY {
        return None;
    }
    let stat = match r.u32().ok()? {
        MSG_ACCEPTED => {
            let _flavor = r.u32().ok()?;
            let verf = r.opaque().ok()?;
            match r.u32().ok()? {
                SUCCESS => ReplyStat::Success { verf, results: r.i },
                PROG_UNAVAIL => ReplyStat::Failed(RpcFailure::ProgUnavail),
                PROG_MISMATCH => {
                    ReplyStat::Failed(RpcFailure::ProgVersMismatch(r.u32().ok()?, r.u32().ok()?))
                }
                PROC_UNAVAIL => ReplyStat::Failed(RpcFailure::ProcUnavail),
                GARBAGE_ARGS => ReplyStat::Failed(RpcFailure::CantDecodeArgs),
                SYSTEM_ERR => ReplyStat::Failed(RpcFailure::SystemError),
                _ => ReplyStat::Failed(RpcFailure::Failed),
            }
        }
        MSG_DENIED => match r.u32().ok()? {
            REJECT_RPC_MISMATCH => {
                ReplyStat::Failed(RpcFailure::VersMismatch(r.u32().ok()?, r.u32().ok()?))
            }
            REJECT_AUTH_ERROR => ReplyStat::Failed(RpcFailure::AuthError(r.u32().ok()?)),
            _ => return None,
        },
        _ => return None,
    };
    Some((xid, stat))
}

// MIT: `clnttcp_call` (lib/rpc/clnt_tcp.c:246-352)
/// replies to other xids, and records that do not read as replies, are read past.
fn exchange(
    stream: &mut TcpStream,
    xid: u32,
    rec: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, ReplyStat), RpcFailure> {
    write_record(stream, rec).map_err(|e| RpcFailure::CantSend(os_error_text(&e)))?;
    loop {
        let reply = read_record(stream).map_err(|e| recv_failure(&e))?;
        if let Some((got, stat)) = read_reply(&reply)
            && got == xid
        {
            return Ok((reply, stat));
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncrReply {
    /// `ret`, an `update_status_t`.
    pub status: u32,
    /// `lastentry`: the serial and time the primary's update log ends at.
    pub last: UlogLast,
    /// The number of updates.
    pub count: usize,
    body: Vec<u8>,
}

impl IncrReply {
    /// The updates, their keys opened under `mkey`.
    /// decode or its keys do not open.
    pub fn updates(&self, mkey: Option<&ProtocolKey>) -> Result<Vec<IpropUpdate>, Error> {
        decode_incr_result(&self.body, mkey).map(|(.., updates)| updates)
    }
}

/// A replica's handle on its primary's iprop service: the connection and the RPCSEC_GSS context made on it, as MIT's `kadm5_init_with_skey` leaves one for `kiprop`.
pub struct IpropClient {
    stream: TcpStream,
    ctx: GssContext,
    handle: Vec<u8>,
    xid: u32,
    seq: u32,
    refreshes: u32,
}

impl std::fmt::Debug for IpropClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpropClient")
            .field("peer", &self.stream.peer_addr().ok())
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

impl IpropClient {
    // MIT: `init_any` (lib/kadm5/clnt/client_init.c:290-294)
    /// a kadm5 handle waits an hour for any reply.
    const TIMEOUT: Duration = Duration::from_hours(1);

    /// The handle on `stream`: an RPCSEC_GSS context with privacy, made with `ticket` and its `session` key as `cname` of `crealm`, the primary's AP-REP required.
    // MIT: `rpc_auth` (lib/kadm5/clnt/client_init.c:645-683)
    /// RPCSEC_GSS with the krb5 mechanism, privacy, and the mutual and replay flags.
    pub fn establish(
        mut stream: TcpStream,
        ticket: Ticket,
        session: &ProtocolKey,
        crealm: &krb5_types::Realm,
        cname: &PrincipalName,
    ) -> Result<Self, Error> {
        stream
            .set_read_timeout(Some(Self::TIMEOUT))
            .map_err(|e| Error::Inner(e.to_string()))?;
        let (mut ctx, token) = GssContext::init_sec_context(
            ticket,
            session,
            crealm,
            cname,
            krb5_gss::GSS_C_MUTUAL | krb5_gss::GSS_C_REPLAY,
            None,
            None,
        )
        .map_err(|e| Error::Inner(e.to_string()))?;
        let mut xid = 1u32;
        let handle = rpcsec_init(&mut stream, &mut ctx, session, &token, &mut xid)?;
        Ok(Self {
            stream,
            ctx,
            handle,
            xid,
            seq: 0,
            refreshes: 0,
        })
    }

    #[cfg(feature = "test-hooks")]
    #[must_use]
    pub fn refreshes(&self) -> u32 {
        self.refreshes
    }

    #[cfg(feature = "test-hooks")]
    pub fn skip_mic(&mut self) {
        let _ = self.ctx.get_mic(&[]);
    }

    /// `IPROP_GET_UPDATES` for the updates after `last`.
    // MIT: `iprop_get_updates_1` (kprop/kpropd_rpc.c:34-46)
    /// the `kdb_last_t` sent, a `kdb_incr_result_t` back.
    /// The call's [`RpcFailure`]; results that do not decode are `RPC_CANTDECODERES`.
    pub fn get_updates(&mut self, last: UlogLast) -> Result<IncrReply, RpcFailure> {
        let mut args = XdrW::default();
        encode_kdb_last(&mut args, last);
        let body = self.call(IPROP_GET_UPDATES, &args.b)?;
        let (status, sno, seconds, useconds, updates) =
            decode_incr_result(&body, None).map_err(|_| RpcFailure::CantDecodeRes)?;
        Ok(IncrReply {
            status,
            last: UlogLast {
                sno,
                time: UlogTime { seconds, useconds },
            },
            count: updates.len(),
            body,
        })
    }

    /// A full resync asked for: `IPROP_FULL_RESYNC_EXT` with the highest dump version this replica loads, else `IPROP_FULL_RESYNC` of a primary without that procedure. The status answered.
    // MIT: `full_resync` (kprop/kpropd.c:606-625)
    /// `IPROPX_VERSION_1` to the extended procedure, then on `RPC_PROCUNAVAIL` the plain one.
    pub fn full_resync(&mut self) -> Result<u32, RpcFailure> {
        let mut vers = XdrW::default();
        vers.u32(IPROPX_VERSION_1);
        let body = match self.call(IPROP_FULL_RESYNC_EXT, &vers.b) {
            Err(RpcFailure::ProcUnavail) => self.call(IPROP_FULL_RESYNC, &[])?,
            other => other?,
        };
        let mut r = XdrR::new(&body);
        let mut word = || r.u32().map_err(|_| RpcFailure::CantDecodeRes);
        for _ in 0..3 {
            word()?;
        }
        word()
    }

    /// verifier must be a MIC of the call's sequence number and whose results must unseal. A reply with another status is asked again twice before it is the failure.
    // MIT: `authgss_marshal` (lib/rpc/auth_gss.c:281-340)
    /// each call takes the next sequence number.
    // MIT: `authgss_validate` (lib/rpc/auth_gss.c:343-392)
    /// a verifier that is no MIC of that number is `AUTH_INVALIDRESP`.
    // MIT: `authgss_refresh` (lib/rpc/auth_gss.c:395-525)
    /// an established context's refresh is a call again.
    fn call(&mut self, proc: u32, args: &[u8]) -> Result<Vec<u8>, RpcFailure> {
        let mut refreshes = 2;
        loop {
            self.seq = self.seq.wrapping_add(1);
            let xid = self.xid;
            self.xid = self.xid.wrapping_add(1);
            let rec = rpcsec_data_call(&mut self.ctx, &self.handle, xid, self.seq, proc, args)
                .ok_or(RpcFailure::CantEncodeArgs)?;
            match exchange(&mut self.stream, xid, &rec)? {
                (reply, ReplyStat::Success { verf, results }) => {
                    if self.ctx.verify_mic(&self.seq.to_be_bytes(), &verf).is_err() {
                        return Err(RpcFailure::AuthError(AUTH_INVALIDRESP));
                    }
                    let sealed = reply.get(results..).unwrap_or_default();
                    return unwrap_results(&mut self.ctx, sealed, self.seq)
                        .ok_or(RpcFailure::CantDecodeRes);
                }
                (_, ReplyStat::Failed(f)) if refreshes == 0 => return Err(f),
                (_, ReplyStat::Failed(_)) => {
                    refreshes -= 1;
                    self.refreshes += 1;
                }
            }
        }
    }
}

fn rpcsec_init(
    stream: &mut TcpStream,
    ctx: &mut GssContext,
    ticket_session: &ProtocolKey,
    token: &[u8],
    xid: &mut u32,
) -> Result<Vec<u8>, Error> {
    let fail = |what: String| Error::Inner(format!("rpcsec init: {what}"));
    let mut cred = XdrW::default();
    cred.u32(RPCSEC_GSS_VERS);
    cred.u32(RPG_INIT);
    cred.u32(0);
    cred.u32(GSS_PRIVACY);
    cred.opaque(&[]);
    let mut arg = XdrW::default();
    arg.opaque(token);
    let mut refreshes = 2;
    let (reply, verf, results) = loop {
        let id = *xid;
        *xid = xid.wrapping_add(1);
        let rec = rpc_call_bytes(
            super::rpc::RpcCallId {
                xid: id,
                prog: IPROP_PROG,
                vers: IPROP_VERS,
                proc: IPROP_NULL,
            },
            FLAVOR_GSS,
            &cred.b,
            FLAVOR_NONE,
            &[],
            &arg.b,
        );
        match exchange(stream, id, &rec).map_err(|f| fail(f.sperror("call")))? {
            (reply, ReplyStat::Success { verf, results }) => break (reply, verf, results),
            (_, ReplyStat::Failed(f)) if refreshes == 0 => return Err(fail(f.sperror("call"))),
            (_, ReplyStat::Failed(_)) => refreshes -= 1,
        }
    };
    let mut r = XdrR::new(reply.get(results..).unwrap_or_default());
    let handle = r.opaque()?;
    let major = r.u32()?;
    let _minor = r.u32()?;
    let window = r.u32()?;
    let out = r.opaque()?;
    if major != GSS_S_COMPLETE && major != GSS_S_CONTINUE_NEEDED {
        return Err(fail(format!("gss major {major}")));
    }
    if out.is_empty() {
        return Err(fail("no AP-REP".into()));
    }
    ctx.process_ap_rep(&out, ticket_session)
        .map_err(|e| fail(format!("ap-rep: {e}")))?;
    ctx.verify_mic(&window.to_be_bytes(), &verf)
        .map_err(|e| fail(format!("window mic: {e}")))?;
    Ok(handle)
}

// MIT: `xdr_rpc_gss_wrap_data` (lib/rpc/authgss_prot.c:130-182)
/// with privacy, the sequence number and the arguments are sealed together.
fn rpcsec_data_call(
    ctx: &mut GssContext,
    handle: &[u8],
    xid: u32,
    seq: u32,
    proc: u32,
    args: &[u8],
) -> Option<Vec<u8>> {
    let mut cred = XdrW::default();
    cred.u32(RPCSEC_GSS_VERS);
    cred.u32(RPG_DATA);
    cred.u32(seq);
    cred.u32(GSS_PRIVACY);
    cred.opaque(handle);
    let mut header = XdrW::default();
    header.u32(xid);
    header.u32(MSG_CALL);
    header.u32(RPC_VERSION);
    header.u32(IPROP_PROG);
    header.u32(IPROP_VERS);
    header.u32(proc);
    header.u32(FLAVOR_GSS);
    header.opaque(&cred.b);
    let mic = ctx.get_mic(&header.b).ok()?;
    let mut inner = Vec::with_capacity(4 + args.len());
    inner.extend_from_slice(&seq.to_be_bytes());
    inner.extend_from_slice(args);
    let wrap = ctx.wrap_with_rrc(&inner, 0).ok()?;
    let mut arg = XdrW::default();
    arg.opaque(&wrap);
    Some(rpc_call_bytes(
        super::rpc::RpcCallId {
            xid,
            prog: IPROP_PROG,
            vers: IPROP_VERS,
            proc,
        },
        FLAVOR_GSS,
        &cred.b,
        FLAVOR_GSS,
        &mic,
        &arg.b,
    ))
}

fn unwrap_results(ctx: &mut GssContext, sealed: &[u8], seq: u32) -> Option<Vec<u8>> {
    let wrapped = XdrR::new(sealed).opaque().ok()?;
    let (plain, conf) = ctx.unwrap_conf(&wrapped).ok()?;
    let (got, results) = plain.split_first_chunk::<4>()?;
    (conf && u32::from_be_bytes(*got) == seq).then(|| results.to_vec())
}

pub(super) fn decode_incr_result(
    b: &[u8],
    mkey: Option<&ProtocolKey>,
) -> Result<(u32, u32, u32, u32, Vec<IpropUpdate>), Error> {
    let mut r = XdrR::new(b);
    let last = r.u32()?;
    let sec = r.u32()?;
    let usec = r.u32()?;
    let n = r.u32()? as usize;
    let mut entries = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        let (update, len) = krb5_kdc::decode_incr_update(r.rest(), mkey).map_err(|e| match e {
            krb5_kdc::XdrError::Short => Error::GarbageArgs,
            krb5_kdc::XdrError::Invalid(s) => Error::Inner(s),
        })?;
        r.i += len;
        entries.push(update);
    }
    let status = r.u32()?;
    Ok((status, last, sec, usec, entries))
}
