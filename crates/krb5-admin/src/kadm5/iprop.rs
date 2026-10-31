//! Keys stay wrapped under the master key.

use std::io;
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use krb5_config::ClientContext;
use krb5_crypto::ProtocolKey;
use krb5_gss::GssContext;
use krb5_kdc::{IpropUpdate, SharedDump as SharedStore, TlData, UlogLast, UlogTime, UlogUpdates};
use krb5_log::klog::{Severity, os_error_text};
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
use super::log::{Caller, iprop_log_resync, iprop_log_unauth, iprop_log_updates};
use super::rpc::{read_record, rpc_call_bytes, write_record};
use super::xdr::{XdrR, XdrW};
use crate::Error;
use crate::kadmind::admin_syslog;
use crate::kprop::{
    KPROP_SERVICE, KPROPD_IO_TIMEOUT, KpropDump, kprop_get_tickets, kprop_open_connection,
    kprop_sendauth, kprop_update_last_prop_file, kprop_xmit_database,
};

// MIT: `krb5_iprop_prog_1` (kadmin/server/ipropd_svc.c:583-588)
// MIT: `iprop_get_updates_1_svc` (kadmin/server/ipropd_svc.c:191-200)
// MIT: `ipropx_resync` (kadmin/server/ipropd_svc.c:400-424)
pub(super) fn dispatch_iprop(
    store: &SharedStore,
    authcfg: &Kadm5AuthConfig,
    resync: Option<&Arc<IpropResync>>,
    who: &Caller<'_>,
    proc: u32,
    args: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut r = XdrR::new(args);
    let (last, vers) = match proc {
        IPROP_GET_UPDATES => {
            let sno = r.u32()?;
            let seconds = r.u32()?;
            let useconds = r.u32()?;
            let time = UlogTime { seconds, useconds };
            (UlogLast { sno, time }, 0)
        }
        IPROP_FULL_RESYNC_EXT => (UlogLast::default(), r.u32()?),
        _ => (UlogLast::default(), 0),
    };
    if proc != IPROP_NULL && !authcfg.stack().iprop(who.client) {
        return Ok(
            if proc == IPROP_FULL_RESYNC || proc == IPROP_FULL_RESYNC_EXT {
                iprop_log_unauth("iprop_full_resync_1", who);
                encode_fullresync_status(UlogLast::default(), krb5_kdc::IPROP_PERM_DENIED)
            } else {
                iprop_log_unauth("iprop_get_updates_1", who);
                encode_incr_status(krb5_kdc::IPROP_PERM_DENIED)
            },
        );
    }
    Ok(match proc {
        IPROP_NULL => Vec::new(),
        IPROP_GET_UPDATES => {
            let entries = store
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .ulog_entries(last);
            let (got, err) = match entries {
                Ok(got) => (got, None),
                Err(e) => (
                    UlogUpdates {
                        status: krb5_kdc::IPROP_ERROR,
                        ..UlogUpdates::default()
                    },
                    Some(e.to_string()),
                ),
            };
            iprop_log_updates(who, last.sno, &got, err.as_deref());
            encode_incr_result(&got)
        }
        IPROP_FULL_RESYNC | IPROP_FULL_RESYNC_EXT => full_resync(store, resync, who, vers),
        _ => encode_incr_status(krb5_kdc::IPROP_FULL_RESYNC),
    })
}

#[doc(hidden)]
pub struct IpropResync {
    pub dump_file: PathBuf,
    pub kprop_port: Option<String>,
    pub profile: krb5_config::Krb5Conf,
    pub realm: String,
}

// MIT: `ipropx_resync` (kadmin/server/ipropd_svc.c:322-424)
fn full_resync(
    store: &SharedStore,
    resync: Option<&Arc<IpropResync>>,
    who: &Caller<'_>,
    vers: u32,
) -> Vec<u8> {
    let Some(resync) = resync else {
        return encode_fullresync_status(UlogLast::default(), krb5_kdc::IPROP_OK);
    };
    let Some(host) = getclhoststr(who.client) else {
        admin_syslog(Severity::Err, "iprop_full_resync_1: getclhoststr failed");
        return encode_fullresync_status(UlogLast::default(), krb5_kdc::IPROP_ERROR);
    };
    let store = store.clone();
    let resync = Arc::clone(resync);
    let host = host.to_owned();
    let (tx, rx) = std::sync::mpsc::channel();
    let log = crate::kadmind::thread_admin_log();
    let spawned = std::thread::Builder::new().spawn(move || {
        crate::kadmind::set_thread_admin_log(log);
        let _ = tx.send(nix::unistd::gettid().as_raw());
        run_resync(&store, &resync, &host, vers);
    });
    if let Err(e) = spawned {
        admin_syslog(
            Severity::Err,
            &format!("iprop_full_resync_1: fork failed: {}", os_error_text(&e)),
        );
        return encode_fullresync_status(UlogLast::default(), krb5_kdc::IPROP_ERROR);
    }
    // MIT logs its child's pid; ours is a thread.
    iprop_log_resync(who, rx.recv().unwrap_or_default());
    encode_fullresync_status(UlogLast::default(), krb5_kdc::IPROP_OK)
}

// MIT: `getclhoststr` (kadmin/server/ipropd_svc.c:245-255)
fn getclhoststr(princ: &str) -> Option<&str> {
    let start = princ.find('/')? + 1;
    let end = princ[start..].find('@')? + start;
    (end > start).then(|| &princ[start..end])
}

// MIT: `ipropx_resync` (kadmin/server/ipropd_svc.c:355-420)
fn run_resync(store: &SharedStore, resync: &IpropResync, host: &str, vers: u32) {
    if let Err(e) = resync_dump_and_send(store, resync, host, vers) {
        admin_syslog(Severity::Err, &format!("iprop_full_resync to {host}: {e}"));
    }
}

// MIT: `main` (kprop/kprop.c:93-120)
fn resync_dump_and_send(
    store: &SharedStore,
    resync: &IpropResync,
    host: &str,
    vers: u32,
) -> Result<(), String> {
    krb5_kdc::conditional_iprop_dump_fresh(store, &resync.dump_file, vers)
        .map_err(|e| e.to_string())?;
    let file = resync.dump_file.to_string_lossy();
    let ctx = ClientContext::new(resync.profile.clone());
    let creds = kprop_get_tickets(&ctx, &resync.realm, host, None).map_err(|e| e.to_string())?;
    let mut dump = KpropDump::open(&file).map_err(|e| e.to_string())?;
    let port = resync.kprop_port.as_deref().unwrap_or(KPROP_SERVICE);
    let (mut stream, sender) = kprop_open_connection(host, port).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(KPROPD_IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(KPROPD_IO_TIMEOUT)))
        .map_err(|e| e.to_string())?;
    let mut auth = kprop_sendauth(&mut stream, &creds, sender).map_err(|e| e.to_string())?;
    let size = dump.size();
    kprop_xmit_database(&mut stream, &mut auth, dump.file(), size, false)
        .map_err(|e| e.to_string())?;
    if let Err(e) = kprop_update_last_prop_file(host, &file) {
        admin_syslog(Severity::Err, &format!("iprop_full_resync to {host}: {e}"));
    }
    dump.close().map_err(|e| e.to_string())
}

// MIT: `xdr_kdb_fullresync_result_t` (lib/kdb/iprop_xdr.c:334-343)
fn fullresync_status(body: &[u8]) -> Result<u32, RpcFailure> {
    let mut r = XdrR::new(body);
    let mut word = || r.u32().map_err(|_| RpcFailure::CantDecodeRes);
    for _ in 0..3 {
        word()?;
    }
    word()
}

// MIT: `xdr_kdb_last_t` (lib/kdb/iprop_xdr.c:309-318)
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

pub(super) fn encode_incr_status(status: u32) -> Vec<u8> {
    encode_incr_result(&UlogUpdates {
        status,
        ..UlogUpdates::default()
    })
}

/// Last entry, updates as logged, status.
// MIT: `xdr_kdb_incr_result_t` (lib/kdb/iprop_xdr.c:321-332)
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

pub(super) fn encode_fullresync_status(last: UlogLast, status: u32) -> Vec<u8> {
    let mut w = XdrW::default();
    encode_kdb_last(&mut w, last);
    w.u32(status);
    w.b
}

// MIT: `IPROPX_VERSION_1` (include/iprop_hdr.h:43-43)
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
    // MIT: `clnt_sperrno` (lib/rpc/clnt_perror.c:233-243)
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
// MIT: `accepted` (lib/rpc/rpc_prot.c:179-212)
// MIT: `rejected` (lib/rpc/rpc_prot.c:215-232)
/// Mismatch: versions; auth error: why.
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
    pub status: u32,
    pub last: UlogLast,
    pub count: usize,
    body: Vec<u8>,
}

impl IncrReply {
    /// Updates, their keys opened under `mkey`.
    pub fn updates(&self, mkey: Option<&ProtocolKey>) -> Result<Vec<IpropUpdate>, Error> {
        decode_incr_result(&self.body, mkey).map(|(.., updates)| updates)
    }
}

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
    const TIMEOUT: Duration = Duration::from_hours(1);

    /// Handle on `stream`: RPCSEC_GSS with privacy.
    // MIT: `rpc_auth` (lib/kadm5/clnt/client_init.c:645-683)
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
            None,
            0,
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

    // MIT: `iprop_get_updates_1` (kprop/kpropd_rpc.c:34-46)
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

    // MIT: `full_resync` (kprop/kpropd.c:606-625)
    pub fn full_resync(&mut self) -> Result<u32, RpcFailure> {
        let mut vers = XdrW::default();
        vers.u32(IPROPX_VERSION_1);
        let body = match self.call(IPROP_FULL_RESYNC_EXT, &vers.b) {
            Err(RpcFailure::ProcUnavail) => self.call(IPROP_FULL_RESYNC, &[])?,
            other => other?,
        };
        fullresync_status(&body)
    }

    #[cfg(feature = "test-hooks")]
    pub fn full_resync_v0(&mut self) -> Result<u32, RpcFailure> {
        let body = self.call(IPROP_FULL_RESYNC, &[])?;
        fullresync_status(&body)
    }

    /// MIC of the sequence; results must unseal.
    // MIT: `authgss_marshal` (lib/rpc/auth_gss.c:281-340)
    // MIT: `authgss_validate` (lib/rpc/auth_gss.c:343-392)
    // MIT: `authgss_refresh` (lib/rpc/auth_gss.c:395-525)
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
