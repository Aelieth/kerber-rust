use std::io::{self, IoSlice, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsFd as _, AsRawFd as _, OwnedFd, RawFd};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::TryRecvError;
use std::time::{Duration, Instant, SystemTime};

use krb5_log::klog::{self, Severity, os_error_text};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{setsockopt, sockopt};
use zeroize::Zeroizing;

use crate::daemon::Shutdown;
#[cfg(feature = "daemon")]
use crate::daemon::Signals;
use crate::listen::{
    Datagram, WHILE_DISPATCHING_TCP, WHILE_DISPATCHING_UDP, recv_from_to, send_udp_reply,
};
use crate::plugins::{
    OtpOutcome, OtpResume, ParkedOtp, set_otp_park_enabled, set_otp_resume, take_otp_park,
};

// MIT: `max_stream_data_connections` (lib/apputils/net-server.c:85-85)
pub const MAX_STREAM_DATA_CONNECTIONS: usize = 45;
// MIT: `accept_stream_connection` (lib/apputils/net-server.c:1278-1278)
pub(crate) const BUFSIZ: usize = 1024 * 1024;
pub const MAX_REQUEST: usize = BUFSIZ - 4;
// MIT: `MAX_DGRAM_SIZE` (include/osconf.hin:113-113)
const MAX_DGRAM_SIZE: usize = 65_536;
/// A read chunk, not a request cap.
pub(crate) const READ_SIZE: usize = 64 * 1024;
// MIT: `setnolinger` (lib/apputils/net-server.c:687-691)
const NO_LINGER: nix::libc::linger = nix::libc::linger {
    l_onoff: 0,
    l_linger: 0,
};
// MIT: `wait_per_try` (lib/rpc/svc_tcp.c:344-344)
pub(crate) const RPC_READ_WAIT: Duration = Duration::from_secs(35);
pub const MAX_RPC_RECORD: usize = 1024 * 1024;
// MIT: `LAST_FRAG` (lib/rpc/xdr_rec.c:94-94)
const LAST_FRAG: u32 = 0x8000_0000;
const ACCEPT_FAILURE_PAUSE: Duration = Duration::from_millis(20);

pub(crate) trait Stream: Read + Write {
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

impl Stream for TcpStream {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::local_addr(self)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    Send(Vec<u8>),
    Nothing,
    Failed(String),
    Parked,
}

// MIT: `dispatch` (include/net-server.h:84-86)
pub trait Dispatch {
    fn dispatch(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        request: &[u8],
        is_tcp: bool,
        log: &mut dyn Log,
    ) -> Reply;

    fn dispatch_resume(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        request: &[u8],
        is_tcp: bool,
        log: &mut dyn Log,
    ) -> Reply {
        let _ = (local, remote, request, is_tcp, log);
        Reply::Nothing
    }

    fn otp_wake_fd(&self) -> Option<OwnedFd> {
        None
    }

    fn make_toolong_error(&mut self) -> Result<Vec<u8>, String>;

    // MIT: `do_reset` (lib/apputils/net-server.c:246-253)
    fn reset(&mut self) {}

    // MIT: `rendezvous_request` (lib/rpc/svc_tcp.c:296-307)
    fn rpc_session(
        &mut self,
        remote: SocketAddr,
        local: SocketAddr,
    ) -> Option<Box<dyn RpcSession>> {
        let _ = (remote, local);
        None
    }
}

pub trait RpcSession {
    fn call(&mut self, record: &[u8]) -> RpcReply;

    fn authenticated(&self) -> bool {
        false
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RpcReply {
    Send(Vec<u8>),
    Nothing,
    Close,
}

pub trait Log {
    fn syslog(&mut self, severity: Severity, msg: &str);

    fn com_err(&mut self, error: &str, msg: &str) {
        self.syslog(Severity::Err, &format!("{error} - {msg}"));
    }

    fn reopen(&mut self) {}
}

pub struct Klog;

impl Log for Klog {
    fn syslog(&mut self, severity: Severity, msg: &str) {
        klog::syslog(severity, msg);
    }

    fn reopen(&mut self) {
        klog::reopen();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnType {
    Tcp,
    Rpc,
}

impl ConnType {
    // MIT: `conn_type_names` (lib/apputils/net-server.c:120-128)
    fn name(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Rpc => "RPC",
        }
    }
}

enum Io {
    Read {
        lenbuf: [u8; 4],
        offset: usize,
        msglen: usize,
        body: Vec<u8>,
    },
    Write {
        lenbuf: [u8; 4],
        reply: Vec<u8>,
        sent: usize,
    },
    Rpc(RpcConn),
    // Held during OTP verify: not polled, not LRU-killed, resumed on verdict.
    Parked,
}

struct RpcConn {
    session: Box<dyn RpcSession>,
    phase: RpcPhase,
    authenticated: bool,
    last_active: Instant,
}

enum RpcPhase {
    Read(RpcRead),
    Write(RpcWrite),
}

struct RpcRead {
    mark: [u8; 4],
    mark_off: usize,
    frag_left: usize,
    last: bool,
    record: Zeroizing<Vec<u8>>,
    taken: usize,
    started: Option<Instant>,
}

impl RpcRead {
    fn new() -> Self {
        Self {
            mark: [0; 4],
            mark_off: 0,
            frag_left: 0,
            last: false,
            record: Zeroizing::new(Vec::new()),
            taken: 0,
            started: None,
        }
    }
}

struct RpcWrite {
    framed: Zeroizing<Vec<u8>>,
    sent: usize,
}

#[derive(Clone)]
pub struct ServeLimits {
    pub max_record: usize,
    pub rpc_record_deadline: Duration,
    pub idle_timeout: Option<Duration>,
    pub per_ip_conns: Option<usize>,
}

impl Default for ServeLimits {
    fn default() -> Self {
        Self {
            max_record: MAX_RPC_RECORD,
            rpc_record_deadline: RPC_READ_WAIT,
            idle_timeout: None,
            per_ip_conns: None,
        }
    }
}

pub(crate) struct Conn<S> {
    id: u64,
    event: u64,
    stream: S,
    fd: RawFd,
    ctype: ConnType,
    remote: SocketAddr,
    addrbuf: String,
    start_time: u64,
    io: Io,
}

impl<S> Conn<S> {
    pub(crate) fn writing(&self) -> bool {
        matches!(self.io, Io::Write { .. })
            || matches!(
                &self.io,
                Io::Rpc(RpcConn {
                    phase: RpcPhase::Write(_),
                    ..
                })
            )
    }

    fn parked(&self) -> bool {
        matches!(self.io, Io::Parked)
    }
}

enum Step {
    Wait,
    Close,
    Respond(Reply),
    Park(Box<Parked>),
}

pub(crate) struct Streams<S> {
    conns: Vec<Conn<S>>,
    max: usize,
    cap: usize,
    next_id: u64,
    next_event: u64,
    scratch: Vec<u8>,
    limits: ServeLimits,
}

impl<S: Stream> Streams<S> {
    pub(crate) fn new(max: usize, cap: usize) -> Self {
        Self {
            conns: Vec::new(),
            max,
            cap,
            next_id: 0,
            next_event: 0,
            scratch: vec![0; READ_SIZE],
            limits: ServeLimits::default(),
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.conns.len()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.conns.is_empty()
    }

    #[cfg(test)]
    fn read_drive(&mut self, id: u64, app: &mut dyn Dispatch, log: &mut dyn Log) {
        self.readable(id, app, &mut Vec::new(), log);
    }

    pub(crate) fn conns(&self) -> impl Iterator<Item = &Conn<S>> {
        self.conns.iter()
    }

    fn position(&self, id: u64) -> Option<usize> {
        self.conns.iter().position(|c| c.id == id)
    }

    fn new_event(&mut self) -> u64 {
        let event = self.next_event;
        self.next_event += 1;
        event
    }

    pub(crate) fn add(
        &mut self,
        stream: S,
        fd: RawFd,
        remote: SocketAddr,
        now: u64,
        log: &mut dyn Log,
    ) -> u64 {
        let conn = Conn {
            id: 0,
            event: 0,
            stream,
            fd,
            ctype: ConnType::Tcp,
            remote,
            addrbuf: print_addr_port(&remote),
            start_time: now,
            io: Io::Read {
                lenbuf: [0; 4],
                offset: 0,
                msglen: 0,
                body: Vec::new(),
            },
        };
        self.insert(conn, log)
    }

    // MIT: `accept_rpc_connection` (lib/apputils/net-server.c:1560-1572)
    pub(crate) fn add_rpc(
        &mut self,
        stream: S,
        fd: RawFd,
        (remote, addrbuf): (SocketAddr, String),
        session: Box<dyn RpcSession>,
        now: u64,
        log: &mut dyn Log,
    ) -> u64 {
        let conn = Conn {
            id: 0,
            event: 0,
            stream,
            fd,
            ctype: ConnType::Rpc,
            remote,
            addrbuf,
            start_time: now,
            io: Io::Rpc(RpcConn {
                session,
                phase: RpcPhase::Read(RpcRead::new()),
                authenticated: false,
                last_active: Instant::now(),
            }),
        };
        self.insert(conn, log)
    }

    fn insert(&mut self, mut conn: Conn<S>, log: &mut dyn Log) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        conn.id = id;
        conn.event = self.new_event();
        self.conns.push(conn);
        if self.conns.len() > self.max {
            self.kill_lru(id, log);
        }
        id
    }

    // MIT: `kill_lru_stream_connection` (lib/apputils/net-server.c:1198-1223)
    fn kill_lru(&mut self, newest: u64, log: &mut dyn Log) {
        log.syslog(Severity::Info, "too many connections");
        // Evict unauthenticated RPC first, then oldest, as MIT.
        let mut victim: Option<usize> = None;
        let mut victim_unauth = false;
        for (i, c) in self.conns.iter().enumerate().rev() {
            if c.id == newest || c.parked() {
                continue;
            }
            let unauth = matches!(
                &c.io,
                Io::Rpc(RpcConn {
                    authenticated: false,
                    ..
                })
            );
            let better = match victim {
                None => true,
                Some(_) if unauth != victim_unauth => unauth,
                Some(o) => self.conns[o].start_time > c.start_time,
            };
            if better {
                victim = Some(i);
                victim_unauth = unauth;
            }
        }
        if let Some(i) = victim {
            let c = &self.conns[i];
            log.syslog(
                Severity::Info,
                &format!("dropping {} fd {} from {}", c.ctype.name(), c.fd, c.addrbuf),
            );
            self.free_socket(i, log);
        }
    }

    // MIT: `free_socket` (lib/apputils/net-server.c:511-519)
    fn free_socket(&mut self, i: usize, log: &mut dyn Log) {
        let conn = self.conns.swap_remove(i);
        log.syslog(Severity::Info, &format!("closing down fd {}", conn.fd));
    }

    fn next_rpc_deadline(&self) -> Option<Instant> {
        let deadline = self.limits.rpc_record_deadline;
        let idle = self.limits.idle_timeout;
        self.conns
            .iter()
            .filter_map(|c| match &c.io {
                Io::Rpc(rpc) => {
                    let rec = match &rpc.phase {
                        RpcPhase::Read(rd) => rd.started.map(|s| s + deadline),
                        RpcPhase::Write(_) => None,
                    };
                    let idl = idle.map(|d| rpc.last_active + d);
                    [rec, idl].into_iter().flatten().min()
                }
                _ => None,
            })
            .min()
    }

    fn sweep_rpc(&mut self, now: Instant, log: &mut dyn Log) {
        let deadline = self.limits.rpc_record_deadline;
        let idle = self.limits.idle_timeout;
        let mut i = 0;
        while i < self.conns.len() {
            let over = match &self.conns[i].io {
                Io::Rpc(rpc) => {
                    let record_over = matches!(&rpc.phase, RpcPhase::Read(rd)
                        if rd.started.is_some_and(|s| now.saturating_duration_since(s) > deadline));
                    let idle_over =
                        idle.is_some_and(|d| now.saturating_duration_since(rpc.last_active) > d);
                    record_over || idle_over
                }
                _ => false,
            };
            if over {
                let c = &self.conns[i];
                log.syslog(
                    Severity::Info,
                    &format!(
                        "RPC record timed out, dropping fd {} from {}",
                        c.fd, c.addrbuf
                    ),
                );
                self.free_socket(i, log);
            } else {
                i += 1;
            }
        }
    }

    // MIT: `verto_free` (util/verto/verto.c:593-595)
    pub(crate) fn open_fds(&self) -> Vec<RawFd> {
        let mut open: Vec<(u64, RawFd)> = self.conns.iter().map(|c| (c.event, c.fd)).collect();
        open.sort_unstable_by_key(|c| std::cmp::Reverse(c.0));
        open.into_iter().map(|(_, fd)| fd).collect()
    }

    // MIT: `process_stream_connection_read` (lib/apputils/net-server.c:1375-1453)
    /// Deviation: failed getsockname closes the stream; MIT uses the freed event.
    pub(crate) fn readable(
        &mut self,
        id: u64,
        app: &mut dyn Dispatch,
        parks: &mut Vec<Parked>,
        log: &mut dyn Log,
    ) {
        let Some(i) = self.position(id) else {
            return;
        };
        let step = if matches!(self.conns[i].io, Io::Rpc(_)) {
            self.rpc_step(i)
        } else {
            self.read_step(i, app, log)
        };
        match step {
            Step::Wait => {}
            Step::Close => self.free_socket(i, log),
            Step::Respond(reply) => self.respond(i, reply, log),
            Step::Park(p) => {
                self.conns[i].io = Io::Parked;
                parks.push(*p);
            }
        }
    }

    pub(crate) fn resume(&mut self, conn_id: u64, reply: Reply, log: &mut dyn Log) {
        let Some(i) = self.position(conn_id) else {
            return;
        };
        self.respond(i, reply, log);
    }

    fn read_step(&mut self, i: usize, app: &mut dyn Dispatch, log: &mut dyn Log) -> Step {
        let Self {
            conns,
            scratch,
            cap,
            ..
        } = self;
        let cap = *cap;
        let conn = &mut conns[i];
        let Io::Read {
            lenbuf,
            offset,
            msglen,
            body,
        } = &mut conn.io
        else {
            return Step::Wait;
        };
        if *offset < 4 {
            match conn.stream.read(&mut lenbuf[*offset..]) {
                Ok(0) => return Step::Close,
                Ok(n) => *offset += n,
                Err(e) if retry(&e) => return Step::Wait,
                Err(_) => return Step::Close,
            }
            if *offset == 4 {
                *msglen = usize::try_from(u32::from_be_bytes(*lenbuf)).unwrap_or(usize::MAX);
                if *msglen > cap {
                    log.syslog(
                        Severity::Err,
                        &format!(
                            "TCP client {} wants {} bytes, cap is {cap}",
                            conn.addrbuf, *msglen
                        ),
                    );
                    return match app.make_toolong_error() {
                        Ok(reply) => Step::Respond(Reply::Send(reply)),
                        Err(e) => {
                            log.syslog(
                                Severity::Err,
                                &format!("error constructing KRB_ERR_FIELD_TOOLONG error! {e}"),
                            );
                            Step::Close
                        }
                    };
                }
                *body = Vec::with_capacity(*msglen);
            }
            return Step::Wait;
        }
        let want = (*msglen - (*offset - 4)).min(READ_SIZE);
        if want == 0 {
            return Step::Close;
        }
        match conn.stream.read(&mut scratch[..want]) {
            Ok(0) => return Step::Close,
            Ok(n) => {
                body.extend_from_slice(&scratch[..n]);
                *offset += n;
            }
            Err(e) if retry(&e) => return Step::Wait,
            Err(_) => return Step::Close,
        }
        if *offset < *msglen + 4 {
            return Step::Wait;
        }
        let local = match conn.stream.local_addr() {
            Ok(a) => a,
            Err(e) => {
                log.syslog(
                    Severity::Err,
                    &format!("getsockname failed: {}", os_error_text(&e)),
                );
                return Step::Close;
            }
        };
        let request = std::mem::take(body);
        let remote = conn.remote;
        let conn_id = conn.id;
        let reply = dispatch_contained(app, local, remote, &request, true, log);
        if matches!(reply, Reply::Parked) {
            return match take_otp_park() {
                Some(otp) => Step::Park(Box::new(Parked {
                    otp,
                    request,
                    local,
                    remote,
                    target: ParkTarget::Tcp { conn: conn_id },
                })),
                None => Step::Wait,
            };
        }
        Step::Respond(reply)
    }

    // MIT: `process_rpc_connection` (lib/apputils/net-server.c:1577-1587)
    // MIT: `svc_do_xprt` (lib/rpc/svc.c:469-531)
    /// Deviation: a panic closes that connection; MIT's process would end.
    fn rpc_step(&mut self, i: usize) -> Step {
        let max_record = self.limits.max_record;
        let now = Instant::now();
        let conn = &mut self.conns[i];
        let Io::Rpc(rpc) = &mut conn.io else {
            return Step::Wait;
        };
        let RpcPhase::Read(rd) = &mut rpc.phase else {
            return Step::Wait;
        };
        // Record read across polls, non-blocking: a stalled peer holds no thread.
        loop {
            if rd.mark_off < 4 {
                match conn.stream.read(&mut rd.mark[rd.mark_off..]) {
                    Ok(0) => return Step::Close,
                    Ok(n) => {
                        rd.started.get_or_insert(now);
                        rpc.last_active = now;
                        rd.mark_off += n;
                        if rd.mark_off == 4 {
                            let mark = u32::from_be_bytes(rd.mark);
                            rd.last = mark & LAST_FRAG != 0;
                            rd.frag_left = usize::try_from(mark & !LAST_FRAG).unwrap_or(usize::MAX);
                            rd.taken = rd.taken.saturating_add(4).saturating_add(rd.frag_left);
                            if rd.taken > max_record {
                                return Step::Close;
                            }
                        }
                    }
                    Err(e) if retry(&e) => return Step::Wait,
                    Err(_) => return Step::Close,
                }
            } else if rd.frag_left > 0 {
                let chunk = rd.frag_left.min(READ_SIZE);
                let base = rd.record.len();
                reserve_wiped(&mut rd.record, chunk);
                rd.record.resize(base + chunk, 0);
                match conn.stream.read(&mut rd.record[base..]) {
                    Ok(0) => return Step::Close,
                    Ok(n) => {
                        rpc.last_active = now;
                        rd.record.truncate(base + n);
                        rd.frag_left -= n;
                    }
                    Err(e) if retry(&e) => {
                        rd.record.truncate(base);
                        return Step::Wait;
                    }
                    Err(_) => {
                        rd.record.truncate(base);
                        return Step::Close;
                    }
                }
            } else if rd.last {
                break;
            } else {
                rd.mark_off = 0;
            }
        }
        let record = std::mem::replace(&mut rd.record, Zeroizing::new(Vec::new()));
        let called = catch_unwind(AssertUnwindSafe(|| {
            (rpc.session.call(&record), rpc.session.authenticated())
        }));
        drop(record);
        match called {
            Ok((RpcReply::Send(reply), authed)) => {
                rpc.authenticated |= authed;
                match frame_rpc_record(&reply) {
                    Ok(framed) => {
                        rpc.phase = RpcPhase::Write(RpcWrite { framed, sent: 0 });
                        Step::Wait
                    }
                    Err(_) => Step::Close,
                }
            }
            Ok((RpcReply::Nothing, authed)) => {
                rpc.authenticated |= authed;
                rpc.phase = RpcPhase::Read(RpcRead::new());
                Step::Wait
            }
            Ok((RpcReply::Close, _)) => Step::Close,
            Err(_) => {
                panic_isolated();
                Step::Close
            }
        }
    }

    // MIT: `process_stream_response` (lib/apputils/net-server.c:1314-1336)
    // MIT: `prepare_for_dispatch` (lib/apputils/net-server.c:1350-1355)
    fn respond(&mut self, i: usize, reply: Reply, log: &mut dyn Log) {
        let mut conn = self.conns.swap_remove(i);
        match reply {
            Reply::Send(reply) => {
                if let Ok(n) = u32::try_from(reply.len()) {
                    conn.io = Io::Write {
                        lenbuf: n.to_be_bytes(),
                        reply,
                        sent: 0,
                    };
                    conn.event = self.new_event();
                    self.conns.push(conn);
                }
            }
            Reply::Nothing => {}
            Reply::Failed(text) => log.com_err(&text, WHILE_DISPATCHING_TCP),
            Reply::Parked => debug_assert!(false, "Reply::Parked reached respond"),
        }
    }

    // MIT: `process_stream_connection_write` (lib/apputils/net-server.c:1467-1494)
    pub(crate) fn writable(&mut self, id: u64, log: &mut dyn Log) {
        let Some(i) = self.position(id) else {
            return;
        };
        let conn = &mut self.conns[i];
        match &mut conn.io {
            Io::Write {
                lenbuf,
                reply,
                sent,
            } => {
                let total = 4 + reply.len();
                let wrote = if *sent < 4 {
                    conn.stream
                        .write_vectored(&[IoSlice::new(&lenbuf[*sent..]), IoSlice::new(reply)])
                } else {
                    conn.stream
                        .write_vectored(&[IoSlice::new(&reply[*sent - 4..])])
                };
                match wrote {
                    Ok(n) if n > 0 => {
                        *sent = (*sent + n).min(total);
                        if *sent < total {
                            return;
                        }
                    }
                    Err(e) if retry(&e) => return,
                    _ => {}
                }
            }
            Io::Rpc(rpc) => {
                rpc.last_active = Instant::now();
                let finished = {
                    let RpcPhase::Write(w) = &mut rpc.phase else {
                        return;
                    };
                    match conn.stream.write(&w.framed[w.sent..]) {
                        Ok(n) if n > 0 => {
                            w.sent += n;
                            if w.sent < w.framed.len() {
                                return;
                            }
                            true
                        }
                        Err(e) if retry(&e) => return,
                        _ => false,
                    }
                };
                if finished {
                    rpc.phase = RpcPhase::Read(RpcRead::new());
                    return;
                }
            }
            _ => return,
        }
        self.free_socket(i, log);
    }
}

impl Streams<TcpStream> {
    /// Deviation: failed non-blocking set: closed, so it can't stall the loop.
    pub(crate) fn accept(
        &mut self,
        listener: &TcpListener,
        now: u64,
        log: &mut dyn Log,
    ) -> io::Result<()> {
        let (stream, remote) = match listener.accept() {
            Ok(taken) => taken,
            Err(e) if passing_accept_failure(&e) => return Ok(()),
            Err(e) => return Err(e),
        };
        let fd = stream.as_raw_fd();
        self.admit(stream, fd, remote, now, log);
        Ok(())
    }

    fn admit(
        &mut self,
        stream: TcpStream,
        fd: RawFd,
        remote: SocketAddr,
        now: u64,
        log: &mut dyn Log,
    ) {
        if !below_fd_setsize(fd) {
            return;
        }
        if stream.set_nonblocking(true).is_err() {
            return;
        }
        let _ = setsockopt(&stream, sockopt::Linger, &NO_LINGER);
        let _ = setsockopt(&stream, sockopt::KeepAlive, &true);
        self.add(stream, fd, remote, now, log);
    }

    /// Deviation: unreadable local address closes the connection; MIT leaves it open.
    pub(crate) fn accept_rpc(
        &mut self,
        listener: &TcpListener,
        now: u64,
        app: &mut dyn Dispatch,
        log: &mut dyn Log,
    ) -> io::Result<()> {
        let (stream, remote) = match listener.accept() {
            Ok(taken) => taken,
            Err(e) if passing_accept_failure(&e) => return Ok(()),
            Err(e) => return Err(e),
        };
        let Ok(local) = stream.local_addr() else {
            return Ok(());
        };
        let fd = stream.as_raw_fd();
        self.admit_rpc(stream, fd, (remote, local), now, app, log);
        Ok(())
    }

    // MIT: `makefd_xprt` (lib/rpc/svc_tcp.c:231-236)
    fn admit_rpc(
        &mut self,
        stream: TcpStream,
        fd: RawFd,
        (remote, local): (SocketAddr, SocketAddr),
        now: u64,
        app: &mut dyn Dispatch,
        log: &mut dyn Log,
    ) {
        if !below_fd_setsize(fd) {
            let _ = writeln!(io::stderr(), "svc_tcp: makefd_xprt: fd too high");
            return;
        }
        if let Some(cap) = self.limits.per_ip_conns {
            let from_ip = self
                .conns
                .iter()
                .filter(|c| matches!(c.ctype, ConnType::Rpc) && c.remote.ip() == remote.ip())
                .count();
            if from_ip >= cap {
                log.syslog(
                    Severity::Info,
                    &format!("too many RPC connections from {}", remote.ip()),
                );
                return;
            }
        }
        // Accept gives no O_NONBLOCK: set it so rpc_step never blocks; fail closed.
        if stream.set_nonblocking(true).is_err() {
            return;
        }
        let addrbuf = stream
            .peer_addr()
            .map_or_else(|_| "<unknown>".to_owned(), |a| print_addr_port(&a));
        let made = catch_unwind(AssertUnwindSafe(|| app.rpc_session(remote, local)));
        let session = made.unwrap_or_else(|_| {
            panic_isolated();
            None
        });
        if let Some(session) = session {
            self.add_rpc(stream, fd, (remote, addrbuf), session, now, log);
        }
    }
}

fn below_fd_setsize(fd: RawFd) -> bool {
    usize::try_from(fd).is_ok_and(|n| n < nix::libc::FD_SETSIZE)
}

fn passing_accept_failure(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted
    )
}

// MIT: `xdrrec_getbytes` (lib/rpc/xdr_rec.c:245-266)
/// Deviation: past 1 MiB, empty fragments included, the record stops unread.
pub fn read_rpc_record_with<F>(mut read_exact: F) -> io::Result<Zeroizing<Vec<u8>>>
where
    F: FnMut(&mut [u8]) -> io::Result<()>,
{
    let mut record = Zeroizing::new(Vec::new());
    let mut taken = 0usize;
    loop {
        let mut mark = [0u8; 4];
        read_exact(&mut mark)?;
        let mark = u32::from_be_bytes(mark);
        let len = usize::try_from(mark & !LAST_FRAG).unwrap_or(usize::MAX);
        taken = taken.saturating_add(4).saturating_add(len);
        if taken > MAX_RPC_RECORD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "rpc record"));
        }
        let start = record.len();
        reserve_wiped(&mut record, len);
        record.resize(start + len, 0);
        read_exact(&mut record[start..])?;
        if mark & LAST_FRAG != 0 {
            return Ok(record);
        }
    }
}

fn reserve_wiped(buf: &mut Zeroizing<Vec<u8>>, more: usize) {
    let need = buf.len().saturating_add(more);
    if need <= buf.capacity() {
        return;
    }
    let mut grown = Zeroizing::new(Vec::with_capacity(
        need.max(buf.capacity().saturating_mul(2)),
    ));
    grown.extend_from_slice(buf);
    *buf = grown;
}

// MIT: `flush_out` (lib/rpc/xdr_rec.c:475-489)
fn frame_rpc_record(body: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    let len = u32::try_from(body.len())
        .ok()
        .filter(|n| n & LAST_FRAG == 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rpc reply"))?;
    let mut record = Zeroizing::new(Vec::with_capacity(4 + body.len()));
    record.extend_from_slice(&(len | LAST_FRAG).to_be_bytes());
    record.extend_from_slice(body);
    Ok(record)
}

fn dispatch_contained(
    app: &mut dyn Dispatch,
    local: SocketAddr,
    remote: SocketAddr,
    request: &[u8],
    is_tcp: bool,
    log: &mut dyn Log,
) -> Reply {
    let run = catch_unwind(AssertUnwindSafe(|| {
        app.dispatch(local, remote, request, is_tcp, log)
    }));
    run.unwrap_or_else(|_| {
        panic_isolated();
        Reply::Nothing
    })
}

fn panic_isolated() {
    tracing::error!(
        event = krb5_log::events::KDC_TRANSPORT,
        correlation_id = krb5_log::current_correlation_id(),
        component = "krb5-kdc",
        outcome = "error",
        error = "request panic isolated",
    );
}

pub(crate) struct Parked {
    otp: ParkedOtp,
    request: Vec<u8>,
    local: SocketAddr,
    remote: SocketAddr,
    target: ParkTarget,
}

enum ParkTarget {
    Udp { sock: usize, recv: Datagram },
    Tcp { conn: u64 },
}

fn shrink_timeout(base: PollTimeout, until: Instant, now: Instant) -> PollTimeout {
    let left = until.saturating_duration_since(now).as_millis();
    let cut = PollTimeout::from(u16::try_from(left).unwrap_or(u16::MAX).max(1));
    if base.is_some() && base <= cut {
        base
    } else {
        cut
    }
}

fn dispatch_resume_contained(
    app: &mut dyn Dispatch,
    local: SocketAddr,
    remote: SocketAddr,
    request: &[u8],
    is_tcp: bool,
    log: &mut dyn Log,
) -> Reply {
    let run = catch_unwind(AssertUnwindSafe(|| {
        app.dispatch_resume(local, remote, request, is_tcp, log)
    }));
    run.unwrap_or_else(|_| {
        panic_isolated();
        Reply::Nothing
    })
}

// Verdict in -> resume; deadline passed -> fail closed; else keep waiting.
fn resolve_parks(
    parks: &mut Vec<Parked>,
    app: &mut dyn Dispatch,
    sockets: &Sockets<'_>,
    streams: &mut Streams<TcpStream>,
    log: &mut dyn Log,
) {
    if parks.is_empty() {
        return;
    }
    let now = Instant::now();
    let mut still = Vec::new();
    for p in std::mem::take(parks) {
        let outcome = match p.otp.rx.try_recv() {
            Ok(v) => OtpOutcome::Verdict(v),
            Err(TryRecvError::Empty) if now < p.otp.deadline => {
                still.push(p);
                continue;
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => OtpOutcome::TimedOut,
        };
        if let Some(reparked) = resume_one(p, outcome, app, sockets, streams, log) {
            still.push(reparked);
        }
    }
    *parks = still;
}

fn resume_one(
    p: Parked,
    outcome: OtpOutcome,
    app: &mut dyn Dispatch,
    sockets: &Sockets<'_>,
    streams: &mut Streams<TcpStream>,
    log: &mut dyn Log,
) -> Option<Parked> {
    let Parked {
        otp,
        request,
        local,
        remote,
        target,
    } = p;
    let is_tcp = matches!(target, ParkTarget::Tcp { .. });
    set_otp_resume(Some(OtpResume {
        token_index: otp.token_index,
        started: otp.started,
        token_type: otp.token_type,
        username: otp.username,
        outcome,
    }));
    let reply = dispatch_resume_contained(app, local, remote, &request, is_tcp, log);
    if matches!(reply, Reply::Parked) {
        let otp = take_otp_park()?;
        return Some(Parked {
            otp,
            request,
            local,
            remote,
            target,
        });
    }
    match target {
        ParkTarget::Udp { sock, recv } => match reply {
            Reply::Send(bytes) => {
                if let Err(e) = send_udp_reply(&sockets.udp[sock], &bytes, &recv) {
                    tracing::error!(
                        event = krb5_log::events::KDC_TRANSPORT,
                        correlation_id = krb5_log::current_correlation_id(),
                        component = "krb5-kdc",
                        outcome = "error",
                        error = %e,
                    );
                }
            }
            Reply::Failed(text) => log.com_err(&text, WHILE_DISPATCHING_UDP),
            Reply::Nothing | Reply::Parked => {}
        },
        ParkTarget::Tcp { conn } => streams.resume(conn, reply, log),
    }
    None
}

pub enum Wake<'a> {
    #[cfg(feature = "daemon")]
    Signals(&'a Signals),
    Shutdown(&'a Shutdown),
    Flag {
        stop: &'a AtomicBool,
        every: Duration,
    },
}

#[derive(Clone, Copy, Default)]
pub struct Sockets<'a> {
    pub udp: &'a [UdpSocket],
    pub tcp: &'a [TcpListener],
    pub rpc: &'a [TcpListener],
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

enum Ready {
    Wake,
    OtpWake,
    Udp(usize),
    Listener(usize),
    Rpc(usize),
    Stream { id: u64, writing: bool },
}

/// Deviation: failed accept waits 20 ms, so EMFILE doesn't spin the loop.
struct Paused(Vec<Option<Instant>>);

impl Paused {
    fn new(n: usize) -> Self {
        Self(vec![None; n])
    }

    fn ready(&self, i: usize, now: Instant) -> bool {
        self.0
            .get(i)
            .copied()
            .flatten()
            .is_none_or(|until| until <= now)
    }

    fn pause(&mut self, i: usize, now: Instant) {
        if let Some(p) = self.0.get_mut(i) {
            *p = now.checked_add(ACCEPT_FAILURE_PAUSE);
        }
    }

    fn timeout(&self, base: PollTimeout, now: Instant) -> PollTimeout {
        let Some(until) = self.0.iter().flatten().filter(|u| **u > now).min() else {
            return base;
        };
        let left = until.saturating_duration_since(now).as_millis();
        let cut = PollTimeout::from(u16::try_from(left).unwrap_or(u16::MAX).max(1));
        if base.is_some() && base <= cut {
            base
        } else {
            cut
        }
    }
}

struct ParkEnabledGuard;

impl Drop for ParkEnabledGuard {
    fn drop(&mut self) {
        set_otp_park_enabled(false);
    }
}

// MIT: `loop_setup_signals` (lib/apputils/net-server.c:265-284)
/// Runtime ignores SIGPIPE.
// MIT: `setup_socket` (lib/apputils/net-server.c:844-851)
pub fn run(
    app: &mut dyn Dispatch,
    sockets: &Sockets<'_>,
    max_streams: usize,
    cap: usize,
    limits: ServeLimits,
    wake: &Wake<'_>,
    log: &mut dyn Log,
) -> io::Result<Vec<RawFd>> {
    for u in sockets.udp {
        u.set_nonblocking(true)?;
    }
    for t in sockets.tcp {
        t.set_nonblocking(true)?;
    }
    let mut streams: Streams<TcpStream> = Streams::new(max_streams, cap);
    streams.limits = limits;
    let mut paused = Paused::new(sockets.tcp.len() + sockets.rpc.len());
    let mut pkt = vec![0u8; MAX_DGRAM_SIZE];
    let mut otp_fd = app.otp_wake_fd();
    set_otp_park_enabled(otp_fd.is_some());
    let _park_enabled = ParkEnabledGuard;
    let mut parks: Vec<Parked> = Vec::new();
    let (pipe, timeout) = match wake {
        #[cfg(feature = "daemon")]
        Wake::Signals(s) => match s.wake_fd() {
            Some(fd) => (Some(fd), PollTimeout::NONE),
            None => (None, PollTimeout::from(1000u16)),
        },
        Wake::Shutdown(sd) => match sd.wake_fd() {
            Some(fd) => (Some(fd), PollTimeout::NONE),
            None => (None, PollTimeout::from(1000u16)),
        },
        Wake::Flag { every, .. } => {
            let ms = u16::try_from(every.as_millis()).unwrap_or(u16::MAX).max(1);
            (None, PollTimeout::from(ms))
        }
    };
    let already_stopped = match wake {
        Wake::Shutdown(sd) => sd.stop_requested(),
        Wake::Flag { stop, .. } => stop.load(Ordering::Relaxed),
        // Signals keeps its pipe wake: a stop during start-up still logs `do_break`.
        #[cfg(feature = "daemon")]
        Wake::Signals(_) => false,
    };
    if already_stopped {
        return Ok(streams.open_fds());
    }
    loop {
        let next_deadline = parks
            .iter()
            .map(|p| p.otp.deadline)
            .chain(streams.next_rpc_deadline())
            .min();
        let ready = wait(
            pipe,
            otp_fd.as_ref(),
            sockets,
            &streams,
            &paused,
            timeout,
            next_deadline,
        )?;
        for r in ready {
            match r {
                Ready::Wake => {
                    drain(pipe);
                }
                Ready::OtpWake => {
                    if drain(otp_fd.as_ref()) {
                        otp_fd = None;
                        set_otp_park_enabled(false);
                    }
                }
                Ready::Udp(i) => {
                    process_packet(i, &sockets.udp[i], &mut pkt, app, &mut parks, log);
                }
                Ready::Listener(i) => {
                    if streams.accept(&sockets.tcp[i], now_secs(), log).is_err() {
                        paused.pause(i, Instant::now());
                    }
                }
                Ready::Rpc(i) => {
                    if streams
                        .accept_rpc(&sockets.rpc[i], now_secs(), app, log)
                        .is_err()
                    {
                        paused.pause(sockets.tcp.len() + i, Instant::now());
                    }
                }
                Ready::Stream { id, writing: false } => {
                    streams.readable(id, app, &mut parks, log);
                }
                Ready::Stream { id, writing: true } => streams.writable(id, log),
            }
        }
        resolve_parks(&mut parks, app, sockets, &mut streams, log);
        streams.sweep_rpc(Instant::now(), log);
        match wake {
            #[cfg(feature = "daemon")]
            Wake::Signals(s) => {
                if s.take_hup() {
                    log.syslog(Severity::Debug, "Got signal to reset");
                    log.reopen();
                    app.reset();
                }
                if s.stop_requested() {
                    // MIT: `do_break` (lib/apputils/net-server.c:235-238)
                    log.syslog(Severity::Debug, "Got signal to request exit");
                    return Ok(streams.open_fds());
                }
            }
            Wake::Shutdown(sd) => {
                if sd.stop_requested() {
                    return Ok(streams.open_fds());
                }
            }
            Wake::Flag { stop, .. } => {
                if stop.load(Ordering::Relaxed) {
                    return Ok(streams.open_fds());
                }
            }
        }
    }
}

fn wait(
    pipe: Option<&OwnedFd>,
    otp: Option<&OwnedFd>,
    sockets: &Sockets<'_>,
    streams: &Streams<TcpStream>,
    paused: &Paused,
    timeout: PollTimeout,
    park_deadline: Option<Instant>,
) -> io::Result<Vec<Ready>> {
    let input = PollFlags::POLLIN;
    let now = Instant::now();
    let mut what = Vec::new();
    let mut fds = Vec::new();
    if let Some(p) = pipe {
        what.push(Ready::Wake);
        fds.push(PollFd::new(p.as_fd(), input));
    }
    if let Some(fd) = otp {
        what.push(Ready::OtpWake);
        fds.push(PollFd::new(fd.as_fd(), input));
    }
    for (i, u) in sockets.udp.iter().enumerate() {
        what.push(Ready::Udp(i));
        fds.push(PollFd::new(u.as_fd(), input));
    }
    for (i, t) in sockets.tcp.iter().enumerate() {
        if paused.ready(i, now) {
            what.push(Ready::Listener(i));
            fds.push(PollFd::new(t.as_fd(), input));
        }
    }
    for (i, r) in sockets.rpc.iter().enumerate() {
        if paused.ready(sockets.tcp.len() + i, now) {
            what.push(Ready::Rpc(i));
            fds.push(PollFd::new(r.as_fd(), input));
        }
    }
    for c in streams.conns() {
        if c.parked() {
            continue;
        }
        let writing = c.writing();
        what.push(Ready::Stream { id: c.id, writing });
        let flags = if writing { PollFlags::POLLOUT } else { input };
        fds.push(PollFd::new(c.stream.as_fd(), flags));
    }
    let base = match park_deadline {
        Some(dl) => shrink_timeout(timeout, dl, now),
        None => timeout,
    };
    match poll(&mut fds, paused.timeout(base, now)) {
        Ok(_) => {}
        Err(nix::errno::Errno::EINTR) => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    }
    Ok(what
        .into_iter()
        .zip(&fds)
        .filter(|(_, f)| f.revents().is_some_and(|r| !r.is_empty()))
        .map(|(w, _)| w)
        .collect())
}

fn drain(pipe: Option<&OwnedFd>) -> bool {
    let Some(p) = pipe else {
        return false;
    };
    let mut buf = [0u8; 64];
    loop {
        match nix::unistd::read(p, &mut buf) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
}

// MIT: `process_packet` (lib/apputils/net-server.c:1150-1188)
// MIT: `process_packet_response` (lib/apputils/net-server.c:1101-1105)
fn process_packet(
    sock_i: usize,
    sock: &UdpSocket,
    buf: &mut [u8],
    app: &mut dyn Dispatch,
    parks: &mut Vec<Parked>,
    log: &mut dyn Log,
) {
    let d = match recv_from_to(sock, buf) {
        Ok(d) => d,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::Interrupted
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::ConnectionRefused
            ) =>
        {
            return;
        }
        Err(e) => {
            log.com_err(&os_error_text(&e), "while receiving from network");
            return;
        }
    };
    if d.len == 0 {
        return;
    }
    let local = match d.to {
        Some(p) => SocketAddr::new(p.addr, sock.local_addr().map_or(0, |a| a.port())),
        None => sock
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0))),
    };
    let request = &buf[..d.len];
    match dispatch_contained(app, local, d.from, request, false, log) {
        Reply::Send(reply) => {
            if let Err(e) = send_udp_reply(sock, &reply, &d) {
                tracing::error!(
                    event = krb5_log::events::KDC_TRANSPORT,
                    correlation_id = krb5_log::current_correlation_id(),
                    component = "krb5-kdc",
                    outcome = "error",
                    error = %e,
                );
            }
        }
        Reply::Nothing => {}
        Reply::Failed(text) => log.com_err(&text, WHILE_DISPATCHING_UDP),
        Reply::Parked => {
            if let Some(otp) = take_otp_park() {
                parks.push(Parked {
                    otp,
                    request: request.to_vec(),
                    local,
                    remote: d.from,
                    target: ParkTarget::Udp {
                        sock: sock_i,
                        recv: d,
                    },
                });
            }
        }
    }
}

#[cfg(test)]
fn process_packet_test(
    sock: &UdpSocket,
    buf: &mut [u8],
    app: &mut dyn Dispatch,
    log: &mut dyn Log,
) {
    process_packet(0, sock, buf, app, &mut Vec::new(), log);
}

fn retry(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

// MIT: `k5_print_addr_port` (lib/krb5/os/addr.c:98-106)
pub(crate) fn print_addr_port(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(a) => a.to_string(),
        SocketAddr::V6(a) if a.scope_id() != 0 => {
            let scope = nix::net::if_::if_indextoname(a.scope_id()).map_or_else(
                |_| a.scope_id().to_string(),
                |name| name.to_string_lossy().into_owned(),
            );
            format!("[{}%{scope}]:{}", a.ip(), a.port())
        }
        SocketAddr::V6(a) => format!("[{}]:{}", a.ip(), a.port()),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use super::*;

    enum Arrival {
        Bytes(Vec<u8>),
        Stall,
    }

    enum Take {
        Fail(io::ErrorKind),
    }

    #[derive(Default)]
    struct Wire {
        incoming: VecDeque<Arrival>,
        out: Vec<u8>,
        writes: VecDeque<Take>,
        reads: usize,
        closed: bool,
    }

    struct Fake(Rc<RefCell<Wire>>);

    impl Read for Fake {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut w = self.0.borrow_mut();
            w.reads += 1;
            match w.incoming.pop_front() {
                None | Some(Arrival::Stall) => Err(io::ErrorKind::WouldBlock.into()),
                Some(Arrival::Bytes(b)) => {
                    let n = b.len().min(buf.len());
                    buf[..n].copy_from_slice(&b[..n]);
                    if n < b.len() {
                        w.incoming.push_front(Arrival::Bytes(b[n..].to_vec()));
                    }
                    Ok(n)
                }
            }
        }
    }

    impl Write for Fake {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_vectored(&[IoSlice::new(buf)])
        }

        fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
            let mut w = self.0.borrow_mut();
            if let Some(Take::Fail(k)) = w.writes.pop_front() {
                return Err(k.into());
            }
            let mut n = 0;
            for b in bufs {
                w.out.extend_from_slice(b);
                n += b.len();
            }
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            self.0.borrow_mut().closed = true;
        }
    }

    impl Stream for Fake {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("192.0.2.88:88".parse().unwrap())
        }
    }

    #[derive(Default)]
    struct Lines(Vec<(Severity, String)>);

    impl Log for Lines {
        fn syslog(&mut self, severity: Severity, msg: &str) {
            self.0.push((severity, msg.to_owned()));
        }
    }

    impl Lines {
        fn take(&mut self) -> Vec<(Severity, String)> {
            std::mem::take(&mut self.0)
        }
    }

    type Calls = Rc<RefCell<Vec<Vec<u8>>>>;

    struct Session {
        calls: Calls,
        replies: VecDeque<RpcReply>,
        panic: bool,
    }

    impl RpcSession for Session {
        fn call(&mut self, record: &[u8]) -> RpcReply {
            self.calls.borrow_mut().push(record.to_vec());
            assert!(!self.panic, "call panicked");
            self.replies
                .pop_front()
                .unwrap_or_else(|| RpcReply::Send(b"answer".to_vec()))
        }
    }

    struct App {
        requests: Vec<(SocketAddr, SocketAddr, Vec<u8>, bool)>,
        reply: Reply,
        toolong: Result<Vec<u8>, String>,
        panic: bool,
        rpc: Option<Calls>,
        otp: RefCell<Option<OwnedFd>>,
    }

    impl Default for App {
        fn default() -> Self {
            Self {
                requests: Vec::new(),
                reply: Reply::Send(b"the reply".to_vec()),
                toolong: Ok(b"too long".to_vec()),
                panic: false,
                rpc: None,
                otp: RefCell::new(None),
            }
        }
    }

    impl Dispatch for App {
        fn dispatch(
            &mut self,
            local: SocketAddr,
            remote: SocketAddr,
            request: &[u8],
            is_tcp: bool,
            _log: &mut dyn Log,
        ) -> Reply {
            self.requests
                .push((local, remote, request.to_vec(), is_tcp));
            assert!(!self.panic, "dispatch panicked");
            match &self.reply {
                Reply::Send(r) => Reply::Send(r.clone()),
                Reply::Nothing => Reply::Nothing,
                Reply::Failed(t) => Reply::Failed(t.clone()),
                Reply::Parked => Reply::Parked,
            }
        }

        fn make_toolong_error(&mut self) -> Result<Vec<u8>, String> {
            self.toolong.clone()
        }

        fn otp_wake_fd(&self) -> Option<OwnedFd> {
            self.otp.borrow_mut().take()
        }

        fn rpc_session(
            &mut self,
            _remote: SocketAddr,
            _local: SocketAddr,
        ) -> Option<Box<dyn RpcSession>> {
            let calls = Rc::clone(self.rpc.as_ref()?);
            Some(Box::new(Session {
                calls,
                replies: VecDeque::new(),
                panic: false,
            }))
        }
    }

    const NO_BYTES: [u8; 0] = [];
    const NO_LINES: [(Severity, String); 0] = [];

    fn info(msg: &str) -> (Severity, String) {
        (Severity::Info, msg.to_owned())
    }

    fn err(msg: &str) -> (Severity, String) {
        (Severity::Err, msg.to_owned())
    }

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut v = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    fn fragment(body: &[u8], last: bool) -> Vec<u8> {
        let bit = if last { LAST_FRAG } else { 0 };
        let mut v = (u32::try_from(body.len()).unwrap() | bit)
            .to_be_bytes()
            .to_vec();
        v.extend_from_slice(body);
        v
    }

    fn peer(n: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], n))
    }

    fn one(now: u64) -> (Streams<Fake>, u64, Rc<RefCell<Wire>>, Lines) {
        let mut t = Streams::new(MAX_STREAM_DATA_CONNECTIONS, MAX_REQUEST);
        let wire = Rc::new(RefCell::new(Wire::default()));
        let mut log = Lines::default();
        let id = t.add(Fake(Rc::clone(&wire)), 7, peer(4242), now, &mut log);
        (t, id, wire, log)
    }

    fn rpc_add(
        t: &mut Streams<Fake>,
        fd: RawFd,
        port: u16,
        (replies, panic): (Vec<RpcReply>, bool),
        log: &mut Lines,
    ) -> (u64, Rc<RefCell<Wire>>, Calls) {
        let wire = Rc::new(RefCell::new(Wire::default()));
        let calls = Calls::default();
        let session = Box::new(Session {
            calls: Rc::clone(&calls),
            replies: replies.into(),
            panic,
        });
        let addrbuf = print_addr_port(&peer(port));
        let id = t.add_rpc(
            Fake(Rc::clone(&wire)),
            fd,
            (peer(port), addrbuf),
            session,
            100,
            log,
        );
        (id, wire, calls)
    }

    fn rpc_one(replies: Vec<RpcReply>) -> (Streams<Fake>, u64, Rc<RefCell<Wire>>, Calls, Lines) {
        let mut t = Streams::new(MAX_STREAM_DATA_CONNECTIONS, MAX_REQUEST);
        let mut log = Lines::default();
        let (id, wire, calls) = rpc_add(&mut t, 7, 4242, (replies, false), &mut log);
        (t, id, wire, calls, log)
    }

    fn arrive(wire: &Rc<RefCell<Wire>>, a: Arrival) {
        wire.borrow_mut().incoming.push_back(a);
    }

    #[test]
    fn a_length_past_the_buffer_is_field_toolong_then_closed() {
        for (n, line) in [
            (
                1_048_573_u32,
                "TCP client 192.0.2.1:4242 wants 1048573 bytes, cap is 1048572",
            ),
            (
                0x8000_0000,
                "TCP client 192.0.2.1:4242 wants 2147483648 bytes, cap is 1048572",
            ),
        ] {
            let (mut t, id, wire, mut log) = one(100);
            let mut app = App::default();
            arrive(&wire, Arrival::Bytes(n.to_be_bytes().to_vec()));
            t.read_drive(id, &mut app, &mut log);
            assert_eq!(log.take(), [err(line)]);
            assert_eq!(app.requests.len(), 0);
            t.writable(id, &mut log);
            assert_eq!(wire.borrow().out, framed(b"too long"));
            assert!(t.is_empty());
            assert_eq!(log.take(), [info("closing down fd 7")]);
        }
        let (mut t, id, wire, mut log) = one(100);
        let mut app = App::default();
        arrive(&wire, Arrival::Bytes(1_048_572_u32.to_be_bytes().to_vec()));
        t.read_drive(id, &mut app, &mut log);
        assert_eq!(log.take(), NO_LINES, "the cap itself is taken");
        assert!(!t.conns().next().unwrap().writing());
        let (mut t, id, wire, mut log) = one(100);
        let mut app = App {
            toolong: Err("Cannot allocate memory".into()),
            ..App::default()
        };
        arrive(
            &wire,
            Arrival::Bytes(0x8000_0000_u32.to_be_bytes().to_vec()),
        );
        t.read_drive(id, &mut app, &mut log);
        assert!(t.is_empty());
        assert_eq!(wire.borrow().out, NO_BYTES);
        assert_eq!(
            log.take(),
            [
                err("TCP client 192.0.2.1:4242 wants 2147483648 bytes, cap is 1048572"),
                err("error constructing KRB_ERR_FIELD_TOOLONG error! Cannot allocate memory"),
                info("closing down fd 7"),
            ]
        );
    }

    fn fill(
        t: &mut Streams<Fake>,
        log: &mut Lines,
        n: usize,
        second: impl Fn(usize) -> u64,
    ) -> Vec<(u64, Rc<RefCell<Wire>>)> {
        (1..=n)
            .map(|i| {
                let wire = Rc::new(RefCell::new(Wire::default()));
                let fd = RawFd::try_from(i + 9).unwrap();
                let port = u16::try_from(i).unwrap();
                let id = t.add(Fake(Rc::clone(&wire)), fd, peer(port), second(i), log);
                (id, wire)
            })
            .collect()
    }

    fn evicted(conns: &[(u64, Rc<RefCell<Wire>>)]) -> Vec<usize> {
        conns
            .iter()
            .enumerate()
            .filter(|(_, (_, w))| w.borrow().closed)
            .map(|(i, _)| i + 1)
            .collect()
    }

    fn eviction(conn: usize) -> [(Severity, String); 3] {
        let fd = conn + 9;
        [
            info("too many connections"),
            info(&format!("dropping TCP fd {fd} from 192.0.2.1:{conn}")),
            info(&format!("closing down fd {fd}")),
        ]
    }

    #[test]
    fn connections_in_one_second_evict_as_mits() {
        let mut t = Streams::new(MAX_STREAM_DATA_CONNECTIONS, MAX_REQUEST);
        let mut log = Lines::default();
        let conns = fill(&mut t, &mut log, 48, |_| 100);
        assert_eq!(evicted(&conns), [45, 46, 47]);
        let want: Vec<_> = [45, 46, 47].into_iter().flat_map(eviction).collect();
        assert_eq!(log.take(), want);
        assert_eq!(t.len(), 45);
    }

    #[test]
    fn connections_over_two_seconds_evict_as_mits() {
        let mut t = Streams::new(MAX_STREAM_DATA_CONNECTIONS, MAX_REQUEST);
        let mut log = Lines::default();
        let conns = fill(&mut t, &mut log, 48, |i| if i <= 20 { 100 } else { 101 });
        assert_eq!(evicted(&conns), [18, 19, 20]);
        let want: Vec<_> = [20, 19, 18].into_iter().flat_map(eviction).collect();
        assert_eq!(log.take(), want);
    }

    #[test]
    fn a_writing_stream_moves_to_the_end_and_can_be_evicted() {
        let mut t = Streams::new(3, MAX_REQUEST);
        let mut log = Lines::default();
        let conns = fill(&mut t, &mut log, 3, |_| 100);
        let (id1, w1) = &conns[0];
        arrive(w1, Arrival::Bytes(framed(b"req")));
        let mut app = App::default();
        t.read_drive(*id1, &mut app, &mut log);
        t.read_drive(*id1, &mut app, &mut log);
        let order: Vec<u64> = t.conns().map(|c| c.id).collect();
        assert_eq!(
            order,
            [conns[2].0, conns[1].0, *id1],
            "c3 took c1's slot, c1 went last"
        );
        assert!(t.conns().last().unwrap().writing());
        let w4 = Rc::new(RefCell::new(Wire::default()));
        t.add(Fake(Rc::clone(&w4)), 13, peer(4), 100, &mut log);
        assert_eq!(evicted(&conns), [1], "the writing stream");
        assert_eq!(w1.borrow().out, NO_BYTES);
        assert_eq!(log.take(), eviction(1));
        assert!(!w4.borrow().closed);
    }

    #[test]
    fn an_rpc_record_past_1_mib_closes_before_its_bytes_are_read() {
        let (mut t, id, wire, calls, mut log) = rpc_one(vec![]);
        let past = u32::try_from(MAX_RPC_RECORD + 1).unwrap() | LAST_FRAG;
        arrive(&wire, Arrival::Bytes(past.to_be_bytes().to_vec()));
        arrive(&wire, Arrival::Bytes(vec![0; 16]));
        t.read_drive(id, &mut App::default(), &mut log);
        assert!(t.is_empty());
        assert_eq!(calls.borrow().len(), 0);
        assert_eq!(wire.borrow().reads, 1, "the mark alone");
        assert_eq!(log.take(), [info("closing down fd 7")]);

        let (mut t, id, wire, calls, mut log) = rpc_one(vec![]);
        let frag = vec![7u8; 600 * 1024];
        arrive(&wire, Arrival::Bytes(fragment(&frag, false)));
        let second = u32::try_from(frag.len()).unwrap().to_be_bytes().to_vec();
        arrive(&wire, Arrival::Bytes(second));
        arrive(&wire, Arrival::Bytes(frag.clone()));
        t.read_drive(id, &mut App::default(), &mut log);
        assert!(t.is_empty());
        assert_eq!(calls.borrow().len(), 0);
        assert!(
            matches!(wire.borrow().incoming.front(), Some(Arrival::Bytes(b)) if b.len() == frag.len()),
            "the crossing fragment is not read"
        );

        let (mut t, id, wire, calls, mut log) = rpc_one(vec![]);
        arrive(
            &wire,
            Arrival::Bytes(fragment(&vec![1u8; MAX_RPC_RECORD - 4], true)),
        );
        t.read_drive(id, &mut App::default(), &mut log);
        assert_eq!(calls.borrow().len(), 1);
        assert_eq!(calls.borrow()[0].len(), MAX_RPC_RECORD - 4);
        assert_eq!(t.len(), 1);
        assert_eq!(log.take(), NO_LINES);
    }

    /// A record of empty fragments, 300,000 marks with no last one, holds no memory for them and closes the connection once its marks pass 1 MiB: the mark that crosses is the last read, and the call is never made.
    #[test]
    fn empty_fragments_close_the_connection_at_the_cap() {
        let (mut t, id, wire, calls, mut log) = rpc_one(vec![]);
        for _ in 0..300_000 {
            arrive(&wire, Arrival::Bytes(vec![0; 4]));
        }
        t.read_drive(id, &mut App::default(), &mut log);
        assert!(t.is_empty(), "closed");
        assert!(wire.borrow().closed);
        assert_eq!(calls.borrow().len(), 0);
        let marks = MAX_RPC_RECORD / 4 + 1;
        assert_eq!(
            wire.borrow().reads,
            marks,
            "the crossing mark is the last read"
        );
        assert_eq!(wire.borrow().incoming.len(), 300_000 - marks);
        assert_eq!(log.take(), [info("closing down fd 7")]);
        let mut grown = Zeroizing::new(Vec::new());
        for _ in 0..300_000 {
            reserve_wiped(&mut grown, 0);
        }
        assert_eq!(grown.capacity(), 0, "an empty fragment takes no room");
    }

    /// A record that never completes is held, then closed at the per-record deadline by the serve sweep.
    #[test]
    fn an_unfinished_rpc_record_closes_at_the_deadline() {
        let rec = fragment(b"0123456789", true);
        for cut in [2, 4, 6] {
            let (mut t, id, wire, calls, mut log) = rpc_one(vec![]);
            let deadline = t.limits.rpc_record_deadline;
            arrive(&wire, Arrival::Bytes(rec[..cut].to_vec()));
            arrive(&wire, Arrival::Stall);
            t.read_drive(id, &mut App::default(), &mut log);
            assert_eq!(t.len(), 1, "cut {cut}: the partial record is held");
            assert_eq!(calls.borrow().len(), 0);
            assert_eq!(wire.borrow().out, NO_BYTES);
            assert_eq!(log.take(), NO_LINES);

            t.sweep_rpc(Instant::now(), &mut log);
            assert_eq!(t.len(), 1, "cut {cut}: within the deadline it is left");
            assert_eq!(log.take(), NO_LINES);

            t.sweep_rpc(Instant::now() + deadline + Duration::from_secs(1), &mut log);
            assert!(t.is_empty(), "cut {cut}: past the deadline it closes");
            assert!(wire.borrow().closed);
            assert_eq!(calls.borrow().len(), 0);
            assert_eq!(wire.borrow().out, NO_BYTES);
            let dropped = format!(
                "RPC record timed out, dropping fd 7 from {}",
                print_addr_port(&peer(4242))
            );
            assert_eq!(log.take(), [info(&dropped), info("closing down fd 7")]);
        }
    }

    #[test]
    fn an_rpc_session_that_ends_or_panics_closes_its_connection_only() {
        let mut t = Streams::new(MAX_STREAM_DATA_CONNECTIONS, MAX_REQUEST);
        let mut log = Lines::default();
        let mut app = App::default();
        let script = vec![RpcReply::Nothing, RpcReply::Close];
        let (a, wa, ca) = rpc_add(&mut t, 7, 1, (script, false), &mut log);
        let (b, wb, cb) = rpc_add(&mut t, 8, 2, (vec![], true), &mut log);
        let (c, wc, _) = rpc_add(&mut t, 9, 3, (vec![], false), &mut log);
        let (d, wd, cd) = rpc_add(&mut t, 10, 4, (vec![], false), &mut log);
        arrive(&wa, Arrival::Bytes(fragment(b"quiet", true)));
        t.read_drive(a, &mut app, &mut log);
        assert_eq!((t.len(), wa.borrow().out.len()), (4, 0));
        arrive(&wa, Arrival::Bytes(fragment(b"bye", true)));
        t.read_drive(a, &mut app, &mut log);
        assert_eq!((ca.borrow().len(), t.len()), (2, 3));
        arrive(&wb, Arrival::Bytes(fragment(b"boom", true)));
        t.read_drive(b, &mut app, &mut log);
        assert_eq!((cb.borrow().len(), t.len()), (1, 2));
        assert_eq!(wb.borrow().out, NO_BYTES);
        // c: the queued reply's write error surfaces on the writable event.
        arrive(&wc, Arrival::Bytes(fragment(b"x", true)));
        wc.borrow_mut()
            .writes
            .push_back(Take::Fail(io::ErrorKind::BrokenPipe));
        t.read_drive(c, &mut app, &mut log);
        assert_eq!(t.len(), 2, "the reply is queued, not yet written");
        t.writable(c, &mut log);
        assert_eq!(t.len(), 1);
        arrive(&wd, Arrival::Bytes(fragment(b"fine", true)));
        t.read_drive(d, &mut app, &mut log);
        t.writable(d, &mut log);
        assert_eq!(cd.borrow().len(), 1);
        assert_eq!(wd.borrow().out, fragment(b"answer", true));
        assert_eq!(
            log.take(),
            [
                info("closing down fd 7"),
                info("closing down fd 8"),
                info("closing down fd 9"),
            ]
        );
    }

    #[test]
    fn rpc_and_tcp_connections_share_the_cap() {
        let mut t = Streams::new(MAX_STREAM_DATA_CONNECTIONS, MAX_REQUEST);
        let mut log = Lines::default();
        let tcp = fill(&mut t, &mut log, 44, |_| 100);
        let (_, rpc, _) = rpc_add(&mut t, 54, 45, (vec![], false), &mut log);
        assert_eq!((t.len(), log.take()), (45, vec![]));
        let w = Rc::new(RefCell::new(Wire::default()));
        t.add(Fake(Rc::clone(&w)), 55, peer(46), 100, &mut log);
        assert!(rpc.borrow().closed);
        assert_eq!(evicted(&tcp), Vec::<usize>::new());
        assert_eq!(
            log.take(),
            [
                info("too many connections"),
                info("dropping RPC fd 54 from 192.0.2.1:45"),
                info("closing down fd 54"),
            ]
        );
        assert_eq!(t.len(), 45);
    }

    #[test]
    fn accept_rpc_takes_the_connection_as_mits() {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        use nix::sys::socket::getsockopt;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut t = Streams::new(MAX_STREAM_DATA_CONNECTIONS, MAX_REQUEST);
        let mut log = Lines::default();
        let mut app = App {
            rpc: Some(Calls::default()),
            ..App::default()
        };
        let client = TcpStream::connect(addr).unwrap();
        t.accept_rpc(&listener, 100, &mut app, &mut log).unwrap();
        assert_eq!(t.len(), 1);
        let conn = t.conns().next().unwrap();
        assert_eq!(conn.ctype, ConnType::Rpc);
        let flags = OFlag::from_bits_truncate(fcntl(&conn.stream, FcntlArg::F_GETFL).unwrap());
        assert!(flags.contains(OFlag::O_NONBLOCK), "non-blocking");
        assert!(!getsockopt(&conn.stream, sockopt::KeepAlive).unwrap());
        assert_eq!(conn.addrbuf, client.local_addr().unwrap().to_string());
        assert_eq!(conn.start_time, 100);

        let closed = |c: &TcpStream| {
            c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            matches!((&*c).read(&mut [0u8; 1]), Ok(0))
        };
        let other = TcpStream::connect(addr).unwrap();
        t.accept_rpc(&listener, 100, &mut App::default(), &mut log)
            .unwrap();
        assert_eq!(t.len(), 1, "no session");
        assert!(closed(&other));
        let third = TcpStream::connect(addr).unwrap();
        let (stream, remote) = listener.accept().unwrap();
        let local = stream.local_addr().unwrap();
        t.admit_rpc(stream, 1024, (remote, local), 100, &mut app, &mut log);
        assert_eq!(t.len(), 1, "fd 1024 is not taken");
        assert!(closed(&third));
        assert_eq!(log.take(), NO_LINES);
        drop(client);
    }

    #[test]
    fn a_datagram_is_dispatched_and_answered_as_mits() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(true).unwrap();
        let addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client
            .set_read_timeout(Some(std::time::Duration::from_millis(300)))
            .unwrap();
        let mut buf = vec![0u8; MAX_DGRAM_SIZE];
        let mut log = Lines::default();
        let mut app = App {
            reply: Reply::Send(b"pong".to_vec()),
            ..App::default()
        };
        let wait = || {
            let mut fds = [PollFd::new(server.as_fd(), PollFlags::POLLIN)];
            poll(&mut fds, PollTimeout::from(2000u16)).unwrap();
        };
        client.send_to(b"ping", addr).unwrap();
        wait();
        process_packet_test(&server, &mut buf, &mut app, &mut log);
        let mut got = [0u8; 16];
        let (n, from) = client.recv_from(&mut got).unwrap();
        assert_eq!((&got[..n], from), (&b"pong"[..], addr));
        let (local, remote, request, is_tcp) = &app.requests[0];
        assert_eq!(
            (*local, *remote, request.as_slice(), *is_tcp),
            (addr, client.local_addr().unwrap(), &b"ping"[..], false)
        );
        for (reply, lines) in [
            (
                Reply::Failed("Invalid message type".into()),
                vec![err("Invalid message type - while dispatching (udp)")],
            ),
            (Reply::Nothing, vec![]),
        ] {
            app.reply = reply;
            client.send_to(b"ping", addr).unwrap();
            wait();
            process_packet_test(&server, &mut buf, &mut app, &mut log);
            assert!(client.recv_from(&mut got).is_err(), "no reply");
            assert_eq!(log.take(), lines);
        }
        let before = app.requests.len();
        client.send_to(b"", addr).unwrap();
        wait();
        process_packet_test(&server, &mut buf, &mut app, &mut log);
        assert_eq!(
            app.requests.len(),
            before,
            "an empty datagram is not dispatched"
        );
        process_packet_test(&server, &mut buf, &mut app, &mut log);
        assert_eq!(log.take(), NO_LINES, "nothing to read is not logged");
    }
}
