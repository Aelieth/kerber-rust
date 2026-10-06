//! MIT's net-server (`lib/apputils/net-server.c`), the stream half: each accepted TCP
//! connection's state, its one read or write per event, and the table of stream connections
//! with MIT's cap and its eviction of the connection that started first.
//!
//! MIT runs one loop per daemon and keeps every connection in that loop's `events` set. A
//! connection reads its four-byte length and then its body, one `read` per readable event, so
//! a slow sender never holds up another connection; a complete request is dispatched, the reply
//! goes out by `writev` as the socket takes it, and the connection closes. There is no timeout:
//! a stream keeps its place until it finishes, fails, or is evicted when a connection past the
//! cap of 45 arrives. [`Streams`] is that set and those handlers, over any [`Stream`] so the
//! units can drive them with scripted sockets.

// Until krb5kdc and kadmind are served from this loop, only the units call it.
#![cfg_attr(not(test), allow(dead_code))]

use std::io::{self, IoSlice, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd as _, RawFd};
use std::panic::{AssertUnwindSafe, catch_unwind};

use krb5_log::klog::{Severity, os_error_text};
use nix::sys::socket::{setsockopt, sockopt};

use crate::listen::WHILE_DISPATCHING_TCP;

/// MIT `max_stream_data_connections` (`lib/apputils/net-server.c:85-85`): at most 45 stream connections.
pub(crate) const MAX_STREAM_DATA_CONNECTIONS: usize = 45;
/// MIT `accept_stream_connection` (`lib/apputils/net-server.c:1278-1278`): a stream's buffer is 1 MiB, its length word included.
pub(crate) const BUFSIZ: usize = 1024 * 1024;
/// The most one read takes. It is not a second cap: a request is read in pieces of at most this
/// size into a buffer the size of its length, so only the pages that receive bytes are touched.
pub(crate) const READ_SIZE: usize = 64 * 1024;
/// MIT `setnolinger` (`lib/apputils/net-server.c:687-691`): an accepted stream does not linger.
const NO_LINGER: nix::libc::linger = nix::libc::linger {
    l_onoff: 0,
    l_linger: 0,
};

/// A stream connection's socket as the handlers use it: [`TcpStream`] in the daemons.
pub(crate) trait Stream: Read + Write {
    /// The address the connection was made to (`getsockname`).
    ///
    /// # Errors
    ///
    /// The `getsockname` error.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

impl Stream for TcpStream {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::local_addr(self)
    }
}

/// What a dispatch produced: MIT `loop_respond_fn`'s `code` and `response`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Reply {
    /// A zero `code` with a response: send it.
    Send(Vec<u8>),
    /// A zero `code` and no response: close the connection unanswered.
    Nothing,
    /// A nonzero `code`, as its message: logged, and the connection closes unanswered.
    Failed(String),
}

/// What the daemon supplies to the loop.
/// MIT `dispatch` (`include/net-server.h:84-86`): one request in and, through the respond callback, one reply out.
pub(crate) trait Dispatch {
    /// Answer one request that came to `local` from `remote`.
    fn dispatch(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        request: &[u8],
        is_tcp: bool,
    ) -> Reply;

    /// The reply to a stream whose length is past the buffer.
    ///
    /// # Errors
    ///
    /// The message of the error that kept the reply from being built.
    fn make_toolong_error(&mut self) -> Result<Vec<u8>, String>;
}

/// Where the loop's log lines go: `klog::syslog` in the daemons, a list in the units.
pub(crate) trait Log {
    /// One line at `severity`.
    fn syslog(&mut self, severity: Severity, msg: &str);

    /// MIT's `com_err` through the daemon log: the error's text, ` - `, then `msg`, as an error.
    fn com_err(&mut self, error: &str, msg: &str) {
        self.syslog(Severity::Err, &format!("{error} - {msg}"));
    }
}

/// A stream connection's kind, as the log names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConnType {
    /// A KDC or kpasswd TCP stream.
    Tcp,
}

impl ConnType {
    /// MIT `conn_type_names` (`lib/apputils/net-server.c:120-128`): a TCP stream is `TCP` in the log.
    fn name(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
        }
    }
}

/// Where a stream is in its one exchange.
enum Io {
    /// Reading the length word, then the body: `offset` counts both.
    Read {
        lenbuf: [u8; 4],
        offset: usize,
        msglen: usize,
        body: Vec<u8>,
    },
    /// Writing the length word and the reply: `sent` counts both.
    Write {
        lenbuf: [u8; 4],
        reply: Vec<u8>,
        sent: usize,
    },
}

/// One stream connection.
/// MIT `struct connection` (`lib/apputils/net-server.c:142-171`): the peer and its printed form, the read and write state, and `start_time`, the second the connection was accepted.
pub(crate) struct Conn<S> {
    id: u64,
    stream: S,
    fd: RawFd,
    ctype: ConnType,
    remote: SocketAddr,
    addrbuf: String,
    start_time: u64,
    io: Io,
}

impl<S> Conn<S> {
    /// Whether the connection waits to write its reply; otherwise it waits to read.
    pub(crate) fn writing(&self) -> bool {
        matches!(self.io, Io::Write { .. })
    }
}

/// What one read event decided.
enum Step {
    /// Wait for the next event.
    Wait,
    /// Close the connection, logging it as MIT's `free_socket` does.
    Close,
    /// The exchange has its reply, or failed: MIT `process_stream_response`.
    Respond(Reply),
}

/// The stream connections in MIT's `events` order, with MIT's cap.
///
/// A connection is pushed when it is accepted and when it turns to writing its reply, and
/// removed by moving the last one into its place, as MIT's `ADD` and `DEL` do; the order is what
/// decides which of several connections that started in the same second is evicted.
pub(crate) struct Streams<S> {
    conns: Vec<Conn<S>>,
    max: usize,
    next_id: u64,
    scratch: Vec<u8>,
}

impl<S: Stream> Streams<S> {
    /// An empty table that holds at most `max` connections.
    pub(crate) fn new(max: usize) -> Self {
        Self {
            conns: Vec::new(),
            max,
            next_id: 0,
            scratch: vec![0; READ_SIZE],
        }
    }

    /// How many stream connections are open (MIT's `stream_data_counter`).
    pub(crate) fn len(&self) -> usize {
        self.conns.len()
    }

    /// Whether no stream connection is open.
    pub(crate) fn is_empty(&self) -> bool {
        self.conns.is_empty()
    }

    /// Each connection in table order, for the loop's poll set.
    pub(crate) fn conns(&self) -> impl Iterator<Item = &Conn<S>> {
        self.conns.iter()
    }

    fn position(&self, id: u64) -> Option<usize> {
        self.conns.iter().position(|c| c.id == id)
    }

    /// Take a new connection from `remote` on descriptor `fd`, started in second `now`, and
    /// evict the connection that started first when it is one past the cap. Returns its id.
    /// MIT `accept_stream_connection` (`lib/apputils/net-server.c:1274-1283`): the peer is printed, `start_time` is the current second, and one past the cap evicts.
    pub(crate) fn add(
        &mut self,
        stream: S,
        fd: RawFd,
        remote: SocketAddr,
        now: u64,
        log: &mut dyn Log,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.conns.push(Conn {
            id,
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
        });
        if self.conns.len() > self.max {
            self.kill_lru(id, log);
        }
        id
    }

    /// Evict the stream that started first, other than the newcomer `newest`. Among streams that
    /// started in the same second the scan from the top of the table keeps the first it met.
    /// MIT `kill_lru_stream_connection` (`lib/apputils/net-server.c:1198-1223`): "too many connections", a scan from the last entry down with a strict `>`, then "dropping %s fd %d from %s".
    fn kill_lru(&mut self, newest: u64, log: &mut dyn Log) {
        log.syslog(Severity::Info, "too many connections");
        let mut oldest: Option<usize> = None;
        for (i, c) in self.conns.iter().enumerate().rev() {
            if c.id == newest {
                continue;
            }
            if oldest.is_none_or(|o| self.conns[o].start_time > c.start_time) {
                oldest = Some(i);
            }
        }
        if let Some(i) = oldest {
            let c = &self.conns[i];
            log.syslog(
                Severity::Info,
                &format!("dropping {} fd {} from {}", c.ctype.name(), c.fd, c.addrbuf),
            );
            self.free_socket(i, log);
        }
    }

    /// Remove the connection at `i`, log its descriptor, and close it.
    /// MIT `free_socket` (`lib/apputils/net-server.c:511-519`): the event leaves the set, "closing down fd %d" is logged, and the descriptor is closed.
    fn free_socket(&mut self, i: usize, log: &mut dyn Log) {
        let conn = self.conns.swap_remove(i);
        log.syslog(Severity::Info, &format!("closing down fd {}", conn.fd));
    }

    /// One readable event on connection `id`: one read of the length word or of the body; a
    /// complete request is dispatched to `app`, whose reply the connection then writes.
    /// MIT `process_stream_connection_read` (`lib/apputils/net-server.c:1375-1453`): a read error or end of file closes the stream, a length past the buffer is logged and answered with `make_toolong_error`, and exactly one complete message is dispatched.
    ///
    /// Deviations: a read that would block, or that a signal cut short, waits for the next event
    /// (MIT's handler runs only when the socket is readable, where neither happens); and when
    /// `getsockname` fails the stream closes as MIT's code means to, where MIT's goes on to use
    /// the event it has just freed.
    pub(crate) fn readable(&mut self, id: u64, app: &mut dyn Dispatch, log: &mut dyn Log) {
        let Some(i) = self.position(id) else {
            return;
        };
        match self.read_step(i, app, log) {
            Step::Wait => {}
            Step::Close => self.free_socket(i, log),
            Step::Respond(reply) => self.respond(i, reply, log),
        }
    }

    fn read_step(&mut self, i: usize, app: &mut dyn Dispatch, log: &mut dyn Log) -> Step {
        let Self { conns, scratch, .. } = self;
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
                if *msglen > BUFSIZ - 4 {
                    log.syslog(
                        Severity::Err,
                        &format!(
                            "TCP client {} wants {} bytes, cap is {}",
                            conn.addrbuf,
                            *msglen,
                            BUFSIZ - 4
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
        // A zero length leaves nothing to read: MIT's read of no bytes returns 0, which is end of
        // file, so the stream closes at its next event without a dispatch.
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
        Step::Respond(dispatch_contained(app, local, remote, &request))
    }

    /// Queue `reply` on connection `i`, which turns to writing, or close it unanswered.
    /// MIT `process_stream_response` (`lib/apputils/net-server.c:1314-1336`): a nonzero code is logged "while dispatching (tcp)"; it or no response closes the stream without "closing down fd", and a response is queued behind its length.
    /// MIT `prepare_for_dispatch` (`lib/apputils/net-server.c:1350-1355`): the read event leaves the set before the dispatch, so the write event is added at its end.
    fn respond(&mut self, i: usize, reply: Reply, log: &mut dyn Log) {
        let mut conn = self.conns.swap_remove(i);
        match reply {
            Reply::Send(reply) => {
                // A reply of 4 GiB or more cannot be framed; it closes the stream unanswered.
                if let Ok(n) = u32::try_from(reply.len()) {
                    conn.io = Io::Write {
                        lenbuf: n.to_be_bytes(),
                        reply,
                        sent: 0,
                    };
                    self.conns.push(conn);
                }
            }
            Reply::Nothing => {}
            Reply::Failed(text) => log.com_err(&text, WHILE_DISPATCHING_TCP),
        }
    }

    /// One writable event on connection `id`: as much of the length word and reply as the
    /// socket takes; once all of it is sent, or the write fails, the connection closes.
    /// MIT `process_stream_connection_write` (`lib/apputils/net-server.c:1467-1494`): one `writev` per event with the unsent parts; when nothing is left, or nothing was written, the stream closes.
    ///
    /// Deviation: a write that would block, or that a signal cut short, waits for the next event
    /// (MIT's handler runs only when the socket is writable, where neither happens).
    pub(crate) fn writable(&mut self, id: u64, log: &mut dyn Log) {
        let Some(i) = self.position(id) else {
            return;
        };
        let conn = &mut self.conns[i];
        let Io::Write {
            lenbuf,
            reply,
            sent,
        } = &mut conn.io
        else {
            return;
        };
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
        self.free_socket(i, log);
    }
}

impl Streams<TcpStream> {
    /// Accept one connection from `listener`, set it up as MIT does, and add it to the table.
    /// MIT `accept_stream_connection` (`lib/apputils/net-server.c:1239-1252`): a failed accept is dropped silently, a descriptor at or past `FD_SETSIZE` is closed, and the stream is made non-blocking, not lingering and keepalive.
    ///
    /// Deviation: a stream that cannot be made non-blocking is closed, where MIT ignores the
    /// result; a blocking one would stall every other connection on its first read.
    pub(crate) fn accept(&mut self, listener: &TcpListener, now: u64, log: &mut dyn Log) {
        // std's accept sets close-on-exec (accept4 with SOCK_CLOEXEC), as `set_cloexec_fd` does.
        let Ok((stream, remote)) = listener.accept() else {
            return;
        };
        let fd = stream.as_raw_fd();
        self.admit(stream, fd, remote, now, log);
    }

    fn admit(
        &mut self,
        stream: TcpStream,
        fd: RawFd,
        remote: SocketAddr,
        now: u64,
        log: &mut dyn Log,
    ) {
        if !usize::try_from(fd).is_ok_and(|n| n < nix::libc::FD_SETSIZE) {
            return;
        }
        if stream.set_nonblocking(true).is_err() {
            return;
        }
        let _ = setsockopt(&stream, sockopt::Linger, &NO_LINGER);
        let _ = setsockopt(&stream, sockopt::KeepAlive, &true);
        self.add(stream, fd, remote, now, log);
    }
}

/// Run `app`'s dispatch, containing a panic: the request is answered with nothing and the loop
/// goes on. MIT's daemon would end with the process; one loop serves every client here, so a
/// panic in one request does not take the others down.
fn dispatch_contained(
    app: &mut dyn Dispatch,
    local: SocketAddr,
    remote: SocketAddr,
    request: &[u8],
) -> Reply {
    let run = catch_unwind(AssertUnwindSafe(|| {
        app.dispatch(local, remote, request, true)
    }));
    run.unwrap_or_else(|_| {
        tracing::error!(
            event = krb5_log::events::KDC_TRANSPORT,
            correlation_id = krb5_log::current_correlation_id(),
            component = "krb5-kdc",
            outcome = "error",
            error = "request panic isolated",
        );
        Reply::Nothing
    })
}

/// A read or write that found nothing to do: the stream waits for its next event.
fn retry(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

/// `addr` as MIT's log prints a peer: an IPv4 address and port joined by a colon, an IPv6 one in
/// brackets, a link-local address's scope by interface name.
/// MIT `k5_print_addr_port` (`lib/krb5/os/addr.c:98-106`): `getnameinfo` with numeric host and service, an IPv6 host in brackets.
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

    /// What the peer has sent and the server has not read yet, one arrival at a time.
    enum Arrival {
        Bytes(Vec<u8>),
        Eof,
        Fail(io::ErrorKind),
    }

    /// How one write call goes.
    enum Take {
        Upto(usize),
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

    /// A scripted socket: each read takes from the front arrival (nothing waiting is
    /// `WouldBlock`), each write takes what its script says (no script takes everything).
    struct Fake(Rc<RefCell<Wire>>);

    impl Read for Fake {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut w = self.0.borrow_mut();
            w.reads += 1;
            match w.incoming.pop_front() {
                None => Err(io::ErrorKind::WouldBlock.into()),
                Some(Arrival::Bytes(b)) => {
                    let n = b.len().min(buf.len());
                    buf[..n].copy_from_slice(&b[..n]);
                    if n < b.len() {
                        w.incoming.push_front(Arrival::Bytes(b[n..].to_vec()));
                    }
                    Ok(n)
                }
                Some(Arrival::Eof) => {
                    w.incoming.push_front(Arrival::Eof);
                    Ok(0)
                }
                Some(Arrival::Fail(k)) => Err(k.into()),
            }
        }
    }

    impl Write for Fake {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_vectored(&[IoSlice::new(buf)])
        }

        fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
            let mut w = self.0.borrow_mut();
            let mut room = match w.writes.pop_front() {
                None => usize::MAX,
                Some(Take::Upto(n)) => n,
                Some(Take::Fail(k)) => return Err(k.into()),
            };
            let mut n = 0;
            for b in bufs {
                let k = b.len().min(room);
                w.out.extend_from_slice(&b[..k]);
                n += k;
                room -= k;
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

    /// The application side: records each request and answers with `reply`.
    struct App {
        requests: Vec<(SocketAddr, SocketAddr, Vec<u8>, bool)>,
        reply: Reply,
        toolong: Result<Vec<u8>, String>,
        panic: bool,
    }

    impl Default for App {
        fn default() -> Self {
            Self {
                requests: Vec::new(),
                reply: Reply::Send(b"the reply".to_vec()),
                toolong: Ok(b"too long".to_vec()),
                panic: false,
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
        ) -> Reply {
            self.requests
                .push((local, remote, request.to_vec(), is_tcp));
            assert!(!self.panic, "dispatch panicked");
            match &self.reply {
                Reply::Send(r) => Reply::Send(r.clone()),
                Reply::Nothing => Reply::Nothing,
                Reply::Failed(t) => Reply::Failed(t.clone()),
            }
        }

        fn make_toolong_error(&mut self) -> Result<Vec<u8>, String> {
            self.toolong.clone()
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

    fn peer(n: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], n))
    }

    /// A table with one fake connection on fd 7 from 192.0.2.1:4242.
    fn one(now: u64) -> (Streams<Fake>, u64, Rc<RefCell<Wire>>, Lines) {
        let mut t = Streams::new(MAX_STREAM_DATA_CONNECTIONS);
        let wire = Rc::new(RefCell::new(Wire::default()));
        let mut log = Lines::default();
        let id = t.add(Fake(Rc::clone(&wire)), 7, peer(4242), now, &mut log);
        (t, id, wire, log)
    }

    fn arrive(wire: &Rc<RefCell<Wire>>, a: Arrival) {
        wire.borrow_mut().incoming.push_back(a);
    }

    /// A deterministic chunking of `n` bytes into pieces of 1 to 40.
    fn chunks(n: usize, mut seed: u32) -> Vec<usize> {
        let mut out = Vec::new();
        let mut left = n;
        while left > 0 {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let k = (usize::try_from(seed % 40).unwrap() + 1).min(left);
            out.push(k);
            left -= k;
        }
        out
    }

    /// A request whose length comes as 1, 1 and 2 bytes and whose body comes in pieces, one
    /// piece per readable event, is dispatched once, whole, with the stream's addresses; the
    /// reply goes out behind its length and the stream closes.
    #[test]
    fn a_request_in_pieces_is_dispatched_once() {
        let (mut t, id, wire, mut log) = one(100);
        let mut app = App::default();
        let body: Vec<u8> = (0..300u16)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let msg = framed(&body);
        let mut pieces = vec![1, 1, 2];
        pieces.extend(chunks(body.len(), 0x5eed));
        let mut at = 0;
        for k in pieces {
            arrive(&wire, Arrival::Bytes(msg[at..at + k].to_vec()));
            at += k;
            assert_eq!(app.requests.len(), 0, "dispatched before the last piece");
            t.readable(id, &mut app, &mut log);
        }
        assert_eq!(app.requests.len(), 1);
        let (local, remote, request, is_tcp) = &app.requests[0];
        assert_eq!(request, &body);
        assert_eq!(*local, "192.0.2.88:88".parse().unwrap());
        assert_eq!(*remote, peer(4242));
        assert!(is_tcp);
        assert!(t.conns().next().unwrap().writing());
        t.writable(id, &mut log);
        assert_eq!(wire.borrow().out, framed(b"the reply"));
        assert!(wire.borrow().closed);
        assert!(t.is_empty());
        assert_eq!(log.take(), [info("closing down fd 7")]);
    }

    /// Each event does one read, and the bytes of a second request sent behind the first are
    /// never read: one exchange per stream, as MIT's.
    #[test]
    fn one_read_per_event_and_nothing_past_the_message() {
        let (mut t, id, wire, mut log) = one(100);
        let mut app = App::default();
        let mut both = framed(b"first");
        both.extend(framed(b"second"));
        arrive(&wire, Arrival::Bytes(both));
        t.readable(id, &mut app, &mut log);
        assert_eq!(wire.borrow().reads, 1);
        assert_eq!(app.requests.len(), 0, "the length word alone");
        t.readable(id, &mut app, &mut log);
        assert_eq!(app.requests.len(), 1);
        assert_eq!(app.requests[0].2, b"first");
        t.readable(id, &mut app, &mut log);
        assert_eq!(wire.borrow().reads, 2, "a writing stream reads nothing");
        match wire.borrow().incoming.front() {
            Some(Arrival::Bytes(rest)) => assert_eq!(rest, &framed(b"second")),
            _ => panic!("the second request was read"),
        }
        t.writable(id, &mut log);
        assert!(t.is_empty());
    }

    /// End of file or a read error part-way through the length word or the body closes the
    /// stream with "closing down fd", no dispatch and no reply; nothing to read only waits.
    #[test]
    fn eof_or_an_error_part_way_closes_with_no_reply() {
        let msg = framed(b"0123456789");
        for cut in [0, 1, 3, 4, 9] {
            for end in [Arrival::Eof, Arrival::Fail(io::ErrorKind::ConnectionReset)] {
                let (mut t, id, wire, mut log) = one(100);
                let mut app = App::default();
                if cut > 0 {
                    arrive(&wire, Arrival::Bytes(msg[..cut].to_vec()));
                }
                arrive(&wire, end);
                let reads = if cut > 4 { 2 } else { usize::from(cut > 0) };
                for _ in 0..reads {
                    t.readable(id, &mut app, &mut log);
                    assert_eq!(t.len(), 1);
                }
                t.readable(id, &mut app, &mut log);
                t.readable(id, &mut app, &mut log);
                assert!(t.is_empty(), "cut {cut}");
                assert_eq!(app.requests.len(), 0);
                assert_eq!(wire.borrow().out, NO_BYTES);
                assert!(wire.borrow().closed);
                assert_eq!(log.take(), [info("closing down fd 7")]);
            }
        }
        let (mut t, id, wire, mut log) = one(100);
        let mut app = App::default();
        t.readable(id, &mut app, &mut log);
        arrive(&wire, Arrival::Fail(io::ErrorKind::Interrupted));
        t.readable(id, &mut app, &mut log);
        assert_eq!(t.len(), 1, "WouldBlock and EINTR wait for the next event");
        assert_eq!(log.take(), NO_LINES);
    }

    /// A length one past the buffer, or with the high bit set, is logged with MIT's line and
    /// answered with `make_toolong_error` before any body, then the stream closes; a length of
    /// exactly the buffer less its length word is taken.
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
            t.readable(id, &mut app, &mut log);
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
        t.readable(id, &mut app, &mut log);
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
        t.readable(id, &mut app, &mut log);
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

    /// A zero length is never dispatched: the stream stays until its next event (more bytes, or
    /// end of file), which closes it.
    #[test]
    fn a_zero_length_closes_at_the_next_event_without_a_dispatch() {
        for next in [Arrival::Bytes(vec![1]), Arrival::Eof] {
            let (mut t, id, wire, mut log) = one(100);
            let mut app = App::default();
            arrive(&wire, Arrival::Bytes(vec![0; 4]));
            t.readable(id, &mut app, &mut log);
            assert_eq!(t.len(), 1);
            arrive(&wire, next);
            t.readable(id, &mut app, &mut log);
            assert!(t.is_empty());
            assert_eq!(app.requests.len(), 0);
            assert_eq!(wire.borrow().out, NO_BYTES);
            assert_eq!(log.take(), [info("closing down fd 7")]);
        }
    }

    /// A socket that takes 3 bytes a call, with calls that would block between, still gets the
    /// whole reply, and the stream closes once it has; a failing write closes it at once.
    #[test]
    fn short_writes_and_wouldblock_still_deliver_the_whole_reply() {
        let (mut t, id, wire, mut log) = one(100);
        let mut app = App {
            reply: Reply::Send(b"a reply of some length".to_vec()),
            ..App::default()
        };
        arrive(&wire, Arrival::Bytes(framed(b"req")));
        t.readable(id, &mut app, &mut log);
        t.readable(id, &mut app, &mut log);
        let want = framed(b"a reply of some length");
        for _ in 0..want.len() {
            wire.borrow_mut().writes.push_back(Take::Upto(3));
            wire.borrow_mut()
                .writes
                .push_back(Take::Fail(io::ErrorKind::WouldBlock));
        }
        let mut events = 0;
        while !t.is_empty() {
            t.writable(id, &mut log);
            events += 1;
            assert!(events < 100);
        }
        assert_eq!(wire.borrow().out, want);
        assert_eq!(log.take(), [info("closing down fd 7")]);
        let (mut t, id, wire, mut log) = one(100);
        arrive(&wire, Arrival::Bytes(framed(b"req")));
        t.readable(id, &mut app, &mut log);
        t.readable(id, &mut app, &mut log);
        wire.borrow_mut().writes.push_back(Take::Upto(2));
        wire.borrow_mut()
            .writes
            .push_back(Take::Fail(io::ErrorKind::BrokenPipe));
        t.writable(id, &mut log);
        assert_eq!(t.len(), 1);
        t.writable(id, &mut log);
        assert!(t.is_empty());
        assert_eq!(wire.borrow().out, want[..2]);
        assert_eq!(log.take(), [info("closing down fd 7")]);
    }

    /// A dispatch that fails logs its message "while dispatching (tcp)", one with no reply logs
    /// nothing; either closes the stream unanswered and without "closing down fd".
    #[test]
    fn a_failed_or_empty_dispatch_closes_without_the_closing_line() {
        for (reply, lines) in [
            (
                Reply::Failed("The KDC should discard this request".into()),
                vec![err(
                    "The KDC should discard this request - while dispatching (tcp)",
                )],
            ),
            (Reply::Nothing, vec![]),
        ] {
            let (mut t, id, wire, mut log) = one(100);
            let mut app = App {
                reply,
                ..App::default()
            };
            arrive(&wire, Arrival::Bytes(framed(b"req")));
            t.readable(id, &mut app, &mut log);
            t.readable(id, &mut app, &mut log);
            assert_eq!(app.requests.len(), 1);
            assert!(t.is_empty());
            assert!(wire.borrow().closed);
            assert_eq!(wire.borrow().out, NO_BYTES);
            assert_eq!(log.take(), lines);
        }
    }

    /// A panicking dispatch closes its stream unanswered; the loop and the other streams go on.
    #[test]
    fn a_panicking_dispatch_is_contained() {
        let mut t = Streams::new(MAX_STREAM_DATA_CONNECTIONS);
        let mut log = Lines::default();
        let (a, b) = (
            Rc::new(RefCell::new(Wire::default())),
            Rc::new(RefCell::new(Wire::default())),
        );
        let ida = t.add(Fake(Rc::clone(&a)), 7, peer(1), 100, &mut log);
        let idb = t.add(Fake(Rc::clone(&b)), 8, peer(2), 100, &mut log);
        arrive(&a, Arrival::Bytes(framed(b"boom")));
        arrive(&b, Arrival::Bytes(framed(b"fine")));
        let mut app = App {
            panic: true,
            ..App::default()
        };
        t.readable(ida, &mut app, &mut log);
        t.readable(ida, &mut app, &mut log);
        assert!(a.borrow().closed);
        assert_eq!(a.borrow().out, NO_BYTES);
        assert_eq!(t.len(), 1);
        app.panic = false;
        t.readable(idb, &mut app, &mut log);
        t.readable(idb, &mut app, &mut log);
        t.writable(idb, &mut log);
        assert_eq!(b.borrow().out, framed(b"the reply"));
        assert_eq!(log.take(), [info("closing down fd 8")]);
    }

    /// Open `n` connections on fds 10.. from ports 1.., the i-th started at `second(i)`.
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

    /// 48 connections in one second: the 46th evicts the 45th, the 47th the 46th and the 48th
    /// the 47th, each with MIT's three lines, as MIT 1.22.2 did when settled live: the scan keeps
    /// the first of a tie from the top, and each newcomer took its victim's place.
    #[test]
    fn connections_in_one_second_evict_as_mits() {
        let mut t = Streams::new(MAX_STREAM_DATA_CONNECTIONS);
        let mut log = Lines::default();
        let conns = fill(&mut t, &mut log, 48, |_| 100);
        assert_eq!(evicted(&conns), [45, 46, 47]);
        let want: Vec<_> = [45, 46, 47].into_iter().flat_map(eviction).collect();
        assert_eq!(log.take(), want);
        assert_eq!(t.len(), 45);
    }

    /// 20 connections in one second and 28 in the next: the 46th evicts the 20th, the 47th the
    /// 19th and the 48th the 18th, as MIT 1.22.2 did when settled live.
    #[test]
    fn connections_over_two_seconds_evict_as_mits() {
        let mut t = Streams::new(MAX_STREAM_DATA_CONNECTIONS);
        let mut log = Lines::default();
        let conns = fill(&mut t, &mut log, 48, |i| if i <= 20 { 100 } else { 101 });
        assert_eq!(evicted(&conns), [18, 19, 20]);
        let want: Vec<_> = [20, 19, 18].into_iter().flat_map(eviction).collect();
        assert_eq!(log.take(), want);
    }

    /// A stream that turns to writing its reply leaves its place and goes to the table's end, as
    /// MIT's write event is added after the read event is removed; there it is the first of a
    /// same-second tie from the top, so the next newcomer evicts it though it is writing.
    #[test]
    fn a_writing_stream_moves_to_the_end_and_can_be_evicted() {
        let mut t = Streams::new(3);
        let mut log = Lines::default();
        let conns = fill(&mut t, &mut log, 3, |_| 100);
        let (id1, w1) = &conns[0];
        arrive(w1, Arrival::Bytes(framed(b"req")));
        let mut app = App::default();
        t.readable(*id1, &mut app, &mut log);
        t.readable(*id1, &mut app, &mut log);
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

    /// An accepted stream is made as MIT makes it — non-blocking, keepalive, not lingering —
    /// and named by its peer; a descriptor at `FD_SETSIZE` or past it is closed at once.
    #[test]
    fn accept_sets_up_the_stream_as_mits() {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        use nix::sys::socket::getsockopt;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let mut t = Streams::new(MAX_STREAM_DATA_CONNECTIONS);
        let mut log = Lines::default();
        let client = TcpStream::connect(addr).unwrap();
        t.accept(&listener, 100, &mut log);
        assert_eq!(t.len(), 1);
        let conn = t.conns().next().unwrap();
        let flags = OFlag::from_bits_truncate(fcntl(&conn.stream, FcntlArg::F_GETFL).unwrap());
        assert!(flags.contains(OFlag::O_NONBLOCK));
        assert!(getsockopt(&conn.stream, sockopt::KeepAlive).unwrap());
        let linger = getsockopt(&conn.stream, sockopt::Linger).unwrap();
        assert_eq!((linger.l_onoff, linger.l_linger), (0, 0));
        assert_eq!(conn.addrbuf, client.local_addr().unwrap().to_string());
        assert_eq!(conn.start_time, 100);
        assert_eq!(conn.fd, conn.stream.as_raw_fd());

        let other = TcpStream::connect(addr).unwrap();
        let (stream, remote) = listener.accept().unwrap();
        t.admit(stream, 1024, remote, 100, &mut log);
        assert_eq!(t.len(), 1, "fd 1024 is not taken");
        let mut buf = [0u8; 1];
        other
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        assert_eq!((&other).read(&mut buf).unwrap(), 0, "closed");
        assert_eq!(log.take(), NO_LINES);
    }

    #[test]
    fn peers_print_as_mits() {
        assert_eq!(
            print_addr_port(&"10.0.0.1:88".parse().unwrap()),
            "10.0.0.1:88"
        );
        assert_eq!(
            print_addr_port(&"[::1]:4242".parse().unwrap()),
            "[::1]:4242"
        );
        let lo = nix::net::if_::if_nametoindex("lo").unwrap();
        let ll = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            88,
            0,
            lo,
        ));
        assert_eq!(print_addr_port(&ll), "[fe80::1%lo]:88");
    }
}
