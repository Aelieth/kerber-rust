//! Thin UDP/TCP 88 listener around [`crate::issue::handle_request`].

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use crate::issue::handle_request;
use crate::kdb::Store;

/// MIT `net-server.c:1101-1105`.
pub const WHILE_DISPATCHING_UDP: &str = "while dispatching (udp)";
/// MIT `net-server.c:1314-1315`.
pub const WHILE_DISPATCHING_TCP: &str = "while dispatching (tcp)";

fn log_dispatch_drop(udp: bool) {
    tracing::debug!(
        event = krb5_log::events::KDC_ISSUE,
        correlation_id = krb5_log::current_correlation_id(),
        component = "krb5-kdc",
        outcome = "ok",
        error = if udp {
            WHILE_DISPATCHING_UDP
        } else {
            WHILE_DISPATCHING_TCP
        },
    );
}

/// Serving store: AS/TGS take a read lock; kadmind/kpasswd take a write lock
/// so runtime mutations reach [`crate::persist::save_store`].
pub type SharedStore = Arc<RwLock<Box<dyn Store>>>;

/// Wrap a [`Store`] backend for [`serve`].
#[must_use]
pub fn shared_store<S: Store + 'static>(store: S) -> SharedStore {
    Arc::new(RwLock::new(Box::new(store)))
}

/// Kadmind still locks [`crate::PrincipalStore`] (dyn-Store admin is deferred).
pub type SharedDump = Arc<RwLock<crate::store::PrincipalStore>>;

/// Wrap a dump-v7 store for kadmind / kpasswd.
#[must_use]
pub fn shared_dump(store: crate::store::PrincipalStore) -> SharedDump {
    Arc::new(RwLock::new(store))
}

fn read_store<R>(store: &SharedStore, f: impl FnOnce(&dyn Store) -> R) -> R {
    {
        let mut w = store
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(e) = w.reload_if_stale() {
            tracing::error!(
                event = krb5_log::events::KDC_LISTEN,
                component = "krb5-kdc",
                outcome = "error",
                error = %e,
                detail = "reload store",
            );
        }
    }
    let g = store
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(&**g)
}

/// Addresses tried when the caller does not pin a bind address.
/// Never includes `0.0.0.0` — the daemon must be given an explicit bind
/// to listen on all interfaces.
pub const BIND_CANDIDATES: &[&str] = &["127.0.0.1:88", "127.0.0.1:8888"];

/// Default cap on concurrent TCP request handlers.
pub const MAX_TCP_WORKERS: usize = 32;
/// MIT `net-server.c:1278` `bufsiz` 1 MiB; FIELD_TOOLONG at `msglen > bufsiz-4`.
pub const MAX_TCP_REQUEST: usize = 1024 * 1024 - 4;
/// MIT `MAX_DGRAM_SIZE` / `kdc_max_dgram_reply_size` default (`osconf.hin`).
pub const MAX_DGRAM_REPLY: usize = 65_536;

/// Resource caps and I/O timeouts for [`serve_until`].
#[derive(Clone, Copy, Debug)]
pub struct ListenLimits {
    /// Concurrent TCP workers (accepted connections being read).
    pub max_tcp_workers: usize,
    /// Maximum TCP length-prefix body.
    pub max_tcp_request: usize,
    /// UDP reply cap; over is KRB-ERROR 52 (`dispatch.c:54-63`).
    pub max_dgram_reply_size: usize,
    /// Read/write timeout for a single TCP exchange, and UDP recv poll.
    pub io_timeout: Duration,
}

impl Default for ListenLimits {
    fn default() -> Self {
        Self {
            max_tcp_workers: MAX_TCP_WORKERS,
            max_tcp_request: MAX_TCP_REQUEST,
            max_dgram_reply_size: MAX_DGRAM_REPLY,
            io_timeout: Duration::from_secs(5),
        }
    }
}

/// Bind UDP and TCP on the same `addr`.
///
/// # Errors
///
/// Returns the first I/O error from either bind.
pub fn bind_udp_tcp(addr: SocketAddr) -> io::Result<(UdpSocket, TcpListener)> {
    let udp = UdpSocket::bind(addr)?;
    let tcp = TcpListener::bind(addr)?;
    Ok((udp, tcp))
}

/// Try each candidate until UDP and TCP both bind.
///
/// # Errors
///
/// Returns the last bind error if every candidate fails.
pub fn bind_preferred(candidates: &[&str]) -> io::Result<(SocketAddr, UdpSocket, TcpListener)> {
    let mut last = io::Error::new(io::ErrorKind::AddrNotAvailable, "no bind candidates");
    for c in candidates {
        let addr: SocketAddr = match c.parse() {
            Ok(a) => a,
            Err(e) => {
                last = io::Error::new(io::ErrorKind::InvalidInput, e);
                continue;
            }
        };
        match bind_udp_tcp(addr) {
            Ok((udp, tcp)) => {
                let local = udp.local_addr().unwrap_or(addr);
                tracing::info!(
                    event = krb5_log::events::KDC_LISTEN,
                    correlation_id = krb5_log::current_correlation_id(),
                    component = "krb5-kdc",
                    outcome = "ok",
                    bind = %local,
                );
                return Ok((local, udp, tcp));
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Drop root after a privileged bind (port 88).
///
/// When effective uid is 0, setgid/setuid to `KRB5_KDC_USER` (default
/// `nobody`). Unprivileged processes return `Ok(false)` without changing
/// credentials.
///
/// # Errors
///
/// Unknown target user, or `setgid`/`setuid` failure.
pub fn drop_privileges() -> io::Result<bool> {
    drop_privileges_to(
        std::env::var("KRB5_KDC_USER")
            .ok()
            .filter(|s| !s.is_empty())
            .as_deref()
            .unwrap_or("nobody"),
    )
}

/// Drop to `username` when running as root.
///
/// # Errors
///
/// Unknown user or credential change failure.
pub fn drop_privileges_to(username: &str) -> io::Result<bool> {
    if !nix::unistd::Uid::effective().is_root() {
        tracing::info!(
            event = krb5_log::events::KDC_LISTEN,
            correlation_id = krb5_log::current_correlation_id(),
            component = "krb5-kdc",
            outcome = "ok",
            detail = "privilege drop skipped (not root)",
        );
        return Ok(false);
    }
    let user = nix::unistd::User::from_name(username)
        .map_err(|e| io::Error::other(e.to_string()))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no user {username}")))?;
    nix::unistd::setgid(user.gid).map_err(|e| io::Error::other(e.to_string()))?;
    nix::unistd::setuid(user.uid).map_err(|e| io::Error::other(e.to_string()))?;
    tracing::info!(
        event = krb5_log::events::KDC_LISTEN,
        correlation_id = krb5_log::current_correlation_id(),
        component = "krb5-kdc",
        outcome = "ok",
        detail = "dropped privileges",
    );
    Ok(true)
}

fn install_shutdown_flag(flag: &Arc<AtomicBool>) {
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        let _ = signal_hook::flag::register(sig, Arc::clone(flag));
    }
}

/// Serve AS/TGS until SIGTERM/SIGINT (or forever if signal registration fails).
///
/// # Errors
///
/// Returns if a listener thread panics; individual datagrams are logged.
pub fn serve(store: SharedStore, udp: UdpSocket, tcp: TcpListener) -> io::Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    install_shutdown_flag(&shutdown);
    serve_until(store, udp, tcp, shutdown, ListenLimits::default())
}

/// Serve until `shutdown` is true. UDP/TCP loops poll so they can exit.
///
/// # Errors
///
/// Listener thread panic, or bind/socket option failures.
#[allow(clippy::needless_pass_by_value)] // Arc is cloned into the UDP/TCP threads
pub fn serve_until(
    store: SharedStore,
    udp: UdpSocket,
    tcp: TcpListener,
    shutdown: Arc<AtomicBool>,
    limits: ListenLimits,
) -> io::Result<()> {
    udp.set_read_timeout(Some(limits.io_timeout))?;
    tcp.set_nonblocking(true)?;
    let udp_store = Arc::clone(&store);
    let tcp_store = store;
    let udp_flag = Arc::clone(&shutdown);
    let tcp_flag = Arc::clone(&shutdown);
    let udp_thread = thread::spawn(move || udp_loop(&udp_store, udp, &udp_flag, limits));
    let tcp_thread = thread::spawn(move || tcp_loop(&tcp_store, tcp, &tcp_flag, limits));
    let _ = udp_thread.join();
    let _ = tcp_thread.join();
    Ok(())
}

#[allow(clippy::needless_pass_by_value)] // UDP socket is owned by the worker thread
fn udp_loop(store: &SharedStore, sock: UdpSocket, shutdown: &AtomicBool, limits: ListenLimits) {
    let mut buf = vec![0u8; 65_535];
    while !shutdown.load(Ordering::Relaxed) {
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                let payload = buf[..n].to_vec();
                let reply = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    read_store(store, |s| handle_request(s, &payload))
                }));
                match reply {
                    Ok(Ok(mut reply)) => {
                        if reply.is_empty() {
                            log_dispatch_drop(true);
                            continue;
                        }
                        if reply.len() > limits.max_dgram_reply_size {
                            reply = read_store(store, |s| {
                                crate::kdc_error_bytes(s, krb5_types::err::RESPONSE_TOO_BIG)
                            });
                        }
                        if let Err(e) = sock.send_to(&reply, peer) {
                            tracing::error!(
                                event = krb5_log::events::KDC_TRANSPORT,
                                correlation_id = krb5_log::current_correlation_id(),
                                component = "krb5-kdc",
                                outcome = "error",
                                error = %e,
                            );
                        }
                    }
                    Ok(Err(e)) => tracing::error!(
                        event = krb5_log::events::KDC_ISSUE,
                        correlation_id = krb5_log::current_correlation_id(),
                        component = "krb5-kdc",
                        outcome = "error",
                        error = %e,
                        error_suffix = WHILE_DISPATCHING_UDP,
                    ),
                    Err(_) => tracing::error!(
                        event = krb5_log::events::KDC_TRANSPORT,
                        correlation_id = krb5_log::current_correlation_id(),
                        component = "krb5-kdc",
                        outcome = "error",
                        error = "request panic isolated",
                    ),
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                tracing::error!(
                    event = krb5_log::events::KDC_ISSUE,
                    component = "krb5-kdc",
                    outcome = "error",
                    error = %e,
                );
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

#[allow(clippy::needless_pass_by_value)] // TCP listener is owned by the worker thread
fn tcp_loop(
    store: &SharedStore,
    listener: TcpListener,
    shutdown: &AtomicBool,
    limits: ListenLimits,
) {
    let workers = Arc::new(AtomicUsize::new(0));
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let current = workers.load(Ordering::SeqCst);
                if current >= limits.max_tcp_workers {
                    tracing::error!(
                        event = krb5_log::events::KDC_TRANSPORT,
                        correlation_id = krb5_log::current_correlation_id(),
                        component = "krb5-kdc",
                        outcome = "error",
                        error = "tcp worker cap",
                    );
                    drop(stream);
                    continue;
                }
                workers.fetch_add(1, Ordering::SeqCst);
                let store = Arc::clone(store);
                let workers_g = Arc::clone(&workers);
                let max_body = limits.max_tcp_request;
                let timeout = limits.io_timeout;
                thread::spawn(move || {
                    let _guard = WorkerGuard(workers_g);
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        handle_tcp(&store, stream, max_body, timeout)
                    }));
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => tracing::error!(
                            event = krb5_log::events::KDC_ISSUE,
                            component = "krb5-kdc",
                            outcome = "error",
                            error = %e,
                        ),
                        Err(_) => tracing::error!(
                            event = krb5_log::events::KDC_TRANSPORT,
                            component = "krb5-kdc",
                            outcome = "error",
                            error = "tcp worker panic isolated",
                        ),
                    }
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                tracing::error!(
                    event = krb5_log::events::KDC_ISSUE,
                    component = "krb5-kdc",
                    outcome = "error",
                    error = %e,
                );
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn handle_tcp(
    store: &SharedStore,
    mut stream: TcpStream,
    max_body: usize,
    timeout: Duration,
) -> io::Result<()> {
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut hdr = [0u8; 4];
    match stream.read_exact(&mut hdr) {
        Ok(()) => {}
        // MIT may TCP-connect :88 and leave without a PDU.
        Err(e)
            if e.kind() == io::ErrorKind::UnexpectedEof
                || e.kind() == io::ErrorKind::TimedOut
                || e.kind() == io::ErrorKind::WouldBlock =>
        {
            return Ok(());
        }
        Err(e) => return Err(e),
    }
    let n = usize::try_from(u32::from_be_bytes(hdr)).unwrap_or(usize::MAX);
    if n == 0 {
        return Ok(());
    }
    if n > max_body {
        let reply = read_store(store, |s| {
            crate::kdc_error_bytes(s, krb5_types::err::FIELD_TOOLONG)
        });
        let len = u32::try_from(reply.len()).unwrap_or(0);
        let _ = stream.write_all(&len.to_be_bytes());
        let _ = stream.write_all(&reply);
        let _ = stream.flush();
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("error constructing KRB_ERR_FIELD_TOOLONG error! length {n}"),
        ));
    }
    let mut req = vec![0u8; n];
    match stream.read_exact(&mut req) {
        Ok(()) => {}
        Err(e)
            if e.kind() == io::ErrorKind::UnexpectedEof
                || e.kind() == io::ErrorKind::TimedOut
                || e.kind() == io::ErrorKind::WouldBlock =>
        {
            return Ok(());
        }
        Err(e) => return Err(e),
    }
    let reply = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        read_store(store, |s| handle_request(s, &req))
    })) {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            tracing::error!(
                event = krb5_log::events::KDC_ISSUE,
                component = "krb5-kdc",
                outcome = "error",
                error = %e,
                error_suffix = WHILE_DISPATCHING_TCP,
            );
            return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
        }
        Err(_) => {
            return Err(io::Error::other("request panic isolated"));
        }
    };
    if reply.is_empty() {
        log_dispatch_drop(false);
        return Ok(());
    }
    let len = u32::try_from(reply.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "reply too large"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&reply)?;
    stream.flush()?;
    Ok(())
}

/// Decrements the TCP worker counter on drop, including unwind.
struct WorkerGuard(Arc<AtomicUsize>);

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap_documented;
    use krb5_asn1::{decode, encode};
    use krb5_types::{PrincipalName, err};

    #[test]
    fn drop_privileges_is_noop_when_unprivileged() {
        assert!(!drop_privileges().expect("unprivileged drop"));
    }

    #[test]
    fn tcp_oversize_length_is_field_toolong() {
        let (store, _) = bootstrap_documented().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let store = shared_store(store);
        thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let _ = handle_tcp(&store, s, 32, Duration::from_secs(2));
        });
        let mut c = std::net::TcpStream::connect(addr).unwrap();
        c.write_all(&64u32.to_be_bytes()).unwrap();
        c.write_all(&[0u8; 8]).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut hdr = [0u8; 4];
        c.read_exact(&mut hdr).expect("FIELD_TOOLONG length");
        let n = u32::from_be_bytes(hdr) as usize;
        let mut body = vec![0u8; n];
        c.read_exact(&mut body).expect("FIELD_TOOLONG body");
        let e: krb5_types::KrbError = decode(&body).expect("KRB-ERROR");
        assert_eq!(e.error_code, err::FIELD_TOOLONG);
    }

    #[test]
    fn tcp_max_request_is_one_mib_minus_four() {
        assert_eq!(MAX_TCP_REQUEST, 1024 * 1024 - 4);
    }

    #[test]
    fn tcp_one_mib_plus_one_is_field_toolong() {
        let (store, _) = bootstrap_documented().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let store = shared_store(store);
        thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let _ = handle_tcp(&store, s, MAX_TCP_REQUEST, Duration::from_secs(2));
        });
        let mut c = std::net::TcpStream::connect(addr).unwrap();
        c.write_all(&(1024 * 1024 + 1u32).to_be_bytes()).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut hdr = [0u8; 4];
        c.read_exact(&mut hdr).expect("FIELD_TOOLONG length");
        let n = u32::from_be_bytes(hdr) as usize;
        let mut body = vec![0u8; n];
        c.read_exact(&mut body).expect("FIELD_TOOLONG body");
        let e: krb5_types::KrbError = decode(&body).expect("KRB-ERROR");
        assert_eq!(e.error_code, err::FIELD_TOOLONG);
    }

    #[test]
    fn tcp_128kib_unknown_cname_is_client_not_found() {
        use krb5_types::{OctetString, PaData};

        let (store, _) = bootstrap_documented().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let store = shared_store(store);
        thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let _ = handle_tcp(&store, s, MAX_TCP_REQUEST, Duration::from_secs(5));
        });
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["nosuch"]);
        let mut req = crate::as_req(cname, crate::TEST_REALM, 1, None).unwrap();
        req.0.padata = Some(vec![PaData {
            padata_type: 9999,
            padata_value: OctetString::from(vec![0u8; 128 * 1024]),
        }]);
        let bytes = encode(&req).unwrap();
        assert!(bytes.len() > 128 * 1024);
        assert!(bytes.len() <= MAX_TCP_REQUEST);
        let mut c = std::net::TcpStream::connect(addr).unwrap();
        c.write_all(&(u32::try_from(bytes.len()).unwrap()).to_be_bytes())
            .unwrap();
        c.write_all(&bytes).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut hdr = [0u8; 4];
        c.read_exact(&mut hdr).expect("KRB-ERROR length");
        let n = u32::from_be_bytes(hdr) as usize;
        let mut body = vec![0u8; n];
        c.read_exact(&mut body).expect("KRB-ERROR body");
        let e: krb5_types::KrbError = decode(&body).expect("KRB-ERROR");
        assert_eq!(e.error_code, err::C_PRINCIPAL_UNKNOWN);
        let text = e
            .e_text
            .as_ref()
            .and_then(|t| std::str::from_utf8(t.as_bytes()).ok());
        assert_eq!(text, Some("CLIENT_NOT_FOUND"));
    }

    #[test]
    fn tcp_zero_length_is_dropped() {
        let (store, _) = bootstrap_documented().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let store = shared_store(store);
        thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            handle_tcp(&store, s, MAX_TCP_REQUEST, Duration::from_secs(2)).expect("zero-len drop");
        });
        let mut c = std::net::TcpStream::connect(addr).unwrap();
        c.write_all(&0u32.to_be_bytes()).unwrap();
        c.set_read_timeout(Some(Duration::from_millis(400)))
            .unwrap();
        let mut hdr = [0u8; 4];
        assert!(
            c.read_exact(&mut hdr).is_err(),
            "zero-length must not reply"
        );
    }

    #[test]
    fn dispatch_suffixes_are_mit_net_server() {
        assert_eq!(WHILE_DISPATCHING_UDP, "while dispatching (udp)");
        assert_eq!(WHILE_DISPATCHING_TCP, "while dispatching (tcp)");
    }

    #[test]
    fn log_dispatch_drop_udp_is_not_tcp() {
        use std::sync::Mutex;
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl Write for Capture {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for Capture {
            type Writer = Self;
            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(Capture(Arc::clone(&buf)))
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            log_dispatch_drop(true);
            log_dispatch_drop(false);
            let (store, _) = bootstrap_documented().unwrap();
            let _ = crate::handle_request(&store, &[]);
        });
        let logged = String::from_utf8_lossy(&buf.lock().unwrap()).into_owned();
        assert!(
            logged.contains(WHILE_DISPATCHING_UDP),
            "listener UDP drop logs MIT suffix, got {logged}"
        );
        assert!(
            logged.contains(WHILE_DISPATCHING_TCP),
            "listener TCP drop logs MIT suffix, got {logged}"
        );
        let issue_only = {
            let buf2 = Arc::new(Mutex::new(Vec::new()));
            let sub2 = tracing_subscriber::fmt()
                .with_writer(Capture(Arc::clone(&buf2)))
                .with_ansi(false)
                .finish();
            tracing::subscriber::with_default(sub2, || {
                let (store, _) = bootstrap_documented().unwrap();
                let _ = crate::handle_request(&store, &[]);
            });
            String::from_utf8_lossy(&buf2.lock().unwrap()).into_owned()
        };
        assert!(
            !issue_only.contains(WHILE_DISPATCHING_UDP),
            "handle_request must not log (udp); got {issue_only}"
        );
    }

    #[test]
    fn udp_oversize_reply_is_response_too_big() {
        let (store, _) = bootstrap_documented().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(addr).unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        let store = shared_store(store);
        let f2 = Arc::clone(&flag);
        thread::spawn(move || {
            let _ = serve_until(
                store,
                udp,
                tcp,
                f2,
                ListenLimits {
                    max_tcp_workers: 2,
                    max_tcp_request: 4096,
                    max_dgram_reply_size: 10,
                    io_timeout: Duration::from_millis(200),
                },
            );
        });
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::TEST_USER]);
        let req = crate::as_req(cname, crate::TEST_REALM, 1, None).unwrap();
        let bytes = encode(&req).unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        sock.send_to(&bytes, addr).unwrap();
        let mut buf = [0u8; 4096];
        let n = sock.recv(&mut buf).unwrap();
        let e: krb5_types::KrbError = decode(&buf[..n]).unwrap();
        assert_eq!(e.error_code, err::RESPONSE_TOO_BIG);
        flag.store(true, Ordering::SeqCst);
    }

    #[test]
    fn serve_until_stops_on_flag() {
        let (store, _) = bootstrap_documented().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(addr).unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        let store = shared_store(store);
        let f2 = Arc::clone(&flag);
        let h = thread::spawn(move || {
            serve_until(
                store,
                udp,
                tcp,
                f2,
                ListenLimits {
                    max_tcp_workers: 2,
                    max_tcp_request: 4096,
                    max_dgram_reply_size: MAX_DGRAM_REPLY,
                    io_timeout: Duration::from_millis(50),
                },
            )
        });
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::TEST_USER]);
        let req = crate::as_req(cname, crate::TEST_REALM, 1, None).unwrap();
        let bytes = encode(&req).unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        sock.send_to(&bytes, addr).unwrap();
        let mut buf = [0u8; 4096];
        let n = sock.recv(&mut buf).unwrap();
        let e: krb5_types::KrbError = decode(&buf[..n]).unwrap();
        assert_eq!(e.error_code, err::PREAUTH_REQUIRED);
        flag.store(true, Ordering::SeqCst);
        h.join().unwrap().unwrap();
    }

    #[test]
    fn tcp_worker_guard_releases_slot_on_panic() {
        let n = Arc::new(AtomicUsize::new(0));
        n.fetch_add(1, Ordering::SeqCst);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = WorkerGuard(Arc::clone(&n));
            panic!("isolated");
        }));
        assert!(r.is_err());
        assert_eq!(n.load(Ordering::SeqCst), 0);
    }
}
