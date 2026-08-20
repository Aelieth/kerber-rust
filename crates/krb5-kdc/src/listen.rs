//! Thin UDP/TCP 88 listener around [`crate::issue::handle_request`].

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::issue::handle_request;
use crate::store::PrincipalStore;

/// Addresses tried when the caller does not pin a bind address.
/// Never includes `0.0.0.0` — the daemon must be given an explicit bind
/// to listen on all interfaces.
pub const BIND_CANDIDATES: &[&str] = &["127.0.0.1:88", "127.0.0.1:8888"];

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

/// Serve AS/TGS forever on already-bound sockets.
///
/// # Errors
///
/// Returns if a listener thread panics; individual datagrams are logged.
pub fn serve(store: Arc<PrincipalStore>, udp: UdpSocket, tcp: TcpListener) -> io::Result<()> {
    let udp_store = Arc::clone(&store);
    let tcp_store = store;
    let udp_thread = thread::spawn(move || udp_loop(&udp_store, udp));
    let tcp_thread = thread::spawn(move || tcp_loop(&tcp_store, tcp));
    let _ = udp_thread.join();
    let _ = tcp_thread.join();
    Ok(())
}

#[allow(clippy::needless_pass_by_value)] // UDP socket is owned by the worker thread
fn udp_loop(store: &PrincipalStore, sock: UdpSocket) {
    let mut buf = vec![0u8; 65_535];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                let payload = buf[..n].to_vec();
                let reply = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    handle_request(store, &payload)
                }));
                match reply {
                    Ok(Ok(reply)) => {
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
fn tcp_loop(store: &Arc<PrincipalStore>, listener: TcpListener) {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let store = Arc::clone(store);
                thread::spawn(move || {
                    if let Err(e) = handle_tcp(&store, stream) {
                        tracing::error!(
                            event = krb5_log::events::KDC_ISSUE,
                            component = "krb5-kdc",
                            outcome = "error",
                            error = %e,
                        );
                    }
                });
            }
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

fn handle_tcp(store: &PrincipalStore, mut stream: TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr)?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n == 0 || n > 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid TCP length {n}"),
        ));
    }
    let mut req = vec![0u8; n];
    stream.read_exact(&mut req)?;
    let reply = handle_request(store, &req)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let len = u32::try_from(reply.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "reply too large"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&reply)?;
    stream.flush()?;
    Ok(())
}
