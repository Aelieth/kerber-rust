//! UDP and TCP exchanges with a KDC (RFC 4120 §7.2).

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use krb5_asn1::decode;
use krb5_types::{err, KrbError};

use crate::error::Error;

/// Default KDC port.
pub const KDC_PORT: u16 = 88;

const TIMEOUT: Duration = Duration::from_secs(5);
const UDP_MAX: usize = 64 * 1024;

/// KDC socket address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdcAddr {
    /// Host name or dotted IP.
    pub host: String,
    /// UDP/TCP port (usually 88).
    pub port: u16,
}

impl KdcAddr {
    /// `host:88`.
    #[must_use]
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: KDC_PORT,
        }
    }
}

/// Send `request` to the KDC. Prefers UDP; retries on TCP if the KDC asks
/// (`KRB_ERR_RESPONSE_TOO_BIG`) or UDP fails. UDP replies are accepted only
/// from the destination we sent to (off-path datagrams are ignored).
///
/// # Errors
///
/// Returns [`Error::Io`] on network failure.
pub fn exchange(addr: &KdcAddr, request: &[u8]) -> Result<Vec<u8>, Error> {
    exchange_with_failover(std::slice::from_ref(addr), request)
}

/// Send `request` on TCP only so a PAC-sized reply cannot silently upgrade UDP.
///
/// # Errors
///
/// Returns [`Error::Io`] on network failure.
pub fn exchange_on_tcp(addr: &KdcAddr, request: &[u8]) -> Result<Vec<u8>, Error> {
    crate::capture_pdu("client-req", request);
    exchange_tcp(addr, request)
}

/// Try each KDC in order with UDP retransmit/backoff (1s, 2s) then TCP.
///
/// # Errors
///
/// Returns the last transport error.
pub fn exchange_with_failover(addrs: &[KdcAddr], request: &[u8]) -> Result<Vec<u8>, Error> {
    let mut last = Error::transport_msg("no KDC addresses");
    for addr in addrs {
        match exchange_one(addr, request) {
            Ok(r) => return Ok(r),
            Err(e) if e.is_retryable() => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

fn exchange_one(addr: &KdcAddr, request: &[u8]) -> Result<Vec<u8>, Error> {
    crate::capture_pdu("client-req", request);
    let reply = match exchange_udp(addr, request) {
        Ok(reply) if is_response_too_big(&reply) => {
            tracing::info!(
                event = krb5_log::events::PROTOCOL_TRANSPORT,
                correlation_id = krb5_log::current_correlation_id(),
                component = "krb5-protocol",
                outcome = "ok",
                error = "KRB_ERR_RESPONSE_TOO_BIG, falling back to TCP",
            );
            exchange_tcp(addr, request)
        }
        Ok(reply) => Ok(reply),
        Err(udp_err) => match exchange_tcp(addr, request) {
            Ok(reply) => Ok(reply),
            Err(tcp_err) => {
                tracing::error!(
                    event = krb5_log::events::PROTOCOL_TRANSPORT,
                    correlation_id = krb5_log::current_correlation_id(),
                    component = "krb5-protocol",
                    outcome = "error",
                    error = %tcp_err,
                );
                // Prefer the TCP error when UDP timed out: TGS replies with a
                // PAC often never fit UDP, and the TCP failure is actionable.
                if matches!(
                    &udp_err,
                    Error::Io {
                        kind: std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut,
                        ..
                    }
                ) {
                    Err(tcp_err)
                } else {
                    Err(udp_err)
                }
            }
        },
    };
    if let Ok(bytes) = &reply {
        crate::capture_pdu("client-rep", bytes);
    }
    reply
}

fn is_response_too_big(bytes: &[u8]) -> bool {
    bytes.first() == Some(&0x7e)
        && decode::<KrbError>(bytes).is_ok_and(|e| e.error_code == err::RESPONSE_TOO_BIG)
}

fn dest_addr(addr: &KdcAddr) -> Result<SocketAddr, Error> {
    if addr.host == "127.0.0.1" || addr.host == "localhost" {
        return Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port));
    }
    if let Ok(ip) = addr.host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, addr.port));
    }
    let dest = format!("{}:{}", addr.host, addr.port);
    dest.to_socket_addrs()
        .map_err(|e| Error::transport_msg(e.to_string()))?
        .next()
        .ok_or_else(|| Error::transport_msg("no KDC address"))
}

fn exchange_udp(addr: &KdcAddr, request: &[u8]) -> Result<Vec<u8>, Error> {
    // Bind loopback when the KDC is loopback so replies stay on lo (Docker
    // bridge + 0.0.0.0 ephemeral ports drop UDP replies).
    let bind = if addr.host == "127.0.0.1" || addr.host == "localhost" {
        "127.0.0.1:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind).map_err(|e| Error::transport_msg(format!("udp bind: {e}")))?;
    sock.set_write_timeout(Some(TIMEOUT))
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    let dest = dest_addr(addr)?;
    // send_to/recv_from (not connect): some stacks drop connected-UDP replies
    // when the KDC answers from a different local address. Source is still
    // checked so an off-path first datagram is not accepted.
    let backoffs = [
        Duration::from_millis(500),
        Duration::from_secs(1),
        Duration::from_secs(2),
    ];
    let mut last = Error::transport_msg("udp timeout");
    for bo in backoffs {
        sock.set_read_timeout(Some(bo)).map_err(Error::from_io)?;
        if let Err(e) = sock.send_to(request, dest) {
            last = Error::from_io(e);
            continue;
        }
        let deadline = std::time::Instant::now() + bo;
        loop {
            let mut buf = vec![0u8; UDP_MAX];
            match sock.recv_from(&mut buf) {
                Ok((n, src)) => {
                    if src.ip() != dest.ip() || src.port() != dest.port() {
                        tracing::info!(
                            event = krb5_log::events::PROTOCOL_TRANSPORT,
                            correlation_id = krb5_log::current_correlation_id(),
                            component = "krb5-protocol",
                            outcome = "ok",
                            error = "ignored off-path UDP datagram",
                        );
                        if std::time::Instant::now() >= deadline {
                            last = Error::transport_msg("udp timeout");
                            break;
                        }
                        continue;
                    }
                    buf.truncate(n);
                    return Ok(buf);
                }
                Err(e) => {
                    last = Error::from_io(e);
                    break;
                }
            }
        }
    }
    Err(last)
}

fn exchange_tcp(addr: &KdcAddr, request: &[u8]) -> Result<Vec<u8>, Error> {
    let sa = dest_addr(addr)?;
    let mut stream = TcpStream::connect_timeout(&sa, TIMEOUT)
        .map_err(|e| Error::transport_msg(format!("tcp connect {sa}: {e}")))?;
    stream
        .set_nodelay(true)
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    let len =
        u32::try_from(request.len()).map_err(|_| Error::transport_msg("request too large"))?;
    let mut out = Vec::with_capacity(4 + request.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(request);
    stream
        .write_all(&out)
        .map_err(|e| Error::transport_msg(format!("tcp write: {e}")))?;
    stream
        .flush()
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    let mut hdr = [0u8; 4];
    stream
        .read_exact(&mut hdr)
        .map_err(|e| Error::transport_msg(format!("tcp read header: {e}")))?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n == 0 || n > 1024 * 1024 {
        return Err(Error::transport_msg(format!("invalid TCP length {n}")));
    }
    let mut buf = vec![0u8; n];
    stream
        .read_exact(&mut buf)
        .map_err(|e| Error::transport_msg(format!("tcp read body: {e}")))?;
    Ok(buf)
}
