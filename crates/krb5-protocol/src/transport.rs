//! UDP and TCP exchanges with a KDC (RFC 4120 §7.2).

use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use krb5_asn1::decode;
use krb5_types::{err, KrbError};

use crate::error::Error;

/// Default KDC port.
pub const KDC_PORT: u16 = 88;

const TIMEOUT: Duration = Duration::from_secs(5);
const UDP_MAX: usize = 65535;

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
/// (`KRB_ERR_RESPONSE_TOO_BIG`) or UDP fails. UDP uses `connect()` so an
/// off-path first datagram is not accepted.
///
/// # Errors
///
/// Returns [`Error::Io`] on network failure.
pub fn exchange(addr: &KdcAddr, request: &[u8]) -> Result<Vec<u8>, Error> {
    exchange_with_failover(std::slice::from_ref(addr), request)
}

/// Try each KDC in order with UDP retransmit/backoff (1s, 2s, 4s).
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
    match exchange_udp(addr, request) {
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
        Err(Error::Io {
            retryable: true, ..
        }) => exchange_tcp(addr, request),
        Err(e) => Err(e),
    }
}

fn is_response_too_big(bytes: &[u8]) -> bool {
    bytes.first() == Some(&0x7e)
        && decode::<KrbError>(bytes)
            .map(|e| e.error_code == err::RESPONSE_TOO_BIG)
            .unwrap_or(false)
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
    sock.set_read_timeout(Some(TIMEOUT))
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    sock.set_write_timeout(Some(TIMEOUT))
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    let dest = format!("{}:{}", addr.host, addr.port);
    sock.connect(dest.as_str()).map_err(Error::from_io)?;
    let backoffs = [
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(4),
    ];
    let mut last = Error::transport_msg("udp timeout");
    for (i, bo) in backoffs.iter().enumerate() {
        sock.set_read_timeout(Some(*bo)).map_err(Error::from_io)?;
        if let Err(e) = sock.send(request) {
            last = Error::from_io(e);
            continue;
        }
        let mut buf = vec![0u8; UDP_MAX];
        match sock.recv(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Err(e) => {
                last = Error::from_io(e);
                if i + 1 == backoffs.len() {
                    break;
                }
            }
        }
    }
    Err(last)
}

fn exchange_tcp(addr: &KdcAddr, request: &[u8]) -> Result<Vec<u8>, Error> {
    let dest = format!("{}:{}", addr.host, addr.port);
    let mut addrs = dest
        .to_socket_addrs()
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    let sa = addrs
        .next()
        .ok_or_else(|| Error::transport_msg("no KDC address"))?;
    let mut stream = TcpStream::connect_timeout(&sa, TIMEOUT)
        .map_err(|e| Error::transport_msg(format!("tcp connect {dest}: {e}")))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    let len =
        u32::try_from(request.len()).map_err(|_| Error::transport_msg("request too large"))?;
    use std::io::{Read, Write};
    stream
        .write_all(&len.to_be_bytes())
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    stream
        .write_all(request)
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    stream
        .flush()
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    let mut hdr = [0u8; 4];
    stream
        .read_exact(&mut hdr)
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n == 0 || n > 1024 * 1024 {
        return Err(Error::transport_msg(format!("invalid TCP length {n}")));
    }
    let mut buf = vec![0u8; n];
    stream
        .read_exact(&mut buf)
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    Ok(buf)
}
