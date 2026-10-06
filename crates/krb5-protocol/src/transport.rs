//! UDP and TCP exchanges with a KDC (RFC 4120 §7.2).

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use krb5_asn1::decode;
use krb5_types::{KrbError, err};

use crate::error::Error;
use crate::trace::{self, RemoteAddr, Transport};

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

/// Which exchange a [`sendto_kdc`] request belongs to: the trace of a reply too big for UDP
/// differs between them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SendKind {
    /// An AS request (MIT `k5_init_creds_get`).
    As,
    /// A TGS request (MIT `krb5_tkt_creds_get`).
    Tgs,
}

/// Send `request` to the KDC. Prefers UDP; retries on TCP if the KDC asks
/// (`KRB_ERR_RESPONSE_TOO_BIG`) or UDP fails. UDP replies are accepted only
/// from the destination we sent to (off-path datagrams are ignored).
///
/// # Errors
///
/// [`Error::Io`] when no reply arrives. A UDP send or receive error keeps its kind
/// (`WouldBlock` when none of the three waits, 0.5, 1 and 2 s, gets a reply); every other
/// failure is `kind: Other`, `retryable: true`: an unresolvable host, a UDP bind, a TCP connect
/// refused or timed out (5 s), a failed TCP write, no TCP reply within 5 s, a TCP reply cut
/// short, or a TCP length of 0 or over 1 MiB. TCP is tried for a request above
/// `udp_preference_limit`, after a `RESPONSE_TOO_BIG` reply, or after UDP fails; when both
/// fail, a UDP timeout yields the TCP error and any other UDP failure the UDP error.
pub fn exchange(addr: &KdcAddr, request: &[u8]) -> Result<Vec<u8>, Error> {
    exchange_with_failover(std::slice::from_ref(addr), request)
}

/// [`exchange`] of an AS or TGS request to `realm`'s KDC, traced as MIT traces it.
/// MIT `k5_sendto_kdc` (`lib/krb5/os/sendto_kdc.c:446-560`): the request's size and realm are
/// traced before the KDC is located and contacted.
pub(crate) fn sendto_kdc(
    addr: &KdcAddr,
    realm: &str,
    request: &[u8],
    kind: SendKind,
) -> Result<Vec<u8>, Error> {
    trace::sendto_kdc(request.len(), realm.as_bytes(), false, false);
    exchange_one(addr, request, Some((realm, kind)))
}

/// Send `request` on TCP only so a PAC-sized reply cannot silently upgrade UDP.
///
/// # Errors
///
/// [`Error::Io`] with `kind: Other` and `retryable: true` when the host does not resolve, the
/// connect is refused or takes over 5 s, the socket cannot be configured, the request cannot be
/// framed or written, no reply arrives within 5 s, the reply is cut short, or its length prefix
/// is 0 or over 1 MiB.
pub fn exchange_on_tcp(addr: &KdcAddr, request: &[u8]) -> Result<Vec<u8>, Error> {
    crate::capture_pdu("client-req", request);
    let sa = dest_addr(addr)?;
    exchange_tcp(sa, request)
}

/// Try each KDC in order: UDP with retransmit waits of 0.5 s, 1 s and 2 s, then TCP.
///
/// # Errors
///
/// [`Error::Io`] (`kind: Other`) when `addrs` is empty. Otherwise each KDC is tried as in
/// [`exchange`]: the first failure that is not retryable (a UDP send or receive error other
/// than a timeout, refusal, reset, or interrupt) is returned at once, else the last KDC's
/// [`Error::Io`].
pub fn exchange_with_failover(addrs: &[KdcAddr], request: &[u8]) -> Result<Vec<u8>, Error> {
    let mut last = Error::transport_msg("no KDC addresses");
    for addr in addrs {
        match exchange_one(addr, request, None) {
            Ok(r) => return Ok(r),
            Err(e) if e.is_retryable() => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

/// MIT `k5_init_creds_get` (`get_in_tkt.c:570-572`): a response-too-big error retries the same
/// request over TCP.
/// A UDP timeout prefers the TCP error, because a reply that cannot fit in a datagram otherwise
/// hides that failure. `traced` is the realm and exchange of a [`sendto_kdc`] request, whose
/// TCP retry is traced as a second send.
fn exchange_one(
    addr: &KdcAddr,
    request: &[u8],
    traced: Option<(&str, SendKind)>,
) -> Result<Vec<u8>, Error> {
    crate::capture_pdu("client-req", request);
    let dest = dest_addr(addr)?;
    if request.len() > krb5_config::udp_preference_limit() {
        let reply = exchange_tcp(dest, request);
        if let Ok(bytes) = &reply {
            crate::capture_pdu("client-rep", bytes);
        }
        return reply;
    }
    let reply = match exchange_udp(addr, dest, request) {
        Ok(reply) if is_response_too_big(&reply) => {
            tracing::info!(
                event = krb5_log::events::PROTOCOL_TRANSPORT,
                correlation_id = krb5_log::current_correlation_id(),
                component = "krb5-protocol",
                outcome = "ok",
                error = "KRB_ERR_RESPONSE_TOO_BIG, falling back to TCP",
            );
            if let Some((realm, kind)) = traced {
                trace_retry_tcp(realm, request.len(), kind);
            }
            exchange_tcp(dest_addr(addr)?, request)
        }
        Ok(reply) => Ok(reply),
        Err(udp_err) => match exchange_tcp(dest, request) {
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

/// The trace between a reply too big for UDP and its TCP resend.
/// MIT `init_creds_validate_reply` (`lib/krb5/krb/get_in_tkt.c:1081-1115`): an AS caller first
/// traces the error itself.
/// MIT `k5_init_creds_get` (`lib/krb5/krb/get_in_tkt.c:546-588`): then the retry, and the request
/// is sent again with no UDP.
fn trace_retry_tcp(realm: &str, len: usize, kind: SendKind) {
    match kind {
        SendKind::As => {
            trace::init_creds_error_reply(trace::kdc_code(err::RESPONSE_TOO_BIG));
            trace::init_creds_retry_tcp();
        }
        SendKind::Tgs => trace::tkt_creds_retry_tcp(),
    }
    trace::sendto_kdc(len, realm.as_bytes(), false, true);
}

fn is_response_too_big(bytes: &[u8]) -> bool {
    bytes.first() == Some(&0x7e)
        && decode::<KrbError>(bytes).is_ok_and(|e| e.error_code == err::RESPONSE_TOO_BIG)
}

/// The KDC's address.
/// MIT `resolve_server` (`lib/krb5/os/sendto_kdc.c:800-881`): a host name, an address literal too,
/// is traced as it is resolved.
fn dest_addr(addr: &KdcAddr) -> Result<SocketAddr, Error> {
    trace::sendto_kdc_resolving(&addr.host);
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

/// The errno of an I/O error, 0 when it has none.
pub(crate) fn errno(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(0)
}

/// MIT `service_udp_read` (`sendto_kdc.c:1209-1216`): a UDP read is taken from the connected peer,
/// and a receive error drops that attempt.
/// This socket is not connected, so a datagram whose source is not the KDC address is ignored and
/// is not the reply.
/// MIT `start_connection` (`lib/krb5/os/sendto_kdc.c:884-990`): the first send is traced as the
/// initial request.
/// MIT `maybe_send` (`lib/krb5/os/sendto_kdc.c:1003-1035`): each later one as a retry.
fn exchange_udp(addr: &KdcAddr, dest: SocketAddr, request: &[u8]) -> Result<Vec<u8>, Error> {
    let ra = RemoteAddr {
        transport: Transport::Udp,
        addr: dest,
    };
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
    // send_to/recv_from (not connect): some stacks drop connected-UDP replies
    // when the KDC answers from a different local address. Source is still
    // checked so an off-path first datagram is not accepted.
    let backoffs = [
        Duration::from_millis(500),
        Duration::from_secs(1),
        Duration::from_secs(2),
    ];
    let mut last = Error::transport_msg("udp timeout");
    for (attempt, bo) in backoffs.into_iter().enumerate() {
        sock.set_read_timeout(Some(bo)).map_err(Error::from_io)?;
        if attempt == 0 {
            trace::sendto_kdc_udp_send_initial(&ra);
        } else {
            trace::sendto_kdc_udp_send_retry(&ra);
        }
        if let Err(e) = sock.send_to(request, dest) {
            if attempt == 0 {
                trace::sendto_kdc_udp_error_send_initial(&ra, errno(&e));
            } else {
                trace::sendto_kdc_udp_error_send_retry(&ra, errno(&e));
            }
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
                    trace::sendto_kdc_response(n, &ra);
                    return Ok(buf);
                }
                Err(e) => {
                    if !is_timeout(&e) {
                        trace::sendto_kdc_udp_error_recv(&ra, errno(&e));
                    }
                    last = Error::from_io(e);
                    break;
                }
            }
        }
    }
    Err(last)
}

/// MIT `service_tcp_connect` (`lib/krb5/os/sendto_kdc.c:1098-1112`): a connection that fails is
/// traced and closed.
/// MIT `service_tcp_write` (`lib/krb5/os/sendto_kdc.c:1115-1146`): the request is traced as it is
/// written.
/// MIT `service_tcp_read` (`lib/krb5/os/sendto_kdc.c:1149-1200`): a read that fails or ends early
/// is traced and closed, a length over 1 MiB closed.
/// MIT `k5_sendto` (`lib/krb5/os/sendto_kdc.c:1498-1638`): an answer is traced, then its
/// connection is closed.
fn exchange_tcp(sa: SocketAddr, request: &[u8]) -> Result<Vec<u8>, Error> {
    let ra = RemoteAddr {
        transport: Transport::Tcp,
        addr: sa,
    };
    trace::sendto_kdc_tcp_connect(&ra);
    let result = tcp_round_trip(sa, &ra, request);
    if let Ok(reply) = &result {
        trace::sendto_kdc_response(reply.len(), &ra);
    }
    trace::sendto_kdc_tcp_disconnect(&ra);
    result
}

fn tcp_round_trip(sa: SocketAddr, ra: &RemoteAddr, request: &[u8]) -> Result<Vec<u8>, Error> {
    let mut stream = TcpStream::connect_timeout(&sa, TIMEOUT).map_err(|e| {
        if !is_timeout(&e) {
            trace::sendto_kdc_tcp_error_connect(ra, errno(&e));
        }
        Error::transport_msg(format!("tcp connect {sa}: {e}"))
    })?;
    stream
        .set_nodelay(true)
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    // MIT `service_tcp_write` (`lib/krb5/os/sendto_kdc.c:1124-1125`): the length and the request
    // go out in one writev.
    trace::sendto_kdc_tcp_send(ra);
    crate::framing::write_messages(&mut stream, &[request]).map_err(|e| {
        trace::sendto_kdc_tcp_error_send(ra, errno(&e));
        Error::transport_msg(format!("tcp write: {e}"))
    })?;
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).map_err(|e| {
        if !is_timeout(&e) {
            trace::sendto_kdc_tcp_error_recv_len(ra, read_errno(&e));
        }
        Error::transport_msg(format!("tcp read header: {e}"))
    })?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n == 0 || n > 1024 * 1024 {
        return Err(Error::transport_msg(format!("invalid TCP length {n}")));
    }
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).map_err(|e| {
        if !is_timeout(&e) {
            trace::sendto_kdc_tcp_error_recv(ra, read_errno(&e));
        }
        Error::transport_msg(format!("tcp read body: {e}"))
    })?;
    Ok(buf)
}

/// A wait that ran out, which MIT's `select` loop does not trace.
pub(crate) fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// The errno of a failed read: a connection closed early is `ECONNRESET`, as MIT counts a read of
/// nothing.
pub(crate) fn read_errno(e: &std::io::Error) -> i32 {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        nix::errno::Errno::ECONNRESET as i32
    } else {
        errno(e)
    }
}
