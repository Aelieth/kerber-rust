//! UDP and TCP exchanges with a KDC (RFC 4120 §7.2).

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use krb5_asn1::decode;
use krb5_types::{KrbError, err};

use krb5_config::KdcTransport;

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
/// MIT `k5_sendto` (`lib/krb5/os/sendto_kdc.c:1537-1600`): when that location list has more than
/// one KDC and `addr` is its first, each entry is contacted. UDP then TCP, one second each, then
/// two seconds, then two UDP passes at four and eight seconds. One KDC keeps [`exchange_one`]'s
/// waits. An explicit address that is not that first KDC is contacted alone. HTTPS is not used.
pub(crate) fn sendto_kdc(
    addr: &KdcAddr,
    realm: &str,
    request: &[u8],
    kind: SendKind,
) -> Result<Vec<u8>, Error> {
    trace::sendto_kdc(request.len(), realm.as_bytes(), false, false);
    // MIT `k5_locate_server` (`lib/krb5/os/locate_kdc.c:853-878`): once per send. A caller that
    // already located `realm` handed that list down; this send does not query again.
    let found = krb5_config::take_handed_kdcs(realm, &addr.host, addr.port)
        .unwrap_or_else(|| krb5_config::discover_kdc(realm));
    let walk = found.len() > 1
        && found
            .first()
            .is_some_and(|ep| ep.host == addr.host && ep.port == addr.port);
    if !walk {
        return exchange_one(addr, request, Some((realm, kind)));
    }
    let addrs: Vec<(KdcAddr, KdcTransport)> = found
        .into_iter()
        .map(|ep| {
            (
                KdcAddr {
                    host: ep.host,
                    port: ep.port,
                },
                ep.transport,
            )
        })
        .collect();
    exchange_passes(&addrs, request, Some((realm, kind)))
}

/// One located KDC, resolved once. A name that does not resolve has no socket.
struct Located {
    addr: KdcAddr,
    transport: KdcTransport,
    dest: Option<SocketAddr>,
    udp: Option<UdpSocket>,
}

impl Located {
    fn prepare(addr: &KdcAddr, transport: KdcTransport) -> Self {
        Self {
            addr: addr.clone(),
            transport,
            dest: dest_addr(addr).ok(),
            udp: None,
        }
    }
}

/// The list walk of [`sendto_kdc`].
struct Passes<'a> {
    request: &'a [u8],
    traced: Option<(&'a str, SendKind)>,
    servers: Vec<Located>,
    last: Error,
    svc: Option<Vec<u8>>,
}

impl<'a> Passes<'a> {
    fn new(
        addrs: &'a [(KdcAddr, KdcTransport)],
        request: &'a [u8],
        traced: Option<(&'a str, SendKind)>,
    ) -> Self {
        Self {
            request,
            traced,
            servers: addrs
                .iter()
                .map(|(addr, transport)| Located::prepare(addr, *transport))
                .collect(),
            last: Error::transport_msg("no KDC addresses"),
            svc: None,
        }
    }

    fn any_udp(&self) -> bool {
        self.servers.iter().any(|s| s.udp.is_some())
    }

    fn done(self) -> Result<Vec<u8>, Error> {
        self.svc.map_or(Err(self.last), |bytes| {
            crate::capture_pdu("client-rep", &bytes);
            Ok(bytes)
        })
    }

    fn first_pass(&mut self, udp_first: bool) -> Option<Vec<u8>> {
        if udp_first {
            self.udp_all(true).or_else(|| self.tcp_all())
        } else {
            self.tcp_all().or_else(|| self.udp_all(true))
        }
    }

    fn udp_all(&mut self, initial: bool) -> Option<Vec<u8>> {
        for i in 0..self.servers.len() {
            if let Some(bytes) = self.udp_one(i, initial) {
                return Some(bytes);
            }
        }
        None
    }

    fn tcp_all(&mut self) -> Option<Vec<u8>> {
        for i in 0..self.servers.len() {
            if self.servers[i].dest.is_none() {
                self.last = Error::transport_msg("no KDC address");
                continue;
            }
            if let Some(bytes) = self.tcp_one(i) {
                return Some(bytes);
            }
        }
        None
    }

    /// MIT `maybe_send` (`lib/krb5/os/sendto_kdc.c:1015-1018`): later passes resend UDP only.
    /// MIT `resolve_server` (`lib/krb5/os/sendto_kdc.c:827-832`): an entry that names one transport uses that transport only.
    fn udp_one(&mut self, index: usize, initial: bool) -> Option<Vec<u8>> {
        if self.servers[index].transport == KdcTransport::Tcp {
            return None;
        }
        if self.servers[index].dest.is_none() {
            self.last = Error::transport_msg("no KDC address");
            return None;
        }
        if let Err(e) = open_udp(&mut self.servers[index]) {
            self.last = e;
            return None;
        }
        let dest = self.servers[index].dest?;
        let ra = RemoteAddr {
            transport: Transport::Udp,
            addr: dest,
        };
        let got = {
            let sock = self.servers[index].udp.as_ref()?;
            if initial {
                trace::sendto_kdc_udp_send_initial(&ra);
            } else {
                trace::sendto_kdc_udp_send_retry(&ra);
            }
            if let Err(e) = sock.send_to(self.request, dest) {
                if initial {
                    trace::sendto_kdc_udp_error_send_initial(&ra, errno(&e));
                } else {
                    trace::sendto_kdc_udp_error_send_retry(&ra, errno(&e));
                }
                Err(Error::from_io(e))
            } else {
                recv_udp(sock, dest, Duration::from_secs(1))
            }
        };
        match got {
            Ok(buf) => self.accept(index, buf),
            Err(e) => {
                self.last = e;
                None
            }
        }
    }

    fn tcp_one(&mut self, index: usize) -> Option<Vec<u8>> {
        if self.servers[index].transport == KdcTransport::Udp {
            return None;
        }
        let Some(dest) = self.servers[index].dest else {
            self.last = Error::transport_msg("no KDC address");
            return None;
        };
        match tcp_exchange(dest, self.request, Duration::from_secs(1), TIMEOUT) {
            Ok(bytes) => {
                crate::capture_pdu("client-rep", &bytes);
                Some(bytes)
            }
            Err(e) => {
                self.last = e;
                None
            }
        }
    }

    fn accept(&mut self, index: usize, bytes: Vec<u8>) -> Option<Vec<u8>> {
        if is_response_too_big(&bytes) {
            if let Some((realm, kind)) = self.traced {
                trace_retry_tcp(realm, self.request.len(), kind);
            }
            return self.tcp_one(index);
        }
        if is_svc_unavailable(&bytes) {
            self.svc = Some(bytes);
            self.last = Error::transport_msg("KDC_ERR_SVC_UNAVAILABLE");
            return None;
        }
        crate::capture_pdu("client-rep", &bytes);
        Some(bytes)
    }

    fn backoff(&mut self, budget: Duration) -> Option<Vec<u8>> {
        let got = wait_udp(&mut self.servers, budget);
        if let Some((index, bytes)) = got {
            return self.accept(index, bytes);
        }
        None
    }
}

/// MIT `k5_sendto` (`lib/krb5/os/sendto_kdc.c:1537-1600`): preferred transport, then the other,
/// one second each, two seconds at the end of that pass, then UDP again with delays of four and
/// eight seconds. `MAX_PASS` is 3.
/// MIT `resolve_server` (`lib/krb5/os/sendto_kdc.c:856-858`): a name that does not resolve adds
/// no connection.
/// MIT `translate_ai_error` (`lib/krb5/os/sendto_kdc.c:776-779`): that miss is not an error.
fn exchange_passes(
    addrs: &[(KdcAddr, KdcTransport)],
    request: &[u8],
    traced: Option<(&str, SendKind)>,
) -> Result<Vec<u8>, Error> {
    crate::capture_pdu("client-req", request);
    let mut walk = Passes::new(addrs, request, traced);
    let udp_first = request.len() <= krb5_config::udp_preference_limit();
    if let Some(reply) = walk.first_pass(udp_first) {
        return Ok(reply);
    }
    if !walk.any_udp() {
        return walk.done();
    }
    if let Some(reply) = walk.backoff(Duration::from_secs(2)) {
        return Ok(reply);
    }
    let mut delay = Duration::from_secs(4);
    for _pass in 1..3 {
        if let Some(reply) = walk.udp_all(false) {
            return Ok(reply);
        }
        if !walk.any_udp() {
            break;
        }
        if let Some(reply) = walk.backoff(delay) {
            return Ok(reply);
        }
        delay *= 2u32;
    }
    walk.done()
}

fn open_udp(server: &mut Located) -> Result<(), Error> {
    if server.udp.is_some() {
        return Ok(());
    }
    let bind = if server.addr.host == "127.0.0.1" || server.addr.host == "localhost" {
        "127.0.0.1:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind).map_err(|e| Error::transport_msg(format!("udp bind: {e}")))?;
    server.udp = Some(sock);
    Ok(())
}

fn recv_udp(sock: &UdpSocket, dest: SocketAddr, budget: Duration) -> Result<Vec<u8>, Error> {
    let deadline = Instant::now() + budget;
    sock.set_read_timeout(Some(budget))
        .map_err(Error::from_io)?;
    let ra = RemoteAddr {
        transport: Transport::Udp,
        addr: dest,
    };
    loop {
        let mut buf = vec![0u8; UDP_MAX];
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                if src.ip() == dest.ip() && src.port() == dest.port() {
                    buf.truncate(n);
                    trace::sendto_kdc_response(n, &ra);
                    return Ok(buf);
                }
                if Instant::now() >= deadline {
                    return Err(Error::transport_msg("udp timeout"));
                }
            }
            Err(e) => {
                if !is_timeout(&e) {
                    trace::sendto_kdc_udp_error_recv(&ra, errno(&e));
                }
                return Err(Error::from_io(e));
            }
        }
    }
}

enum Ready {
    Reply(Vec<u8>),
    Dead,
    Wait,
}

fn recv_ready(server: &Located, dest: SocketAddr, budget: Duration) -> Ready {
    let Some(sock) = server.udp.as_ref() else {
        return Ready::Wait;
    };
    if sock.set_read_timeout(Some(budget)).is_err() {
        return Ready::Dead;
    }
    let mut buf = vec![0u8; UDP_MAX];
    match sock.recv_from(&mut buf) {
        Ok((n, src)) if src.ip() == dest.ip() && src.port() == dest.port() => {
            buf.truncate(n);
            let ra = RemoteAddr {
                transport: Transport::Udp,
                addr: dest,
            };
            trace::sendto_kdc_response(n, &ra);
            Ready::Reply(buf)
        }
        Ok(_) => Ready::Wait,
        Err(e) if is_timeout(&e) => Ready::Wait,
        Err(e) => {
            let ra = RemoteAddr {
                transport: Transport::Udp,
                addr: dest,
            };
            trace::sendto_kdc_udp_error_recv(&ra, errno(&e));
            Ready::Dead
        }
    }
}

fn wait_udp(servers: &mut [Located], budget: Duration) -> Option<(usize, Vec<u8>)> {
    if servers.iter().all(|s| s.udp.is_none()) {
        return None;
    }
    let deadline = Instant::now() + budget;
    let slice = Duration::from_millis(50);
    while Instant::now() < deadline {
        if servers.iter().all(|s| s.udp.is_none()) {
            return None;
        }
        for (i, server) in servers.iter_mut().enumerate() {
            let Some(dest) = server.dest else {
                continue;
            };
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            let outcome = recv_ready(server, dest, slice.min(left));
            match outcome {
                Ready::Reply(buf) => return Some((i, buf)),
                Ready::Dead => server.udp = None,
                Ready::Wait => {}
            }
        }
    }
    None
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

fn is_svc_unavailable(bytes: &[u8]) -> bool {
    bytes.first() == Some(&0x7e)
        && decode::<KrbError>(bytes).is_ok_and(|e| e.error_code == err::SVC_UNAVAILABLE)
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
    tcp_exchange(sa, request, TIMEOUT, TIMEOUT)
}

fn tcp_exchange(
    sa: SocketAddr,
    request: &[u8],
    connect: Duration,
    io_timeout: Duration,
) -> Result<Vec<u8>, Error> {
    let ra = RemoteAddr {
        transport: Transport::Tcp,
        addr: sa,
    };
    trace::sendto_kdc_tcp_connect(&ra);
    let result = tcp_round_trip(sa, &ra, request, connect, io_timeout);
    if let Ok(reply) = &result {
        trace::sendto_kdc_response(reply.len(), &ra);
    }
    trace::sendto_kdc_tcp_disconnect(&ra);
    result
}

fn tcp_round_trip(
    sa: SocketAddr,
    ra: &RemoteAddr,
    request: &[u8],
    connect: Duration,
    io_timeout: Duration,
) -> Result<Vec<u8>, Error> {
    let mut stream = TcpStream::connect_timeout(&sa, connect).map_err(|e| {
        if !is_timeout(&e) {
            trace::sendto_kdc_tcp_error_connect(ra, errno(&e));
        }
        Error::transport_msg(format!("tcp connect {sa}: {e}"))
    })?;
    stream
        .set_nodelay(true)
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    stream
        .set_read_timeout(Some(io_timeout))
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    stream
        .set_write_timeout(Some(io_timeout))
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

#[cfg(test)]
mod kdc_list {
    use std::net::UdpSocket;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{KdcAddr, SendKind, sendto_kdc};

    struct ClearPaths;
    impl Drop for ClearPaths {
        fn drop(&mut self) {
            krb5_config::set_test_krb5_paths(None);
        }
    }

    fn pin(kdcs: &[&str]) -> ClearPaths {
        let dir = krb5_testkit::scratch_dir("kl-kdc-list");
        let path = dir.join("krb5.conf");
        let mut body = String::from(
            "[libdefaults]\n    dns_lookup_kdc = false\n[realms]\n    KERBER.TEST = {\n",
        );
        for kdc in kdcs {
            body.push_str("        kdc = ");
            body.push_str(kdc);
            body.push('\n');
        }
        body.push_str("    }\n");
        std::fs::write(&path, body).unwrap();
        krb5_config::set_test_krb5_paths(Some(vec![path]));
        ClearPaths
    }

    fn serve(stop_after: usize, reply_at: Option<usize>) -> (String, Arc<Mutex<Vec<Instant>>>) {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = sock.local_addr().unwrap().port();
        let hits = Arc::new(Mutex::new(Vec::new()));
        let hits2 = Arc::clone(&hits);
        thread::spawn(move || {
            let _ = sock.set_read_timeout(Some(Duration::from_secs(30)));
            let mut buf = [0u8; 1500];
            for n in 1..=stop_after {
                let Ok((_, src)) = sock.recv_from(&mut buf) else {
                    break;
                };
                hits2.lock().unwrap().push(Instant::now());
                if reply_at == Some(n) {
                    let _ = sock.send_to(b"kdc-reply", src);
                }
            }
        });
        (format!("127.0.0.1:{port}"), hits)
    }

    fn send(host: &str, port: u16) -> Result<Vec<u8>, super::Error> {
        sendto_kdc(
            &KdcAddr {
                host: host.to_owned(),
                port,
            },
            "KERBER.TEST",
            b"ping",
            SendKind::As,
        )
    }

    #[test]
    fn a_dead_first_profile_kdc_is_skipped_for_the_live_one() {
        let (dead, dead_hits) = serve(2, None);
        let (live, live_hits) = serve(1, Some(1));
        let _pin = pin(&[&dead, &live]);
        let port: u16 = dead.rsplit_once(':').unwrap().1.parse().unwrap();
        let started = Instant::now();
        let reply = send("127.0.0.1", port).unwrap();
        let elapsed = started.elapsed();
        assert_eq!(reply, b"kdc-reply");
        assert!(elapsed > Duration::from_millis(700), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(2500), "{elapsed:?}");
        let dead_at = dead_hits.lock().unwrap().clone();
        let live_at = live_hits.lock().unwrap().clone();
        assert_eq!(dead_at.len(), 1, "{dead_at:?}");
        assert_eq!(live_at.len(), 1, "{live_at:?}");
        let gap = live_at[0].saturating_duration_since(dead_at[0]);
        assert!(gap > Duration::from_millis(700), "{gap:?}");
        assert!(gap < Duration::from_millis(1800), "{gap:?}");
    }

    #[test]
    fn a_root_target_is_tried_and_the_next_kdc_answers() {
        let (live, hits) = serve(1, Some(1));
        let _pin = pin(&["..", &live]);
        let started = Instant::now();
        let reply = send("..", 88).unwrap();
        assert_eq!(reply, b"kdc-reply");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(hits.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_single_kdc_retransmits_after_half_a_second() {
        let (only, hits) = serve(2, Some(2));
        let _pin = pin(&[&only]);
        let port: u16 = only.rsplit_once(':').unwrap().1.parse().unwrap();
        let reply = send("127.0.0.1", port).unwrap();
        assert_eq!(reply, b"kdc-reply");
        let at = hits.lock().unwrap().clone();
        assert_eq!(at.len(), 2, "{at:?}");
        let gap = at[1].saturating_duration_since(at[0]);
        assert!(gap > Duration::from_millis(300), "{gap:?}");
        assert!(gap < Duration::from_millis(800), "{gap:?}");
    }

    #[test]
    fn an_explicit_kdc_is_not_replaced_by_the_profile_list() {
        let (dead, dead_hits) = serve(1, None);
        let (live, live_hits) = serve(1, Some(1));
        let (mock, mock_hits) = serve(1, Some(1));
        let _pin = pin(&[&dead, &live]);
        let port: u16 = mock.rsplit_once(':').unwrap().1.parse().unwrap();
        let reply = send("127.0.0.1", port).unwrap();
        assert_eq!(reply, b"kdc-reply");
        assert!(dead_hits.lock().unwrap().is_empty());
        assert!(live_hits.lock().unwrap().is_empty());
        assert_eq!(mock_hits.lock().unwrap().len(), 1);
    }

    #[test]
    fn every_profile_kdc_dead_is_an_unreachable_kdc() {
        let (first, first_hits) = serve(3, None);
        let (second, second_hits) = serve(3, None);
        let _pin = pin(&[&first, &second]);
        let port: u16 = first.rsplit_once(':').unwrap().1.parse().unwrap();
        let started = Instant::now();
        let err = send("127.0.0.1", port).unwrap_err();
        let elapsed = started.elapsed();
        assert!(err.is_retryable(), "{err}");
        assert!(elapsed > Duration::from_secs(16), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(30), "{elapsed:?}");
        let a = first_hits.lock().unwrap().clone();
        let b = second_hits.lock().unwrap().clone();
        assert_eq!(a.len(), 3, "{a:?}");
        assert_eq!(b.len(), 3, "{b:?}");
        let gap = b[0].saturating_duration_since(a[0]);
        assert!(
            gap > Duration::from_millis(700) && gap < Duration::from_millis(1800),
            "{gap:?}"
        );
    }

    /// An SRV `_udp` root and an SRV `_tcp` KDC: UDP is not sent to the TCP entry.
    #[test]
    fn a_tcp_srv_entry_is_not_sent_over_udp() {
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        let udp = UdpSocket::bind(("127.0.0.1", port)).unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts2 = Arc::clone(&accepts);
        thread::spawn(move || {
            if let Ok((stream, _)) = tcp.accept() {
                accepts2.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let udp_hits = Arc::new(AtomicUsize::new(0));
        let udp_hits2 = Arc::clone(&udp_hits);
        thread::spawn(move || {
            let _ = udp.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0u8; 64];
            if udp.recv_from(&mut buf).is_ok() {
                udp_hits2.fetch_add(1, Ordering::SeqCst);
            }
        });
        let servers = [
            (
                KdcAddr {
                    host: "..".to_owned(),
                    port: 88,
                },
                krb5_config::KdcTransport::Udp,
            ),
            (
                KdcAddr {
                    host: "127.0.0.1".to_owned(),
                    port,
                },
                krb5_config::KdcTransport::Tcp,
            ),
        ];
        let started = Instant::now();
        let result = super::exchange_passes(&servers, b"ping", Some(("KERBER.TEST", SendKind::As)));
        let elapsed = started.elapsed();
        assert!(result.is_err(), "{result:?}");
        assert!(elapsed < Duration::from_millis(1500), "{elapsed:?}");
        assert_eq!(udp_hits.load(Ordering::SeqCst), 0);
        assert_eq!(accepts.load(Ordering::SeqCst), 1);
    }
}
