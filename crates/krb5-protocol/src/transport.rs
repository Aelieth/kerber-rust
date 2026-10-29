use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use krb5_asn1::decode;
use krb5_types::{KrbError, err};

use krb5_config::{KdcTransport, Krb5Conf};

use crate::error::Error;
use crate::trace::{self, RemoteAddr, Transport};

pub const KDC_PORT: u16 = 88;

const TIMEOUT: Duration = Duration::from_secs(5);

// MIT: `k5_sendto` (lib/krb5/os/sendto_kdc.c:1520-1524)
fn request_deadline(profile: &Krb5Conf) -> Option<Instant> {
    profile.request_timeout.map(|limit| Instant::now() + limit)
}

// MIT: `k5_init_creds_get` (lib/krb5/krb/get_in_tkt.c:570-578)
// MIT: `krb5_tkt_creds_get` (lib/krb5/krb/get_creds.c:1220-1228)
fn fresh_deadline(limit: Option<Duration>) -> Option<Instant> {
    limit.map(|span| Instant::now() + span)
}

fn cap_budget(budget: Duration, deadline: Option<Instant>) -> Option<Duration> {
    let Some(end) = deadline else {
        return Some(budget);
    };
    let left = end.saturating_duration_since(Instant::now());
    if left.is_zero() {
        None
    } else {
        Some(budget.min(left))
    }
}

fn request_timeout_error() -> Error {
    Error::from_io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "Cannot contact any KDC for requested realm",
    ))
}
/// A stream that arms its socket timeout from `end` before every read and write.
// MIT: `service_fds` (lib/krb5/os/sendto_kdc.c:1421-1437)
pub(crate) struct DeadlineIo<'a> {
    stream: &'a mut TcpStream,
    end: Option<Instant>,
}

impl<'a> DeadlineIo<'a> {
    pub(crate) fn new(stream: &'a mut TcpStream, end: Option<Instant>) -> Self {
        Self { stream, end }
    }

    fn arm(&self, write: bool) -> io::Result<()> {
        let Some(end) = self.end else {
            return Ok(());
        };
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if write {
            self.stream.set_write_timeout(Some(left))
        } else {
            self.stream.set_read_timeout(Some(left))
        }
    }
}

impl Read for DeadlineIo<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.arm(false)?;
        self.stream.read(buf)
    }
}

impl Write for DeadlineIo<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.arm(true)?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

const UDP_MAX: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdcAddr {
    pub host: String,
    pub port: u16,
}

impl KdcAddr {
    #[must_use]
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: KDC_PORT,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SendKind {
    As,
    Tgs,
}

/// UDP first, then TCP when the reply is too big or UDP fails.
pub fn exchange(profile: &Krb5Conf, addr: &KdcAddr, request: &[u8]) -> Result<Vec<u8>, Error> {
    exchange_with_failover(profile, std::slice::from_ref(addr), request)
}

// MIT: `k5_sendto_kdc` (lib/krb5/os/sendto_kdc.c:446-560)
// MIT: `k5_sendto` (lib/krb5/os/sendto_kdc.c:1537-1600)
/// Several KDCs: UDP/TCP 1 s each, then 2 s, then UDP widening.
pub(crate) fn sendto_kdc(
    profile: &Krb5Conf,
    addr: &KdcAddr,
    realm: &str,
    request: &[u8],
    kind: SendKind,
) -> Result<Vec<u8>, Error> {
    trace::sendto_kdc(request.len(), realm.as_bytes(), false, false);
    let deadline = request_deadline(profile);
    // MIT: `k5_locate_server` (lib/krb5/os/locate_kdc.c:853-878)
    let found = match krb5_config::take_handed_kdcs(realm, &addr.host, addr.port) {
        Some(list) => list,
        None => match profile.kdcs_for_traced(realm, &mut crate::trace::dns_srv) {
            Ok(list) => list,
            Err(krb5_config::Error::InvalidArgument) => return Err(Error::InvalidArgument),
            Err(_) => Vec::new(),
        },
    };
    let walk = found.len() > 1
        && found
            .first()
            .is_some_and(|ep| ep.host == addr.host && ep.port == addr.port);
    if !walk {
        return exchange_one(
            addr,
            request,
            profile.udp_limit(),
            Some((realm, kind)),
            deadline,
            profile.request_timeout,
        );
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
    exchange_passes(
        &addrs,
        request,
        profile.udp_limit(),
        Some((realm, kind)),
        deadline,
        profile.request_timeout,
    )
}

struct Located {
    transport: KdcTransport,
    dest: Option<SocketAddr>,
    udp: Option<UdpSocket>,
}

impl Located {
    fn prepare(addr: &KdcAddr, transport: KdcTransport) -> Self {
        Self {
            transport,
            dest: dest_addr(addr).ok(),
            udp: None,
        }
    }
}

struct Passes<'a> {
    request: &'a [u8],
    traced: Option<(&'a str, SendKind)>,
    servers: Vec<Located>,
    last: Error,
    svc: Option<Vec<u8>>,
    deadline: Option<Instant>,
    limit: Option<Duration>,
}

impl<'a> Passes<'a> {
    fn new(
        addrs: &'a [(KdcAddr, KdcTransport)],
        request: &'a [u8],
        traced: Option<(&'a str, SendKind)>,
        deadline: Option<Instant>,
        limit: Option<Duration>,
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
            deadline,
            limit,
        }
    }

    fn past_deadline(&mut self) -> bool {
        if self.deadline.is_some_and(|end| Instant::now() >= end) {
            self.last = request_timeout_error();
            true
        } else {
            false
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

    // MIT: `maybe_send` (lib/krb5/os/sendto_kdc.c:1015-1018)
    // MIT: `resolve_server` (lib/krb5/os/sendto_kdc.c:827-832)
    fn udp_one(&mut self, index: usize, initial: bool) -> Option<Vec<u8>> {
        if self.servers[index].transport == KdcTransport::Tcp {
            return None;
        }
        if self.past_deadline() {
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
                match cap_budget(Duration::from_secs(1), self.deadline) {
                    Some(budget) => recv_udp(sock, dest, budget),
                    None => Err(request_timeout_error()),
                }
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
        if self.past_deadline() {
            return None;
        }
        let Some(dest) = self.servers[index].dest else {
            self.last = Error::transport_msg("no KDC address");
            return None;
        };
        let Some(connect) = cap_budget(Duration::from_secs(1), self.deadline) else {
            self.last = request_timeout_error();
            return None;
        };
        let Some(io_timeout) = cap_budget(TIMEOUT, self.deadline) else {
            self.last = request_timeout_error();
            return None;
        };
        match tcp_exchange(dest, self.request, connect, io_timeout, self.deadline) {
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
            let kept = self.deadline;
            self.deadline = fresh_deadline(self.limit);
            let reply = self.tcp_one(index);
            self.deadline = kept;
            return reply;
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
        let Some(budget) = cap_budget(budget, self.deadline) else {
            self.last = request_timeout_error();
            return None;
        };
        let got = wait_udp(&mut self.servers, budget);
        if let Some((index, bytes)) = got {
            return self.accept(index, bytes);
        }
        None
    }
}

// MIT: `resolve_server` (lib/krb5/os/sendto_kdc.c:856-858)
// MIT: `translate_ai_error` (lib/krb5/os/sendto_kdc.c:776-779)
fn exchange_passes(
    addrs: &[(KdcAddr, KdcTransport)],
    request: &[u8],
    udp_limit: usize,
    traced: Option<(&str, SendKind)>,
    deadline: Option<Instant>,
    limit: Option<Duration>,
) -> Result<Vec<u8>, Error> {
    crate::capture_pdu("client-req", request);
    let mut walk = Passes::new(addrs, request, traced, deadline, limit);
    let udp_first = request.len() <= udp_limit;
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

// MIT: `start_connection` (lib/krb5/os/sendto_kdc.c:884-990)
fn udp_socket_for(dest: &SocketAddr) -> std::io::Result<UdpSocket> {
    let ip = match (dest.ip().is_loopback(), dest.is_ipv4()) {
        (true, true) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        (true, false) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        (false, true) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        (false, false) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    UdpSocket::bind(SocketAddr::new(ip, 0))
}

fn open_udp(server: &mut Located) -> Result<(), Error> {
    if server.udp.is_some() {
        return Ok(());
    }
    let dest = server
        .dest
        .ok_or_else(|| Error::transport_msg("no KDC address"))?;
    let sock = udp_socket_for(&dest).map_err(|e| Error::transport_msg(format!("udp bind: {e}")))?;
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

pub fn exchange_on_tcp(addr: &KdcAddr, request: &[u8]) -> Result<Vec<u8>, Error> {
    crate::capture_pdu("client-req", request);
    let sa = dest_addr(addr)?;
    exchange_tcp(sa, request)
}

pub fn exchange_with_failover(
    profile: &Krb5Conf,
    addrs: &[KdcAddr],
    request: &[u8],
) -> Result<Vec<u8>, Error> {
    let deadline = request_deadline(profile);
    let mut last = Error::transport_msg("no KDC addresses");
    for addr in addrs {
        if deadline.is_some_and(|end| Instant::now() >= end) {
            break;
        }
        match exchange_one(
            addr,
            request,
            profile.udp_limit(),
            None,
            deadline,
            profile.request_timeout,
        ) {
            Ok(r) => return Ok(r),
            Err(e) if e.is_retryable() => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

// MIT: `k5_init_creds_get` (lib/krb5/krb/get_in_tkt.c:570-578)
// MIT: `krb5_tkt_creds_get` (lib/krb5/krb/get_creds.c:1220-1228)
/// A UDP timeout returns the TCP error, so a reply that never fit is not
/// hidden.
fn exchange_one(
    addr: &KdcAddr,
    request: &[u8],
    udp_limit: usize,
    traced: Option<(&str, SendKind)>,
    deadline: Option<Instant>,
    limit: Option<Duration>,
) -> Result<Vec<u8>, Error> {
    crate::capture_pdu("client-req", request);
    let dest = dest_addr(addr)?;
    if request.len() > udp_limit {
        let reply = exchange_tcp_capped(dest, request, deadline);
        if let Ok(bytes) = &reply {
            crate::capture_pdu("client-rep", bytes);
        }
        return reply;
    }
    let reply = match exchange_udp(dest, request, deadline) {
        Ok(reply) if is_response_too_big(&reply) => {
            tracing::debug!(
                event = krb5_log::events::PROTOCOL_TRANSPORT,
                correlation_id = krb5_log::current_correlation_id(),
                component = "krb5-protocol",
                outcome = "ok",
                error = "KRB_ERR_RESPONSE_TOO_BIG, falling back to TCP",
            );
            if let Some((realm, kind)) = traced {
                trace_retry_tcp(realm, request.len(), kind);
            }
            exchange_tcp_capped(dest_addr(addr)?, request, fresh_deadline(limit))
        }
        Ok(reply) => Ok(reply),
        Err(udp_err) if deadline.is_some_and(|end| Instant::now() >= end) => Err(udp_err),
        Err(udp_err) => match exchange_tcp_capped(dest, request, deadline) {
            Ok(reply) => Ok(reply),
            Err(tcp_err) => {
                tracing::error!(
                    event = krb5_log::events::PROTOCOL_TRANSPORT,
                    correlation_id = krb5_log::current_correlation_id(),
                    component = "krb5-protocol",
                    outcome = "error",
                    error = %tcp_err,
                );
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

// MIT: `init_creds_validate_reply` (lib/krb5/krb/get_in_tkt.c:1081-1115)
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

pub(crate) fn errno(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(0)
}

// MIT: `service_udp_read` (sendto_kdc.c:1209-1216)
fn exchange_udp(
    dest: SocketAddr,
    request: &[u8],
    deadline: Option<Instant>,
) -> Result<Vec<u8>, Error> {
    let ra = RemoteAddr {
        transport: Transport::Udp,
        addr: dest,
    };
    let sock = udp_socket_for(&dest).map_err(|e| Error::transport_msg(format!("udp bind: {e}")))?;
    let Some(write_timeout) = cap_budget(TIMEOUT, deadline) else {
        return Err(request_timeout_error());
    };
    sock.set_write_timeout(Some(write_timeout))
        .map_err(|e| Error::transport_msg(e.to_string()))?;
    let backoffs = [
        Duration::from_millis(500),
        Duration::from_secs(1),
        Duration::from_secs(2),
    ];
    let mut last = Error::transport_msg("udp timeout");
    for (attempt, bo) in backoffs.into_iter().enumerate() {
        let Some(bo) = cap_budget(bo, deadline) else {
            return Err(if attempt == 0 {
                request_timeout_error()
            } else {
                last
            });
        };
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
                        tracing::debug!(
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

// MIT: `service_tcp_connect` (lib/krb5/os/sendto_kdc.c:1098-1112)
// MIT: `service_tcp_write` (lib/krb5/os/sendto_kdc.c:1115-1146)
// MIT: `service_tcp_read` (lib/krb5/os/sendto_kdc.c:1149-1200)
fn exchange_tcp(sa: SocketAddr, request: &[u8]) -> Result<Vec<u8>, Error> {
    tcp_exchange(sa, request, TIMEOUT, TIMEOUT, None)
}

fn exchange_tcp_capped(
    sa: SocketAddr,
    request: &[u8],
    deadline: Option<Instant>,
) -> Result<Vec<u8>, Error> {
    let connect = cap_budget(TIMEOUT, deadline).ok_or_else(request_timeout_error)?;
    let io_timeout = cap_budget(TIMEOUT, deadline).ok_or_else(request_timeout_error)?;
    tcp_exchange(sa, request, connect, io_timeout, deadline)
}

fn tcp_exchange(
    sa: SocketAddr,
    request: &[u8],
    connect: Duration,
    io_timeout: Duration,
    deadline: Option<Instant>,
) -> Result<Vec<u8>, Error> {
    let ra = RemoteAddr {
        transport: Transport::Tcp,
        addr: sa,
    };
    trace::sendto_kdc_tcp_connect(&ra);
    let result = tcp_round_trip(sa, &ra, request, connect, io_timeout, deadline);
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
    deadline: Option<Instant>,
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
    let end = Instant::now() + io_timeout;
    let mut stream = DeadlineIo::new(&mut stream, Some(deadline.map_or(end, |d| end.min(d))));
    // MIT: `service_tcp_write` (lib/krb5/os/sendto_kdc.c:1124-1125)
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

pub(crate) fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// An early close is `ECONNRESET`, as MIT counts a read of nothing.
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

    use krb5_config::Krb5Conf;

    use super::{KdcAddr, SendKind, sendto_kdc};

    fn pin(kdcs: &[&str]) -> Krb5Conf {
        let mut body = String::from(
            "[libdefaults]\n    dns_lookup_kdc = false\n[realms]\n    KERBER.TEST = {\n",
        );
        for kdc in kdcs {
            body.push_str("        kdc = ");
            body.push_str(kdc);
            body.push('\n');
        }
        body.push_str("    }\n");
        Krb5Conf::parse(&body).unwrap()
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

    fn send(profile: &Krb5Conf, host: &str, port: u16) -> Result<Vec<u8>, super::Error> {
        sendto_kdc(
            profile,
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
        let profile = pin(&[&dead, &live]);
        let port: u16 = dead.rsplit_once(':').unwrap().1.parse().unwrap();
        let started = Instant::now();
        let reply = send(&profile, "127.0.0.1", port).unwrap();
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
        let profile = pin(&["..", &live]);
        let started = Instant::now();
        let reply = send(&profile, "..", 88).unwrap();
        assert_eq!(reply, b"kdc-reply");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(hits.lock().unwrap().len(), 1);
    }

    #[test]
    fn every_profile_kdc_dead_is_an_unreachable_kdc() {
        let (first, first_hits) = serve(3, None);
        let (second, second_hits) = serve(3, None);
        let profile = pin(&[&first, &second]);
        let port: u16 = first.rsplit_once(':').unwrap().1.parse().unwrap();
        let started = Instant::now();
        let err = send(&profile, "127.0.0.1", port).unwrap_err();
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

    #[test]
    fn a_tcp_srv_entry_is_not_sent_over_udp() {
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // The port may be taken in UDP only: take UDP's, then try TCP on it.
        let (tcp, udp) = (0..50)
            .find_map(|_| {
                let udp = UdpSocket::bind("127.0.0.1:0").ok()?;
                let port = udp.local_addr().ok()?.port();
                Some((TcpListener::bind(("127.0.0.1", port)).ok()?, udp))
            })
            .expect("a loopback port free in both TCP and UDP");
        let port = udp.local_addr().unwrap().port();
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
        let result = super::exchange_passes(
            &servers,
            b"ping",
            1465,
            Some(("KERBER.TEST", SendKind::As)),
            None,
            None,
        );
        let elapsed = started.elapsed();
        assert!(result.is_err(), "{result:?}");
        assert!(elapsed < Duration::from_millis(1500), "{elapsed:?}");
        assert_eq!(udp_hits.load(Ordering::SeqCst), 0);
        assert_eq!(accepts.load(Ordering::SeqCst), 1);
    }
}
