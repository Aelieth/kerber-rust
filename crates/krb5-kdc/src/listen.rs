//! The KDC's listeners and the one loop that serves them.

use std::io::{self, IoSlice, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard};
use std::time::Duration;

use crate::Error;
#[cfg(feature = "daemon")]
use crate::daemon::Signals;
use crate::issue::KdcDispatch;
#[cfg(test)]
use crate::issue::ThreadSlots;
use crate::kdb::{KdcEnv, PrincipalRead, Store};
use crate::net_server::{Klog, Sockets, Wake};
use crate::store::{Policy, Principal};
use krb5_config::listen::{BindType, ListenAddr};
use krb5_log::klog::{self, Severity, os_error_text};
use nix::sys::socket::{
    AddressFamily, Backlog, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
    SockaddrStorage, bind, listen, recvmsg, sendmsg, setsockopt, socket, sockopt,
};

// MIT: `process_packet_response` (net-server.c:1101-1105)
pub const WHILE_DISPATCHING_UDP: &str = "while dispatching (udp)";
// MIT: `process_stream_response` (net-server.c:1314-1315)
pub const WHILE_DISPATCHING_TCP: &str = "while dispatching (tcp)";

pub type SharedStore = Arc<RwLock<dyn Store>>;

#[must_use]
pub fn shared_store<S: Store + 'static>(store: S) -> SharedStore {
    Arc::new(RwLock::new(store))
}

pub type SharedDump = Arc<RwLock<crate::store::PrincipalStore>>;

#[must_use]
pub fn shared_dump(store: crate::store::PrincipalStore) -> SharedDump {
    Arc::new(RwLock::new(store))
}

/// The shared lock is held only while the database is read.
// MIT: `krb5_db2_get_principal` (plugins/kdb/db2/kdb_db2.c:771-801)
pub(crate) fn read_store<R>(store: &SharedStore, f: impl FnOnce(&dyn PrincipalRead) -> R) -> R {
    {
        let g = store.read().unwrap_or_else(PoisonError::into_inner);
        let stale = match g.read_hold() {
            Ok(None) => false,
            Ok(Some((held, stale))) => {
                drop(held);
                stale
            }
            Err(e) => return f(&Unreadable::new(&*g, &e)),
        };
        if !stale {
            return f(&*g);
        }
    }
    let reread = store
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .reload_if_stale();
    let g = store.read().unwrap_or_else(PoisonError::into_inner);
    match reread {
        Ok(()) => f(&*g),
        Err(e) => f(&Unreadable::new(&*g, &e)),
    }
}

pub fn read_fresh(
    store: &SharedDump,
) -> (
    RwLockReadGuard<'_, crate::store::PrincipalStore>,
    Result<(), Error>,
) {
    {
        let g = store.read().unwrap_or_else(PoisonError::into_inner);
        let stale = match g.read_hold() {
            Ok(None) => false,
            Ok(Some((held, stale))) => {
                drop(held);
                stale
            }
            Err(e) => return (g, Err(e)),
        };
        if !stale {
            return (g, Ok(()));
        }
    }
    let reread = store
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .reload_if_stale();
    (store.read().unwrap_or_else(PoisonError::into_inner), reread)
}

pub(crate) fn plain_store<R>(store: &SharedStore, f: impl FnOnce(&dyn PrincipalRead) -> R) -> R {
    let g = store.read().unwrap_or_else(PoisonError::into_inner);
    f(&*g)
}

// MIT: `process_as_req` (kdc/do_as_req.c:577-580)
/// A lookup that cannot lock the database is `KDC_ERR_SVC_UNAVAILABLE`.
struct Unreadable<'a> {
    inner: &'a dyn PrincipalRead,
    error: Error,
}

impl<'a> Unreadable<'a> {
    fn new(inner: &'a dyn PrincipalRead, why: &Error) -> Self {
        tracing::error!(
            event = krb5_log::events::KDC_LISTEN,
            component = "krb5-kdc",
            outcome = "error",
            error = %why,
            detail = "read database",
        );
        let error = match why {
            Error::Db { text, .. } if *text == crate::DbLockError::CantLock.to_string() => {
                Error::Protocol {
                    code: krb5_types::err::SVC_UNAVAILABLE,
                    text: None,
                    e_data: None,
                    detail: None,
                }
            }
            other => other.clone(),
        };
        Self { inner, error }
    }
}

impl PrincipalRead for Unreadable<'_> {
    fn realm(&self) -> &str {
        self.inner.realm()
    }
    fn policy(&self) -> &Policy {
        self.inner.policy()
    }
    fn domain_sid(&self) -> &krb5_types::pac::RpcSid {
        self.inner.domain_sid()
    }
    fn env(&self) -> &KdcEnv {
        self.inner.env()
    }
    fn fetch(&self, _id: &str) -> Result<Option<Principal>, Error> {
        Err(self.error.clone())
    }
    fn list_ids(&self) -> Result<Vec<String>, Error> {
        Err(self.error.clone())
    }
    fn list_principals(&self) -> Result<Vec<Principal>, Error> {
        Err(self.error.clone())
    }
}

/// An all-interfaces bind is explicit.
pub const BIND_CANDIDATES: &[&str] = &["127.0.0.1:88", "127.0.0.1:8888"];

// MIT: `max_stream_data_connections` (net-server.c:85-85)
pub const MAX_TCP_WORKERS: usize = crate::net_server::MAX_STREAM_DATA_CONNECTIONS;
// MIT: `accept_stream_connection` (net-server.c:1278-1278)
pub const MAX_TCP_REQUEST: usize = crate::net_server::MAX_REQUEST;
pub const MAX_DGRAM_REPLY: usize = 65_536;

#[derive(Clone, Copy, Debug)]
pub struct ListenLimits {
    pub max_tcp_workers: usize,
    pub max_tcp_request: usize,
    // MIT: `finish_dispatch` (dispatch.c:54-63)
    pub max_dgram_reply_size: usize,
    pub shutdown_poll: Duration,
}

impl Default for ListenLimits {
    fn default() -> Self {
        Self {
            max_tcp_workers: MAX_TCP_WORKERS,
            max_tcp_request: MAX_TCP_REQUEST,
            max_dgram_reply_size: MAX_DGRAM_REPLY,
            shutdown_poll: Duration::from_millis(250),
        }
    }
}

// MIT: `DEFAULT_TCP_LISTEN_BACKLOG` (include/osconf.hin:100-100)
pub const DEFAULT_TCP_LISTEN_BACKLOG: i32 = 5;
/// The TCP backlog is 128; MIT's is 5.
const KDC_TCP_LISTEN_BACKLOG: i32 = 128;
// MIT: `svctcp_create` (lib/rpc/svc_tcp.c:178-178)
const RPC_LISTEN_BACKLOG: i32 = 2;
// MIT: `setnolinger` (lib/apputils/net-server.c:686-691)
const NO_LINGER: nix::libc::linger = nix::libc::linger {
    l_onoff: 0,
    l_linger: 0,
};

pub(crate) fn bind_udp_tcp(addr: SocketAddr) -> io::Result<(UdpSocket, TcpListener)> {
    let udp = UdpSocket::from(setup_socket(
        addr,
        BindType::Udp,
        DEFAULT_TCP_LISTEN_BACKLOG,
    )?);
    let tcp = TcpListener::from(setup_socket(
        addr,
        BindType::Tcp,
        DEFAULT_TCP_LISTEN_BACKLOG,
    )?);
    Ok((udp, tcp))
}

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
                tracing::debug!(
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

// MIT: `setup_addresses` (lib/apputils/net-server.c:1011-1036)
/// `EAFNOSUPPORT` is skipped when another address of the entry binds.
pub fn bind_udp_listeners(addrs: &[ListenAddr]) -> io::Result<Vec<UdpSocket>> {
    Ok(
        bind_listeners(addrs, BindType::Udp, DEFAULT_TCP_LISTEN_BACKLOG)?
            .into_iter()
            .map(UdpSocket::from)
            .collect(),
    )
}

pub fn bind_tcp_listeners(addrs: &[ListenAddr]) -> io::Result<Vec<TcpListener>> {
    bind_tcp_listeners_with_backlog(addrs, KDC_TCP_LISTEN_BACKLOG)
}

// MIT: `loop_setup_network` (lib/apputils/net-server.c:1053-1070)
pub fn bind_tcp_listeners_with_backlog(
    addrs: &[ListenAddr],
    backlog: i32,
) -> io::Result<Vec<TcpListener>> {
    Ok(bind_listeners(addrs, BindType::Tcp, backlog)?
        .into_iter()
        .map(TcpListener::from)
        .collect())
}

pub fn bind_rpc_listeners(addrs: &[ListenAddr]) -> io::Result<Vec<TcpListener>> {
    Ok(
        bind_listeners(addrs, BindType::Rpc, DEFAULT_TCP_LISTEN_BACKLOG)?
            .into_iter()
            .map(TcpListener::from)
            .collect(),
    )
}

fn proto(kind: BindType) -> &'static str {
    match kind {
        BindType::Udp => "udp",
        BindType::Tcp | BindType::Rpc => "tcp",
    }
}

// MIT: `setup_addresses` (lib/apputils/net-server.c:1029-1030)
fn is_unsupported_family(err: &io::Error) -> bool {
    err.raw_os_error() == Some(nix::errno::Errno::EAFNOSUPPORT as i32)
}

fn bind_listeners(addrs: &[ListenAddr], kind: BindType, backlog: i32) -> io::Result<Vec<OwnedFd>> {
    let proto = proto(kind);
    let named = |a: SocketAddr, e: io::Error| io::Error::new(e.kind(), format!("{proto} {a}: {e}"));
    let mut out = Vec::new();
    for entry in addrs {
        let resolved = entry.resolve().map_err(|e| {
            log_lines(&resolve_failure_lines(entry, &e.to_string()));
            io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
        })?;
        let mut bound_any = false;
        let mut skipped = None;
        for a in resolved {
            match setup_socket(a, kind, backlog) {
                Ok(fd) => {
                    tracing::debug!(
                        event = krb5_log::events::KDC_LISTEN,
                        correlation_id = krb5_log::current_correlation_id(),
                        component = "krb5-kdc",
                        outcome = "ok",
                        bind = %a,
                        proto,
                    );
                    out.push(fd);
                    bound_any = true;
                }
                Err(e) => {
                    klog::syslog(Severity::Err, &setup_failure_line(a, kind));
                    if !is_unsupported_family(&e) {
                        log_network_failure(&e);
                        return Err(named(a, e));
                    }
                    skipped = Some((a, e));
                }
            }
        }
        if !bound_any {
            return Err(match skipped {
                Some((a, e)) => {
                    log_network_failure(&e);
                    named(a, e)
                }
                None => io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("{proto} {entry}: no address"),
                ),
            });
        }
    }
    Ok(out)
}

// MIT: `setup_socket` (lib/apputils/net-server.c:813-859)
// MIT: `setup_socket` (lib/apputils/net-server.c:861-875)
// MIT: `svctcp_create` (lib/rpc/svc_tcp.c:178-178)
fn setup_socket(addr: SocketAddr, kind: BindType, backlog: i32) -> io::Result<OwnedFd> {
    klog::syslog(
        Severity::Debug,
        &format!("Setting up {} socket for address {addr}", kind.name()),
    );
    let fd = create_server_socket(addr, kind)?;
    match kind {
        BindType::Udp if addr.ip().is_unspecified() => {
            klog::syslog(
                Severity::Debug,
                &format!("Setting pktinfo on socket {addr}"),
            );
            if let Err(e) = set_pktinfo(&fd, addr) {
                com_err(
                    &e.into(),
                    &format!(
                        "Cannot request packet info for UDP socket address {addr} port {}",
                        addr.port()
                    ),
                );
                klog::syslog(
                    Severity::Info,
                    "System does not support pktinfo yet binding to a wildcard address.  \
                     Packets are not guaranteed to return on the received address.",
                );
            }
        }
        BindType::Udp => {}
        BindType::Tcp => {
            let backlog = Backlog::new(backlog).unwrap_or(if backlog < 0 {
                Backlog::MAXALLOWABLE
            } else {
                Backlog::MAXCONN
            });
            listen(&fd, backlog)
                .map_err(|e| failed(e, &format!("Cannot listen on TCP server socket on {addr}")))?;
            setsockopt(&fd, sockopt::Linger, &NO_LINGER)
                .map_err(|e| failed(e, &format!("cannot set SO_LINGER on TCP socket on {addr}")))?;
        }
        BindType::Rpc => {
            listen(&fd, Backlog::new(RPC_LISTEN_BACKLOG)?).map_err(|e| {
                let e = io::Error::from(e);
                klog::syslog(
                    Severity::Err,
                    &format!("Cannot create RPC service: {}", os_error_text(&e)),
                );
                e
            })?;
        }
    }
    Ok(fd)
}

// MIT: `create_server_socket` (lib/apputils/net-server.c:625-631)
// MIT: `create_server_socket` (lib/apputils/net-server.c:644-658)
// MIT: `create_server_socket` (lib/apputils/net-server.c:660-666)
fn create_server_socket(addr: SocketAddr, kind: BindType) -> io::Result<OwnedFd> {
    let family = if addr.is_ipv4() {
        AddressFamily::Inet
    } else {
        AddressFamily::Inet6
    };
    let ty = match kind {
        BindType::Udp => SockType::Datagram,
        BindType::Tcp | BindType::Rpc => SockType::Stream,
    };
    let fd = socket(family, ty, SockFlag::SOCK_CLOEXEC, None)
        .map_err(|e| failed(e, &format!("Cannot create TCP server socket on {addr}")))?;
    let n = fd.as_raw_fd();
    if let Err(e) = setsockopt(&fd, sockopt::ReuseAddr, &true) {
        com_err(&e.into(), &format!("Cannot enable SO_REUSEADDR on fd {n}"));
    }
    if addr.is_ipv6() {
        match setsockopt(&fd, sockopt::Ipv6V6Only, &true) {
            Ok(()) => klog::com_err(None, &format!("setsockopt({n},IPV6_V6ONLY,1) worked")),
            Err(e) => com_err(&e.into(), &format!("setsockopt({n},IPV6_V6ONLY,1) failed")),
        }
    }
    bind(n, &SockaddrStorage::from(addr))
        .map_err(|e| failed(e, &format!("Cannot bind server socket on {addr}")))?;
    Ok(fd)
}

// MIT: `set_pktinfo` (lib/apputils/udppktinfo.c:123-133)
fn set_pktinfo(fd: &OwnedFd, addr: SocketAddr) -> nix::Result<()> {
    if addr.is_ipv4() {
        setsockopt(fd, sockopt::Ipv4PacketInfo, &true)
    } else {
        setsockopt(fd, sockopt::Ipv6RecvPacketInfo, &true)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PktInfo {
    pub addr: IpAddr,
    pub ifindex: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Datagram {
    pub len: usize,
    pub from: SocketAddr,
    pub to: Option<PktInfo>,
}

// MIT: `recv_from_to` (lib/apputils/udppktinfo.c:283-325)
pub fn recv_from_to(sock: &UdpSocket, buf: &mut [u8]) -> io::Result<Datagram> {
    if !sock.local_addr()?.ip().is_unspecified() {
        let (len, from) = sock.recv_from(buf)?;
        return Ok(Datagram {
            len,
            from,
            to: None,
        });
    }
    let mut iov = [IoSliceMut::new(buf)];
    let mut cmsg = nix::cmsg_space!(nix::libc::in6_pktinfo);
    let msg = recvmsg::<SockaddrStorage>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg),
        MsgFlags::empty(),
    )?;
    let from =
        msg.address.as_ref().and_then(inet_addr).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "datagram from no IP address")
        })?;
    let to = msg
        .cmsgs()
        .ok()
        .into_iter()
        .flatten()
        .find_map(|c| match c {
            ControlMessageOwned::Ipv4PacketInfo(info) => Some(PktInfo {
                addr: Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes()).into(),
                ifindex: 0,
            }),
            ControlMessageOwned::Ipv6PacketInfo(info) => Some(PktInfo {
                addr: Ipv6Addr::from(info.ipi6_addr.s6_addr).into(),
                ifindex: info.ipi6_ifindex,
            }),
            _ => None,
        });
    Ok(Datagram {
        len: msg.bytes,
        from,
        to,
    })
}

fn inet_addr(a: &SockaddrStorage) -> Option<SocketAddr> {
    a.as_sockaddr_in()
        .map(|v4| SocketAddr::V4((*v4).into()))
        .or_else(|| a.as_sockaddr_in6().map(|v6| SocketAddr::V6((*v6).into())))
}

// MIT: `send_to_from` (lib/apputils/udppktinfo.c:443-474)
// MIT: `set_msg_from_ipv6_pktinfo` (lib/apputils/udppktinfo.c:383-394)
fn send_to_from(
    sock: &UdpSocket,
    buf: &[u8],
    to: SocketAddr,
    from: Option<PktInfo>,
) -> io::Result<usize> {
    let wildcard = sock.local_addr()?.ip().is_unspecified();
    let Some(from) = from.filter(|f| wildcard && f.addr.is_ipv4() == to.is_ipv4()) else {
        return sock.send_to(buf, to);
    };
    let iov = [IoSlice::new(buf)];
    let dest = SockaddrStorage::from(to);
    let fd = sock.as_raw_fd();
    let sent = match from.addr {
        IpAddr::V4(ip) => {
            let info = nix::libc::in_pktinfo {
                ipi_ifindex: 0,
                ipi_spec_dst: nix::libc::in_addr {
                    s_addr: u32::from_ne_bytes(ip.octets()),
                },
                ipi_addr: nix::libc::in_addr { s_addr: 0 },
            };
            let cmsg = [ControlMessage::Ipv4PacketInfo(&info)];
            sendmsg(fd, &iov, &cmsg, MsgFlags::empty(), Some(&dest))
        }
        IpAddr::V6(ip) => {
            let info = nix::libc::in6_pktinfo {
                ipi6_addr: nix::libc::in6_addr {
                    s6_addr: ip.octets(),
                },
                ipi6_ifindex: if ip.is_unicast_link_local() {
                    from.ifindex
                } else {
                    0
                },
            };
            let cmsg = [ControlMessage::Ipv6PacketInfo(&info)];
            sendmsg(fd, &iov, &cmsg, MsgFlags::empty(), Some(&dest))
        }
    };
    Ok(sent?)
}

// MIT: `process_packet_response` (lib/apputils/net-server.c:1107-1125)
pub fn send_udp_reply(sock: &UdpSocket, reply: &[u8], d: &Datagram) -> io::Result<()> {
    match send_to_from(sock, reply, d.from, d.to) {
        Ok(n) if n == reply.len() => Ok(()),
        Ok(n) => {
            klog::com_err(None, &format!("short reply write {} vs {n}\n", reply.len()));
            Ok(())
        }
        Err(e) => {
            let local =
                d.to.map(|p| p.addr)
                    .or_else(|| sock.local_addr().ok().map(|a| a.ip()))
                    .map_or_else(|| "<unknown>".to_owned(), |ip| ip.to_string());
            com_err(
                &e,
                &format!("while sending reply to {} from {local}", d.from),
            );
            Err(e)
        }
    }
}

fn com_err(e: &io::Error, what: &str) {
    klog::com_err(Some(&os_error_text(e)), what);
}

fn failed(e: nix::Error, what: &str) -> io::Error {
    let e = io::Error::from(e);
    com_err(&e, what);
    e
}

// MIT: `setup_addresses` (lib/apputils/net-server.c:1024-1030)
fn setup_failure_line(a: SocketAddr, kind: BindType) -> String {
    format!(
        "Failed setting up a {} socket (for {})",
        kind.name(),
        a.ip()
    )
}

// MIT: `loop_setup_network` (lib/apputils/net-server.c:1068-1073)
fn log_network_failure(e: &io::Error) {
    klog::syslog(
        Severity::Err,
        &format!("{} - Error setting up network", os_error_text(e)),
    );
}

fn log_lines(lines: &[String]) {
    for line in lines {
        klog::syslog(Severity::Err, line);
    }
}

// MIT: `setup_addresses` (lib/apputils/net-server.c:993-1000)
// MIT: `loop_setup_network` (lib/apputils/net-server.c:1068-1073)
fn resolve_failure_lines(entry: &ListenAddr, error: &str) -> [String; 2] {
    let host = entry.host.as_deref().unwrap_or("<wildcard>");
    let gai = error
        .rsplit_once("failed to lookup address information: ")
        .map_or(error, |(_, text)| text);
    let eio = io::Error::from_raw_os_error(nix::errno::Errno::EIO as i32);
    [
        format!("Failed getting address info (for {host}): {gai}"),
        format!("{} - Error setting up network", os_error_text(&eio)),
    ]
}

/// Only a test-hooks build drops root.
#[cfg(feature = "test-hooks")]
#[allow(clippy::disallowed_methods, reason = "a test-hooks build's override")]
pub fn drop_privileges() -> io::Result<bool> {
    drop_privileges_to(
        std::env::var("KRB5_KDC_USER")
            .ok()
            .filter(|s| !s.is_empty())
            .as_deref()
            .unwrap_or("nobody"),
    )
}

#[cfg(feature = "test-hooks")]
pub(crate) fn drop_privileges_to(username: &str) -> io::Result<bool> {
    if !nix::unistd::Uid::effective().is_root() {
        tracing::debug!(
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
    tracing::debug!(
        event = krb5_log::events::KDC_LISTEN,
        correlation_id = krb5_log::current_correlation_id(),
        component = "krb5-kdc",
        outcome = "ok",
        detail = "dropped privileges",
    );
    Ok(true)
}

#[cfg(feature = "daemon")]
fn install_shutdown_flag(flag: &Arc<AtomicBool>) {
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        let _ = signal_hook::flag::register(sig, Arc::clone(flag));
    }
}

#[derive(Clone, Default)]
pub struct KdcLog {
    sink: Option<Arc<dyn klog::LogSink>>,
}

impl KdcLog {
    #[must_use]
    pub fn process() -> Self {
        Self { sink: None }
    }

    #[must_use]
    pub fn with_sink(sink: Arc<dyn klog::LogSink>) -> Self {
        Self { sink: Some(sink) }
    }
}

#[cfg(feature = "daemon")]
pub fn serve(store: SharedStore, udp: UdpSocket, tcp: TcpListener, log: &KdcLog) -> io::Result<()> {
    serve_all(store, vec![udp], vec![tcp], log)
}

#[cfg(feature = "daemon")]
pub fn serve_all(
    store: SharedStore,
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpListener>,
    log: &KdcLog,
) -> io::Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    install_shutdown_flag(&shutdown);
    serve_all_until(store, udp, tcp, shutdown, ListenLimits::default(), log)
}

pub fn serve_until(
    store: SharedStore,
    udp: UdpSocket,
    tcp: TcpListener,
    shutdown: Arc<AtomicBool>,
    limits: ListenLimits,
    log: &KdcLog,
) -> io::Result<()> {
    serve_all_until(store, vec![udp], vec![tcp], shutdown, limits, log)
}

#[allow(clippy::needless_pass_by_value)] // the loop owns the store and the stop flag
pub fn serve_all_until(
    store: SharedStore,
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpListener>,
    shutdown: Arc<AtomicBool>,
    limits: ListenLimits,
    log: &KdcLog,
) -> io::Result<()> {
    if limits.shutdown_poll.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "shutdown_poll must be more than zero",
        ));
    }
    let wake = Wake::Flag {
        stop: &shutdown,
        every: limits.shutdown_poll,
    };
    serve_loop(store, &udp, &tcp, &wake, limits, log)
}

// MIT: `main` (kdc/main.c:1030-1030)
#[allow(clippy::needless_pass_by_value)] // the loop owns the store
#[cfg(feature = "daemon")]
pub fn serve_daemon(
    store: SharedStore,
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpListener>,
    signals: &Signals,
    limits: ListenLimits,
    log: &KdcLog,
) -> io::Result<()> {
    serve_loop(store, &udp, &tcp, &Wake::Signals(signals), limits, log)
}

fn otp_serve_start(store: &SharedStore) {
    let verifiers = read_store(store, |s| crate::plugins::otp_verifiers(s.policy()));
    let empty = verifiers.is_empty();
    if !empty {
        let rt = Arc::new(crate::plugins::OtpRuntime::new(verifiers));
        store
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .install_otp_runtime(rt);
    }
    read_store(store, |s| crate::preauth::serve_start_diagnostics(s, empty));
}

fn serve_loop(
    store: SharedStore,
    udp: &[UdpSocket],
    tcp: &[TcpListener],
    wake: &Wake<'_>,
    limits: ListenLimits,
    log: &KdcLog,
) -> io::Result<()> {
    let _sink = log.sink.clone().map(klog::push_thread_sink);
    #[cfg(test)]
    let _slots = ThreadSlots::take();
    otp_serve_start(&store);
    let teardown = Arc::clone(&store);
    let mut app = KdcDispatch::new(store, limits.max_dgram_reply_size);
    let sockets = Sockets {
        udp,
        tcp,
        ..Sockets::default()
    };
    let result = crate::net_server::run(
        &mut app,
        &sockets,
        limits.max_tcp_workers,
        limits.max_tcp_request,
        crate::net_server::ServeLimits::default(),
        wake,
        &mut Klog,
    )
    .map(drop);
    drop(
        teardown
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take_otp_runtime(),
    );
    result
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::TcpStream;
    use std::thread;

    use super::*;
    use crate::testrealm::bootstrap_documented;

    /// The documented realm saved to a scratch database, served from a [`SharedStore`].
    fn persisted(tag: &str) -> (SharedStore, std::path::PathBuf) {
        let dir = krb5_testkit::scratch_dir(&format!("krb5-listen-{tag}"));
        let (db, stash) = (dir.join("principal"), dir.join("stash"));
        let (store, _) = bootstrap_documented().unwrap();
        crate::save_store(&store, &db, &stash).unwrap();
        (shared_store(crate::load_store(&db, &stash).unwrap()), db)
    }

    /// Requests that keep overlapping never hold the lock across their own work, so another process's writer gets it within a bounded wait.
    #[test]
    fn a_writer_gets_the_lock_under_continuous_lookups() {
        let (store, db) = persisted("busy");
        let id = format!("krbtgt/{0}@{0}", crate::testrealm::TEST_REALM);
        let stop = Arc::new(AtomicBool::new(false));
        let readers: Vec<_> = (0..8)
            .map(|_| {
                let (store, id, stop) = (Arc::clone(&store), id.clone(), Arc::clone(&stop));
                thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        read_store(&store, |s| {
                            let _ = s.fetch(&id);
                            thread::sleep(Duration::from_millis(2));
                        });
                    }
                })
            })
            .collect();
        thread::sleep(Duration::from_millis(100));
        let writer = Arc::new(crate::DbLock::open(&db).unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let held = writer.hold(crate::DbLockMode::Exclusive);
            tx.send(held.is_ok()).unwrap();
        });
        let got = rx.recv_timeout(Duration::from_secs(5));
        stop.store(true, Ordering::Relaxed);
        for reader in readers {
            reader.join().unwrap();
        }
        assert_eq!(got, Ok(true));
    }

    /// A database changed into one that does not load answers every lookup with its error, never with the principals read before; put back, it serves again.
    #[test]
    fn a_database_that_does_not_read_again_answers_with_its_error() {
        let (store, db) = persisted("unreadable");
        let id = format!("krbtgt/{0}@{0}", crate::testrealm::TEST_REALM);
        assert!(read_store(&store, |s| s.fetch(&id)).unwrap().is_some());
        let lock = crate::DbLock::open(&db).unwrap();
        let away = db.with_extension("away");
        std::fs::rename(&db, &away).unwrap();
        std::fs::write(&db, "not a database\n").unwrap();
        lock.update_age();
        match read_store(&store, |s| s.fetch(&id)) {
            Err(Error::Db { text, .. }) => assert!(
                text.starts_with(&format!("Cannot open DB2 database '{}': ", db.display())),
                "{text}"
            ),
            other => panic!("{other:?}"),
        }
        std::fs::rename(&away, &db).unwrap();
        lock.update_age();
        assert!(read_store(&store, |s| s.fetch(&id)).unwrap().is_some());
    }

    use std::io::Read as _;
    use std::sync::atomic::Ordering;

    use krb5_asn1::{decode, encode};
    use krb5_types::{KrbError, PrincipalName, err};

    /// The documented realm served by `serve_until` on a thread of its own with `limits`: the address it serves, the stop flag, and the thread.
    fn serving(limits: ListenLimits) -> (SocketAddr, Arc<AtomicBool>, thread::JoinHandle<()>) {
        let (store, _) = bootstrap_documented().unwrap();
        let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
        let addr = udp.local_addr().unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&flag);
        let h = thread::spawn(move || {
            serve_until(
                shared_store(store),
                udp,
                tcp,
                stop,
                limits,
                &KdcLog::process(),
            )
            .unwrap();
        });
        (addr, flag, h)
    }

    fn limits() -> ListenLimits {
        ListenLimits {
            shutdown_poll: Duration::from_millis(50),
            ..ListenLimits::default()
        }
    }

    fn stop(flag: &AtomicBool, h: thread::JoinHandle<()>) {
        flag.store(true, Ordering::SeqCst);
        h.join().unwrap();
    }

    /// The length-prefixed reply on `c`, decoded as a KRB-ERROR.
    fn tcp_error(c: &mut TcpStream) -> KrbError {
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut hdr = [0u8; 4];
        c.read_exact(&mut hdr).expect("a reply's length");
        let mut body = vec![0u8; u32::from_be_bytes(hdr) as usize];
        c.read_exact(&mut body).expect("a reply");
        decode(&body).expect("KRB-ERROR")
    }

    /// An AS-REQ without preauth for the documented user.
    fn as_req_bytes(nonce: u32) -> Vec<u8> {
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::testrealm::TEST_USER]);
        encode(&krb5_protocol::as_req(cname, crate::testrealm::TEST_REALM, nonce, None).unwrap())
            .unwrap()
    }

    /// A length past the cap is answered with FIELD_TOOLONG before any body, and so is a length one past MIT's 1 MiB buffer.
    #[test]
    fn tcp_oversize_length_is_field_toolong() {
        for (cap, n) in [(32, 64u32), (MAX_TCP_REQUEST, 1024 * 1024 + 1)] {
            let (addr, flag, h) = serving(ListenLimits {
                max_tcp_request: cap,
                ..limits()
            });
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(&n.to_be_bytes()).unwrap();
            assert_eq!(tcp_error(&mut c).error_code, err::FIELD_TOOLONG);
            stop(&flag, h);
        }
    }

    #[test]
    fn udp_oversize_reply_is_response_too_big() {
        let (addr, flag, h) = serving(ListenLimits {
            max_dgram_reply_size: 10,
            ..limits()
        });
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        sock.send_to(&as_req_bytes(1), addr).unwrap();
        let mut buf = [0u8; 4096];
        let n = sock.recv(&mut buf).unwrap();
        let e: KrbError = decode(&buf[..n]).unwrap();
        assert_eq!(e.error_code, err::RESPONSE_TOO_BIG);
        stop(&flag, h);
    }

    /// Past the cap a new connection evicts the one that started first, and among connections of the same second the one met first from the top of the table: c1 started a second before c2 and c3, so c3 evicts c1 and takes its place at the table's start; c4 then meets c2 first from the top, and evicts it.
    // MIT: `kill_lru_stream_connection` (lib/apputils/net-server.c:1198-1223)
    /// the scan from the top keeps the first of a tie.
    #[test]
    fn tcp_over_cap_evicts_the_connection_that_started_first() {
        let (addr, flag, h) = serving(ListenLimits {
            max_tcp_workers: 2,
            ..limits()
        });
        let closed = |c: &TcpStream| {
            c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut b = [0u8; 1];
            matches!((&*c).read(&mut b), Ok(0))
        };
        let open = |c: &TcpStream| {
            c.set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let mut b = [0u8; 1];
            matches!((&*c).read(&mut b), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
        };
        let next_second = || {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap();
            thread::sleep(
                Duration::from_millis(1050)
                    .saturating_sub(Duration::from_nanos(now.subsec_nanos().into())),
            );
        };
        next_second();
        let c1 = TcpStream::connect(addr).unwrap();
        thread::sleep(Duration::from_millis(50));
        next_second();
        let c2 = TcpStream::connect(addr).unwrap();
        thread::sleep(Duration::from_millis(50));
        let c3 = TcpStream::connect(addr).unwrap();
        assert!(closed(&c1), "c1 started first");
        assert!(open(&c2) && open(&c3));
        let c4 = TcpStream::connect(addr).unwrap();
        assert!(closed(&c2), "c2: the first of the tie from the top");
        assert!(open(&c3) && open(&c4));
        stop(&flag, h);
    }
}
