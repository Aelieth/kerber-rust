//! The KDC's listeners: MIT's net-server sockets ([`bind_udp_listeners`], [`bind_tcp_listeners`])
//! and the serve functions that run [`crate::net_server`]'s one loop over them on the calling
//! thread, with [`crate::issue::KdcDispatch`] answering each request.

use std::io::{self, IoSlice, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use crate::Error;
use crate::daemon::Signals;
use crate::issue::{KdcDispatch, ThreadSlots};
use crate::kdb::{KdcEnv, PrincipalRead, Store};
use crate::net_server::{Klog, Sockets, Wake};
use crate::store::{Policy, Principal};
use krb5_config::listen::ListenAddr;
use krb5_log::klog::{self, Severity, os_error_text};
use nix::sys::socket::{
    AddressFamily, Backlog, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
    SockaddrStorage, bind, listen, recvmsg, sendmsg, setsockopt, socket, sockopt,
};

/// MIT `process_packet_response` (`net-server.c:1101-1105`): a dispatch error is logged
/// with this text and no reply is sent.
pub const WHILE_DISPATCHING_UDP: &str = "while dispatching (udp)";
/// MIT `process_stream_response` (`net-server.c:1314-1315`): a dispatch error is logged
/// with this text.
pub const WHILE_DISPATCHING_TCP: &str = "while dispatching (tcp)";

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

/// Answer one request from the store, after reading the database again when another process
/// changed it. The database's lock is held shared only while its age and file are compared and
/// the database is read again, and let go before the request is answered from the store: a
/// write holder makes the request wait, a read holder does not, and a writer waiting for the
/// lock gets it between lookups however many requests run. A lock that may not be taken answers
/// every lookup with `SVC_UNAVAILABLE`, and a database that cannot be read again answers with
/// its error, never with what the store read before.
/// MIT `krb5_db2_get_principal` (`plugins/kdb/db2/kdb_db2.c:771-801`): a lookup takes the shared lock, reads, and lets it go.
pub(crate) fn read_store<R>(store: &SharedStore, f: impl FnOnce(&dyn PrincipalRead) -> R) -> R {
    {
        let g = store.read().unwrap_or_else(PoisonError::into_inner);
        let stale = match g.read_hold() {
            Ok(None) => false,
            Ok(Some((held, stale))) => {
                drop(held);
                stale
            }
            Err(e) => return f(&Unreadable::new(&**g, &e)),
        };
        if !stale {
            return f(&**g);
        }
    }
    {
        let mut w = store.write().unwrap_or_else(PoisonError::into_inner);
        if let Err(e) = w.reload_if_stale() {
            return f(&Unreadable::new(&**w, &e));
        }
    }
    let g = store.read().unwrap_or_else(PoisonError::into_inner);
    f(&**g)
}

/// The store, without its database lock, for a reply that needs no lookup (an error built from
/// the realm alone).
pub(crate) fn plain_store<R>(store: &SharedStore, f: impl FnOnce(&dyn PrincipalRead) -> R) -> R {
    let g = store.read().unwrap_or_else(PoisonError::into_inner);
    f(&**g)
}

/// A store whose database may not be locked or read again: every lookup fails as MIT's do when
/// the database does not lock or reopen, `SVC_UNAVAILABLE` for `KRB5_KDB_CANTLOCK_DB` and the
/// database's own error otherwise.
/// MIT `process_as_req` (`kdc/do_as_req.c:577-580`): a lookup that cannot lock the database is `KDC_ERR_SVC_UNAVAILABLE`.
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

/// Addresses tried when the caller does not pin a bind address.
/// Never includes `0.0.0.0` — the daemon must be given an explicit bind
/// to listen on all interfaces.
pub const BIND_CANDIDATES: &[&str] = &["127.0.0.1:88", "127.0.0.1:8888"];

/// The most stream connections a loop keeps: at the cap a new connection evicts the one that
/// started first rather than being refused.
/// MIT `max_stream_data_connections` (`net-server.c:85-85`): the cap is 45 stream connections.
pub const MAX_TCP_WORKERS: usize = crate::net_server::MAX_STREAM_DATA_CONNECTIONS;
/// The longest TCP request: FIELD_TOOLONG at `msglen > bufsiz-4`.
/// MIT `accept_stream_connection` (`net-server.c:1278-1278`): `bufsiz` is 1 MiB.
pub const MAX_TCP_REQUEST: usize = crate::net_server::MAX_REQUEST;
/// MIT `MAX_DGRAM_SIZE` / `kdc_max_dgram_reply_size` default (`osconf.hin`).
pub const MAX_DGRAM_REPLY: usize = 65_536;

/// The limits of one serving loop.
#[derive(Clone, Copy, Debug)]
pub struct ListenLimits {
    /// The most stream connections at once, past which the one that started first is evicted.
    pub max_tcp_workers: usize,
    /// Maximum TCP length-prefix body.
    pub max_tcp_request: usize,
    /// UDP reply cap; over is KRB-ERROR 52.
    /// MIT `finish_dispatch` (`dispatch.c:54-63`): a UDP reply over `max_dgram_reply_size`
    /// is replaced by the response-too-big error.
    pub max_dgram_reply_size: usize,
    /// The longest wait between two looks at a caller's stop flag ([`serve_all_until`]); the
    /// daemon's signals wake the loop at once ([`serve_daemon`]). A stream has no timeout.
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

/// MIT `DEFAULT_TCP_LISTEN_BACKLOG` (`include/osconf.hin:100-100`): MIT's TCP listen backlog is 5.
/// TCP listeners that still use 5: `bind_udp_tcp` (the test-hooks pinned KDC, `--test-realm` /
/// `KRB5_KDC_BIND`) and kadmind's kpasswd listeners (`bind_tcp_listeners_with_backlog`). UDP setup
/// ignores this value. `bind_rpc_listeners` passes it, then an RPC socket listens at 2.
pub const DEFAULT_TCP_LISTEN_BACKLOG: i32 = 5;
/// The embedder's TCP `listen` backlog ([`bind_tcp_listeners`]). MIT's is 5; 128 is the deviation
/// in `docs/mit-deviations.md`, the same default an unset `kdc_tcp_listen_backlog` takes.
const KDC_TCP_LISTEN_BACKLOG: i32 = 128;
/// MIT `svctcp_create` (`lib/rpc/svc_tcp.c:178-178`): an RPC listener's backlog is 2.
const RPC_LISTEN_BACKLOG: i32 = 2;
/// MIT `setnolinger` (`lib/apputils/net-server.c:686-691`): a TCP listener does not linger.
const NO_LINGER: nix::libc::linger = nix::libc::linger {
    l_onoff: 0,
    l_linger: 0,
};

/// Bind UDP and TCP on the same `addr`, each socket made as a configured listener's is
/// ([`bind_udp_listeners`]).
///
/// # Errors
///
/// The `io::Error` from setting up the UDP socket on `addr`, or from setting up the TCP listener
/// when the UDP socket was set up.
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

/// Try each candidate until UDP and TCP both bind.
///
/// # Errors
///
/// The last candidate's error when none binds: `io::ErrorKind::InvalidInput` for a candidate that
/// is not a socket address, else that candidate's bind error; `io::ErrorKind::AddrNotAvailable`
/// when `candidates` is empty.
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

/// Bind a UDP socket on every listener in `addrs` (the `kdc_listen` list): one socket for each
/// address an entry resolves to, so the wildcard is two sockets, `0.0.0.0` and an IPv6-only
/// `[::]`, whatever the host's default for IPv6 sockets (`net.ipv6.bindv6only`).
///
/// MIT `setup_addresses` (`lib/apputils/net-server.c:1011-1036`): every address of an entry is
/// set up; an address family the host lacks (`EAFNOSUPPORT`) is skipped when another address of
/// the entry binds, and any other failure stops the daemon.
///
/// # Errors
///
/// `io::ErrorKind::InvalidInput` when an entry does not resolve, and the setup error, named with
/// its address, for an address that does not bind.
pub fn bind_udp_listeners(addrs: &[ListenAddr]) -> io::Result<Vec<UdpSocket>> {
    Ok(
        bind_listeners(addrs, BindType::Udp, DEFAULT_TCP_LISTEN_BACKLOG)?
            .into_iter()
            .map(UdpSocket::from)
            .collect(),
    )
}

/// [`bind_udp_listeners`] for a TCP list (`kdc_tcp_listen`), each listening with the KDC's
/// default backlog of 128. kadmind's kpasswd list passes 5 to [`bind_tcp_listeners_with_backlog`].
///
/// # Errors
///
/// As [`bind_udp_listeners`].
pub fn bind_tcp_listeners(addrs: &[ListenAddr]) -> io::Result<Vec<TcpListener>> {
    bind_tcp_listeners_with_backlog(addrs, KDC_TCP_LISTEN_BACKLOG)
}

/// [`bind_tcp_listeners`] with the backlog `listen` is given (krb5kdc's
/// `kdc_tcp_listen_backlog`), as C's `listen` takes it: a negative one is the system's most.
/// MIT `loop_setup_network` (`lib/apputils/net-server.c:1053-1070`): the TCP listeners listen with the backlog the daemon passes.
///
/// # Errors
///
/// As [`bind_udp_listeners`].
pub fn bind_tcp_listeners_with_backlog(
    addrs: &[ListenAddr],
    backlog: i32,
) -> io::Result<Vec<TcpListener>> {
    Ok(bind_listeners(addrs, BindType::Tcp, backlog)?
        .into_iter()
        .map(TcpListener::from)
        .collect())
}

/// [`bind_tcp_listeners`] for an RPC service's list (kadmind's `kadmind_listen`), whose sockets
/// the daemon log names RPC.
///
/// # Errors
///
/// As [`bind_udp_listeners`].
pub fn bind_rpc_listeners(addrs: &[ListenAddr]) -> io::Result<Vec<TcpListener>> {
    Ok(
        bind_listeners(addrs, BindType::Rpc, DEFAULT_TCP_LISTEN_BACKLOG)?
            .into_iter()
            .map(TcpListener::from)
            .collect(),
    )
}

/// A listener's kind, as a failed setup names it in the daemon log.
/// MIT `enum bind_type` (`lib/apputils/net-server.c:130-132`): a UDP, TCP or RPC listener.
#[derive(Clone, Copy)]
enum BindType {
    Udp,
    Tcp,
    /// An RPC service's TCP listener (kadmind's kadm5).
    Rpc,
}

impl BindType {
    /// MIT `bind_type_names` (`lib/apputils/net-server.c:134-139`): the name a failed setup logs.
    fn name(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Rpc => "RPC",
        }
    }

    /// The transport, as the JSON log and a bind error name it.
    fn proto(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp | Self::Rpc => "tcp",
        }
    }
}

fn bind_listeners(addrs: &[ListenAddr], kind: BindType, backlog: i32) -> io::Result<Vec<OwnedFd>> {
    let proto = kind.proto();
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
                    tracing::info!(
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
                    if e.raw_os_error() != Some(nix::errno::Errno::EAFNOSUPPORT as i32) {
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

/// One listener on `addr`, made as MIT's net-server makes it: created and bound by
/// [`create_server_socket`], then a TCP listener listens with MIT's backlog and does not linger,
/// an RPC listener listens with the RPC library's backlog, and a UDP socket on a wildcard address
/// asks for each datagram's destination, which its reply leaves from ([`send_to_from`]).
/// MIT `setup_socket` (`lib/apputils/net-server.c:813-859`): the setup is logged at debug, then the socket is created and a stream one listens, each failure logged and fatal.
/// MIT `setup_socket` (`lib/apputils/net-server.c:861-875`): a UDP socket on a wildcard address asks for pktinfo; without it the socket is kept and the reason logged.
/// MIT `svctcp_create` (`lib/rpc/svc_tcp.c:178-178`): an RPC listener that cannot listen is no RPC service.
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
            // Past what `Backlog` takes, the kernel gives the system's most, as for MIT's `listen`.
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

/// A socket for `addr`, close-on-exec, with `SO_REUSEADDR` and, on IPv6, `IPV6_V6ONLY`, bound;
/// a failure is logged with the address.
/// MIT `create_server_socket` (`lib/apputils/net-server.c:625-631`): a socket that is not made is logged as a TCP one, whatever its type.
/// MIT `create_server_socket` (`lib/apputils/net-server.c:644-658`): `SO_REUSEADDR`, then `IPV6_V6ONLY` on an IPv6 socket, each logged and neither fatal.
/// MIT `create_server_socket` (`lib/apputils/net-server.c:660-666`): a bind that fails is logged with the address and the socket closed.
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

/// MIT `set_pktinfo` (`lib/apputils/udppktinfo.c:123-133`): `IP_PKTINFO` on an IPv4 socket, `IPV6_RECVPKTINFO` on an IPv6 one.
fn set_pktinfo(fd: &OwnedFd, addr: SocketAddr) -> nix::Result<()> {
    if addr.is_ipv4() {
        setsockopt(fd, sockopt::Ipv4PacketInfo, &true)
    } else {
        setsockopt(fd, sockopt::Ipv6RecvPacketInfo, &true)
    }
}

/// Where a datagram was sent: the local address, and for IPv6 the interface it came in on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PktInfo {
    /// The address the datagram was sent to.
    pub addr: IpAddr,
    /// The interface an IPv6 datagram came in on; 0 for IPv4.
    pub ifindex: u32,
}

/// One datagram as [`recv_from_to`] read it.
#[derive(Clone, Copy, Debug)]
pub struct Datagram {
    /// Its length, at the start of the buffer.
    pub len: usize,
    /// The sender.
    pub from: SocketAddr,
    /// Where it was sent, when the socket is bound to a wildcard address and the system says.
    pub to: Option<PktInfo>,
}

/// Read one datagram from `sock` into `buf`, with the address it was sent to when `sock` is
/// bound to a wildcard address, so the reply can leave from it ([`send_udp_reply`]).
/// MIT `recv_from_to` (`lib/apputils/udppktinfo.c:283-325`): a socket bound to a wildcard address is read with its pktinfo; any other socket, or a datagram without pktinfo, has no destination.
///
/// # Errors
///
/// The receive's `io::Error` (`WouldBlock` when the socket's read timeout passes), and
/// `io::ErrorKind::InvalidData` for a datagram whose sender is not an IP address.
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

/// Send `buf` to `to` on `sock`, from `from` when it is where the request was sent and `sock` is
/// bound to a wildcard address, so a client whose socket is connected to that address takes it.
/// MIT `send_to_from` (`lib/apputils/udppktinfo.c:443-474`): pktinfo names the source only on a wildcard socket and for a source of the destination's family; otherwise the datagram goes out with `sendto`.
/// MIT `set_msg_from_ipv6_pktinfo` (`lib/apputils/udppktinfo.c:383-394`): the interface is named only for a link-local source.
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

/// Answer the datagram `d` with `reply` from the address it was sent to ([`recv_from_to`]); a
/// failed send is logged with both addresses, a short one with both lengths.
/// MIT `process_packet_response` (`lib/apputils/net-server.c:1107-1125`): the reply goes out with `send_to_from`; a failed send is logged with the client's address and the local one, a short send with the lengths.
///
/// # Errors
///
/// The send's `io::Error`, once it is logged.
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

/// Log a failed call as MIT's `com_err` does: the error's text, ` - `, then `what`.
fn com_err(e: &io::Error, what: &str) {
    klog::com_err(Some(&os_error_text(e)), what);
}

/// [`com_err`] for a call whose failure ends the setup: `e`, logged, as an `io::Error`.
fn failed(e: nix::Error, what: &str) -> io::Error {
    let e = io::Error::from(e);
    com_err(&e, what);
    e
}

/// MIT `setup_addresses` (`lib/apputils/net-server.c:1024-1030`): a failed setup is logged with its socket type and address.
fn setup_failure_line(a: SocketAddr, kind: BindType) -> String {
    format!(
        "Failed setting up a {} socket (for {})",
        kind.name(),
        a.ip()
    )
}

/// MIT `loop_setup_network` (`lib/apputils/net-server.c:1068-1073`): the error the setup stopped on is logged once more, and the daemon exits.
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

/// The daemon log lines for a listen entry whose host does not resolve; the daemon then stops.
/// `error` is the resolver's text, which ends with `getaddrinfo`'s message.
/// MIT `setup_addresses` (`lib/apputils/net-server.c:993-1000`): the host (`<wildcard>` for
/// none) and `gai_strerror`, and the setup fails with EIO.
/// MIT `loop_setup_network` (`lib/apputils/net-server.c:1068-1073`): that error once more.
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

/// Drop root after a privileged bind (port 88): the gates' test realm, in a `test-hooks` build only.
/// MIT's `krb5kdc` never changes user and reads no `KRB5_KDC_USER`, so a release build has neither.
///
/// When effective uid is 0, setgid/setuid to `KRB5_KDC_USER` (default
/// `nobody`). Unprivileged processes return `Ok(false)` without changing
/// credentials.
///
/// # Errors
///
/// Only as root: `io::ErrorKind::NotFound` when the target user does not exist, and
/// `io::ErrorKind::Other` when the user lookup, `setgid` or `setuid` fails.
#[cfg(feature = "test-hooks")]
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
/// Only as root: `io::ErrorKind::NotFound` when `username` does not exist, and
/// `io::ErrorKind::Other` when the user lookup, `setgid` or `setuid` fails.
#[cfg(any(test, feature = "test-hooks"))]
pub(crate) fn drop_privileges_to(username: &str) -> io::Result<bool> {
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
/// As [`serve_all_until`].
pub fn serve(store: SharedStore, udp: UdpSocket, tcp: TcpListener) -> io::Result<()> {
    serve_all(store, vec![udp], vec![tcp])
}

/// [`serve`] on every socket of [`bind_udp_listeners`] / [`bind_tcp_listeners`].
///
/// # Errors
///
/// As [`serve_all_until`].
pub fn serve_all(store: SharedStore, udp: Vec<UdpSocket>, tcp: Vec<TcpListener>) -> io::Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    install_shutdown_flag(&shutdown);
    serve_all_until(store, udp, tcp, shutdown, ListenLimits::default())
}

/// Serve until `shutdown` is true, looked at every `limits.shutdown_poll`.
///
/// # Errors
///
/// As [`serve_all_until`].
pub fn serve_until(
    store: SharedStore,
    udp: UdpSocket,
    tcp: TcpListener,
    shutdown: Arc<AtomicBool>,
    limits: ListenLimits,
) -> io::Result<()> {
    serve_all_until(store, vec![udp], vec![tcp], shutdown, limits)
}

/// [`serve_until`] on several sockets: one loop on the calling thread serves them all, with one
/// lookaside cache and one stream cap, as MIT's net-server loop does. An embedder runs it on a
/// thread of its own; plugin modules set for the calling thread alone do not apply while it runs.
///
/// # Errors
///
/// `io::ErrorKind::InvalidInput` when `limits.shutdown_poll` is zero, and the OS error when a
/// listener cannot be made non-blocking or the loop's poll fails. Per-request failures are only
/// logged.
#[allow(clippy::needless_pass_by_value)] // the loop owns the store and the stop flag
pub fn serve_all_until(
    store: SharedStore,
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpListener>,
    shutdown: Arc<AtomicBool>,
    limits: ListenLimits,
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
    serve_loop(store, &udp, &tcp, &wake, limits)
}

/// krb5kdc's loop: serve on the calling thread until SIGINT, SIGTERM or SIGQUIT, each logged as
/// MIT's, with SIGHUP reopening the log.
/// MIT `main` (`kdc/main.c:1030-1030`): `verto_run` serves every realm from the one loop.
///
/// # Errors
///
/// The OS error when a listener cannot be made non-blocking or the loop's poll fails.
#[allow(clippy::needless_pass_by_value)] // the loop owns the store
pub fn serve_daemon(
    store: SharedStore,
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpListener>,
    signals: &Signals,
    limits: ListenLimits,
) -> io::Result<()> {
    serve_loop(store, &udp, &tcp, &Wake::Signals(signals), limits)
}

fn serve_loop(
    store: SharedStore,
    udp: &[UdpSocket],
    tcp: &[TcpListener],
    wake: &Wake<'_>,
    limits: ListenLimits,
) -> io::Result<()> {
    let _slots = ThreadSlots::take();
    let mut app = KdcDispatch::new(store, limits.max_dgram_reply_size);
    let sockets = Sockets {
        udp,
        tcp,
        ..Sockets::default()
    };
    // krb5kdc closes its log before it frees the loop, so the connections left open are not
    // logged.
    // MIT `main` (`kdc/main.c:1032-1044`): "shutting down", the log closed, then the loop freed.
    crate::net_server::run(
        &mut app,
        &sockets,
        limits.max_tcp_workers,
        limits.max_tcp_request,
        wake,
        &mut Klog,
    )
    .map(drop)
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{Shutdown, TcpStream};
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

    #[test]
    fn a_lookup_without_the_policy_lock_file_is_svc_unavailable() {
        let (store, db) = persisted("svc");
        let id = format!("krbtgt/{0}@{0}", crate::testrealm::TEST_REALM);
        assert!(read_store(&store, |s| s.fetch(&id)).unwrap().is_some());
        std::fs::remove_file(crate::suffixed(&db, crate::SUFFIX_POLICY_LOCK)).unwrap();
        match read_store(&store, |s| s.fetch(&id)) {
            Err(Error::Protocol { code, .. }) => {
                assert_eq!(code, krb5_types::err::SVC_UNAVAILABLE);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_lookup_waits_for_a_write_holder_not_for_a_read_holder() {
        let (store, db) = persisted("wait");
        let other = Arc::new(crate::DbLock::open(&db).unwrap());
        let id = format!("krbtgt/{0}@{0}", crate::testrealm::TEST_REALM);
        let lookup = |store: &SharedStore| {
            let (store, id) = (Arc::clone(store), id.clone());
            let (tx, rx) = std::sync::mpsc::channel();
            thread::spawn(move || {
                let found = read_store(&store, |s| s.fetch(&id).ok().flatten().is_some());
                tx.send(found).unwrap();
            });
            rx
        };
        let held = other.hold(crate::DbLockMode::Shared).unwrap();
        assert_eq!(
            lookup(&store).recv_timeout(Duration::from_secs(5)),
            Ok(true)
        );
        drop(held);
        let held = other.hold(crate::DbLockMode::Exclusive).unwrap();
        let rx = lookup(&store);
        assert!(rx.recv_timeout(Duration::from_millis(400)).is_err());
        drop(held);
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(true));
    }

    /// Requests that keep overlapping never hold the lock across their own work, so another
    /// process's writer gets it within a bounded wait.
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

    /// A database changed into one that does not load answers every lookup with its error, never
    /// with the principals read before; put back, it serves again.
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

    #[test]
    fn listen_entry_failures_log_mits_lines() {
        let entry = ListenAddr {
            host: Some("nosuch.invalid".into()),
            port: 88,
        };
        let error = "listen address nosuch.invalid: failed to lookup address information: \
                     Temporary failure in name resolution";
        assert_eq!(
            resolve_failure_lines(&entry, error),
            [
                "Failed getting address info (for nosuch.invalid): Temporary failure in name \
                 resolution"
                    .to_owned(),
                "Input/output error - Error setting up network".to_owned(),
            ]
        );
        let wildcard = ListenAddr {
            host: None,
            port: 88,
        };
        assert!(resolve_failure_lines(&wildcard, "x")[0].contains("(for <wildcard>): x"));
        assert_eq!(
            setup_failure_line("[::]:88".parse().unwrap(), BindType::Udp),
            "Failed setting up a UDP socket (for ::)"
        );
        // kadmind's kadm5 listener is an RPC one, as MIT names it.
        assert_eq!(
            setup_failure_line("[::]:749".parse().unwrap(), BindType::Rpc),
            "Failed setting up a RPC socket (for ::)"
        );
        assert_eq!(BindType::Tcp.name(), "TCP");
        assert_eq!(BindType::Rpc.proto(), "tcp");
    }

    use std::io::Read as _;
    use std::sync::atomic::Ordering;

    use krb5_asn1::{decode, encode};
    use krb5_types::{KrbError, PrincipalName, err};

    /// The documented realm served by `serve_until` on a thread of its own with `limits`: the
    /// address it serves, the stop flag, and the thread.
    fn serving(limits: ListenLimits) -> (SocketAddr, Arc<AtomicBool>, thread::JoinHandle<()>) {
        let (store, _) = bootstrap_documented().unwrap();
        let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
        let addr = udp.local_addr().unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&flag);
        let h = thread::spawn(move || {
            serve_until(shared_store(store), udp, tcp, stop, limits).unwrap();
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

    #[test]
    fn drop_privileges_is_noop_when_unprivileged() {
        assert!(!drop_privileges_to("nobody").expect("unprivileged drop"));
    }

    /// A length past the cap is answered with FIELD_TOOLONG before any body, and so is a length
    /// one past MIT's 1 MiB buffer.
    #[test]
    fn tcp_oversize_length_is_field_toolong() {
        for (cap, n) in [(32, 64u32), (MAX_TCP_REQUEST, 1024 * 1024 + 1)] {
            let (addr, flag, h) = serving(ListenLimits {
                max_tcp_request: cap,
                ..limits()
            });
            let mut c = TcpStream::connect(addr).unwrap();
            // The length word alone: body bytes the server does not read turn its close into a
            // reset, which can reach this socket before the reply has been read.
            c.write_all(&n.to_be_bytes()).unwrap();
            assert_eq!(tcp_error(&mut c).error_code, err::FIELD_TOOLONG);
            stop(&flag, h);
        }
    }

    #[test]
    fn tcp_max_request_is_one_mib_minus_four() {
        assert_eq!(MAX_TCP_REQUEST, 1024 * 1024 - 4);
    }

    /// A 128 KiB AS-REQ arrives in many reads and is answered as one request.
    #[test]
    fn tcp_128kib_unknown_cname_is_client_not_found() {
        use krb5_types::{OctetString, PaData};

        let (addr, flag, h) = serving(limits());
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["nosuch"]);
        let mut req = krb5_protocol::as_req(cname, crate::testrealm::TEST_REALM, 1, None).unwrap();
        req.0.padata = Some(vec![PaData {
            padata_type: 9999,
            padata_value: OctetString::from(vec![0u8; 128 * 1024]),
        }]);
        let bytes = encode(&req).unwrap();
        assert!(bytes.len() > 128 * 1024);
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(&(u32::try_from(bytes.len()).unwrap()).to_be_bytes())
            .unwrap();
        c.write_all(&bytes).unwrap();
        let e = tcp_error(&mut c);
        assert_eq!(e.error_code, err::C_PRINCIPAL_UNKNOWN);
        let text = e
            .e_text
            .as_ref()
            .and_then(|t| std::str::from_utf8(t.as_bytes()).ok());
        assert_eq!(text, Some("CLIENT_NOT_FOUND"));
        stop(&flag, h);
    }

    /// A zero length is not dispatched: no reply, and the stream closes at its next event.
    #[test]
    fn tcp_zero_length_is_dropped() {
        let (addr, flag, h) = serving(limits());
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(&0u32.to_be_bytes()).unwrap();
        c.set_read_timeout(Some(Duration::from_millis(400)))
            .unwrap();
        let mut hdr = [0u8; 4];
        let waited = c.read(&mut hdr);
        assert!(
            matches!(&waited, Err(e) if e.kind() == io::ErrorKind::WouldBlock),
            "no reply and no close yet: {waited:?}"
        );
        c.shutdown(Shutdown::Write).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(c.read(&mut hdr).unwrap(), 0, "closed at the next event");
        stop(&flag, h);
    }

    #[test]
    fn dispatch_suffixes_are_mit_net_server() {
        assert_eq!(WHILE_DISPATCHING_UDP, "while dispatching (udp)");
        assert_eq!(WHILE_DISPATCHING_TCP, "while dispatching (tcp)");
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

    #[test]
    fn serve_until_stops_on_flag() {
        let (addr, flag, h) = serving(limits());
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        sock.send_to(&as_req_bytes(1), addr).unwrap();
        let mut buf = [0u8; 4096];
        let n = sock.recv(&mut buf).unwrap();
        let e: KrbError = decode(&buf[..n]).unwrap();
        assert_eq!(e.error_code, err::PREAUTH_REQUIRED);
        stop(&flag, h);
    }

    #[test]
    fn a_zero_shutdown_poll_is_refused() {
        let (store, _) = bootstrap_documented().unwrap();
        let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
        let flag = Arc::new(AtomicBool::new(false));
        let zero = ListenLimits {
            shutdown_poll: Duration::ZERO,
            ..ListenLimits::default()
        };
        let e = serve_until(shared_store(store), udp, tcp, flag, zero).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
    }

    /// Past the cap a new connection evicts the one that started first, and among connections
    /// of the same second the one met first from the top of the table: c1 started a second
    /// before c2 and c3, so c3 evicts c1 and takes its place at the table's start; c4 then meets
    /// c2 first from the top, and evicts it.
    /// MIT `kill_lru_stream_connection` (`lib/apputils/net-server.c:1198-1223`): the scan from the top keeps the first of a tie.
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
        // Start c1 just after a second begins, and c2 / c3 just after the next.
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
