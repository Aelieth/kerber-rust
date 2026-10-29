//! One loop: kpasswd, kadm5, iprop; one cap of 45 connections.

use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use krb5_config::listen::{BindAddresses, BindType, ListenLog};
use krb5_config::{KadmindListen, ProfileSet};
use krb5_crypto::ProtocolKey;
#[cfg(feature = "daemon")]
use krb5_kdc::Signals;
use krb5_kdc::net_server::{
    self, Dispatch, Log, MAX_REQUEST, MAX_STREAM_DATA_CONNECTIONS, Reply, RpcSession, Sockets, Wake,
};
use krb5_kdc::principals::kadmin_changepw;
use krb5_kdc::{
    Acl, DEFAULT_TCP_LISTEN_BACKLOG, Kadm5Hook, Pwqual, SharedDump as SharedStore, Shutdown,
    WHILE_DISPATCHING_TCP, WHILE_DISPATCHING_UDP, bind_rpc_listeners,
    bind_tcp_listeners_with_backlog, bind_udp_listeners, clear_thread_kadm5_hook,
    clear_thread_pwqual, set_thread_kadm5_hook, set_thread_pwqual,
};
use krb5_log::klog::{self, Severity};
use krb5_protocol::{AcceptorConfig, ReplayCache};

use crate::kadm5::{IpropResync, Kadm5Auth, Kadm5AuthConfig, Kadm5Conn};
use crate::listen::{client_addr, handle_kpasswd_from, kpasswd_toolong_error};
use crate::{Programs, RpcPeer, UnhandledRpc, acceptor_names_served};

#[derive(Clone, Copy, Debug)]
pub struct Services {
    pub kpasswd_udp: bool,
    pub kpasswd_tcp: bool,
    pub kadm5: bool,
    pub iprop: bool,
}

impl Services {
    pub const ALL: Self = Self {
        kpasswd_udp: true,
        kpasswd_tcp: true,
        kadm5: true,
        iprop: true,
    };
    pub const DAEMON: Self = Self {
        kpasswd_udp: true,
        kpasswd_tcp: true,
        kadm5: true,
        iprop: false,
    };

    fn kpasswd(self) -> bool {
        self.kpasswd_udp || self.kpasswd_tcp
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ServeLimits {
    pub max_connections: usize,
    pub max_request: usize,
    pub idle_timeout: Option<Duration>,
    pub per_ip_conns: Option<usize>,
}

impl Default for ServeLimits {
    fn default() -> Self {
        Self {
            max_connections: MAX_STREAM_DATA_CONNECTIONS,
            max_request: MAX_REQUEST,
            idle_timeout: None,
            per_ip_conns: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct IpropConfig {
    pub listen: Option<String>,
    pub port: i32,
    pub dump_file: Option<PathBuf>,
    pub kprop_port: Option<String>,
}

pub struct KadmindConfig {
    pub profile: Arc<ProfileSet>,
    pub services: Services,
    pub listen: KadmindListen,
    pub limits: ServeLimits,
    pub acl: Acl,
    pub auth_modules: Vec<Arc<dyn Kadm5Auth>>,
    pub log: Arc<dyn AdminLog>,
    pub pwqual: Vec<Arc<dyn Pwqual>>,
    pub hooks: Vec<Arc<dyn Kadm5Hook>>,
    pub iprop: Option<IpropConfig>,
}

pub trait AdminLog: Send + Sync {
    fn syslog(&self, severity: Severity, msg: &str);

    fn syslog_open(&self, severity: Severity, msg: &str) {
        self.syslog(severity, msg);
    }

    fn reopen(&self) {}
}

pub struct KlogAdmin;

impl AdminLog for KlogAdmin {
    fn syslog(&self, severity: Severity, msg: &str) {
        klog::syslog(severity, msg);
    }

    fn syslog_open(&self, severity: Severity, msg: &str) {
        klog::syslog_open(severity, msg);
    }

    fn reopen(&self) {
        klog::reopen();
    }
}

pub struct TracingAdmin;

impl AdminLog for TracingAdmin {
    fn syslog(&self, severity: Severity, msg: &str) {
        match severity {
            Severity::Emerg | Severity::Alert | Severity::Crit | Severity::Err => {
                tracing::error!(target: "krb5_admin", "{msg}");
            }
            Severity::Warning => tracing::warn!(target: "krb5_admin", "{msg}"),
            Severity::Debug => tracing::debug!(target: "krb5_admin", "{msg}"),
            Severity::Notice | Severity::Info => tracing::info!(target: "krb5_admin", "{msg}"),
        }
    }

    fn syslog_open(&self, severity: Severity, msg: &str) {
        klog::syslog_open(severity, msg);
    }
}

struct AdminLogFwd(Arc<dyn AdminLog>);

impl Log for AdminLogFwd {
    fn syslog(&mut self, severity: Severity, msg: &str) {
        self.0.syslog(severity, msg);
    }

    fn reopen(&mut self) {
        self.0.reopen();
    }
}

std::thread_local! {
    static THREAD_ADMIN_LOG: std::cell::RefCell<Option<Arc<dyn AdminLog>>> =
        const { std::cell::RefCell::new(None) };
}

pub(crate) fn admin_syslog(severity: Severity, msg: &str) {
    let sent = THREAD_ADMIN_LOG.with(|slot| {
        let slot = slot.borrow();
        if let Some(log) = slot.as_ref() {
            log.syslog(severity, msg);
            true
        } else {
            false
        }
    });
    if !sent {
        klog::syslog(severity, msg);
    }
}

pub(crate) fn admin_syslog_open(severity: Severity, msg: &str) {
    let sent = THREAD_ADMIN_LOG.with(|slot| {
        let slot = slot.borrow();
        if let Some(log) = slot.as_ref() {
            log.syslog_open(severity, msg);
            true
        } else {
            false
        }
    });
    if !sent {
        klog::syslog_open(severity, msg);
    }
}

pub(crate) fn thread_admin_log() -> Option<Arc<dyn AdminLog>> {
    THREAD_ADMIN_LOG.with(|slot| slot.borrow().clone())
}

pub(crate) fn set_thread_admin_log(log: Option<Arc<dyn AdminLog>>) {
    THREAD_ADMIN_LOG.with(|slot| *slot.borrow_mut() = log);
}

#[derive(Debug)]
pub enum StartError {
    Pwqual(io::Error),
    Config(String),
    AcceptorNames,
    Listen(String),
    Bind(io::Error),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pwqual(e) | Self::Bind(e) => write!(f, "{e}"),
            Self::Config(m) | Self::Listen(m) => f.write_str(m),
            Self::AcceptorNames => f.write_str("Cannot set GSSAPI authentication names"),
        }
    }
}

impl std::error::Error for StartError {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BindService {
    Kpasswd,
    Kadm,
    Iprop,
}

pub struct Kadmind {
    store: SharedStore,
    authcfg: Arc<Kadm5AuthConfig>,
    cpw_key: Option<ProtocolKey>,
    rcache: ReplayCache,
    conf: Arc<AcceptorConfig>,
    programs: Programs,
    report: Option<UnhandledRpc>,
    limits: ServeLimits,
    iprop_resync: Option<Arc<IpropResync>>,
    log: Arc<dyn AdminLog>,
    pwqual: Vec<Arc<dyn Pwqual>>,
    hooks: Vec<Arc<dyn Kadm5Hook>>,
}

impl Kadmind {
    // MIT: `kadm5_init` (lib/kadm5/srv/server_init.c:158-276)
    pub fn prepare_store(store: &SharedStore, profile: &ProfileSet) -> Result<(), StartError> {
        let mut guard = store.write().unwrap_or_else(PoisonError::into_inner);
        guard
            .init_pwqual(profile.kdc.as_ref())
            .map_err(StartError::Pwqual)?;
        guard
            .apply_profile(profile)
            .map_err(|e| StartError::Config(e.to_string()))?;
        Ok(())
    }

    pub fn new(store: SharedStore, cfg: KadmindConfig) -> Result<Self, StartError> {
        Self::prepare_store(&store, &cfg.profile)?;
        // MIT: `kadm5_init_krb5_context` (lib/kadm5/srv/server_init.c:334-345)
        let conf = AcceptorConfig::from_profile(&cfg.profile);
        let cpw_key = {
            let guard = store.read().unwrap_or_else(PoisonError::into_inner);
            if !acceptor_names_served(&guard, &conf) {
                return Err(StartError::AcceptorNames);
            }
            if cfg.services.kpasswd() {
                guard
                    .get_name(&kadmin_changepw())
                    .and_then(|p| p.best_key())
                    .map(|k| k.key.clone())
            } else {
                None
            }
        };
        let kdc_default = krb5_config::KdcConf::default();
        let relations = krb5_config::kdc_plugin_relations(
            cfg.profile.kdc.as_ref().unwrap_or(&kdc_default),
            &cfg.profile.krb5,
            "kadm5_auth",
        );
        let authcfg = Arc::new(Kadm5AuthConfig::build(
            cfg.acl,
            &cfg.auth_modules,
            &relations,
        ));
        let iprop_resync = cfg.iprop.as_ref().and_then(|ip| {
            ip.dump_file.as_ref().map(|dump_file| {
                let realm = store
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .realm()
                    .to_owned();
                Arc::new(IpropResync {
                    dump_file: dump_file.clone(),
                    kprop_port: ip.kprop_port.clone(),
                    profile: cfg.profile.krb5.clone(),
                    realm,
                })
            })
        });
        Ok(Self {
            store,
            authcfg,
            cpw_key,
            rcache: ReplayCache::new(),
            conf: Arc::new(conf),
            programs: Programs::BOTH,
            report: None,
            limits: cfg.limits,
            iprop_resync,
            log: cfg.log,
            pwqual: cfg.pwqual,
            hooks: cfg.hooks,
        })
    }

    #[must_use]
    pub fn serve_programs(mut self, programs: Programs) -> Self {
        self.programs = programs;
        self
    }

    #[must_use]
    pub fn report_unhandled(mut self, report: UnhandledRpc) -> Self {
        self.report = Some(report);
        self
    }

    pub fn serve(&mut self, listeners: &Listeners, stop: &Shutdown) -> io::Result<ServeSummary> {
        self.programs = listeners.programs;
        let (max_conns, max_req) = (self.limits.max_connections, self.limits.max_request);
        let sockets = Sockets {
            udp: &listeners.udp,
            tcp: &listeners.tcp,
            rpc: &listeners.rpc,
        };
        run_logged(self, &sockets, max_conns, max_req, &Wake::Shutdown(stop))
            .map(|open_fds| ServeSummary { open_fds })
    }

    #[must_use]
    pub fn serves_kpasswd(&self) -> bool {
        self.cpw_key.is_some()
    }

    fn realm(&self) -> String {
        self.store
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .realm()
            .to_owned()
    }
}

impl Dispatch for Kadmind {
    // MIT: `dispatch` (kadmin/server/schpw.c:420-436)
    /// A failure answers nothing; the loop is told.
    fn dispatch(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        request: &[u8],
        is_tcp: bool,
        _log: &mut dyn Log,
    ) -> Reply {
        if self.cpw_key.is_none() {
            return Reply::Nothing;
        }
        let replay = ReplayCache::new();
        let from = client_addr(remote.ip());
        let here = Some(local.ip());
        match handle_kpasswd_from(
            &self.store,
            &self.authcfg,
            &self.conf,
            &replay,
            request,
            &from,
            here,
        ) {
            Ok(reply) => Reply::Send(reply),
            Err(e) => {
                let suffix = if is_tcp {
                    WHILE_DISPATCHING_TCP
                } else {
                    WHILE_DISPATCHING_UDP
                };
                tracing::error!(
                    event = krb5_log::events::ADMIN,
                    component = "krb5-admin",
                    outcome = "error",
                    error = %e,
                    "{e} - {suffix}"
                );
                Reply::Failed(e.to_string())
            }
        }
    }

    fn make_toolong_error(&mut self) -> Result<Vec<u8>, String> {
        kpasswd_toolong_error(&self.realm()).map_err(|e| e.to_string())
    }

    fn rpc_session(
        &mut self,
        remote: SocketAddr,
        local: SocketAddr,
    ) -> Option<Box<dyn RpcSession>> {
        Some(Box::new(Kadm5Conn::new(
            Arc::clone(&self.store),
            Arc::clone(&self.authcfg),
            self.realm(),
            self.rcache.clone(),
            Arc::clone(&self.conf),
            self.programs,
            RpcPeer::new(Some(remote), Some(local)),
            self.report.clone(),
            self.iprop_resync.clone(),
        )?))
    }
}

pub struct Listeners {
    pub(crate) udp: Vec<UdpSocket>,
    pub(crate) tcp: Vec<TcpListener>,
    pub(crate) rpc: Vec<TcpListener>,
    pub(crate) programs: Programs,
}

impl Listeners {
    // MIT: `setup_loop` (kadmin/server/ovsec_kadmd.c:134-174)
    pub fn bind(
        listen: &KadmindListen,
        services: Services,
        iprop: Option<&IpropConfig>,
        log: &dyn AdminLog,
    ) -> Result<Self, StartError> {
        let mut list: BindAddresses<BindService> = BindAddresses::default();
        let mut added = Ok(());
        if services.kpasswd_udp || services.kpasswd_tcp {
            let kpasswd = listen.kpasswd_listen.as_deref();
            if services.kpasswd_udp {
                added = added.and_then(|()| {
                    list.add_addresses(
                        kpasswd,
                        listen.kpasswd_port,
                        BindType::Udp,
                        &BindService::Kpasswd,
                    )
                });
            }
            if services.kpasswd_tcp {
                added = added.and_then(|()| {
                    list.add_addresses(
                        kpasswd,
                        listen.kpasswd_port,
                        BindType::Tcp,
                        &BindService::Kpasswd,
                    )
                });
            }
            // MIT: `loop_add_unix_socket` (lib/apputils/net-server.c:461-468)
            // A `/path` entry is a UNIX socket; it is not bound.
            for entry in kpasswd
                .into_iter()
                .flat_map(|l| l.split([',', ';', ' ']))
                .filter(|e| e.starts_with('/'))
            {
                log.syslog(
                    Severity::Warning,
                    &format!(
                        "kpasswd_listen entry {entry} is a UNIX-domain socket, which is not supported; it is skipped"
                    ),
                );
            }
        }
        if services.kadm5 {
            added = added.and_then(|()| {
                list.add_addresses(
                    listen.kadmind_listen.as_deref(),
                    listen.kadmind_port,
                    BindType::Rpc,
                    &BindService::Kadm,
                )
            });
        }
        if let Some(iprop) = iprop.filter(|_| services.iprop) {
            added = added.and_then(|()| {
                list.add_addresses(
                    iprop.listen.as_deref(),
                    iprop.port,
                    BindType::Rpc,
                    &BindService::Iprop,
                )
            });
        }
        for line in list.take_log() {
            match line {
                ListenLog::Debug(l) => log.syslog(Severity::Debug, &l),
                ListenLog::Err(l) => log.syslog(Severity::Err, &l),
            }
        }
        // A refusal or empty list stops kadmind before it binds.
        if added.is_err() || list.entries().is_empty() {
            return Err(StartError::Listen("Invalid argument".into()));
        }
        // MIT: `loop_setup_network` (lib/apputils/net-server.c:1068-1068)
        log.syslog(Severity::Info, "setting up network...");
        let (mut rpc, mut udp, mut tcp) = (Vec::new(), Vec::new(), Vec::new());
        let mut programs = Programs {
            kadm: false,
            iprop: false,
        };
        // MIT: `setup_addresses` (lib/apputils/net-server.c:965-1042)
        for entry in list.entries() {
            let one = std::slice::from_ref(&entry.addr);
            match entry.kind {
                BindType::Udp => udp.extend(bind_udp_listeners(one).map_err(StartError::Bind)?),
                BindType::Tcp => tcp.extend(
                    bind_tcp_listeners_with_backlog(one, DEFAULT_TCP_LISTEN_BACKLOG)
                        .map_err(StartError::Bind)?,
                ),
                BindType::Rpc => {
                    rpc.extend(bind_rpc_listeners(one).map_err(StartError::Bind)?);
                    match entry.service {
                        BindService::Kadm => programs.kadm = true,
                        BindService::Iprop => programs.iprop = true,
                        BindService::Kpasswd => {}
                    }
                }
            }
        }
        log.syslog(
            Severity::Info,
            &format!("set up {} sockets", udp.len() + tcp.len() + rpc.len()),
        );
        Ok(Self {
            udp,
            tcp,
            rpc,
            programs,
        })
    }

    #[must_use]
    pub fn from_sockets(
        udp: Vec<UdpSocket>,
        tcp: Vec<TcpListener>,
        rpc: Vec<TcpListener>,
        programs: Programs,
    ) -> Self {
        Self {
            udp,
            tcp,
            rpc,
            programs,
        }
    }

    #[must_use]
    pub fn sockets(&self) -> Sockets<'_> {
        Sockets {
            udp: &self.udp,
            tcp: &self.tcp,
            rpc: &self.rpc,
        }
    }

    #[must_use]
    pub fn programs(&self) -> Programs {
        self.programs
    }
}

pub struct ServeSummary {
    pub open_fds: Vec<RawFd>,
}

#[cfg(feature = "daemon")]
/// Until SIGINT/TERM/QUIT; SIGHUP reopens the log.
pub fn serve_kadmind(
    kadmind: &mut Kadmind,
    sockets: &Sockets<'_>,
    signals: &Signals,
) -> io::Result<Vec<RawFd>> {
    run_logged(
        kadmind,
        sockets,
        MAX_STREAM_DATA_CONNECTIONS,
        MAX_REQUEST,
        &Wake::Signals(signals),
    )
}

fn run_logged(
    kadmind: &mut Kadmind,
    sockets: &Sockets<'_>,
    max_conns: usize,
    max_req: usize,
    wake: &Wake<'_>,
) -> io::Result<Vec<RawFd>> {
    let set_pw = !kadmind.pwqual.is_empty();
    let set_hooks = !kadmind.hooks.is_empty();
    if set_pw {
        set_thread_pwqual(kadmind.pwqual.clone());
    }
    if set_hooks {
        set_thread_kadm5_hook(kadmind.hooks.clone());
    }
    set_thread_admin_log(Some(Arc::clone(&kadmind.log)));
    let mut log = AdminLogFwd(Arc::clone(&kadmind.log));
    let serve_limits = net_server::ServeLimits {
        idle_timeout: kadmind.limits.idle_timeout,
        per_ip_conns: kadmind.limits.per_ip_conns,
        ..net_server::ServeLimits::default()
    };
    let result = net_server::run(
        kadmind,
        sockets,
        max_conns,
        max_req,
        serve_limits,
        wake,
        &mut log,
    );
    set_thread_admin_log(None);
    if set_pw {
        clear_thread_pwqual();
    }
    if set_hooks {
        clear_thread_kadm5_hook();
    }
    result
}
