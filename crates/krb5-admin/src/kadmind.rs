//! kadmind's one loop: kpasswd over UDP and TCP and the kadm5 and iprop RPC programs, served from
//! MIT's net-server loop on the caller's thread, as MIT's kadmind serves them from the loop
//! `setup_loop` builds. Every connection, kpasswd's and kadm5's alike, counts toward the one cap
//! of 45.

use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use krb5_crypto::ProtocolKey;
use krb5_kdc::net_server::{
    self, Dispatch, Klog, Log, MAX_REQUEST, MAX_STREAM_DATA_CONNECTIONS, Reply, RpcSession,
    Sockets, Wake,
};
use krb5_kdc::{
    Acl, SharedDump as SharedStore, Signals, WHILE_DISPATCHING_TCP, WHILE_DISPATCHING_UDP,
};
use krb5_protocol::{AcceptorConfig, ReplayCache};

use crate::kadm5::Kadm5Conn;
use crate::listen::{client_addr, handle_kpasswd_from, kpasswd_toolong_error};
use crate::{RpcPeer, UnhandledRpc};

/// kadmind's side of the loop: kpasswd's requests and each kadm5 connection's session, over one
/// store, one ACL, one replay cache for the kadm5 acceptor and one set of acceptor profile values.
pub struct Kadmind {
    store: SharedStore,
    acl: Acl,
    cpw_key: Option<ProtocolKey>,
    rcache: ReplayCache,
    conf: Arc<AcceptorConfig>,
    report: Option<UnhandledRpc>,
}

impl Kadmind {
    /// kadmind over `store` and `acl`, its acceptors on the profile values `conf` (the KDC
    /// context's, [`AcceptorConfig::from_profile`]). A kpasswd request is verified with the
    /// `kadmin/changepw` keys the database holds, and only while there is a `cpw_key`.
    #[must_use]
    pub fn new(
        store: SharedStore,
        acl: Acl,
        cpw_key: Option<ProtocolKey>,
        conf: AcceptorConfig,
    ) -> Self {
        Self {
            store,
            acl,
            cpw_key,
            rcache: ReplayCache::new(),
            conf: Arc::new(conf),
            report: None,
        }
    }

    /// Hand the message of each kadm5 call that does not decode (it gets no reply) to `report`;
    /// without one it goes to the JSON log alone.
    #[must_use]
    pub fn report_unhandled(mut self, report: UnhandledRpc) -> Self {
        self.report = Some(report);
        self
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
    /// One kpasswd request, over UDP or TCP; a request that fails is the loop's "while
    /// dispatching" line, with no reply.
    /// MIT `dispatch` (`kadmin/server/schpw.c:420-436`): the request goes through `process_chpw_request`, and a failure is handed to the loop with no response.
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
            &self.acl,
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

    /// A kadm5 connection's session. Its acceptor keys are the database's, looked up for each
    /// context it accepts, under the database's lock, as MIT's KDB keytab reads them.
    /// MIT `krb5_db2_get_principal` (`plugins/kdb/db2/kdb_db2.c:769-773`): the KDB keytab's lookup takes the shared lock, and fails when it cannot.
    fn rpc_session(
        &mut self,
        remote: SocketAddr,
        local: SocketAddr,
    ) -> Option<Box<dyn RpcSession>> {
        Some(Box::new(Kadm5Conn::new(
            Arc::clone(&self.store),
            self.acl.clone(),
            self.realm(),
            self.rcache.clone(),
            Arc::clone(&self.conf),
            RpcPeer::new(Some(remote), Some(local)),
            self.report.clone(),
        )))
    }
}

/// Serve `sockets` to `kadmind` from one loop on this thread until SIGINT, SIGTERM or SIGQUIT,
/// SIGHUP reopening the log: kpasswd on `udp` and `tcp`, kadm5 and iprop on `rpc`, at most 45
/// connections together. Returns the descriptors of the connections still open, the newest
/// first, for kadmind's last lines.
/// MIT `main` (`kadmin/server/ovsec_kadmd.c:542-542`): `verto_run` serves until a signal ends the loop.
///
/// # Errors
///
/// The OS error of making a kpasswd socket non-blocking, or of a poll that fails other than by a
/// signal.
pub fn serve_kadmind(
    kadmind: &mut Kadmind,
    sockets: &Sockets<'_>,
    signals: &Signals,
) -> io::Result<Vec<RawFd>> {
    net_server::run(
        kadmind,
        sockets,
        MAX_STREAM_DATA_CONNECTIONS,
        MAX_REQUEST,
        &Wake::Signals(signals),
        &mut Klog,
    )
}

/// [`serve_kadmind`] until `stop` is set, looked at after each wait of at most `poll`: an
/// embedder's or a test's loop.
///
/// # Errors
///
/// As [`serve_kadmind`].
pub fn serve_kadmind_until(
    kadmind: &mut Kadmind,
    sockets: &Sockets<'_>,
    stop: &AtomicBool,
    poll: Duration,
) -> io::Result<()> {
    let wake = Wake::Flag { stop, every: poll };
    net_server::run(
        kadmind,
        sockets,
        MAX_STREAM_DATA_CONNECTIONS,
        MAX_REQUEST,
        &wake,
        &mut Klog,
    )
    .map(drop)
}
