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
use krb5_kdc::principals::{kadmin_admin, kadmin_changepw, kadmin_history};
use krb5_kdc::{
    Acl, PrincipalStore, SharedDump as SharedStore, Signals, WHILE_DISPATCHING_TCP,
    WHILE_DISPATCHING_UDP,
};
use krb5_log::klog::{self, Severity};
use krb5_protocol::ReplayCache;

use crate::kadm5::Kadm5Conn;
use crate::listen::{client_addr, handle_kpasswd_from, kpasswd_toolong_error};
use crate::{RpcPeer, UnhandledRpc};

/// kadmind's side of the loop: kpasswd's requests and each kadm5 connection's session, over one
/// store, one ACL and one replay cache for the kadm5 acceptor.
pub struct Kadmind {
    store: SharedStore,
    acl: Acl,
    cpw_key: Option<ProtocolKey>,
    rcache: ReplayCache,
    report: Option<UnhandledRpc>,
}

impl Kadmind {
    /// kadmind over `store` and `acl`. A kpasswd request is verified with the `kadmin/changepw`
    /// keys the database holds and `cpw_key`; without `cpw_key` it gets no answer.
    #[must_use]
    pub fn new(store: SharedStore, acl: Acl, cpw_key: Option<ProtocolKey>) -> Self {
        Self {
            store,
            acl,
            cpw_key,
            rcache: ReplayCache::new(),
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
        let Some(key) = &self.cpw_key else {
            return Reply::Nothing;
        };
        let replay = ReplayCache::new();
        let from = client_addr(remote.ip());
        let here = Some(local.ip());
        match handle_kpasswd_from(&self.store, &self.acl, key, &replay, request, &from, here) {
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

    /// A kadm5 connection's session, with the acceptor keys as the database holds them now,
    /// read under its lock as MIT's KDB keytab reads them for each context: a lock that may not
    /// be taken leaves the session no key, so no context is accepted.
    /// MIT `krb5_db2_get_principal` (`plugins/kdb/db2/kdb_db2.c:769-773`): the KDB keytab's lookup takes the shared lock, and fails when it cannot.
    fn rpc_session(
        &mut self,
        remote: SocketAddr,
        local: SocketAddr,
    ) -> Option<Box<dyn RpcSession>> {
        let (keys, realm) = {
            let mut g = self.store.write().unwrap_or_else(PoisonError::into_inner);
            let keys = match g.reload_if_stale() {
                Ok(()) => acceptor_keys(&g),
                Err(e) => {
                    klog::syslog(Severity::Err, &format!("{e} while reloading database"));
                    Vec::new()
                }
            };
            (keys, g.realm().to_owned())
        };
        Some(Box::new(Kadm5Conn::new(
            Arc::clone(&self.store),
            self.acl.clone(),
            keys,
            realm,
            self.rcache.clone(),
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

/// The keys a kadm5 or iprop client may authenticate to: the realm's `kadmin/admin`,
/// `kadmin/changepw` and `kadmin/history`, and every `kiprop/<host>` (a replica's iprop service).
/// The RPC layer then admits only the acceptor names each program allows.
/// MIT `setup_kdb_keytab` (`kadmin/server/ovsec_kadmd.c:178-190`): the acceptor keytab is the
/// whole database, and `check_rpcsec_auth` decides which names may call.
#[must_use]
pub fn acceptor_keys(store: &PrincipalStore) -> Vec<ProtocolKey> {
    let mut keys = Vec::new();
    for name in [kadmin_admin(), kadmin_changepw(), kadmin_history()] {
        if let Some(p) = store.get_name(&name) {
            keys.extend(p.keys.iter().map(|k| k.key.clone()));
        }
    }
    let realm_suffix = format!("@{}", store.realm());
    for id in store.ids() {
        let Some(name) = id.strip_suffix(&realm_suffix) else {
            continue;
        };
        if let Some(host) = name.strip_prefix("kiprop/")
            && !host.is_empty()
            && !host.contains('/')
            && let Some(p) = store.get(&id)
        {
            keys.extend(p.keys.iter().map(|k| k.key.clone()));
        }
    }
    keys
}
