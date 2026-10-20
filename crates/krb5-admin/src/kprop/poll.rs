//! kpropd's iprop mode on a replica (MIT `kprop/kpropd.c`'s `do_iprop`): it polls the primary's
//! kadmind for the updates after its own update log and applies them, asks for a full resync when
//! the log cannot bridge the gap (the dump then comes to kpropd's listener), and backs off while
//! the primary is busy or cannot be reached.

use std::net::{TcpStream, ToSocketAddrs as _};
use std::path::Path;
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use krb5_config::{IpropParams, Krb5Conf};
use krb5_kdc::{IpropRole, PrincipalStore, Ulog};
use krb5_log::klog::{self, Severity};
use krb5_protocol::trace::{ERROR_TABLE_BASE_KRB5, error_message};
use krb5_types::PrincipalName;

use super::send::init_creds_keytab;
use crate::kadm5::{
    IncrReply, IpropClient, KADM5_BAD_PASSWORD, KADM5_CANT_RESOLVE, KADM5_GSS_ERROR,
    KADM5_MISSING_KRB5_CONF_PARAMS, KADM5_RPC_ERROR, KADM5_SECURE_PRINC_MISSING,
    kadm5_error_message,
};

/// MIT `KIPROP_SVC_NAME` (`include/iprop_hdr.h:29-29`): the service of a replica's and a primary's iprop principals.
const KIPROP_SVC_NAME: &str = "kiprop";

/// MIT `MAX_BACKOFF` (`include/iprop_hdr.h:30-30`): the longest wait, in seconds, between tries of a busy or unreachable primary.
const MAX_BACKOFF: u32 = 300;

/// MIT `UPDATE_BUSY`: the primary asks the replica to come back later.
const UPDATE_BUSY: u32 = 3;

/// What kpropd's iprop mode runs with: its options and the realm's iprop parameters.
#[derive(Debug)]
pub struct KpropdIprop<'a> {
    /// The name kpropd was run as, which leads its `com_err` lines.
    pub progname: &'a str,
    /// The realm.
    pub realm: &'a str,
    /// `-s`: the keytab with `kiprop/<this host>`'s keys; `None` is the default keytab.
    pub keytab: Option<&'a str>,
    /// `-A`, else the realm's `admin_server`, its port taken off: the primary.
    pub admin_server: Option<&'a str>,
    /// The realm's iprop parameters: the port, the poll interval, the resync timeout, the log.
    pub params: &'a IpropParams,
    /// The replica's database.
    pub db: &'a Path,
    /// The replica's stash.
    pub stash: &'a Path,
    /// `-t`: return after the first answer that is not "full resync needed".
    pub runonce: bool,
    /// `-d`: the debug lines on standard error, and `com_err` there instead of syslog.
    pub debug: bool,
    /// kpropd's profile, the KDC context's, read when kpropd started.
    pub profile: &'a Krb5Conf,
}

/// What ends the poller's wait early: SIGUSR1, or the listener after a full propagation.
#[derive(Debug, Default)]
pub struct IpropWake {
    poked: Mutex<bool>,
    cv: Condvar,
}

impl IpropWake {
    /// End the wait under way now.
    /// MIT `do_standalone` (`kprop/kpropd.c:466-471`): after each full propagation the listener signals the iprop parent with SIGUSR1.
    pub fn poke(&self) {
        *self.poked.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.cv.notify_all();
    }

    /// Wait `secs` seconds, or until poked. A poke from before the wait does not count, as a
    /// signal that comes outside MIT's `sleep` interrupts nothing.
    /// MIT `usr1_handler` (`kprop/kpropd.c:222-225`): SIGUSR1 does nothing but interrupt the `sleep`.
    fn sleep(&self, secs: u32) {
        let end = Instant::now() + Duration::from_secs(u64::from(secs));
        let mut poked = self.poked.lock().unwrap_or_else(PoisonError::into_inner);
        *poked = false;
        while !*poked {
            let Some(left) = end.checked_duration_since(Instant::now()) else {
                break;
            };
            poked = self
                .cv
                .wait_timeout(poked, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        *poked = false;
    }
}

/// Where the iprop mode's lines go: `com_err`'s to syslog, or with `-d` to standard error, and
/// the debug lines to standard error with `-d` only.
struct Log<'a> {
    progname: &'a str,
    debug: bool,
}

impl Log<'_> {
    /// MIT `kpropd_com_err_proc` (`kprop/kpropd.c:1030-1040`): `whoami: `, the code's text and a space, then the message, at `LOG_ERR`; with `-d` the default `com_err` on standard error.
    fn com_err(&self, code: Option<&str>, msg: &str) {
        let line = match code {
            Some(text) => format!("{}: {text} {msg}", self.progname),
            None => format!("{}: {msg}", self.progname),
        };
        if self.debug {
            eprintln!("{line}");
        } else {
            klog::syslog(Severity::Err, &line);
        }
    }

    fn debug(&self, msg: &str) {
        if self.debug {
            eprintln!("{msg}");
        }
    }
}

/// kpropd's iprop mode: poll the primary for the updates after this replica's update log, apply
/// them, ask for a full resync when the primary says one is needed, and back off while it is busy
/// or unreachable. It returns only when the primary answers an error, the update log or the
/// replica's name fails, or with `-t` after the first answer that is not "full resync needed":
/// 0 then with `-t`, 1 without, as MIT's.
/// MIT `do_iprop` (`kprop/kpropd.c:634-1003`): the kiprop handle made with backoff, then the loop on `IPROP_GET_UPDATES` and its answers.
#[must_use]
pub fn kpropd_do_iprop(cfg: &KpropdIprop<'_>, wake: &IpropWake) -> i32 {
    let log = Log {
        progname: cfg.progname,
        debug: cfg.debug,
    };
    let done = || i32::from(!cfg.runonce);
    let bail = || {
        log.debug("ERROR returned by primary, bailing");
        klog::syslog(Severity::Err, "ERROR returned by primary KDC, bailing.");
        done()
    };
    log.debug("Incremental propagation enabled");
    // MIT `do_iprop` (`kprop/kpropd.c:653-655`): the poll interval, 10 seconds when it is 0.
    let pollin = match cfg.params.poll_time.cast_unsigned() {
        0 => 10,
        t => t,
    };
    let conf = cfg.profile;
    // MIT `sn2princ_realm` (`kprop/kprop_util.c:35-57`): `kiprop` and this host, host-based, in kpropd's realm.
    let me = krb5_config::local_host_name(conf);
    let Ok(client) =
        PrincipalName::try_new(PrincipalName::NT_SRV_HST, [KIPROP_SVC_NAME, me.as_str()])
    else {
        log.com_err(None, "while trying to construct host service principal");
        return done();
    };
    let client_name = format!("{}@{}", client.unparse_no_realm(), cfg.realm);
    let ulog = match Ulog::map(&cfg.params.logfile, cfg.params.ulogsize) {
        Ok(u) => u,
        Err(e) => {
            log.com_err(Some(&e.to_string()), "reading update log header");
            return done();
        }
    };
    let mut store = None;
    let (mut reinit_cnt, mut backoff_cnt) = (0, 0);
    let mut frrequested: Option<i64> = None;
    'reinit: loop {
        log.debug(&format!("Initializing kadm5 as client {client_name}"));
        let mut handle = match kiprop_init(cfg, conf, &client) {
            Ok(h) => h,
            // MIT `do_iprop` (`kprop/kpropd.c:701-741`): a failed init is retried after a backoff, and an RPC failure is told apart.
            Err(InitFailure { rpc, text }) => {
                log.debug("kadm5 initialization failed!");
                reinit_cnt += 1;
                let (during, why) = if rpc {
                    (
                        "while attempting to connect to primary KDC ... retrying".to_owned(),
                        "(RPC ERROR)",
                    )
                } else {
                    (
                        format!("while initializing {} interface, retrying", cfg.progname),
                        "(krb5kdc not running?)",
                    )
                };
                log.com_err(Some(&text), &during);
                let backoff = backoff_from_primary(&mut reinit_cnt);
                log.debug(&format!(
                    "Sleeping {backoff} seconds to re-initialize kadm5 {why}"
                ));
                wake.sleep(backoff);
                continue;
            }
        };
        log.debug("kadm5 initialization succeeded");
        reinit_cnt = 0;
        loop {
            let mylast = match ulog.get_last() {
                Ok(l) => l,
                Err(e) => {
                    log.com_err(Some(&e.to_string()), "reading update log header");
                    return done();
                }
            };
            log.debug(&format!(
                "Calling iprop_get_updates_1 (sno={} sec={} usec={})",
                mylast.sno, mylast.time.seconds, mylast.time.useconds
            ));
            let start = Instant::now();
            // MIT `do_iprop` (`kprop/kpropd.c:784-797`): a failed call is printed by `clnt_perror` and the handle is made again.
            let incr = match handle.get_updates(mylast) {
                Ok(r) => r,
                Err(f) => {
                    eprintln!("{}", f.sperror("iprop_get_updates call failed"));
                    log.debug("Reinitializing iprop because get updates failed");
                    continue 'reinit;
                }
            };
            match incr.status {
                // MIT `do_iprop` (`kprop/kpropd.c:801-876`): a full resync is asked for unless one asked for is still within `iprop_resync_timeout`.
                krb5_kdc::IPROP_FULL_RESYNC => {
                    let now = unix_now();
                    if frrequested.is_some_and(|at| now - at < i64::from(cfg.params.resync_timeout))
                    {
                        log.debug("Still waiting for full resync");
                    } else {
                        frrequested = Some(now);
                        log.debug("Full resync needed");
                        klog::syslog(Severity::Info, "kpropd: Full resync needed.");
                        match handle.full_resync() {
                            Err(f) => {
                                eprintln!("{}", f.sperror("iprop_full_resync call failed"));
                                continue 'reinit;
                            }
                            Ok(krb5_kdc::IPROP_OK) => {
                                log.debug("Full resync request granted");
                                klog::syslog(Severity::Info, "Full resync request granted.");
                                backoff_cnt = 0;
                            }
                            Ok(UPDATE_BUSY) => {
                                log.debug("Exponential backoff");
                                backoff_cnt += 1;
                            }
                            Ok(krb5_kdc::IPROP_PERM_DENIED) => {
                                log.debug("Full resync permission denied");
                                klog::syslog(Severity::Err, "Full resync, permission denied.");
                                return bail();
                            }
                            Ok(krb5_kdc::IPROP_ERROR) => {
                                log.debug("Full resync error from primary");
                                klog::syslog(
                                    Severity::Err,
                                    " Full resync, error returned from primary KDC.",
                                );
                                return bail();
                            }
                            Ok(_) => {
                                backoff_cnt = 0;
                                log.debug("Full resync invalid result from primary");
                                klog::syslog(
                                    Severity::Err,
                                    "Full resync, invalid return from primary KDC.",
                                );
                            }
                        }
                    }
                }
                // MIT `do_iprop` (`kprop/kpropd.c:878-918`): the updates are replayed into the database and kept in the update log; a replay that fails is logged and the poll goes on.
                krb5_kdc::IPROP_OK => {
                    backoff_cnt = 0;
                    frrequested = None;
                    log.debug(&format!(
                        "Got incremental updates (sno={} sec={} usec={})",
                        incr.last.sno, incr.last.time.seconds, incr.last.time.useconds
                    ));
                    if let Err(msg) = ulog_replay(cfg, &mut store, &incr) {
                        log.debug(&format!(
                            "ulog_replay failed ({msg}), updates not registered"
                        ));
                        klog::syslog(
                            Severity::Err,
                            &format!("ulog_replay failed ({msg}), updates not registered."),
                        );
                    } else {
                        let line = format!(
                            "Incremental updates: {} updates / {} us",
                            incr.count,
                            start.elapsed().as_micros()
                        );
                        klog::syslog(Severity::Info, &line);
                        log.debug(&line);
                    }
                }
                krb5_kdc::IPROP_PERM_DENIED => {
                    log.debug("get_updates permission denied");
                    klog::syslog(Severity::Err, "get_updates, permission denied.");
                    return bail();
                }
                krb5_kdc::IPROP_ERROR => {
                    log.debug("get_updates error from primary");
                    klog::syslog(
                        Severity::Err,
                        "get_updates, error returned from primary KDC.",
                    );
                    return bail();
                }
                UPDATE_BUSY => {
                    log.debug("get_updates primary busy; backoff");
                    backoff_cnt += 1;
                }
                krb5_kdc::IPROP_NIL => {
                    log.debug("KDC is synchronized with primary.");
                    backoff_cnt = 0;
                    frrequested = None;
                }
                _ => {
                    backoff_cnt = 0;
                    log.debug("get_updates invalid result from primary");
                    klog::syslog(
                        Severity::Err,
                        "get_updates, invalid return from primary KDC.",
                    );
                }
            }
            // MIT `do_iprop` (`kprop/kpropd.c:961-985`): `-t` stops after the first answer that is not "full resync needed"; else the poll interval, or the backoff while the primary is busy.
            if cfg.runonce && incr.status != krb5_kdc::IPROP_FULL_RESYNC {
                return done();
            }
            if backoff_cnt > 0 {
                let backoff = backoff_from_primary(&mut backoff_cnt);
                log.debug(&format!(
                    "Busy signal received from primary, backoff for {backoff} secs"
                ));
                wake.sleep(backoff);
            } else {
                log.debug(&format!(
                    "Waiting for {pollin} seconds before checking for updates again"
                ));
                wake.sleep(pollin);
            }
        }
    }
}

/// The seconds to wait before trying a busy or unreachable primary again: `2 << cnt`, at most
/// [`MAX_BACKOFF`], the count stepped back when the cap is hit.
/// MIT `backoff_from_primary` (`kprop/kpropd.c:1008-1019`): the doubling, capped at `MAX_BACKOFF`.
fn backoff_from_primary(cnt: &mut u32) -> u32 {
    let btime = 2u32.checked_shl(*cnt).unwrap_or(u32::MAX);
    if btime > MAX_BACKOFF {
        *cnt -= 1;
        return MAX_BACKOFF;
    }
    btime
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Why kpropd's kiprop handle could not be made: the text of the code `kadm5_init_with_skey`
/// returned, and whether that code is `KADM5_RPC_ERROR`, which `do_iprop` tells apart.
struct InitFailure {
    rpc: bool,
    text: String,
}

impl InitFailure {
    fn kadm5(code: u32) -> Self {
        Self {
            rpc: code == KADM5_RPC_ERROR,
            text: kadm5_error_message(code),
        }
    }
}

/// kpropd's handle on the primary's iprop service: the parameters checked,
/// `kiprop/<this host>`'s credentials for `kiprop/<admin server>` from the keytab, the
/// connection to the iprop port, and the RPCSEC_GSS context.
/// MIT `init_any` (`lib/kadm5/clnt/client_init.c:172-361`): the admin server is required; the credentials come first, then the connection to `iprop_port`, then the context, and a kiprop handle makes no init call.
/// MIT `kadm5_get_kiprop_host_srv_name` (`kprop/kpropd.c:1617-1630`): the service is `kiprop/` and the admin server.
/// MIT `get_init_creds` (`lib/kadm5/clnt/client_init.c:366-434`): a decrypt failure is `KADM5_BAD_PASSWORD`, an unknown service `KADM5_SECURE_PRINC_MISSING`.
fn kiprop_init(
    cfg: &KpropdIprop<'_>,
    conf: &Krb5Conf,
    client: &PrincipalName,
) -> Result<IpropClient, InitFailure> {
    let admin = cfg
        .admin_server
        .ok_or_else(|| InitFailure::kadm5(KADM5_MISSING_KRB5_CONF_PARAMS))?;
    let service = format!("{KIPROP_SVC_NAME}/{admin}");
    let creds =
        init_creds_keytab(conf, cfg.realm, client, &service, cfg.keytab, true).map_err(|e| {
            let text = e.com_err.and_then(|(code, _)| code).unwrap_or_default();
            let is = |n: i64| text == error_message(ERROR_TABLE_BASE_KRB5 + n);
            if is(31) {
                InitFailure::kadm5(KADM5_BAD_PASSWORD)
            } else if is(7) {
                InitFailure::kadm5(KADM5_SECURE_PRINC_MISSING)
            } else {
                InitFailure { rpc: false, text }
            }
        })?;
    let stream =
        connect_to_server(admin, cfg.params.port.unwrap_or(0)).map_err(InitFailure::kadm5)?;
    IpropClient::establish(
        stream,
        creds.ticket,
        &creds.session,
        &creds.crealm,
        &creds.client,
    )
    .map_err(|_| InitFailure::kadm5(KADM5_GSS_ERROR))
}

/// A connection to `host` at `port`, each of its addresses tried in turn.
/// MIT `connect_to_server` (`lib/kadm5/clnt/client_init.c:521-561`): a name that does not resolve is `KADM5_CANT_RESOLVE`, no address that connects `KADM5_RPC_ERROR`.
fn connect_to_server(host: &str, port: i32) -> Result<TcpStream, u32> {
    let port = u16::try_from(port).map_err(|_| KADM5_CANT_RESOLVE)?;
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|_| KADM5_CANT_RESOLVE)?;
    addrs
        .into_iter()
        .find_map(|a| TcpStream::connect(a).ok())
        .ok_or(KADM5_RPC_ERROR)
}

/// Apply `incr`'s updates to the replica's database, which is read when first needed and kept,
/// and keep each in the update log; the failure's text when they do not apply.
/// MIT `ulog_replay` (`lib/kdb/kdb_log.c:401-480`): the database opened, each update put or deleted without being logged again, then stored in the update log.
fn ulog_replay(
    cfg: &KpropdIprop<'_>,
    store: &mut Option<PrincipalStore>,
    incr: &IncrReply,
) -> Result<(), String> {
    if store.is_none() {
        let mut s = krb5_kdc::load_store(cfg.db, cfg.stash).map_err(|e| e.to_string())?;
        s.persist_paths = Some((cfg.db.to_path_buf(), cfg.stash.to_path_buf()));
        s.map_ulog(&cfg.params.logfile, cfg.params.ulogsize, IpropRole::Replica)
            .map_err(|e| e.to_string())?;
        *store = Some(s);
    }
    let Some(s) = store.as_mut() else {
        return Err("no database".into());
    };
    let updates = incr
        .updates(s.iprop_master_key().as_ref())
        .map_err(|e| e.to_string())?;
    s.change(|s| s.apply_updates(&updates))
        .and_then(|applied| applied)
        .map_err(|e| e.to_string())
}
