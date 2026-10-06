//! The store's side of the update log (`lib/kdb/kdb5.c`'s `logging()` sites, `kdb_log.c`'s
//! `ulog_replay`): which changes a primary logs, when, and in what order; what a replica keeps of
//! what it applies; and what `IPROP_GET_UPDATES` answers. The log itself is [`crate::ulog`].
//!
//! A process logs only when it has mapped the realm's update log in the primary role, as MIT's
//! kadmind, kadmin.local and kdb5_util do when `iprop_enable` is set; the KDC never maps it.
//! Without a mapped log no change is logged and no file is touched.

use std::collections::HashMap;
use std::sync::Arc;

use super::PrincipalStore;
use super::iprop_xdr::encode_kdbe;
use super::kdb_convert::{
    IpropUpdate, ULOG_ADD_ATTRS, conv_2dbentry, conv_2logentry, find_changed_attrs,
};
use super::principal::{Principal, strip_db_args};
use crate::error::Error;
use crate::ulog::{Ulog, UlogBatch, UlogError, UlogLast, UlogUpdates};

/// The principals by `name@REALM`, and for each one changed since the update log last recorded
/// it, that recorded record: the one read from the database, or none for a new principal.
/// MIT `ulog_conv_2logentry` (`lib/kdb/kdb_convert.c:332-360`): a change is compared with the record the database holds before the put.
/// A change goes through `get_mut`, `insert` or `remove`, which keep the record they find first.
/// The journal holds one whole record, keys included, per principal touched: a store with a
/// database starts it again at every change, and one without grows it to every principal touched.
#[derive(Clone, Debug, Default)]
pub(crate) struct PrincipalMap {
    map: HashMap<String, Principal>,
    logged: HashMap<String, Option<Principal>>,
}

impl PrincipalMap {
    pub(crate) fn get(&self, id: &str) -> Option<&Principal> {
        self.map.get(id)
    }

    pub(crate) fn contains_key(&self, id: &str) -> bool {
        self.map.contains_key(id)
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = &String> {
        self.map.keys()
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &Principal> {
        self.map.values()
    }

    pub(crate) fn get_mut(&mut self, id: &str) -> Option<&mut Principal> {
        self.keep(id);
        self.map.get_mut(id)
    }

    pub(crate) fn insert(&mut self, id: String, p: Principal) -> Option<Principal> {
        self.keep(&id);
        self.map.insert(id, p)
    }

    pub(crate) fn remove(&mut self, id: &str) -> Option<Principal> {
        self.keep(id);
        self.map.remove(id)
    }

    /// The records' derived views only (the decrypted key history), which no update carries.
    pub(crate) fn values_mut(&mut self) -> impl Iterator<Item = &mut Principal> {
        self.map.values_mut()
    }

    /// A record read from the database, or put by a replica's apply: no change of this store's.
    pub(crate) fn insert_unlogged(&mut self, id: String, p: Principal) {
        self.map.insert(id, p);
    }

    /// A replica's delete: no change of this store's.
    fn remove_unlogged(&mut self, id: &str) {
        self.map.remove(id);
    }

    fn keep(&mut self, id: &str) {
        if !self.logged.contains_key(id) {
            let before = self.map.get(id).cloned();
            self.logged.insert(id.to_owned(), before);
        }
    }

    /// The record the update log compares a change of `id` with, which `now` replaces.
    fn log(&mut self, id: &str, now: Option<&Principal>) -> Option<Principal> {
        let before = self
            .logged
            .remove(id)
            .unwrap_or_else(|| self.map.get(id).cloned());
        self.logged.insert(id.to_owned(), now.cloned());
        before
    }
}

/// MIT `UPDATE_OK`.
pub const IPROP_OK: u32 = 0;

/// MIT `UPDATE_ERROR`: the primary could not build the answer.
pub const IPROP_ERROR: u32 = 1;

/// MIT `UPDATE_FULL_RESYNC_NEEDED`.
pub const IPROP_FULL_RESYNC: u32 = 2;

/// MIT `UPDATE_NIL`.
pub const IPROP_NIL: u32 = 4;

/// MIT `UPDATE_PERM_DENIED`.
pub const IPROP_PERM_DENIED: u32 = 5;

/// Whose update log a process maps.
/// MIT `enum iprop_role` (`include/iprop_hdr.h:32-36`): a primary logs its changes; a replica keeps what it replays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpropRole {
    /// kadmind, kadmin.local and kdb5_util on the primary: every principal put or delete is
    /// logged, and a policy change starts the log over.
    Primary,
    /// kpropd's side on a replica: the log keeps the updates it applies, as they came.
    Replica,
}

/// The update log this process mapped and its role (MIT's `kdb_log_context`), shared by the
/// store's clones and kept across its rereads.
#[derive(Debug)]
pub(crate) struct LogContext {
    pub(crate) ulog: Ulog,
    pub(crate) role: IpropRole,
}

/// A change waiting for the database write that makes it real, in the order made.
#[derive(Clone, Debug)]
pub(crate) enum LogNote {
    /// A principal put (with its record after the change and the attributes the change listed)
    /// or deleted.
    Put {
        name: String,
        deleted: bool,
        princ: Option<Box<Principal>>,
        attrs: u32,
    },
    /// A policy created, changed or deleted.
    Reset,
    /// An update a replica applied, as it came from its primary.
    Replay(Vec<u8>),
}

/// Changes made ready for the update log before the database write that holds them
/// ([`PrincipalStore::prepare_log`]), appended once it is made ([`PrincipalStore::write_logged`]).
pub struct PreparedLog(Vec<Ready>);

/// Why a logged write ([`PrincipalStore::write_logged`]) failed.
#[derive(Debug)]
pub enum LoggedWrite<E> {
    /// The log could not be marked before the write; nothing was written.
    Before(Error),
    /// The database write failed; nothing was logged.
    Write(E),
    /// The database holds the change, but the log could not take it; the log is left unstable,
    /// so its next user starts it over and the replicas resynchronize in full.
    After(Error),
}

impl LoggedWrite<Error> {
    /// The error, whichever step it came from.
    #[must_use]
    pub fn into_error(self) -> Error {
        match self {
            Self::Before(e) | Self::Write(e) | Self::After(e) => e,
        }
    }
}

/// A note made ready for the log: an update's values encoded with its keys wrapped.
pub(super) enum Ready {
    Put {
        name: String,
        deleted: bool,
        kdbe: Vec<u8>,
    },
    Reset,
    Replay(Vec<u8>),
}

fn log_error(e: &UlogError) -> Error {
    Error::Db {
        kind: match e {
            UlogError::Io(io) => io.kind(),
            _ => std::io::ErrorKind::Other,
        },
        text: e.to_string(),
    }
}

impl PrincipalStore {
    /// Master key for iprop `AT_KEYDATA`: the stash's, else (with the `test-hooks` feature)
    /// one derived from `KRB5_MASTER_PASSWORD`, else the `K/M` principal's.
    #[must_use]
    pub fn iprop_master_key(&self) -> Option<krb5_crypto::ProtocolKey> {
        if let Some((_, stash)) = &self.persist_paths
            && let Ok(bytes) = krb5_protocol::read_secret_file(stash)
        {
            if let Some(k) = crate::persist::stash_keytab_key(&bytes) {
                return Some(k);
            }
            for et in [
                krb5_crypto::EncryptionType::Aes256CtsHmacSha384192,
                krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            ] {
                if let Ok(k) = krb5_crypto::ProtocolKey::from_bytes(et, &bytes) {
                    return Some(k);
                }
            }
        }
        if let Some((_, master)) = &self.persist_master {
            return Some(master.clone());
        }
        #[cfg(feature = "test-hooks")]
        let hooked = std::env::var("KRB5_MASTER_PASSWORD")
            .ok()
            .map(zeroize::Zeroizing::new);
        #[cfg(not(feature = "test-hooks"))]
        let hooked: Option<zeroize::Zeroizing<String>> = None;
        if let Some(pw) = hooked
            && let Ok(k) = crate::master_key_from_password(
                &self.realm,
                pw.as_bytes(),
                crate::default_master_etype(),
            )
        {
            return Some(k);
        }
        self.get(&format!("K/M@{}", self.realm))
            .and_then(|km| km.best_key())
            .map(|k| k.key.clone())
    }

    /// Map the realm's update log at `path`, holding `entries` entries, in `role`: from now on
    /// this process logs (a primary) or keeps (a replica) updates there.
    /// MIT `ulog_set_role` (`lib/kdb/kdb_log.c:651-658`): the role is recorded before the log is mapped.
    ///
    /// # Errors
    ///
    /// As [`Ulog::map`].
    pub fn map_ulog(
        &mut self,
        path: &std::path::Path,
        entries: u32,
        role: IpropRole,
    ) -> Result<(), UlogError> {
        let ulog = Ulog::map(path, entries)?;
        self.set_ulog(ulog, role);
        Ok(())
    }

    /// Use `ulog` as this store's update log, in `role` (in tests, one in memory for a store with
    /// no database).
    pub fn set_ulog(&mut self, ulog: Ulog, role: IpropRole) {
        self.log = Some(Arc::new(LogContext { ulog, role }));
    }

    /// The update log this store's process mapped, when it mapped one.
    #[must_use]
    pub fn ulog(&self) -> Option<&Ulog> {
        self.log.as_deref().map(|c| &c.ulog)
    }

    /// Whether this store logs its changes: its update log is mapped, as a primary's.
    /// MIT `logging` (`lib/kdb/kdb5.c:107-114`): the log is mapped and the role is the primary's.
    #[must_use]
    pub fn logging(&self) -> bool {
        self.log
            .as_deref()
            .is_some_and(|c| c.role == IpropRole::Primary)
    }

    /// The update log's last serial: 0 when no log is mapped.
    #[must_use]
    pub fn serial(&self) -> u32 {
        self.ulog_last().map_or(0, |l| l.sno)
    }

    /// The update log's last serial and time; `None` when no log is mapped or it does not read.
    #[must_use]
    pub fn ulog_last(&self) -> Option<UlogLast> {
        self.ulog().and_then(|u| u.get_last().ok())
    }

    /// MIT iprop `GET_UPDATES` for a replica that has applied `last`: the status and the
    /// updates it lacks, as the log holds them. A log that does not read, or none mapped, is
    /// `UPDATE_ERROR`.
    /// MIT `iprop_get_updates_1_svc` (`kadmin/server/ipropd_svc.c:203-205`): the answer is `ulog_get_entries`'s.
    #[must_use]
    pub fn ulog_get_entries(&self, last: UlogLast) -> UlogUpdates {
        let error = UlogUpdates {
            status: IPROP_ERROR,
            ..UlogUpdates::default()
        };
        match self.ulog() {
            Some(u) => u.get_entries(last).unwrap_or(error),
            None => error,
        }
    }

    /// Apply a replica's updates, each in turn deleting its principal or putting the replica's
    /// record with the update applied; an update that carries nothing changes nothing, and one
    /// not committed ends the batch there, as MIT's loop never moves past it. A replica that
    /// mapped its update log keeps each update there once the database holds it, and starts the
    /// log over when an update does not apply (one whose tagged data holds database arguments
    /// included, which db2 refuses), so its next request is a full resync.
    /// MIT `ulog_replay` (`lib/kdb/kdb_log.c:423-454`): each update in turn deletes its principal or puts the replica's record with the update applied.
    /// MIT `ulog_replay` (`lib/kdb/kdb_log.c:423-425`): an update not committed is skipped without moving to the next, so none after it applies.
    /// MIT `krb5int_put_principal_no_log` (`lib/kdb/kdb5.c:970-975`): database arguments in the tagged data are taken out, and db2 refuses any.
    /// MIT `ulog_replay` (`lib/kdb/kdb_log.c:474-476`): an update that fails resets the log.
    ///
    /// # Errors
    ///
    /// As [`conv_2dbentry`], for the update that fails, or [`Error::InvalidArgument`] for one
    /// that carries database arguments; the caller's change then reads the database back.
    pub fn apply_updates(&mut self, updates: &[IpropUpdate]) -> Result<(), Error> {
        for u in updates {
            if !u.commit {
                break;
            }
            let id = krb5_types::principal_from_unparsed(&u.name, "").map_or_else(
                |_| u.name.clone(),
                |(name, realm)| crate::kdb::lookup_principal_id(&name, &realm),
            );
            if u.deleted {
                self.map.remove_unlogged(&id);
            } else if !u.vals.is_empty() {
                let put = conv_2dbentry(self.map.get(&id), &u.name, &u.vals, true).and_then(|e| {
                    let mut e = self.assign_iprop_rid(e);
                    strip_db_args(&mut e.tl_data).map(|()| e)
                });
                match put {
                    Ok(entry) => self.map.insert_unlogged(entry.id(), entry),
                    Err(e) => {
                        if let Some(u) = self.ulog() {
                            let _ = u.init_header();
                        }
                        return Err(e);
                    }
                }
            }
            if !u.raw.is_empty() {
                self.push_note(LogNote::Replay(u.raw.clone()));
            }
        }
        self.resolve_history_all();
        self.save_if_configured()
    }

    /// Incremental kdbe has no SID (vendor `0x4B0x` is stripped). A new
    /// replica row with `rid==0` must not PAC as `RID_FIRST_USER`.
    fn assign_iprop_rid(&mut self, mut p: Principal) -> Principal {
        self.settle_rid(&mut p);
        p
    }

    fn push_note(&self, note: LogNote) {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(note);
    }

    /// Record a change of `name` for the update log, with the attributes MIT's primary lists.
    /// MIT `ulog_conv_2logentry` (`lib/kdb/kdb_convert.c:338-360`): a new principal lists every attribute up to `AT_LEN`, a change what `find_changed_attrs` finds but the lockout ones.
    pub(super) fn note_ulog(&mut self, name: String, deleted: bool, princ: Option<Principal>) {
        let now = princ.as_ref().filter(|_| !deleted);
        let attrs = match (self.map.log(&name, now), now) {
            (Some(before), Some(after)) => find_changed_attrs(&before, after, true),
            (None, Some(_)) => ULOG_ADD_ATTRS,
            (_, None) => 0,
        };
        self.push_note(LogNote::Put {
            name,
            deleted,
            princ: princ.map(Box::new),
            attrs,
        });
    }

    /// Record a policy change, which starts the update log over: iprop does not carry policies,
    /// so replicas take them with a full resync.
    /// MIT `krb5_db_create_policy` (`lib/kdb/kdb5.c:2440-2457`): after a policy is created, a primary's log is reinitialized.
    /// MIT `krb5_db_put_policy` (`lib/kdb/kdb5.c:2473-2490`): after a policy is changed, a primary's log is reinitialized.
    /// MIT `krb5_db_delete_policy` (`lib/kdb/kdb5.c:2507-2524`): after a policy is deleted, a primary's log is reinitialized.
    pub(super) fn note_ulog_reset(&self) {
        self.push_note(LogNote::Reset);
    }

    /// The changes noted so far, made ready for the log: a primary's puts encoded with their keys
    /// wrapped under the master key, before the database is written. A store that does not log
    /// drops its notes (a replica keeps its replays).
    /// MIT `krb5_db_put_principal` (`lib/kdb/kdb5.c:987-999`): the update is converted before the put, and a conversion failure fails the put.
    pub(super) fn ready_notes(&self) -> Result<Vec<Ready>, Error> {
        let notes: Vec<LogNote> = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
            .collect();
        let Some(ctx) = self.log.as_deref() else {
            return Ok(Vec::new());
        };
        let primary = ctx.role == IpropRole::Primary;
        let needs_key = primary
            && notes.iter().any(|n| {
                matches!(
                    n,
                    LogNote::Put {
                        deleted: false,
                        princ: Some(_),
                        ..
                    }
                )
            });
        let mkey = if needs_key {
            Some(self.iprop_master_key().ok_or_else(|| Error::Db {
                kind: std::io::ErrorKind::Other,
                text: UlogError::Conv.to_string(),
            })?)
        } else {
            None
        };
        let wrap = |raw: &[u8]| match &mkey {
            Some(m) => {
                krb5_crypto::kdb_encrypt_key(m, raw).map_err(|e| Error::Crypto(e.to_string()))
            }
            None => Err(Error::Crypto("no master key".into())),
        };
        let mut ready = Vec::with_capacity(notes.len());
        for note in notes {
            match note {
                LogNote::Put {
                    name,
                    deleted,
                    princ,
                    attrs,
                } if primary => {
                    let vals = match (&princ, deleted) {
                        (Some(p), false) => conv_2logentry(p, attrs),
                        _ => Vec::new(),
                    };
                    ready.push(Ready::Put {
                        name,
                        deleted,
                        kdbe: encode_kdbe(&vals, &wrap)?,
                    });
                }
                LogNote::Reset if primary => ready.push(Ready::Reset),
                LogNote::Replay(raw) if !primary => ready.push(Ready::Replay(raw)),
                _ => {}
            }
        }
        Ok(ready)
    }

    /// Append `ready` to the run `batch`, in order, then end it: the database holds the changes.
    /// A replica whose log cannot keep an update leaves it unstable, so its next request is a full
    /// resync.
    /// MIT `krb5_db_put_principal` (`lib/kdb/kdb5.c:1006-1007`): the update is logged after the put, and a logging failure is the put's error.
    /// MIT `krb5_db_delete_principal` (`lib/kdb/kdb5.c:1037-1049`): a delete is logged after it is made, with no values.
    fn append_notes(mut batch: UlogBatch<'_>, ready: Vec<Ready>) -> Result<(), UlogError> {
        for r in ready {
            match r {
                Ready::Put {
                    name,
                    deleted,
                    kdbe,
                } => batch.add_update(&name, deleted, &kdbe).map(drop)?,
                Ready::Reset => batch.init_header()?,
                Ready::Replay(raw) => batch.replay_update(&raw)?,
            }
        }
        batch.finish()
    }

    /// Run `write`, the database's, with `prepared` logged around it: the update log marked
    /// unstable before the write ([`Ulog::begin`]), the updates appended after it, then marked
    /// stable. A process stopped between the write and the last append leaves the log unstable,
    /// and its next user starts it over, so a replica resynchronizes in full instead of skipping
    /// the updates the log never took. With nothing to log, `write` runs alone.
    ///
    /// # Errors
    ///
    /// [`LoggedWrite::Before`] when the log cannot be marked (nothing is written);
    /// [`LoggedWrite::Write`] with `write`'s error (nothing is logged; a replica's log starts
    /// over); [`LoggedWrite::After`] when the database holds the change but the log could not
    /// take it.
    pub fn write_logged<E>(
        &self,
        prepared: PreparedLog,
        write: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), LoggedWrite<E>> {
        let ready = prepared.0;
        let ctx = self.log.clone();
        let batch = match ctx.as_deref() {
            Some(c) if !ready.is_empty() => Some(
                c.ulog
                    .begin()
                    .map_err(|e| LoggedWrite::Before(log_error(&e)))?,
            ),
            _ => None,
        };
        if let Err(e) = write() {
            if let Some(b) = batch {
                let _ = b.abandon();
            }
            self.write_failed(&ready);
            return Err(LoggedWrite::Write(e));
        }
        match batch {
            Some(b) => Self::append_notes(b, ready).map_err(|e| LoggedWrite::After(log_error(&e))),
            None => Ok(()),
        }
    }

    /// Log the changes noted so far now: for a store with no database, whose change is made when
    /// it is noted.
    ///
    /// # Errors
    ///
    /// [`Error::Db`] when an update cannot be encoded (no master key) or the log cannot be
    /// written.
    pub fn log_pending(&self) -> Result<(), Error> {
        let prepared = self.prepare_log()?;
        self.write_logged(prepared, || Ok::<(), Error>(()))
            .map_err(LoggedWrite::into_error)
    }

    /// The changes noted so far, made ready for the log before a writer that saves the database
    /// itself writes it (`kdb5_util load -update`): each update encoded with its keys wrapped
    /// under the master key, so a change that cannot be logged is refused before anything is
    /// written. [`Self::write_logged`] appends them around the database write.
    /// MIT `krb5_db_put_principal` (`lib/kdb/kdb5.c:987-999`): the update is converted before the put, and a conversion failure fails the put.
    ///
    /// # Errors
    ///
    /// [`Error::Db`] when an update cannot be encoded (no master key, or a key that does not
    /// wrap).
    pub fn prepare_log(&self) -> Result<PreparedLog, Error> {
        self.ready_notes().map(PreparedLog)
    }

    /// Ready the noted changes, run `write` (the database's), then log them: what each MIT put
    /// does around its write ([`Self::write_logged`]). Nothing is logged when `write` fails, and
    /// a replica whose applied updates were not written starts its log over
    /// ([`Self::write_failed`]).
    pub(super) fn logged_write<E>(&self, write: impl FnOnce() -> Result<(), E>) -> Result<(), Error>
    where
        Error: From<E>,
    {
        let prepared = self.prepare_log()?;
        self.write_logged(prepared, write).map_err(|e| match e {
            LoggedWrite::Write(e) => Error::from(e),
            LoggedWrite::Before(e) | LoggedWrite::After(e) => e,
        })
    }

    /// The database write that would have held `ready` failed: a replica whose updates did not
    /// apply starts its log over, so its next request is a full resync.
    /// MIT `ulog_replay` (`lib/kdb/kdb_log.c:451-454`): a put that fails ends the replay, and the log is reinitialized.
    pub(super) fn write_failed(&self, ready: &[Ready]) {
        if ready.iter().any(|r| matches!(r, Ready::Replay(_)))
            && let Some(ctx) = self.log.as_deref()
        {
            let _ = ctx.ulog.init_header();
        }
    }
}
