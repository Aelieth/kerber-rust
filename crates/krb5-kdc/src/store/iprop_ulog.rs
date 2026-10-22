//! A primary logs its own changes; the KDC never maps the update log.

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

// MIT: `ulog_conv_2logentry` (lib/kdb/kdb_convert.c:332-360)
#[derive(Clone, Debug, Default)]
pub(crate) struct PrincipalMap {
    map: HashMap<String, Principal>,
    logged: HashMap<String, Option<Principal>>,
    undo: Undo,
}

#[derive(Clone, Debug, Default)]
enum Undo {
    #[default]
    Off,
    On(HashMap<String, Option<Principal>>),
    Lost,
}

impl PrincipalMap {
    pub(crate) fn get(&self, id: &str) -> Option<&Principal> {
        self.map.get(id)
    }

    pub(crate) fn len_u64(&self) -> u64 {
        u64::try_from(self.map.len()).unwrap_or(u64::MAX)
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

    pub(crate) fn values_mut(&mut self) -> impl Iterator<Item = &mut Principal> {
        self.map.values_mut()
    }

    pub(crate) fn insert_unlogged(&mut self, id: String, p: Principal) {
        self.lose_undo();
        self.map.insert(id, p);
    }

    pub(crate) fn get_mut_unlogged(&mut self, id: &str) -> Option<&mut Principal> {
        self.map.get_mut(id)
    }

    pub(crate) fn remove_unlogged(&mut self, id: &str) {
        self.lose_undo();
        self.map.remove(id);
    }

    fn lose_undo(&mut self) {
        if matches!(self.undo, Undo::On(_)) {
            self.undo = Undo::Lost;
        }
    }

    fn keep(&mut self, id: &str) {
        if !self.logged.contains_key(id) {
            let before = self.map.get(id).cloned();
            self.logged.insert(id.to_owned(), before);
        }
        let map = &self.map;
        if let Undo::On(undo) = &mut self.undo {
            undo.entry(id.to_owned())
                .or_insert_with(|| map.get(id).cloned());
        }
    }

    pub(crate) fn begin_change(&mut self) {
        self.logged.clear();
        self.undo = Undo::On(HashMap::new());
    }

    pub(crate) fn touched(&self) -> Option<Vec<String>> {
        let Undo::On(before) = &self.undo else {
            return None;
        };
        let mut ids: Vec<String> = before.keys().cloned().collect();
        ids.sort();
        Some(ids)
    }

    pub(crate) fn end_change(&mut self) {
        self.undo = Undo::Off;
    }

    pub(crate) fn undo_change(&mut self) -> bool {
        let Undo::On(before) = std::mem::take(&mut self.undo) else {
            return false;
        };
        for (id, p) in before {
            match p {
                Some(p) => {
                    self.map.insert(id, p);
                }
                None => {
                    self.map.remove(&id);
                }
            }
        }
        self.logged.clear();
        true
    }

    fn log(&mut self, id: &str, now: Option<&Principal>) -> Option<Principal> {
        let before = self
            .logged
            .remove(id)
            .unwrap_or_else(|| self.map.get(id).cloned());
        self.logged.insert(id.to_owned(), now.cloned());
        before
    }
}

pub const IPROP_OK: u32 = 0;

pub const IPROP_ERROR: u32 = 1;

pub const IPROP_FULL_RESYNC: u32 = 2;

pub const IPROP_NIL: u32 = 4;

pub const IPROP_PERM_DENIED: u32 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpropRole {
    Primary,
    Replica,
}

#[derive(Debug)]
pub(crate) struct LogContext {
    pub(crate) ulog: Ulog,
    pub(crate) role: IpropRole,
}

#[derive(Clone, Debug)]
pub(crate) enum LogNote {
    Put {
        name: String,
        deleted: bool,
        princ: Option<Box<Principal>>,
        attrs: u32,
    },
    Reset,
    Replay(Vec<u8>),
}

pub struct PreparedLog(Vec<Ready>);

#[derive(Debug)]
pub enum LoggedWrite<E> {
    Before(Error),
    Write(E),
    /// The log stays unstable, so replicas resync in full.
    After(Error),
}

impl LoggedWrite<Error> {
    #[must_use]
    pub fn into_error(self) -> Error {
        match self {
            Self::Before(e) | Self::Write(e) | Self::After(e) => e,
        }
    }
}

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
        #[allow(clippy::disallowed_methods, reason = "a test-hooks build's override")]
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

    // MIT: `ulog_set_role` (lib/kdb/kdb_log.c:651-658)
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

    pub fn set_ulog(&mut self, ulog: Ulog, role: IpropRole) {
        self.log = Some(Arc::new(LogContext { ulog, role }));
    }

    #[must_use]
    pub fn ulog(&self) -> Option<&Ulog> {
        self.log.as_deref().map(|c| &c.ulog)
    }

    // MIT: `logging` (lib/kdb/kdb5.c:107-114)
    #[must_use]
    pub fn logging(&self) -> bool {
        self.log
            .as_deref()
            .is_some_and(|c| c.role == IpropRole::Primary)
    }

    #[must_use]
    pub fn serial(&self) -> u32 {
        self.ulog_last().map_or(0, |l| l.sno)
    }

    #[must_use]
    pub fn ulog_last(&self) -> Option<UlogLast> {
        self.ulog().and_then(|u| u.get_last().ok())
    }

    // MIT: `iprop_get_updates_1_svc` (kadmin/server/ipropd_svc.c:203-205)
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

    // MIT: `ulog_replay` (lib/kdb/kdb_log.c:423-454)
    // MIT: `krb5int_put_principal_no_log` (lib/kdb/kdb5.c:970-975)
    // MIT: `ulog_replay` (lib/kdb/kdb_log.c:423-425)
    // MIT: `ulog_replay` (lib/kdb/kdb_log.c:474-476)
    pub fn apply_updates(&mut self, updates: &[IpropUpdate]) -> Result<(), Error> {
        self.inside_change()?;
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

    /// A new row's RID of 0 would PAC as the first user.
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

    // MIT: `krb5_db_create_policy` (lib/kdb/kdb5.c:2440-2457)
    // MIT: `krb5_db_put_policy` (lib/kdb/kdb5.c:2473-2490)
    // MIT: `krb5_db_delete_policy` (lib/kdb/kdb5.c:2507-2524)
    /// Policies are not carried, so a change starts the log over.
    pub(super) fn note_ulog_reset(&self) {
        self.push_note(LogNote::Reset);
    }

    // MIT: `krb5_db_put_principal` (lib/kdb/kdb5.c:987-999)
    /// Logged keys are wrapped; no master key fails the change.
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

    // MIT: `krb5_db_put_principal` (lib/kdb/kdb5.c:1006-1007)
    // MIT: `krb5_db_delete_principal` (lib/kdb/kdb5.c:1037-1049)
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

    pub fn log_pending(&self) -> Result<(), Error> {
        let prepared = self.prepare_log()?;
        self.write_logged(prepared, || Ok::<(), Error>(()))
            .map_err(LoggedWrite::into_error)
    }

    pub fn prepare_log(&self) -> Result<PreparedLog, Error> {
        self.ready_notes().map(PreparedLog)
    }

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

    pub(super) fn write_failed(&self, ready: &[Ready]) {
        if ready.iter().any(|r| matches!(r, Ready::Replay(_)))
            && let Some(ctx) = self.log.as_deref()
        {
            let _ = ctx.ulog.init_header();
        }
    }
}
