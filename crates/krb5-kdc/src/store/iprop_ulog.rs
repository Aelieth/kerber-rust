//! Incremental-propagation update log (`kdb_log.c`, `kdb_incr_update`):
//! the ring, `GET_UPDATES` status, replica apply, and the
//! principal-only ship rule (policy changes never enter the ulog).

use std::collections::HashMap;
use std::sync::atomic::Ordering;

use super::kdb_convert::{
    IpropUpdate, KdbeVal, ULOG_ADD_ATTRS, conv_2dbentry, conv_2logentry, find_changed_attrs,
};
use super::principal::{Principal, strip_db_args};
use super::{PrincipalStore, unix_now_u32};

/// Circular iprop update-log entry (serial-numbered; MIT `kdb_incr_update`).
#[derive(Clone, Debug)]
pub struct UlogEntry {
    /// Monotonic serial (`kdb_sno_t`).
    pub sno: u32,
    /// Unix seconds.
    pub time: u32,
    /// Unparsed `name@REALM` (or `policy:<name>`).
    pub name: String,
    /// Deletion marker.
    pub deleted: bool,
    /// The record after the change: the values the update sends.
    pub princ: Option<Principal>,
    /// The attributes the change touched, as MIT lists them (bit `n` is `kdbe_attr_type_t` `n`).
    pub attrs: u32,
}

impl UlogEntry {
    /// The update this entry sends: its listed attributes of the record, as MIT's primary
    /// converts them.
    #[must_use]
    pub fn kdbe_vals(&self) -> Vec<KdbeVal> {
        match (&self.princ, self.deleted) {
            (Some(p), false) => conv_2logentry(p, self.attrs),
            _ => Vec::new(),
        }
    }

    /// The update as a replica receives it.
    #[must_use]
    pub fn to_update(&self) -> IpropUpdate {
        IpropUpdate {
            sno: self.sno,
            time: self.time,
            name: self.name.clone(),
            deleted: self.deleted,
            vals: self.kdbe_vals(),
        }
    }
}

/// A local `policy:<name>` marker, which only advances the serial: a policy name cannot contain
/// `@` (`svr_policy`) and a principal id always ends in `@REALM`.
fn is_policy_marker(name: &str) -> bool {
    name.starts_with("policy:") && !name.contains('@')
}

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

const ULOG_CAP: usize = 1024;

/// MIT `UPDATE_OK`.
pub const IPROP_OK: u32 = 0;

/// MIT `UPDATE_ERROR`: the master could not build the update (here: no master
/// key to wrap the plaintext keys the Rust store holds, so it refuses rather
/// than ship them in the clear).
pub const IPROP_ERROR: u32 = 1;

/// MIT `UPDATE_FULL_RESYNC_NEEDED`.
pub const IPROP_FULL_RESYNC: u32 = 2;

/// MIT `UPDATE_NIL`.
pub const IPROP_NIL: u32 = 4;

/// MIT `UPDATE_PERM_DENIED`.
pub const IPROP_PERM_DENIED: u32 = 5;

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

    /// Monotonic iprop serial (0 = never mutated via save).
    #[must_use]
    pub fn serial(&self) -> u32 {
        self.serial.load(Ordering::SeqCst)
    }

    /// Set serial after dump load (`TL_KERBER_SERIAL`).
    pub(crate) fn set_serial(&self, sno: u32) {
        self.serial.store(sno, Ordering::SeqCst);
    }

    /// Reload ulog entries from persist (`{db}.ulog`).
    pub(crate) fn restore_ulog(&self, entries: Vec<UlogEntry>) {
        let mut log = self
            .ulog
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *log = entries.into();
    }

    /// Snapshot of the update log (oldest first).
    #[must_use]
    pub fn ulog(&self) -> Vec<UlogEntry> {
        self.ulog
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    /// Entries with `sno > last_sno`.
    #[must_use]
    pub fn updates_after(&self, last_sno: u32) -> Vec<UlogEntry> {
        self.ulog()
            .into_iter()
            .filter(|e| e.sno > last_sno)
            .collect()
    }

    /// MIT iprop GET_UPDATES: `(status, last_sno, entries)`.
    ///
    /// `last_sno == 0` is first contact → full resync. A gap in the
    /// circular log also returns full resync.
    #[must_use]
    pub fn iprop_get(&self, last_sno: u32) -> (u32, u32, Vec<UlogEntry>) {
        let cur = self.serial();
        if last_sno == 0 {
            return (IPROP_FULL_RESYNC, cur, Vec::new());
        }
        if last_sno == cur {
            return (IPROP_NIL, cur, Vec::new());
        }
        // MIT `get_sno_status` (`kdb_log.c:142-165`): a replica whose serial is
        // AHEAD of the master's (a primary restored from an older dump, or a
        // replica repointed at a different primary) is `UPDATE_FULL_RESYNC_NEEDED`,
        // never `UPDATE_NIL`. (MIT also resyncs when `last_sno`'s timestamp does
        // not match the ulog entry's — a reused serial; the Rust replica does not
        // yet thread `last_time`, tracked as a residual.)
        if last_sno > cur {
            return (IPROP_FULL_RESYNC, cur, Vec::new());
        }
        let entries = self.updates_after(last_sno);
        if entries.is_empty() {
            return (IPROP_FULL_RESYNC, cur, Vec::new());
        }
        let first = entries.first().map_or(0, |e| e.sno);
        if last_sno.saturating_add(1) < first {
            return (IPROP_FULL_RESYNC, cur, Vec::new());
        }
        // MIT never logs policy changes (kdb5.c krb5_db_create_policy /
        // put_policy / delete_policy add no ulog entry; kpropd's ulog_replay
        // knows principals only), so policies reach a replica by full resync.
        // The local `policy:<name>` markers only advance the serial. A policy
        // name cannot contain `@` (svr_policy) and a principal id always ends
        // in `@REALM`, so the `@` distinguishes a marker from a principal
        // literally named `policy:...@REALM` (which must NOT be filtered).
        let entries = entries
            .into_iter()
            .filter(|e| !is_policy_marker(&e.name))
            .collect();
        (IPROP_OK, cur, entries)
    }

    /// Apply serial-delta (does not re-log).
    ///
    /// MIT `ulog_replay` (`lib/kdb/kdb_log.c:423-454`): each update in turn deletes its principal or puts the replica's record with the update applied.
    /// An update that carries nothing changes nothing, and one whose tagged data holds database
    /// arguments is skipped.
    ///
    /// # Errors
    ///
    /// As [`conv_2dbentry`], for the update that fails; the caller's change then reads the
    /// database back.
    pub fn apply_updates(&mut self, updates: &[IpropUpdate]) -> Result<(), crate::Error> {
        for u in updates {
            let id = krb5_types::principal_from_unparsed(&u.name, "").map_or_else(
                |_| u.name.clone(),
                |(name, realm)| crate::kdb::lookup_principal_id(&name, &realm),
            );
            if u.deleted {
                self.map.remove_unlogged(&id);
            } else if !u.vals.is_empty() {
                let entry = conv_2dbentry(self.map.get(&id), &u.name, &u.vals, true)?;
                let mut entry = self.assign_iprop_rid(entry);
                if strip_db_args(&mut entry.tl_data).is_ok() {
                    self.map.insert_unlogged(entry.id(), entry);
                }
            }
            let cur = self.serial();
            if u.sno > cur {
                self.serial.store(u.sno, Ordering::SeqCst);
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

    /// Record a change of `name` for the update log, with the attributes MIT's primary lists.
    /// MIT `ulog_conv_2logentry` (`lib/kdb/kdb_convert.c:338-360`): a new principal lists every attribute up to `AT_LEN`, a change what `find_changed_attrs` finds but the lockout ones.
    pub(super) fn note_ulog(&mut self, name: String, deleted: bool, princ: Option<Principal>) {
        let attrs = if is_policy_marker(&name) {
            0
        } else {
            let now = princ.as_ref().filter(|_| !deleted);
            match (self.map.log(&name, now), now) {
                (Some(before), Some(after)) => find_changed_attrs(&before, after, true),
                (None, Some(_)) => ULOG_ADD_ATTRS,
                (_, None) => 0,
            }
        };
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(UlogEntry {
                sno: 0,
                time: unix_now_u32(),
                name,
                deleted,
                princ,
                attrs,
            });
    }

    pub(super) fn commit_ulog(&self) {
        let pending: Vec<UlogEntry> = {
            self.pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .drain(..)
                .collect()
        };
        if pending.is_empty() {
            return;
        }
        let mut log = self
            .ulog
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for mut e in pending {
            e.sno = self.serial.fetch_add(1, Ordering::SeqCst) + 1;
            log.push_back(e);
            while log.len() > ULOG_CAP {
                log.pop_front();
            }
        }
    }
}
