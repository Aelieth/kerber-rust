//! Incremental-propagation update log (`kdb_log.c`, `kdb_incr_update`):
//! the ring, `GET_UPDATES` status, replica apply, and the
//! principal-only ship rule (policy changes never enter the ulog).

use std::sync::atomic::Ordering;

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
    /// Snapshot for in-process apply (absent on dump-only markers).
    pub princ: Option<Principal>,
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
    /// Master key for iprop `AT_KEYDATA` (stash, `K/M`, or `KRB5_MASTER_PASSWORD`).
    #[must_use]
    pub fn iprop_master_key(&self) -> Option<krb5_crypto::ProtocolKey> {
        if let Some((_, stash)) = &self.persist_paths
            && let Ok(bytes) = std::fs::read(stash)
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
        if let Ok(pw) = std::env::var("KRB5_MASTER_PASSWORD")
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
            .filter(|e| !e.name.starts_with("policy:") || e.name.contains('@'))
            .collect();
        (IPROP_OK, cur, entries)
    }

    /// Apply serial-delta (does not re-log).
    ///
    /// MIT incremental kdbe is a field mask: a later `setstr` update may
    /// omit `AT_KEYDATA`. Empty incoming keys/history keep the existing
    /// principal's.
    pub fn apply_updates(&mut self, entries: &[UlogEntry]) {
        for e in entries {
            if e.deleted {
                self.map.remove(&e.name);
            } else if let Some(p) = &e.princ {
                let merged = if let Some(old) = self.map.get(&p.id()) {
                    Self::merge_iprop_princ(old, p)
                } else {
                    p.clone()
                };
                let mut merged = self.assign_iprop_rid(merged);
                if strip_db_args(&mut merged.tl_data).is_ok() {
                    self.map.insert(merged.id(), merged);
                }
            }
            let cur = self.serial();
            if e.sno > cur {
                self.serial.store(e.sno, Ordering::SeqCst);
            }
        }
        self.resolve_history_all();
        let _ = self.save_if_configured();
    }

    fn merge_iprop_princ(old: &Principal, new: &Principal) -> Principal {
        let mut m = new.clone();
        if m.keys.is_empty() {
            m.keys.clone_from(&old.keys);
        }
        if m.key_history.is_empty() {
            m.key_history.clone_from(&old.key_history);
        }
        if m.string_attrs.is_empty() {
            m.string_attrs.clone_from(&old.string_attrs);
        }
        if m.tl_data.is_empty() {
            m.tl_data.clone_from(&old.tl_data);
            m.kadm = old.kadm.clone();
        }
        if m.pw_policy.is_none() {
            m.pw_policy.clone_from(&old.pw_policy);
        }
        if m.salt.is_empty() {
            m.salt.clone_from(&old.salt);
        }
        if m.rid == 0 {
            m.rid = old.rid;
        }
        m
    }

    /// Incremental kdbe has no SID (vendor `0x4B0x` is stripped). A new
    /// replica row with `rid==0` must not PAC as `RID_FIRST_USER`.
    fn assign_iprop_rid(&mut self, mut p: Principal) -> Principal {
        self.settle_rid(&mut p);
        p
    }

    pub(super) fn note_ulog(&self, name: String, deleted: bool, princ: Option<Principal>) {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(UlogEntry {
                sno: 0,
                time: unix_now_u32(),
                name,
                deleted,
                princ,
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
