use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{Before, HeldSaves, PrincipalStore};
use crate::error::Error;
use crate::host::{
    KerberosStore, KerberosStoreError, LoadedRealm, RealmBatch, SealKey, open_policy,
    open_principal, open_realm_state, policy_row, principal_row, realm_state, row_name,
};
use crate::kdb_dump::{DumpFile, KDB_DUMP_VERSION};

pub(super) type NoCommit = fn(RealmBatch) -> Result<(), KerberosStoreError>;

#[derive(Clone)]
pub(crate) struct HostSeam {
    store: Arc<dyn KerberosStore>,
    seal: SealKey,
    pub(super) reload_due: bool,
    before: Option<Before>,
}

impl std::fmt::Debug for HostSeam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostSeam")
            .field("reload_due", &self.reload_due)
            .finish_non_exhaustive()
    }
}

fn journal_lost() -> Error {
    Error::Db {
        kind: std::io::ErrorKind::Other,
        text: "the change lost its record journal".to_owned(),
    }
}

impl PrincipalStore {
    pub fn open_host(
        host: Arc<dyn KerberosStore>,
        realm: &str,
        seal: SealKey,
    ) -> Result<Self, Error> {
        let loaded = host.load().map_err(Error::Host)?;
        let mut store = Self::from_host_rows(realm, &loaded, &seal)?;
        store.host = Some(HostSeam {
            store: host,
            seal,
            reload_due: false,
            before: None,
        });
        Ok(store)
    }

    pub(crate) fn from_host_rows(
        realm: &str,
        loaded: &LoadedRealm,
        seal: &SealKey,
    ) -> Result<Self, Error> {
        let mut princs = loaded
            .principals
            .iter()
            .map(|row| open_principal(row, realm, seal))
            .collect::<Result<Vec<_>, _>>()
            .map_err(Error::Record)?;
        let km = format!("K/M@{realm}");
        princs.sort_by_key(|p| p.name != km);
        let file = DumpFile {
            version: KDB_DUMP_VERSION,
            records: princs.len(),
            princs,
            policies: Vec::new(),
            applied_len: 0,
            seen_rid: 0,
        };
        let mut store = file.into_store(&seal.key).map_err(|e| Error::Db {
            kind: std::io::ErrorKind::InvalidData,
            text: e.to_string(),
        })?;
        for row in &loaded.policies {
            store.load_policy(open_policy(row, realm, seal).map_err(Error::Record)?);
        }
        if let Some(state) = &loaded.realm {
            let (sid, next_rid) = open_realm_state(state, realm, seal).map_err(Error::Record)?;
            store.set_domain_sid(sid);
            store.raise_next_rid(next_rid);
        }
        Ok(store)
    }

    /// Takes back what the host holds; a host that regains its realm calls it.
    pub fn reload_from_host(&mut self) -> Result<(), Error> {
        let seam = self
            .host
            .clone()
            .ok_or_else(|| Error::InvalidArgument("no host store".to_owned()))?;
        let loaded = seam.store.load().map_err(Error::Host)?;
        let fresh = Self::from_host_rows(&self.realm, &loaded, &seam.seal)?;
        self.adopt(fresh);
        if let Some(h) = self.host.as_mut() {
            h.reload_due = false;
            h.before = None;
        }
        Ok(())
    }

    #[must_use]
    pub fn host_seal_key(&self) -> Option<SealKey> {
        let km = self.get(&format!("K/M@{}", self.realm))?;
        let k = km.keys.first()?;
        Some(SealKey {
            kvno: k.kvno,
            key: k.key.clone(),
        })
    }

    pub fn host_full_batch(&self) -> Result<RealmBatch, Error> {
        let seal = self
            .host_seal_key()
            .ok_or_else(|| Error::InvalidArgument("no K/M in the store".to_owned()))?;
        self.host_rows(&self.ids(), true, &seal)
    }

    pub(crate) fn host_rows(
        &self,
        ids: &[String],
        with_policies: bool,
        seal: &SealKey,
    ) -> Result<RealmBatch, Error> {
        let mut batch = RealmBatch::default();
        for id in ids {
            if let Some(p) = self.map.get(id) {
                batch.upsert_principals.push(principal_row(self, p, seal)?);
            }
        }
        if with_policies {
            let mut names: Vec<&String> = self.policies.keys().collect();
            names.sort();
            for name in names {
                batch
                    .put_policies
                    .push(policy_row(&self.policies[name], &self.realm, seal)?);
            }
        }
        batch.realm = Some(realm_state(
            &self.realm,
            &self.domain_sid,
            self.next_rid,
            seal,
        )?);
        Ok(batch)
    }

    pub(crate) fn attach_host(
        &mut self,
        host: Arc<dyn KerberosStore>,
        seal: SealKey,
        lockout: std::path::PathBuf,
    ) {
        self.lockout.set_host_file(lockout);
        self.host = Some(HostSeam {
            store: host,
            seal,
            reload_due: false,
            before: None,
        });
    }

    fn reload_or_mark(&mut self) {
        if self.reload_from_host().is_err()
            && let Some(h) = self.host.as_mut()
        {
            h.reload_due = true;
        }
    }

    pub fn change_committing<T, E>(
        &mut self,
        commit: impl FnOnce(RealmBatch) -> Result<(), KerberosStoreError>,
        f: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<Result<T, E>, Error> {
        if self.host.is_none() || self.post.is_some() || self.saves_held {
            return Err(Error::InvalidArgument(
                "change_committing needs a host store and no open change".to_owned(),
            ));
        }
        self.posted(|s| s.change_host(Some(commit), f))
    }

    // MIT: `kdb_put_entry` (lib/kadm5/srv/server_kdb.c:364-405)
    pub(super) fn change_host<T, E, C>(
        &mut self,
        commit: Option<C>,
        f: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<Result<T, E>, Error>
    where
        C: FnOnce(RealmBatch) -> Result<(), KerberosStoreError>,
    {
        if self.host.as_ref().is_some_and(|h| h.reload_due) {
            self.reload_from_host()?;
        }
        self.changed.0.store(false, Ordering::Relaxed);
        self.map.begin_change();
        let before = Before::of(self);
        self.set_host_before(Some(before));
        let done = {
            let inside = HeldSaves::new(self);
            f(&mut *inside.0)
        };
        let before = self.set_host_before(None).ok_or_else(journal_lost)?;
        let value = match done {
            Ok(v) => v,
            Err(e) => {
                self.host_undo(before);
                if self.host.as_ref().is_some_and(|h| h.reload_due) {
                    self.reload_or_mark();
                }
                return Ok(Err(e));
            }
        };
        let (batch, gone) = match self.host_batch(&before) {
            Ok(b) => b,
            Err(e) => {
                self.host_undo(before);
                return Err(e);
            }
        };
        let committed = match commit {
            Some(c) => c(batch),
            None if batch.is_empty() => Ok(()),
            None => self.host_store()?.commit(batch),
        };
        match committed {
            Ok(()) => {
                self.map.end_change();
                self.lockout.drop_host_rows(&gone);
                self.pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clear();
                Ok(Ok(value))
            }
            Err(e) => {
                self.host_undo(before);
                if !matches!(e, KerberosStoreError::Refused(_)) {
                    self.reload_or_mark();
                }
                Err(Error::Host(e))
            }
        }
    }

    // MIT: `create_hist` (lib/kadm5/srv/server_kdb.c:141-164)
    pub(super) fn host_commit_through(&mut self) -> Result<(), Error> {
        let before = self.set_host_before(None).ok_or_else(journal_lost)?;
        let committed = self.host_batch(&before).and_then(|(b, _)| {
            if b.is_empty() {
                Ok(())
            } else {
                self.host_store()?.commit(b).map_err(Error::Host)
            }
        });
        if let Err(e) = committed {
            if !matches!(e, Error::Host(KerberosStoreError::Refused(_)))
                && let Some(h) = self.host.as_mut()
            {
                h.reload_due = true;
            }
            self.set_host_before(Some(before));
            return Err(e);
        }
        self.map.end_change();
        self.map.begin_change();
        let rebased = Before::of(self);
        self.set_host_before(Some(rebased));
        Ok(())
    }

    fn host_undo(&mut self, before: Before) {
        if !before.restore(self) {
            self.reload_or_mark();
        }
    }

    fn host_store(&self) -> Result<Arc<dyn KerberosStore>, Error> {
        self.host
            .as_ref()
            .map(|h| Arc::clone(&h.store))
            .ok_or_else(|| Error::InvalidArgument("no host store".to_owned()))
    }

    fn set_host_before(&mut self, before: Option<Before>) -> Option<Before> {
        let h = self.host.as_mut()?;
        std::mem::replace(&mut h.before, before)
    }

    fn host_batch(&self, before: &Before) -> Result<(RealmBatch, Vec<String>), Error> {
        let seal = &self
            .host
            .as_ref()
            .ok_or_else(|| Error::InvalidArgument("no host store".to_owned()))?
            .seal;
        let mut batch = RealmBatch::default();
        let mut gone = Vec::new();
        for id in self.map.touched().ok_or_else(journal_lost)? {
            if let Some(p) = self.map.get(&id) {
                batch.upsert_principals.push(principal_row(self, p, seal)?);
            } else {
                batch.delete_principals.push(row_name(&id, &self.realm));
                gone.push(id);
            }
        }
        let mut names: Vec<&String> = self.policies.keys().collect();
        names.sort();
        for name in names {
            let pol = &self.policies[name];
            if before.policies.get(name) != Some(pol) {
                batch.put_policies.push(policy_row(pol, &self.realm, seal)?);
            }
        }
        let mut dropped: Vec<String> = before
            .policies
            .keys()
            .filter(|n| !self.policies.contains_key(*n))
            .cloned()
            .collect();
        dropped.sort();
        batch.delete_policies = dropped;
        if before.next_rid != self.next_rid || before.domain_sid != self.domain_sid {
            batch.realm = Some(realm_state(
                &self.realm,
                &self.domain_sid,
                self.next_rid,
                seal,
            )?);
        }
        Ok((batch, gone))
    }
}
