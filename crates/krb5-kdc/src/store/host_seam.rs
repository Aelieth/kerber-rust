use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{Before, HeldSaves, Principal, PrincipalStore, kadm5_mask};
use crate::error::Error;
use crate::host::{
    Caller, HostChange, HostPrepared, KerberosStore, KerberosStoreError, LoadedRealm, Operation,
    RealmBatch, RowChange, SealKey, TargetPeek, WriteIntent, open_policy, open_principal,
    open_realm_state, policy_row, principal_row, realm_state, row_name,
};
use crate::kdb_dump::{
    DumpFile, KDB_DUMP_VERSION, TL_KADM_DATA, TL_KERBER_HOST_OWNED, TL_LAST_PWD_CHANGE,
    TL_MOD_PRINC,
};

pub(super) type NoCommit = fn(HostChange) -> Result<(), KerberosStoreError>;
pub(super) type Declared<'p> = Option<(WriteIntent, &'p mut Option<HostPrepared>)>;

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
            store.put_domain_sid(sid);
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

    #[must_use]
    pub fn has_host(&self) -> bool {
        self.host.is_some()
    }

    /// A host owns its rows: iprop and dump loads would bypass it.
    pub(crate) fn refuse_bulk_ingest(&self) -> Result<(), Error> {
        if self.host.is_some() {
            return Err(Error::InvalidArgument(
                "bulk loads are not taken into a host store".to_owned(),
            ));
        }
        Ok(())
    }

    /// The record a write would act on, resolved through an alias.
    #[must_use]
    pub fn target_peek(
        &self,
        name: &krb5_types::PrincipalName,
        princ_realm: &str,
    ) -> Option<TargetPeek> {
        let id = self.canonical_id(name, princ_realm).ok()?;
        let host_owned = self.map.get(&id)?.host_owned();
        Some(TargetPeek { id, host_owned })
    }

    /// The host's ownership mark; only inside a change on a host store.
    pub fn set_host_owned_in(
        &mut self,
        name: &krb5_types::PrincipalName,
        princ_realm: &str,
        owned: bool,
    ) -> Result<(), Error> {
        if self.host.is_none() || !self.saves_held {
            return Err(Error::InvalidArgument(
                "the host mark is set inside a host store's change".to_owned(),
            ));
        }
        let id = self.adb_id(name, princ_realm)?;
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        p.tl_data.retain(|t| t.ty != TL_KERBER_HOST_OWNED);
        if owned {
            p.tl_data.push(super::TlData {
                ty: TL_KERBER_HOST_OWNED,
                contents: vec![1],
            });
        }
        let snap = self.map.get(&id).cloned();
        self.note_ulog(id, false, snap);
        self.save_if_configured()
    }

    /// Every row, as the realm's first commit to an empty host.
    pub fn host_full_change(&self) -> Result<HostChange, Error> {
        let seal = self
            .host_seal_key()
            .ok_or_else(|| Error::InvalidArgument("no K/M in the store".to_owned()))?;
        self.host_bootstrap_change(&self.ids(), true, &seal)
    }

    pub(crate) fn host_bootstrap_change(
        &self,
        ids: &[String],
        with_policies: bool,
        seal: &SealKey,
    ) -> Result<HostChange, Error> {
        let batch = self.host_rows(ids, with_policies, seal)?;
        let rows = ids
            .iter()
            .filter_map(|id| {
                let p = self.map.get(id)?;
                Some(row_change(id.clone(), None, Some(p.clone())))
            })
            .collect();
        Ok(HostChange {
            intent: WriteIntent::new(Operation::Bootstrap, Caller::Embedder),
            rows,
            prepared: None,
            batch,
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

    /// The host's own write: `commit` gets the change as `Embedded`.
    pub fn change_committing<T, E>(
        &mut self,
        commit: impl FnOnce(HostChange) -> Result<(), KerberosStoreError>,
        f: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<Result<T, E>, Error> {
        if self.host.is_none() || self.post.is_some() || self.saves_held {
            return Err(Error::InvalidArgument(
                "change_committing needs a host store and no open change".to_owned(),
            ));
        }
        let intent = WriteIntent::new(Operation::Embedded, Caller::Embedder);
        let mut no_token = None;
        self.posted(|s| s.change_host(Some(commit), Some((intent, &mut no_token)), f))
    }

    // MIT: `kdb_put_entry` (lib/kadm5/srv/server_kdb.c:364-405)
    pub(super) fn change_host<T, E, C>(
        &mut self,
        commit: Option<C>,
        declared: Declared<'_>,
        f: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<Result<T, E>, Error>
    where
        C: FnOnce(HostChange) -> Result<(), KerberosStoreError>,
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
            catch_unwind(AssertUnwindSafe(|| f(&mut *inside.0)))
        };
        let mut committed = false;
        let tail = catch_unwind(AssertUnwindSafe(|| {
            self.host_finish(done, commit, declared, &mut committed)
        }));
        match tail {
            Ok(Ok(out)) => out,
            Ok(Err(panic)) => resume_unwind(panic),
            Err(panic) => {
                if committed {
                    self.set_host_before(None);
                    self.map.end_change();
                } else {
                    self.undo_parked();
                }
                resume_unwind(panic);
            }
        }
    }

    fn host_finish<T, E, C>(
        &mut self,
        done: std::thread::Result<Result<T, E>>,
        commit: Option<C>,
        declared: Declared<'_>,
        committed: &mut bool,
    ) -> std::thread::Result<Result<Result<T, E>, Error>>
    where
        C: FnOnce(HostChange) -> Result<(), KerberosStoreError>,
    {
        let value = match done {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                self.undo_parked();
                if self.host.as_ref().is_some_and(|h| h.reload_due) {
                    self.reload_or_mark();
                }
                return Ok(Ok(Err(e)));
            }
            Err(panic) => {
                self.undo_parked();
                return Err(panic);
            }
        };
        let batch = self
            .host
            .as_ref()
            .and_then(|h| h.before.as_ref())
            .ok_or_else(journal_lost)
            .and_then(|before| self.host_batch(before));
        let (batch, gone, rows) = match batch {
            Ok(b) => b,
            Err(e) => {
                self.undo_parked();
                return Ok(Err(e));
            }
        };
        let skip = rows.is_empty() && batch.is_empty();
        let mut no_token = None;
        let (intent, slot) = match declared {
            Some(d) => d,
            None => (
                WriteIntent::new(Operation::Unspecified, Caller::Embedder),
                &mut no_token,
            ),
        };
        let prepared = if commit.is_none() && skip {
            None
        } else {
            slot.take()
        };
        let change = HostChange {
            intent,
            rows,
            prepared,
            batch,
        };
        let host = match self.host_store() {
            Ok(h) => h,
            Err(e) => {
                self.undo_parked();
                return Ok(Err(e));
            }
        };
        let outcome = catch_unwind(AssertUnwindSafe(|| match commit {
            Some(c) => c(change),
            None if skip => Ok(()),
            None => host.commit_change(change),
        }))
        .unwrap_or_else(|_| {
            Err(KerberosStoreError::Failed(
                "the host's commit panicked".to_owned(),
            ))
        });
        match outcome {
            Ok(()) => {
                *committed = true;
                self.set_host_before(None);
                self.map.end_change();
                self.lockout.drop_host_rows(&gone);
                self.pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clear();
                Ok(Ok(Ok(value)))
            }
            Err(e) => {
                self.undo_parked();
                if !matches!(
                    e,
                    KerberosStoreError::Refused(_) | KerberosStoreError::Denied(_)
                ) {
                    self.reload_or_mark();
                }
                Ok(Err(Error::Host(e)))
            }
        }
    }

    fn undo_parked(&mut self) {
        match self.set_host_before(None) {
            Some(before) => self.host_undo(before),
            None => self.reload_or_mark(),
        }
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

    fn host_batch(
        &self,
        before: &Before,
    ) -> Result<(RealmBatch, Vec<String>, Vec<RowChange>), Error> {
        let seal = &self
            .host
            .as_ref()
            .ok_or_else(|| Error::InvalidArgument("no host store".to_owned()))?
            .seal;
        let mut batch = RealmBatch::default();
        let mut gone = Vec::new();
        let mut rows = Vec::new();
        for (id, was) in self.map.touched_before().ok_or_else(journal_lost)? {
            let now = self.map.get(&id).cloned();
            if let Some(p) = &now {
                batch.upsert_principals.push(principal_row(self, p, seal)?);
            } else {
                batch.delete_principals.push(row_name(&id, &self.realm));
                gone.push(id.clone());
            }
            rows.push(row_change(id, was, now));
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
        Ok((batch, gone, rows))
    }
}

pub(crate) fn row_change(
    id: String,
    before: Option<Principal>,
    after: Option<Principal>,
) -> RowChange {
    let host_owned = before.iter().chain(&after).any(Principal::host_owned);
    let mask = match (&before, &after) {
        (Some(a), Some(b)) => row_mask(a, b),
        (None, None) => 0,
        _ => kadm5_mask::PRINCIPAL,
    };
    RowChange {
        id,
        before,
        after,
        mask,
        host_owned,
    }
}

/// A new field fails to build here until it has a bit; lockout fields have none.
fn row_mask(a: &Principal, b: &Principal) -> u32 {
    use kadm5_mask as m;
    let Principal {
        name,
        realm,
        keys,
        key_history,
        opaque_keys,
        salt,
        max_life,
        pw_expire,
        attributes,
        max_renewable_life,
        expiration,
        last_success: _,
        last_failed: _,
        fail_auth_count: _,
        mkvno,
        db_entry_len: _,
        tl_data,
        e_data,
        rid,
        s4u_allowed_from,
        s4u_allowed_to,
        pw_policy,
        kadm,
        string_attrs,
        loaded_ct: _,
    } = a;
    let tl_of = |p: &Principal, ty: i32| -> Vec<super::TlData> {
        p.tl_data.iter().filter(|t| t.ty == ty).cloned().collect()
    };
    let other_tl = |p: &Principal| -> Vec<super::TlData> {
        p.tl_data
            .iter()
            .filter(|t| ![TL_LAST_PWD_CHANGE, TL_MOD_PRINC, TL_KADM_DATA].contains(&t.ty))
            .cloned()
            .collect()
    };
    let _ = tl_data;
    let bit = |differs: bool, bits: u32| if differs { bits } else { 0 };
    bit(*name != b.name || *realm != b.realm, m::PRINCIPAL)
        | bit(*expiration != b.expiration, m::PRINC_EXPIRE_TIME)
        | bit(*pw_expire != b.pw_expire, m::PW_EXPIRATION)
        | bit(
            tl_of(a, TL_LAST_PWD_CHANGE) != tl_of(b, TL_LAST_PWD_CHANGE),
            m::LAST_PWD_CHANGE,
        )
        | bit(*attributes != b.attributes, m::ATTRIBUTES)
        | bit(*max_life != b.max_life, m::MAX_LIFE)
        | bit(
            tl_of(a, TL_MOD_PRINC) != tl_of(b, TL_MOD_PRINC),
            m::MOD_TIME | m::MOD_NAME,
        )
        | bit(a.top_kvno() != b.top_kvno(), m::KVNO)
        | bit(*mkvno != b.mkvno, m::MKVNO)
        | bit(*kadm != b.kadm, m::AUX_ATTRIBUTES)
        | bit(
            *pw_policy != b.pw_policy,
            if b.pw_policy.is_some() {
                m::POLICY
            } else {
                m::POLICY_CLR
            },
        )
        | bit(*max_renewable_life != b.max_renewable_life, m::MAX_RLIFE)
        | bit(
            !super::password::same_keys(keys, &b.keys)
                || !super::password::same_keys(key_history, &b.key_history)
                || *opaque_keys != b.opaque_keys
                || *salt != b.salt,
            m::KEY_DATA,
        )
        | bit(
            other_tl(a) != other_tl(b)
                || *e_data != b.e_data
                || *rid != b.rid
                || *s4u_allowed_from != b.s4u_allowed_from
                || *s4u_allowed_to != b.s4u_allowed_to
                || *string_attrs != b.string_attrs,
            m::TL_DATA,
        )
}

/// Outside every lock: peek at the target, build the intent, and ask the host to prepare.
pub fn declare_shared(
    store: &crate::listen::SharedDump,
    target: Option<(&krb5_types::PrincipalName, &str)>,
    make: impl FnOnce(Option<&TargetPeek>) -> WriteIntent,
) -> Result<(WriteIntent, Option<HostPrepared>), Error> {
    let (host, peek) = {
        let (g, _) = crate::listen::read_fresh(store);
        let host = g.host.as_ref().map(|h| Arc::clone(&h.store));
        let peek = host
            .as_ref()
            .and(target)
            .and_then(|(n, r)| g.target_peek(n, r));
        (host, peek)
    };
    let intent = make(peek.as_ref());
    let prepared = match host {
        Some(h) => h.prepare(&intent, peek.as_ref()).map_err(Error::Host)?,
        None => None,
    };
    Ok((intent, prepared))
}
