//! `kadmin/history` and the osa password-history ring
//! (`server_kdb.c` `kdb_get_hist_key` / `create_hist`,
//! `svr_principal.c` `create_history_entry` / `add_to_history`).

use krb5_crypto::ProtocolKey;

use super::PrincipalStore;
use super::keys::{KeyEntry, random_key};
use super::principal::{Principal, refresh_kadm_tl, stamp_admin_tl};
use crate::error::Error;
use crate::osa::{INITIAL_HIST_KVNO, OsaKeyData, OsaPrincEnt};

pub(crate) fn prune_key_history(keys: Vec<KeyEntry>, depth: u32) -> Vec<KeyEntry> {
    if depth == 0 {
        return Vec::new();
    }
    let mut kvnos: Vec<u32> = keys.iter().map(|k| k.kvno).collect();
    kvnos.sort_unstable();
    kvnos.dedup();
    let keep: Vec<u32> = kvnos.into_iter().rev().take(depth as usize).collect();
    keys.into_iter()
        .filter(|k| keep.contains(&k.kvno))
        .collect()
}

fn resolve_history(p: &mut Principal, hist: Option<&(u32, ProtocolKey)>) {
    if p.kadm.old_keys.is_empty() || !p.key_history.is_empty() {
        return;
    }
    let Some((kvno, key)) = hist else {
        return;
    };
    if *kvno != p.kadm.admin_history_kvno {
        return;
    }
    let osa = OsaPrincEnt {
        old_key_next: p.kadm.old_key_next,
        old_keys: p.kadm.old_keys.clone(),
        ..OsaPrincEnt::default()
    };
    p.key_history = osa
        .old_keys_oldest_first()
        .into_iter()
        .flat_map(|e| crate::osa::decrypt_entry(e, key))
        .collect();
}

/// MIT `create_history_entry` (`svr_principal.c:1004-1062`): + `add_to_history`: the replaced keys of the
/// most recent kvno become one history entry under the history key; a history
/// key newer than the record's resets the ring; `pw_history_num` counts the
/// current password, so `nhist - 1` entries are kept, oldest dropped first.
pub(super) fn record_history(
    p: &mut Principal,
    old: &[KeyEntry],
    nhist: u32,
    hist_kvno: u32,
    hist_key: &ProtocolKey,
) -> Result<(), Error> {
    if p.kadm.admin_history_kvno != hist_kvno {
        p.key_history.clear();
        p.kadm.old_keys.clear();
        p.kadm.old_key_next = 0;
        p.kadm.admin_history_kvno = hist_kvno;
    }
    if nhist <= 1 {
        return Ok(());
    }
    let top = old.iter().map(|k| k.kvno).max().unwrap_or(0);
    let recent: Vec<KeyEntry> = old.iter().filter(|k| k.kvno == top).cloned().collect();
    if recent.is_empty() {
        return Ok(());
    }
    let entry =
        crate::osa::history_entry(&recent, hist_key).map_err(|e| Error::Crypto(e.to_string()))?;
    let keep = (nhist - 1) as usize;
    let mut entries: Vec<Vec<OsaKeyData>> = OsaPrincEnt {
        old_key_next: p.kadm.old_key_next,
        old_keys: std::mem::take(&mut p.kadm.old_keys),
        ..OsaPrincEnt::default()
    }
    .old_keys_oldest_first()
    .into_iter()
    .cloned()
    .collect();
    entries.push(entry);
    while entries.len() > keep {
        entries.remove(0);
    }
    p.kadm.old_key_next = u32::try_from(entries.len() % keep).unwrap_or(0);
    p.kadm.old_keys = entries;
    p.key_history.extend(recent);
    p.key_history = prune_key_history(std::mem::take(&mut p.key_history), nhist - 1);
    Ok(())
}

impl PrincipalStore {
    /// The current `kadmin/history` key and its kvno (`kdb_get_hist_key`
    /// without the creation), if the principal exists.
    #[must_use]
    pub fn history_key(&self) -> Option<(u32, ProtocolKey)> {
        let p = self.get_name(&crate::principals::kadmin_history())?;
        let k = p.keys.iter().max_by_key(|k| k.kvno)?;
        Some((k.kvno, k.key.clone()))
    }

    /// MIT `kdb_get_hist_key` (`server_kdb.c:174-223`): then MIT `create_hist` (`server_kdb.c:142-164`): + `create_hist` : the
    /// history key, creating `kadmin/history` on first use with MIT's shape —
    /// `max_life` 64 s (`KRB5_KDB_DISALLOW_ALL_TIX` assigned to `max_life`),
    /// no attributes, one random key of the master enctype at kvno 2.
    ///
    /// # Errors
    ///
    /// [`Error::Rng`] when the history key fails.
    pub(crate) fn ensure_history_principal(
        &mut self,
        actor: &str,
    ) -> Result<(u32, ProtocolKey), Error> {
        if let Some(h) = self.history_key() {
            return Ok(h);
        }
        let name = crate::principals::kadmin_history();
        let etype = self
            .get(&format!("K/M@{}", self.realm))
            .and_then(|km| km.keys.first().map(|k| k.etype))
            .unwrap_or_else(crate::mkey::default_master_etype);
        let key = random_key(etype)?;
        let salt = name.default_salt(&self.realm);
        let mut p = Principal::from_keys(
            name,
            self.realm.clone(),
            vec![KeyEntry::new(etype, key.clone(), INITIAL_HIST_KVNO)],
            salt,
            crate::store::PrincipalFields {
                requires_preauth: false,
                max_life: 64,
                locked: false,
                pw_expire: 0,
            },
        );
        p.max_renewable_life = self.policy.max_renewable_life;
        refresh_kadm_tl(&mut p);
        stamp_admin_tl(&mut p, true, actor);
        self.put_principal(p);
        Ok((INITIAL_HIST_KVNO, key))
    }

    /// Decrypt every principal's stored history with the history key (the
    /// reading half of `kdb_get_hist_key` + `check_pw_reuse`); a record whose
    /// `admin_history_kvno` is not the current history kvno stays unreadable,
    /// as MIT treats it.
    pub(crate) fn resolve_history_all(&mut self) {
        let hist = self.history_key();
        for p in self.map.values_mut() {
            resolve_history(p, hist.as_ref());
        }
    }
}
