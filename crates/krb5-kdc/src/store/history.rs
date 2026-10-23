//! The kadmin history principal.

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

/// A new history kvno clears the ring.
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
    #[must_use]
    pub fn history_key(&self) -> Option<(u32, ProtocolKey)> {
        let p = self.get_name(&crate::principals::kadmin_history())?;
        let k = p.keys.iter().max_by_key(|k| k.kvno)?;
        Some((k.kvno, k.key.clone()))
    }

    // MIT: `kdb_get_hist_key` (server_kdb.c:166-188)
    // MIT: `create_hist` (server_kdb.c:141-164)
    /// First use sets max life to 64 seconds.
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
        let salt = name.default_salt(&self.realm);
        let mut p = Principal::from_keys(
            name,
            self.realm.clone(),
            vec![KeyEntry::new(etype, random_key(etype)?, 1)],
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
        let id = p.id();
        self.put_principal(p);
        let key = random_key(etype)?;
        let mut p = self.map.get(&id).cloned().ok_or(Error::NotFound)?;
        p.keys = vec![KeyEntry::new(etype, key.clone(), INITIAL_HIST_KVNO)];
        stamp_admin_tl(&mut p, true, actor);
        self.put_principal(p);
        self.save_through()?;
        Ok((INITIAL_HIST_KVNO, key))
    }

    pub(crate) fn resolve_history_all(&mut self) {
        let hist = self.history_key();
        for p in self.map.values_mut() {
            resolve_history(p, hist.as_ref());
        }
    }

    pub(crate) fn resolve_history_of(&mut self, ids: &[String]) {
        let hist = self.history_key();
        for id in ids {
            if let Some(p) = self.map.get_mut_unlogged(id) {
                resolve_history(p, hist.as_ref());
            }
        }
    }
}
