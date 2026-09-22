//! Long-term keys (`krb5_key_data`): `KeyEntry`, lookup
//! (`kdb_default.c` `krb5_dbe_find_enctype`), chrand / setkey /
//! purgekeys / ktadd (`svr_principal.c`) and the krbtgt key set.

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_protocol::{Keytab, KeytabEntry};
use krb5_types::PrincipalName;

use super::PrincipalStore;
use super::flags::{KDB_LOCKDOWN_KEYS, KDB_REQUIRES_PWCHANGE};
use super::password::apply_keysalt_policy;
use super::principal::{Principal, default_mod_actor, stamp_admin_tl};
use crate::acl::{Acl, AdminOp};
use crate::error::Error;

#[cfg(test)]
use super::{FAIL_NEXT_CHRAND_SAVE, FAIL_NEXT_KTADD_EXPORT};
#[cfg(test)]
use std::cell::Cell;

/// Long-term key for one etype.
#[derive(Clone, Debug)]
pub struct KeyEntry {
    /// Encryption type.
    pub etype: EncryptionType,
    /// Protocol key.
    pub key: ProtocolKey,
    /// Key version.
    pub kvno: u32,
    /// MIT `key_data_type[1]` when dump `ver` is 2.
    pub salt_type: Option<i32>,
    /// MIT `key_data_contents[1]` (salt) when dump `ver` is 2.
    pub kdb_salt: Option<Vec<u8>>,
}

/// Why [`Principal::find_enctype`] found nothing: MIT `KRB5_KDB_NO_MATCHING_KEY`
/// (no key of that etype/kvno at all) versus `KRB5_KDB_NO_PERMITTED_KEY` (the
/// requested etype, or every matching key, is outside `permitted_enctypes`).
/// Both are KDB-library codes the KDC clamps to 60 `GENERIC` on the wire; the
/// split is for logs and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyLookup {
    /// `KRB5_KDB_NO_MATCHING_KEY`.
    NoMatchingKey,
    /// `KRB5_KDB_NO_PERMITTED_KEY`.
    NoPermittedKey,
}

impl KeyEntry {
    /// Key without dump salt metadata (`ver` 1 on write).
    #[must_use]
    pub fn new(etype: EncryptionType, key: ProtocolKey, kvno: u32) -> Self {
        Self {
            etype,
            key,
            kvno,
            salt_type: None,
            kdb_salt: None,
        }
    }
}

pub(super) fn cap_key_versions(keys: &mut Vec<KeyEntry>, n: u32) {
    let mut kvnos: Vec<u32> = keys.iter().map(|k| k.kvno).collect();
    kvnos.sort_unstable();
    kvnos.dedup();
    kvnos.reverse();
    let keep: std::collections::HashSet<u32> = kvnos.into_iter().take(n as usize).collect();
    keys.retain(|k| keep.contains(&k.kvno));
}

/// Fill a random protocol key of `etype`.
///
/// # Errors
///
/// [`Error::Rng`] when the CSPRNG fails.
pub fn random_key(etype: EncryptionType) -> Result<ProtocolKey, Error> {
    let mut buf = vec![0u8; etype.key_len()];
    getrandom::getrandom(&mut buf).map_err(|_| Error::Rng)?;
    ProtocolKey::from_bytes(etype, &buf).map_err(Error::from)
}

pub(super) fn randkey_etypes() -> [EncryptionType; 4] {
    [
        EncryptionType::Aes256CtsHmacSha196,
        EncryptionType::Aes128CtsHmacSha196,
        EncryptionType::Aes256CtsHmacSha384192,
        EncryptionType::Aes128CtsHmacSha256128,
    ]
}

impl PrincipalStore {
    /// `krbtgt/REALM@REALM`.
    #[must_use]
    pub fn krbtgt(&self) -> Option<&Principal> {
        self.get_name(&PrincipalName::krbtgt(&self.realm))
    }

    /// ACL-gated keytab export using the existing v2 writer.
    ///
    /// `LOCKDOWN_KEYS` is refused. Local CLI export uses
    /// [`Self::export_keytab_local`].
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn export_keytab(
        &self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
    ) -> Result<Keytab, Error> {
        let id = crate::kdb::lookup_principal_id(name, &self.realm);
        acl.check(actor, AdminOp::Ktadd, Some(&id))?;
        let p = self.get_name(name).ok_or(Error::NotFound)?;
        if p.attributes & KDB_LOCKDOWN_KEYS != 0 {
            return Err(Error::AclDenied);
        }
        Self::keytab_from(p)
    }

    /// Local-operator keytab export for `--export-keytab` /
    /// `--export-krbtgt-keytab`.
    ///
    /// The operator already holds the DB and stash, so `LOCKDOWN_KEYS` is
    /// not applied. Remote kadm5 extract still uses [`Self::export_keytab`].
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn export_keytab_local(&self, name: &PrincipalName) -> Result<Keytab, Error> {
        #[cfg(test)]
        if FAIL_NEXT_KTADD_EXPORT.with(Cell::get) {
            FAIL_NEXT_KTADD_EXPORT.with(|c| c.set(false));
            return Err(Error::Crypto("injected export fail".into()));
        }
        let p = self.get_name(name).ok_or(Error::NotFound)?;
        Self::keytab_from(p)
    }

    /// Local `ktadd`: optional rotate, export ignoring lockdown, then `write`.
    ///
    /// On export, write, or chrand-save failure a rotation is rolled back
    /// so the dump kvno is unchanged. Standalone `chrand` does not roll
    /// back. A rollback save error is returned with the original failure
    /// (not swallowed).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`], RNG, persist, or `write`.
    pub fn ktadd_local_atomic(
        &mut self,
        name: &PrincipalName,
        rotate: bool,
        actor: &str,
        write: impl FnOnce(&Keytab) -> Result<(), Error>,
    ) -> Result<Keytab, Error> {
        let snap = self.get_name(name).cloned().ok_or(Error::NotFound)?;
        if rotate && let Err(e) = self.chrand_etypes_keepold(name, &[], 0, actor) {
            return Err(self.rollback_rotate(true, snap, e));
        }
        let kt = match self.export_keytab_local(name) {
            Ok(kt) => kt,
            Err(e) => return Err(self.rollback_rotate(rotate, snap, e)),
        };
        match write(&kt) {
            Ok(()) => Ok(kt),
            Err(e) => Err(self.rollback_rotate(rotate, snap, e)),
        }
    }

    fn rollback_rotate(&mut self, rotate: bool, snap: Principal, e: Error) -> Error {
        if !rotate {
            return e;
        }
        let id = snap.id();
        self.note_ulog(id.clone(), false, Some(snap.clone()));
        self.map.insert(id, snap);
        match self.save_if_configured() {
            Ok(()) => e,
            Err(re) => Error::Crypto(format!("{e}; rollback failed: {re}")),
        }
    }

    fn keytab_from(p: &Principal) -> Result<Keytab, Error> {
        if p.keys.is_empty() {
            return Err(Error::NotFound);
        }
        let ts = krb5_types::KerberosTime::now().unix_seconds();
        let realm =
            krb5_types::try_ascii(&p.realm).map_err(|_| Error::Crypto("non-ascii realm".into()))?;
        let entries = p
            .keys
            .iter()
            .map(|key| KeytabEntry {
                realm: realm.clone(),
                name: p.name.clone(),
                timestamp: ts,
                kvno: key.kvno,
                key: key.key.clone(),
            })
            .collect();
        Ok(Keytab {
            version: 0x0502,
            skipped_unknown_etype: 0,
            unparsed: Vec::new(),
            entries,
        })
    }

    /// Replace long-term keys with a new random kvno (kadm5 `chrand`).
    ///
    /// Default MIT `cpw -randkey` / `ktadd` does not keep old kvnos, so the
    /// previous password must fail `kinit`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] or RNG failure.
    pub fn chrand(&mut self, name: &PrincipalName) -> Result<Vec<KeyEntry>, Error> {
        self.chrand_keepold_n(name, 0)
    }

    /// [`Self::chrand`] with MIT `keepold` (0 / 1 / N versions).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] or RNG failure.
    pub fn chrand_keepold_n(
        &mut self,
        name: &PrincipalName,
        keepold: u32,
    ) -> Result<Vec<KeyEntry>, Error> {
        let realm = self.realm.clone();
        let actor = default_mod_actor(&realm);
        self.chrand_etypes_keepold_in(name, &realm, &[], keepold, &actor)
    }

    /// [`Self::chrand_etypes_keepold`] for `name@princ_realm`.
    ///
    /// Empty `etypes` is MIT's omitted `-e` (`svr_principal.c:1425`
    /// `apply_keysalt_policy`).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`], [`Error::BadKeysalts`], or RNG failure.
    pub fn chrand_etypes_keepold_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        etypes: &[EncryptionType],
        keepold: u32,
        actor: &str,
    ) -> Result<Vec<KeyEntry>, Error> {
        let id = self.canonical_id(name, princ_realm)?;
        let existing = self.map.get(&id).ok_or(Error::NotFound)?;
        let next_kvno = existing
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let allowed = existing
            .pw_policy
            .as_ref()
            .and_then(|n| self.policies.get(n))
            .and_then(|p| p.allowed_keysalts.clone());
        let use_etypes =
            apply_keysalt_policy(allowed.as_deref(), etypes, &self.policy.password_etypes())?;
        let mut new_keys = Vec::new();
        for etype in use_etypes {
            new_keys.push(KeyEntry::new(etype, random_key(etype)?, next_kvno));
        }
        {
            let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
            let old = std::mem::replace(&mut p.keys, new_keys.clone());
            if keepold > 0 {
                p.keys.extend(old);
                if keepold > 1 {
                    cap_key_versions(&mut p.keys, keepold);
                }
            }
            stamp_admin_tl(p, true, actor);
        }
        self.apply_pw_max_life_in(name, princ_realm)?;
        let snap = self.map.get(&id).cloned();
        self.note_ulog(id, false, snap);
        #[cfg(test)]
        if FAIL_NEXT_CHRAND_SAVE.with(Cell::get) {
            FAIL_NEXT_CHRAND_SAVE.with(|c| c.set(false));
            return Err(Error::Crypto("injected chrand save fail".into()));
        }
        self.save_if_configured()?;
        Ok(new_keys)
    }

    /// `cpw -randkey -e` with MIT `keepold`. Empty `etypes` uses policy salts.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] or RNG failure.
    pub fn chrand_etypes_keepold(
        &mut self,
        name: &PrincipalName,
        etypes: &[EncryptionType],
        keepold: u32,
        actor: &str,
    ) -> Result<Vec<KeyEntry>, Error> {
        let realm = self.realm.clone();
        self.chrand_etypes_keepold_in(name, &realm, etypes, keepold, actor)
    }

    /// Drop keys with kvno below `keepkvno`. `keepkvno <= 0` keeps only the
    /// newest kvno (MIT `purgekeys` without `-keepkvno`).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn purgekeys(&mut self, name: &PrincipalName, keepkvno: i32) -> Result<(), Error> {
        let realm = self.realm.clone();
        let actor = default_mod_actor(&realm);
        self.purgekeys_in(name, &realm, keepkvno, &actor)
    }

    /// [`Self::purgekeys`] for `name@princ_realm`.
    ///
    /// MIT `kadm5_purgekeys` → `kdb_put_entry` stamps `current_caller`
    /// even when no old keys are dropped.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn purgekeys_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        keepkvno: i32,
        actor: &str,
    ) -> Result<(), Error> {
        let id = self.canonical_id(name, princ_realm)?;
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        let keep = if keepkvno <= 0 {
            p.keys.iter().map(|k| k.kvno).max().unwrap_or(0)
        } else {
            u32::try_from(keepkvno).unwrap_or(u32::MAX)
        };
        p.keys.retain(|k| k.kvno >= keep);
        stamp_admin_tl(p, false, actor);
        let snap = p.clone();
        self.note_ulog(id, false, Some(snap));
        self.save_if_configured()
    }

    /// Replace keys with caller-supplied material (`kadm5_setkey_principal`).
    ///
    /// `kvno == 0` on every entry picks the next version. `keepold` is MIT's
    /// integer: 0 discard, 1 keep all, N keep N versions including the new.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`], or [`Error::Crypto`] when `keepold` collides with
    /// an existing kvno.
    pub fn set_keys(
        &mut self,
        name: &PrincipalName,
        keys: Vec<KeyEntry>,
        keepold: u32,
    ) -> Result<(), Error> {
        let realm = self.realm.clone();
        let actor = default_mod_actor(&realm);
        self.set_keys_in(name, &realm, keys, keepold, &actor)
    }

    /// [`Self::set_keys`] for `name@princ_realm`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`], or [`Error::Crypto`] when `keepold` collides with
    /// an existing kvno.
    pub fn set_keys_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        mut keys: Vec<KeyEntry>,
        keepold: u32,
        actor: &str,
    ) -> Result<(), Error> {
        if keys.is_empty() {
            return Err(Error::Crypto("setkey empty".into()));
        }
        let id = self.canonical_id(name, princ_realm)?;
        {
            let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
            let want = keys[0].kvno;
            if keys.iter().any(|k| k.kvno != want) {
                return Err(Error::Crypto("setkey kvno".into()));
            }
            let kvno = if want == 0 {
                p.keys
                    .iter()
                    .chain(p.key_history.iter())
                    .map(|k| k.kvno)
                    .max()
                    .unwrap_or(0)
                    .saturating_add(1)
            } else {
                if keepold > 0 && p.keys.iter().any(|k| k.kvno == want) {
                    return Err(Error::Crypto("setkey kvno".into()));
                }
                want
            };
            for k in &mut keys {
                k.kvno = kvno;
            }
            if keepold > 0 {
                let old = std::mem::replace(&mut p.keys, keys);
                p.keys.extend(old);
                if keepold > 1 {
                    cap_key_versions(&mut p.keys, keepold);
                }
            } else {
                p.keys = keys;
            }
            p.attributes &= !KDB_REQUIRES_PWCHANGE;
            p.fail_auth_count = 0;
            stamp_admin_tl(p, true, actor);
        }
        self.apply_pw_max_life_in(name, princ_realm)?;
        let snap = self.map.get(&id).cloned();
        self.note_ulog(id, false, snap);
        self.save_if_configured()
    }
}
