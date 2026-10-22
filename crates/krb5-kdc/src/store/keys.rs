//! Long-term keys (`krb5_key_data`): `KeyEntry`, lookup (`kdb_default.c` `krb5_dbe_find_enctype`), chrand / setkey / purgekeys / ktadd (`svr_principal.c`) and the krbtgt key set.

use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_protocol::{Keytab, KeytabEntry};
use krb5_types::PrincipalName;

use super::PrincipalStore;
use super::flags::{
    KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_SVR, KDB_LOCKDOWN_KEYS, KDB_REQUIRES_PWCHANGE,
};
use super::password::apply_keysalt_policy;
use super::principal::{Principal, default_mod_actor, stamp_admin_tl};
use crate::acl::{Acl, AdminOp};
use crate::error::Error;

#[cfg(test)]
use super::{FAIL_NEXT_CHRAND_SAVE, FAIL_NEXT_KTADD_EXPORT};
#[cfg(test)]
use std::cell::Cell;

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

/// Why [`Principal::find_enctype`] found nothing: MIT `KRB5_KDB_NO_MATCHING_KEY` (no key of that etype/kvno at all) versus `KRB5_KDB_NO_PERMITTED_KEY` (the requested etype, or every matching key, is outside `permitted_enctypes`).
/// Both are KDB-library codes the KDC clamps to 60 `GENERIC` on the wire; the split is for logs and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyLookup {
    /// `KRB5_KDB_NO_MATCHING_KEY`.
    NoMatchingKey,
    /// `KRB5_KDB_NO_PERMITTED_KEY`.
    NoPermittedKey,
}

/// MIT `krb5_ktkdb_get_entry` (`lib/kdb/keytab.c:117-185`): the code it returns.
/// MIT `keytab_fetch_error` (`lib/krb5/krb/rd_req_dec.c:118-148`): takes `KRB5_KT_NOTFOUND` and `KRB5_KT_KVNONOTFOUND` as codes of their own and passes any other on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KtkdbError {
    /// `KRB5_KT_NOTFOUND`: no such principal, or one that may not be a service (`KRB5_KDB_DISALLOW_SVR`, `KRB5_KDB_DISALLOW_ALL_TIX`).
    NotFound,
    /// `KRB5_KT_KVNONOTFOUND`: the principal has no key at that kvno.
    KvnoNotFound,
    /// `KRB5_KDB_NO_PERMITTED_KEY`: the key found is not of the ticket's enctype, or every key at the kvno is outside `permitted_enctypes`.
    NoPermittedKey,
    /// `KRB5_BAD_ENCTYPE`: the ticket's enctype or the key's is not one MIT implements.
    BadEnctype,
}

impl From<KtkdbError> for krb5_protocol::KeytabLookup {
    fn from(e: KtkdbError) -> Self {
        match e {
            KtkdbError::NotFound => Self::NotFound,
            KtkdbError::KvnoNotFound => Self::KvnoNotFound,
            KtkdbError::NoPermittedKey => Self::Other(krb5_protocol::Error::KdbNoPermittedKey),
            KtkdbError::BadEnctype => Self::Other(krb5_protocol::Error::BadEnctype),
        }
    }
}

/// The key the KDB keytab gives for a ticket's kvno and enctype.
/// MIT `is_xrealm_tgt` (`lib/kdb/keytab.c:200-220`): `krbtgt` (a prefix of the word does) and a second component that is not the realm.
pub fn ktkdb_get_entry<'p>(
    principal: Option<&'p Principal>,
    name: &PrincipalName,
    realm: &str,
    kvno: u32,
    etype: i32,
    permitted: impl Fn(EncryptionType) -> bool,
) -> Result<&'p KeyEntry, KtkdbError> {
    let xrealm_tgt = is_xrealm_tgt(name, realm);
    let Some(p) = principal else {
        return Err(KtkdbError::NotFound);
    };
    if p.attributes & (KDB_DISALLOW_SVR | KDB_DISALLOW_ALL_TIX) != 0 {
        return Err(KtkdbError::NotFound);
    }
    let want = if xrealm_tgt {
        match EncryptionType::known(etype) {
            Ok(e) => Some(e),
            Err(_) => return Err(KtkdbError::NoPermittedKey),
        }
    } else {
        None
    };
    let key = match p.find_enctype(want, kvno, permitted) {
        Ok(k) => k,
        Err(KeyLookup::NoMatchingKey) => return Err(KtkdbError::KvnoNotFound),
        Err(KeyLookup::NoPermittedKey) => return Err(KtkdbError::NoPermittedKey),
    };
    if etype > 0 {
        match (enctype_class(etype), enctype_class(key.etype.to_iana())) {
            (Some(a), Some(b)) if a == b => {}
            (Some(_), Some(_)) => return Err(KtkdbError::NoPermittedKey),
            _ => return Err(KtkdbError::BadEnctype),
        }
    }
    Ok(key)
}

fn is_xrealm_tgt(name: &PrincipalName, realm: &str) -> bool {
    let [c0, c1] = name.name_string.as_slice() else {
        return false;
    };
    b"krbtgt".starts_with(c0.as_bytes()) && c1.as_bytes() != realm.as_bytes()
}

/// MIT `krb5_c_enctype_compare` (`lib/crypto/krb/enctype_util.c:73-86`): two enctypes are similar when they share an encryption method and a string-to-key.
/// MIT `krb5int_enctypes_list` (`lib/crypto/krb/etypes.c:38-145`): des3-cbc-raw and des3-cbc-sha1 are alike, so are arcfour-hmac and its export form; each AES and Camellia enctype stands alone.
fn enctype_class(etype: i32) -> Option<u8> {
    match etype {
        6 | 16 => Some(1),
        23 | 24 => Some(2),
        17 => Some(3),
        18 => Some(4),
        19 => Some(5),
        20 => Some(6),
        25 => Some(7),
        26 => Some(8),
        _ => None,
    }
}

impl KeyEntry {
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

/// A random protocol key of `etype`: every key this KDC draws, a principal's `-randkey` and `ktadd` keys, the krbtgt, history and master keys and the session and sub keys of its replies.
/// MIT `krb5_c_make_random_key` (`lib/crypto/krb/make_random_key.c:31-76`): `keybytes` random octets through the enctype's random-to-key, so a des3 key is 21 octets spread over 24 with odd parity on each (`k5_rand2key_des3`, `k5_des_fixup_key_parity`), and every other enctype takes its random octets as the key.
pub fn random_key(etype: EncryptionType) -> Result<ProtocolKey, Error> {
    ProtocolKey::random(etype).map_err(|e| match e {
        krb5_crypto::Error::Rng => Error::Rng,
        e => Error::from(e),
    })
}

/// The key types a new key set takes when kdc.conf names no `supported_enctypes`.
/// MIT `KRB5_DEFAULT_SUPPORTED_ENCTYPES` (`include/osconf.hin:109-111`): aes256-cts-hmac-sha1-96 and aes128-cts-hmac-sha1-96, normal salt.
pub(super) fn default_supported_enctypes() -> [EncryptionType; 2] {
    [
        EncryptionType::Aes256CtsHmacSha196,
        EncryptionType::Aes128CtsHmacSha196,
    ]
}

impl PrincipalStore {
    #[must_use]
    pub fn krbtgt(&self) -> Option<&Principal> {
        self.get_name(&PrincipalName::krbtgt(&self.realm))
    }

    /// ACL-gated keytab export using the existing v2 writer.
    /// `LOCKDOWN_KEYS` is refused. Local CLI export uses [`Self::export_keytab_local`].
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

    /// Local-operator keytab export for `--export-keytab` / `--export-krbtgt-keytab`.
    /// The operator already holds the DB and stash, so `LOCKDOWN_KEYS` is not applied. Remote kadm5 extract still uses [`Self::export_keytab`].
    pub fn export_keytab_local(&self, name: &PrincipalName) -> Result<Keytab, Error> {
        #[cfg(test)]
        if FAIL_NEXT_KTADD_EXPORT.with(Cell::get) {
            FAIL_NEXT_KTADD_EXPORT.with(|c| c.set(false));
            return Err(Error::Crypto("injected export fail".into()));
        }
        let p = self.get_name(name).ok_or(Error::NotFound)?;
        Self::keytab_from(p)
    }

    /// Local `ktadd`: optional rotate, export ignoring lockdown, then `write`, as one change to the database under its exclusive lock ([`Self::change`]): the rotation is written only once `write` succeeded, so a failed export or `write` leaves the database's kvno as it was (a store with no database puts the old keys back). Standalone `chrand` does not roll back.
    pub fn ktadd_local_atomic(
        &mut self,
        name: &PrincipalName,
        rotate: bool,
        actor: &str,
        write: impl FnOnce(&Keytab) -> Result<(), Error>,
    ) -> Result<Keytab, Error> {
        let snap = self.get_name(name).cloned().ok_or(Error::NotFound)?;
        let persisted = self.persist_paths.is_some();
        self.change(|s| {
            let done = (|| {
                if rotate {
                    s.chrand_etypes_keepold(name, &[], 0, actor)?;
                }
                let kt = s.export_keytab_local(name)?;
                write(&kt)?;
                Ok(kt)
            })();
            if done.is_err() && rotate && !persisted {
                let id = snap.id();
                s.note_ulog(id.clone(), false, Some(snap.clone()));
                s.map.insert(id, snap);
                let _ = s.log_pending();
            }
            done
        })?
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
    /// Default MIT `cpw -randkey` / `ktadd` does not keep old kvnos, so the previous password must fail `kinit`.
    /// [`Error::NotFound`] when the principal is missing; [`Error::Rng`] when the CSPRNG fails; [`Error::Db`] when saving the store to `persist_paths` fails.
    pub fn chrand(&mut self, name: &PrincipalName) -> Result<Vec<KeyEntry>, Error> {
        self.chrand_keepold_n(name, 0)
    }

    /// [`Self::chrand`] with MIT `keepold` (0 / 1 / N versions).
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
    /// MIT `kadm5_randkey_principal_3` (`svr_principal.c:1425-1425`): an omitted `-e` reaches `apply_keysalt_policy` as zero keysalts, so the policy or realm default applies.
    pub fn chrand_etypes_keepold_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        etypes: &[EncryptionType],
        keepold: u32,
        actor: &str,
    ) -> Result<Vec<KeyEntry>, Error> {
        self.inside_change()?;
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
        for etype in &use_etypes {
            new_keys.push(KeyEntry::new(*etype, random_key(*etype)?, next_kvno));
        }
        super::kadm5_hook::hook_chpass(
            self,
            super::kadm5_hook::HookStage::Precommit,
            name,
            princ_realm,
            keepold,
            None,
            &use_etypes,
        )?;
        {
            let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
            let old = std::mem::replace(&mut p.keys, new_keys.clone());
            if keepold > 0 {
                p.keys.extend(old);
                if keepold > 1 {
                    cap_key_versions(&mut p.keys, keepold);
                }
            }
            // MIT `kadm5_randkey_principal_3` (`lib/kadm5/srv/svr_principal.c:1452-1475`): new keys clear REQUIRES_PWCHANGE and unlock the principal on this KDC.
            p.attributes &= !KDB_REQUIRES_PWCHANGE;
            p.fail_auth_count = 0;
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
        self.postcommit(super::kadm5_hook::Post::Chpass {
            princ: name.clone(),
            realm: princ_realm.to_owned(),
            keepold,
            password: None,
            etypes: use_etypes,
        });
        Ok(new_keys)
    }

    /// `cpw -randkey -e` with MIT `keepold`. Empty `etypes` uses policy salts.
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

    /// Drop keys with kvno below `keepkvno`. `keepkvno <= 0` keeps only the newest kvno (MIT `purgekeys` without `-keepkvno`).
    pub fn purgekeys(&mut self, name: &PrincipalName, keepkvno: i32) -> Result<(), Error> {
        let realm = self.realm.clone();
        let actor = default_mod_actor(&realm);
        self.purgekeys_in(name, &realm, keepkvno, &actor)
    }

    /// [`Self::purgekeys`] for `name@princ_realm`.
    /// MIT `kadm5_purgekeys` → `kdb_put_entry` stamps `current_caller` even when no old keys are dropped.
    pub fn purgekeys_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        keepkvno: i32,
        actor: &str,
    ) -> Result<(), Error> {
        self.inside_change()?;
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
    /// `kvno == 0` on every entry picks the next version. `keepold` is MIT's integer: 0 discard, 1 keep all, N keep N versions including the new.
    /// [`Error::NotFound`] when the principal is missing; [`Error::Crypto`] when `keys` is empty, its entries carry different kvnos or `keepold` collides with an existing kvno; [`Error::Db`] when saving the store to `persist_paths` fails.
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
    pub fn set_keys_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        mut keys: Vec<KeyEntry>,
        keepold: u32,
        actor: &str,
    ) -> Result<(), Error> {
        self.inside_change()?;
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
