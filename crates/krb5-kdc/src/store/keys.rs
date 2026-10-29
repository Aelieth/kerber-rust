//! Long-term keys, lookup, and a keytab export.

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
    pub etype: EncryptionType,
    pub key: ProtocolKey,
    pub kvno: u32,
    pub salt_type: Option<i32>,
    pub kdb_salt: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyLookup {
    NoMatchingKey,
    NoPermittedKey,
}

impl KeyLookup {
    // MIT: `KRB5_KDB_NO_PERMITTED_KEY` (lib/krb5/error_tables/kdb5_err.et:72-72)
    // MIT: `KRB5_KDB_NO_MATCHING_KEY` (lib/krb5/error_tables/kdb5_err.et:73-73)
    #[must_use]
    pub fn message(self) -> &'static str {
        match self {
            Self::NoPermittedKey => "No matching key in entry having a permitted enctype",
            Self::NoMatchingKey => "No matching key in entry",
        }
    }
}

// MIT: `krb5_ktkdb_get_entry` (lib/kdb/keytab.c:117-185)
// MIT: `keytab_fetch_error` (lib/krb5/krb/rd_req_dec.c:118-148)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KtkdbError {
    NotFound,
    KvnoNotFound,
    NoPermittedKey,
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

// MIT: `is_xrealm_tgt` (lib/kdb/keytab.c:200-220)
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

/// A prefix of krbtgt; the second component is not the realm.
fn is_xrealm_tgt(name: &PrincipalName, realm: &str) -> bool {
    let [c0, c1] = name.name_string.as_slice() else {
        return false;
    };
    b"krbtgt".starts_with(c0.as_bytes()) && c1.as_bytes() != realm.as_bytes()
}

// MIT: `krb5_c_enctype_compare` (lib/crypto/krb/enctype_util.c:73-86)
// MIT: `krb5int_enctypes_list` (lib/crypto/krb/etypes.c:38-145)
fn enctype_class(etype: i32) -> Option<u8> {
    // des3-cbc-raw and des3-cbc-sha1 match; so do the two arcfour enctypes.
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

// MIT: `rekey` (lib/kdb/kdb_cpw.c:355-362)
pub(super) fn next_kvno(keys: &[KeyEntry]) -> u32 {
    match keys.iter().map(|k| k.kvno).max() {
        Some(n) if n >= 65535 => 1,
        Some(n) => n + 1,
        None => 1,
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

// MIT: `krb5_c_make_random_key` (lib/crypto/krb/make_random_key.c:31-76)
pub fn random_key(etype: EncryptionType) -> Result<ProtocolKey, Error> {
    ProtocolKey::random(etype).map_err(|e| match e {
        krb5_crypto::Error::Rng => Error::Rng,
        e => Error::from(e),
    })
}

// MIT: `KRB5_DEFAULT_SUPPORTED_ENCTYPES` (include/osconf.hin:109-111)
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

    /// Local export skips LOCKDOWN_KEYS.
    pub fn export_keytab_local(&self, name: &PrincipalName) -> Result<Keytab, Error> {
        #[cfg(test)]
        if FAIL_NEXT_KTADD_EXPORT.with(Cell::get) {
            FAIL_NEXT_KTADD_EXPORT.with(|c| c.set(false));
            return Err(Error::Crypto("injected export fail".into()));
        }
        let p = self.get_name(name).ok_or(Error::NotFound)?;
        Self::keytab_from(p)
    }

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
            // No database: a failed rotate puts the old keys back.
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

    pub fn chrand(&mut self, name: &PrincipalName) -> Result<Vec<KeyEntry>, Error> {
        self.chrand_keepold_n(name, 0)
    }

    /// 0 drops old keys; 1 keeps every older kvno; N keeps N, new included.
    pub fn chrand_keepold_n(
        &mut self,
        name: &PrincipalName,
        keepold: u32,
    ) -> Result<Vec<KeyEntry>, Error> {
        let realm = self.realm.clone();
        let actor = default_mod_actor(&realm);
        self.chrand_etypes_keepold_in(name, &realm, &[], keepold, &actor)
    }

    // MIT: `kadm5_randkey_principal_3` (svr_principal.c:1425-1425)
    pub fn chrand_etypes_keepold_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        etypes: &[EncryptionType],
        keepold: u32,
        actor: &str,
    ) -> Result<Vec<KeyEntry>, Error> {
        self.inside_change()?;
        let history = princ_realm == self.realm && name.components_joined() == "kadmin/history";
        if history && keepold > 0 {
            return Err(Error::InvalidArgument(
                "Cannot change protected principal".into(),
            ));
        }
        let id = self.canonical_id(name, princ_realm)?;
        let existing = self.map.get(&id).ok_or(Error::NotFound)?;
        let kvno = next_kvno(&existing.keys);
        let allowed = existing
            .pw_policy
            .as_ref()
            .and_then(|n| self.policies.get(n))
            .and_then(|p| p.allowed_keysalts.clone());
        let mut use_etypes =
            apply_keysalt_policy(allowed.as_deref(), etypes, &self.policy.password_etypes())?;
        if history {
            use_etypes.truncate(1);
        }
        let mut new_keys = Vec::new();
        for etype in &use_etypes {
            new_keys.push(KeyEntry::new(*etype, random_key(*etype)?, kvno));
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
            // MIT: `kadm5_randkey_principal_3` (lib/kadm5/srv/svr_principal.c:1452-1475)
            p.attributes &= !KDB_REQUIRES_PWCHANGE;
            p.fail_auth_count = 0;
            stamp_admin_tl(p, true, actor);
        }
        self.apply_pw_max_life_in(name, princ_realm)?;
        let snap = self.map.get(&id).cloned();
        if let Some(p) = &snap {
            self.zero_fail_count_in_file(p, crate::store::unix_now_u32());
        }
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

    pub fn purgekeys(&mut self, name: &PrincipalName, keepkvno: i32) -> Result<(), Error> {
        let realm = self.realm.clone();
        let actor = default_mod_actor(&realm);
        self.purgekeys_in(name, &realm, keepkvno, &actor)
    }

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

    // MIT: `kadm5_setkey_principal_4` (lib/kadm5/srv/svr_principal.c:1581-1750)
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
            return Err(Error::InvalidArgument("Invalid argument".into()));
        }
        if princ_realm == self.realm && name.components_joined() == "kadmin/history" {
            return Err(Error::InvalidArgument(
                "Cannot change protected principal".into(),
            ));
        }
        let want = keys[0].kvno;
        if keys.iter().any(|k| k.kvno != want) {
            return Err(Error::Crypto("setkey kvno".into()));
        }
        let id = self.canonical_id(name, princ_realm)?;
        let p = self.map.get(&id).ok_or(Error::NotFound)?;
        let kvno = if want == 0 {
            next_kvno(&p.keys)
        } else if want > 65535 || keepold > 0 && p.keys.iter().any(|k| k.kvno == want) {
            return Err(Error::Crypto("setkey kvno".into()));
        } else {
            want
        };
        let allowed = p.pw_policy.as_ref().and_then(|n| self.policies.get(n));
        let etypes: Vec<EncryptionType> = keys.iter().map(|k| k.etype).collect();
        apply_keysalt_policy(
            allowed.and_then(|pol| pol.allowed_keysalts.as_deref()),
            &etypes,
            &[],
        )?;
        let salt = |k: &KeyEntry| k.salt_type.filter(|t| *t > 0).unwrap_or(0);
        for (i, a) in keys.iter().enumerate() {
            if keys[i + 1..]
                .iter()
                .any(|b| a.etype == b.etype && salt(a) == salt(b))
            {
                return Err(Error::InvalidArgument(
                    "Multiple values for single or folded enctype".into(),
                ));
            }
        }
        {
            let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
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
        if let Some(p) = &snap {
            self.zero_fail_count_in_file(p, crate::store::unix_now_u32());
        }
        self.note_ulog(id, false, snap);
        self.save_if_configured()
    }
}
