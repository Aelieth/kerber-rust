//! Realm principal records and the kadm5 create, modify, rename, and delete path.

use krb5_crypto::{EncryptionType, KeySalt};
use krb5_types::PrincipalName;

use super::flags::{KDB_DISALLOW_ALL_TIX, KDB_REQUIRES_PRE_AUTH, KDB_V1_BASE_LENGTH};
use super::keys::{KeyEntry, KeyLookup, random_keys};
use super::password::{apply_keysalt_policy, c_password, keys_from_password};
use super::{PrincipalStore, kadm5_mask, unix_now_u32};
use crate::acl::{Acl, AdminOp, Restrictions};
use crate::error::Error;
use crate::kdb_dump::{
    TL_ALIAS_TARGET, TL_DB_ARGS, TL_KADM_DATA, TL_KERBER_HIST, TL_KERBER_POLICY,
    TL_LAST_ADMIN_UNLOCK, TL_LAST_PWD_CHANGE, TL_MOD_PRINC, TL_STRING_ATTRS,
};
use crate::lockout::{Lockout, LockoutUpdate};
use crate::osa::{INITIAL_HIST_KVNO, KADM5_POLICY, OsaKeyData, OsaPrincEnt};

fn qualify_s4u_from(from: &str, local_realm: &str) -> String {
    if from.contains('@') {
        from.to_owned()
    } else {
        format!("{from}@{local_realm}")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TlData {
    pub ty: i32,
    pub contents: Vec<u8>,
}

impl std::fmt::Debug for TlData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlData")
            .field("ty", &self.ty)
            .field("contents", &self.contents.len())
            .finish()
    }
}

// MIT: `extract_db_args_from_tl_data` (kdb5.c:893-945)
/// A `KRB5_TL_DB_ARGS` without a trailing NUL is `EINVAL`.
// MIT: `krb5_db2_put_principal` (kdb_db2.c:817-822)
#[must_use]
pub(crate) fn db_args_put_error(tl: &[TlData]) -> Option<Error> {
    for t in tl {
        if t.ty != TL_DB_ARGS {
            continue;
        }
        if t.contents.last() != Some(&0) {
            return Some(Error::InvalidArgument("Invalid argument".into()));
        }
        let s = String::from_utf8_lossy(&t.contents[..t.contents.len() - 1]);
        return Some(Error::InvalidArgument(format!(
            "Unsupported argument \"{s}\" for db2"
        )));
    }
    None
}

pub fn strip_db_args(tl: &mut Vec<TlData>) -> Result<(), Error> {
    if let Some(e) = db_args_put_error(tl) {
        return Err(e);
    }
    tl.retain(|t| t.ty != TL_DB_ARGS);
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KadmData {
    pub aux_attributes: u32,
    pub old_key_next: u32,
    pub admin_history_kvno: u32,
    pub old_keys: Vec<Vec<OsaKeyData>>,
}

impl Default for KadmData {
    fn default() -> Self {
        Self {
            aux_attributes: 0,
            old_key_next: 0,
            admin_history_kvno: INITIAL_HIST_KVNO,
            old_keys: Vec::new(),
        }
    }
}

impl KadmData {
    #[must_use]
    pub fn from_osa(osa: &OsaPrincEnt) -> Self {
        Self {
            aux_attributes: osa.aux_attributes,
            old_key_next: osa.old_key_next,
            admin_history_kvno: osa.admin_history_kvno,
            old_keys: osa.old_keys.clone(),
        }
    }
}

/// Unix seconds, 0 never; max_life 0: no limit; renewable life 0: no renewal.
#[derive(Clone)]
pub struct Principal {
    pub name: PrincipalName,
    pub realm: String,
    pub keys: Vec<KeyEntry>,
    pub key_history: Vec<KeyEntry>,
    pub salt: Vec<u8>,
    pub(crate) requires_preauth: bool,
    pub max_life: u64,
    pub(crate) locked: bool,
    pub pw_expire: u32,
    pub attributes: u32,
    pub max_renewable_life: u64,
    pub expiration: u32,
    pub last_success: u32,
    pub last_failed: u32,
    pub fail_auth_count: u32,
    pub mkvno: u16,
    pub db_entry_len: u32,
    pub tl_data: Vec<TlData>,
    pub e_data: Vec<u8>,
    pub rid: u32,
    pub s4u_allowed_from: Vec<String>,
    pub s4u_allowed_to: Vec<String>,
    pub pw_policy: Option<String>,
    pub kadm: KadmData,
    pub string_attrs: Vec<(String, String)>,
}

impl std::fmt::Debug for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Principal")
            .field("name", &self.name)
            .field("realm", &self.realm)
            .field("keys", &self.keys.len())
            .field("key_history", &self.key_history.len())
            .field("salt", &self.salt.len())
            .field("requires_preauth", &self.requires_preauth)
            .field("max_life", &self.max_life)
            .field("locked", &self.locked)
            .field("pw_expire", &self.pw_expire)
            .field("attributes", &self.attributes)
            .field("max_renewable_life", &self.max_renewable_life)
            .field("expiration", &self.expiration)
            .field("last_success", &self.last_success)
            .field("last_failed", &self.last_failed)
            .field("fail_auth_count", &self.fail_auth_count)
            .field("mkvno", &self.mkvno)
            .field("db_entry_len", &self.db_entry_len)
            .field("tl_data", &self.tl_data)
            .field("e_data", &self.e_data.len())
            .field("rid", &self.rid)
            .field("s4u_allowed_from", &self.s4u_allowed_from)
            .field("s4u_allowed_to", &self.s4u_allowed_to)
            .field("pw_policy", &self.pw_policy)
            .field("kadm", &self.kadm)
            .field("string_attrs", &self.string_attrs)
            .finish()
    }
}

// MIT: `krb5_db_entry` (include/kdb.h:191-213)
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PrincipalFields {
    pub(crate) requires_preauth: bool,
    pub(crate) max_life: u64,
    pub(crate) locked: bool,
    pub(crate) pw_expire: u32,
}

impl Principal {
    #[must_use]
    pub fn tl_with_s4u(&self) -> Vec<TlData> {
        let mut tl = self.tl_data.clone();
        crate::kdb_dump::merge_s4u_tl(&mut tl, self);
        tl
    }

    // MIT: `missing_required_preauth` (kdc_preauth.c:729-750)
    #[must_use]
    pub fn requires_preauth(&self) -> bool {
        self.attributes & KDB_REQUIRES_PRE_AUTH != 0
    }

    #[must_use]
    pub fn locked(&self) -> bool {
        self.attributes & KDB_DISALLOW_ALL_TIX != 0
    }

    pub(crate) fn reconcile_flags(&mut self) {
        self.requires_preauth = self.requires_preauth();
        self.locked = self.locked();
    }

    pub(crate) fn set_locked(&mut self, on: bool) {
        if on {
            self.attributes |= KDB_DISALLOW_ALL_TIX;
        } else {
            self.attributes &= !KDB_DISALLOW_ALL_TIX;
        }
        self.locked = on;
    }

    pub(crate) fn from_keys(
        name: PrincipalName,
        realm: String,
        keys: Vec<KeyEntry>,
        salt: Vec<u8>,
        fields: PrincipalFields,
    ) -> Self {
        let PrincipalFields {
            requires_preauth,
            max_life,
            locked,
            pw_expire,
        } = fields;
        let mut attributes = 0u32;
        if requires_preauth {
            attributes |= KDB_REQUIRES_PRE_AUTH;
        }
        if locked {
            attributes |= KDB_DISALLOW_ALL_TIX;
        }
        Self {
            name,
            realm,
            keys,
            key_history: Vec::new(),
            salt,
            requires_preauth,
            max_life,
            locked,
            pw_expire,
            attributes,
            max_renewable_life: 0,
            expiration: 0,
            last_success: 0,
            last_failed: 0,
            fail_auth_count: 0,
            mkvno: 1,
            db_entry_len: KDB_V1_BASE_LENGTH,
            tl_data: Vec::new(),
            e_data: Vec::new(),
            rid: 0,
            s4u_allowed_from: Vec::new(),
            s4u_allowed_to: Vec::new(),
            pw_policy: None,
            kadm: KadmData::default(),
            string_attrs: Vec::new(),
        }
    }
}

pub struct PrincipalBuilder {
    name: PrincipalName,
    realm: String,
    keys: Vec<KeyEntry>,
    salt: Vec<u8>,
    attributes: u32,
    max_life: u64,
    pw_expire: u32,
}

impl PrincipalBuilder {
    #[must_use]
    pub fn new(name: PrincipalName, realm: impl Into<String>) -> Self {
        let realm = realm.into();
        let salt = name.default_salt(&realm);
        Self {
            name,
            realm,
            keys: Vec::new(),
            salt,
            attributes: 0,
            max_life: 0,
            pw_expire: 0,
        }
    }

    #[must_use]
    pub fn keys(mut self, keys: Vec<KeyEntry>) -> Self {
        self.keys = keys;
        self
    }

    #[must_use]
    pub fn attributes(mut self, attributes: u32) -> Self {
        self.attributes = attributes;
        self
    }

    #[must_use]
    pub fn requires_preauth(mut self, on: bool) -> Self {
        if on {
            self.attributes |= KDB_REQUIRES_PRE_AUTH;
        } else {
            self.attributes &= !KDB_REQUIRES_PRE_AUTH;
        }
        self
    }

    #[must_use]
    pub fn locked(mut self, on: bool) -> Self {
        if on {
            self.attributes |= KDB_DISALLOW_ALL_TIX;
        } else {
            self.attributes &= !KDB_DISALLOW_ALL_TIX;
        }
        self
    }

    #[must_use]
    pub fn max_life(mut self, max_life: u64) -> Self {
        self.max_life = max_life;
        self
    }

    #[must_use]
    pub fn build(self) -> Principal {
        let mut p = Principal::from_keys(
            self.name,
            self.realm,
            self.keys,
            self.salt,
            PrincipalFields {
                requires_preauth: self.attributes & KDB_REQUIRES_PRE_AUTH != 0,
                max_life: self.max_life,
                locked: self.attributes & KDB_DISALLOW_ALL_TIX != 0,
                pw_expire: self.pw_expire,
            },
        );
        p.attributes = self.attributes;
        p.reconcile_flags();
        p
    }
}

// MIT: `kadm5_create_principal_3` (svr_principal.c:376-420)
/// A field applies only with its mask bit set; else the realm default.
// MIT: `impose_restrictions` (auth.c:205-265)
// MIT: `auth_restrict` (auth.c:267-272)
#[derive(Copy, Clone)]
pub enum CreateKeys<'a> {
    Password(&'a [u8]),
    Random,
    Explicit(&'a [KeyEntry]),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdminEnt {
    pub mask: u32,
    pub attributes: u32,
    pub max_life: u32,
    pub max_renewable_life: u32,
    pub princ_expire_time: u32,
    pub pw_expiration: u32,
    pub kvno: u32,
    pub policy: Option<String>,
}

impl Principal {
    #[must_use]
    pub fn id(&self) -> String {
        crate::kdb::lookup_principal_id(&self.name, &self.realm)
    }

    #[must_use]
    pub fn alias_target(&self) -> Option<String> {
        let tl = self.tl_data.iter().find(|t| t.ty == TL_ALIAS_TARGET)?;
        let (nul, target) = tl.contents.split_last()?;
        if *nul != 0 {
            return None;
        }
        String::from_utf8(target.to_vec()).ok()
    }

    #[must_use]
    pub fn key_for(&self, etype: EncryptionType) -> Option<&KeyEntry> {
        self.keys
            .iter()
            .filter(|k| k.etype == etype)
            .max_by_key(|k| k.kvno)
    }

    #[must_use]
    pub fn first_current_key(&self) -> Option<&KeyEntry> {
        let kvno = self.keys.iter().map(|k| k.kvno).max()?;
        self.first_key_at_kvno(kvno)
    }

    #[must_use]
    pub fn first_key_at_kvno(&self, kvno: u32) -> Option<&KeyEntry> {
        self.keys.iter().find(|k| k.kvno == kvno)
    }

    // MIT: `krb5_dbe_def_search_enctype` (kdb_default.c:47-94)
    pub fn find_enctype(
        &self,
        etype: Option<EncryptionType>,
        kvno: u32,
        permitted: impl Fn(EncryptionType) -> bool,
    ) -> Result<&KeyEntry, KeyLookup> {
        if let Some(e) = etype
            && !permitted(e)
        {
            return Err(KeyLookup::NoPermittedKey);
        }
        let Some(top) = self.keys.iter().map(|k| k.kvno).max() else {
            return Err(KeyLookup::NoMatchingKey);
        };
        let kvno = if kvno == 0 { top } else { kvno };
        let mut saw_non_permitted = false;
        for k in &self.keys {
            if k.kvno != kvno || etype.is_some_and(|e| k.etype != e) {
                continue;
            }
            if !permitted(k.etype) {
                saw_non_permitted = true;
                continue;
            }
            return Ok(k);
        }
        Err(if saw_non_permitted {
            KeyLookup::NoPermittedKey
        } else {
            KeyLookup::NoMatchingKey
        })
    }

    #[must_use]
    pub fn best_key(&self) -> Option<&KeyEntry> {
        EncryptionType::preferred()
            .into_iter()
            .find_map(|e| self.key_for(e))
            .or_else(|| self.keys.first())
    }
}

pub(crate) fn refresh_kadm_tl(p: &mut Principal) {
    let bound = p.pw_policy.as_deref().is_some_and(|s| !s.is_empty());
    p.kadm.aux_attributes = if bound {
        p.kadm.aux_attributes | KADM5_POLICY
    } else {
        p.kadm.aux_attributes & !KADM5_POLICY
    };
    let rec = OsaPrincEnt {
        policy: p.pw_policy.clone().filter(|s| !s.is_empty()),
        aux_attributes: p.kadm.aux_attributes,
        old_key_next: p.kadm.old_key_next,
        admin_history_kvno: p.kadm.admin_history_kvno,
        old_keys: p.kadm.old_keys.clone(),
    };
    p.tl_data
        .retain(|t| t.ty != TL_KADM_DATA && t.ty != TL_KERBER_POLICY && t.ty != TL_KERBER_HIST);
    p.tl_data.push(TlData {
        ty: TL_KADM_DATA,
        contents: rec.encode(),
    });
}

/// A create without a kadm5 handle is stamped `db_creation@REALM`.
// MIT: `db_creator_entries` (kdb5_create.c:114-115)
// MIT: `db_create_princ` (kdb5_create.c:127-133)
pub(super) fn default_mod_actor(realm: &str) -> String {
    format!("db_creation@{realm}")
}

// MIT: `kadm5_init` (server_init.c:239-241)
fn canonical_mod_actor(actor: &str, realm: &str) -> String {
    if actor.contains('@') {
        actor.to_owned()
    } else {
        format!("{actor}@{realm}")
    }
}

// MIT: `krb5_dbe_update_last_pwd_change` (lib/kdb/kdb5.c:2055-2067)
// MIT: `krb5_dbe_update_mod_princ_data` (lib/kdb/kdb5.c:1596-1632)
pub(super) fn stamp_admin_tl(p: &mut Principal, pwd_change: bool, actor: &str) {
    let now = unix_now_u32();
    if pwd_change {
        super::update_tl_data(
            &mut p.tl_data,
            TlData {
                ty: TL_LAST_PWD_CHANGE,
                contents: now.to_le_bytes().to_vec(),
            },
        );
    }
    let mut modp = now.to_le_bytes().to_vec();
    modp.extend_from_slice(canonical_mod_actor(actor, &p.realm).as_bytes());
    modp.push(0);
    super::update_tl_data(
        &mut p.tl_data,
        TlData {
            ty: TL_MOD_PRINC,
            contents: modp,
        },
    );
}

// MIT: `kadm5_principal_ent_rec` (lib/kadm5/admin.h:213-213)
// MIT: `KADM5_ATTRIBUTES` (admin.h:92-92)
// MIT: `KADM5_MAX_LIFE` (admin.h:93-93)
// MIT: `KADM5_PRINC_EXPIRE_TIME` (admin.h:89-89)
// MIT: `KADM5_PW_EXPIRATION` (admin.h:90-90)
// MIT: `KADM5_POLICY` (admin.h:99-99)
// MIT: `KADM5_POLICY_CLR` (admin.h:100-100)
// MIT: `KADM5_MAX_RLIFE` (admin.h:102-102)
#[derive(Clone, Default)]
pub struct AdminFields {
    pub attributes: Option<u32>,
    pub max_life: Option<u64>,
    pub expiration: Option<u32>,
    pub pw_expire: Option<u32>,
    pub policy: Option<String>,
    pub clear_policy: bool,
    pub max_renewable_life: Option<u64>,
}

impl PrincipalStore {
    pub(crate) fn remove_id_inner(&mut self, id: &str) -> Result<(), Error> {
        self.inside_change()?;
        let (name, realm) = {
            let principal = self.map.get(id).ok_or(Error::NotFound)?;
            (principal.name.clone(), principal.realm.clone())
        };
        if realm == self.realm && name.components_joined() == "K/M" {
            return Err(Error::InvalidArgument(
                "Cannot change protected principal".into(),
            ));
        }
        super::kadm5_hook::hook_remove(
            self,
            super::kadm5_hook::HookStage::Precommit,
            &name,
            &realm,
        )?;
        self.map.remove(id).ok_or(Error::NotFound)?;
        self.note_ulog(id.to_owned(), true, None);
        self.save_if_configured()?;
        self.postcommit(super::kadm5_hook::Post::Remove { princ: name, realm });
        Ok(())
    }

    #[doc(hidden)]
    /// Memory only; use `record_s4u_to` for a store.
    pub fn allow_s4u_from(&mut self, name: &PrincipalName, from: &str) {
        let id = crate::kdb::lookup_principal_id(name, &self.realm);
        let qualified = qualify_s4u_from(from, &self.realm);
        if let Some(p) = self.map.get_mut(&id) {
            p.s4u_allowed_from.push(qualified);
        }
    }

    #[doc(hidden)]
    /// Memory only; use `record_s4u_to` for a store.
    pub fn allow_s4u_to(&mut self, name: &PrincipalName, to: &str) {
        let id = crate::kdb::lookup_principal_id(name, &self.realm);
        if let Some(p) = self.map.get_mut(&id) {
            p.s4u_allowed_to.push(to.to_owned());
        }
    }

    pub fn record_s4u_to(
        &mut self,
        name: &PrincipalName,
        to: &str,
        actor: &str,
    ) -> Result<(), Error> {
        self.inside_change()?;
        let id = crate::kdb::lookup_principal_id(name, &self.realm);
        let snap = {
            let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
            if p.s4u_allowed_to.iter().any(|have| have == to) {
                return Ok(());
            }
            p.s4u_allowed_to.push(to.to_owned());
            stamp_admin_tl(p, false, actor);
            p.clone()
        };
        self.note_ulog(id, false, Some(snap));
        self.save_if_configured()
    }

    pub fn clear_s4u_to(&mut self, name: &PrincipalName) {
        let id = crate::kdb::lookup_principal_id(name, &self.realm);
        if let Some(p) = self.map.get_mut(&id) {
            p.s4u_allowed_to.clear();
        }
    }

    pub fn create_password(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
        password: &[u8],
    ) -> Result<(), Error> {
        self.create_password_etypes(acl, actor, name, password, &[])
    }

    pub fn create_password_etypes(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
        password: &[u8],
        etypes: &[KeySalt],
    ) -> Result<(), Error> {
        let realm = self.realm.clone();
        self.create_password_etypes_in(acl, actor, name, &realm, password, etypes)
    }

    pub(crate) fn create_password_etypes_in(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
        princ_realm: &str,
        password: &[u8],
        etypes: &[KeySalt],
    ) -> Result<(), Error> {
        let id = crate::kdb::lookup_principal_id(name, princ_realm);
        acl.check(actor, AdminOp::Create, Some(&id))?;
        self.insert_new_password(name, princ_realm, password, etypes, actor)?;
        if let Some(rs) = acl.restrictions(actor, Some(&id)) {
            self.apply_acl_restrictions(&id, rs)?;
        }
        Ok(())
    }

    pub fn insert_new_password(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        password: &[u8],
        etypes: &[KeySalt],
        actor: &str,
    ) -> Result<(), Error> {
        self.create_principal_3_in(
            name,
            princ_realm,
            CreateKeys::Password(password),
            etypes,
            &AdminEnt::default(),
            actor,
        )
    }

    // MIT: `kadm5_create_principal_3` (svr_principal.c:463-470)
    /// A NULL password is random keys and skips `passwd_check`.
    pub fn insert_new_randkey(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        etypes: &[KeySalt],
        actor: &str,
    ) -> Result<(), Error> {
        self.create_principal_3_in(
            name,
            princ_realm,
            CreateKeys::Random,
            etypes,
            &AdminEnt::default(),
            actor,
        )
    }

    /// A create without `KADM5_ATTRIBUTES` takes `default_principal_flags`.
    #[must_use]
    pub fn default_create_attributes(&self, password_keyed: bool) -> u32 {
        self.policy.default_principal_flags.unwrap_or(
            if password_keyed && self.policy.requires_preauth {
                KDB_REQUIRES_PRE_AUTH
            } else {
                0
            },
        )
    }

    // MIT: `kadm5_create_principal_3` (svr_principal.c:290-511)
    // MIT: `kadm5_create_principal_3` (svr_principal.c:444-447)
    pub fn create_principal_3_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        keys: CreateKeys<'_>,
        etypes: &[KeySalt],
        ent: &AdminEnt,
        actor: &str,
    ) -> Result<(), Error> {
        self.inside_change()?;
        let (password, explicit) = match keys {
            CreateKeys::Password(p) => (Some(c_password(p)), None),
            CreateKeys::Random => (None, None),
            CreateKeys::Explicit(k) => (None, Some(k)),
        };
        let id = crate::kdb::lookup_principal_id(name, princ_realm);
        if self.get(&id).is_some() {
            return Err(Error::AlreadyExists);
        }
        let policy_name = (ent.mask & kadm5_mask::POLICY != 0)
            .then(|| ent.policy.clone())
            .flatten();
        let polent = policy_name
            .as_deref()
            .and_then(|n| self.policies.get(n))
            .cloned();
        if let Some(pw) = password {
            self.check_new_password_in(
                name,
                princ_realm,
                policy_name.as_deref(),
                pw,
                &mut |s, t| {
                    krb5_log::klog::syslog(s, t);
                },
            )?;
        }
        let now = unix_now_u32();
        let use_etypes: Vec<KeySalt> = if let Some(given) = explicit {
            given.iter().map(|k| KeySalt::from(k.etype)).collect()
        } else {
            apply_keysalt_policy(
                polent.as_ref().and_then(|p| p.allowed_keysalts.as_deref()),
                etypes,
                &self.policy.password_keysalts(),
            )?
        };
        let asked = if ent.mask & kadm5_mask::KVNO != 0 {
            if ent.kvno > 65535 {
                return Err(Error::InvalidArgument("invalid kvno".into()));
            }
            Some(ent.kvno)
        } else {
            None
        };
        let kvno = asked.unwrap_or(1);
        let keys = if let Some(given) = explicit {
            let mut keys = given.to_vec();
            if let Some(kvno) = asked {
                for key in &mut keys {
                    key.kvno = kvno;
                }
            }
            keys
        } else if let Some(pw) = password {
            keys_from_password(&use_etypes, pw, name, princ_realm, kvno)?
        } else {
            random_keys(&use_etypes, kvno)?
        };
        let attributes = if ent.mask & kadm5_mask::ATTRIBUTES != 0 {
            ent.attributes
        } else {
            self.default_create_attributes(password.is_some())
        };
        let salt = crate::kdb_dump::salt_of_keys(&keys, name, princ_realm);
        let mut p = Principal::from_keys(
            name.clone(),
            princ_realm.to_owned(),
            keys,
            salt,
            PrincipalFields {
                requires_preauth: attributes & KDB_REQUIRES_PRE_AUTH != 0,
                max_life: 0,
                locked: attributes & KDB_DISALLOW_ALL_TIX != 0,
                pw_expire: 0,
            },
        );
        p.attributes = attributes;
        p.max_life = if ent.mask & kadm5_mask::MAX_LIFE != 0 {
            u64::from(ent.max_life)
        } else {
            self.policy.max_life
        };
        p.max_renewable_life = if ent.mask & kadm5_mask::MAX_RLIFE != 0 {
            u64::from(ent.max_renewable_life)
        } else {
            self.policy.max_renewable_life
        };
        p.expiration = if ent.mask & kadm5_mask::PRINC_EXPIRE_TIME != 0 {
            ent.princ_expire_time
        } else {
            self.policy.default_principal_expiration
        };
        p.pw_expire = if ent.mask & kadm5_mask::PW_EXPIRATION != 0 {
            ent.pw_expiration
        } else {
            match &polent {
                Some(pol) if pol.pw_max_life != 0 => now.saturating_add(pol.pw_max_life),
                _ => 0,
            }
        };
        if let Some(pol) = policy_name {
            p.pw_policy = Some(pol);
            refresh_kadm_tl(&mut p);
        }
        stamp_admin_tl(&mut p, true, actor);
        let hook_etypes: Vec<EncryptionType> = use_etypes.iter().map(|ks| ks.etype).collect();
        super::kadm5_hook::hook_create(
            self,
            super::kadm5_hook::HookStage::Precommit,
            name,
            princ_realm,
            ent.mask,
            password,
            &hook_etypes,
        )?;
        self.put_principal(p)?;
        self.save_if_configured()?;
        self.postcommit(super::kadm5_hook::Post::Create {
            princ: name.clone(),
            realm: princ_realm.to_owned(),
            mask: ent.mask,
            password: password.map(|p| zeroize::Zeroizing::new(p.to_vec())),
            etypes: hook_etypes,
        });
        Ok(())
    }

    pub fn create_host(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
    ) -> Result<(), Error> {
        self.create_host_etypes(acl, actor, name, &[])
    }

    pub fn create_host_etypes(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
        etypes: &[KeySalt],
    ) -> Result<(), Error> {
        self.inside_change()?;
        let id = crate::kdb::lookup_principal_id(name, &self.realm);
        acl.check(actor, AdminOp::Create, Some(&id))?;
        if self.get(&id).is_some() {
            return Err(Error::AlreadyExists);
        }
        let realm = self.realm.clone();
        self.create_principal_3_in(
            name,
            &realm,
            CreateKeys::Random,
            etypes,
            &AdminEnt::default(),
            actor,
        )?;
        if let Some(rs) = acl.restrictions(actor, Some(&id)) {
            self.apply_acl_restrictions(&id, rs)?;
        }
        self.save_if_configured()?;
        Ok(())
    }

    pub fn create_etypes_pol(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
        password: Option<&[u8]>,
        etypes: &[KeySalt],
        policy: Option<&str>,
    ) -> Result<(), Error> {
        let realm = self.realm.clone();
        let id = crate::kdb::lookup_principal_id(name, &realm);
        acl.check(actor, AdminOp::Create, Some(&id))?;
        let mut ent = AdminEnt::default();
        if let Some(p) = policy {
            ent.mask |= kadm5_mask::POLICY;
            ent.policy = Some(p.to_owned());
        }
        let keys = match password {
            Some(p) => CreateKeys::Password(p),
            None => CreateKeys::Random,
        };
        self.create_principal_3_in(name, &realm, keys, etypes, &ent, actor)?;
        if let Some(rs) = acl.restrictions(actor, Some(&id)) {
            self.apply_acl_restrictions(&id, rs)?;
        }
        Ok(())
    }

    pub fn set_status(
        &mut self,
        name: &PrincipalName,
        locked: bool,
        pw_expire: u32,
        actor: &str,
    ) -> Result<(), Error> {
        self.inside_change()?;
        let id = self.canonical_id(name, &self.realm)?;
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        p.set_locked(locked);
        p.pw_expire = pw_expire;
        stamp_admin_tl(p, false, actor);
        let snap = p.clone();
        self.note_ulog(id, false, Some(snap));
        self.save_if_configured()
    }

    pub fn admin_unlock(&mut self, name: &PrincipalName) -> Result<(), Error> {
        let realm = self.realm.clone();
        let actor = default_mod_actor(&realm);
        self.admin_unlock_in(name, &realm, &actor)
    }

    // MIT: `kadm5_modify_principal` (svr_principal.c:685-685)
    // MIT: `kdb_put_entry` (server_kdb.c:376-377)
    pub fn admin_unlock_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        actor: &str,
    ) -> Result<(), Error> {
        self.inside_change()?;
        let id = self.canonical_id(name, princ_realm)?;
        let now = unix_now_u32();
        {
            let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
            p.fail_auth_count = 0;
            p.tl_data.retain(|t| t.ty != TL_LAST_ADMIN_UNLOCK);
            p.tl_data.push(TlData {
                ty: TL_LAST_ADMIN_UNLOCK,
                contents: now.to_le_bytes().to_vec(),
            });
            stamp_admin_tl(p, false, actor);
        }
        let snap = self.map.get(&id).cloned();
        if let Some(p) = &snap {
            self.zero_fail_count_in_file(p, now);
        }
        self.note_ulog(id, false, snap);
        self.save_if_configured()
    }

    pub fn clear_fail_auth_count_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        actor: &str,
    ) -> Result<(), Error> {
        self.inside_change()?;
        let id = self.canonical_id(name, princ_realm)?;
        {
            let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
            p.fail_auth_count = 0;
            stamp_admin_tl(p, false, actor);
        }
        let snap = self.map.get(&id).cloned();
        if let Some(p) = &snap {
            self.zero_fail_count_in_file(p, unix_now_u32());
        }
        self.note_ulog(id, false, snap);
        self.save_if_configured()
    }

    /// A kvno change does not touch the password history.
    pub fn set_kvno_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        kvno: u32,
        actor: &str,
    ) -> Result<(), Error> {
        self.inside_change()?;
        if kvno > 65535 {
            return Err(Error::InvalidArgument("invalid kvno".into()));
        }
        let id = self.canonical_id(name, princ_realm)?;
        {
            let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
            for k in &mut p.keys {
                k.kvno = kvno;
            }
            stamp_admin_tl(p, false, actor);
        }
        let snap = self.map.get(&id).cloned();
        self.note_ulog(id, false, snap);
        self.save_if_configured()
    }

    pub fn merge_tl_data_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        tls: &[TlData],
        actor: &str,
    ) -> Result<(), Error> {
        let id = self.canonical_id(name, princ_realm)?;
        let mut p = self.map.get(&id).ok_or(Error::NotFound)?.clone();
        for tl in tls {
            if tl.ty != TL_DB_ARGS {
                p.tl_data.retain(|t| t.ty != tl.ty);
            }
            p.tl_data.push(tl.clone());
        }
        crate::kdb_dump::absorb_s4u_tl(&mut p);
        strip_db_args(&mut p.tl_data)?;
        stamp_admin_tl(&mut p, false, actor);
        self.inside_change()?;
        self.put_principal(p)?;
        self.save_if_configured()
    }

    pub fn delete(&mut self, acl: &Acl, actor: &str, name: &PrincipalName) -> Result<(), Error> {
        let realm = self.realm.clone();
        self.delete_in(acl, actor, name, &realm)
    }

    pub(crate) fn delete_in(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
        princ_realm: &str,
    ) -> Result<(), Error> {
        let id = crate::kdb::lookup_principal_id(name, princ_realm);
        acl.check(actor, AdminOp::Delete, Some(&id))?;
        self.remove_id_inner(&id)
    }

    pub fn remove_in(&mut self, name: &PrincipalName, princ_realm: &str) -> Result<(), Error> {
        self.remove_id_inner(&crate::kdb::lookup_principal_id(name, princ_realm))
    }

    /// A rename keeps the RID and does not reallocate it.
    pub fn rename(
        &mut self,
        acl: &Acl,
        actor: &str,
        old: &PrincipalName,
        new: &PrincipalName,
    ) -> Result<(), Error> {
        let realm = self.realm.clone();
        self.rename_in(acl, actor, old, &realm, new, &realm)
    }

    pub(crate) fn rename_in(
        &mut self,
        acl: &Acl,
        actor: &str,
        old: &PrincipalName,
        old_realm: &str,
        new: &PrincipalName,
        new_realm: &str,
    ) -> Result<(), Error> {
        let old_id = crate::kdb::lookup_principal_id(old, old_realm);
        let new_id = crate::kdb::lookup_principal_id(new, new_realm);
        acl.check_rename(actor, &old_id, &new_id)?;
        self.rename_unchecked(old, old_realm, new, new_realm, actor)
    }

    // MIT: `rename_principal_2_svc` (server_stubs.c:700-712)
    pub fn rename_unchecked(
        &mut self,
        old: &PrincipalName,
        old_realm: &str,
        new: &PrincipalName,
        new_realm: &str,
        actor: &str,
    ) -> Result<(), Error> {
        self.inside_change()?;
        let old_id = crate::kdb::lookup_principal_id(old, old_realm);
        let new_id = crate::kdb::lookup_principal_id(new, new_realm);
        if self.get(&new_id).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self
            .map
            .get(&old_id)
            .ok_or(Error::NotFound)?
            .alias_target()
            .is_some()
        {
            return Err(Error::AliasUnsupported);
        }
        super::kadm5_hook::hook_rename(
            self,
            super::kadm5_hook::HookStage::Precommit,
            old,
            old_realm,
            new,
            new_realm,
        )?;
        {
            let p = self.map.get_mut(&old_id).ok_or(Error::NotFound)?;
            crate::kdb_dump::specialize_salts(p)?;
        }
        let mut p = self.map.remove(&old_id).ok_or(Error::NotFound)?;
        p.name = new.clone();
        new_realm.clone_into(&mut p.realm);
        self.rename_lockout_in_file(&old_id, &p);
        // MIT: `krb5_db_def_rename_principal` (lib/kdb/kdb_default.c:537-545)
        self.note_ulog(p.id(), false, Some(p.clone()));
        self.note_ulog(old_id, true, None);
        // MIT: `kadm5_rename_principal` (lib/kadm5/srv/svr_principal.c:730-737)
        stamp_admin_tl(&mut p, false, actor);
        self.note_ulog(p.id(), false, Some(p.clone()));
        self.map.insert(p.id(), p);
        self.save_if_configured()?;
        self.postcommit(super::kadm5_hook::Post::Rename {
            old: old.clone(),
            old_realm: old_realm.to_owned(),
            new: new.clone(),
            new_realm: new_realm.to_owned(),
        });
        Ok(())
    }

    #[cfg(any(test, feature = "test-hooks"))]
    pub(super) fn insert_password(
        &mut self,
        name: &PrincipalName,
        password: &[u8],
    ) -> Result<(), Error> {
        let realm = self.realm.clone();
        self.insert_new_password(name, &realm, password, &[], &default_mod_actor(&realm))
    }

    pub fn apply_admin_fields(
        &mut self,
        name: &PrincipalName,
        fields: AdminFields,
    ) -> Result<(), Error> {
        let AdminFields {
            attributes,
            max_life,
            expiration,
            pw_expire,
            policy,
            clear_policy,
            max_renewable_life,
        } = fields;
        let realm = self.realm.clone();
        let actor = default_mod_actor(&realm);
        self.apply_admin_fields_in(
            name,
            &realm,
            AdminFields {
                attributes,
                max_life,
                expiration,
                pw_expire,
                policy,
                clear_policy,
                max_renewable_life,
            },
            &actor,
        )
    }

    pub fn apply_admin_fields_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        fields: AdminFields,
        actor: &str,
    ) -> Result<(), Error> {
        self.inside_change()?;
        let AdminFields {
            attributes,
            max_life,
            expiration,
            pw_expire,
            policy,
            clear_policy,
            max_renewable_life,
        } = fields;
        let id = self.canonical_id(name, princ_realm)?;
        let mut mask = 0u32;
        if attributes.is_some() {
            mask |= kadm5_mask::ATTRIBUTES;
        }
        if max_life.is_some() {
            mask |= kadm5_mask::MAX_LIFE;
        }
        if expiration.is_some() {
            mask |= kadm5_mask::PRINC_EXPIRE_TIME;
        }
        if pw_expire.is_some() {
            mask |= kadm5_mask::PW_EXPIRATION;
        }
        if clear_policy {
            mask |= kadm5_mask::POLICY_CLR;
        } else if policy.is_some() {
            mask |= kadm5_mask::POLICY;
        }
        if max_renewable_life.is_some() {
            mask |= kadm5_mask::MAX_RLIFE;
        }
        super::kadm5_hook::hook_modify(
            self,
            super::kadm5_hook::HookStage::Precommit,
            name,
            princ_realm,
            mask,
        )?;
        let apply_max = policy.is_some() && !clear_policy && pw_expire.is_none();
        {
            let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
            if let Some(a) = attributes {
                p.attributes = a;
                p.requires_preauth = a & KDB_REQUIRES_PRE_AUTH != 0;
                p.locked = a & KDB_DISALLOW_ALL_TIX != 0;
            }
            if let Some(m) = max_life {
                p.max_life = m;
            }
            if let Some(m) = max_renewable_life {
                p.max_renewable_life = m;
            }
            if let Some(e) = expiration {
                p.expiration = e;
            }
            if let Some(e) = pw_expire {
                p.pw_expire = e;
            }
            if clear_policy {
                p.pw_policy = None;
                p.pw_expire = 0;
                refresh_kadm_tl(p);
            } else if let Some(pol) = policy {
                p.pw_policy = Some(pol);
                refresh_kadm_tl(p);
            }
            stamp_admin_tl(p, false, actor);
        }
        if apply_max {
            self.apply_pw_max_life_in(name, princ_realm)?;
        }
        let snap = self.map.get(&id).cloned();
        self.note_ulog(id, false, snap);
        self.save_if_configured()?;
        self.postcommit(super::kadm5_hook::Post::Modify {
            princ: name.clone(),
            realm: princ_realm.to_owned(),
            mask,
        });
        Ok(())
    }

    pub fn impose_acl_restrictions(
        &mut self,
        name: &PrincipalName,
        rs: &Restrictions,
    ) -> Result<(), Error> {
        let realm = self.realm.clone();
        self.impose_acl_restrictions_in(name, &realm, rs)
    }

    pub(crate) fn impose_acl_restrictions_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        rs: &Restrictions,
    ) -> Result<(), Error> {
        self.inside_change()?;
        let id = self.canonical_id(name, princ_realm)?;
        self.apply_acl_restrictions(&id, rs)?;
        self.save_if_configured()
    }

    pub(crate) fn apply_acl_restrictions(
        &mut self,
        id: &str,
        rs: &Restrictions,
    ) -> Result<(), Error> {
        self.inside_change()?;
        let mut ent = AdminEnt::default();
        rs.impose(&mut ent, unix_now_u32());
        let p = self.map.get_mut(id).ok_or(Error::NotFound)?;
        if ent.mask & kadm5_mask::ATTRIBUTES != 0 {
            p.attributes = ent.attributes;
            p.requires_preauth = p.attributes & KDB_REQUIRES_PRE_AUTH != 0;
            p.locked = p.attributes & KDB_DISALLOW_ALL_TIX != 0;
        }
        if ent.mask & kadm5_mask::MAX_LIFE != 0 {
            p.max_life = u64::from(ent.max_life);
        }
        if ent.mask & kadm5_mask::MAX_RLIFE != 0 {
            p.max_renewable_life = u64::from(ent.max_renewable_life);
        }
        if ent.mask & kadm5_mask::PRINC_EXPIRE_TIME != 0 {
            p.expiration = ent.princ_expire_time;
        }
        if ent.mask & kadm5_mask::PW_EXPIRATION != 0 {
            p.pw_expire = ent.pw_expiration;
        }
        if ent.mask & kadm5_mask::POLICY_CLR != 0 {
            p.pw_policy = None;
            refresh_kadm_tl(p);
        } else if ent.mask & kadm5_mask::POLICY != 0 {
            p.pw_policy.clone_from(&ent.policy);
            refresh_kadm_tl(p);
        }
        let snap = p.clone();
        self.note_ulog(id.to_owned(), false, Some(snap));
        self.save_if_configured()
    }

    pub fn get_strings(&self, name: &PrincipalName) -> Result<Vec<(String, String)>, Error> {
        self.get_strings_in(name, &self.realm)
    }

    pub fn get_strings_in(
        &self,
        name: &PrincipalName,
        princ_realm: &str,
    ) -> Result<Vec<(String, String)>, Error> {
        let p = self
            .get_in_realm(name, princ_realm)
            .ok_or(Error::NotFound)?;
        Ok(p.string_attrs.clone())
    }

    pub fn set_string(
        &mut self,
        name: &PrincipalName,
        key: &str,
        value: Option<&str>,
    ) -> Result<(), Error> {
        let realm = self.realm.clone();
        let actor = default_mod_actor(&realm);
        self.set_string_in(name, &realm, key, value, &actor)
    }

    // MIT: `kadm5_set_string` (svr_principal.c:2022-2043)
    pub fn set_string_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        key: &str,
        value: Option<&str>,
        actor: &str,
    ) -> Result<(), Error> {
        self.inside_change()?;
        let id = self.canonical_id(name, princ_realm)?;
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        p.string_attrs.retain(|(k, _)| k != key);
        if let Some(v) = value {
            p.string_attrs.push((key.to_owned(), v.to_owned()));
        }
        // MIT: `krb5_dbe_set_string` (lib/kdb/kdb5.c:2236-2240)
        // The string-attribute record stays when the last string is deleted.
        super::update_tl_data(
            &mut p.tl_data,
            TlData {
                ty: TL_STRING_ATTRS,
                contents: super::encode_string_attrs(&p.string_attrs),
            },
        );
        stamp_admin_tl(p, false, actor);
        let snap = p.clone();
        self.note_ulog(id, false, Some(snap));
        self.save_if_configured()
    }

    // MIT: `klmdb_get_principal` (plugins/kdb/lmdb/kdb_lmdb.c:713-744)
    #[must_use]
    pub fn lockout_of(&self, p: &Principal) -> Lockout {
        self.lockout.lookup(self.db_path(), self.dblock.as_ref(), p)
    }

    #[must_use]
    pub(crate) fn lockout_kept(&self, p: &Principal) -> Lockout {
        self.lockout
            .overlay_get(&p.id())
            .unwrap_or_else(|| Lockout::of(p))
    }

    pub(crate) fn merge_lockout_records(
        &mut self,
        records: &std::collections::HashMap<String, Lockout>,
    ) {
        for p in self.map.values_mut() {
            if let Some(l) = records.get(&p.id()) {
                l.set_on(p);
            }
        }
    }

    #[must_use]
    pub fn fail_auth_of(&self, p: &Principal) -> u32 {
        self.lockout_of(p).fail_auth_count
    }

    #[must_use]
    pub fn last_failed_of(&self, p: &Principal) -> u32 {
        self.lockout_of(p).last_failed
    }

    #[must_use]
    pub fn last_success_of(&self, p: &Principal) -> u32 {
        self.lockout_of(p).last_success
    }

    pub fn merge_lockout(&self, p: &mut Principal) {
        self.lockout_of(p).set_on(p);
    }

    /// The lockout record is written in place under the database lock.
    // MIT: `klmdb_update_lockout` (plugins/kdb/lmdb/kdb_lmdb.c:1054-1121)
    pub fn update_lockout(&self, p: &Principal, stamp: u32, update: LockoutUpdate) {
        self.lockout
            .update(self.db_path(), self.dblock.as_ref(), p, stamp, update);
    }

    pub(crate) fn zero_fail_count_in_file(&self, p: &Principal, stamp: u32) {
        self.update_lockout(
            p,
            stamp,
            LockoutUpdate {
                zero_fail_count: true,
                ..Default::default()
            },
        );
    }

    pub(crate) fn rename_lockout_in_file(&self, old_id: &str, new: &Principal) {
        self.lockout
            .rename_row(self.db_path(), self.dblock.as_ref(), old_id, new);
    }

    #[cfg(feature = "test-hooks")]
    fn lockout_id(&self, name: &PrincipalName) -> String {
        let id = crate::kdb::lookup_principal_id(name, &self.realm);
        self.resolve_id(&id).unwrap_or(id)
    }

    #[cfg(feature = "test-hooks")]
    pub fn record_as_outcome(&self, name: &PrincipalName, ok: bool) {
        let Some(mut p) = self.map.get(&self.lockout_id(name)).cloned() else {
            return;
        };
        self.merge_lockout(&mut p);
        let status = if ok {
            0
        } else {
            krb5_types::err::PREAUTH_FAILED
        };
        crate::lockout::lockout_audit(self, &p, unix_now_u32(), status);
    }

    pub(crate) fn put_principal(&mut self, mut p: Principal) -> Result<(), Error> {
        strip_db_args(&mut p.tl_data)?;
        p.reconcile_flags();
        self.settle_rid(&mut p);
        if p.name.components_joined() != "K/M"
            && self.rid_owner(p.rid).is_some_and(|owner| owner != p.id())
        {
            return Err(Error::InvalidArgument("duplicate RID".into()));
        }
        let id = p.id();
        self.note_ulog(id.clone(), false, Some(p.clone()));
        self.map.insert(id, p);
        Ok(())
    }
}
