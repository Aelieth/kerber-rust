//! Realm principal records (`kdb5.c` `krb5_db_entry`) and the kadm5
//! create / modify / rename / delete / unlock path (`svr_principal.c`,
//! `server_stubs.c`), including `KRB5_TL_*` stamps and the AS-fail
//! overlay (`lockout.c`).

use krb5_crypto::EncryptionType;
use krb5_types::PrincipalName;

use super::flags::{
    KDB_DISALLOW_ALL_TIX, KDB_PWCHANGE_SERVICE, KDB_REQUIRES_PRE_AUTH, KDB_V1_BASE_LENGTH,
};
use super::keys::{KeyEntry, KeyLookup, random_key};
use super::password::{apply_keysalt_policy, keys_from_password};
use super::{PrincipalStore, kadm5_mask, unix_now, unix_now_u32};
use crate::acl::{Acl, AdminOp, Restrictions};
use crate::error::Error;
use crate::kdb_dump::{
    TL_ALIAS_TARGET, TL_DB_ARGS, TL_KADM_DATA, TL_KERBER_HIST, TL_KERBER_POLICY,
    TL_LAST_ADMIN_UNLOCK, TL_LAST_PWD_CHANGE, TL_MOD_PRINC,
};
use crate::osa::{INITIAL_HIST_KVNO, KADM5_POLICY, OsaKeyData, OsaPrincEnt};

fn qualify_s4u_from(from: &str, local_realm: &str) -> String {
    if from.contains('@') {
        from.to_owned()
    } else {
        format!("{from}@{local_realm}")
    }
}

/// MIT dump `tl_data` triplet (type, length implied by contents).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlData {
    /// `tl_data_type` (`KRB5_TL_*`).
    pub ty: i32,
    /// Raw contents (length is `contents.len()`).
    pub contents: Vec<u8>,
}

/// `extract_db_args_from_tl_data` + DB2 reject (`kdb5.c:893-945`, `kdb_db2.c:817-822`).
#[must_use]
pub fn db_args_put_error(tl: &[TlData]) -> Option<Error> {
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

/// Remove every `KRB5_TL_DB_ARGS` after [`db_args_put_error`].
///
/// # Errors
///
/// [`Error::InvalidArgument`] when any `0x7fff` is present or not NUL-terminated.
pub fn strip_db_args(tl: &mut Vec<TlData>) -> Result<(), Error> {
    if let Some(e) = db_args_put_error(tl) {
        return Err(e);
    }
    tl.retain(|t| t.ty != TL_DB_ARGS);
    Ok(())
}

/// The kadm5 admin record MIT keeps in `KRB5_TL_KADM_DATA` (`osa_princ_ent_rec`)
/// beside the bound policy: `aux_attributes`, the history ring position, the
/// history key's kvno, and the old passwords' keys as stored (encrypted under
/// that history key; [`Principal::key_history`] is their decrypted view).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KadmData {
    /// `aux_attributes` (`KADM5_POLICY` follows [`Principal::pw_policy`]).
    pub aux_attributes: u32,
    /// `old_key_next`.
    pub old_key_next: u32,
    /// `admin_history_kvno`.
    pub admin_history_kvno: u32,
    /// `old_keys`, one entry per old password, as MIT stores them.
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
    /// The record's fields from a decoded `KRB5_TL_KADM_DATA`.
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

/// One realm principal.
#[derive(Clone, Debug)]
pub struct Principal {
    /// Name (no realm).
    pub name: PrincipalName,
    /// Realm.
    pub realm: String,
    /// Active key_data (current kvno, plus `keepold` kvnos).
    pub keys: Vec<KeyEntry>,
    /// OSA password-history keys (dump `TL_KERBER_HIST`; not getprinc/EXTRACT).
    pub key_history: Vec<KeyEntry>,
    /// Salt used for password-derived keys.
    pub salt: Vec<u8>,
    /// Whether AS requires PA-ENC-TIMESTAMP.
    pub requires_preauth: bool,
    /// Max ticket life in seconds (0 = use realm policy).
    pub max_life: u64,
    /// Locked out.
    pub locked: bool,
    /// Password expiry unix seconds (0 = none).
    pub pw_expire: u32,
    /// MIT KDB attributes bitfield (passthrough for dump/load).
    pub attributes: u32,
    /// Max renewable life in seconds (0 is a cap of 0).
    pub max_renewable_life: u64,
    /// Principal expiration unix seconds (0 = never).
    pub expiration: u32,
    /// Last successful authentication unix seconds.
    pub last_success: u32,
    /// Last failed authentication unix seconds.
    pub last_failed: u32,
    /// Failed password attempts.
    pub fail_auth_count: u32,
    /// Master-key kvno that encrypts `key_data`.
    pub mkvno: u16,
    /// Dump `len` field (`KRB5_KDB_V1_BASE_LENGTH` = 38).
    pub db_entry_len: u32,
    /// Opaque MIT `tl_data` for lossless dump round-trip.
    pub tl_data: Vec<TlData>,
    /// Opaque MIT extra data (`e_data`).
    pub e_data: Vec<u8>,
    /// Relative ID in the realm domain SID (0 = unassigned).
    pub rid: u32,
    /// Impersonators allowed to S4U2Proxy here (RBCD), `name@REALM`.
    pub s4u_allowed_from: Vec<String>,
    /// Target names this principal may S4U2Proxy to (classic constrained
    /// delegation / `msDS-AllowedToDelegateTo`).
    pub s4u_allowed_to: Vec<String>,
    /// Bound named password policy (`policy\t` / kadm5).
    pub pw_policy: Option<String>,
    /// MIT's `KRB5_TL_KADM_DATA` record (policy bit, history ring and keys).
    pub kadm: KadmData,
    /// MIT string attributes (`setstr` / `KRB5_TL_STRING_ATTRS`).
    pub string_attrs: Vec<(String, String)>,
}

impl Principal {
    /// Construct a principal with dump metadata zeroed (bootstrap / KDB3 load).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_keys(
        name: PrincipalName,
        realm: String,
        keys: Vec<KeyEntry>,
        salt: Vec<u8>,
        requires_preauth: bool,
        max_life: u64,
        locked: bool,
        pw_expire: u32,
    ) -> Self {
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

/// Process-local AS fail overlay (count + timestamps). Dump rows stay stale.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AsFailState {
    pub count: u32,
    pub last_failed: u32,
    pub last_success: u32,
}

/// The `kadm5_principal_ent_rec` fields `kadm5_create_principal_3`
/// (`svr_principal.c:376-420`) and `impose_restrictions` (`auth.c:205-272`)
/// read, with the request `mask`. A field is applied only when its
/// [`kadm5_mask`] bit is set; otherwise the realm default
/// (`handle->params.*`) is used. Values are as the client sent them (MIT
/// `kadmin` zero-fills the record), which matters for restrictions that
/// set a bit on a value the client never meant.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdminEnt {
    /// `KADM5_*` bits.
    pub mask: u32,
    /// `attributes` (`KADM5_ATTRIBUTES`).
    pub attributes: u32,
    /// `max_life` seconds (`KADM5_MAX_LIFE`).
    pub max_life: u32,
    /// `max_renewable_life` seconds (`KADM5_MAX_RLIFE`).
    pub max_renewable_life: u32,
    /// `princ_expire_time` (`KADM5_PRINC_EXPIRE_TIME`).
    pub princ_expire_time: u32,
    /// `pw_expiration` (`KADM5_PW_EXPIRATION`).
    pub pw_expiration: u32,
    /// `kvno` (`KADM5_KVNO`).
    pub kvno: u32,
    /// `policy` (`KADM5_POLICY`; `KADM5_POLICY_CLR` clears).
    pub policy: Option<String>,
}

impl Principal {
    /// `name@REALM` lookup key (`krb5_unparse_name`).
    #[must_use]
    pub fn id(&self) -> String {
        crate::kdb::lookup_principal_id(&self.name, &self.realm)
    }

    /// Target of an alias stub (`krb5_dbe_read_alias`): the NUL-terminated
    /// unparsed name in `KRB5_TL_ALIAS_TARGET`. An unterminated value is
    /// MIT `KRB5_KDB_TRUNCATED_RECORD` and resolves to nothing.
    #[must_use]
    pub fn alias_target(&self) -> Option<String> {
        let tl = self.tl_data.iter().find(|t| t.ty == TL_ALIAS_TARGET)?;
        let (nul, target) = tl.contents.split_last()?;
        if *nul != 0 {
            return None;
        }
        String::from_utf8(target.to_vec()).ok()
    }

    /// First key of `etype`, if present (highest kvno preferred).
    #[must_use]
    pub fn key_for(&self, etype: EncryptionType) -> Option<&KeyEntry> {
        self.keys
            .iter()
            .filter(|k| k.etype == etype)
            .max_by_key(|k| k.kvno)
    }

    /// The first stored key of the highest kvno, *unfiltered*: MIT
    /// `current_kvno(tgt)` / `tgt->key_data[0]`. KDC key selection goes
    /// through [`crate::Policy::first_current_key`], which skips
    /// non-permitted enctypes the way `krb5_dbe_find_enctype` does.
    #[must_use]
    pub fn first_current_key(&self) -> Option<&KeyEntry> {
        let kvno = self.keys.iter().map(|k| k.kvno).max()?;
        self.first_key_at_kvno(kvno)
    }

    /// The first stored key of `kvno`, unfiltered (see [`Principal::find_enctype`]
    /// for the permitted-enctype form the KDC uses).
    #[must_use]
    pub fn first_key_at_kvno(&self, kvno: u32) -> Option<&KeyEntry> {
        self.keys.iter().find(|k| k.kvno == kvno)
    }

    /// MIT `krb5_dbe_def_search_enctype` from index 0 (`kdb_default.c:47-94`)
    /// with salttype -1, i.e. `krb5_dbe_find_enctype(ent, etype, -1, kvno)`:
    /// `etype` `None` is -1 (any); `kvno` 0 is the highest kvno and no other;
    /// an `etype` that is not permitted is `NoPermittedKey` before the list is
    /// read (`:60-61`); keys of a non-permitted enctype are skipped (`:82-86`)
    /// and, when they were the only matches, the answer is `NoPermittedKey`
    /// rather than `NoMatchingKey` (`:92-94`). Stored order decides between
    /// several permitted keys of the same kvno, as MIT's `key_data` order does.
    ///
    /// # Errors
    ///
    /// [`KeyLookup::NoMatchingKey`] when no key matches `etype`/`kvno` at all;
    /// [`KeyLookup::NoPermittedKey`] when `etype` itself, or every matching
    /// key, is outside `permitted`.
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

    /// Preferred stored key (highest etype in [`EncryptionType::preferred`]).
    #[must_use]
    pub fn best_key(&self) -> Option<&KeyEntry> {
        EncryptionType::preferred()
            .into_iter()
            .find_map(|e| self.key_for(e))
            .or_else(|| self.keys.first())
    }
}

/// Re-encode the principal's `KRB5_TL_KADM_DATA` from its policy binding and
/// history record (MIT `kdb_put_entry`), retiring the private policy/history
/// `tl_data` older Rust dumps carried.
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

/// MIT `kdb5_util create` (`kdb5_create.c:114-133`): principals written
/// without a kadm5 handle are stamped `db_creation@REALM`. Live kadm5
/// paths pass `current_caller`.
pub(super) fn default_mod_actor(realm: &str) -> String {
    format!("db_creation@{realm}")
}

/// `krb5_parse_name` of `client_name` then `krb5_unparse_name` (`server_init.c:239-241`).
fn canonical_mod_actor(actor: &str, realm: &str) -> String {
    if actor.contains('@') {
        actor.to_owned()
    } else {
        format!("{actor}@{realm}")
    }
}

pub(super) fn stamp_admin_tl(p: &mut Principal, pwd_change: bool, actor: &str) {
    let now = unix_now_u32();
    p.tl_data
        .retain(|t| t.ty != TL_MOD_PRINC && !(pwd_change && t.ty == TL_LAST_PWD_CHANGE));
    let mut modp = now.to_le_bytes().to_vec();
    modp.extend_from_slice(canonical_mod_actor(actor, &p.realm).as_bytes());
    modp.push(0);
    p.tl_data.push(TlData {
        ty: TL_MOD_PRINC,
        contents: modp,
    });
    if pwd_change {
        p.tl_data.push(TlData {
            ty: TL_LAST_PWD_CHANGE,
            contents: now.to_le_bytes().to_vec(),
        });
    }
}

impl PrincipalStore {
    pub(crate) fn remove_id_inner(&mut self, id: &str) -> Result<(), Error> {
        self.map.remove(id).ok_or(Error::NotFound)?;
        self.note_ulog(id.to_owned(), true, None);
        self.save_if_configured()
    }

    /// Permit `from` to S4U2Proxy to `name` (RBCD). A bare name is the local realm.
    pub fn allow_s4u_from(&mut self, name: &PrincipalName, from: &str) {
        let id = crate::kdb::lookup_principal_id(name, &self.realm);
        let qualified = qualify_s4u_from(from, &self.realm);
        if let Some(p) = self.map.get_mut(&id) {
            p.s4u_allowed_from.push(qualified);
        }
    }

    /// Permit `name` to S4U2Proxy to `to` (classic constrained delegation).
    pub fn allow_s4u_to(&mut self, name: &PrincipalName, to: &str) {
        let id = crate::kdb::lookup_principal_id(name, &self.realm);
        if let Some(p) = self.map.get_mut(&id) {
            p.s4u_allowed_to.push(to.to_owned());
        }
    }

    /// Drop classic S4U2Proxy targets (MIT db2 has none).
    pub fn clear_s4u_to(&mut self, name: &PrincipalName) {
        let id = crate::kdb::lookup_principal_id(name, &self.realm);
        if let Some(p) = self.map.get_mut(&id) {
            p.s4u_allowed_to.clear();
        }
    }

    /// ACL-gated create of a password principal.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::AlreadyExists`].
    pub fn create_password(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
        password: &[u8],
    ) -> Result<(), Error> {
        self.create_password_etypes(acl, actor, name, password, &[])
    }

    /// ACL-gated create with an explicit keysalt list (`addprinc -e`).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::AlreadyExists`].
    pub fn create_password_etypes(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
        password: &[u8],
        etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        let realm = self.realm.clone();
        self.create_password_etypes_in(acl, actor, name, &realm, password, etypes)
    }

    /// [`Self::create_password_etypes`] storing `name@princ_realm`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::AlreadyExists`].
    pub fn create_password_etypes_in(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
        princ_realm: &str,
        password: &[u8],
        etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        let id = crate::kdb::lookup_principal_id(name, princ_realm);
        acl.check(actor, AdminOp::Create, Some(&id))?;
        self.insert_new_password(name, princ_realm, password, etypes, actor)?;
        if let Some(rs) = acl.restrictions(actor, Some(&id)) {
            self.apply_acl_restrictions(&id, rs)?;
        }
        Ok(())
    }

    /// Insert without ACL (`kadm5_create_principal_3` after stub_auth) with
    /// no entry fields in the mask: every field is the realm default.
    ///
    /// # Errors
    ///
    /// [`Error::AlreadyExists`].
    pub fn insert_new_password(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        password: &[u8],
        etypes: &[EncryptionType],
        actor: &str,
    ) -> Result<(), Error> {
        self.create_principal_3_in(
            name,
            princ_realm,
            Some(password),
            etypes,
            &AdminEnt::default(),
            actor,
        )
    }

    /// kadm5 `create_principal` with a NULL password
    /// (`svr_principal.c:463-470` `krb5_dbe_crk`): random keys of `etypes`
    /// (empty = `supported_enctypes`) at kvno 1, no `passwd_check`. This is
    /// `kadmin addprinc -randkey` since 1.8; the pre-1.8 client sends a
    /// dummy password and `DISALLOW_ALL_TIX` instead.
    ///
    /// # Errors
    ///
    /// [`Error::AlreadyExists`] or [`Error::Rng`].
    pub fn insert_new_randkey(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        etypes: &[EncryptionType],
        actor: &str,
    ) -> Result<(), Error> {
        self.create_principal_3_in(name, princ_realm, None, etypes, &AdminEnt::default(), actor)
    }

    /// MIT `handle->params.flags` for a create without `KADM5_ATTRIBUTES`:
    /// `[realms] default_principal_flags` (`alt_prof.c:596-632`) when set,
    /// parsed over 0 like MIT. Without the stanza MIT's `KRB5_KDB_DEF_FLAGS`
    /// is 0; the Rust `requires_preauth` knob (predates the stanza, default
    /// on) adds `REQUIRES_PRE_AUTH` to *password-keyed* creates only — its
    /// scope since before W1-Z — so random-key (service) creates are MIT's 0
    /// and U2U to a fresh `-randkey` service keeps working
    /// (`docs/security.md`). A written stanza overrides the knob for both.
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

    /// MIT `kadm5_create_principal_3` (`svr_principal.c:290-511`) after the
    /// stub's ACL / `impose_restrictions` step and mask validation: the
    /// entry must not exist (`KADM5_DUP`); the named policy is loaded when it
    /// exists (`get_policy`: an unknown name is *no* policy, not an error);
    /// `passwd_check` runs on a non-NULL password with that policy before
    /// anything is written; then every field is the request value when its
    /// mask bit is set, else the realm default — `attributes` ←
    /// `params.flags`, `max_life` ← `params.max_life`, `max_renewable_life`
    /// ← `params.max_rlife`, `expiration` ← `params.expiration`
    /// (`default_principal_expiration`, 0),
    /// `pw_expiration` ← `now + pw_max_life` under a policy with one, else 0;
    /// a password is keyed at `kvno` (default 1) and a NULL password is
    /// `krb5_dbe_crk` with the kvno rewritten; `KADM5_POLICY` binds the name
    /// (`adb.policy`) even when the policy does not exist. Key/salt tuples
    /// are `apply_keysalt_policy` (`svr_principal.c:444-447`): the request's
    /// `-e` list, else the bound policy's `allowed_keysalts`, else
    /// `supported_enctypes`. TL-data stays with the callers.
    ///
    /// # Errors
    ///
    /// [`Error::AlreadyExists`], [`Error::PasswordPolicy`], [`Error::Rng`].
    pub fn create_principal_3_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        password: Option<&[u8]>,
        etypes: &[EncryptionType],
        ent: &AdminEnt,
        actor: &str,
    ) -> Result<(), Error> {
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
            self.check_new_password(name, policy_name.as_deref(), pw)?;
        }
        let now = unix_now();
        let use_etypes = apply_keysalt_policy(
            polent.as_ref().and_then(|p| p.allowed_keysalts.as_deref()),
            etypes,
            &self.policy.password_etypes(),
        )?;
        let salt = name.default_salt(princ_realm);
        let kvno = if ent.mask & kadm5_mask::KVNO != 0 {
            ent.kvno
        } else {
            1
        };
        let keys = if let Some(pw) = password {
            keys_from_password(&use_etypes, pw, &salt, kvno)?
        } else {
            let mut keys = Vec::new();
            for etype in &use_etypes {
                keys.push(KeyEntry::new(*etype, random_key(*etype)?, kvno));
            }
            keys
        };
        let attributes = if ent.mask & kadm5_mask::ATTRIBUTES != 0 {
            ent.attributes
        } else {
            self.default_create_attributes(password.is_some())
        };
        let mut p = Principal::from_keys(
            name.clone(),
            princ_realm.to_owned(),
            keys,
            salt,
            attributes & KDB_REQUIRES_PRE_AUTH != 0,
            0,
            attributes & KDB_DISALLOW_ALL_TIX != 0,
            0,
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
        self.put_principal(p);
        self.save_if_configured()
    }

    /// ACL-gated create of a random-key host (or other) principal.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::AlreadyExists`].
    pub fn create_host(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
    ) -> Result<(), Error> {
        self.create_host_etypes(acl, actor, name, &[])
    }

    /// `addprinc -randkey -e`. Does not seed `allowed_to_delegate`
    /// (MIT `addprinc -randkey` has no targets).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::AlreadyExists`].
    pub fn create_host_etypes(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
        etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        let id = crate::kdb::lookup_principal_id(name, &self.realm);
        acl.check(actor, AdminOp::Create, Some(&id))?;
        if self.get(&id).is_some() {
            return Err(Error::AlreadyExists);
        }
        let realm = self.realm.clone();
        self.create_principal_3_in(name, &realm, None, etypes, &AdminEnt::default(), actor)?;
        let self_name = name.components_joined();
        if self_name == "kadmin/changepw"
            && let Some(p) = self.map.get_mut(&id)
        {
            p.attributes |= KDB_PWCHANGE_SERVICE;
        }
        if let Some(rs) = acl.restrictions(actor, Some(&id)) {
            self.apply_acl_restrictions(&id, rs)?;
        }
        if let Some(p) = self.map.get(&id) {
            self.note_ulog(id.clone(), false, Some(p.clone()));
        }
        self.save_if_configured()?;
        Ok(())
    }

    /// ACL-gated create with an optional bound policy so
    /// `apply_keysalt_policy` sees `allowed_keysalts` (`svr_principal.c:444-447`).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`], [`Error::AlreadyExists`], or [`Error::BadKeysalts`].
    pub fn create_etypes_pol(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
        password: Option<&[u8]>,
        etypes: &[EncryptionType],
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
        self.create_principal_3_in(name, &realm, password, etypes, &ent, actor)?;
        if password.is_none() {
            let self_name = name.components_joined();
            if self_name == "kadmin/changepw"
                && let Some(p) = self.map.get_mut(&id)
            {
                p.attributes |= KDB_PWCHANGE_SERVICE;
            }
        }
        if let Some(rs) = acl.restrictions(actor, Some(&id)) {
            self.apply_acl_restrictions(&id, rs)?;
        }
        Ok(())
    }

    /// Set lockout and password-expiry, then persist when `persist_paths` is set.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when the principal is missing, or persist I/O.
    pub fn set_status(
        &mut self,
        name: &PrincipalName,
        locked: bool,
        pw_expire: u32,
    ) -> Result<(), Error> {
        let id = self.canonical_id(name, &self.realm)?;
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        p.locked = locked;
        p.pw_expire = pw_expire;
        if locked {
            p.attributes |= KDB_DISALLOW_ALL_TIX;
        } else {
            p.attributes &= !KDB_DISALLOW_ALL_TIX;
        }
        let snap = p.clone();
        self.note_ulog(id, false, Some(snap));
        self.save_if_configured()
    }

    /// MIT `unlock_princ`: fail_auth_count = 0 and `KRB5_TL_LAST_ADMIN_UNLOCK`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn admin_unlock(&mut self, name: &PrincipalName) -> Result<(), Error> {
        let realm = self.realm.clone();
        let actor = default_mod_actor(&realm);
        self.admin_unlock_in(name, &realm, &actor)
    }

    /// [`Self::admin_unlock`] for `name@princ_realm`.
    ///
    /// `kdb_put_entry` stamps `KRB5_TL_MOD_PRINC` with `actor`
    /// (`svr_principal.c:685` through `server_kdb.c:376-377`).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn admin_unlock_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        actor: &str,
    ) -> Result<(), Error> {
        let id = self.canonical_id(name, princ_realm)?;
        let now = unix_now();
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
        self.clear_as_fail_count(name);
        let snap = self.map.get(&id).cloned();
        self.note_ulog(id, false, snap);
        self.save_if_configured()
    }

    /// Zero `fail_auth_count` without rewriting TL data (`kadm5_modify_principal`).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn clear_fail_auth_count_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
    ) -> Result<(), Error> {
        let id = self.canonical_id(name, princ_realm)?;
        {
            let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
            p.fail_auth_count = 0;
        }
        self.clear_as_fail_count(name);
        let snap = self.map.get(&id).cloned();
        self.note_ulog(id, false, snap);
        self.save_if_configured()
    }

    /// Merge client-supplied `tl_data` (`kadm5_modify_principal` `KADM5_TL_DATA`).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn merge_tl_data_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        tls: &[TlData],
    ) -> Result<(), Error> {
        let id = self.canonical_id(name, princ_realm)?;
        let mut p = self.map.get(&id).ok_or(Error::NotFound)?.clone();
        for tl in tls {
            if tl.ty != TL_DB_ARGS {
                p.tl_data.retain(|t| t.ty != tl.ty);
            }
            p.tl_data.push(tl.clone());
        }
        strip_db_args(&mut p.tl_data)?;
        self.put_principal(p);
        self.save_if_configured()
    }

    /// ACL-gated delete.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn delete(&mut self, acl: &Acl, actor: &str, name: &PrincipalName) -> Result<(), Error> {
        let realm = self.realm.clone();
        self.delete_in(acl, actor, name, &realm)
    }

    /// [`Self::delete`] of `name@princ_realm`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn delete_in(
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

    /// Drop `name@princ_realm` with no ACL (stub already authorised).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn remove_in(&mut self, name: &PrincipalName, princ_realm: &str) -> Result<(), Error> {
        self.remove_id_inner(&crate::kdb::lookup_principal_id(name, princ_realm))
    }

    /// Rename a principal. Requires add and delete ACL privs (MIT).
    ///
    /// RID, keys, and attributes are kept. A non-zero RID is not
    /// re-allocated. Default-salt password keys stay verbatim (MIT);
    /// `kinit` after rename may need an explicit salt or `cpw`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`], [`Error::NotFound`], or [`Error::AlreadyExists`].
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

    /// [`Self::rename`] with request realms.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`], [`Error::NotFound`], or [`Error::AlreadyExists`].
    pub fn rename_in(
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

    /// Rename after stub ACL (`server_stubs.c:700-712`).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] or [`Error::AlreadyExists`].
    pub fn rename_unchecked(
        &mut self,
        old: &PrincipalName,
        old_realm: &str,
        new: &PrincipalName,
        new_realm: &str,
        actor: &str,
    ) -> Result<(), Error> {
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
        let mut p = self.map.remove(&old_id).ok_or(Error::NotFound)?;
        p.name = new.clone();
        new_realm.clone_into(&mut p.realm);
        stamp_admin_tl(&mut p, false, actor);
        self.note_ulog(old_id, true, None);
        self.note_ulog(p.id(), false, Some(p.clone()));
        self.map.insert(p.id(), p);
        self.save_if_configured()
    }

    pub(super) fn insert_password(
        &mut self,
        name: &PrincipalName,
        password: &[u8],
    ) -> Result<(), Error> {
        let realm = self.realm.clone();
        self.insert_new_password(name, &realm, password, &[], &default_mod_actor(&realm))
    }

    /// Apply kadm5 `modprinc` fields (mask already interpreted by the caller).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    #[allow(clippy::too_many_arguments)]
    pub fn apply_admin_fields(
        &mut self,
        name: &PrincipalName,
        attributes: Option<u32>,
        max_life: Option<u64>,
        expiration: Option<u32>,
        pw_expire: Option<u32>,
        policy: Option<String>,
        clear_policy: bool,
        max_renewable_life: Option<u64>,
    ) -> Result<(), Error> {
        let realm = self.realm.clone();
        let actor = default_mod_actor(&realm);
        self.apply_admin_fields_in(
            name,
            &realm,
            attributes,
            max_life,
            expiration,
            pw_expire,
            policy,
            clear_policy,
            max_renewable_life,
            &actor,
        )
    }

    /// [`Self::apply_admin_fields`] for `name@princ_realm`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    #[allow(clippy::too_many_arguments)]
    pub fn apply_admin_fields_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        attributes: Option<u32>,
        max_life: Option<u64>,
        expiration: Option<u32>,
        pw_expire: Option<u32>,
        policy: Option<String>,
        clear_policy: bool,
        max_renewable_life: Option<u64>,
        actor: &str,
    ) -> Result<(), Error> {
        let id = self.canonical_id(name, princ_realm)?;
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
        self.save_if_configured()
    }

    /// Impose kadm5.acl restrictions after create/modify (`auth.c` `impose_restrictions`).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn impose_acl_restrictions(
        &mut self,
        name: &PrincipalName,
        rs: &Restrictions,
    ) -> Result<(), Error> {
        let realm = self.realm.clone();
        self.impose_acl_restrictions_in(name, &realm, rs)
    }

    /// [`Self::impose_acl_restrictions`] for `name@princ_realm`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn impose_acl_restrictions_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        rs: &Restrictions,
    ) -> Result<(), Error> {
        let id = self.canonical_id(name, princ_realm)?;
        self.apply_acl_restrictions(&id, rs)?;
        self.save_if_configured()
    }

    /// `impose_restrictions` on a request that carries none of the
    /// restricted fields (the local CLI verbs; MIT `kadmin.local` has no
    /// ACL, so this is the RPC shape with an empty mask): every restriction
    /// lands as its cap. The RPC paths call [`Restrictions::impose`] on the
    /// parsed request instead.
    fn apply_acl_restrictions(&mut self, id: &str, rs: &Restrictions) -> Result<(), Error> {
        let mut ent = AdminEnt::default();
        rs.impose(&mut ent, unix_now());
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
        Ok(())
    }

    /// MIT `kadm5_get_strings`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn get_strings(&self, name: &PrincipalName) -> Result<Vec<(String, String)>, Error> {
        self.get_strings_in(name, &self.realm)
    }

    /// [`Self::get_strings`] for `name@princ_realm`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
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

    /// MIT `kadm5_set_string`. `value == None` deletes `key`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
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

    /// [`Self::set_string`] for `name@princ_realm`.
    ///
    /// MIT `kadm5_set_string` → `kdb_put_entry` stamps `current_caller`
    /// (`svr_principal.c:2022-2043`).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn set_string_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        key: &str,
        value: Option<&str>,
        actor: &str,
    ) -> Result<(), Error> {
        let id = self.canonical_id(name, princ_realm)?;
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        p.string_attrs.retain(|(k, _)| k != key);
        if let Some(v) = value {
            p.string_attrs.push((key.to_owned(), v.to_owned()));
        }
        stamp_admin_tl(p, false, actor);
        let snap = p.clone();
        self.note_ulog(id, false, Some(snap));
        self.save_if_configured()
    }

    /// Overlay AS-fail count for lockout (absolute; success stores 0).
    #[must_use]
    pub fn fail_auth_of(&self, p: &Principal) -> u32 {
        self.as_fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&p.id())
            .map_or(p.fail_auth_count, |s| s.count)
    }

    /// Overlay last-failed unix seconds (dump field if the overlay is empty).
    #[must_use]
    pub fn last_failed_of(&self, p: &Principal) -> u32 {
        self.as_fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&p.id())
            .map_or(p.last_failed, |s| s.last_failed)
    }

    /// Overlay last-success unix seconds.
    #[must_use]
    pub fn last_success_of(&self, p: &Principal) -> u32 {
        self.as_fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&p.id())
            .map_or(p.last_success, |s| s.last_success)
    }

    /// Zero the overlay fail count without stamping last_success (interval reset).
    pub fn clear_as_fail_count(&self, name: &PrincipalName) {
        let id = self.lockout_id(name);
        let fallback = self
            .map
            .get(&id)
            .map_or(AsFailState::default(), |p| AsFailState {
                count: 0,
                last_failed: p.last_failed,
                last_success: p.last_success,
            });
        let mut g = self
            .as_fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match g.get_mut(&id) {
            Some(s) => s.count = 0,
            None => {
                g.insert(id, fallback);
            }
        }
    }

    fn lockout_id(&self, name: &PrincipalName) -> String {
        let id = crate::kdb::lookup_principal_id(name, &self.realm);
        self.resolve_id(&id).unwrap_or(id)
    }

    /// Record AS password outcome (interior-mutable; dump writes the overlay).
    pub fn record_as_outcome(&self, name: &PrincipalName, ok: bool) {
        let id = self.lockout_id(name);
        let fallback = self
            .map
            .get(&id)
            .map_or(AsFailState::default(), |p| AsFailState {
                count: p.fail_auth_count,
                last_failed: p.last_failed,
                last_success: p.last_success,
            });
        let now = unix_now_u32();
        let mut g = self
            .as_fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cur = g.get(&id).copied().unwrap_or(fallback);
        if ok {
            let requires_preauth = self
                .map
                .get(&id)
                .is_some_and(|p| p.attributes & KDB_REQUIRES_PRE_AUTH != 0);
            g.insert(
                id,
                AsFailState {
                    count: if requires_preauth { 0 } else { cur.count },
                    last_failed: cur.last_failed,
                    last_success: if requires_preauth {
                        now
                    } else {
                        cur.last_success
                    },
                },
            );
        } else {
            g.insert(
                id,
                AsFailState {
                    count: cur.count.saturating_add(1),
                    last_failed: now,
                    last_success: cur.last_success,
                },
            );
        }
    }

    pub(super) fn put_principal(&mut self, mut p: Principal) {
        if strip_db_args(&mut p.tl_data).is_err() {
            return;
        }
        self.settle_rid(&mut p);
        let id = p.id();
        self.note_ulog(id.clone(), false, Some(p.clone()));
        self.map.insert(id, p);
    }
}
