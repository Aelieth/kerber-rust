//! Password checks and a password change.

use krb5_crypto::{EncryptionType, KeySalt, ProtocolKey, parse_keysalts, string_to_key};
use krb5_log::klog::{self, Severity};
use krb5_types::PrincipalName;
use subtle::ConstantTimeEq;

use super::flags::KDB_REQUIRES_PWCHANGE;
use super::history::record_history;
use super::keys::{KeyEntry, cap_key_versions, next_kvno};
use super::policy::NamedPolicy;
use super::principal::{Principal, TlData, default_mod_actor, refresh_kadm_tl, stamp_admin_tl};
use super::{PrincipalStore, unix_now_u32};
use crate::acl::{Acl, AdminOp};
use crate::error::Error;
use crate::kdb_dump::TL_LAST_PWD_CHANGE;

pub const S2K_ITERS: u32 = 4096;

// MIT: `empty_check` (pwqual_empty.c:40-44)
pub const PWQUAL_EMPTY: &str = "Empty passwords are not allowed";

// MIT: `princ_check` (pwqual_princ.c:50-51)
pub const PWQUAL_PRINC: &str = "Password may not match principal name";

// MIT: `princ_check` (pwqual_princ.c:45-47)
pub const PWQUAL_DICT: &str = "Password is in the password dictionary";

fn last_pwd_unix(p: &Principal) -> u32 {
    p.tl_data
        .iter()
        .find(|t| t.ty == TL_LAST_PWD_CHANGE)
        .and_then(|t| t.contents.get(..4))
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

/// Checks and keys see the bytes before the first NUL.
pub(super) fn c_password(password: &[u8]) -> &[u8] {
    match password.iter().position(|&b| b == 0) {
        Some(n) => password.get(..n).unwrap_or_default(),
        None => password,
    }
}

// MIT: `check_against_policy` (lib/kadm5/srv/server_misc.c:81-100)
/// Length is bytes; a non-ASCII byte is the other class.
fn check_against_policy(password: &[u8], pol: &NamedPolicy) -> Result<(), Error> {
    if pol.min_length > 0 && password.len() < pol.min_length as usize {
        return Err(Error::PasswordPolicy(format!(
            "min_length {}",
            pol.min_length
        )));
    }
    if pol.min_classes > 0 {
        let mut has_upper = false;
        let mut has_lower = false;
        let mut has_digit = false;
        let mut has_punct = false;
        let mut has_other = false;
        for &c in password {
            if c.is_ascii_lowercase() {
                has_lower = true;
            } else if c.is_ascii_uppercase() {
                has_upper = true;
            } else if c.is_ascii_digit() {
                has_digit = true;
            } else if c.is_ascii_punctuation() {
                has_punct = true;
            } else {
                has_other = true;
            }
        }
        let n = u32::from(has_upper)
            + u32::from(has_lower)
            + u32::from(has_digit)
            + u32::from(has_punct)
            + u32::from(has_other);
        if n < pol.min_classes {
            return Err(Error::PasswordPolicy(format!(
                "min_classes {}",
                pol.min_classes
            )));
        }
    }
    Ok(())
}

// MIT: `passwd_check` (lib/kadm5/srv/server_misc.c:127-130)
pub(super) fn module_refusal(
    note: &mut dyn FnMut(Severity, &str),
    module: &str,
    princ: &str,
    text: &str,
) -> Error {
    // syslog LOG_ERR
    note(
        Severity::Err,
        &format!("password quality module {module} rejected password for {princ}: {text}"),
    );
    Error::PasswordPolicy(text.to_owned())
}

fn syslog_note(severity: Severity, text: &str) {
    klog::syslog(severity, text);
}

// MIT: `apply_keysalt_policy` (svr_principal.c:128-231)
pub fn apply_keysalt_policy(
    allowed_keysalts: Option<&str>,
    requested: &[KeySalt],
    supported: &[KeySalt],
) -> Result<Vec<KeySalt>, Error> {
    let Some(ak) = allowed_keysalts
        .filter(|s| !s.is_empty())
        .map(parse_keysalts)
    else {
        return Ok(if requested.is_empty() {
            supported.to_vec()
        } else {
            requested.to_vec()
        });
    };
    if requested.iter().any(|ks| !ak.contains(ks)) {
        return Err(Error::BadKeysalts);
    }
    if requested.is_empty() {
        return Ok(ak);
    }
    Ok(ak.into_iter().filter(|ks| requested.contains(ks)).collect())
}

// MIT: `add_key_pwd` (lib/kdb/kdb_cpw.c:255-312)
pub(super) fn keys_from_password(
    keysalts: &[KeySalt],
    password: &[u8],
    name: &PrincipalName,
    realm: &str,
    kvno: u32,
) -> Result<Vec<KeyEntry>, Error> {
    let mut keys: Vec<KeyEntry> = Vec::new();
    for ks in keysalts {
        if keys.iter().any(|k| k.etype == ks.etype) {
            continue;
        }
        let salt = match ks.salt {
            0 => name.default_salt(realm),
            2 => {
                let mut salt = Vec::new();
                for part in &name.name_string {
                    salt.extend_from_slice(part.as_bytes());
                }
                salt
            }
            3 => realm.as_bytes().to_vec(),
            4 => random_salt()?,
            _ => return Err(Error::InvalidArgument("Unsupported salt type".into())),
        };
        let mut key = KeyEntry::new(
            ks.etype,
            string_to_key(ks.etype, password, &salt, None)?,
            kvno,
        );
        if ks.salt > 0 {
            key.salt_type = Some(ks.salt);
            key.kdb_salt = Some(salt);
        }
        keys.push(key);
    }
    Ok(keys)
}

// MIT: `make_random_salt` (lib/kdb/kdb_cpw.c:211-238)
fn random_salt() -> Result<Vec<u8>, Error> {
    let mut rnd = [0u8; 8];
    getrandom::getrandom(&mut rnd).map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(rnd
        .iter()
        .flat_map(|b| [0x40 | (b >> 4), 0x40 | (b & 0x0f)])
        .collect())
}

impl PrincipalStore {
    pub fn set_password(&mut self, name: &PrincipalName, password: &[u8]) -> Result<(), Error> {
        self.set_password_keepold(name, password, false)
    }

    // MIT: `check_min_life` (misc.c:60-121)
    pub fn check_min_life(&self, name: &PrincipalName) -> Result<(), Error> {
        self.check_min_life_in(name, &self.realm)
    }

    pub fn check_min_life_in(&self, name: &PrincipalName, princ_realm: &str) -> Result<(), Error> {
        let p = self
            .get_in_realm(name, princ_realm)
            .ok_or(Error::NotFound)?;
        if p.attributes & KDB_REQUIRES_PWCHANGE != 0 {
            return Ok(());
        }
        let Some(pol_name) = p.pw_policy.as_ref() else {
            return Ok(());
        };
        let Some(pol) = self.policies.get(pol_name) else {
            return Ok(());
        };
        if pol.pw_min_life == 0 {
            return Ok(());
        }
        let last = last_pwd_unix(p);
        let now = unix_now_u32();
        if now.saturating_sub(last) < pol.pw_min_life {
            return Err(Error::PassTooSoon {
                until: last.saturating_add(pol.pw_min_life),
            });
        }
        Ok(())
    }

    pub(crate) fn set_password_keepold(
        &mut self,
        name: &PrincipalName,
        password: &[u8],
        keepold: bool,
    ) -> Result<(), Error> {
        self.set_password_keepold_n(name, password, u32::from(keepold))
    }

    pub(crate) fn set_password_keepold_n(
        &mut self,
        name: &PrincipalName,
        password: &[u8],
        keepold: u32,
    ) -> Result<(), Error> {
        let realm = self.realm.clone();
        let actor = default_mod_actor(&realm);
        self.set_password_keepold_n_in(name, &realm, password, keepold, &actor)
    }

    pub fn set_password_keepold_n_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        password: &[u8],
        keepold: u32,
        actor: &str,
    ) -> Result<(), Error> {
        self.set_password_etypes_keepold_n_in(name, princ_realm, password, keepold, actor, &[])
    }

    // MIT: `kadm5_chpass_principal_3` (svr_principal.c:1259-1259)
    pub fn set_password_etypes_keepold_n_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        password: &[u8],
        keepold: u32,
        actor: &str,
        etypes: &[KeySalt],
    ) -> Result<(), Error> {
        self.inside_change()?;
        if princ_realm == self.realm && name.components_joined() == "kadmin/history" {
            return Err(Error::InvalidArgument(
                "Cannot change protected principal".into(),
            ));
        }
        // MIT: `add_key_pwd` (lib/kdb/kdb_cpw.c:315-315)
        let password = c_password(password);
        let id = self.canonical_id(name, princ_realm)?;
        let pol = self
            .map
            .get(&id)
            .ok_or(Error::NotFound)?
            .pw_policy
            .as_ref()
            .and_then(|n| self.policies.get(n));
        let nhist = pol.map(|pol| pol.history);
        let allowed = pol.and_then(|p| p.allowed_keysalts.clone());
        let use_ks =
            apply_keysalt_policy(allowed.as_deref(), etypes, &self.policy.password_keysalts())?;
        let use_etypes: Vec<EncryptionType> = use_ks.iter().map(|ks| ks.etype).collect();
        // A refused password still leaves kadmin/history.
        let hist = match nhist {
            Some(_) => Some(self.ensure_history_principal(actor)?),
            None => None,
        };
        self.check_password_quality_in(name, princ_realm, password, &mut syslog_note)?;
        let Some(existing) = self.map.get(&id) else {
            return Err(Error::NotFound);
        };
        let kvno = next_kvno(&existing.keys);
        let new_keys =
            keys_from_password(&use_ks, password, &existing.name, &existing.realm, kvno)?;
        super::kadm5_hook::hook_chpass(
            self,
            super::kadm5_hook::HookStage::Precommit,
            name,
            princ_realm,
            keepold,
            Some(password),
            &use_etypes,
        )?;
        self.replace_password_keys(&id, new_keys, nhist.zip(hist), keepold, actor)?;
        if let Some(p) = self.map.get_mut(&id) {
            p.salt = crate::kdb_dump::salt_of_keys(&p.keys, &p.name, &p.realm);
        }
        self.apply_pw_max_life_in(name, princ_realm)?;
        let snap = self.map.get(&id).cloned();
        if let Some(p) = &snap {
            self.zero_fail_count_in_file(p, unix_now_u32());
        }
        self.note_ulog(id, false, snap);
        self.save_if_configured()?;
        self.postcommit(super::kadm5_hook::Post::Chpass {
            princ: name.clone(),
            realm: princ_realm.to_owned(),
            keepold,
            password: Some(zeroize::Zeroizing::new(password.to_vec())),
            etypes: use_etypes,
        });
        Ok(())
    }

    pub(super) fn apply_pw_max_life_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
    ) -> Result<(), Error> {
        let id = self.canonical_id(name, princ_realm)?;
        let max_life = {
            let p = self.map.get(&id).ok_or(Error::NotFound)?;
            p.pw_policy
                .as_ref()
                .and_then(|n| self.policies.get(n))
                .map_or(0, |pol| pol.pw_max_life)
        };
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        p.pw_expire = if max_life == 0 {
            0
        } else {
            last_pwd_unix(p).saturating_add(max_life)
        };
        Ok(())
    }

    fn replace_password_keys(
        &mut self,
        id: &str,
        new_keys: Vec<KeyEntry>,
        history: Option<(u32, (u32, ProtocolKey))>,
        keepold: u32,
        actor: &str,
    ) -> Result<(), Error> {
        let p = self.map.get_mut(id).ok_or(Error::NotFound)?;
        let old = std::mem::replace(&mut p.keys, new_keys);
        if let Some((nhist, (hist_kvno, hist_key))) = history {
            record_history(p, &old, nhist, hist_kvno, &hist_key)?;
            refresh_kadm_tl(p);
        }
        if keepold > 0 {
            p.keys.extend(old);
            if keepold > 1 {
                cap_key_versions(&mut p.keys, keepold);
            }
        }
        p.attributes &= !KDB_REQUIRES_PWCHANGE;
        p.fail_auth_count = 0;
        stamp_admin_tl(p, true, actor);
        Ok(())
    }

    pub fn change_password(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
        password: &[u8],
    ) -> Result<(), Error> {
        let id = crate::kdb::lookup_principal_id(name, &self.realm);
        acl.check(actor, AdminOp::ChangePassword, Some(&id))?;
        self.set_password_keepold_n_in(name, &self.realm.clone(), password, 0, actor)
    }

    pub fn set_last_pwd_unix(&mut self, name: &PrincipalName, ts: u32) -> Result<(), Error> {
        self.inside_change()?;
        let id = self.canonical_id(name, &self.realm)?;
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        p.tl_data.retain(|t| t.ty != TL_LAST_PWD_CHANGE);
        p.tl_data.push(TlData {
            ty: TL_LAST_PWD_CHANGE,
            contents: ts.to_le_bytes().to_vec(),
        });
        let snap = p.clone();
        self.note_ulog(id, false, Some(snap));
        self.save_if_configured()
    }

    // MIT: `kadm5_create_principal_3` (svr_principal.c:364-373)
    pub fn check_new_password(
        &self,
        name: &PrincipalName,
        policy: Option<&str>,
        password: &[u8],
    ) -> Result<(), Error> {
        let realm = self.realm.clone();
        self.check_new_password_in(name, &realm, policy, password, &mut syslog_note)
    }

    pub(super) fn check_new_password_in(
        &self,
        name: &PrincipalName,
        princ_realm: &str,
        policy: Option<&str>,
        password: &[u8],
        note: &mut dyn FnMut(Severity, &str),
    ) -> Result<(), Error> {
        let password = c_password(password);
        let bound = policy.filter(|name| self.policies.contains_key(*name));
        if let Some(pol) = bound.and_then(|name| self.policies.get(name)) {
            check_against_policy(password, pol)?;
        }
        super::pwqual::run(self, name, princ_realm, bound, password, note)
    }

    // MIT: `kadm5_chpass_principal_3` (lib/kadm5/srv/svr_principal.c:1282-1282)
    pub fn check_password_quality(
        &self,
        name: &PrincipalName,
        password: &[u8],
    ) -> Result<(), Error> {
        let realm = self.realm.clone();
        self.check_password_quality_in(name, &realm, password, &mut syslog_note)
    }

    pub(super) fn check_password_quality_in(
        &self,
        name: &PrincipalName,
        princ_realm: &str,
        password: &[u8],
        note: &mut dyn FnMut(Severity, &str),
    ) -> Result<(), Error> {
        let password = c_password(password);
        if self.get_in_realm(name, princ_realm).is_none() {
            return Ok(());
        }
        let pol_name = self
            .get_in_realm(name, princ_realm)
            .and_then(|p| p.pw_policy.clone());
        let has_policy = pol_name
            .as_ref()
            .is_some_and(|n| self.policies.contains_key(n));
        if let Some(pol) = pol_name.as_ref().and_then(|n| self.policies.get(n)) {
            check_against_policy(password, pol)?;
        }
        let bound = if has_policy {
            pol_name.as_deref()
        } else {
            None
        };
        super::pwqual::run(self, name, princ_realm, bound, password, note)?;
        let history = pol_name
            .as_ref()
            .and_then(|n| self.policies.get(n))
            .map(|pol| pol.history);
        let Some(history) = history else {
            return Ok(());
        };
        if history == 0 {
            return Ok(());
        }
        let Some(p) = self.get_in_realm(name, princ_realm) else {
            return Ok(());
        };
        // N includes the current key; 1 keeps none older.
        let extra = history.saturating_sub(1) as usize;
        let mut hist: Vec<&KeyEntry> = p.key_history.iter().collect();
        let mut kvnos: Vec<u32> = hist.iter().map(|k| k.kvno).collect();
        kvnos.sort_unstable();
        kvnos.dedup();
        let keep: Vec<u32> = kvnos.into_iter().rev().take(extra).collect();
        hist.retain(|k| keep.contains(&k.kvno));
        for k in p.keys.iter().chain(hist) {
            if let Ok(nk) = string_to_key(k.etype, password, &p.salt, None)
                && bool::from(nk.as_bytes().ct_eq(k.key.as_bytes()))
            {
                return Err(Error::PasswordPolicy("history".into()));
            }
        }
        Ok(())
    }
}
