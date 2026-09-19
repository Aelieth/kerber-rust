//! Password quality (`pwqual_*.c`, `server_misc.c` `passwd_check`),
//! min-life (`misc.c` `check_min_life`), keysalt policy
//! (`svr_principal.c` `apply_keysalt_policy`) and the chpass path
//! including the password-history `ct_eq` compare.

use krb5_crypto::{EncryptionType, ProtocolKey, parse_keysalt_list, string_to_key};
use krb5_types::PrincipalName;
use subtle::ConstantTimeEq;

use super::flags::KDB_REQUIRES_PWCHANGE;
use super::history::record_history;
use super::keys::{KeyEntry, cap_key_versions};
use super::policy::NamedPolicy;
use super::principal::{Principal, TlData, default_mod_actor, refresh_kadm_tl, stamp_admin_tl};
use super::{PrincipalStore, unix_now_u32};
use crate::acl::{Acl, AdminOp};
use crate::error::Error;
use crate::kdb_dump::TL_LAST_PWD_CHANGE;

/// Default PBKDF2 iteration count advertised in ETYPE-INFO2 (RFC 3962 default).
pub const S2K_ITERS: u32 = 4096;

/// MIT `pwqual_empty.c:40-44` extended message (`KADM5_PASS_Q_TOOSHORT`).
pub const PWQUAL_EMPTY: &str = "Empty passwords are not allowed";

/// MIT `pwqual_princ.c:50-51` extended message (`KADM5_PASS_Q_DICT`).
pub const PWQUAL_PRINC: &str = "Password may not match principal name";

/// MIT `kadm_err.et` `KADM5_PASS_Q_DICT` text: the `dict` module and the
/// realm branch of `princ_check` (`pwqual_princ.c:45-47`) set no message.
pub const PWQUAL_DICT: &str = "Password is in the password dictionary";

fn last_pwd_unix(p: &Principal) -> u32 {
    p.tl_data
        .iter()
        .find(|t| t.ty == TL_LAST_PWD_CHANGE)
        .and_then(|t| t.contents.get(..4))
        .and_then(|b| b.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

fn check_pwqual(password: &[u8], pol: &NamedPolicy) -> Result<(), Error> {
    let s = std::str::from_utf8(password).unwrap_or("");
    if pol.min_length > 0 && s.len() < pol.min_length as usize {
        return Err(Error::PasswordPolicy(format!(
            "min_length {}",
            pol.min_length
        )));
    }
    if pol.min_classes > 0 {
        let mut n = 0u32;
        if s.chars().any(|c| c.is_ascii_lowercase()) {
            n += 1;
        }
        if s.chars().any(|c| c.is_ascii_uppercase()) {
            n += 1;
        }
        if s.chars().any(|c| c.is_ascii_digit()) {
            n += 1;
        }
        if s.chars().any(|c| c.is_ascii_punctuation()) {
            n += 1;
        }
        if s.chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c.is_ascii_punctuation()))
        {
            n += 1;
        }
        if n < pol.min_classes {
            return Err(Error::PasswordPolicy(format!(
                "min_classes {}",
                pol.min_classes
            )));
        }
    }
    Ok(())
}

/// MIT `apply_keysalt_policy` (`svr_principal.c:128-231`): the request's
/// `-e` tuples when present, else the bound policy's `allowed_keysalts`,
/// else `supported_enctypes`. A requested tuple outside the policy is
/// `KADM5_BAD_KEYSALTS`. Salt types are stripped like `parse_keysalt_list`
/// (the live cell is `:normal`).
///
/// # Errors
///
/// [`Error::BadKeysalts`].
pub fn apply_keysalt_policy(
    allowed_keysalts: Option<&str>,
    requested: &[EncryptionType],
    supported: &[EncryptionType],
) -> Result<Vec<EncryptionType>, Error> {
    let allowed = allowed_keysalts
        .filter(|s| !s.is_empty())
        .map(parse_keysalt_list);
    match allowed {
        None => {
            if requested.is_empty() {
                Ok(supported.to_vec())
            } else {
                Ok(requested.to_vec())
            }
        }
        Some(ak) => {
            for e in requested {
                if !ak.contains(e) {
                    return Err(Error::BadKeysalts);
                }
            }
            if requested.is_empty() {
                Ok(ak)
            } else {
                Ok(ak.into_iter().filter(|e| requested.contains(e)).collect())
            }
        }
    }
}

pub(super) fn keys_from_password(
    etypes: &[EncryptionType],
    password: &[u8],
    salt: &[u8],
    kvno: u32,
) -> Result<Vec<KeyEntry>, Error> {
    let mut keys = Vec::new();
    for etype in etypes {
        let params = s2k_params(*etype);
        let key = string_to_key(*etype, password, salt, Some(&params))?;
        keys.push(KeyEntry::new(*etype, key, kvno));
    }
    Ok(keys)
}

/// s2kparams (4-byte big-endian iteration count) for `etype`.
///
/// RFC 3962 default 4096; RFC 8009 default 32768. MIT 1.22 rejects the
/// SHA-1 count on SHA-2 etypes (`KRB5_ERR_BAD_S2K_PARAMS`).
#[must_use]
pub fn s2k_params(etype: EncryptionType) -> Vec<u8> {
    etype.default_iterations().to_be_bytes().to_vec()
}

impl PrincipalStore {
    /// Replace password-derived keys (`keepold=false`): one active kvno;
    /// prior keys go to [`Principal::key_history`] pruned to policy depth N.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when the principal is missing.
    pub fn set_password(&mut self, name: &PrincipalName, password: &[u8]) -> Result<(), Error> {
        self.set_password_keepold(name, password, false)
    }

    /// MIT `check_min_life` (`misc.c:60-121`).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] or [`Error::PassTooSoon`].
    pub fn check_min_life(&self, name: &PrincipalName) -> Result<(), Error> {
        self.check_min_life_in(name, &self.realm)
    }

    /// [`Self::check_min_life`] for `name@princ_realm`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] or [`Error::PassTooSoon`].
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

    /// Password change; `keepold` is MIT's count (0 discard, 1 all, n cap).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when the principal is missing.
    pub fn set_password_keepold(
        &mut self,
        name: &PrincipalName,
        password: &[u8],
        keepold: bool,
    ) -> Result<(), Error> {
        self.set_password_keepold_n(name, password, u32::from(keepold))
    }

    /// [`Self::set_password_keepold`] with MIT's integer keepold.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when the principal is missing.
    pub fn set_password_keepold_n(
        &mut self,
        name: &PrincipalName,
        password: &[u8],
        keepold: u32,
    ) -> Result<(), Error> {
        let realm = self.realm.clone();
        let actor = default_mod_actor(&realm);
        self.set_password_keepold_n_in(name, &realm, password, keepold, &actor)
    }

    /// [`Self::set_password_keepold_n`] for `name@princ_realm`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when the principal is missing, or
    /// [`Error::BadKeysalts`].
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

    /// [`Self::set_password_keepold_n_in`] with a v3 `ks_tuple` list
    /// (`kadm5_chpass_principal_3`, `svr_principal.c:1259`).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when the principal is missing, or
    /// [`Error::BadKeysalts`].
    pub fn set_password_etypes_keepold_n_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        password: &[u8],
        keepold: u32,
        actor: &str,
        etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        let id = self.canonical_id(name, princ_realm)?;
        // MIT `kadm5_chpass_principal_3`: a bound policy (`have_pol`) fetches
        // the history key — creating `kadmin/history` on first use — and
        // records the old keys BEFORE `passwd_check`, so a chpass rejected for
        // quality still leaves `kadmin/history` created; `pw_history_num` counts
        // the current password inside N, so history=1 keeps no old keys.
        let nhist = self
            .map
            .get(&id)
            .ok_or(Error::NotFound)?
            .pw_policy
            .as_ref()
            .and_then(|n| self.policies.get(n))
            .map(|pol| pol.history);
        let hist = match nhist {
            Some(_) => Some(self.ensure_history_principal(actor)?),
            None => None,
        };
        self.check_password_quality(name, password)?;
        let Some(existing) = self.map.get(&id) else {
            return Err(Error::NotFound);
        };
        let salt = existing.salt.clone();
        let next_kvno = existing
            .keys
            .iter()
            .chain(existing.key_history.iter())
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
        let new_keys = keys_from_password(&use_etypes, password, &salt, next_kvno)?;
        self.replace_password_keys(&id, new_keys, nhist.zip(hist), keepold, actor)?;
        self.apply_pw_max_life_in(name, princ_realm)?;
        let snap = self.map.get(&id).cloned();
        self.note_ulog(id, false, snap);
        self.save_if_configured()
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

    /// ACL-gated password change (admin `c` / `*`).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
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

    /// Set `TL_LAST_PWD_CHANGE` (tests / min_life).
    pub fn set_last_pwd_unix(&mut self, name: &PrincipalName, ts: u32) {
        let Ok(id) = self.canonical_id(name, &self.realm) else {
            return;
        };
        if let Some(p) = self.map.get_mut(&id) {
            p.tl_data.retain(|t| t.ty != TL_LAST_PWD_CHANGE);
            p.tl_data.push(TlData {
                ty: TL_LAST_PWD_CHANGE,
                contents: ts.to_le_bytes().to_vec(),
            });
        }
    }

    /// MIT `passwd_check` for a new principal (`svr_principal.c:364-373`):
    /// the named policy's length and class floors when the policy exists
    /// (`get_policy` treats an unknown name as no policy), then the built-in
    /// quality modules. `-randkey` creates do not come here.
    ///
    /// # Errors
    ///
    /// [`Error::PasswordPolicy`].
    pub fn check_new_password(
        &self,
        name: &PrincipalName,
        policy: Option<&str>,
        password: &[u8],
    ) -> Result<(), Error> {
        let pol = policy.and_then(|n| self.policies.get(n));
        if let Some(pol) = pol {
            check_pwqual(password, pol)?;
        }
        self.pwqual_modules(name, pol.is_some(), password)
    }

    /// MIT built-in password-quality modules in `k5_pwqual_load` order
    /// (`server_misc.c:44-58`: `dict`, `empty`, `princ`). `dict` and `princ`
    /// skip a principal without a policy (`pwqual_dict.c:222-223`,
    /// `pwqual_princ.c:40-41`); `empty` always applies (`pwqual_empty.c:38-44`).
    /// `princ_check` compares the realm first (plain `KADM5_PASS_Q_DICT`) and
    /// then every component (`Password may not match principal name`), all
    /// with `strcasecmp`.
    fn pwqual_modules(
        &self,
        name: &PrincipalName,
        has_policy: bool,
        password: &[u8],
    ) -> Result<(), Error> {
        if has_policy
            && !self.policy.dict_words.is_empty()
            && self
                .policy
                .dict_words
                .binary_search(&String::from_utf8_lossy(password).to_ascii_lowercase())
                .is_ok()
        {
            return Err(Error::PasswordPolicy(PWQUAL_DICT.into()));
        }
        if password.is_empty() {
            return Err(Error::PasswordPolicy(PWQUAL_EMPTY.into()));
        }
        if has_policy {
            if self.realm.as_bytes().eq_ignore_ascii_case(password) {
                return Err(Error::PasswordPolicy(PWQUAL_DICT.into()));
            }
            if name
                .name_string
                .iter()
                .any(|c| c.as_bytes().eq_ignore_ascii_case(password))
            {
                return Err(Error::PasswordPolicy(PWQUAL_PRINC.into()));
            }
        }
        Ok(())
    }

    /// MIT `passwd_check` on a password change (`svr_principal.c:1282`):
    /// the bound policy's floors, the built-in quality modules, then the
    /// policy's history.
    ///
    /// # Errors
    ///
    /// [`Error::PasswordPolicy`].
    pub fn check_password_quality(
        &self,
        name: &PrincipalName,
        password: &[u8],
    ) -> Result<(), Error> {
        let Some(p) = self.get_name(name) else {
            return Ok(());
        };
        let pol = p.pw_policy.as_ref().and_then(|n| self.policies.get(n));
        if let Some(pol) = pol {
            check_pwqual(password, pol)?;
        }
        self.pwqual_modules(name, pol.is_some(), password)?;
        let Some(pol) = pol else {
            return Ok(());
        };
        if pol.history == 0 {
            return Ok(());
        }
        let extra = pol.history.saturating_sub(1) as usize;
        let mut hist: Vec<&KeyEntry> = p.key_history.iter().collect();
        let mut kvnos: Vec<u32> = hist.iter().map(|k| k.kvno).collect();
        kvnos.sort_unstable();
        kvnos.dedup();
        let keep: Vec<u32> = kvnos.into_iter().rev().take(extra).collect();
        hist.retain(|k| keep.contains(&k.kvno));
        for k in p.keys.iter().chain(hist) {
            let params = s2k_params(k.etype);
            if let Ok(nk) = string_to_key(k.etype, password, &p.salt, Some(&params))
                && bool::from(nk.as_bytes().ct_eq(k.key.as_bytes()))
            {
                return Err(Error::PasswordPolicy("history".into()));
            }
        }
        Ok(())
    }
}
