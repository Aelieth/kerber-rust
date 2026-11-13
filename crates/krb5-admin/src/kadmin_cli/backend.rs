//! The store calls of the command layer, at `kadm5` granularity.

use krb5_kdc::PrincipalWrite as _;
use krb5_kdc::{AdminEnt, AdminFields, Error, KeyEntry, NamedPolicy, Principal, PrincipalStore};
use krb5_types::PrincipalName;

use crate::PolicyArgs;

pub(super) mod mask {
    pub(crate) const PRINCIPAL: u32 = 0x0000_0001;
    pub(crate) const PRINC_EXPIRE_TIME: u32 = 0x0000_0002;
    pub(crate) const PW_EXPIRATION: u32 = 0x0000_0004;
    pub(crate) const ATTRIBUTES: u32 = 0x0000_0010;
    pub(crate) const MAX_LIFE: u32 = 0x0000_0020;
    pub(crate) const KVNO: u32 = 0x0000_0100;
    pub(crate) const POLICY: u32 = 0x0000_0800;
    pub(crate) const POLICY_CLR: u32 = 0x0000_1000;
    pub(crate) const MAX_RLIFE: u32 = 0x0000_2000;
    pub(crate) const FAIL_AUTH_COUNT: u32 = 0x0001_0000;
    pub(crate) const KEY_DATA: u32 = 0x0002_0000;
    pub(crate) const TL_DATA: u32 = 0x0004_0000;
}

pub(crate) struct NewPrincipal<'a> {
    pub(crate) name: &'a PrincipalName,
    pub(crate) realm: &'a str,
    pub(crate) ent: AdminEnt,
    pub(crate) keysalts: &'a [krb5_crypto::KeySalt],
    pub(crate) db_args: &'a [String],
    pub(crate) nokey: bool,
    pub(crate) pass: Option<&'a [u8]>,
}

pub(crate) struct ModPrincipal<'a> {
    pub(crate) name: &'a PrincipalName,
    pub(crate) realm: &'a str,
    pub(crate) ent: AdminEnt,
    pub(crate) db_args: &'a [String],
    pub(crate) unlock: bool,
    pub(crate) had_policy: bool,
}

/// What `kadmin` asks of the database; MIT's `kadm5` API.
pub(crate) trait Kadm5Api {
    fn refresh(&mut self) -> Result<(), Error>;
    fn get_principal(&mut self, name: &PrincipalName, realm: &str) -> Result<Principal, Error>;
    fn merge_lockout(&self, p: &mut Principal);
    fn list_principals(&mut self, expr: Option<&str>) -> Result<Vec<String>, Error>;
    fn match_principals(&mut self, pattern: &str) -> Result<Vec<String>, Error>;
    fn create_principal(&mut self, req: &NewPrincipal<'_>) -> Result<(), Error>;
    fn modify_principal(&mut self, req: &ModPrincipal<'_>) -> Result<(), Error>;
    fn delete_principal(&mut self, name: &PrincipalName, realm: &str) -> Result<(), Error>;
    fn rename_principal(
        &mut self,
        old: &PrincipalName,
        old_realm: &str,
        new: &PrincipalName,
        new_realm: &str,
    ) -> Result<(), Error>;
    fn create_alias(
        &mut self,
        alias: &PrincipalName,
        alias_realm: &str,
        target: &PrincipalName,
        target_realm: &str,
    ) -> Result<(), Error>;
    fn change_password(
        &mut self,
        name: &PrincipalName,
        realm: &str,
        pw: &[u8],
        keepold: u32,
        keysalts: &[krb5_crypto::KeySalt],
    ) -> Result<(), Error>;
    fn randomize_key(
        &mut self,
        name: &PrincipalName,
        realm: &str,
        keysalts: &[krb5_crypto::KeySalt],
        keepold: u32,
    ) -> Result<Vec<KeyEntry>, Error>;
    fn get_principal_keys(
        &mut self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Vec<KeyEntry>, Error>;
    fn purge_keys(&mut self, name: &PrincipalName, realm: &str, keepkvno: i32)
    -> Result<(), Error>;
    fn get_strings(
        &mut self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Vec<(String, String)>, Error>;
    fn set_string(
        &mut self,
        name: &PrincipalName,
        realm: &str,
        key: &str,
        value: Option<&str>,
    ) -> Result<(), Error>;
    fn policy_exists(&mut self, name: &str) -> bool;
    fn has_policy(&self, name: &str) -> bool;
    fn get_policy(&mut self, name: &str) -> Result<NamedPolicy, Error>;
    fn list_policies(&mut self, expr: Option<&str>) -> Result<Vec<String>, Error>;
    fn create_policy(&mut self, args: &PolicyArgs) -> Result<(), Error>;
    fn modify_policy(&mut self, args: &PolicyArgs, clear_keysalts: bool) -> Result<(), Error>;
    fn delete_policy(&mut self, name: &str) -> Result<(), Error>;
    fn map_update_log(&mut self, path: &std::path::Path, entries: u32) -> Result<(), String>;
    fn lock(&mut self) -> Result<(), Error>;
    fn unlock(&mut self) -> Result<(), Error>;
    #[cfg(all(test, feature = "test-hooks"))]
    fn local_store(&self) -> &PrincipalStore;
}

pub(crate) struct LocalBackend {
    store: PrincipalStore,
    caller: String,
}

impl LocalBackend {
    pub(crate) fn new(store: PrincipalStore, caller: String) -> Self {
        Self { store, caller }
    }

    /// One change under the database's exclusive lock, written once; a failure reads
    /// the store back.
    fn mutate<T>(
        &mut self,
        f: impl FnOnce(&mut PrincipalStore, &str) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let caller = self.caller.clone();
        self.store.change(|st| f(st, &caller))?
    }

    /// The keys are derived before the database's lock is taken, as MIT's create.
    fn create_staged(&mut self, r: &NewPrincipal<'_>, pw: &[u8]) -> Result<(), Error> {
        if self.refresh().is_ok() {
            let prepared = self
                .store
                .plan_create_password(r.name, r.realm, pw, r.keysalts, &r.ent)?
                .derive()?;
            if self.mutate(|st, caller| st.create_prepared(prepared, caller))? {
                return Ok(());
            }
        }
        self.mutate(|st, caller| create(st, caller, r, Some(pw)))
    }
}

/// `-nokey` leaves the entry keyless; a db2 argument is refused only after the
/// existence and password checks, as MIT orders them.
fn create(
    st: &mut PrincipalStore,
    caller: &str,
    r: &NewPrincipal<'_>,
    pass: Option<&[u8]>,
) -> Result<(), Error> {
    if let Some(arg) = r.db_args.first() {
        if let Some(p) = st.get_in_realm(r.name, r.realm) {
            p.check_kadm_data()?;
            return Err(Error::AlreadyExists);
        }
        if let Some(pw) = pass {
            st.check_new_password(r.name, r.ent.policy.as_deref(), pw)?;
        }
        return Err(db2_put_refused(arg));
    }
    let keys = match pass {
        Some(p) => krb5_kdc::CreateKeys::Password(p),
        None if r.nokey => krb5_kdc::CreateKeys::Explicit(&[]),
        None => krb5_kdc::CreateKeys::Random,
    };
    st.create_principal_3_in(r.name, r.realm, keys, r.keysalts, &r.ent, caller)?;
    Ok(())
}

// MIT: `krb5_db2_put_principal` (kdb_db2.c:812-822)
fn db2_put_refused(arg: &str) -> Error {
    Error::InvalidArgument(format!("Unsupported argument \"{arg}\" for db2"))
}

fn modify(st: &mut PrincipalStore, caller: &str, r: &ModPrincipal<'_>) -> Result<(), Error> {
    let (name, realm, a) = (r.name, r.realm, &r.ent);
    let mut entry = st
        .get_in_realm(name, realm)
        .cloned()
        .ok_or(Error::NotFound)?;
    if let Some(arg) = r.db_args.first() {
        return Err(db2_put_refused(arg));
    }
    if a.mask & mask::KVNO != 0 {
        for k in &mut entry.keys {
            k.kvno = a.kvno & 0xffff;
        }
        st.put_principal(entry)?;
    }
    if r.unlock {
        st.admin_unlock_in(name, realm, caller)?;
    }
    let set = |bit: u32| a.mask & bit != 0;
    st.apply_admin_fields_in(
        name,
        realm,
        AdminFields {
            attributes: set(mask::ATTRIBUTES).then_some(a.attributes),
            max_life: set(mask::MAX_LIFE).then_some(u64::from(a.max_life)),
            expiration: set(mask::PRINC_EXPIRE_TIME).then_some(a.princ_expire_time),
            pw_expire: set(mask::PW_EXPIRATION).then_some(a.pw_expiration),
            policy: if set(mask::POLICY) {
                a.policy.clone()
            } else {
                None
            },
            clear_policy: set(mask::POLICY_CLR) && r.had_policy,
            max_renewable_life: set(mask::MAX_RLIFE).then_some(u64::from(a.max_renewable_life)),
        },
        caller,
    )
}

impl Kadm5Api for LocalBackend {
    fn refresh(&mut self) -> Result<(), Error> {
        self.store.reload_if_stale()
    }

    fn get_principal(&mut self, name: &PrincipalName, realm: &str) -> Result<Principal, Error> {
        self.refresh()?;
        let p = self
            .store
            .get_in_realm(name, realm)
            .ok_or(Error::NotFound)?;
        p.check_kadm_data()?;
        Ok(p.clone())
    }

    fn merge_lockout(&self, p: &mut Principal) {
        self.store.merge_lockout(p);
    }

    fn list_principals(&mut self, expr: Option<&str>) -> Result<Vec<String>, Error> {
        self.refresh()?;
        Ok(crate::kadm5::principals_matching(&self.store, expr))
    }

    fn match_principals(&mut self, pattern: &str) -> Result<Vec<String>, Error> {
        self.refresh()?;
        let pat = crate::kadm5::glob_expand(pattern, true);
        Ok(self
            .store
            .ids()
            .into_iter()
            .filter(|id| crate::kadm5::glob_is_match(pat.as_bytes(), id.as_bytes()))
            .collect())
    }

    fn create_principal(&mut self, r: &NewPrincipal<'_>) -> Result<(), Error> {
        match r.pass {
            Some(pw) if r.db_args.is_empty() => self.create_staged(r, pw),
            _ => self.mutate(|st, caller| create(st, caller, r, r.pass)),
        }
    }

    fn modify_principal(&mut self, r: &ModPrincipal<'_>) -> Result<(), Error> {
        self.mutate(|st, caller| modify(st, caller, r))
    }

    fn delete_principal(&mut self, name: &PrincipalName, realm: &str) -> Result<(), Error> {
        self.mutate(|st, _| st.remove_in(name, realm))
    }

    fn rename_principal(
        &mut self,
        old: &PrincipalName,
        old_realm: &str,
        new: &PrincipalName,
        new_realm: &str,
    ) -> Result<(), Error> {
        self.mutate(|st, caller| st.rename_unchecked(old, old_realm, new, new_realm, caller))
    }

    fn create_alias(
        &mut self,
        alias: &PrincipalName,
        alias_realm: &str,
        target: &PrincipalName,
        target_realm: &str,
    ) -> Result<(), Error> {
        self.mutate(|st, caller| {
            st.create_alias_in(alias, alias_realm, target, target_realm, caller)
        })
    }

    fn change_password(
        &mut self,
        name: &PrincipalName,
        realm: &str,
        pw: &[u8],
        keepold: u32,
        keysalts: &[krb5_crypto::KeySalt],
    ) -> Result<(), Error> {
        let caller = self.caller.clone();
        self.store
            .change_password_staged(name, realm, pw, keepold, &caller, keysalts)
            .and_then(|r| r)
    }

    fn randomize_key(
        &mut self,
        name: &PrincipalName,
        realm: &str,
        keysalts: &[krb5_crypto::KeySalt],
        keepold: u32,
    ) -> Result<Vec<KeyEntry>, Error> {
        self.mutate(|st, caller| {
            st.chrand_etypes_keepold_in(name, realm, keysalts, keepold, caller)
        })
    }

    // MIT: `kadm5_get_principal_keys` (lib/kadm5/srv/svr_principal.c:1775-1776)
    fn get_principal_keys(
        &mut self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Vec<KeyEntry>, Error> {
        self.refresh().and_then(|()| {
            let p = self
                .store
                .get_in_realm(name, realm)
                .ok_or(Error::NotFound)?;
            p.check_kadm_data()?;
            Ok(p.keys_in_order().into_iter().cloned().collect())
        })
    }

    fn purge_keys(
        &mut self,
        name: &PrincipalName,
        realm: &str,
        keepkvno: i32,
    ) -> Result<(), Error> {
        self.mutate(|st, caller| st.purgekeys_in(name, realm, keepkvno, caller))
    }

    fn get_strings(
        &mut self,
        name: &PrincipalName,
        realm: &str,
    ) -> Result<Vec<(String, String)>, Error> {
        self.refresh()
            .and_then(|()| self.store.get_strings_in(name, realm))
    }

    fn set_string(
        &mut self,
        name: &PrincipalName,
        realm: &str,
        key: &str,
        value: Option<&str>,
    ) -> Result<(), Error> {
        self.mutate(|st, caller| st.set_string_in(name, realm, key, value, caller))
    }

    fn policy_exists(&mut self, name: &str) -> bool {
        let _ = self.refresh();
        self.has_policy(name)
    }

    fn has_policy(&self, name: &str) -> bool {
        self.store.policies().contains_key(name)
    }

    fn get_policy(&mut self, name: &str) -> Result<NamedPolicy, Error> {
        self.refresh()?;
        self.store
            .policies()
            .get(name)
            .cloned()
            .ok_or(Error::NotFound)
    }

    fn list_policies(&mut self, expr: Option<&str>) -> Result<Vec<String>, Error> {
        self.refresh()?;
        Ok(crate::kadm5::policies_matching(&self.store, expr))
    }

    fn create_policy(&mut self, args: &PolicyArgs) -> Result<(), Error> {
        self.mutate(|st, _| {
            let exists = st.policies().contains_key(&args.name);
            let pol = crate::kadm5::create_policy_local(exists, args)
                .map_err(|t| Error::InvalidArgument(t.to_owned()))?;
            st.put_policy(pol)
        })
    }

    fn modify_policy(&mut self, args: &PolicyArgs, clear_keysalts: bool) -> Result<(), Error> {
        self.mutate(|st, _| {
            let existing = st
                .policies()
                .get(&args.name)
                .cloned()
                .ok_or(Error::NotFound)?;
            let mut pol = crate::kadm5::modify_policy_local(&existing, args)
                .map_err(|t| Error::InvalidArgument(t.to_owned()))?;
            if clear_keysalts {
                pol.allowed_keysalts = None;
            }
            st.put_policy(pol)
        })
    }

    fn delete_policy(&mut self, name: &str) -> Result<(), Error> {
        self.mutate(|st, _| st.delete_policy(name))
    }

    fn map_update_log(&mut self, path: &std::path::Path, entries: u32) -> Result<(), String> {
        self.store
            .map_ulog(path, entries, krb5_kdc::IpropRole::Primary)
            .map_err(|e| e.to_string())
    }

    fn lock(&mut self) -> Result<(), Error> {
        self.store.lock_database()
    }

    fn unlock(&mut self) -> Result<(), Error> {
        self.store.unlock_database()
    }

    #[cfg(all(test, feature = "test-hooks"))]
    fn local_store(&self) -> &PrincipalStore {
        &self.store
    }
}
