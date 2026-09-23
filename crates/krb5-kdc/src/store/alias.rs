//! Alias stubs (`kdb5.c` `krb5_dbe_make_alias_entry` /
//! `krb5_dbe_read_alias`): `MAX_ALIAS_DEPTH`, create-alias, and the
//! hop walk used by `get` / `get_raw`.

use krb5_types::PrincipalName;

use super::PrincipalStore;
use super::principal::{Principal, TlData, stamp_admin_tl};
use crate::error::Error;
use crate::kdb_dump::{TL_ALIAS_TARGET, TL_KADM_DATA};

/// `kdb5.c` `MAX_ALIAS_DEPTH`: alias hops `krb5_db_get_principal` follows.
pub const MAX_ALIAS_DEPTH: usize = 10;

/// `xdr_osa_princ_ent_rec` of a zeroed record: version `OSA_ADB_PRINC_VERSION_1`,
/// empty policy, `aux_attributes`, `old_key_next`, `admin_history_kvno`,
/// empty `old_keys` (`kdb_put_entry` on `kadm5_create_alias`).
fn empty_kadm_data() -> Vec<u8> {
    let mut v = 0x1234_5c01u32.to_be_bytes().to_vec();
    v.resize(24, 0);
    v
}

impl PrincipalStore {
    pub(super) fn resolve_id(&self, id: &str) -> Option<String> {
        crate::kdb::resolve_alias_id(&self.realm, |k| self.map.get(k), id)
    }

    pub(super) fn canonical_id(
        &self,
        name: &PrincipalName,
        princ_realm: &str,
    ) -> Result<String, Error> {
        self.resolve_id(&crate::kdb::lookup_principal_id(name, princ_realm))
            .ok_or(Error::NotFound)
    }

    /// `kadm5_create_alias` (`svr_principal.c:2051-2087`): an alias stub is
    /// a keyless `DISALLOW_ALL_TIX` entry whose only content is
    /// `KRB5_TL_ALIAS_TARGET`. The target need not exist; the alias name must
    /// not resolve to anything.
    ///
    /// # Errors
    ///
    /// [`Error::AliasRealm`] or [`Error::AlreadyExists`].
    pub fn create_alias_in(
        &mut self,
        alias: &PrincipalName,
        alias_realm: &str,
        target: &PrincipalName,
        target_realm: &str,
        actor: &str,
    ) -> Result<(), Error> {
        if alias_realm != target_realm {
            return Err(Error::AliasRealm);
        }
        let id = crate::kdb::lookup_principal_id(alias, alias_realm);
        if self.get(&id).is_some() {
            return Err(Error::AlreadyExists);
        }
        let mut p = Principal::from_keys(
            alias.clone(),
            alias_realm.to_owned(),
            Vec::new(),
            Vec::new(),
            crate::store::PrincipalFields {
                requires_preauth: false,
                max_life: 0,
                locked: true,
                pw_expire: 0,
            },
        );
        p.tl_data.push(TlData {
            ty: TL_KADM_DATA,
            contents: empty_kadm_data(),
        });
        stamp_admin_tl(&mut p, false, actor);
        let mut contents = target.unparse_with_realm(target_realm).into_bytes();
        contents.push(0);
        p.tl_data.push(TlData {
            ty: TL_ALIAS_TARGET,
            contents,
        });
        self.note_ulog(id.clone(), false, Some(p.clone()));
        self.map.insert(id, p);
        self.save_if_configured()
    }
}
