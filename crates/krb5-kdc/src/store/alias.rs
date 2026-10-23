use krb5_types::PrincipalName;

use super::PrincipalStore;
use super::principal::{Principal, TlData, stamp_admin_tl};
use crate::error::Error;
use crate::kdb_dump::{TL_ALIAS_TARGET, TL_KADM_DATA};

pub const MAX_ALIAS_DEPTH: usize = 10;

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

    // MIT: `kadm5_create_alias` (svr_principal.c:2051-2087)
    /// An absent target is fine; the alias must not resolve.
    pub fn create_alias_in(
        &mut self,
        alias: &PrincipalName,
        alias_realm: &str,
        target: &PrincipalName,
        target_realm: &str,
        actor: &str,
    ) -> Result<(), Error> {
        self.inside_change()?;
        if alias_realm != target_realm {
            return Err(Error::AliasRealm);
        }
        let id = crate::kdb::lookup_principal_id(alias, alias_realm);
        if self.get(&id).is_some() {
            return Err(Error::AlreadyExists);
        }
        super::kadm5_hook::hook_alias(
            self,
            super::kadm5_hook::HookStage::Precommit,
            alias,
            alias_realm,
            target,
            target_realm,
        )?;
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
        // MIT: `kdb_put_entry` (lib/kadm5/srv/server_kdb.c:376-395)
        stamp_admin_tl(&mut p, false, actor);
        super::update_tl_data(
            &mut p.tl_data,
            TlData {
                ty: TL_KADM_DATA,
                contents: empty_kadm_data(),
            },
        );
        let mut contents = target.unparse_with_realm(target_realm).into_bytes();
        contents.push(0);
        p.tl_data.push(TlData {
            ty: TL_ALIAS_TARGET,
            contents,
        });
        self.note_ulog(id.clone(), false, Some(p.clone()));
        self.map.insert(id, p);
        self.save_if_configured()?;
        self.postcommit(super::kadm5_hook::Post::Alias {
            alias: alias.clone(),
            alias_realm: alias_realm.to_owned(),
            target: target.clone(),
            target_realm: target_realm.to_owned(),
        });
        Ok(())
    }
}
