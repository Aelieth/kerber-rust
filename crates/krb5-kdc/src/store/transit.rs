//! Transited realms and inter-realm trust.

use std::collections::BTreeMap;

use krb5_crypto::ProtocolKey;
use krb5_types::PrincipalName;

use super::PrincipalStore;
use super::flags::KDB_LOCKDOWN_KEYS;
use super::keys::KeyEntry;
use super::principal::{AdminEnt, CreateKeys};
use crate::acl::{Acl, AdminOp};
use crate::error::Error;

impl PrincipalStore {
    pub fn set_capaths(&mut self, capaths: BTreeMap<String, BTreeMap<String, Vec<String>>>) {
        self.policy.capaths = capaths;
    }

    pub fn create_interrealm(
        &mut self,
        acl: &Acl,
        actor: &str,
        foreign_realm: &str,
        password: &[u8],
    ) -> Result<(), Error> {
        let (out_name, out_id, in_name, in_id) = self.trust_ids(foreign_realm);
        let make_in = !self.map.contains_key(&in_id);
        self.allow_trust(acl, actor, &out_id, &in_id, make_in)?;
        let realm = self.realm.clone();
        self.create_principal_3_in(
            &out_name,
            &realm,
            CreateKeys::Password(password),
            &[],
            &AdminEnt::default(),
            actor,
        )?;
        self.impose_trust(acl, actor, &out_id)?;
        if make_in {
            self.create_principal_3_in(
                &in_name,
                foreign_realm,
                CreateKeys::Password(password),
                &[],
                &AdminEnt::default(),
                actor,
            )?;
            self.impose_trust(acl, actor, &in_id)?;
        }
        Ok(())
    }

    pub fn create_interrealm_key(
        &mut self,
        acl: &Acl,
        actor: &str,
        foreign_realm: &str,
        key: ProtocolKey,
        kvno: Option<u32>,
    ) -> Result<(), Error> {
        let (out_name, out_id, in_name, in_id) = self.trust_ids(foreign_realm);
        let make_in = !self.map.contains_key(&in_id);
        self.allow_trust(acl, actor, &out_id, &in_id, make_in)?;
        let kvno = asked_kvno(kvno)?;
        let ent = kvno_ent(kvno);
        let entry = KeyEntry::new(key.etype(), key, kvno);
        let realm = self.realm.clone();
        self.create_principal_3_in(
            &out_name,
            &realm,
            CreateKeys::Explicit(std::slice::from_ref(&entry)),
            &[],
            &ent,
            actor,
        )?;
        self.impose_trust(acl, actor, &out_id)?;
        if make_in {
            self.create_principal_3_in(
                &in_name,
                foreign_realm,
                CreateKeys::Explicit(std::slice::from_ref(&entry)),
                &[],
                &ent,
                actor,
            )?;
            self.impose_trust(acl, actor, &in_id)?;
        }
        Ok(())
    }

    pub fn add_interrealm_decrypt_key(
        &mut self,
        acl: &Acl,
        actor: &str,
        foreign_realm: &str,
        key: ProtocolKey,
        kvno: Option<u32>,
    ) -> Result<(), Error> {
        self.put_incoming_trust_key(acl, actor, foreign_realm, key, false, kvno)
    }

    pub fn set_interrealm_decrypt_key(
        &mut self,
        acl: &Acl,
        actor: &str,
        foreign_realm: &str,
        key: ProtocolKey,
        kvno: Option<u32>,
    ) -> Result<(), Error> {
        self.put_incoming_trust_key(acl, actor, foreign_realm, key, true, kvno)
    }

    // MIT: `create_principal_2_svc` (server_stubs.c:477-485)
    // MIT: `setkey_principal4_2_svc` (server_stubs.c:1069-1084)
    /// An ACL denial creates nothing.
    fn put_incoming_trust_key(
        &mut self,
        acl: &Acl,
        actor: &str,
        foreign_realm: &str,
        key: ProtocolKey,
        replace: bool,
        kvno: Option<u32>,
    ) -> Result<(), Error> {
        self.inside_change()?;
        let name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", self.realm.as_str()]);
        let id = crate::kdb::lookup_principal_id(&name, foreign_realm);
        if let Some(p) = self.map.get(&id) {
            acl.check(actor, AdminOp::SetKey, Some(&id))?;
            if p.attributes & KDB_LOCKDOWN_KEYS != 0 {
                return Err(Error::AclDenied);
            }
            let entry = KeyEntry::new(key.etype(), key, kvno.unwrap_or(0));
            return self.set_keys_in(
                &name,
                foreign_realm,
                vec![entry],
                u32::from(!replace),
                actor,
            );
        }
        acl.check(actor, AdminOp::Create, Some(&id))?;
        let kvno = asked_kvno(kvno)?;
        let ent = kvno_ent(kvno);
        let entry = KeyEntry::new(key.etype(), key, kvno);
        self.create_principal_3_in(
            &name,
            foreign_realm,
            CreateKeys::Explicit(std::slice::from_ref(&entry)),
            &[],
            &ent,
            actor,
        )?;
        self.impose_trust(acl, actor, &id)
    }

    fn trust_ids(&self, foreign_realm: &str) -> (PrincipalName, String, PrincipalName, String) {
        let out_name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", foreign_realm]);
        let out_id = crate::kdb::lookup_principal_id(&out_name, &self.realm);
        let in_name =
            PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", self.realm.as_str()]);
        let in_id = crate::kdb::lookup_principal_id(&in_name, foreign_realm);
        (out_name, out_id, in_name, in_id)
    }

    fn allow_trust(
        &self,
        acl: &Acl,
        actor: &str,
        out_id: &str,
        in_id: &str,
        make_in: bool,
    ) -> Result<(), Error> {
        self.inside_change()?;
        acl.check(actor, AdminOp::Create, Some(out_id))?;
        if self.get(out_id).is_some() {
            return Err(Error::AlreadyExists);
        }
        if make_in {
            acl.check(actor, AdminOp::Create, Some(in_id))?;
        }
        Ok(())
    }

    fn impose_trust(&mut self, acl: &Acl, actor: &str, id: &str) -> Result<(), Error> {
        if let Some(rs) = acl.restrictions(actor, Some(id)) {
            self.apply_acl_restrictions(id, rs)?;
        }
        Ok(())
    }
}

fn asked_kvno(kvno: Option<u32>) -> Result<u32, Error> {
    match kvno.unwrap_or(1) {
        n if n > 65535 => Err(Error::InvalidArgument("invalid kvno".into())),
        n => Ok(n),
    }
}

fn kvno_ent(kvno: u32) -> AdminEnt {
    let mut ent = AdminEnt::default();
    ent.mask |= super::kadm5_mask::KVNO;
    ent.kvno = kvno;
    ent
}
