//! Transited realms and inter-realm trust.

use std::collections::BTreeMap;

use krb5_crypto::ProtocolKey;
use krb5_types::transited::hierarchical_walk_realms;
use krb5_types::{MAX_TRANSIT_RAW, PrincipalName};

use super::PrincipalStore;
use super::keys::{KeyEntry, next_kvno};
use super::principal::{AdminEnt, CreateKeys};
use crate::acl::{Acl, AdminOp};
use crate::error::Error;

/// Any dot capath lists no intermediate.
pub(super) fn permitted_transited(
    capaths: &BTreeMap<String, BTreeMap<String, Vec<String>>>,
    crealm: &str,
    srealm: &str,
) -> Vec<String> {
    if let Some(vals) = capaths.get(crealm).and_then(|m| m.get(srealm)) {
        if vals.iter().any(|v| v == ".") {
            return Vec::new();
        }
        return vals.clone();
    }
    hierarchical_intermediates(crealm, srealm)
}

pub(crate) fn walk_realm_instances(
    capaths: &BTreeMap<String, BTreeMap<String, Vec<String>>>,
    client: &str,
    server: &str,
) -> Vec<String> {
    if client == server {
        return Vec::new();
    }
    if let Some(vals) = capaths.get(client).and_then(|m| m.get(server)) {
        let mut out = vec![client.to_owned()];
        if !(vals.len() == 1 && vals[0] == ".") {
            for v in vals {
                if v != "." {
                    out.push(v.clone());
                }
            }
        }
        out.push(server.to_owned());
        return out;
    }
    hierarchical_walk_realms(client, server)
}

/// An overlong realm name is not walked.
pub(super) fn hierarchical_intermediates(client: &str, server: &str) -> Vec<String> {
    if client.len() >= MAX_TRANSIT_RAW || server.len() >= MAX_TRANSIT_RAW {
        return Vec::new();
    }
    let c: Vec<&str> = client.split('.').collect();
    let s: Vec<&str> = server.split('.').collect();
    let mut common = 0usize;
    while common < c.len() && common < s.len() && c[c.len() - 1 - common] == s[s.len() - 1 - common]
    {
        common += 1;
    }
    if common == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for k in 1..=c.len() - common {
        out.push(c[k..].join("."));
    }
    for k in (0..s.len() - common).rev() {
        out.push(s[k..].join("."));
    }
    out
}

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
        if self.get(&out_id).is_some() {
            return Err(Error::AlreadyExists);
        }
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
        acl.check(actor, AdminOp::Create, Some(&id))?;
        if self.map.contains_key(&id) {
            let n = if let Some(k) = kvno {
                asked_kvno(Some(k))?
            } else {
                let keys = self
                    .map
                    .get(&id)
                    .map(|p| p.keys.clone())
                    .unwrap_or_default();
                next_kvno(&keys)
            };
            let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
            if replace {
                p.keys.clear();
            }
            p.keys.push(KeyEntry::new(key.etype(), key, n));
            let snap = p.clone();
            self.note_ulog(id, false, Some(snap));
            return self.save_if_configured();
        }
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
