//! Transited-realm walks (`walk_rtree.c` `krb5_walk_realm_tree`,
//! `rtree_hier_realms`) and inter-realm krbtgt trust principals
//! (`kdc_util.c` incoming / outgoing `krbtgt/<realm>`).

use std::collections::BTreeMap;

use krb5_crypto::ProtocolKey;
use krb5_types::transited::hierarchical_walk_realms;
use krb5_types::{MAX_TRANSIT_RAW, PrincipalName};

use super::PrincipalStore;
use super::keys::KeyEntry;
use super::principal::Principal;
use crate::acl::{Acl, AdminOp};
use crate::error::Error;

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

/// MIT `krb5_walk_realm_tree` instance list (`walk_rtree.c`): local, hops, dest.
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
    /// `[capaths]` from krb5.conf / kdc.conf.
    pub fn set_capaths(&mut self, capaths: BTreeMap<String, BTreeMap<String, Vec<String>>>) {
        self.policy.capaths = capaths;
    }

    /// ACL-gated inter-realm `krbtgt/FOREIGN` (shared key with the foreign KDC).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::AlreadyExists`].
    pub fn create_interrealm(
        &mut self,
        acl: &Acl,
        actor: &str,
        foreign_realm: &str,
        password: &[u8],
    ) -> Result<(), Error> {
        let name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", foreign_realm]);
        let id = crate::kdb::lookup_principal_id(&name, &self.realm);
        acl.check(actor, AdminOp::Create, Some(&id))?;
        if self.get(&id).is_some() {
            return Err(Error::AlreadyExists);
        }
        self.insert_password(&name, password)?;
        if let Some(p) = self.map.get_mut(&id) {
            p.requires_preauth = false;
        }
        if let Some(p) = self.map.get(&id) {
            self.note_ulog(id.clone(), false, Some(p.clone()));
        }
        self.ensure_incoming_trust(foreign_realm);
        self.save_if_configured()
    }

    /// Inter-realm `krbtgt/FOREIGN` with an explicit shared key (same bytes
    /// on both KDCs; default salts would diverge).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::AlreadyExists`].
    pub fn create_interrealm_key(
        &mut self,
        acl: &Acl,
        actor: &str,
        foreign_realm: &str,
        key: ProtocolKey,
    ) -> Result<(), Error> {
        let name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", foreign_realm]);
        let id = crate::kdb::lookup_principal_id(&name, &self.realm);
        acl.check(actor, AdminOp::Create, Some(&id))?;
        if self.get(&id).is_some() {
            return Err(Error::AlreadyExists);
        }
        let salt = name.default_salt(&self.realm);
        let p = Principal::from_keys(
            name,
            self.realm.clone(),
            vec![KeyEntry::new(key.etype(), key, 1)],
            salt,
            crate::store::PrincipalFields {
                requires_preauth: false,
                max_life: 0,
                locked: false,
                pw_expire: 0,
            },
        );
        self.put_principal(p);
        self.ensure_incoming_trust(foreign_realm);
        self.save_if_configured()
    }

    /// Incoming trust `krbtgt/<local>@<foreign>` (MIT KDB naming).
    ///
    /// `replace` drops keys already on that principal (the first
    /// `KRB5_TEST_INTERREALM_KEY_ACCEPT` value). Further keys append.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`].
    pub fn add_interrealm_decrypt_key(
        &mut self,
        acl: &Acl,
        actor: &str,
        foreign_realm: &str,
        key: ProtocolKey,
    ) -> Result<(), Error> {
        self.put_incoming_trust_key(acl, actor, foreign_realm, key, false)
    }

    /// Replace keys on the incoming trust principal.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`].
    pub fn set_interrealm_decrypt_key(
        &mut self,
        acl: &Acl,
        actor: &str,
        foreign_realm: &str,
        key: ProtocolKey,
    ) -> Result<(), Error> {
        self.put_incoming_trust_key(acl, actor, foreign_realm, key, true)
    }

    /// MIT `create_principal_2_svc` (`server_stubs.c:477-485`): an ACL denial does not create the principal.
    /// Replacing the trust key drops the previous versions, and adding one uses the next kvno rather than reusing the current one.
    fn put_incoming_trust_key(
        &mut self,
        acl: &Acl,
        actor: &str,
        foreign_realm: &str,
        key: ProtocolKey,
        replace: bool,
    ) -> Result<(), Error> {
        let name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", self.realm.as_str()]);
        let id = crate::kdb::lookup_principal_id(&name, foreign_realm);
        acl.check(actor, AdminOp::Create, Some(&id))?;
        if let Some(p) = self.map.get_mut(&id) {
            if replace {
                p.keys.clear();
                p.keys.push(KeyEntry::new(key.etype(), key, 1));
            } else {
                let kvno = p
                    .keys
                    .iter()
                    .map(|k| k.kvno)
                    .max()
                    .unwrap_or(0)
                    .saturating_add(1);
                p.keys.push(KeyEntry::new(key.etype(), key, kvno));
            }
            let snap = p.clone();
            self.note_ulog(id, false, Some(snap));
            return self.save_if_configured();
        }
        let salt = name.default_salt(foreign_realm);
        let p = Principal::from_keys(
            name,
            foreign_realm.to_owned(),
            vec![KeyEntry::new(key.etype(), key, 1)],
            salt,
            crate::store::PrincipalFields {
                requires_preauth: false,
                max_life: 0,
                locked: false,
                pw_expire: 0,
            },
        );
        self.put_principal(p);
        self.save_if_configured()
    }

    fn ensure_incoming_trust(&mut self, foreign_realm: &str) {
        let out_name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", foreign_realm]);
        let out_id = crate::kdb::lookup_principal_id(&out_name, &self.realm);
        let Some(out) = self.map.get(&out_id).cloned() else {
            return;
        };
        let in_name =
            PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", self.realm.as_str()]);
        let in_id = crate::kdb::lookup_principal_id(&in_name, foreign_realm);
        if self.map.contains_key(&in_id) {
            return;
        }
        let mut incoming = out;
        incoming.name = in_name;
        foreign_realm.clone_into(&mut incoming.realm);
        incoming.salt = incoming.name.default_salt(foreign_realm);
        incoming.rid = 0;
        self.put_principal(incoming);
    }
}
