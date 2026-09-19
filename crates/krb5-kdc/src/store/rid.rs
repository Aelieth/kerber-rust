//! Per-realm NT domain SID and PAC RIDs (MS-ADTS well-known
//! Administrator 500 / krbtgt 502; MIT has no RID concept).

use krb5_types::PrincipalName;
use krb5_types::pac::{PacIdentity, RpcSid};

use super::PrincipalStore;
use super::principal::Principal;
use crate::error::Error;

/// Well-known RID: Administrator.
pub const RID_ADMINISTRATOR: u32 = 500;

/// Well-known RID: krbtgt.
pub const RID_KRBTGT: u32 = 502;

/// First allocated RID for ordinary principals (AD-style).
pub const RID_FIRST_USER: u32 = 1000;

pub(super) fn generate_domain_sid() -> Result<RpcSid, Error> {
    let mut b = [0u8; 12];
    getrandom::getrandom(&mut b).map_err(|_| Error::Rng)?;
    sid_from_random_bytes(&b)
}

pub(super) fn sid_from_random_bytes(b: &[u8; 12]) -> Result<RpcSid, Error> {
    if b.iter().all(|x| *x == 0) {
        return Err(Error::Rng);
    }
    let a = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) | 1;
    let c = u32::from_le_bytes([b[4], b[5], b[6], b[7]]) | 1;
    let d = u32::from_le_bytes([b[8], b[9], b[10], b[11]]) | 1;
    let sid = RpcSid::nt_domain(a, c, d);
    if sid.to_sddl() == RpcSid::dummy_domain().to_sddl() {
        return Err(Error::Rng);
    }
    Ok(sid)
}

impl PrincipalStore {
    /// Realm NT domain SID.
    #[must_use]
    pub fn domain_sid(&self) -> &RpcSid {
        &self.domain_sid
    }

    /// Next RID that would be allocated for an ordinary principal.
    #[must_use]
    pub fn next_rid(&self) -> u32 {
        self.next_rid
    }

    /// Override the realm domain SID (config / dump / persist).
    pub fn set_domain_sid(&mut self, sid: RpcSid) {
        self.domain_sid = sid;
    }

    pub(crate) fn set_principal_rid(&mut self, id: &str, rid: u32) {
        if let Some(p) = self.map.get_mut(id) {
            p.rid = rid;
        }
    }

    pub(crate) fn set_next_rid(&mut self, next: u32) {
        if next >= RID_FIRST_USER {
            self.next_rid = next;
        }
    }

    /// PAC identity for `name` in `crealm` (store RID, or `RID_FIRST_USER` if unknown).
    #[must_use]
    pub fn pac_identity(&self, name: &PrincipalName, crealm: &str) -> PacIdentity {
        let rid = self.get_name(name).map_or(RID_FIRST_USER, |p| {
            if p.rid == 0 { RID_FIRST_USER } else { p.rid }
        });
        PacIdentity {
            sam: name.components_joined(),
            realm: crealm.to_owned(),
            domain_sid: self.domain_sid.clone(),
            rid,
        }
    }

    pub(super) fn settle_rid(&mut self, p: &mut Principal) {
        if p.rid == 0 && p.alias_target().is_none() {
            if p.name.is_krbtgt_for(&self.realm) && p.realm == self.realm {
                p.rid = RID_KRBTGT;
            } else {
                p.rid = self.alloc_rid(&p.name);
            }
        }
        self.bump_next_rid(p.rid);
    }

    fn alloc_rid(&mut self, name: &PrincipalName) -> u32 {
        if name.name_type == PrincipalName::NT_PRINCIPAL
            && name
                .components_joined()
                .eq_ignore_ascii_case("Administrator")
        {
            return RID_ADMINISTRATOR;
        }
        let r = self.next_rid;
        self.next_rid = self.next_rid.saturating_add(1);
        r
    }

    fn bump_next_rid(&mut self, rid: u32) {
        if rid >= RID_FIRST_USER && rid >= self.next_rid {
            self.next_rid = rid.saturating_add(1);
        }
    }
}
