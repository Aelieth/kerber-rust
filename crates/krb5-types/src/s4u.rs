//! MS-SFU PA-FOR-USER (S4U2Self) and MS-KILE PA-PAC-OPTIONS.

use rasn::prelude::*;

use crate::{Checksum, KerberosFlags, PrincipalName, Realm};

/// MS-KILE PA-PAC-OPTIONS flags bit: resource-based constrained delegation.
pub const PAC_OPTIONS_RBCD: usize = 3;

/// PA-FOR-USER ::= SEQUENCE { userName, userRealm, cksum, auth-package }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaForUser {
    /// Impersonated user.
    #[rasn(tag(explicit(0)))]
    pub user_name: PrincipalName,
    /// Impersonated realm.
    #[rasn(tag(explicit(1)))]
    pub user_realm: Realm,
    /// Checksum over the name encoding (key usage 17).
    #[rasn(tag(explicit(2)))]
    pub cksum: Checksum,
    /// Auth package, typically `Kerberos`.
    #[rasn(tag(explicit(3)))]
    pub auth_package: crate::KerberosString,
}

/// Bytes checksummed for PA-FOR-USER (MIT/MS-SFU layout).
#[must_use]
pub fn pa_for_user_cksum_data(user: &PrincipalName, realm: &str, package: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&user.name_type.to_le_bytes());
    for p in &user.name_string {
        v.extend_from_slice(p.as_bytes());
    }
    v.extend_from_slice(realm.as_bytes());
    v.extend_from_slice(package.as_bytes());
    v
}

/// MS-KILE `PA-PAC-OPTIONS` (padata 167).
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaPacOptions {
    /// KerberosFlags: claims(0), branch(1), forward-to-full-DC(2), RBCD(3).
    #[rasn(tag(explicit(0)))]
    pub flags: KerberosFlags,
}

impl PaPacOptions {
    /// Flags with only the RBCD bit set.
    #[must_use]
    pub fn rbcd() -> Self {
        let mut flags = KerberosFlags::repeat(false, 32);
        if PAC_OPTIONS_RBCD < flags.len() {
            flags.set(PAC_OPTIONS_RBCD, true);
        }
        Self { flags }
    }

    /// Whether resource-based constrained delegation (bit 3) is set.
    #[must_use]
    pub fn resource_based_constrained_delegation(&self) -> bool {
        PAC_OPTIONS_RBCD < self.flags.len() && self.flags[PAC_OPTIONS_RBCD]
    }
}
