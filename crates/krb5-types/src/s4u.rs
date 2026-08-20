//! MS-SFU PA-FOR-USER (S4U2Self).

use rasn::prelude::*;

use crate::{Checksum, PrincipalName, Realm};

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
