use rasn::prelude::*;

use crate::{Checksum, KerberosFlags, OctetString, PrincipalName, Realm};

pub const S4U_OPTS_USE_REPLY_KEY_USAGE: usize = 2;

pub const PAC_OPTIONS_RBCD: usize = 3;

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaForUser {
    #[rasn(tag(explicit(0)))]
    pub user_name: PrincipalName,
    #[rasn(tag(explicit(1)))]
    pub user_realm: Realm,
    #[rasn(tag(explicit(2)))]
    pub cksum: Checksum,
    #[rasn(tag(explicit(3)))]
    pub auth_package: crate::KerberosString,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct S4uUserId {
    #[rasn(tag(explicit(0)))]
    pub nonce: i32,
    #[rasn(tag(explicit(1)))]
    pub user: Option<PrincipalName>,
    #[rasn(tag(explicit(2)))]
    pub realm: Realm,
    #[rasn(tag(explicit(3)))]
    pub subject_cert: Option<OctetString>,
    #[rasn(tag(explicit(4)))]
    pub options: Option<KerberosFlags>,
}

impl S4uUserId {
    #[must_use]
    pub fn use_reply_key_usage(&self) -> bool {
        self.options.as_ref().is_some_and(|f| {
            S4U_OPTS_USE_REPLY_KEY_USAGE < f.len() && f[S4U_OPTS_USE_REPLY_KEY_USAGE]
        })
    }
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaS4uX509User {
    #[rasn(tag(explicit(0)))]
    pub user_id: S4uUserId,
    #[rasn(tag(explicit(1)))]
    pub cksum: Checksum,
}

#[must_use]
pub fn s4u_reply_key_usage_flags() -> KerberosFlags {
    let mut flags = KerberosFlags::repeat(false, 32);
    if S4U_OPTS_USE_REPLY_KEY_USAGE < flags.len() {
        flags.set(S4U_OPTS_USE_REPLY_KEY_USAGE, true);
    }
    flags
}

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

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaPacOptions {
    #[rasn(tag(explicit(0)))]
    pub flags: KerberosFlags,
}

impl PaPacOptions {
    #[must_use]
    pub fn rbcd() -> Self {
        let mut flags = KerberosFlags::repeat(false, 32);
        if PAC_OPTIONS_RBCD < flags.len() {
            flags.set(PAC_OPTIONS_RBCD, true);
        }
        Self { flags }
    }

    #[must_use]
    pub fn resource_based_constrained_delegation(&self) -> bool {
        PAC_OPTIONS_RBCD < self.flags.len() && self.flags[PAC_OPTIONS_RBCD]
    }
}
