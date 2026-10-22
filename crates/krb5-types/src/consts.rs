#![allow(clippy::disallowed_methods)]

use crate::{KerberosString, PrincipalName};

#[must_use]
pub fn ascii(s: &str) -> KerberosString {
    crate::ascii(s)
}

#[must_use]
pub fn principal(
    name_type: i32,
    parts: impl IntoIterator<Item = impl AsRef<str>>,
) -> PrincipalName {
    PrincipalName::new(name_type, parts)
}

#[must_use]
pub fn krbtgt(realm: &str) -> PrincipalName {
    PrincipalName::krbtgt(realm)
}
