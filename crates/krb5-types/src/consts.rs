//! Static GeneralString text. This module may call the infallible constructors.
#![allow(clippy::disallowed_methods)]

use crate::{KerberosString, PrincipalName};

/// [`crate::ascii`] for text already known to be GeneralString.
#[must_use]
pub fn ascii(s: &str) -> KerberosString {
    crate::ascii(s)
}

/// [`PrincipalName::new`] for components already known to be GeneralString.
#[must_use]
pub fn principal(
    name_type: i32,
    parts: impl IntoIterator<Item = impl AsRef<str>>,
) -> PrincipalName {
    PrincipalName::new(name_type, parts)
}

/// [`PrincipalName::krbtgt`] for a realm already known to be GeneralString.
#[must_use]
pub fn krbtgt(realm: &str) -> PrincipalName {
    PrincipalName::krbtgt(realm)
}
