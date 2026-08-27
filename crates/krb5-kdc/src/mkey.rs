//! Master-key recovery for MIT KDB dump/load.
//!
//! First cut derives `K/M@REALM` from the master password. The salt is the
//! RFC 4120 default salt of that principal (`REALM` ‖ `"KM"`). The harness
//! `master_key_type` is etype 20 (`aes256-cts-hmac-sha384-192`); s2kparams
//! are the etype default (32768). Stash `.k5.REALM` parsing is later.

use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_types::PrincipalName;

use crate::error::Error;

/// MIT master principal name components (`K/M`).
pub const MASTER_NAME: [&str; 2] = ["K", "M"];

/// Derive the KDB master key from `password` for `realm`.
///
/// # Errors
///
/// String-to-key failures from [`string_to_key`].
pub fn master_key_from_password(
    realm: &str,
    password: impl AsRef<[u8]>,
    etype: EncryptionType,
) -> Result<ProtocolKey, Error> {
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, MASTER_NAME);
    let salt = name.default_salt(realm);
    string_to_key(etype, password, &salt, None).map_err(Error::from)
}

/// Documented harness master-key etype (`aes256-cts-hmac-sha384-192`).
#[must_use]
pub fn harness_master_etype() -> EncryptionType {
    EncryptionType::Aes256CtsHmacSha384192
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_is_realm_km() {
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, MASTER_NAME);
        assert_eq!(name.default_salt("KERBER.TEST"), b"KERBER.TESTKM");
    }
}
