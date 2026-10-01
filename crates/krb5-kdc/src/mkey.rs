//! Master-key recovery for MIT KDB dump/load.
//!
//! The master key `K/M@REALM` is derived from the master password with the RFC 4120 default
//! salt of that principal (`REALM` ‖ `"KM"`) and the etype default s2kparams. Its enctype is
//! kdc.conf's `master_key_type`, else MIT's `DEFAULT_KDC_ENCTYPE`.

use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_types::PrincipalName;

use crate::error::Error;

/// MIT master principal name components (`K/M`).
pub(crate) const MASTER_NAME: [&str; 2] = ["K", "M"];

/// Derive the KDB master key from `password` for `realm`.
///
/// # Errors
///
/// [`Error::Crypto`] when [`string_to_key`] cannot derive a key for `etype` from `password`.
pub fn master_key_from_password(
    realm: &str,
    password: impl AsRef<[u8]>,
    etype: EncryptionType,
) -> Result<ProtocolKey, Error> {
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, MASTER_NAME);
    let salt = name.default_salt(realm);
    string_to_key(etype, password, &salt, None).map_err(Error::from)
}

/// The master key type of a realm whose kdc.conf sets no `master_key_type`.
/// MIT `DEFAULT_KDC_ENCTYPE` (`osconf.hin:90-90`): aes256-cts-hmac-sha1-96.
#[must_use]
pub fn default_master_etype() -> EncryptionType {
    EncryptionType::Aes256CtsHmacSha196
}

/// The master key type `master_key_type` names, else [`default_master_etype`]. Every tool takes
/// the name from [`krb5_config::KdcPaths::master_key_type`]: `KRB5_MASTER_ETYPE`, else the
/// realm's kdc.conf `master_key_type`.
/// MIT `kadm5_get_config_params` (`alt_prof.c:541-555`): the profile's `master_key_type`, else
/// `DEFAULT_KDC_ENCTYPE`; a name that is no enctype leaves none, and no master key is made.
///
/// # Errors
///
/// `<name>: <why>` when `master_key_type` names no enctype this port supports.
pub fn master_etype(master_key_type: Option<&str>) -> Result<EncryptionType, String> {
    master_key_type.map_or(Ok(default_master_etype()), |name| {
        EncryptionType::from_mit_name(name).map_err(|e| format!("{name}: {e}"))
    })
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
