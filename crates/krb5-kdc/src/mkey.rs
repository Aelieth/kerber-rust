//! Master-key recovery for MIT KDB dump/load. `K/M@REALM` is derived from the master password with the RFC 4120 default salt of that principal (`REALM` ‖ `"KM"`) and the etype default s2kparams; its enctype is kdc.conf `master_key_type`, else MIT's `DEFAULT_KDC_ENCTYPE`.

use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_types::PrincipalName;

use crate::error::Error;

/// MIT master principal name components (`K/M`).
pub(crate) const MASTER_NAME: [&str; 2] = ["K", "M"];

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

// MIT: `DEFAULT_KDC_ENCTYPE` (osconf.hin:90-90)
/// aes256-cts-hmac-sha1-96 when kdc.conf sets no `master_key_type`.
#[must_use]
pub fn default_master_etype() -> EncryptionType {
    EncryptionType::Aes256CtsHmacSha196
}

// MIT: `kadm5_get_config_params` (alt_prof.c:541-555)
/// the profile's `master_key_type`, else `DEFAULT_KDC_ENCTYPE`; a name that is no enctype leaves none, and no master key is made.
/// `<name>: <why>` when `master_key_type` names no enctype this port supports.
pub fn master_etype(master_key_type: Option<&str>) -> Result<EncryptionType, String> {
    master_key_type.map_or(Ok(default_master_etype()), string_to_enctype)
}

// MIT: `krb5_string_to_enctype` (lib/crypto/krb/enctype_util.c:89-114)
/// an enctype's name or alias, compared without case; a number is no name.
/// `<name>: <why>` when `name` is a number, has blanks around it, or names no enctype this port supports.
pub fn string_to_enctype(name: &str) -> Result<EncryptionType, String> {
    if name.trim() != name || name.parse::<i64>().is_ok() {
        return Err(format!("{name}: not an enctype name"));
    }
    EncryptionType::from_mit_name(name).map_err(|e| format!("{name}: {e}"))
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
