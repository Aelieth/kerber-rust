use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_types::PrincipalName;

use crate::error::Error;

pub(crate) const MASTER_NAME: [&str; 2] = ["K", "M"];

/// Salt: the realm, then KM.
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
#[must_use]
pub fn default_master_etype() -> EncryptionType {
    EncryptionType::Aes256CtsHmacSha196
}

// MIT: `kadm5_get_config_params` (alt_prof.c:541-555)
pub fn master_etype(master_key_type: Option<&str>) -> Result<EncryptionType, String> {
    master_key_type.map_or(Ok(default_master_etype()), string_to_enctype)
}

// MIT: `krb5_string_to_enctype` (lib/crypto/krb/enctype_util.c:89-114)
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
