use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    UnsupportedEtype(i32),
    WeakEtypeRefused(i32),
    InvalidKeyLength,
    InvalidKeyUsage,
    InvalidParams,
    InvalidConfounder,
    CiphertextTooShort,
    Integrity,
    UnsupportedChecksum(i32),
    BadChecksumSize,
    InappChecksum,
    Rng,
    // MIT: `KRB5_ERR_BAD_S2K_PARAMS` (lib/krb5/error_tables/krb5_err.et:337-337)
    BadS2kParams,
    // MIT: `krb5_k_decrypt` (lib/crypto/krb/decrypt.c:30-85)
    // MIT: `KRB5_BAD_ENCTYPE` (lib/krb5/error_tables/krb5_err.et:254-254)
    BadEnctype(i32),
    // MIT: `mit_des3_key_sched` (lib/crypto/builtin/des/d3_kysched.c:29-53)
    // MIT: `validate_and_schedule` (lib/crypto/builtin/enc_provider/des3.c:33-53)
    // MIT: `KRB5DES_BAD_KEYPAR` (lib/krb5/error_tables/krb5_err.et:251-251)
    DesBadParity,
    // MIT: `KRB5DES_WEAK_KEY` (lib/krb5/error_tables/krb5_err.et:252-252)
    DesWeakKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedEtype(n) => write!(f, "unsupported encryption type {n}"),
            Self::WeakEtypeRefused(n) => {
                write!(
                    f,
                    "encryption type {n} is known but refused (allow_weak_crypto is false)"
                )
            }
            Self::InvalidKeyLength => write!(f, "protocol key length does not match etype"),
            Self::InvalidKeyUsage => write!(f, "key usage 0 is not permitted (RFC 3961)"),
            Self::InvalidParams => write!(f, "invalid string-to-key parameters"),
            Self::InvalidConfounder => write!(f, "confounder must be 16 octets"),
            Self::CiphertextTooShort => write!(f, "ciphertext too short"),
            Self::Integrity => write!(f, "integrity check failed"),
            Self::UnsupportedChecksum(n) => write!(f, "unsupported checksum type {n}"),
            Self::BadChecksumSize => write!(f, "checksum length does not match output size"),
            Self::InappChecksum => write!(f, "inappropriate checksum type"),
            Self::Rng => write!(f, "failed to generate random confounder"),
            Self::BadS2kParams => write!(f, "Invalid key generation parameters from KDC"),
            Self::BadEnctype(_) => write!(f, "Bad encryption type"),
            Self::DesBadParity => write!(f, "DES key has bad parity"),
            Self::DesWeakKey => write!(f, "DES key is a weak key"),
        }
    }
}

impl std::error::Error for Error {}
