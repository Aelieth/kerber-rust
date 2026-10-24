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
    IterationLimit,
    // MIT krb5_k_decrypt; see docs/parity/b1-client.md
    // MIT KRB5_BAD_ENCTYPE; see docs/parity/b1-client.md
    BadEnctype(i32),
    // MIT mit_des3_key_sched; see docs/parity/b1-crypto-keys.md
    // MIT validate_and_schedule; see docs/parity/b1-crypto-keys.md
    // MIT KRB5DES_BAD_KEYPAR; see docs/parity/b1-crypto-keys.md
    DesBadParity,
    // MIT KRB5DES_WEAK_KEY; see docs/parity/b1-crypto-keys.md
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
            Self::IterationLimit => write!(f, "PBKDF2 iteration count exceeds local limit"),
            Self::BadEnctype(_) => write!(f, "Bad encryption type"),
            Self::DesBadParity => write!(f, "DES key has bad parity"),
            Self::DesWeakKey => write!(f, "DES key is a weak key"),
        }
    }
}

impl std::error::Error for Error {}
