//! Error type for RFC 3961 operations.

use std::fmt;

/// Failure from a crypto operation. Integrity failures do not distinguish
/// "wrong key" from "truncated" beyond the variant, and never include the
/// raw MAC bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// IANA etype number is not implemented.
    UnsupportedEtype(i32),
    /// Etype is known (legacy/AD) but refused because `allow_weak_crypto` is off.
    WeakEtypeRefused(i32),
    /// Protocol key length does not match the etype.
    InvalidKeyLength,
    /// RFC 3961 forbids key usage 0.
    InvalidKeyUsage,
    /// String-to-key params are the wrong length, or the iteration count is
    /// zero (RFC 3962 maps 0 to 2^32; this implementation refuses that DoS).
    InvalidParams,
    /// Confounder is not one AES block (16 octets).
    InvalidConfounder,
    /// Ciphertext shorter than confounder + truncated HMAC.
    CiphertextTooShort,
    /// HMAC did not match; ciphertext is discarded.
    Integrity,
    /// Operating-system CSPRNG failed while generating a confounder.
    Rng,
    /// PBKDF2 iteration count exceeds the local resource limit.
    IterationLimit,
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
            Self::Rng => write!(f, "failed to generate random confounder"),
            Self::IterationLimit => write!(f, "PBKDF2 iteration count exceeds local limit"),
        }
    }
}

impl std::error::Error for Error {}
