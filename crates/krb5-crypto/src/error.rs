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
    /// Claimed cksumtype is not in MIT `cksumtypes.c`.
    UnsupportedChecksum(i32),
    /// `cksum->length != output_size` (`verify_checksum.c` `KRB5_BAD_MSIZE`).
    BadChecksumSize,
    /// Not keyed / not collision-proof (`rd_safe.c` / `kdc_util.c` `INAPP_CKSUM`).
    InappChecksum,
    /// Operating-system CSPRNG failed while generating a confounder.
    Rng,
    /// PBKDF2 iteration count exceeds the local resource limit.
    IterationLimit,
    /// An EncryptedData's enctype (the value given) is not the key's.
    /// MIT `krb5_k_decrypt` (`lib/crypto/krb/decrypt.c:45-46`): `KRB5_BAD_ENCTYPE`, before anything is decrypted.
    BadEnctype(i32),
    /// A des3 key with an octet of even parity.
    /// MIT `mit_des3_key_sched` (`lib/crypto/builtin/des/d3_kysched.c:29-53`): the parity of each DES key is checked first, and an octet of even parity gives `-1`.
    /// MIT `validate_and_schedule` (`lib/crypto/builtin/enc_provider/des3.c:33-53`): that `-1` is `KRB5DES_BAD_KEYPAR`, returned to every encryption, decryption and derivation under the key.
    DesBadParity,
    /// A des3 key with a weak or semi-weak DES key among its three.
    /// MIT `mit_des3_key_sched` (`lib/crypto/builtin/des/d3_kysched.c:29-53`): the weakness of each DES key is checked after its parity, and a weak key gives `-2`.
    /// MIT `validate_and_schedule` (`lib/crypto/builtin/enc_provider/des3.c:33-53`): that `-2` is `KRB5DES_WEAK_KEY`.
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
            // MIT `KRB5_BAD_ENCTYPE` (`krb5_err.et:254-254`): the text.
            Self::BadEnctype(_) => write!(f, "Bad encryption type"),
            // MIT `KRB5DES_BAD_KEYPAR` (`krb5_err.et:251-251`): the text.
            Self::DesBadParity => write!(f, "DES key has bad parity"),
            // MIT `KRB5DES_WEAK_KEY` (`krb5_err.et:252-252`): the text.
            Self::DesWeakKey => write!(f, "DES key is a weak key"),
        }
    }
}

impl std::error::Error for Error {}
