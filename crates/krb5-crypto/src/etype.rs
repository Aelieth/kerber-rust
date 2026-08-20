//! IANA Kerberos encryption-type numbers implemented in this crate.

use crate::error::Error;

/// RFC 4120 key-usage number. Zero is rejected at construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyUsage(u32);

impl KeyUsage {
    /// Construct a usage. RFC 3961 section 2: zero is not permitted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKeyUsage`] when `n` is 0.
    pub fn new(n: u32) -> Result<Self, Error> {
        if n == 0 {
            return Err(Error::InvalidKeyUsage);
        }
        Ok(Self(n))
    }

    /// Numeric usage value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Five-octet DK/KDF constant: usage as big-endian u32 plus a suffix byte
    /// (`0x99` Kc, `0xAA` Ke, `0x55` Ki).
    #[must_use]
    pub fn derivation_constant(self, suffix: u8) -> [u8; 5] {
        let b = self.0.to_be_bytes();
        [b[0], b[1], b[2], b[3], suffix]
    }
}

/// Encryption types 17–20 (AES-CTS with HMAC-SHA-1 or HMAC-SHA-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum EncryptionType {
    /// aes128-cts-hmac-sha1-96 (RFC 3962).
    Aes128CtsHmacSha196 = 17,
    /// aes256-cts-hmac-sha1-96 (RFC 3962).
    Aes256CtsHmacSha196 = 18,
    /// aes128-cts-hmac-sha256-128 (RFC 8009).
    Aes128CtsHmacSha256128 = 19,
    /// aes256-cts-hmac-sha384-192 (RFC 8009).
    Aes256CtsHmacSha384192 = 20,
}

impl EncryptionType {
    /// Parse an IANA etype number.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedEtype`] when `n` is not 17–20.
    pub fn from_iana(n: i32) -> Result<Self, Error> {
        match n {
            17 => Ok(Self::Aes128CtsHmacSha196),
            18 => Ok(Self::Aes256CtsHmacSha196),
            19 => Ok(Self::Aes128CtsHmacSha256128),
            20 => Ok(Self::Aes256CtsHmacSha384192),
            other => Err(Error::UnsupportedEtype(other)),
        }
    }

    /// IANA etype number.
    #[must_use]
    pub const fn to_iana(self) -> i32 {
        self as i32
    }

    /// AES key length in octets (16 or 32).
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128CtsHmacSha196 | Self::Aes128CtsHmacSha256128 => 16,
            Self::Aes256CtsHmacSha196 | Self::Aes256CtsHmacSha384192 => 32,
        }
    }

    /// Truncated HMAC length in octets.
    #[must_use]
    pub const fn hmac_output_len(self) -> usize {
        match self {
            Self::Aes128CtsHmacSha196 | Self::Aes256CtsHmacSha196 => 12,
            Self::Aes128CtsHmacSha256128 => 16,
            Self::Aes256CtsHmacSha384192 => 24,
        }
    }

    /// RFC 8009 checksum key (`Kc`) / integrity key (`Ki`) length. Equal to
    /// [`Self::key_len`] for RFC 3962 etypes.
    #[must_use]
    pub const fn mac_key_len(self) -> usize {
        match self {
            Self::Aes128CtsHmacSha196 | Self::Aes256CtsHmacSha196 => self.key_len(),
            Self::Aes128CtsHmacSha256128 => 16,
            Self::Aes256CtsHmacSha384192 => 24,
        }
    }

    /// Whether this etype uses the RFC 8009 profile (HMAC over IV||ciphertext)
    /// rather than the RFC 3961 simplified profile.
    #[must_use]
    pub const fn is_rfc8009(self) -> bool {
        matches!(
            self,
            Self::Aes128CtsHmacSha256128 | Self::Aes256CtsHmacSha384192
        )
    }

    /// Default PBKDF2 iteration count when string-to-key params are omitted.
    #[must_use]
    pub const fn default_iterations(self) -> u32 {
        if self.is_rfc8009() {
            32_768
        } else {
            4_096
        }
    }

    /// RFC 8009 `enctype-name` prepended to the salt, or `None` for RFC 3962.
    #[must_use]
    pub const fn enctype_name(self) -> Option<&'static str> {
        match self {
            Self::Aes128CtsHmacSha256128 => Some("aes128-cts-hmac-sha256-128"),
            Self::Aes256CtsHmacSha384192 => Some("aes256-cts-hmac-sha384-192"),
            Self::Aes128CtsHmacSha196 | Self::Aes256CtsHmacSha196 => None,
        }
    }
}
