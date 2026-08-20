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

/// Encryption types implemented or recognized by this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum EncryptionType {
    /// des3-cbc-sha1 (RFC 3961 etype 16). Weak; see [`Self::is_weak`].
    Des3CbcSha1 = 16,
    /// aes128-cts-hmac-sha1-96 (RFC 3962).
    Aes128CtsHmacSha196 = 17,
    /// aes256-cts-hmac-sha1-96 (RFC 3962).
    Aes256CtsHmacSha196 = 18,
    /// aes128-cts-hmac-sha256-128 (RFC 8009).
    Aes128CtsHmacSha256128 = 19,
    /// aes256-cts-hmac-sha384-192 (RFC 8009).
    Aes256CtsHmacSha384192 = 20,
    /// rc4-hmac (etype 23). Weak; see [`Self::is_weak`].
    Rc4Hmac = 23,
    /// camellia128-cts-cmac (RFC 6803 etype 25). Weak unless locally allowed.
    Camellia128CtsCmac = 25,
    /// camellia256-cts-cmac (RFC 6803 etype 26). Weak unless locally allowed.
    Camellia256CtsCmac = 26,
}

impl EncryptionType {
    /// Parse an IANA etype number. Weak etypes are refused.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedEtype`] or [`Error::WeakEtypeRefused`].
    pub fn from_iana(n: i32) -> Result<Self, Error> {
        Self::from_iana_policy(n, false)
    }

    /// Parse an IANA etype, optionally allowing legacy/AD enctypes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedEtype`] when `n` is unknown, or
    /// [`Error::WeakEtypeRefused`] when it is known-but-disabled.
    pub fn from_iana_policy(n: i32, allow_weak: bool) -> Result<Self, Error> {
        let e = Self::known(n)?;
        if e.is_weak() && !allow_weak {
            return Err(Error::WeakEtypeRefused(n));
        }
        Ok(e)
    }

    /// Recognize an etype without applying the weak-crypto policy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedEtype`] when `n` is not implemented.
    pub fn known(n: i32) -> Result<Self, Error> {
        match n {
            16 => Ok(Self::Des3CbcSha1),
            17 => Ok(Self::Aes128CtsHmacSha196),
            18 => Ok(Self::Aes256CtsHmacSha196),
            19 => Ok(Self::Aes128CtsHmacSha256128),
            20 => Ok(Self::Aes256CtsHmacSha384192),
            23 => Ok(Self::Rc4Hmac),
            25 => Ok(Self::Camellia128CtsCmac),
            26 => Ok(Self::Camellia256CtsCmac),
            other => Err(Error::UnsupportedEtype(other)),
        }
    }

    /// DES3, RC4, and Camellia are behind `allow_weak_crypto`.
    #[must_use]
    pub const fn is_weak(self) -> bool {
        matches!(
            self,
            Self::Des3CbcSha1 | Self::Rc4Hmac | Self::Camellia128CtsCmac | Self::Camellia256CtsCmac
        )
    }

    /// IANA etype number.
    #[must_use]
    pub const fn to_iana(self) -> i32 {
        self as i32
    }

    /// Protocol key length in octets.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128CtsHmacSha196
            | Self::Aes128CtsHmacSha256128
            | Self::Camellia128CtsCmac
            | Self::Rc4Hmac => 16,
            Self::Aes256CtsHmacSha196 | Self::Aes256CtsHmacSha384192 | Self::Camellia256CtsCmac => {
                32
            }
            Self::Des3CbcSha1 => 24,
        }
    }

    /// Truncated HMAC / CMAC length in octets.
    #[must_use]
    pub const fn hmac_output_len(self) -> usize {
        match self {
            Self::Aes128CtsHmacSha196 | Self::Aes256CtsHmacSha196 => 12,
            Self::Aes128CtsHmacSha256128 => 16,
            Self::Aes256CtsHmacSha384192 => 24,
            Self::Des3CbcSha1 => 20,
            Self::Rc4Hmac => 16,
            Self::Camellia128CtsCmac | Self::Camellia256CtsCmac => 16,
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
            Self::Des3CbcSha1 => 24,
            Self::Rc4Hmac => 16,
            Self::Camellia128CtsCmac => 16,
            Self::Camellia256CtsCmac => 32,
        }
    }

    /// Associated keyed checksum type (RFC 3962 / RFC 8009 / RFC 4757).
    #[must_use]
    pub const fn checksum_type(self) -> i32 {
        match self {
            Self::Aes128CtsHmacSha196 => 15,
            Self::Aes256CtsHmacSha196 => 16,
            Self::Aes128CtsHmacSha256128 => 19,
            Self::Aes256CtsHmacSha384192 => 20,
            Self::Des3CbcSha1 => 12,
            Self::Rc4Hmac => -138,
            Self::Camellia128CtsCmac => 17,
            Self::Camellia256CtsCmac => 18,
        }
    }

    /// Preference order for AS/TGS etype lists (strongest first).
    #[must_use]
    pub const fn preferred() -> [Self; 4] {
        [
            Self::Aes256CtsHmacSha384192,
            Self::Aes128CtsHmacSha256128,
            Self::Aes256CtsHmacSha196,
            Self::Aes128CtsHmacSha196,
        ]
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

    /// AES-CTS etypes 17–20.
    #[must_use]
    pub const fn is_aes(self) -> bool {
        matches!(
            self,
            Self::Aes128CtsHmacSha196
                | Self::Aes256CtsHmacSha196
                | Self::Aes128CtsHmacSha256128
                | Self::Aes256CtsHmacSha384192
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
            Self::Aes128CtsHmacSha196
            | Self::Aes256CtsHmacSha196
            | Self::Des3CbcSha1
            | Self::Rc4Hmac
            | Self::Camellia128CtsCmac
            | Self::Camellia256CtsCmac => None,
        }
    }
}
