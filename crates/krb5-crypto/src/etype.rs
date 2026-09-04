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

    /// RFC usage number without the [`Self::new`] zero check.
    ///
    /// Protocol encrypt/decrypt must use [`Self::new`]. MIT KDB
    /// `krb5_dbe_def_encrypt_key_data` is the documented exception that
    /// uses usage 0 (`from_rfc(0)` via `kdb_encrypt_key` /
    /// `kdb_decrypt_key`).
    #[must_use]
    pub const fn from_rfc(n: u32) -> Self {
        Self(n)
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
            Self::Aes128CtsHmacSha256128
            | Self::Rc4Hmac
            | Self::Camellia128CtsCmac
            | Self::Camellia256CtsCmac => 16,
            Self::Aes256CtsHmacSha384192 => 24,
            Self::Des3CbcSha1 => 20,
        }
    }

    /// RFC 8009 checksum key (`Kc`) / integrity key (`Ki`) length. Equal to
    /// [`Self::key_len`] for RFC 3962 etypes.
    #[must_use]
    pub const fn mac_key_len(self) -> usize {
        match self {
            Self::Aes128CtsHmacSha196 | Self::Aes256CtsHmacSha196 => self.key_len(),
            Self::Aes128CtsHmacSha256128 | Self::Rc4Hmac | Self::Camellia128CtsCmac => 16,
            Self::Aes256CtsHmacSha384192 | Self::Des3CbcSha1 => 24,
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
            Self::Aes256CtsHmacSha196,
            Self::Aes128CtsHmacSha196,
            Self::Aes256CtsHmacSha384192,
            Self::Aes128CtsHmacSha256128,
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
        if self.is_rfc8009() || self.is_camellia() {
            32_768
        } else {
            4_096
        }
    }

    /// RFC 6803 Camellia-CTS-CMAC.
    #[must_use]
    pub const fn is_camellia(self) -> bool {
        matches!(self, Self::Camellia128CtsCmac | Self::Camellia256CtsCmac)
    }

    /// MIT `klist -e` / `kdc.conf` enctype name.
    #[must_use]
    pub const fn to_mit_name(self) -> &'static str {
        match self {
            Self::Aes128CtsHmacSha196 => "aes128-cts-hmac-sha1-96",
            Self::Aes256CtsHmacSha196 => "aes256-cts-hmac-sha1-96",
            Self::Aes128CtsHmacSha256128 => "aes128-cts-hmac-sha256-128",
            Self::Aes256CtsHmacSha384192 => "aes256-cts-hmac-sha384-192",
            Self::Des3CbcSha1 => "des3-cbc-sha1",
            Self::Rc4Hmac => "arcfour-hmac",
            Self::Camellia128CtsCmac => "camellia128-cts-cmac",
            Self::Camellia256CtsCmac => "camellia256-cts-cmac",
        }
    }

    /// MIT `enctype` name as used in `kdc.conf` (`aes256-cts-hmac-sha384-192`).
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedEtype`] when `name` is not an implemented etype.
    pub fn from_mit_name(name: &str) -> Result<Self, Error> {
        let n = name.trim();
        if let Ok(num) = n.parse::<i32>() {
            return Self::known(num);
        }
        match n.to_ascii_lowercase().as_str() {
            "aes128-cts-hmac-sha1-96" | "aes128-cts" | "aes128-sha1" => {
                Ok(Self::Aes128CtsHmacSha196)
            }
            "aes256-cts-hmac-sha1-96" | "aes256-cts" | "aes256-sha1" => {
                Ok(Self::Aes256CtsHmacSha196)
            }
            "aes128-cts-hmac-sha256-128" | "aes128-sha2" => Ok(Self::Aes128CtsHmacSha256128),
            "aes256-cts-hmac-sha384-192" | "aes256-sha2" => Ok(Self::Aes256CtsHmacSha384192),
            "des3-cbc-sha1" | "des3-cbc-sha1-kd" | "des3-hmac-sha1" => Ok(Self::Des3CbcSha1),
            "arcfour-hmac" | "rc4-hmac" | "arcfour-hmac-md5" => Ok(Self::Rc4Hmac),
            "camellia128-cts-cmac" | "camellia128-cts" => Ok(Self::Camellia128CtsCmac),
            "camellia256-cts-cmac" | "camellia256-cts" => Ok(Self::Camellia256CtsCmac),
            _ => Err(Error::UnsupportedEtype(0)),
        }
    }

    /// MIT `etype.c` `ETYPE_WEAK`. None of the implemented types set that flag.
    #[must_use]
    pub const fn is_mit_weak(self) -> bool {
        false
    }

    /// RFC 8009 / RFC 6803 `enctype-name` prepended to the salt, or `None`
    /// for RFC 3962 AES-SHA-1.
    #[must_use]
    pub const fn enctype_name(self) -> Option<&'static str> {
        match self {
            Self::Aes128CtsHmacSha256128 => Some("aes128-cts-hmac-sha256-128"),
            Self::Aes256CtsHmacSha384192 => Some("aes256-cts-hmac-sha384-192"),
            Self::Camellia128CtsCmac => Some("camellia128-cts-cmac"),
            Self::Camellia256CtsCmac => Some("camellia256-cts-cmac"),
            Self::Aes128CtsHmacSha196
            | Self::Aes256CtsHmacSha196
            | Self::Des3CbcSha1
            | Self::Rc4Hmac => None,
        }
    }
}

/// MIT `krb5_c_is_keyed_cksum`: types in `cksumtypes.c` without `CKSUM_UNKEYED`.
#[must_use]
pub const fn cksumtype_is_keyed(cksumtype: i32) -> bool {
    matches!(cksumtype, 12 | 15 | 16 | 17 | 18 | 19 | 20 | -137 | -138)
}

/// MIT `cksumtypes.c` unkeyed types (`CKSUM_UNKEYED`).
#[must_use]
pub const fn cksumtype_is_unkeyed(cksumtype: i32) -> bool {
    // MIT cksumtypes.c: MD4 2 / MD5 7 / NIST-SHA 9 / SHA1 14. CRC32 (1) has no entry.
    matches!(cksumtype, 2 | 7 | 9 | 14)
}

/// MIT `krb5_c_valid_cksumtype`: a row in `cksumtypes.c`.
#[must_use]
pub const fn cksumtype_is_known(cksumtype: i32) -> bool {
    cksumtype_is_keyed(cksumtype) || cksumtype_is_unkeyed(cksumtype)
}

/// MIT `krb5_c_is_coll_proof_cksum` (`coll_proof_cksum.c:30-40`).
///
/// 1.22.2 sets `CKSUM_NOT_COLL_PROOF` on no table row, so every known
/// type is collision-proof.
#[must_use]
pub const fn cksumtype_is_coll_proof(cksumtype: i32) -> bool {
    cksumtype_is_known(cksumtype)
}

/// MIT `default_enctype_list` (`init_ctx.c:59-66`).
#[must_use]
pub const fn default_enctype_list() -> [EncryptionType; 8] {
    [
        EncryptionType::Aes256CtsHmacSha196,
        EncryptionType::Aes128CtsHmacSha196,
        EncryptionType::Aes256CtsHmacSha384192,
        EncryptionType::Aes128CtsHmacSha256128,
        EncryptionType::Des3CbcSha1,
        EncryptionType::Rc4Hmac,
        EncryptionType::Camellia128CtsCmac,
        EncryptionType::Camellia256CtsCmac,
    ]
}

/// MIT `krb5int_parse_enctype_list`. Empty result is `None` (`KRB5_CONFIG_ETYPE_NOSUPP`).
#[must_use]
pub fn parse_enctype_list(profstr: &str, allow_weak: bool) -> Option<Vec<EncryptionType>> {
    let mut list = Vec::new();
    for token in profstr.split(|c: char| c.is_ascii_whitespace() || c == ',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let (add, rest) = if let Some(r) = token.strip_prefix('+') {
            (true, r)
        } else if let Some(r) = token.strip_prefix('-') {
            (false, r)
        } else {
            (true, token)
        };
        let key = rest.to_ascii_lowercase();
        let family: Vec<EncryptionType> = match key.as_str() {
            "default" => default_enctype_list().into_iter().collect(),
            "des3" => vec![EncryptionType::Des3CbcSha1],
            "aes" => vec![
                EncryptionType::Aes256CtsHmacSha196,
                EncryptionType::Aes128CtsHmacSha196,
                EncryptionType::Aes256CtsHmacSha384192,
                EncryptionType::Aes128CtsHmacSha256128,
            ],
            "rc4" => vec![EncryptionType::Rc4Hmac],
            "camellia" => vec![
                EncryptionType::Camellia256CtsCmac,
                EncryptionType::Camellia128CtsCmac,
            ],
            _ => match EncryptionType::from_mit_name(&key) {
                Ok(e) => vec![e],
                Err(_) => continue,
            },
        };
        for e in family {
            if !allow_weak && e.is_mit_weak() {
                continue;
            }
            if add {
                if !list.contains(&e) {
                    list.push(e);
                }
            } else {
                list.retain(|x| *x != e);
            }
        }
    }
    if list.is_empty() { None } else { Some(list) }
}

/// MIT keysalt list (`aes256-cts:normal rc4-hmac:normal`). Unknown tokens are skipped.
#[must_use]
pub fn parse_keysalt_list(s: &str) -> Vec<EncryptionType> {
    let mut out = Vec::new();
    for tok in s.split(|c: char| c.is_ascii_whitespace() || c == ',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        let et = tok.split_once(':').map_or(tok, |(e, _)| e);
        if let Ok(e) = EncryptionType::from_mit_name(et)
            && !out.contains(&e)
        {
            out.push(e);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_enctype_list_families_and_minus() {
        let v = parse_enctype_list("aes -aes256-cts rc4-hmac", false).unwrap();
        assert_eq!(
            v,
            vec![
                EncryptionType::Aes128CtsHmacSha196,
                EncryptionType::Aes256CtsHmacSha384192,
                EncryptionType::Aes128CtsHmacSha256128,
                EncryptionType::Rc4Hmac,
            ]
        );
        assert!(parse_enctype_list("nosuch", false).is_none());
        assert!(
            parse_enctype_list("DEFAULT", false)
                .unwrap()
                .contains(&EncryptionType::Rc4Hmac)
        );
        assert_eq!(
            parse_enctype_list("aes128-sha1,AES256-CTS", false).unwrap(),
            vec![
                EncryptionType::Aes128CtsHmacSha196,
                EncryptionType::Aes256CtsHmacSha196,
            ]
        );
    }

    #[test]
    fn parse_keysalt_list_strips_salt() {
        let v = parse_keysalt_list("aes256-cts-hmac-sha384-192:normal rc4-hmac:normal");
        assert_eq!(
            v,
            vec![
                EncryptionType::Aes256CtsHmacSha384192,
                EncryptionType::Rc4Hmac,
            ]
        );
    }
}
