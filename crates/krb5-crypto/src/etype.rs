use crate::error::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyUsage(u32);

impl KeyUsage {
    pub fn new(n: u32) -> Result<Self, Error> {
        if n == 0 {
            return Err(Error::InvalidKeyUsage);
        }
        Ok(Self(n))
    }

    #[must_use]
    pub const fn from_rfc(n: u32) -> Self {
        Self(n)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn derivation_constant(self, suffix: u8) -> [u8; 5] {
        let b = self.0.to_be_bytes();
        [b[0], b[1], b[2], b[3], suffix]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum EncryptionType {
    Des3CbcSha1 = 16,
    Aes128CtsHmacSha196 = 17,
    Aes256CtsHmacSha196 = 18,
    Aes128CtsHmacSha256128 = 19,
    Aes256CtsHmacSha384192 = 20,
    Rc4Hmac = 23,
    Camellia128CtsCmac = 25,
    Camellia256CtsCmac = 26,
}

impl EncryptionType {
    pub fn from_iana(n: i32) -> Result<Self, Error> {
        Self::from_iana_policy(n, false)
    }

    pub fn from_iana_policy(n: i32, allow_weak: bool) -> Result<Self, Error> {
        let e = Self::known(n)?;
        if e.is_weak() && !allow_weak {
            return Err(Error::WeakEtypeRefused(n));
        }
        Ok(e)
    }

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

    // MIT krb5int_c_deprecated_enctype; see docs/parity/b1-crypto-keys.md
    #[must_use]
    pub const fn is_deprecated(self) -> bool {
        matches!(self, Self::Des3CbcSha1 | Self::Rc4Hmac)
    }

    #[must_use]
    pub const fn is_weak(self) -> bool {
        matches!(
            self,
            Self::Des3CbcSha1 | Self::Rc4Hmac | Self::Camellia128CtsCmac | Self::Camellia256CtsCmac
        )
    }

    #[must_use]
    pub const fn to_iana(self) -> i32 {
        self as i32
    }

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

    #[must_use]
    pub const fn keybytes(self) -> usize {
        match self {
            Self::Des3CbcSha1 => 21,
            _ => self.key_len(),
        }
    }

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

    #[must_use]
    pub const fn mac_key_len(self) -> usize {
        match self {
            Self::Aes128CtsHmacSha196 | Self::Aes256CtsHmacSha196 => self.key_len(),
            Self::Aes128CtsHmacSha256128 | Self::Rc4Hmac | Self::Camellia128CtsCmac => 16,
            Self::Aes256CtsHmacSha384192 | Self::Des3CbcSha1 => 24,
            Self::Camellia256CtsCmac => 32,
        }
    }

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

    // MIT default_enctype_list; see docs/parity/b1-crypto-keys.md
    #[must_use]
    pub const fn preferred() -> [Self; 4] {
        [
            Self::Aes256CtsHmacSha196,
            Self::Aes128CtsHmacSha196,
            Self::Aes256CtsHmacSha384192,
            Self::Aes128CtsHmacSha256128,
        ]
    }

    #[must_use]
    pub const fn is_rfc8009(self) -> bool {
        matches!(
            self,
            Self::Aes128CtsHmacSha256128 | Self::Aes256CtsHmacSha384192
        )
    }

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

    #[must_use]
    pub const fn default_iterations(self) -> u32 {
        if self.is_rfc8009() || self.is_camellia() {
            32_768
        } else {
            4_096
        }
    }

    #[must_use]
    pub const fn is_camellia(self) -> bool {
        matches!(self, Self::Camellia128CtsCmac | Self::Camellia256CtsCmac)
    }

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

    // MIT ETYPE_WEAK; see docs/parity/a4-kadmin.md
    #[must_use]
    pub const fn is_mit_weak(self) -> bool {
        false
    }

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

// MIT krb5_c_is_keyed_cksum; see docs/parity/a3-preauth.md
// MIT CKSUM_UNKEYED; see docs/parity/b1-crypto-keys.md
#[must_use]
pub const fn cksumtype_is_keyed(cksumtype: i32) -> bool {
    matches!(cksumtype, 12 | 15 | 16 | 17 | 18 | 19 | 20 | -137 | -138)
}

#[must_use]
pub const fn cksumtype_is_unkeyed(cksumtype: i32) -> bool {
    matches!(cksumtype, 2 | 7 | 9 | 14)
}

// MIT krb5_c_valid_cksumtype; see docs/parity/b1-crypto-keys.md
#[must_use]
pub const fn cksumtype_is_known(cksumtype: i32) -> bool {
    cksumtype_is_keyed(cksumtype) || cksumtype_is_unkeyed(cksumtype)
}

// MIT krb5_c_is_coll_proof_cksum; see docs/parity/b1-crypto-keys.md
#[must_use]
pub const fn cksumtype_is_coll_proof(cksumtype: i32) -> bool {
    cksumtype_is_known(cksumtype)
}

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

// MIT krb5int_parse_enctype_list; see docs/parity/b1-crypto-keys.md
// MIT KRB5_CONFIG_ETYPE_NOSUPP; see docs/parity/b1-crypto-keys.md
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

// MIT krb5_string_to_keysalts; see docs/parity/a4-kadmin.md
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
