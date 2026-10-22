//! ```
//! use krb5_types::PrincipalName;
//! let name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "REALM"]);
//! assert_eq!(name.components_joined(), "krbtgt/REALM");
//! ```
//! ```
//! use krb5_types::PrincipalName;
//! let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
//! assert_eq!(name.unparse_with_realm("REALM"), "user@REALM");
//! ```
//! ```
//! use krb5_types::deltat::parse;
//! let secs = parse("1h")?;
//! assert_eq!(secs, 3600);
//! Ok::<(), krb5_types::deltat::DeltatError>(())
//! ```
//! ```
//! use krb5_types::deltat::parse;
//! let secs = parse("3d")?;
//! assert_eq!(secs, 3 * 24 * 3600);
//! Ok::<(), krb5_types::deltat::DeltatError>(())
//! ```
//! ```
//! use krb5_types::deltat::parse;
//! let secs = parse("42")?;
//! assert_eq!(secs, 42);
//! Ok::<(), krb5_types::deltat::DeltatError>(())
//! ```
//! ```
//! use krb5_types::KerberosTime;
//! let t = KerberosTime::from_unix_seconds(1_500_000_000);
//! assert_eq!(t.unix_seconds(), 1_500_000_000);
//! ```

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use chrono::{FixedOffset, NaiveDateTime, TimeZone, Timelike, Utc};
use rasn::prelude::*;

pub use rasn::types::{BitString, GeneralizedTime, OctetString};

pub mod cammac;
mod constants;
pub mod consts;
pub mod deltat;
pub mod der;
pub mod ere;
pub mod extra;
pub mod fast;
pub mod k5json;
mod name;
mod name_error;
pub mod otp;
pub mod pac;
pub mod pkinit;
pub mod s4u;
pub mod spake;
pub mod timestamp;
pub mod transited;
mod wipe;

pub use constants::{ap_bit, err, flag_bit, ku, pa};
pub use extra::{
    ApRep, ChangePasswdData, EncApRepPart, EncKrbCredPart, EncKrbPrivPart, KrbCred, KrbCredInfo,
    KrbPriv, KrbSafe, KrbSafeBody,
};
pub use name::{
    ParsedName, infer_name_type, parse_name, parse_name_ex, principal_from_unparsed,
    principal_from_unparsed_ex, quote_component, unparse_components, unparse_components_no_realm,
    unparse_name,
};
pub use name_error::{NameError, TimeError};

// MIT `krb5_principal_compare_flags` (`princ_comp.c:79-124`): ignores name type;
#[must_use]
pub fn principal_compare(
    name_a: &PrincipalName,
    realm_a: &str,
    name_b: &PrincipalName,
    realm_b: &str,
) -> bool {
    realm_a == realm_b && name_a.components_eq(name_b)
}

/// Callers that take untrusted input must use [`try_ascii`].
#[must_use]
#[allow(clippy::expect_used)]
pub fn ascii(s: &str) -> KerberosString {
    KerberosString::try_from(s).expect("KerberosString requires the GeneralString alphabet")
}

pub fn try_ascii(s: &str) -> Result<KerberosString, NameError> {
    if !s.is_ascii() {
        return Err(NameError::NotGeneralString);
    }
    KerberosString::try_from(s).map_err(|_| NameError::NotGeneralString)
}

pub fn kerberos_string_from_bytes(bytes: &[u8]) -> Result<KerberosString, NameError> {
    let s = std::str::from_utf8(bytes).map_err(|_| NameError::NotUtf8)?;
    try_ascii(s)
}

pub type KerberosString = GeneralString;
pub type Realm = KerberosString;
pub type HostAddresses = SequenceOf<HostAddress>;
pub type AuthorizationData = SequenceOf<AuthorizationDataValue>;
pub type MethodData = SequenceOf<PaData>;
/// (RFC 6113; MIT `encode_krb5_typed_data`, tags `[0]`/`[1]` not PA-DATA `[1]`/`[2]`).
pub type TypedDataList = SequenceOf<TypedData>;
pub type KerberosFlags = BitString;
#[derive(AsnType, Clone, Copy, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct Microseconds(pub u32);

impl Microseconds {
    pub const MIN: u32 = 0;
    pub const MAX: u32 = 999_999;
    pub const ZERO: Self = Self(0);

    pub fn new(n: u32) -> Result<Self, TimeError> {
        if n > Self::MAX {
            Err(TimeError::MicrosecondsOutOfRange(n))
        } else {
            Ok(Self(n))
        }
    }

    #[must_use]
    pub fn from_subsec_micros(n: u32) -> Self {
        Self(n % 1_000_000)
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    pub fn validate(self) -> Result<Self, TimeError> {
        Self::new(self.0)
    }
}

// MIT decode_atype; see docs/parity/b1-asn1.md
pub(crate) struct WireImmediate(pub(crate) i32);

impl AsnType for WireImmediate {
    const TAG: Tag = Tag::INTEGER;
}

impl Decode for WireImmediate {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        decoder
            .decode_integer::<i64>(tag, constraints)
            .map(|_| Self(0))
    }
}

impl Encode for WireImmediate {
    fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        self.0
            .encode_with_tag_and_constraints(encoder, tag, constraints, identifier)
    }
}

// MIT uint; see docs/parity/b1-asn1.md
// MIT uint32; see docs/parity/b1-asn1.md
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WireUint32(pub(crate) i32);

impl AsnType for WireUint32 {
    const TAG: Tag = Tag::INTEGER;
}

impl Decode for WireUint32 {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let value = decoder.decode_integer::<i64>(tag, constraints)?;
        u32::try_from(value)
            .map(|v| Self(v.cast_signed()))
            .map_err(|_| {
                <D::Error as rasn::de::Error>::custom(
                    "an unsigned field outside 0..=0xFFFFFFFF",
                    decoder.codec(),
                )
            })
    }
}

impl Encode for WireUint32 {
    fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        u64::from(self.0.cast_unsigned()).encode_with_tag_and_constraints(
            encoder,
            tag,
            constraints,
            identifier,
        )
    }
}

// MIT krb5_version; see docs/parity/b1-asn1.md
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WireVersion(pub(crate) i32);

impl AsnType for WireVersion {
    const TAG: Tag = Tag::INTEGER;
}

impl Decode for WireVersion {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        match decoder.decode_integer::<i64>(tag, constraints)? {
            5 => Ok(Self(5)),
            _ => Err(<D::Error as rasn::de::Error>::custom(
                "KRB5KDC_ERR_BAD_PVNO: the version is not 5",
                decoder.codec(),
            )),
        }
    }
}

impl Encode for WireVersion {
    fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        self.0
            .encode_with_tag_and_constraints(encoder, tag, constraints, identifier)
    }
}

#[derive(AsnType, Clone, Debug, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct KerberosTime(pub GeneralizedTime);

// MIT k5_asn1_decode_generaltime; see docs/parity/b1-asn1.md
// MIT decode_kerberos_time; see docs/parity/b1-asn1.md
impl Decode for KerberosTime {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let octets: Vec<u8> = decoder.decode_octet_string(tag, constraints)?;
        mit_generaltime(&octets)
            .map(Self::from_unix_seconds)
            .ok_or_else(|| {
                <D::Error as rasn::de::Error>::custom(
                    format!(
                        "KerberosTime is not YYYYMMDDhhmmssZ ({} octets)",
                        octets.len()
                    ),
                    decoder.codec(),
                )
            })
    }
}

fn mit_generaltime(s: &[u8]) -> Option<u32> {
    if s.len() != 15 || s[14] != b'Z' {
        return None;
    }
    if s == b"19700101000000Z" {
        return Some(0);
    }
    let digits = |from: usize, to: usize| -> Option<i64> {
        s[from..to].iter().try_fold(0i64, |acc, &c| {
            let d = c.wrapping_sub(b'0');
            (d <= 9).then_some(acc * 10 + i64::from(d))
        })
    };
    let (year, month) = (digits(0, 4)?, digits(4, 6)? - 1);
    let (mday, hour, min, sec) = (
        digits(6, 8)?,
        digits(8, 10)?,
        digits(10, 12)?,
        digits(12, 14)?,
    );
    let (y, m) = (year + month.div_euclid(12), month.rem_euclid(12) + 1);
    let days = days_from_civil(y, m) + mday - 1;
    let t = days * 86_400 + hour * 3_600 + min * 60 + sec;
    if t == -1 {
        return None;
    }
    Some(u32::try_from(t.rem_euclid(1 << 32)).unwrap_or_default())
}

fn days_from_civil(y: i64, m: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PrincipalName {
    /// Name type (RFC 4120 §6.2). Treat as a hint.
    #[rasn(tag(explicit(0)))]
    pub name_type: i32,
    #[rasn(tag(explicit(1)))]
    pub name_string: SequenceOf<KerberosString>,
}

impl PrincipalName {
    pub const NT_UNKNOWN: i32 = 0;
    pub const NT_PRINCIPAL: i32 = 1;
    pub const NT_SRV_INST: i32 = 2;
    pub const NT_SRV_HST: i32 = 3;
    pub const NT_ENTERPRISE: i32 = 10;
    pub const NT_WELLKNOWN: i32 = 11;
    pub const NT_MS_PRINCIPAL: i32 = -128;

    /// Untrusted input must use [`Self::try_new`].
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn new(name_type: i32, parts: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self::try_new(name_type, parts).expect("KerberosString requires the GeneralString alphabet")
    }

    pub fn try_new(
        name_type: i32,
        parts: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, NameError> {
        let mut name_string = SequenceOf::new();
        for p in parts {
            name_string.push(try_ascii(p.as_ref())?);
        }
        Ok(Self {
            name_type,
            name_string,
        })
    }

    pub fn try_from_bytes(
        name_type: i32,
        parts: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> Result<Self, NameError> {
        let mut name_string = SequenceOf::new();
        for p in parts {
            name_string.push(kerberos_string_from_bytes(p.as_ref())?);
        }
        Ok(Self {
            name_type,
            name_string,
        })
    }

    #[must_use]
    pub fn krbtgt(realm: &str) -> Self {
        Self::new(Self::NT_SRV_INST, ["krbtgt", realm])
    }

    #[must_use]
    pub fn components_eq(&self, other: &Self) -> bool {
        self.name_string == other.name_string
    }

    #[must_use]
    pub fn components_joined(&self) -> String {
        self.name_string
            .iter()
            .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
            .collect::<Vec<_>>()
            .join("/")
    }

    #[must_use]
    pub fn unparse(&self) -> String {
        crate::unparse_components(&self.component_strings())
    }

    #[must_use]
    pub fn unparse_with_realm(&self, realm: &str) -> String {
        crate::unparse_name(&self.component_strings(), realm)
    }

    #[must_use]
    pub fn unparse_no_realm(&self) -> String {
        crate::unparse_components_no_realm(&self.component_strings())
    }

    fn component_strings(&self) -> Vec<String> {
        self.name_string
            .iter()
            .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
            .collect()
    }

    #[must_use]
    pub fn default_salt(&self, realm: &str) -> Vec<u8> {
        let mut salt = realm.as_bytes().to_vec();
        for part in &self.name_string {
            salt.extend_from_slice(part.as_bytes());
        }
        salt
    }

    #[must_use]
    pub fn is_krbtgt(&self) -> bool {
        self.name_string.len() == 2
            && self
                .name_string
                .first()
                .is_some_and(|p| p.as_bytes() == b"krbtgt")
    }

    #[must_use]
    pub fn is_krbtgt_for(&self, realm: &str) -> bool {
        self.name_string.len() == 2
            && self.name_string[0].as_bytes() == b"krbtgt"
            && self.name_string[1].as_bytes() == realm.as_bytes()
    }

    #[must_use]
    pub fn is_local_tgs_principal(&self, princ_realm: &str) -> bool {
        self.is_krbtgt() && self.is_krbtgt_for(princ_realm)
    }

    #[must_use]
    pub fn is_cross_tgs_principal(&self, princ_realm: &str) -> bool {
        self.is_krbtgt() && !self.is_krbtgt_for(princ_realm)
    }
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct HostAddress {
    #[rasn(tag(explicit(0)))]
    pub addr_type: i32,
    #[rasn(tag(explicit(1)))]
    pub address: OctetString,
}

impl HostAddress {
    pub const ADDRTYPE_INET: i32 = 2;
    pub const ADDRTYPE_NETBIOS: i32 = 0x14;
    pub const ADDRTYPE_INET6: i32 = 0x18;

    // MIT k5_sockaddr_to_address; see docs/parity/a2-as.md
    #[must_use]
    pub fn from_socket(addr: std::net::SocketAddr) -> Self {
        match addr {
            std::net::SocketAddr::V4(v) => Self {
                addr_type: Self::ADDRTYPE_INET,
                address: v.ip().octets().to_vec().into(),
            },
            std::net::SocketAddr::V6(v) => {
                if let Some(v4) = v.ip().to_ipv4_mapped() {
                    Self {
                        addr_type: Self::ADDRTYPE_INET,
                        address: v4.octets().to_vec().into(),
                    }
                } else {
                    Self {
                        addr_type: Self::ADDRTYPE_INET6,
                        address: v.ip().octets().to_vec().into(),
                    }
                }
            }
        }
    }
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct AuthorizationDataValue {
    #[rasn(tag(explicit(0)))]
    pub ad_type: i32,
    #[rasn(tag(explicit(1)))]
    pub ad_data: OctetString,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaData {
    #[rasn(tag(explicit(1)))]
    pub padata_type: i32,
    #[rasn(tag(explicit(2)))]
    pub padata_value: OctetString,
}

// MIT `typed_data_0` (`asn1_k_encode.c:1547-1547`): `data-type [0]` is an Int32.
// MIT `typed_data_1` (`asn1_k_encode.c:1548-1548`): `data-value [1]` is an OCTET STRING, encoded
/// even when empty, so it is not optional on the wire.
// MIT `typed_data_fields` (`asn1_k_encode.c:1549-1551`): the element's two fields, in that
// MIT `typed_data` (`asn1_k_encode.c:1552-1552`): the element is the SEQUENCE of those
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct TypedData {
    #[rasn(tag(explicit(0)))]
    pub data_type: i32,
    #[rasn(tag(explicit(1)))]
    pub data_value: OctetString,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct EncryptedData {
    #[rasn(tag(explicit(0)))]
    pub etype: i32,
    #[rasn(tag(explicit(1)))]
    pub kvno: Option<u32>,
    #[rasn(tag(explicit(2)))]
    pub cipher: OctetString,
}

/// Dropping a key zeroizes the whole allocation of [`Self::keyvalue`] in place when the key holds
#[derive(AsnType, Clone, Decode, Encode, PartialEq, Eq, Hash)]
pub struct EncryptionKey {
    #[rasn(tag(explicit(0)))]
    pub keytype: i32,
    #[rasn(tag(explicit(1)))]
    pub keyvalue: OctetString,
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        wipe::wipe_octets(std::mem::take(&mut self.keyvalue));
    }
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionKey")
            .field("keytype", &self.keytype)
            .field(
                "keyvalue",
                &format_args!("<redacted, {} octets>", self.keyvalue.len()),
            )
            .finish()
    }
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct Checksum {
    #[rasn(tag(explicit(0)))]
    pub cksumtype: i32,
    #[rasn(tag(explicit(1)))]
    pub checksum: OctetString,
}

#[derive(AsnType, Clone, Debug, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 1)))]
pub struct Ticket {
    #[rasn(tag(explicit(0)))]
    pub tkt_vno: i32,
    #[rasn(tag(explicit(1)))]
    pub realm: Realm,
    #[rasn(tag(explicit(2)))]
    pub sname: PrincipalName,
    #[rasn(tag(explicit(3)))]
    pub enc_part: EncryptedData,
}

impl Ticket {
    pub const VNO: i32 = 5;
}

#[derive(AsnType, Decode)]
#[rasn(tag(explicit(application, 1)))]
struct TicketOnWire {
    #[rasn(tag(explicit(0)))]
    tkt_vno: WireVersion,
    #[rasn(tag(explicit(1)))]
    realm: Realm,
    #[rasn(tag(explicit(2)))]
    sname: PrincipalName,
    #[rasn(tag(explicit(3)))]
    enc_part: EncryptedData,
}

impl Decode for Ticket {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let w = TicketOnWire::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(Self {
            tkt_vno: w.tkt_vno.0,
            realm: w.realm,
            sname: w.sname,
            enc_part: w.enc_part,
        })
    }
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct TicketFlags(pub KerberosFlags);

impl TicketFlags {
    #[must_use]
    pub fn none() -> Self {
        Self(KerberosFlags::repeat(false, 32))
    }

    #[must_use]
    pub fn initial_preauth() -> Self {
        let mut bits = KerberosFlags::repeat(false, 32);
        bits.set(flag_bit::INITIAL, true);
        bits.set(flag_bit::PRE_AUTHENT, true);
        Self(bits)
    }

    /// Construct flags from a MIT-packed 32-bit integer (MSB is RFC bit 0).
    #[must_use]
    pub fn from_u32(v: u32) -> Self {
        let mut bits = KerberosFlags::repeat(false, 32);
        for i in 0..32 {
            if v & (1u32 << (31 - i)) != 0 {
                bits.set(i, true);
            }
        }
        Self(bits)
    }

    #[must_use]
    pub fn bit(&self, n: usize) -> bool {
        n < self.0.len() && self.0[n]
    }

    #[must_use]
    pub fn initial(&self) -> bool {
        self.bit(flag_bit::INITIAL)
    }

    #[must_use]
    pub fn pre_authent(&self) -> bool {
        self.bit(flag_bit::PRE_AUTHENT)
    }

    #[must_use]
    pub fn renewable(&self) -> bool {
        self.bit(flag_bit::RENEWABLE)
    }

    #[must_use]
    pub fn forwardable(&self) -> bool {
        self.bit(flag_bit::FORWARDABLE)
    }

    #[must_use]
    pub fn proxiable(&self) -> bool {
        self.bit(flag_bit::PROXIABLE)
    }

    #[must_use]
    pub fn mit_letters(&self) -> String {
        let mut s = String::new();
        let bits = [
            (flag_bit::FORWARDABLE, 'F'),
            (flag_bit::FORWARDED, 'f'),
            (flag_bit::PROXIABLE, 'P'),
            (flag_bit::PROXY, 'p'),
            (flag_bit::MAY_POSTDATE, 'D'),
            (flag_bit::POSTDATED, 'd'),
            (flag_bit::INVALID, 'i'),
            (flag_bit::RENEWABLE, 'R'),
            (flag_bit::INITIAL, 'I'),
            (flag_bit::HW_AUTHENT, 'H'),
            (flag_bit::PRE_AUTHENT, 'A'),
            (flag_bit::TRANSITED_POLICY_CHECKED, 'T'),
            (flag_bit::OK_AS_DELEGATE, 'O'),
            (flag_bit::ANONYMOUS, 'a'),
        ];
        for (bit, ch) in bits {
            if self.bit(bit) {
                s.push(ch);
            }
        }
        s
    }

    #[must_use]
    pub fn invalid(&self) -> bool {
        self.bit(flag_bit::INVALID)
    }

    #[must_use]
    pub fn enc_pa_rep(&self) -> bool {
        self.bit(flag_bit::ENC_PA_REP)
    }

    #[must_use]
    pub fn with_bit(mut self, n: usize, on: bool) -> Self {
        if n < self.0.len() {
            self.0.set(n, on);
        }
        self
    }
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct KdcOptions(pub KerberosFlags);

impl KdcOptions {
    #[must_use]
    pub fn none() -> Self {
        Self(KerberosFlags::repeat(false, 32))
    }

    #[must_use]
    pub fn forwardable() -> Self {
        Self::none().with_bit(flag_bit::FORWARDABLE, true)
    }

    #[must_use]
    pub fn bit(&self, n: usize) -> bool {
        n < self.0.len() && self.0[n]
    }

    #[must_use]
    pub fn with_bit(mut self, n: usize, on: bool) -> Self {
        if n < self.0.len() {
            self.0.set(n, on);
        }
        self
    }

    /// Packed MIT integer (MSB is RFC bit 0).
    #[must_use]
    pub fn to_u32(&self) -> u32 {
        flags_to_u32(&self.0)
    }

    #[must_use]
    pub fn unsupported_bits(&self) -> u32 {
        let supported = (1u32 << (31 - flag_bit::FORWARDABLE))
            | (1u32 << (31 - flag_bit::FORWARDED))
            | (1u32 << (31 - flag_bit::PROXIABLE))
            | (1u32 << (31 - flag_bit::PROXY))
            | (1u32 << (31 - flag_bit::RENEWABLE))
            | (1u32 << (31 - flag_bit::CNAME_IN_ADDL_TKT))
            | (1u32 << (31 - flag_bit::CANONICALIZE))
            | (1u32 << (31 - flag_bit::DISABLE_TRANSITED_CHECK))
            | (1u32 << (31 - flag_bit::RENEWABLE_OK))
            | (1u32 << (31 - flag_bit::ENC_TKT_IN_SKEY))
            | (1u32 << (31 - flag_bit::RENEW))
            | (1u32 << (31 - flag_bit::MAY_POSTDATE))
            | (1u32 << (31 - flag_bit::POSTDATED))
            | (1u32 << (31 - flag_bit::VALIDATE));
        self.to_u32() & !supported
    }

    // MIT NON_TGT_OPTION; see docs/parity/a1-tgs.md
    // MIT NO_REFERRAL_OPTION; see docs/parity/a1-tgs.md
    // MIT AS_INVALID_OPTIONS; see docs/parity/a1-tgs.md
    #[must_use]
    pub fn as_invalid_bits(&self) -> u32 {
        let mask = (1u32 << (31 - flag_bit::FORWARDED))
            | (1u32 << (31 - flag_bit::PROXY))
            | (1u32 << (31 - flag_bit::RENEW))
            | (1u32 << (31 - flag_bit::VALIDATE))
            | (1u32 << (31 - flag_bit::ENC_TKT_IN_SKEY))
            | (1u32 << (31 - flag_bit::CNAME_IN_ADDL_TKT));
        self.to_u32() & mask
    }
}

impl TicketFlags {
    /// RFC 4120 bit string packed as a 32-bit integer (MSB is bit 0).
    #[must_use]
    pub fn to_u32(&self) -> u32 {
        flags_to_u32(&self.0)
    }
}

fn flags_to_u32(bits: &KerberosFlags) -> u32 {
    let mut v = 0u32;
    let n = bits.len().min(32);
    for i in 0..n {
        if bits[i] {
            v |= 1 << (31 - i);
        }
    }
    v
}

#[derive(AsnType, Clone, Debug, PartialEq, Eq, Hash)]
pub struct KdcReq {
    #[rasn(tag(explicit(1)))]
    pub pvno: i32,
    #[rasn(tag(explicit(2)))]
    pub msg_type: i32,
    #[rasn(tag(explicit(3)))]
    pub padata: Option<SequenceOf<PaData>>,
    #[rasn(tag(explicit(4)))]
    pub req_body: KdcReqBody,
}

impl KdcReq {
    pub const PVNO: i32 = 5;
    pub const MSG_AS_REQ: i32 = 10;
    pub const MSG_TGS_REQ: i32 = 12;
}

#[derive(AsnType, Decode, Encode)]
struct KdcReqOnWire {
    #[rasn(tag(explicit(1)))]
    pvno: WireVersion,
    #[rasn(tag(explicit(2)))]
    msg_type: WireUint32,
    #[rasn(tag(explicit(3)))]
    padata: Option<SequenceOf<PaData>>,
    #[rasn(tag(explicit(4)))]
    req_body: KdcReqBody,
}

impl Decode for KdcReq {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let w = KdcReqOnWire::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(Self {
            pvno: w.pvno.0,
            msg_type: w.msg_type.0,
            padata: w.padata,
            req_body: w.req_body,
        })
    }
}

impl Encode for KdcReq {
    fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        KdcReqOnWire {
            pvno: WireVersion(self.pvno),
            msg_type: WireUint32(self.msg_type),
            padata: self.padata.clone(),
            req_body: self.req_body.clone(),
        }
        .encode_with_tag_and_constraints(encoder, tag, constraints, identifier)
    }
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KdcReqBody {
    #[rasn(tag(explicit(0)))]
    pub kdc_options: KdcOptions,
    #[rasn(tag(explicit(1)))]
    pub cname: Option<PrincipalName>,
    #[rasn(tag(explicit(2)))]
    pub realm: Realm,
    #[rasn(tag(explicit(3)))]
    pub sname: Option<PrincipalName>,
    #[rasn(tag(explicit(4)))]
    pub from: Option<KerberosTime>,
    #[rasn(tag(explicit(5)))]
    pub till: KerberosTime,
    #[rasn(tag(explicit(6)))]
    pub rtime: Option<KerberosTime>,
    #[rasn(tag(explicit(7)))]
    pub nonce: u32,
    #[rasn(tag(explicit(8)))]
    pub etype: SequenceOf<i32>,
    #[rasn(tag(explicit(9)))]
    pub addresses: Option<HostAddresses>,
    #[rasn(tag(explicit(10)))]
    pub enc_authorization_data: Option<EncryptedData>,
    #[rasn(tag(explicit(11)))]
    pub additional_tickets: Option<SequenceOf<Ticket>>,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 10)), delegate)]
pub struct AsReq(pub KdcReq);

#[derive(AsnType, Clone, Debug, PartialEq, Eq, Hash)]
pub struct KdcRep {
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    #[rasn(tag(explicit(2)))]
    pub padata: Option<SequenceOf<PaData>>,
    #[rasn(tag(explicit(3)))]
    pub crealm: Realm,
    #[rasn(tag(explicit(4)))]
    pub cname: PrincipalName,
    #[rasn(tag(explicit(5)))]
    pub ticket: Ticket,
    #[rasn(tag(explicit(6)))]
    pub enc_part: EncryptedData,
}

impl KdcRep {
    pub const PVNO: i32 = 5;
    pub const MSG_AS_REP: i32 = 11;
    pub const MSG_TGS_REP: i32 = 13;
}

#[derive(AsnType, Decode, Encode)]
struct KdcRepOnWire {
    #[rasn(tag(explicit(0)))]
    pvno: WireVersion,
    #[rasn(tag(explicit(1)))]
    msg_type: WireUint32,
    #[rasn(tag(explicit(2)))]
    padata: Option<SequenceOf<PaData>>,
    #[rasn(tag(explicit(3)))]
    crealm: Realm,
    #[rasn(tag(explicit(4)))]
    cname: PrincipalName,
    #[rasn(tag(explicit(5)))]
    ticket: Ticket,
    #[rasn(tag(explicit(6)))]
    enc_part: EncryptedData,
}

impl Decode for KdcRep {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let w = KdcRepOnWire::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(Self {
            pvno: w.pvno.0,
            msg_type: w.msg_type.0,
            padata: w.padata,
            crealm: w.crealm,
            cname: w.cname,
            ticket: w.ticket,
            enc_part: w.enc_part,
        })
    }
}

impl Encode for KdcRep {
    fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        KdcRepOnWire {
            pvno: WireVersion(self.pvno),
            msg_type: WireUint32(self.msg_type),
            padata: self.padata.clone(),
            crealm: self.crealm.clone(),
            cname: self.cname.clone(),
            ticket: self.ticket.clone(),
            enc_part: self.enc_part.clone(),
        }
        .encode_with_tag_and_constraints(encoder, tag, constraints, identifier)
    }
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 11)), delegate)]
pub struct AsRep(pub KdcRep);

#[derive(AsnType, Clone, Debug, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 14)))]
pub struct ApReq {
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    #[rasn(tag(explicit(2)))]
    pub ap_options: ApOptions,
    #[rasn(tag(explicit(3)))]
    pub ticket: Ticket,
    #[rasn(tag(explicit(4)))]
    pub authenticator: EncryptedData,
}

impl ApReq {
    pub const PVNO: i32 = 5;
    pub const MSG_TYPE: i32 = 14;
}

// MIT `ap_req_msg_type` (`lib/krb5/asn.1/asn1_k_encode.c:747-747`): the msg-type is an immediate with no error, so any INTEGER of up to eight octets decodes and none is kept.
#[derive(AsnType, Decode)]
#[rasn(tag(explicit(application, 14)))]
struct ApReqOnWire {
    #[rasn(tag(explicit(0)))]
    pvno: WireVersion,
    #[rasn(tag(explicit(1)))]
    #[allow(dead_code)]
    msg_type: WireImmediate,
    #[rasn(tag(explicit(2)))]
    ap_options: ApOptions,
    #[rasn(tag(explicit(3)))]
    ticket: Ticket,
    #[rasn(tag(explicit(4)))]
    authenticator: EncryptedData,
}

impl Decode for ApReq {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let w = ApReqOnWire::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(Self {
            pvno: w.pvno.0,
            msg_type: Self::MSG_TYPE,
            ap_options: w.ap_options,
            ticket: w.ticket,
            authenticator: w.authenticator,
        })
    }
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct ApOptions(pub KerberosFlags);

impl ApOptions {
    #[must_use]
    pub fn none() -> Self {
        Self(KerberosFlags::repeat(false, 32))
    }

    #[must_use]
    pub fn mutual_required() -> Self {
        let mut bits = KerberosFlags::repeat(false, 32);
        bits.set(ap_bit::MUTUAL_REQUIRED, true);
        Self(bits)
    }

    #[must_use]
    pub fn bit(&self, n: usize) -> bool {
        n < self.0.len() && self.0[n]
    }

    #[must_use]
    pub fn wants_mutual(&self) -> bool {
        self.bit(ap_bit::MUTUAL_REQUIRED)
    }

    #[must_use]
    pub fn use_session_key(&self) -> bool {
        self.bit(ap_bit::USE_SESSION_KEY)
    }
}

#[derive(AsnType, Clone, Debug, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 30)))]
pub struct KrbError {
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    #[rasn(tag(explicit(2)))]
    pub ctime: Option<KerberosTime>,
    #[rasn(tag(explicit(3)))]
    pub cusec: Option<Microseconds>,
    #[rasn(tag(explicit(4)))]
    pub stime: KerberosTime,
    #[rasn(tag(explicit(5)))]
    pub susec: Microseconds,
    #[rasn(tag(explicit(6)))]
    pub error_code: i32,
    #[rasn(tag(explicit(7)))]
    pub crealm: Option<Realm>,
    #[rasn(tag(explicit(8)))]
    pub cname: Option<PrincipalName>,
    #[rasn(tag(explicit(9)))]
    pub realm: Realm,
    #[rasn(tag(explicit(10)))]
    pub sname: PrincipalName,
    #[rasn(tag(explicit(11)))]
    pub e_text: Option<KerberosString>,
    #[rasn(tag(explicit(12)))]
    pub e_data: Option<OctetString>,
}

impl KrbError {
    pub const PVNO: i32 = 5;
    pub const MSG_TYPE: i32 = 30;
}

// MIT `error_msg_type` (`lib/krb5/asn.1/asn1_k_encode.c:911-911`): the msg-type is an immediate with no error, so any INTEGER of up to eight octets decodes and none is kept.
#[derive(AsnType, Decode, Encode)]
#[rasn(tag(explicit(application, 30)))]
struct KrbErrorOnWire {
    #[rasn(tag(explicit(0)))]
    pvno: WireVersion,
    #[rasn(tag(explicit(1)))]
    #[allow(dead_code)]
    msg_type: WireImmediate,
    #[rasn(tag(explicit(2)))]
    ctime: Option<KerberosTime>,
    #[rasn(tag(explicit(3)))]
    cusec: Option<Microseconds>,
    #[rasn(tag(explicit(4)))]
    stime: KerberosTime,
    #[rasn(tag(explicit(5)))]
    susec: Microseconds,
    #[rasn(tag(explicit(6)))]
    error_code: WireUint32,
    #[rasn(tag(explicit(7)))]
    crealm: Option<Realm>,
    #[rasn(tag(explicit(8)))]
    cname: Option<PrincipalName>,
    #[rasn(tag(explicit(9)))]
    realm: Realm,
    #[rasn(tag(explicit(10)))]
    sname: PrincipalName,
    #[rasn(tag(explicit(11)))]
    e_text: Option<KerberosString>,
    #[rasn(tag(explicit(12)))]
    e_data: Option<OctetString>,
}

impl Decode for KrbError {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let w = KrbErrorOnWire::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(Self {
            pvno: w.pvno.0,
            msg_type: Self::MSG_TYPE,
            ctime: w.ctime,
            cusec: w.cusec,
            stime: w.stime,
            susec: w.susec,
            error_code: w.error_code.0,
            crealm: w.crealm,
            cname: w.cname,
            realm: w.realm,
            sname: w.sname,
            e_text: w.e_text,
            e_data: w.e_data,
        })
    }
}

impl Encode for KrbError {
    fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        KrbErrorOnWire {
            pvno: WireVersion(self.pvno),
            msg_type: WireImmediate(self.msg_type),
            ctime: self.ctime.clone(),
            cusec: self.cusec,
            stime: self.stime.clone(),
            susec: self.susec,
            error_code: WireUint32(self.error_code),
            crealm: self.crealm.clone(),
            cname: self.cname.clone(),
            realm: self.realm.clone(),
            sname: self.sname.clone(),
            e_text: self.e_text.clone(),
            e_data: self.e_data.clone(),
        }
        .encode_with_tag_and_constraints(encoder, tag, constraints, identifier)
    }
}

pub fn kerberos_time_from_utc_z(s: &str) -> Result<KerberosTime, TimeError> {
    let body = s
        .strip_suffix('Z')
        .ok_or_else(|| TimeError::Parse(format!("missing Z: {s}")))?;
    let naive = NaiveDateTime::parse_from_str(body, "%Y%m%d%H%M%S")
        .map_err(|e| TimeError::Parse(e.to_string()))?;
    let tz = FixedOffset::east_opt(0).ok_or_else(|| TimeError::Parse("UTC offset".into()))?;
    Ok(KerberosTime(tz.from_utc_datetime(&naive)))
}

impl KerberosTime {
    /// RFC 4120 forbids fractional seconds; nanoseconds are zeroed so DER
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn now() -> Self {
        let tz = FixedOffset::east_opt(0).expect("UTC offset 0 is valid");
        let dt = Utc::now().with_timezone(&tz);
        Self(dt.with_nanosecond(0).unwrap_or(dt))
    }

    #[must_use]
    pub fn unix_seconds(&self) -> u32 {
        u32::try_from(self.0.timestamp().max(0)).unwrap_or(u32::MAX)
    }

    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn from_unix_seconds(s: u32) -> Self {
        let tz = FixedOffset::east_opt(0).expect("UTC offset 0 is valid");
        let utc = chrono::DateTime::from_timestamp(i64::from(s), 0).unwrap_or_else(Utc::now);
        let dt = utc.with_timezone(&tz);
        Self(dt.with_nanosecond(0).unwrap_or(dt))
    }

    pub fn add_hours(&self, hours: i64) -> Result<Self, TimeError> {
        let dur = chrono::TimeDelta::try_hours(hours).ok_or(TimeError::Overflow)?;
        let dt = self.0.checked_add_signed(dur).ok_or(TimeError::Overflow)?;
        Ok(Self(dt.with_nanosecond(0).unwrap_or(dt)))
    }

    pub fn add_seconds(&self, seconds: i64) -> Result<Self, TimeError> {
        let dur = chrono::TimeDelta::try_seconds(seconds).ok_or(TimeError::Overflow)?;
        let dt = self.0.checked_add_signed(dur).ok_or(TimeError::Overflow)?;
        Ok(Self(dt.with_nanosecond(0).unwrap_or(dt)))
    }

    #[must_use]
    pub fn delta_seconds(&self, other: &Self) -> i64 {
        self.0.timestamp().saturating_sub(other.0.timestamp())
    }
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaPacRequest {
    #[rasn(tag(explicit(0)))]
    pub include_pac: bool,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaEncTsEnc {
    #[rasn(tag(explicit(0)))]
    pub patimestamp: KerberosTime,
    #[rasn(tag(explicit(1)))]
    pub pausec: Option<Microseconds>,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct EtypeInfo2Entry {
    #[rasn(tag(explicit(0)))]
    pub etype: i32,
    #[rasn(tag(explicit(1)))]
    pub salt: Option<KerberosString>,
    #[rasn(tag(explicit(2)))]
    pub s2kparams: Option<OctetString>,
}

pub type EtypeInfo2 = SequenceOf<EtypeInfo2Entry>;

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct EtypeInfoEntry {
    #[rasn(tag(explicit(0)))]
    pub etype: i32,
    #[rasn(tag(explicit(1)))]
    pub salt: Option<OctetString>,
}

pub type EtypeInfo = SequenceOf<EtypeInfoEntry>;

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct LastReqValue {
    #[rasn(tag(explicit(0)))]
    pub lr_type: i32,
    #[rasn(tag(explicit(1)))]
    pub lr_value: KerberosTime,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct EncKdcRepPart {
    #[rasn(tag(explicit(0)))]
    pub key: EncryptionKey,
    #[rasn(tag(explicit(1)))]
    pub last_req: SequenceOf<LastReqValue>,
    #[rasn(tag(explicit(2)))]
    pub nonce: u32,
    #[rasn(tag(explicit(3)))]
    pub key_expiration: Option<KerberosTime>,
    #[rasn(tag(explicit(4)))]
    pub flags: TicketFlags,
    #[rasn(tag(explicit(5)))]
    pub authtime: KerberosTime,
    #[rasn(tag(explicit(6)))]
    pub starttime: Option<KerberosTime>,
    #[rasn(tag(explicit(7)))]
    pub endtime: KerberosTime,
    #[rasn(tag(explicit(8)))]
    pub renew_till: Option<KerberosTime>,
    #[rasn(tag(explicit(9)))]
    pub srealm: Realm,
    #[rasn(tag(explicit(10)))]
    pub sname: PrincipalName,
    #[rasn(tag(explicit(11)))]
    pub caddr: Option<HostAddresses>,
    #[rasn(tag(explicit(12)))]
    pub encrypted_pa_data: Option<SequenceOf<PaData>>,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 25)), delegate)]
pub struct EncAsRepPart(pub EncKdcRepPart);

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 26)), delegate)]
pub struct EncTgsRepPart(pub EncKdcRepPart);

#[derive(AsnType, Clone, Debug, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 2)))]
pub struct Authenticator {
    #[rasn(tag(explicit(0)))]
    pub authenticator_vno: i32,
    /// `crealm [1]`: the client's realm; must match the ticket's.
    #[rasn(tag(explicit(1)))]
    pub crealm: Realm,
    /// `cname [2]`: the client principal; must match the ticket's.
    #[rasn(tag(explicit(2)))]
    pub cname: PrincipalName,
    #[rasn(tag(explicit(3)))]
    pub cksum: Option<Checksum>,
    #[rasn(tag(explicit(4)))]
    pub cusec: Microseconds,
    /// `ctime [5]`: the client's time; must be within the clock-skew window.
    #[rasn(tag(explicit(5)))]
    pub ctime: KerberosTime,
    #[rasn(tag(explicit(6)))]
    pub subkey: Option<EncryptionKey>,
    #[rasn(tag(explicit(7)))]
    pub seq_number: Option<u32>,
    #[rasn(tag(explicit(8)))]
    pub authorization_data: Option<AuthorizationData>,
}

impl Authenticator {
    pub const VNO: i32 = 5;
}

#[derive(AsnType, Decode, Encode)]
#[rasn(tag(explicit(application, 2)))]
struct AuthenticatorOnWire {
    #[rasn(tag(explicit(0)))]
    authenticator_vno: WireVersion,
    #[rasn(tag(explicit(1)))]
    crealm: Realm,
    #[rasn(tag(explicit(2)))]
    cname: PrincipalName,
    #[rasn(tag(explicit(3)))]
    cksum: Option<Checksum>,
    #[rasn(tag(explicit(4)))]
    cusec: Microseconds,
    #[rasn(tag(explicit(5)))]
    ctime: KerberosTime,
    #[rasn(tag(explicit(6)))]
    subkey: Option<EncryptionKey>,
    #[rasn(tag(explicit(7)))]
    seq_number: Option<extra::WireSeqNumber>,
    #[rasn(tag(explicit(8)))]
    authorization_data: Option<AuthorizationData>,
}

impl Decode for Authenticator {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let w = AuthenticatorOnWire::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(Self {
            authenticator_vno: w.authenticator_vno.0,
            crealm: w.crealm,
            cname: w.cname,
            cksum: w.cksum,
            cusec: w.cusec,
            ctime: w.ctime,
            subkey: w.subkey,
            seq_number: w.seq_number.map(|s| s.0),
            authorization_data: w.authorization_data,
        })
    }
}

impl Encode for Authenticator {
    fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        AuthenticatorOnWire {
            authenticator_vno: WireVersion(self.authenticator_vno),
            crealm: self.crealm.clone(),
            cname: self.cname.clone(),
            cksum: self.cksum.clone(),
            cusec: self.cusec,
            ctime: self.ctime.clone(),
            subkey: self.subkey.clone(),
            seq_number: self.seq_number.map(extra::WireSeqNumber),
            authorization_data: self.authorization_data.clone(),
        }
        .encode_with_tag_and_constraints(encoder, tag, constraints, identifier)
    }
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 12)), delegate)]
pub struct TgsReq(pub KdcReq);

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 13)), delegate)]
pub struct TgsRep(pub KdcRep);

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct TransitedEncoding {
    #[rasn(tag(explicit(0)))]
    pub tr_type: i32,
    #[rasn(tag(explicit(1)))]
    pub contents: OctetString,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransitError {
    #[error("transited field too long")]
    FieldTooLong,
    #[error("too many transited fields")]
    TooManyFields,
    #[error("transited intermediates invalid")]
    BadIntermediates,
}

impl TransitedEncoding {
    #[must_use]
    pub fn empty() -> Self {
        Self::from_realms(&[])
    }

    #[must_use]
    pub fn from_realms(realms: &[&str]) -> Self {
        let mut contents = Vec::new();
        for r in realms {
            contents = encode_append(&contents, r);
        }
        Self {
            tr_type: 1,
            contents: OctetString::from(contents),
        }
    }

    pub fn realms_for(&self, crealm: &str, srealm: &str) -> Result<Vec<String>, TransitError> {
        expand_domain_x500(self.contents.as_ref(), crealm, srealm)
    }

    pub fn append_realm(
        &self,
        realm: &str,
        crealm: &str,
        srealm: &str,
    ) -> Result<Self, TransitError> {
        let _ = (crealm, srealm);
        let hops = expand_add_path(self.contents.as_ref())?;
        if hops.iter().any(|h| h == realm) {
            return Ok(self.clone());
        }
        let contents = encode_append(self.contents.as_ref(), realm);
        if contents.len() >= MAX_ADD_PATH_TOTAL {
            return Err(TransitError::FieldTooLong);
        }
        Ok(Self {
            tr_type: 1,
            contents: OctetString::from(contents),
        })
    }

    pub fn validate_add_path(&self) -> Result<(), TransitError> {
        expand_add_path(self.contents.as_ref()).map(|_| ())
    }
}

/// Cap on comma-separated transited fields. Rust-STRICTER than MIT.
pub const MAX_TRANSIT_REALMS: usize = 256;
pub const MAX_TRANSIT_HOPS: usize = 4096;
pub const MAX_TRANSIT_RAW: usize = 512;
const MAX_TRANSIT_JOINED: usize = 512;
const MAX_ADD_PATH_RAW: usize = 500;
const MAX_ADD_PATH_JOINED: usize = 499;
const MAX_ADD_PATH_TOTAL: usize = 500;

fn strip_trailing_nul(raw: &[u8]) -> &[u8] {
    match raw.split_last() {
        Some((0, rest)) => rest,
        _ => raw,
    }
}

fn drop_trailing_unescaped_comma(buf: &mut Vec<u8>) {
    if buf.last() != Some(&b',') {
        return;
    }
    let mut bs = 0usize;
    let mut i = buf.len() - 1;
    while i > 0 && buf[i - 1] == b'\\' {
        bs += 1;
        i -= 1;
    }
    if bs.is_multiple_of(2) {
        buf.pop();
    }
}

fn encode_append(raw: &[u8], realm: &str) -> Vec<u8> {
    let mut contents = strip_trailing_nul(raw).to_vec();
    drop_trailing_unescaped_comma(&mut contents);
    if !contents.is_empty() {
        contents.push(b',');
        if realm.starts_with('/') {
            contents.push(b' ');
        }
    }
    contents.extend_from_slice(escape_transit_realm(realm).as_bytes());
    contents
}

fn expand_add_path(raw: &[u8]) -> Result<Vec<String>, TransitError> {
    let raw = strip_trailing_nul(raw);
    let mut stripped = raw.to_vec();
    drop_trailing_unescaped_comma(&mut stripped);
    if stripped.len() >= MAX_ADD_PATH_TOTAL {
        return Err(TransitError::FieldTooLong);
    }
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let s = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    let mut last = String::new();
    let mut cur = String::new();
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            if cur.len() >= MAX_ADD_PATH_RAW {
                return Err(TransitError::FieldTooLong);
            }
            continue;
        }
        match c {
            '\\' => escaped = true,
            ',' => emit_add_path_field(&mut out, &mut last, &mut cur)?,
            _ => {
                cur.push(c);
                if cur.len() >= MAX_ADD_PATH_RAW {
                    return Err(TransitError::FieldTooLong);
                }
            }
        }
    }
    emit_add_path_field(&mut out, &mut last, &mut cur)?;
    Ok(out)
}

fn emit_add_path_field(
    out: &mut Vec<String>,
    last: &mut String,
    cur: &mut String,
) -> Result<(), TransitError> {
    if cur.is_empty() {
        return Ok(());
    }
    let this = add_path_join(last, cur)?;
    push_hop(out, this.clone())?;
    *last = this;
    cur.clear();
    Ok(())
}

fn add_path_join(last: &str, cur: &str) -> Result<String, TransitError> {
    if let Some(rest) = cur.strip_prefix(' ') {
        if rest.len() >= MAX_ADD_PATH_RAW {
            return Err(TransitError::FieldTooLong);
        }
        return Ok(rest.to_owned());
    }
    if cur.starts_with('/') && last.starts_with('/') {
        if last.len() + cur.len() >= MAX_ADD_PATH_JOINED {
            return Err(TransitError::FieldTooLong);
        }
        return Ok(format!("{last}{cur}"));
    }
    if cur.ends_with('.') {
        if cur.len() + last.len() >= MAX_ADD_PATH_JOINED {
            return Err(TransitError::FieldTooLong);
        }
        return Ok(format!("{cur}{last}"));
    }
    Ok(cur.to_owned())
}

fn escape_transit_realm(realm: &str) -> String {
    let mut out = String::with_capacity(realm.len());
    for c in realm.chars() {
        if c == '\\' || c == ',' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

// MIT krb5_check_transited_list; see docs/parity/b1-client.md
fn expand_domain_x500(raw: &[u8], crealm: &str, srealm: &str) -> Result<Vec<String>, TransitError> {
    let raw = strip_trailing_nul(raw);
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let mut commas = 0usize;
    for &b in raw {
        if b == b',' {
            commas += 1;
            if commas > MAX_TRANSIT_REALMS {
                return Err(TransitError::TooManyFields);
            }
        }
    }
    let s = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    let mut last = String::new();
    let mut cur = String::new();
    let mut escaped = false;
    let mut intermediates = false;
    let mut at_start = true;
    for c in s.chars() {
        if escaped {
            cur.push(c);
            escaped = false;
            at_start = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            ',' => {
                if cur.is_empty() {
                    intermediates = true;
                    if at_start {
                        if crealm.len() >= MAX_TRANSIT_RAW {
                            return Err(TransitError::FieldTooLong);
                        }
                        crealm.clone_into(&mut last);
                    }
                } else {
                    emit_joined(&mut out, &mut last, &mut cur, intermediates)?;
                    intermediates = false;
                }
            }
            ' ' if cur.is_empty() => last.clear(),
            _ => cur.push(c),
        }
        at_start = false;
    }
    if cur.is_empty() {
        if srealm.len() >= MAX_TRANSIT_RAW {
            return Err(TransitError::FieldTooLong);
        }
        process_intermediates(&last, srealm, &mut out)?;
    } else {
        emit_joined(&mut out, &mut last, &mut cur, intermediates)?;
    }
    Ok(out)
}

fn emit_joined(
    out: &mut Vec<String>,
    last: &mut String,
    cur: &mut String,
    intermediates: bool,
) -> Result<(), TransitError> {
    let this = maybe_join(last, cur)?;
    let Some(this) = this else {
        cur.clear();
        return Ok(());
    };
    push_hop(out, this.clone())?;
    if intermediates {
        process_intermediates(&this, last, out)?;
    }
    *last = this;
    cur.clear();
    Ok(())
}

fn maybe_join(last: &str, cur: &str) -> Result<Option<String>, TransitError> {
    if cur.is_empty() {
        return Ok(None);
    }
    if cur.len() >= MAX_TRANSIT_RAW {
        return Err(TransitError::FieldTooLong);
    }
    let expanded = if cur.starts_with('/') {
        format!("{last}{cur}")
    } else if cur.ends_with('.') {
        format!("{cur}{last}")
    } else {
        cur.to_owned()
    };
    if expanded.len() > MAX_TRANSIT_JOINED {
        return Err(TransitError::FieldTooLong);
    }
    Ok(Some(expanded))
}

fn push_hop(out: &mut Vec<String>, hop: String) -> Result<(), TransitError> {
    if out.len() >= MAX_TRANSIT_HOPS {
        return Err(TransitError::TooManyFields);
    }
    out.push(hop);
    Ok(())
}

// MIT process_intermediates; see docs/parity/a1-tgs.md
fn process_intermediates(n1: &str, n2: &str, out: &mut Vec<String>) -> Result<(), TransitError> {
    let (short, long) = if n1.len() > n2.len() {
        (n2, n1)
    } else {
        (n1, n2)
    };
    if short.len() == long.len() {
        return if short == long {
            Ok(())
        } else {
            Err(TransitError::BadIntermediates)
        };
    }
    if short.is_empty() {
        return Err(TransitError::BadIntermediates);
    }
    let sb = short.as_bytes();
    let lb = long.as_bytes();
    if sb[0] == b'/' {
        if lb[0] != b'/' || !long.starts_with(short) {
            return Err(TransitError::BadIntermediates);
        }
        for i in (short.len() + 1)..long.len() {
            if lb[i] == b'/' {
                push_hop(out, long[..i].to_owned())?;
            }
        }
    } else {
        if lb[0] == b'/' || !long.ends_with(short) {
            return Err(TransitError::BadIntermediates);
        }
        let mut i = long.len() - short.len() - 1;
        while i > 0 {
            if lb[i - 1] == b'.' {
                push_hop(out, long[i..].to_owned())?;
            }
            i -= 1;
        }
    }
    Ok(())
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 3)))]
pub struct EncTicketPart {
    #[rasn(tag(explicit(0)))]
    pub flags: TicketFlags,
    #[rasn(tag(explicit(1)))]
    pub key: EncryptionKey,
    #[rasn(tag(explicit(2)))]
    pub crealm: Realm,
    #[rasn(tag(explicit(3)))]
    pub cname: PrincipalName,
    #[rasn(tag(explicit(4)))]
    pub transited: TransitedEncoding,
    #[rasn(tag(explicit(5)))]
    pub authtime: KerberosTime,
    #[rasn(tag(explicit(6)))]
    pub starttime: Option<KerberosTime>,
    #[rasn(tag(explicit(7)))]
    pub endtime: KerberosTime,
    #[rasn(tag(explicit(8)))]
    pub renew_till: Option<KerberosTime>,
    #[rasn(tag(explicit(9)))]
    pub caddr: Option<HostAddresses>,
    #[rasn(tag(explicit(10)))]
    pub authorization_data: Option<AuthorizationData>,
}

#[cfg(test)]
mod tests;
