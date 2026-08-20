//! RFC 4120 Kerberos V5 owned protocol types.
//!
//! Types carry rasn `Encode`/`Decode` derives. Tagging matches the ASN.1 in
//! RFC 4120 (EXPLICIT context tags, APPLICATION tags on the PDUs). This crate
//! does not perform I/O; see `krb5-asn1` for DER helpers and error mapping.
//!
//! Field meanings are those of RFC 4120. Comments here capture invariants
//! that the codec itself cannot express (APPLICATION numbers, OPTIONAL
//! presence).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use chrono::{FixedOffset, NaiveDateTime, TimeZone, Timelike, Utc};
use rasn::prelude::*;
use zeroize::Zeroize;

pub use rasn::types::{BitString, GeneralizedTime, OctetString};

mod constants;
pub mod extra;
pub mod fast;
mod name_error;
pub mod pac;
pub mod pkinit;
pub mod s4u;
pub mod spake;

pub use constants::{ap_bit, err, flag_bit, ku, pa};
pub use extra::{
    ApRep, EncApRepPart, EncKrbCredPart, EncKrbPrivPart, KrbCred, KrbCredInfo, KrbPriv, KrbSafe,
    KrbSafeBody,
};
pub use name_error::{NameError, TimeError};

/// Construct a [`KerberosString`] from ASCII / GeneralString text.
///
/// # Panics
///
/// Panics if `s` contains characters outside the GeneralString alphabet.
/// Callers that take untrusted input must use [`try_ascii`].
#[must_use]
#[allow(clippy::expect_used)]
pub fn ascii(s: &str) -> KerberosString {
    KerberosString::try_from(s).expect("KerberosString requires the GeneralString alphabet")
}

/// Fallible [`KerberosString`] from untrusted text.
///
/// # Errors
///
/// Returns [`NameError`] when `s` is not a GeneralString.
pub fn try_ascii(s: &str) -> Result<KerberosString, NameError> {
    if !s.is_ascii() {
        return Err(NameError::NotGeneralString);
    }
    KerberosString::try_from(s).map_err(|_| NameError::NotGeneralString)
}

/// Fallible [`KerberosString`] from untrusted bytes (keytab/ccache/wire).
///
/// # Errors
///
/// Returns [`NameError`] when the bytes are not UTF-8 GeneralString.
pub fn kerberos_string_from_bytes(bytes: &[u8]) -> Result<KerberosString, NameError> {
    let s = std::str::from_utf8(bytes).map_err(|_| NameError::NotUtf8)?;
    try_ascii(s)
}

/// KerberosString ::= GeneralString (IA5String in RFC 4120).
pub type KerberosString = GeneralString;
/// A realm name. Together with [`PrincipalName`] this identifies a principal.
pub type Realm = KerberosString;
/// HostAddresses ::= SEQUENCE OF HostAddress
pub type HostAddresses = SequenceOf<HostAddress>;
/// AuthorizationData ::= SEQUENCE OF SEQUENCE { ad-type, ad-data }
pub type AuthorizationData = SequenceOf<AuthorizationDataValue>;
/// METHOD-DATA ::= SEQUENCE OF PA-DATA
pub type MethodData = SequenceOf<PaData>;
/// KerberosFlags ::= BIT STRING (SIZE (32..MAX))
pub type KerberosFlags = BitString;
/// Microseconds ::= INTEGER (0..999999)
#[derive(AsnType, Clone, Copy, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct Microseconds(pub u32);

impl Microseconds {
    /// Inclusive lower bound.
    pub const MIN: u32 = 0;
    /// Inclusive upper bound (RFC 4120).
    pub const MAX: u32 = 999_999;
    /// Zero microseconds.
    pub const ZERO: Self = Self(0);

    /// Construct a constrained microseconds value.
    ///
    /// # Errors
    ///
    /// Returns [`TimeError::MicrosecondsOutOfRange`] when `n > 999999`.
    pub fn new(n: u32) -> Result<Self, TimeError> {
        if n > Self::MAX {
            Err(TimeError::MicrosecondsOutOfRange(n))
        } else {
            Ok(Self(n))
        }
    }

    /// Reduce `n` into `0..1000000` (subsecond micros from a clock).
    #[must_use]
    pub fn from_subsec_micros(n: u32) -> Self {
        Self(n % 1_000_000)
    }

    /// Numeric value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Reject out-of-range values decoded from the wire.
    ///
    /// # Errors
    ///
    /// Returns [`TimeError::MicrosecondsOutOfRange`] when the stored integer
    /// is greater than 999999.
    pub fn validate(self) -> Result<Self, TimeError> {
        Self::new(self.0)
    }
}

/// RFC 4120 `KerberosTime` (GeneralizedTime, UTC, no fractions).
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct KerberosTime(pub GeneralizedTime);

/// Principal name: type hint plus name-string components.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PrincipalName {
    /// Name type (RFC 4120 §6.2). Treat as a hint.
    #[rasn(tag(explicit(0)))]
    pub name_type: i32,
    /// Name components. `rasn-kerberos` used `string`; RFC 4120 field is
    /// `name-string`.
    #[rasn(tag(explicit(1)))]
    pub name_string: SequenceOf<KerberosString>,
}

impl PrincipalName {
    /// NT-UNKNOWN (0).
    pub const NT_UNKNOWN: i32 = 0;
    /// NT-PRINCIPAL (1).
    pub const NT_PRINCIPAL: i32 = 1;
    /// NT-SRV-INST (2).
    pub const NT_SRV_INST: i32 = 2;
    /// NT-SRV-HST (3).
    pub const NT_SRV_HST: i32 = 3;

    /// Build a principal from a name type and GeneralString components.
    ///
    /// # Panics
    ///
    /// Panics if a component is outside the GeneralString alphabet.
    /// Untrusted input must use [`Self::try_new`].
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn new(name_type: i32, parts: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self::try_new(name_type, parts).expect("KerberosString requires the GeneralString alphabet")
    }

    /// Fallible principal constructor for untrusted components.
    ///
    /// # Errors
    ///
    /// Returns [`NameError`] when a component is not a GeneralString.
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

    /// Fallible constructor from untrusted UTF-8 / GeneralString bytes.
    ///
    /// # Errors
    ///
    /// Returns [`NameError`] when a component is not UTF-8 GeneralString.
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

    /// `krbtgt/REALM` as NT-SRV-INST.
    #[must_use]
    pub fn krbtgt(realm: &str) -> Self {
        Self::new(Self::NT_SRV_INST, ["krbtgt", realm])
    }

    /// Name-string components joined with `/` (`user`, `host/foo`).
    #[must_use]
    pub fn components_joined(&self) -> String {
        self.name_string
            .iter()
            .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
            .collect::<Vec<_>>()
            .join("/")
    }

    /// RFC 4120 default salt: realm concatenated with name components.
    #[must_use]
    pub fn default_salt(&self, realm: &str) -> Vec<u8> {
        let mut salt = realm.as_bytes().to_vec();
        for part in &self.name_string {
            salt.extend_from_slice(part.as_bytes());
        }
        salt
    }

    /// Whether this name is `krbtgt/SOMETHING` (TGT / referral TGT).
    #[must_use]
    pub fn is_krbtgt(&self) -> bool {
        self.name_string
            .first()
            .is_some_and(|p| p.as_bytes() == b"krbtgt")
    }

    /// Whether this is `krbtgt/{realm}` for `realm`.
    #[must_use]
    pub fn is_krbtgt_for(&self, realm: &str) -> bool {
        self.name_string.len() == 2
            && self.name_string[0].as_bytes() == b"krbtgt"
            && self.name_string[1].as_bytes() == realm.as_bytes()
    }
}

/// Network address of a host.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct HostAddress {
    #[rasn(tag(explicit(0)))]
    pub addr_type: i32,
    #[rasn(tag(explicit(1)))]
    pub address: OctetString,
}

/// One authorization-data element.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct AuthorizationDataValue {
    #[rasn(tag(explicit(0)))]
    pub ad_type: i32,
    #[rasn(tag(explicit(1)))]
    pub ad_data: OctetString,
}

/// Pre-authentication data.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaData {
    #[rasn(tag(explicit(1)))]
    pub padata_type: i32,
    #[rasn(tag(explicit(2)))]
    pub padata_value: OctetString,
}

/// Encrypted blob: etype, optional kvno, ciphertext.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct EncryptedData {
    #[rasn(tag(explicit(0)))]
    pub etype: i32,
    #[rasn(tag(explicit(1)))]
    pub kvno: Option<u32>,
    #[rasn(tag(explicit(2)))]
    pub cipher: OctetString,
}

/// EncryptionKey ::= SEQUENCE { keytype, keyvalue }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct EncryptionKey {
    /// IANA etype of [`Self::keyvalue`].
    #[rasn(tag(explicit(0)))]
    pub keytype: i32,
    /// Protocol key octets. Wiped on drop when the buffer is uniquely owned.
    #[rasn(tag(explicit(1)))]
    pub keyvalue: OctetString,
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        let mut v = self.keyvalue.to_vec();
        v.zeroize();
        self.keyvalue = OctetString::from(Vec::<u8>::new());
    }
}

/// Checksum ::= SEQUENCE { cksumtype, checksum }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct Checksum {
    #[rasn(tag(explicit(0)))]
    pub cksumtype: i32,
    #[rasn(tag(explicit(1)))]
    pub checksum: OctetString,
}

/// Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno, realm, sname, enc-part }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
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
    /// RFC 4120 ticket version number.
    pub const VNO: i32 = 5;
}

/// TicketFlags ::= KerberosFlags
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct TicketFlags(pub KerberosFlags);

impl TicketFlags {
    /// 32 zero bits. KerberosFlags SIZE (32..MAX).
    #[must_use]
    pub fn none() -> Self {
        Self(KerberosFlags::repeat(false, 32))
    }

    /// INITIAL (bit 9) and PRE-AUTHENT (bit 10) as issued after PA-ENC-TIMESTAMP.
    ///
    /// RFC 4120 §5.3: renewable is bit 8, initial is bit 9, pre-authent is bit 10.
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

    /// Whether RFC bit `n` is set.
    #[must_use]
    pub fn bit(&self, n: usize) -> bool {
        n < self.0.len() && self.0[n]
    }

    /// RFC 4120 `initial` (bit 9).
    #[must_use]
    pub fn initial(&self) -> bool {
        self.bit(flag_bit::INITIAL)
    }

    /// RFC 4120 `pre-authent` (bit 10).
    #[must_use]
    pub fn pre_authent(&self) -> bool {
        self.bit(flag_bit::PRE_AUTHENT)
    }

    /// RFC 4120 `renewable` (bit 8).
    #[must_use]
    pub fn renewable(&self) -> bool {
        self.bit(flag_bit::RENEWABLE)
    }

    /// RFC 4120 `forwardable` (bit 1).
    #[must_use]
    pub fn forwardable(&self) -> bool {
        self.bit(flag_bit::FORWARDABLE)
    }

    /// RFC 4120 `invalid` (bit 7).
    #[must_use]
    pub fn invalid(&self) -> bool {
        self.bit(flag_bit::INVALID)
    }

    /// Set RFC bit `n`.
    #[must_use]
    pub fn with_bit(mut self, n: usize, on: bool) -> Self {
        if n < self.0.len() {
            self.0.set(n, on);
        }
        self
    }
}

/// KDCOptions ::= KerberosFlags
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct KdcOptions(pub KerberosFlags);

impl KdcOptions {
    /// 32 zero bits.
    #[must_use]
    pub fn none() -> Self {
        Self(KerberosFlags::repeat(false, 32))
    }

    /// Set RFC 4120 bit 1 (forwardable).
    #[must_use]
    pub fn forwardable() -> Self {
        Self::none().with_bit(flag_bit::FORWARDABLE, true)
    }

    /// Whether RFC bit `n` is set.
    #[must_use]
    pub fn bit(&self, n: usize) -> bool {
        n < self.0.len() && self.0[n]
    }

    /// Set RFC bit `n`.
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

    /// Bits that this implementation honors on AS/TGS requests.
    #[must_use]
    pub fn unsupported_bits(&self) -> u32 {
        let supported = (1u32 << (31 - flag_bit::FORWARDABLE))
            | (1u32 << (31 - flag_bit::FORWARDED))
            | (1u32 << (31 - flag_bit::PROXIABLE))
            | (1u32 << (31 - flag_bit::PROXY))
            | (1u32 << (31 - flag_bit::MAY_POSTDATE))
            | (1u32 << (31 - flag_bit::POSTDATED))
            | (1u32 << (31 - flag_bit::RENEWABLE))
            | (1u32 << (31 - flag_bit::CNAME_IN_ADDL_TKT))
            | (1u32 << (31 - flag_bit::CANONICALIZE))
            | (1u32 << (31 - flag_bit::DISABLE_TRANSITED_CHECK))
            | (1u32 << (31 - flag_bit::RENEWABLE_OK))
            | (1u32 << (31 - flag_bit::ENC_TKT_IN_SKEY))
            | (1u32 << (31 - flag_bit::RENEW))
            | (1u32 << (31 - flag_bit::VALIDATE));
        self.to_u32() & !supported
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

/// KDC-REQ (untagged). AS-REQ is APPLICATION 10 wrapping this SEQUENCE.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
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
    /// Protocol version.
    pub const PVNO: i32 = 5;
    /// AS-REQ msg-type.
    pub const MSG_AS_REQ: i32 = 10;
    /// TGS-REQ msg-type.
    pub const MSG_TGS_REQ: i32 = 12;
}

/// Remainder of a KDC-REQ; checksums over this field.
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

/// AS-REQ ::= [APPLICATION 10] KDC-REQ
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 10)), delegate)]
pub struct AsReq(pub KdcReq);

/// KDC-REP (untagged). AS-REP is APPLICATION 11 wrapping this SEQUENCE.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
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
    /// Protocol version.
    pub const PVNO: i32 = 5;
    /// AS-REP msg-type.
    pub const MSG_AS_REP: i32 = 11;
    /// TGS-REP msg-type.
    pub const MSG_TGS_REP: i32 = 13;
}

/// AS-REP ::= [APPLICATION 11] KDC-REP
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 11)), delegate)]
pub struct AsRep(pub KdcRep);

/// AP-REQ ::= [APPLICATION 14] SEQUENCE { pvno, msg-type, ap-options, ticket, authenticator }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
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
    /// Protocol version.
    pub const PVNO: i32 = 5;
    /// AP-REQ msg-type.
    pub const MSG_TYPE: i32 = 14;
}

/// APOptions ::= KerberosFlags
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(delegate)]
pub struct ApOptions(pub KerberosFlags);

impl ApOptions {
    /// 32 zero bits.
    #[must_use]
    pub fn none() -> Self {
        Self(KerberosFlags::repeat(false, 32))
    }

    /// MUTUAL-REQUIRED (RFC 4120 bit 2).
    #[must_use]
    pub fn mutual_required() -> Self {
        let mut bits = KerberosFlags::repeat(false, 32);
        bits.set(ap_bit::MUTUAL_REQUIRED, true);
        Self(bits)
    }

    /// Whether RFC bit `n` is set.
    #[must_use]
    pub fn bit(&self, n: usize) -> bool {
        n < self.0.len() && self.0[n]
    }

    /// Whether `mutual-required` is set.
    #[must_use]
    pub fn wants_mutual(&self) -> bool {
        self.bit(ap_bit::MUTUAL_REQUIRED)
    }

    /// Whether `use-session-key` is set (user-to-user).
    #[must_use]
    pub fn use_session_key(&self) -> bool {
        self.bit(ap_bit::USE_SESSION_KEY)
    }
}

/// KRB-ERROR ::= [APPLICATION 30] SEQUENCE { ... }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
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
    /// Protocol version.
    pub const PVNO: i32 = 5;
    /// KRB-ERROR msg-type.
    pub const MSG_TYPE: i32 = 30;
}

/// Parse RFC 4120 UTC KerberosTime (`YYYYMMDDHHMMSSZ`).
///
/// # Errors
///
/// Returns [`TimeError::Parse`] when `s` is not that form.
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
    /// Current UTC time as KerberosTime.
    ///
    /// RFC 4120 forbids fractional seconds; nanoseconds are zeroed so DER
    /// encoding is `YYYYMMDDHHMMSSZ`.
    ///
    /// # Panics
    ///
    /// Panics only if chrono rejects UTC offset 0 (it does not).
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn now() -> Self {
        let tz = FixedOffset::east_opt(0).expect("UTC offset 0 is valid");
        let dt = Utc::now().with_timezone(&tz);
        Self(dt.with_nanosecond(0).unwrap_or(dt))
    }

    /// POSIX seconds for FILE ccache timestamps.
    #[must_use]
    pub fn unix_seconds(&self) -> u32 {
        u32::try_from(self.0.timestamp().max(0)).unwrap_or(u32::MAX)
    }

    /// Add whole hours without panicking on overflow.
    ///
    /// # Errors
    ///
    /// Returns [`TimeError::Overflow`] when the calendar cannot represent
    /// the result.
    pub fn add_hours(&self, hours: i64) -> Result<Self, TimeError> {
        let dur = chrono::TimeDelta::try_hours(hours).ok_or(TimeError::Overflow)?;
        let dt = self.0.checked_add_signed(dur).ok_or(TimeError::Overflow)?;
        Ok(Self(dt.with_nanosecond(0).unwrap_or(dt)))
    }

    /// Add whole seconds without panicking.
    ///
    /// # Errors
    ///
    /// Returns [`TimeError::Overflow`] when the calendar cannot represent
    /// the result.
    pub fn add_seconds(&self, seconds: i64) -> Result<Self, TimeError> {
        let dur = chrono::TimeDelta::try_seconds(seconds).ok_or(TimeError::Overflow)?;
        let dt = self.0.checked_add_signed(dur).ok_or(TimeError::Overflow)?;
        Ok(Self(dt.with_nanosecond(0).unwrap_or(dt)))
    }

    /// Difference in seconds (`self - other`) as i64, saturating.
    #[must_use]
    pub fn delta_seconds(&self, other: &Self) -> i64 {
        self.0.timestamp().saturating_sub(other.0.timestamp())
    }
}

/// PA-ENC-TS-ENC ::= SEQUENCE { patimestamp, pausec OPTIONAL }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaEncTsEnc {
    #[rasn(tag(explicit(0)))]
    pub patimestamp: KerberosTime,
    #[rasn(tag(explicit(1)))]
    pub pausec: Option<Microseconds>,
}

/// ETYPE-INFO2-ENTRY
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct EtypeInfo2Entry {
    #[rasn(tag(explicit(0)))]
    pub etype: i32,
    #[rasn(tag(explicit(1)))]
    pub salt: Option<KerberosString>,
    #[rasn(tag(explicit(2)))]
    pub s2kparams: Option<OctetString>,
}

/// ETYPE-INFO2 ::= SEQUENCE OF ETYPE-INFO2-ENTRY
pub type EtypeInfo2 = SequenceOf<EtypeInfo2Entry>;

/// ETYPE-INFO-ENTRY (legacy PA-ETYPE-INFO).
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct EtypeInfoEntry {
    #[rasn(tag(explicit(0)))]
    pub etype: i32,
    #[rasn(tag(explicit(1)))]
    pub salt: Option<OctetString>,
}

/// ETYPE-INFO ::= SEQUENCE OF ETYPE-INFO-ENTRY
pub type EtypeInfo = SequenceOf<EtypeInfoEntry>;

/// LastReq element.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct LastReqValue {
    #[rasn(tag(explicit(0)))]
    pub lr_type: i32,
    #[rasn(tag(explicit(1)))]
    pub lr_value: KerberosTime,
}

/// EncKDCRepPart ::= SEQUENCE { key, last-req, nonce, ... }
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

/// EncASRepPart ::= [APPLICATION 25] EncKDCRepPart
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 25)), delegate)]
pub struct EncAsRepPart(pub EncKdcRepPart);

/// EncTGSRepPart ::= [APPLICATION 26] EncKDCRepPart
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 26)), delegate)]
pub struct EncTgsRepPart(pub EncKdcRepPart);

/// Authenticator ::= [APPLICATION 2] SEQUENCE { ... }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 2)))]
pub struct Authenticator {
    #[rasn(tag(explicit(0)))]
    pub authenticator_vno: i32,
    #[rasn(tag(explicit(1)))]
    pub crealm: Realm,
    #[rasn(tag(explicit(2)))]
    pub cname: PrincipalName,
    #[rasn(tag(explicit(3)))]
    pub cksum: Option<Checksum>,
    #[rasn(tag(explicit(4)))]
    pub cusec: Microseconds,
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
    /// Authenticator version.
    pub const VNO: i32 = 5;
}

/// TGS-REQ ::= [APPLICATION 12] KDC-REQ
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 12)), delegate)]
pub struct TgsReq(pub KdcReq);

/// TGS-REP ::= [APPLICATION 13] KDC-REP
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 13)), delegate)]
pub struct TgsRep(pub KdcRep);

/// TransitedEncoding ::= SEQUENCE { tr-type, contents }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct TransitedEncoding {
    #[rasn(tag(explicit(0)))]
    pub tr_type: i32,
    #[rasn(tag(explicit(1)))]
    pub contents: OctetString,
}

impl TransitedEncoding {
    /// Empty encoding (type 0, no realms).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            tr_type: 0,
            contents: OctetString::from(Vec::<u8>::new()),
        }
    }

    /// Local profile: `tr-type` 1, comma-separated realm names (not X.500 compress).
    #[must_use]
    pub fn from_realms(realms: &[&str]) -> Self {
        let s = realms.join(",");
        Self {
            tr_type: 1,
            contents: OctetString::from(s.into_bytes()),
        }
    }

    /// Realm names encoded in [`Self::from_realms`].
    #[must_use]
    pub fn realms(&self) -> Vec<String> {
        let s = String::from_utf8_lossy(self.contents.as_ref());
        s.split(',')
            .filter(|r| !r.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// Append `realm` if it is not already present.
    #[must_use]
    pub fn with_realm(&self, realm: &str) -> Self {
        let mut rs = self.realms();
        if !rs.iter().any(|r| r == realm) {
            rs.push(realm.to_owned());
        }
        let refs: Vec<&str> = rs.iter().map(String::as_str).collect();
        Self::from_realms(&refs)
    }
}

/// EncTicketPart ::= [APPLICATION 3] SEQUENCE { flags, key, crealm, ... }
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
mod tests {
    use super::*;

    #[test]
    fn ticket_flags_initial_preauth_is_rfc_bits_9_and_10() {
        let f = TicketFlags::initial_preauth();
        assert!(f.initial(), "bit 9 initial");
        assert!(f.pre_authent(), "bit 10 pre-authent");
        assert!(!f.renewable(), "must not set renewable (bit 8)");
        // MIT packed: bit 9 => 1<<22, bit 10 => 1<<21
        assert_eq!(f.to_u32(), 0x0060_0000);
        let round = TicketFlags::from_u32(0x0060_0000);
        assert!(round.initial() && round.pre_authent() && !round.renewable());
    }

    #[test]
    fn microseconds_rejects_out_of_range() {
        assert!(Microseconds::new(0).is_ok());
        assert!(Microseconds::new(999_999).is_ok());
        assert_eq!(
            Microseconds::new(1_000_000).unwrap_err(),
            TimeError::MicrosecondsOutOfRange(1_000_000)
        );
        assert_eq!(Microseconds::from_subsec_micros(1_000_042).get(), 42);
        assert!(Microseconds(1_000_001).validate().is_err());
    }

    #[test]
    fn add_hours_does_not_panic_on_overflow() {
        let t = kerberos_time_from_utc_z("99991231235959Z").expect("max");
        assert_eq!(t.add_hours(i64::MAX).unwrap_err(), TimeError::Overflow);
        let now = KerberosTime::now();
        assert!(now.add_hours(10).is_ok());
    }

    #[test]
    fn try_new_rejects_non_ascii_principal() {
        let err = PrincipalName::try_new(1, ["usér"]).unwrap_err();
        assert_eq!(err, NameError::NotGeneralString);
        let err = kerberos_string_from_bytes(&[0x80, 0x81]).unwrap_err();
        assert_eq!(err, NameError::NotUtf8);
    }

    #[test]
    fn ap_options_mutual_required_is_bit_2() {
        let o = ApOptions::mutual_required();
        assert!(o.wants_mutual());
        assert!(!o.use_session_key());
        assert!(!ApOptions::none().wants_mutual());
    }

    #[test]
    fn krbtgt_name_helpers() {
        let t = PrincipalName::krbtgt("KERBER.TEST");
        assert!(t.is_krbtgt());
        assert!(t.is_krbtgt_for("KERBER.TEST"));
        assert!(!t.is_krbtgt_for("OTHER.TEST"));
        let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "x"]);
        assert!(!host.is_krbtgt());
    }

    #[test]
    fn transited_csv_round_trip() {
        let t = TransitedEncoding::empty()
            .with_realm("A.TEST")
            .with_realm("B.TEST");
        assert_eq!(t.realms(), vec!["A.TEST".to_string(), "B.TEST".to_string()]);
        assert_eq!(t.with_realm("A.TEST").realms().len(), 2);
    }

    #[test]
    fn pac_ndr_logon_info_round_trip() {
        let raw = pac::logon_info_buffer("user", "KERBER.TEST");
        let (c, r) = pac::parse_logon_info(&raw).expect("NDR parse");
        assert_eq!(c, "user");
        assert_eq!(r, "KERBER.TEST");
    }

    #[test]
    fn pkinit_cms_wrap_unwrap() {
        let inner = b"authpack-bytes";
        let wrapped = pkinit::cms_wrap(inner);
        assert_ne!(wrapped, inner);
        assert_eq!(pkinit::cms_unwrap(&wrapped), inner);
        assert_eq!(pkinit::cms_unwrap(inner), inner);
        assert_eq!(
            pkinit::cms_verify(&wrapped).expect("cert-backed ECDSA"),
            inner
        );
        let mut bad = wrapped.clone();
        if let Some(b) = bad.last_mut() {
            *b ^= 0x01;
        }
        assert!(pkinit::cms_verify(&bad).is_err());
    }
}
