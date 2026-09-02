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
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
    ApRep, ChangePasswdData, EncApRepPart, EncKrbCredPart, EncKrbPrivPart, KrbCred, KrbCredInfo,
    KrbPriv, KrbSafe, KrbSafeBody,
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
    /// NT-ENTERPRISE (10), RFC 6806. One component, typically `user@REALM`.
    pub const NT_ENTERPRISE: i32 = 10;

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
        self.name_string.len() == 2
            && self
                .name_string
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

    /// RFC 4120 `proxiable` (bit 3).
    #[must_use]
    pub fn proxiable(&self) -> bool {
        self.bit(flag_bit::PROXIABLE)
    }

    /// MIT `klist -f` flag letters (same order as MIT 1.22.2).
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

    /// Inverse of [`Self::unix_seconds`].
    ///
    /// # Panics
    ///
    /// Panics only if chrono rejects UTC offset 0 (it does not).
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn from_unix_seconds(s: u32) -> Self {
        let tz = FixedOffset::east_opt(0).expect("UTC offset 0 is valid");
        let utc = chrono::DateTime::from_timestamp(i64::from(s), 0).unwrap_or_else(Utc::now);
        let dt = utc.with_timezone(&tz);
        Self(dt.with_nanosecond(0).unwrap_or(dt))
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

/// DOMAIN-X500-COMPRESS expansion failure (`chk_trans.c` / Rust comma cap).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransitError {
    /// Check-path raw ≥ 512 or joined > 512; add-path raw ≥ 500, joined ≥ 499,
    /// or rebuilt encoding ≥ 500 (MIT `MAX_REALM_LN`).
    #[error("transited field too long")]
    FieldTooLong,
    /// More than 256 commas, or more than [`MAX_TRANSIT_HOPS`] emitted hops
    /// (Rust-STRICTER; MIT has no field-count or hop cap).
    #[error("too many transited fields")]
    TooManyFields,
    /// Null-subfield neighbours are mixed X.500/domain or non-hierarchical.
    #[error("transited intermediates invalid")]
    BadIntermediates,
}

impl TransitedEncoding {
    /// Empty DOMAIN-X500-COMPRESS encoding (MIT AS `tr_type = 1`).
    #[must_use]
    pub fn empty() -> Self {
        Self::from_realms(&[])
    }

    /// DOMAIN-X500-COMPRESS (`tr-type` 1): comma-separated DNS realms matching
    /// MIT KDC `add_to_transited` for domain-style names (no trailing comma).
    /// Standalone X.500 realms encode as `/A, /B` (space before a `/` hop).
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

    /// Realm names in `contents`. `tr-type` 1 is RFC 4120 §3.3.3.2
    /// DOMAIN-X500-COMPRESS. MIT `chk_trans.c`: strip one trailing NUL;
    /// raw field ≥ 512 or joined > 512 is an error; join on unescaped
    /// text; null subfields seed `crealm`/`srealm` and emit hierarchical
    /// intermediates (`process_intermediates`). More than 256 raw commas
    /// (including escaped `\,`) or [`MAX_TRANSIT_HOPS`] emitted hops is a
    /// Rust-STRICTER error. Encode stays uncompressed ([`Self::from_realms`]).
    ///
    /// # Errors
    ///
    /// Bound or structure failure. A lone NUL is the empty list, not an error.
    pub fn realms_for(&self, crealm: &str, srealm: &str) -> Result<Vec<String>, TransitError> {
        expand_domain_x500(self.contents.as_ref(), crealm, srealm)
    }

    /// Append `realm` onto the original contents (MIT `add_to_transited`:
    /// add-path tokenizer, trailing-comma drop, space before `/`, appended
    /// length ≤ 499). Escapes `\\` and `,` in `realm`. Does not
    /// expand-then-rejoin. `crealm`/`srealm` are unused (no null-subfields).
    /// No-append paths (validate / already-present hop) still reject a
    /// stripped inbound ≥ 500.
    ///
    /// # Errors
    ///
    /// Inbound add-path bound failure, or appended encoding ≥ 500.
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

    /// Validate inbound with the add-path tokenizer (no append).
    ///
    /// # Errors
    ///
    /// Add-path raw ≥ 500 or joined ≥ 499.
    pub fn validate_add_path(&self) -> Result<(), TransitError> {
        expand_add_path(self.contents.as_ref()).map(|_| ())
    }
}

/// Cap on comma-separated transited fields. Rust-STRICTER than MIT.
pub const MAX_TRANSIT_REALMS: usize = 256;
/// Cap on hops emitted by DOMAIN-X500-COMPRESS expansion. MIT streams
/// `process_intermediates` callbacks at O(1) memory; Rust materializes
/// the list. 4096 is ~100× any honest path and bounds allocation.
pub const MAX_TRANSIT_HOPS: usize = 4096;
/// MIT `chk_trans.c` `MAXLEN`. Writing the 512th raw unescaped byte errors.
pub const MAX_TRANSIT_RAW: usize = 512;
/// MIT `maybe_join`: `last + cur > 512` errors; joined of 512 is accepted.
const MAX_TRANSIT_JOINED: usize = 512;
/// MIT `kdc_transit.c` `MAX_REALM_LN`. Raw field of 500 unescaped bytes errors.
const MAX_ADD_PATH_RAW: usize = 500;
/// MIT `strlen(exp)+strlen(x)+1 >= 500`: joined ≥ 499 errors.
const MAX_ADD_PATH_JOINED: usize = 499;
/// MIT `strlcat` into a 500-byte buffer: rebuilt encoding ≥ 500 errors.
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
        assert_eq!(round.mit_letters(), "IA");
        let fwd = TicketFlags::none().with_bit(flag_bit::FORWARDABLE, true);
        assert_eq!(fwd.mit_letters(), "F");
        let ha = TicketFlags::none()
            .with_bit(flag_bit::HW_AUTHENT, true)
            .with_bit(flag_bit::PRE_AUTHENT, true);
        assert_eq!(ha.mit_letters(), "HA");
        let anon = TicketFlags::none().with_bit(flag_bit::ANONYMOUS, true);
        assert_eq!(anon.mit_letters(), "a");
    }

    #[test]
    fn is_krbtgt_requires_two_components() {
        let two = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", "KERBER.TEST"]);
        assert!(two.is_krbtgt());
        let three = PrincipalName::new(
            PrincipalName::NT_SRV_INST,
            ["krbtgt", "KERBER.TEST", "extra"],
        );
        assert!(!three.is_krbtgt());
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
        let flat = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["krbtgt/KERBER.TEST"]);
        assert_eq!(t.components_joined(), flat.components_joined());
        assert_ne!(t.name_string, flat.name_string);
    }

    fn te(contents: &[u8]) -> TransitedEncoding {
        TransitedEncoding {
            tr_type: 1,
            contents: OctetString::from(contents.to_vec()),
        }
    }

    fn hops(contents: &[u8]) -> Vec<String> {
        te(contents).realms_for("", "").expect("expand")
    }

    #[test]
    fn transited_csv_round_trip() {
        let t = TransitedEncoding::empty()
            .append_realm("A.TEST", "", "")
            .unwrap()
            .append_realm("B.TEST", "", "")
            .unwrap();
        assert_eq!(
            t.realms_for("", "").unwrap(),
            vec!["A.TEST".to_string(), "B.TEST".to_string()]
        );
        assert_eq!(
            t.append_realm("A.TEST", "", "")
                .unwrap()
                .realms_for("", "")
                .unwrap()
                .len(),
            2
        );
        assert_eq!(t.tr_type, 1);
        assert_eq!(TransitedEncoding::empty().tr_type, 1);
    }

    #[test]
    fn transited_x500_expand_mit_live_fixture() {
        // Live MIT 1.22.2 4-hop A.EX.COM→EX.COM→B.EX.COM→C.EX.COM issued
        // tr-type 1 contents "EX.COM,B." (captured s2-live-compress.log).
        assert_eq!(
            hops(b"EX.COM,B."),
            vec!["EX.COM".to_string(), "B.EX.COM".to_string()]
        );
    }

    #[test]
    fn transited_x500_expand_rfc4120_example() {
        assert_eq!(
            hops(b"EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS."),
            vec![
                "EDU".to_string(),
                "MIT.EDU".to_string(),
                "ATHENA.MIT.EDU".to_string(),
                "WASHINGTON.EDU".to_string(),
                "CS.WASHINGTON.EDU".to_string(),
            ]
        );
    }

    #[test]
    fn transited_x500_overlong_is_err() {
        let spam = te(&vec![b','; 20_000]);
        assert_eq!(
            spam.realms_for("", "").unwrap_err(),
            TransitError::TooManyFields
        );

        let modest = te(format!("{}X.COM", "X.COM,".repeat(199)).as_bytes());
        let hops = modest.realms_for("", "").unwrap();
        assert_eq!(hops.len(), 200);
        assert_eq!(hops[0], "X.COM");

        let mut long_field = b"X.COM,".to_vec();
        long_field.extend(vec![b'A'; 513]);
        assert_eq!(
            te(&long_field).realms_for("", "").unwrap_err(),
            TransitError::FieldTooLong,
            "≤256 commas holding a >512-byte literal field must err"
        );
    }

    #[test]
    fn transited_x500_escaped_marker_still_joins() {
        assert_eq!(
            hops(b"X.COM,C\\."),
            vec!["X.COM".to_string(), "C.X.COM".to_string()],
            "MIT maybe_join: escaped trailing . still suffix-joins"
        );
        assert_eq!(
            hops(b"X.COM,\\/Y"),
            vec!["X.COM".to_string(), "X.COM/Y".to_string()],
            "MIT maybe_join: escaped leading / still prefix-joins"
        );
        assert_eq!(
            hops(b"X.COM,/Y"),
            vec!["X.COM".to_string(), "X.COM/Y".to_string()],
            "unescaped leading / still prefix-joins"
        );
    }

    #[test]
    fn transited_x500_bounds_nul_and_append() {
        assert_eq!(hops(&vec![b'A'; 511]), vec!["A".repeat(511)]);
        assert_eq!(
            te(&vec![b'A'; 512]).realms_for("", "").unwrap_err(),
            TransitError::FieldTooLong
        );
        assert_eq!(
            te(b",").realms_for("A.TEST", &"A".repeat(512)).unwrap_err(),
            TransitError::FieldTooLong
        );

        let mut joined_ok = b"X,".to_vec();
        joined_ok.extend(vec![b'B'; 510]);
        joined_ok.push(b'.');
        assert_eq!(
            hops(&joined_ok),
            vec!["X".to_string(), format!("{}.X", "B".repeat(510))]
        );

        let mut joined_err = b"XX,".to_vec();
        joined_err.extend(vec![b'B'; 510]);
        joined_err.push(b'.');
        assert_eq!(
            te(&joined_err).realms_for("", "").unwrap_err(),
            TransitError::FieldTooLong
        );

        assert_eq!(hops(b"EDU\0"), vec!["EDU".to_string()]);
        assert!(te(b"\0").realms_for("", "").unwrap().is_empty());

        let x500 = te(b"/COM,/HP").append_realm("X", "", "").unwrap();
        assert_eq!(x500.contents.as_ref(), b"/COM,/HP,X");
        assert_eq!(
            x500.realms_for("", "").unwrap(),
            vec!["/COM".to_string(), "/COM/HP".to_string(), "X".to_string()]
        );

        let spaced = te(b"/COM,/HP").append_realm("/EDU/W", "", "").unwrap();
        assert_eq!(spaced.contents.as_ref(), b"/COM,/HP, /EDU/W");
        assert_eq!(
            spaced.realms_for("", "").unwrap(),
            vec![
                "/COM".to_string(),
                "/COM/HP".to_string(),
                "/EDU/W".to_string()
            ]
        );
    }

    #[test]
    fn transited_mit_transit_tests_vectors() {
        fn set(xs: &[&str]) -> std::collections::BTreeSet<String> {
            xs.iter().map(|s| (*s).to_string()).collect()
        }
        fn got(crealm: &str, srealm: &str, transit: &[u8]) -> std::collections::BTreeSet<String> {
            te(transit)
                .realms_for(crealm, srealm)
                .expect("expand")
                .into_iter()
                .collect()
        }

        assert_eq!(
            got("ATHENA.MIT.EDU", "HACK.FOOBAR.COM", b",EDU,BLORT.COM,COM,"),
            set(&["MIT.EDU", "EDU", "BLORT.COM", "COM", "FOOBAR.COM"])
        );
        assert_eq!(got("ATHENA.MIT.EDU", "EDU", b","), set(&["MIT.EDU"]));
        assert_eq!(got("EDU", "ATHENA.MIT.EDU", b","), set(&["MIT.EDU"]));
        assert_eq!(
            got("x", "x", b"/COM,/HP,/APOLLO, /COM/DEC"),
            set(&["/COM", "/COM/HP", "/COM/HP/APOLLO", "/COM/DEC"])
        );
        assert_eq!(
            got("x", "x", b"EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS."),
            set(&[
                "EDU",
                "MIT.EDU",
                "ATHENA.MIT.EDU",
                "WASHINGTON.EDU",
                "CS.WASHINGTON.EDU"
            ])
        );
        assert_eq!(
            te(b",EDU,/COM,")
                .realms_for("ATHENA.MIT.EDU", "/COM/HP/APOLLO")
                .unwrap_err(),
            TransitError::BadIntermediates
        );
        assert_eq!(
            got("ATHENA.MIT.EDU", "/COM/HP/APOLLO", b",EDU, /COM,"),
            set(&["EDU", "MIT.EDU", "/COM", "/COM/HP"])
        );
        let edu = got("ATHENA.MIT.EDU", "CS.CMU.EDU", b",EDU,");
        assert_eq!(edu, set(&["EDU", "MIT.EDU", "CMU.EDU"]));
        assert_ne!(edu, set(&["EDU"]), ",EDU, must not be hops {{EDU}} only");
        assert_eq!(
            got("XYZZY.ATHENA.MIT.EDU", "XYZZY.CS.CMU.EDU", b",EDU,"),
            set(&["EDU", "MIT.EDU", "ATHENA.MIT.EDU", "CMU.EDU", "CS.CMU.EDU"])
        );
    }

    #[test]
    fn transited_hop_cap_is_too_many_fields() {
        // Space-clears last, emits "/", then 510 slashes with intermediates.
        // Nine cycles exceed MAX_TRANSIT_HOPS; comma count stays under 256.
        let mut cycle = b" /,,".to_vec();
        cycle.extend(std::iter::repeat_n(b'/', 510));
        cycle.push(b',');
        let buf = cycle.repeat(9);
        assert_eq!(
            te(&buf).realms_for("", "").unwrap_err(),
            TransitError::TooManyFields
        );
        assert_eq!(
            hops(b"EX.COM,B."),
            vec!["EX.COM".to_string(), "B.EX.COM".to_string()]
        );
    }

    #[test]
    fn transited_add_path_bounds() {
        let r499 = "A".repeat(499);
        assert_eq!(
            TransitedEncoding::empty()
                .append_realm(&r499, "", "")
                .unwrap()
                .contents
                .as_ref()
                .len(),
            499
        );
        assert_eq!(
            TransitedEncoding::empty()
                .append_realm(&"A".repeat(500), "", "")
                .unwrap_err(),
            TransitError::FieldTooLong
        );
        assert!(te(&vec![b'A'; 511]).realms_for("", "").is_ok());
        assert_eq!(
            te(&vec![b'A'; 512]).realms_for("", "").unwrap_err(),
            TransitError::FieldTooLong
        );
        assert_eq!(
            te(&vec![b'A'; 500]).append_realm("X", "", "").unwrap_err(),
            TransitError::FieldTooLong
        );
        assert_eq!(
            te(&vec![b'A'; 497])
                .append_realm("X", "", "")
                .unwrap()
                .contents
                .as_ref()
                .len(),
            499
        );
        assert_eq!(
            te(&vec![b'A'; 498]).append_realm("X", "", "").unwrap_err(),
            TransitError::FieldTooLong
        );

        let mut joined_ok = b"X,".to_vec();
        joined_ok.extend(vec![b'B'; 496]);
        joined_ok.push(b'.');
        te(&joined_ok)
            .append_realm("X", "", "")
            .expect("joined 498 ok");

        let mut joined_err = b"X,".to_vec();
        joined_err.extend(vec![b'B'; 497]);
        joined_err.push(b'.');
        assert_eq!(
            te(&joined_err).append_realm("X", "", "").unwrap_err(),
            TransitError::FieldTooLong
        );

        let edu = te(b"EDU,").append_realm("X", "", "").unwrap();
        assert_eq!(edu.contents.as_ref(), b"EDU,X");

        let inner = te(b"A,,B").append_realm("X", "", "").unwrap();
        assert_eq!(inner.contents.as_ref(), b"A,,B,X");

        let five = std::iter::repeat_n("A".repeat(100), 5)
            .collect::<Vec<_>>()
            .join(",");
        assert!(five.len() >= 500);
        assert_eq!(
            te(five.as_bytes()).validate_add_path().unwrap_err(),
            TransitError::FieldTooLong
        );
        let named = format!("{},B.TEST", "A".repeat(494));
        assert!(named.len() >= 500);
        assert_eq!(
            te(named.as_bytes())
                .append_realm("B.TEST", "", "")
                .unwrap_err(),
            TransitError::FieldTooLong
        );
    }

    #[test]
    fn pac_ndr_logon_info_round_trip() {
        let raw = pac::logon_info_buffer(
            "user",
            "KERBER.TEST",
            &pac::RpcSid::nt_domain(9, 8, 7),
            1000,
        );
        let (c, r) = pac::parse_logon_info(&raw).expect("NDR parse");
        assert_eq!(c, "user");
        assert_eq!(r, "KERBER.TEST");
    }

    #[test]
    fn pkinit_cms_wrap_unwrap() {
        let inner = b"authpack-bytes";
        let ca = pkinit::PkinitCa::generate().expect("CA");
        let wrapped = pkinit::cms_wrap(inner, &ca).expect("wrap");
        assert_ne!(wrapped, inner);
        assert_eq!(pkinit::cms_unwrap(&wrapped), inner);
        assert_eq!(pkinit::cms_unwrap(inner), inner);
        assert_eq!(
            pkinit::cms_verify(&wrapped, &ca.ca_cert).expect("cert-backed ECDSA"),
            inner
        );
        let mut bad = wrapped.clone();
        if let Some(b) = bad.last_mut() {
            *b ^= 0x01;
        }
        assert!(pkinit::cms_verify(&bad, &ca.ca_cert).is_err());
        assert!(ca.cert_pem().contains("BEGIN CERTIFICATE"));
        let id = ca.user_identity_pem("user@KERBER.TEST").expect("user pem");
        assert!(id.contains("BEGIN CERTIFICATE"));
        assert!(id.contains("BEGIN EC PRIVATE KEY"));
        let wrapped2 = ca.sign_cms(inner, "kdc").expect("ca cms");
        assert_eq!(
            pkinit::cms_verify(&wrapped2, &ca.ca_cert).expect("ca-backed"),
            inner
        );
        let other = pkinit::PkinitCa::generate().expect("other CA");
        assert!(
            pkinit::cms_verify(&wrapped, &other.ca_cert).is_err(),
            "forged / wrong-anchor CMS must not authenticate"
        );
        assert!(
            pkinit::cms_verify(inner, &ca.ca_cert).is_err(),
            "unwrapped plaintext is not a valid CMS"
        );
        let (cert, key) = pkinit::parse_identity_pem(&id).expect("parse identity");
        assert!(
            cert.windows(6)
                .any(|w| w == [0x2b, 0x06, 0x01, 0x05, 0x02, 0x02]),
            "client cert must carry id-pkinit-san 1.3.6.1.5.2.2"
        );
        let signed =
            pkinit::cms_sign_leaf(inner, &cert, &key, pkinit::ECONTENT_AUTHDATA).expect("leaf cms");
        assert_eq!(
            pkinit::cms_verify(&signed, &ca.ca_cert).expect("leaf verify"),
            inner
        );
        let kdc_pem = ca.kdc_identity_pem().expect("kdc pem");
        assert!(kdc_pem.contains("BEGIN CERTIFICATE"));
        assert!(kdc_pem.contains("BEGIN EC PRIVATE KEY"));
        let (kcert, kkey) = pkinit::parse_identity_pem(&kdc_pem).expect("kdc identity");
        let ksigned =
            pkinit::cms_sign_leaf(inner, &kcert, &kkey, pkinit::ECONTENT_DHKEY).expect("kdc cms");
        assert_eq!(
            pkinit::cms_verify(&ksigned, &ca.ca_cert).expect("kdc leaf verify"),
            inner
        );
        pkinit::require_kdc_pkinit_cert(&kcert, "KERBER.TEST").expect("KPKdc SAN");
        assert!(pkinit::require_kdc_pkinit_cert(&kcert, "OTHER.TEST").is_err());
        assert!(pkinit::require_kdc_pkinit_cert(&cert, "KERBER.TEST").is_err());
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        pkinit::require_client_pkinit_cert(&cert, &user, "KERBER.TEST").expect("client SAN");
        let other = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["other"]);
        assert!(pkinit::require_client_pkinit_cert(&cert, &other, "KERBER.TEST").is_err());

        let split = pkinit::cms_sign_leaf_oids(
            inner,
            &cert,
            &key,
            pkinit::ECONTENT_AUTHDATA,
            pkinit::ECONTENT_DHKEY,
        )
        .expect("split oids");
        assert_eq!(
            pkinit::cms_verify_full(&split, &ca.ca_cert).expect_err("content-type"),
            "cms content-type"
        );
        let body = b"kdc-req-body";
        let ck = pkinit::kdc_req_body_checksum(body);
        let pk_auth = pkinit::PkAuthenticator {
            cusec: Microseconds::ZERO,
            ctime: KerberosTime::now(),
            nonce: 1,
            pa_checksum: Some(ck.clone().into()),
        };
        let pack = pkinit::encode_client_authpack(&pk_auth, &pkinit::encode_ec_spki(&[0x04u8; 65]))
            .expect("authpack");
        pkinit::authpack_pa_checksum_ok(&pack, body).expect("paChecksum");
        assert!(pkinit::authpack_pa_checksum_ok(&pack, b"other-body").is_err());
        let mut ck_bad = ck;
        ck_bad[0] ^= 1;
        let pk_bad = pkinit::PkAuthenticator {
            cusec: Microseconds::ZERO,
            ctime: KerberosTime::now(),
            nonce: 1,
            pa_checksum: Some(ck_bad.into()),
        };
        let pack_bad =
            pkinit::encode_client_authpack(&pk_bad, &pkinit::encode_ec_spki(&[0x04u8; 65]))
                .expect("authpack bad");
        assert!(pkinit::authpack_pa_checksum_ok(&pack_bad, body).is_err());
    }

    #[test]
    fn pkinit_cms_path_validation() {
        let ca = pkinit::PkinitCa::generate().expect("CA");
        let inner = b"path-validation";
        let wrapped = pkinit::cms_wrap(inner, &ca).expect("wrap");
        assert_eq!(
            pkinit::cms_verify(&wrapped, &ca.ca_cert).expect("in-window chain"),
            inner
        );

        let (expired, ekey) = ca
            .client_identity_window("user@KERBER.TEST", b"200101000000Z", b"210101000000Z")
            .expect("expired");
        let cms = pkinit::cms_sign_leaf(inner, &expired, &ekey, pkinit::ECONTENT_AUTHDATA)
            .expect("expired cms");
        assert_eq!(
            pkinit::cms_verify(&cms, &ca.ca_cert).expect_err("expired"),
            "cms expired"
        );

        let (ee, ek) = pkinit::PkinitCa::self_signed_end_entity().expect("ee");
        let cms =
            pkinit::cms_sign_leaf(inner, &ee, &ek, pkinit::ECONTENT_AUTHDATA).expect("ee cms");
        assert_eq!(
            pkinit::cms_verify(&cms, &ee).expect_err("non-CA anchor"),
            "cms ca"
        );

        let (wrong, wkey) = ca
            .client_identity_wrong_issuer("user@KERBER.TEST")
            .expect("wrong issuer");
        let cms = pkinit::cms_sign_leaf(inner, &wrong, &wkey, pkinit::ECONTENT_AUTHDATA)
            .expect("wrong cms");
        assert_eq!(
            pkinit::cms_verify(&cms, &ca.ca_cert).expect_err("DN mismatch"),
            "cms chain"
        );

        let expired_ca = pkinit::PkinitCa::generate_window(b"200101000000Z", b"210101000000Z")
            .expect("expired CA");
        let cms = expired_ca.sign_cms(inner, "user").expect("expired ca cms");
        assert_eq!(
            pkinit::cms_verify(&cms, &expired_ca.ca_cert).expect_err("expired CA"),
            "cms ca expired"
        );

        let noku = pkinit::PkinitCa::generate_no_key_cert_sign().expect("no ku");
        let cms = noku.sign_cms(inner, "user").expect("no ku cms");
        assert_eq!(
            pkinit::cms_verify(&cms, &noku.ca_cert).expect_err("no keyCertSign"),
            "cms ca ku"
        );
        let absent = pkinit::PkinitCa::generate_absent_key_usage().expect("absent ku");
        let cms = absent.sign_cms(inner, "user").expect("absent ku cms");
        assert_eq!(
            pkinit::cms_verify(&cms, &absent.ca_cert).expect("RFC 5280 absent KU"),
            inner
        );

        let kcert = {
            let (c, _, _) = ca.kdc_identity_for("KERBER.TEST").expect("kdc");
            c
        };
        assert!(pkinit::require_kdc_pkinit_cert(&kcert, "kerber.test").is_err());
    }

    #[test]
    fn pa_pk_as_rep_is_choice_dhinfo() {
        let rep = pkinit::PaPkAsRep::DhInfo(pkinit::DhRepInfo {
            dh_signed_data: vec![1, 2, 3].into(),
            server_dh_nonce: None,
        });
        let der = rasn::der::encode(&rep).expect("CHOICE");
        assert_eq!(
            der.first().copied(),
            Some(0xa0),
            "PA-PK-AS-REP dhInfo is [0] EXPLICIT, not a SEQUENCE"
        );
        let back = rasn::der::decode::<pkinit::PaPkAsRep>(&der).expect("round-trip");
        match back {
            pkinit::PaPkAsRep::DhInfo(info) => assert_eq!(info.dh_signed_data.as_ref(), &[1, 2, 3]),
            pkinit::PaPkAsRep::EncKeyPack(_) => panic!("expected DhInfo"),
        }
    }

    #[test]
    fn pa_pk_as_req_signed_auth_pack_is_implicit() {
        let req = pkinit::PaPkAsReq {
            signed_auth_pack: vec![9, 9, 9].into(),
            trusted_certifiers: None,
            kdc_pk_id: None,
        };
        let der = rasn::der::encode(&req).expect("req");
        assert_eq!(der.first().copied(), Some(0x30));
        let body = rasn::der::decode::<pkinit::PaPkAsReq>(&der).expect("round-trip");
        assert_eq!(body.signed_auth_pack.as_ref(), &[9, 9, 9]);
        let cms = pkinit::parse_pa_pk_as_req_cms(&der).expect("implicit 0x80");
        assert_eq!(cms, vec![9, 9, 9]);
        assert_eq!(
            der.get(2).copied(),
            Some(0x80),
            "signedAuthPack is [0] IMPLICIT OCTET STRING"
        );
    }

    #[test]
    fn parse_authpack_accepts_spki_sequence() {
        let spki = pkinit::encode_ec_spki(&[0x04u8; 65]);
        // AuthPack SEQUENCE { [0] empty-ish, [1] EXPLICIT SPKI }
        // Minimal: SEQUENCE { [1] EXPLICIT SPKI } is enough for parse_authpack.
        let mut inner = vec![0xa1];
        let spki_len = u8::try_from(spki.len()).expect("spki");
        inner.push(spki_len);
        inner.extend_from_slice(&spki);
        let mut seq = vec![0x30, 0];
        seq.extend_from_slice(&inner);
        seq[1] = u8::try_from(inner.len()).expect("seq");
        let (nonce, got) = pkinit::parse_authpack(&seq).expect("parse");
        assert_eq!(nonce, 0);
        assert_eq!(got, spki);
    }

    #[test]
    fn parse_dh_spki_round_trips_p_and_y() {
        let p = vec![0xff, 0xff, 0xff, 0xfd];
        let y = vec![0x03];
        let spki = pkinit::encode_dh_spki(&p, &y);
        let (got_p, got_y) = pkinit::parse_dh_spki(&spki).expect("DH SPKI");
        assert_eq!(got_p, p);
        assert_eq!(got_y, y);
        assert!(pkinit::decode_ec_spki(&spki).is_none());
    }
}
