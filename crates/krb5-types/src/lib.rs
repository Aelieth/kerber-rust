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
#![allow(missing_docs)]

use chrono::{FixedOffset, NaiveDateTime, TimeZone};
use rasn::prelude::*;

pub use rasn::types::{BitString, GeneralizedTime, OctetString};

/// Construct a [`KerberosString`] from ASCII / GeneralString text.
///
/// # Panics
///
/// Panics if `s` contains characters outside the GeneralString alphabet.
/// Callers that take untrusted input should use [`KerberosString::try_from`].
#[must_use]
pub fn ascii(s: &str) -> KerberosString {
    KerberosString::try_from(s).expect("KerberosString requires the GeneralString alphabet")
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
pub type Microseconds = u32;

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
    #[must_use]
    pub fn new(name_type: i32, parts: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self {
            name_type,
            name_string: parts.into_iter().map(|p| ascii(p.as_ref())).collect(),
        }
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
    #[rasn(tag(explicit(0)))]
    pub keytype: i32,
    #[rasn(tag(explicit(1)))]
    pub keyvalue: OctetString,
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
/// Returns a string description when `s` is not that form.
pub fn kerberos_time_from_utc_z(s: &str) -> Result<KerberosTime, String> {
    let body = s
        .strip_suffix('Z')
        .ok_or_else(|| format!("missing Z: {s}"))?;
    let naive = NaiveDateTime::parse_from_str(body, "%Y%m%d%H%M%S").map_err(|e| e.to_string())?;
    let tz = FixedOffset::east_opt(0).ok_or_else(|| "UTC offset".to_owned())?;
    Ok(KerberosTime(tz.from_utc_datetime(&naive)))
}
