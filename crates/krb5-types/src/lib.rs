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

use chrono::{FixedOffset, NaiveDateTime, TimeZone, Timelike, Utc};
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

    /// `krbtgt/REALM` as NT-SRV-INST.
    #[must_use]
    pub fn krbtgt(realm: &str) -> Self {
        Self::new(Self::NT_SRV_INST, ["krbtgt", realm])
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

    /// Set RFC 4120 bit 1 (forwardable).
    #[must_use]
    pub fn forwardable() -> Self {
        let mut bits = KerberosFlags::repeat(false, 32);
        bits.set(1, true);
        Self(bits)
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

impl KerberosTime {
    /// Current UTC time as KerberosTime.
    ///
    /// RFC 4120 forbids fractional seconds; nanoseconds are zeroed so DER
    /// encoding is `YYYYMMDDHHMMSSZ`.
    #[must_use]
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
}

/// RFC 4120 PA-DATA type numbers used in Stage 3.
pub mod pa {
    /// PA-TGS-REQ (AP-REQ in TGS-REQ padata).
    pub const TGS_REQ: i32 = 1;
    /// PA-ENC-TIMESTAMP.
    pub const ENC_TIMESTAMP: i32 = 2;
    /// PA-PW-SALT.
    pub const PW_SALT: i32 = 3;
    /// PA-ETYPE-INFO.
    pub const ETYPE_INFO: i32 = 11;
    /// PA-ETYPE-INFO2.
    pub const ETYPE_INFO2: i32 = 19;
}

/// RFC 4120 error codes used in Stage 3.
pub mod err {
    /// KDC_ERR_PREAUTH_FAILED
    pub const PREAUTH_FAILED: i32 = 24;
    /// KDC_ERR_PREAUTH_REQUIRED
    pub const PREAUTH_REQUIRED: i32 = 25;
    /// KRB_ERR_RESPONSE_TOO_BIG
    pub const RESPONSE_TOO_BIG: i32 = 52;
}

/// RFC 4120 key-usage numbers used in Stage 3.
pub mod ku {
    /// AS-REQ PA-ENC-TIMESTAMP.
    pub const PA_ENC_TIMESTAMP: u32 = 1;
    /// AS-REP encrypted part (client long-term key).
    pub const AS_REP_ENC_PART: u32 = 3;
    /// TGS-REQ authenticator checksum.
    pub const TGS_REQ_AUTH_CKSUM: u32 = 6;
    /// TGS-REQ authenticator.
    pub const TGS_REQ_AUTHENTICATOR: u32 = 7;
    /// TGS-REP encrypted part (TGT session key).
    pub const TGS_REP_ENC_PART: u32 = 8;
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
