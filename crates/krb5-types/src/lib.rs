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

pub mod cammac;
mod constants;
pub mod deltat;
pub mod extra;
pub mod fast;
mod name;
mod name_error;
pub mod pac;
pub mod pkinit;
pub mod s4u;
pub mod spake;
pub mod timestamp;
pub mod transited;

pub use constants::{ap_bit, err, flag_bit, ku, pa};
pub use extra::{
    ApRep, ChangePasswdData, EncApRepPart, EncKrbCredPart, EncKrbPrivPart, KrbCred, KrbCredInfo,
    KrbPriv, KrbSafe, KrbSafeBody,
};
pub use name::{
    ParsedName, infer_name_type, parse_name, parse_name_ex, principal_from_unparsed,
    principal_from_unparsed_ex, quote_component, unparse_components, unparse_name,
};
pub use name_error::{NameError, TimeError};

/// Name-type-insensitive equality of components and realm.
///
/// MIT `krb5_principal_compare_flags` (`princ_comp.c:79-124`): krb5_principal_compare ignores name type.
#[must_use]
pub fn principal_compare(
    name_a: &PrincipalName,
    realm_a: &str,
    name_b: &PrincipalName,
    realm_b: &str,
) -> bool {
    realm_a == realm_b && name_a.components_eq(name_b)
}

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
/// `TYPED-DATA ::= SEQUENCE OF SEQUENCE { data-type [0], data-value [1] OPTIONAL }`
/// (RFC 6113; encode_krb5_typed_data, tags `[0]`/`[1]` not PA-DATA `[1]`/`[2]`).
pub type TypedDataList = SequenceOf<TypedData>;
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
    /// NT-WELLKNOWN (11), RFC 6111.
    pub const NT_WELLKNOWN: i32 = 11;
    /// MIT `get_pac_princ_with_realm` (`kdc_util.c:638-675`): `KRB5_NT_MS_PRINCIPAL` (−128)..
    pub const NT_MS_PRINCIPAL: i32 = -128;

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

    /// Name-string components, ignoring `name_type`.
    #[must_use]
    pub fn components_eq(&self, other: &Self) -> bool {
        self.name_string == other.name_string
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

    /// MIT `krb5_unparse_name` (`unparse.c:221-228`): quoting of components.
    #[must_use]
    pub fn unparse(&self) -> String {
        crate::unparse_components(&self.component_strings())
    }

    /// Quoted components `@` quoted realm (`unparse.c`).
    #[must_use]
    pub fn unparse_with_realm(&self, realm: &str) -> String {
        crate::unparse_name(&self.component_strings(), realm)
    }

    fn component_strings(&self) -> Vec<String> {
        self.name_string
            .iter()
            .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
            .collect()
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

    /// MIT `is_local_tgs_principal` (`kdc_util.c:106-110`): TGS whose instance equals the principal realm.
    #[must_use]
    pub fn is_local_tgs_principal(&self, princ_realm: &str) -> bool {
        self.is_krbtgt() && self.is_krbtgt_for(princ_realm)
    }

    /// MIT `is_cross_tgs_principal` (`kdc_util.c:98-102`): TGS whose instance is not the principal realm.
    #[must_use]
    pub fn is_cross_tgs_principal(&self, princ_realm: &str) -> bool {
        self.is_krbtgt() && !self.is_krbtgt_for(princ_realm)
    }
}

/// Network address of a host.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct HostAddress {
    /// `addr-type [0]`: address family (`ADDRTYPE_INET` 2, `ADDRTYPE_NETBIOS` 20, `ADDRTYPE_INET6` 24).
    #[rasn(tag(explicit(0)))]
    pub addr_type: i32,
    /// `address [1]`: the address octets in the family's own encoding.
    #[rasn(tag(explicit(1)))]
    pub address: OctetString,
}

impl HostAddress {
    /// ADDRTYPE_INET.
    pub const ADDRTYPE_INET: i32 = 2;
    /// ADDRTYPE_NETBIOS.
    pub const ADDRTYPE_NETBIOS: i32 = 0x14;
    /// ADDRTYPE_INET6.
    pub const ADDRTYPE_INET6: i32 = 0x18;

    /// MIT `k5_sockaddr_to_address` (`addr.c:44-75`): `local_use` false).
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

/// One authorization-data element.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct AuthorizationDataValue {
    /// `ad-type [0]`: the authorization-data element type (`AD_*`; negative values are site-local).
    #[rasn(tag(explicit(0)))]
    pub ad_type: i32,
    /// `ad-data [1]`: the element body, encoded as its type defines.
    #[rasn(tag(explicit(1)))]
    pub ad_data: OctetString,
}

/// Pre-authentication data.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaData {
    /// `padata-type [1]`: the pre-authentication type (`PA_*`).
    #[rasn(tag(explicit(1)))]
    pub padata_type: i32,
    /// `padata-value [2]`: the type's own encoding; opaque at this layer.
    #[rasn(tag(explicit(2)))]
    pub padata_value: OctetString,
}

/// One TYPED-DATA element (`asn1_k_encode.c`).
///
/// DEFCNFIELD always encodes `data-value` (possibly empty); it is not
/// optional on the wire.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct TypedData {
    /// `data-type [0]`: the TYPED-DATA element type.
    #[rasn(tag(explicit(0)))]
    pub data_type: i32,
    /// `data-value [1]`: the element body; always encoded (see the struct note).
    #[rasn(tag(explicit(1)))]
    pub data_value: OctetString,
}

/// Encrypted blob: etype, optional kvno, ciphertext.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct EncryptedData {
    /// `etype [0]`: the encryption type of `cipher` (RFC 3961 registry).
    #[rasn(tag(explicit(0)))]
    pub etype: i32,
    /// `kvno [1]` OPTIONAL: version of the long-term key that encrypted `cipher`; absent under session keys.
    #[rasn(tag(explicit(1)))]
    pub kvno: Option<u32>,
    /// `cipher [2]`: the ciphertext, confounder and integrity tag included as the etype defines.
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
    /// `cksumtype [0]`: the checksum algorithm (RFC 3961 registry).
    #[rasn(tag(explicit(0)))]
    pub cksumtype: i32,
    /// `checksum [1]`: the checksum octets; length fixed by `cksumtype`.
    #[rasn(tag(explicit(1)))]
    pub checksum: OctetString,
}

/// Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno, realm, sname, enc-part }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 1)))]
pub struct Ticket {
    /// `tkt-vno [0]`: ticket format version, always 5.
    #[rasn(tag(explicit(0)))]
    pub tkt_vno: i32,
    /// `realm [1]`: the realm that issued the ticket (the service's realm).
    #[rasn(tag(explicit(1)))]
    pub realm: Realm,
    /// `sname [2]`: the service principal the ticket is for, in `realm`.
    #[rasn(tag(explicit(2)))]
    pub sname: PrincipalName,
    /// `enc-part [3]`: the `EncTicketPart`, encrypted in the service's key (key usage 2).
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

    /// RFC 6806 `enc-pa-rep` (bit 15).
    #[must_use]
    pub fn enc_pa_rep(&self) -> bool {
        self.bit(flag_bit::ENC_PA_REP)
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

    /// AS_INVALID_OPTIONS (`kdc_util.h`): TGS-only options that
    /// are invalid in an AS-REQ.
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

/// KDC-REQ (untagged). AS-REQ is APPLICATION 10 wrapping this SEQUENCE.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KdcReq {
    /// `pvno [1]`: protocol version number, always 5.
    #[rasn(tag(explicit(1)))]
    pub pvno: i32,
    /// `msg-type [2]`: 10 for AS-REQ, 12 for TGS-REQ.
    #[rasn(tag(explicit(2)))]
    pub msg_type: i32,
    /// `padata [3]` OPTIONAL: pre-authentication data; a TGS-REQ carries its PA-TGS-REQ AP-REQ here.
    #[rasn(tag(explicit(3)))]
    pub padata: Option<SequenceOf<PaData>>,
    /// `req-body [4]`: the request proper (what the PA-TGS-REQ authenticator checksum covers).
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
    /// `kdc-options [0]`: the requested ticket flags.
    #[rasn(tag(explicit(0)))]
    pub kdc_options: KdcOptions,
    /// `cname [1]` OPTIONAL: the client principal; used in AS-REQ only (a TGS-REQ client is the TGT's).
    #[rasn(tag(explicit(1)))]
    pub cname: Option<PrincipalName>,
    /// `realm [2]`: the server's realm; in an AS-REQ also the client's.
    #[rasn(tag(explicit(2)))]
    pub realm: Realm,
    /// `sname [3]` OPTIONAL: the requested service principal; absent only with ENC-TKT-IN-SKEY, where the additional ticket names it.
    #[rasn(tag(explicit(3)))]
    pub sname: Option<PrincipalName>,
    /// `from [4]` OPTIONAL: requested start time; meaningful only with POSTDATED.
    #[rasn(tag(explicit(4)))]
    pub from: Option<KerberosTime>,
    /// `till [5]`: requested expiration time; the KDC caps it at the policy maximum.
    #[rasn(tag(explicit(5)))]
    pub till: KerberosTime,
    /// `rtime [6]` OPTIONAL: requested renew-till time; meaningful only with RENEWABLE.
    #[rasn(tag(explicit(6)))]
    pub rtime: Option<KerberosTime>,
    /// `nonce [7]`: random value echoed in the reply's `EncKDCRepPart`, binding reply to request.
    #[rasn(tag(explicit(7)))]
    pub nonce: u32,
    /// `etype [8]`: encryption types the client accepts for the session key, in preference order.
    #[rasn(tag(explicit(8)))]
    pub etype: SequenceOf<i32>,
    /// `addresses [9]` OPTIONAL: addresses the ticket is valid from; absent means no address restriction.
    #[rasn(tag(explicit(9)))]
    pub addresses: Option<HostAddresses>,
    /// `enc-authorization-data [10]` OPTIONAL: authorization data for the ticket, encrypted in the TGS session key (usage 4) or subkey (usage 5).
    #[rasn(tag(explicit(10)))]
    pub enc_authorization_data: Option<EncryptedData>,
    /// `additional-tickets [11]` OPTIONAL: tickets the request needs (the server's TGT for ENC-TKT-IN-SKEY, the evidence ticket for S4U2Proxy).
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
    /// `pvno [0]`: protocol version number, always 5.
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    /// `msg-type [1]`: 11 for AS-REP, 13 for TGS-REP.
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    /// `padata [2]` OPTIONAL: pre-authentication data returned to the client (ETYPE-INFO2, FAST and PKINIT replies).
    #[rasn(tag(explicit(2)))]
    pub padata: Option<SequenceOf<PaData>>,
    /// `crealm [3]`: the client's realm.
    #[rasn(tag(explicit(3)))]
    pub crealm: Realm,
    /// `cname [4]`: the client principal, as the KDC canonicalised it.
    #[rasn(tag(explicit(4)))]
    pub cname: PrincipalName,
    /// `ticket [5]`: the issued ticket.
    #[rasn(tag(explicit(5)))]
    pub ticket: Ticket,
    /// `enc-part [6]`: the `EncKDCRepPart`, encrypted in the client's key (AS, usage 3) or the TGS session key / subkey (TGS, usage 8 / 9).
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
    /// `pvno [0]`: protocol version number, always 5.
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    /// `msg-type [1]`: 14 (KRB-AP-REQ).
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    /// `ap-options [2]`: USE-SESSION-KEY and MUTUAL-REQUIRED.
    #[rasn(tag(explicit(2)))]
    pub ap_options: ApOptions,
    /// `ticket [3]`: the ticket for the server.
    #[rasn(tag(explicit(3)))]
    pub ticket: Ticket,
    /// `authenticator [4]`: the `Authenticator`, encrypted in the ticket's session key (usage 11; 7 inside PA-TGS-REQ).
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
    /// `pvno [0]`: protocol version number, always 5.
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    /// `msg-type [1]`: 30 (KRB-ERROR).
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    /// `ctime [2]` OPTIONAL: the client's time from the failing request, when the KDC could read it.
    #[rasn(tag(explicit(2)))]
    pub ctime: Option<KerberosTime>,
    /// `cusec [3]` OPTIONAL: microseconds of `ctime`.
    #[rasn(tag(explicit(3)))]
    pub cusec: Option<Microseconds>,
    /// `stime [4]`: the server's current time.
    #[rasn(tag(explicit(4)))]
    pub stime: KerberosTime,
    /// `susec [5]`: microseconds of `stime`.
    #[rasn(tag(explicit(5)))]
    pub susec: Microseconds,
    /// `error-code [6]`: the KDC_ERR / KRB_AP_ERR code (RFC 4120 §7.5.9).
    #[rasn(tag(explicit(6)))]
    pub error_code: i32,
    /// `crealm [7]` OPTIONAL: the client's realm, echoed when known.
    #[rasn(tag(explicit(7)))]
    pub crealm: Option<Realm>,
    /// `cname [8]` OPTIONAL: the client principal, echoed when known.
    #[rasn(tag(explicit(8)))]
    pub cname: Option<PrincipalName>,
    /// `realm [9]`: the server's realm (the replying KDC's).
    #[rasn(tag(explicit(9)))]
    pub realm: Realm,
    /// `sname [10]`: the server principal the request named.
    #[rasn(tag(explicit(10)))]
    pub sname: PrincipalName,
    /// `e-text [11]` OPTIONAL: a human-readable explanation.
    #[rasn(tag(explicit(11)))]
    pub e_text: Option<KerberosString>,
    /// `e-data [12]` OPTIONAL: METHOD-DATA (a PA-DATA list) for PREAUTH_REQUIRED / PREAUTH_FAILED, TYPED-DATA otherwise.
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

/// `PA-PAC-REQUEST ::= SEQUENCE { include-pac [0] BOOLEAN }`
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaPacRequest {
    /// `include-pac [0]`: whether the client wants a PAC in the ticket (MS-KILE §2.2.3).
    #[rasn(tag(explicit(0)))]
    pub include_pac: bool,
}

/// PA-ENC-TS-ENC ::= SEQUENCE { patimestamp, pausec OPTIONAL }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaEncTsEnc {
    /// `patimestamp [0]`: the client's time, proving knowledge of the long-term key.
    #[rasn(tag(explicit(0)))]
    pub patimestamp: KerberosTime,
    /// `pausec [1]` OPTIONAL: microseconds of `patimestamp`.
    #[rasn(tag(explicit(1)))]
    pub pausec: Option<Microseconds>,
}

/// ETYPE-INFO2-ENTRY
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct EtypeInfo2Entry {
    /// `etype [0]`: an encryption type the KDC holds a key for.
    #[rasn(tag(explicit(0)))]
    pub etype: i32,
    /// `salt [1]` OPTIONAL: string-to-key salt; absent means the default principal-derived salt.
    #[rasn(tag(explicit(1)))]
    pub salt: Option<KerberosString>,
    /// `s2kparams [2]` OPTIONAL: string-to-key parameters (the AES iteration count); absent means the etype default.
    #[rasn(tag(explicit(2)))]
    pub s2kparams: Option<OctetString>,
}

/// ETYPE-INFO2 ::= SEQUENCE OF ETYPE-INFO2-ENTRY
pub type EtypeInfo2 = SequenceOf<EtypeInfo2Entry>;

/// ETYPE-INFO-ENTRY (legacy PA-ETYPE-INFO).
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct EtypeInfoEntry {
    /// `etype [0]`: an encryption type the KDC holds a key for.
    #[rasn(tag(explicit(0)))]
    pub etype: i32,
    /// `salt [1]` OPTIONAL: string-to-key salt as raw octets (the pre-ETYPE-INFO2 form).
    #[rasn(tag(explicit(1)))]
    pub salt: Option<OctetString>,
}

/// ETYPE-INFO ::= SEQUENCE OF ETYPE-INFO-ENTRY
pub type EtypeInfo = SequenceOf<EtypeInfoEntry>;

/// LastReq element.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct LastReqValue {
    /// `lr-type [0]`: what `lr-value` records (last initial request, last renewal, password expiry, ...); 0 means unused.
    #[rasn(tag(explicit(0)))]
    pub lr_type: i32,
    /// `lr-value [1]`: the time for `lr-type`.
    #[rasn(tag(explicit(1)))]
    pub lr_value: KerberosTime,
}

/// EncKDCRepPart ::= SEQUENCE { key, last-req, nonce, ... }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct EncKdcRepPart {
    /// `key [0]`: the ticket's session key.
    #[rasn(tag(explicit(0)))]
    pub key: EncryptionKey,
    /// `last-req [1]`: last-request times for the client; may be a single `lr-type` 0 entry.
    #[rasn(tag(explicit(1)))]
    pub last_req: SequenceOf<LastReqValue>,
    /// `nonce [2]`: the request's nonce, echoed so the client can match the reply.
    #[rasn(tag(explicit(2)))]
    pub nonce: u32,
    /// `key-expiration [3]` OPTIONAL: when the client's key expires; advisory, AS-REP only.
    #[rasn(tag(explicit(3)))]
    pub key_expiration: Option<KerberosTime>,
    /// `flags [4]`: the ticket's flags, as issued.
    #[rasn(tag(explicit(4)))]
    pub flags: TicketFlags,
    /// `authtime [5]`: when the client first authenticated (copied from the ticket).
    #[rasn(tag(explicit(5)))]
    pub authtime: KerberosTime,
    /// `starttime [6]` OPTIONAL: when the ticket becomes valid; absent means `authtime`.
    #[rasn(tag(explicit(6)))]
    pub starttime: Option<KerberosTime>,
    /// `endtime [7]`: when the ticket expires.
    #[rasn(tag(explicit(7)))]
    pub endtime: KerberosTime,
    /// `renew-till [8]` OPTIONAL: the renewal limit; present only for RENEWABLE tickets.
    #[rasn(tag(explicit(8)))]
    pub renew_till: Option<KerberosTime>,
    /// `srealm [9]`: the server's realm.
    #[rasn(tag(explicit(9)))]
    pub srealm: Realm,
    /// `sname [10]`: the server principal the ticket names.
    #[rasn(tag(explicit(10)))]
    pub sname: PrincipalName,
    /// `caddr [11]` OPTIONAL: the addresses in the ticket, if any.
    #[rasn(tag(explicit(11)))]
    pub caddr: Option<HostAddresses>,
    /// `encrypted-pa-data [12]` OPTIONAL: pre-authentication data under the reply key (RFC 6806 §11, e.g. PA-REQ-ENC-PA-REP).
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
    /// `authenticator-vno [0]`: format version, always 5.
    #[rasn(tag(explicit(0)))]
    pub authenticator_vno: i32,
    /// `crealm [1]`: the client's realm; must match the ticket's.
    #[rasn(tag(explicit(1)))]
    pub crealm: Realm,
    /// `cname [2]`: the client principal; must match the ticket's.
    #[rasn(tag(explicit(2)))]
    pub cname: PrincipalName,
    /// `cksum [3]` OPTIONAL: checksum of the application data (the KDC-REQ-BODY in PA-TGS-REQ, the channel bindings in GSS-API).
    #[rasn(tag(explicit(3)))]
    pub cksum: Option<Checksum>,
    /// `cusec [4]`: microseconds of `ctime`; with it, the replay-cache key.
    #[rasn(tag(explicit(4)))]
    pub cusec: Microseconds,
    /// `ctime [5]`: the client's time; must be within the clock-skew window.
    #[rasn(tag(explicit(5)))]
    pub ctime: KerberosTime,
    /// `subkey [6]` OPTIONAL: a client-chosen key to protect the exchange instead of the session key.
    #[rasn(tag(explicit(6)))]
    pub subkey: Option<EncryptionKey>,
    /// `seq-number [7]` OPTIONAL: initial sequence number for KRB-SAFE / KRB-PRIV.
    #[rasn(tag(explicit(7)))]
    pub seq_number: Option<u32>,
    /// `authorization-data [8]` OPTIONAL: restrictions the client adds (AD-IF-RELEVANT, GSS channel bindings, ...).
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
    /// `tr-type [0]`: the encoding of `contents`; 1 (DOMAIN-X500-COMPRESS) is the only defined value.
    #[rasn(tag(explicit(0)))]
    pub tr_type: i32,
    /// `contents [1]`: the realms transited, in `tr-type`'s encoding; empty for a directly issued ticket.
    #[rasn(tag(explicit(1)))]
    pub contents: OctetString,
}

/// DOMAIN-X500-COMPRESS expansion failure (`chk_trans.c` / Rust comma cap).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransitError {
    /// Check-path raw ≥ 512 or joined > 512; add-path raw ≥ 500, joined ≥ 499,
    /// or rebuilt encoding ≥ 500 (MAX_REALM_LN).
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

    /// MIT `add_to_transited` (`kdc_transit.c:144-414`): Append `realm` onto the original contents (
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
/// MIT `maybe_join` (`chk_trans.c:138-163`): `last + cur > 512` errors; joined of 512 is accepted.
const MAX_TRANSIT_JOINED: usize = 512;
/// MIT `kdc_transit.c` `MAX_REALM_LN`. Raw field of 500 unescaped bytes errors.
const MAX_ADD_PATH_RAW: usize = 500;
/// MIT `strlen(exp)+strlen(x)+1 >= 500`: joined ≥ 499 errors.
const MAX_ADD_PATH_JOINED: usize = 499;
/// strlcat into a 500-byte buffer: rebuilt encoding ≥ 500 errors.
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

/// MIT `krb5_check_transited_list` (`chk_trans.c:326-327`): an empty transit list is not a failure.
/// More commas than the realm cap is an error, not a truncated path.
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

/// MIT `rtree_hier_tree` (`walk_rtree.c:358-361`): a hierarchy that cannot be built returns the error and no tree.
/// Two names of equal length add no hop unless they are the same name, and a domain hop is emitted only when the longer name ends with the shorter one.
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
    /// `flags [0]`: the ticket flags.
    #[rasn(tag(explicit(0)))]
    pub flags: TicketFlags,
    /// `key [1]`: the session key shared by client and server.
    #[rasn(tag(explicit(1)))]
    pub key: EncryptionKey,
    /// `crealm [2]`: the client's realm.
    #[rasn(tag(explicit(2)))]
    pub crealm: Realm,
    /// `cname [3]`: the client principal.
    #[rasn(tag(explicit(3)))]
    pub cname: PrincipalName,
    /// `transited [4]`: the realms the authentication path crossed; checked against `[capaths]` unless TRANSITED-POLICY-CHECKED is set.
    #[rasn(tag(explicit(4)))]
    pub transited: TransitedEncoding,
    /// `authtime [5]`: when the client first authenticated (the AS exchange); carried through renewals.
    #[rasn(tag(explicit(5)))]
    pub authtime: KerberosTime,
    /// `starttime [6]` OPTIONAL: when the ticket becomes valid; absent means `authtime`.
    #[rasn(tag(explicit(6)))]
    pub starttime: Option<KerberosTime>,
    /// `endtime [7]`: when the ticket expires.
    #[rasn(tag(explicit(7)))]
    pub endtime: KerberosTime,
    /// `renew-till [8]` OPTIONAL: the renewal limit; present only for RENEWABLE tickets.
    #[rasn(tag(explicit(8)))]
    pub renew_till: Option<KerberosTime>,
    /// `caddr [9]` OPTIONAL: addresses the ticket may be used from; absent means any.
    #[rasn(tag(explicit(9)))]
    pub caddr: Option<HostAddresses>,
    /// `authorization-data [10]` OPTIONAL: restrictions and the PAC (AD-IF-RELEVANT / AD-WIN2K-PAC, AD-KDC-ISSUED, AD-CAMMAC).
    #[rasn(tag(explicit(10)))]
    pub authorization_data: Option<AuthorizationData>,
}

#[cfg(test)]
mod tests;
