//! RFC 4120 AP-REP, KRB-SAFE, KRB-PRIV, and KRB-CRED.

use rasn::prelude::*;

use crate::{
    Checksum, EncryptedData, EncryptionKey, HostAddress, KerberosTime, Microseconds, OctetString,
    PrincipalName, Realm, Ticket,
};

/// AP-REP ::= [APPLICATION 15] SEQUENCE { pvno, msg-type, enc-part }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 15)))]
pub struct ApRep {
    /// Protocol version.
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    /// Message type (15).
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    /// Encrypted [`EncApRepPart`].
    #[rasn(tag(explicit(2)))]
    pub enc_part: EncryptedData,
}

impl ApRep {
    /// Protocol version.
    pub const PVNO: i32 = 5;
    /// AP-REP msg-type.
    pub const MSG_TYPE: i32 = 15;
}

/// EncAPRepPart ::= [APPLICATION 27] SEQUENCE { ctime, cusec, subkey, seq-number }
#[derive(AsnType, Clone, Debug, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 27)))]
pub struct EncApRepPart {
    /// Client time from the AP-REQ authenticator.
    #[rasn(tag(explicit(0)))]
    pub ctime: KerberosTime,
    /// Client microseconds from the AP-REQ authenticator.
    #[rasn(tag(explicit(1)))]
    pub cusec: Microseconds,
    /// Optional negotiated sub-session key.
    #[rasn(tag(explicit(2)))]
    pub subkey: Option<EncryptionKey>,
    /// Optional sequence number.
    #[rasn(tag(explicit(3)))]
    pub seq_number: Option<u32>,
}

/// KRB-SAFE ::= [APPLICATION 20] SEQUENCE { pvno, msg-type, safe-body, cksum }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 20)))]
pub struct KrbSafe {
    /// Protocol version.
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    /// Message type (20).
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    /// Integrity-protected body.
    #[rasn(tag(explicit(2)))]
    pub safe_body: KrbSafeBody,
    /// Checksum over the body (key usage 15).
    #[rasn(tag(explicit(3)))]
    pub cksum: Checksum,
}

impl KrbSafe {
    /// Protocol version.
    pub const PVNO: i32 = 5;
    /// KRB-SAFE msg-type.
    pub const MSG_TYPE: i32 = 20;
}

/// KRB-SAFE-BODY
#[derive(AsnType, Clone, Debug, Encode, PartialEq, Eq, Hash)]
pub struct KrbSafeBody {
    /// Application payload.
    #[rasn(tag(explicit(0)))]
    pub user_data: OctetString,
    /// Optional timestamp.
    #[rasn(tag(explicit(1)))]
    pub timestamp: Option<KerberosTime>,
    /// Optional microseconds.
    #[rasn(tag(explicit(2)))]
    pub usec: Option<Microseconds>,
    /// Optional sequence number.
    #[rasn(tag(explicit(3)))]
    pub seq_number: Option<u32>,
    /// Sender address.
    #[rasn(tag(explicit(4)))]
    pub s_address: HostAddress,
    /// Optional recipient address.
    #[rasn(tag(explicit(5)))]
    pub r_address: Option<HostAddress>,
}

/// KRB-PRIV ::= [APPLICATION 21] SEQUENCE { pvno, msg-type, enc-part }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 21)))]
pub struct KrbPriv {
    /// Protocol version.
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    /// Message type (21).
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    /// Encrypted [`EncKrbPrivPart`] (key usage 13).
    #[rasn(tag(explicit(3)))]
    pub enc_part: EncryptedData,
}

impl KrbPriv {
    /// Protocol version.
    pub const PVNO: i32 = 5;
    /// KRB-PRIV msg-type.
    pub const MSG_TYPE: i32 = 21;
}

/// EncKrbPrivPart ::= [APPLICATION 28] SEQUENCE { ... }
#[derive(AsnType, Clone, Debug, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 28)))]
pub struct EncKrbPrivPart {
    /// Application payload.
    #[rasn(tag(explicit(0)))]
    pub user_data: OctetString,
    /// Optional timestamp.
    #[rasn(tag(explicit(1)))]
    pub timestamp: Option<KerberosTime>,
    /// Optional microseconds.
    #[rasn(tag(explicit(2)))]
    pub usec: Option<Microseconds>,
    /// Optional sequence number.
    #[rasn(tag(explicit(3)))]
    pub seq_number: Option<u32>,
    /// Sender address.
    #[rasn(tag(explicit(4)))]
    pub s_address: HostAddress,
    /// Optional recipient address.
    #[rasn(tag(explicit(5)))]
    pub r_address: Option<HostAddress>,
}

/// A seq-number as a KRB-SAFE, a KRB-PRIV, an AP-REP or an authenticator carries it: the value
/// MIT reads, or `None` for an INTEGER MIT refuses. rasn reads an OPTIONAL field whose decode
/// fails as absent, so the refusal is the message's ([`WireSeqNumber::value`]).
/// MIT `decode_seqno` (`lib/krb5/asn.1/asn1_k_encode.c:133-146`): an INTEGER from `INT32_MIN` to `0xFFFFFFFF` decodes, a negative one (an old Heimdal's) as the same 32 bits unsigned, and a wider one is `ASN1_OVERFLOW`, which fails the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WireSeqNumber(Option<u32>);

impl WireSeqNumber {
    /// The seq-number, or the error that fails the message carrying an INTEGER MIT refuses.
    pub(crate) fn value<E: rasn::de::Error>(self, codec: rasn::Codec) -> Result<u32, E> {
        self.0
            .ok_or_else(|| E::custom("seq-number outside INT32_MIN..=0xFFFFFFFF", codec))
    }
}

impl AsnType for WireSeqNumber {
    const TAG: Tag = Tag::INTEGER;
}

impl Decode for WireSeqNumber {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let value = decoder.decode_integer::<Integer>(tag, constraints)?;
        Ok(Self(
            i32::try_from(&value)
                .map(i32::cast_unsigned)
                .or_else(|_| u32::try_from(&value))
                .ok(),
        ))
    }
}

impl Encode for WireSeqNumber {
    fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        // An unsigned INTEGER, as MIT's `encode_seqno` writes it.
        self.0.unwrap_or_default().encode_with_tag_and_constraints(
            encoder,
            tag,
            constraints,
            identifier,
        )
    }
}

/// [`EncApRepPart`] as it decodes, its seq-number read as MIT reads it.
#[derive(AsnType, Decode)]
#[rasn(tag(explicit(application, 27)))]
struct EncApRepPartOnWire {
    #[rasn(tag(explicit(0)))]
    ctime: KerberosTime,
    #[rasn(tag(explicit(1)))]
    cusec: Microseconds,
    #[rasn(tag(explicit(2)))]
    subkey: Option<EncryptionKey>,
    #[rasn(tag(explicit(3)))]
    seq_number: Option<WireSeqNumber>,
}

impl Decode for EncApRepPart {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let w = EncApRepPartOnWire::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(Self {
            ctime: w.ctime,
            cusec: w.cusec,
            subkey: w.subkey,
            seq_number: w
                .seq_number
                .map(|s| s.value::<D::Error>(decoder.codec()))
                .transpose()?,
        })
    }
}

/// [`KrbSafeBody`] as it decodes, its seq-number read as MIT reads it.
#[derive(AsnType, Decode)]
struct KrbSafeBodyOnWire {
    #[rasn(tag(explicit(0)))]
    user_data: OctetString,
    #[rasn(tag(explicit(1)))]
    timestamp: Option<KerberosTime>,
    #[rasn(tag(explicit(2)))]
    usec: Option<Microseconds>,
    #[rasn(tag(explicit(3)))]
    seq_number: Option<WireSeqNumber>,
    #[rasn(tag(explicit(4)))]
    s_address: HostAddress,
    #[rasn(tag(explicit(5)))]
    r_address: Option<HostAddress>,
}

impl Decode for KrbSafeBody {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let w = KrbSafeBodyOnWire::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(Self {
            user_data: w.user_data,
            timestamp: w.timestamp,
            usec: w.usec,
            seq_number: w
                .seq_number
                .map(|s| s.value::<D::Error>(decoder.codec()))
                .transpose()?,
            s_address: w.s_address,
            r_address: w.r_address,
        })
    }
}

/// [`EncKrbPrivPart`] as it decodes, its seq-number read as MIT reads it.
#[derive(AsnType, Decode)]
#[rasn(tag(explicit(application, 28)))]
struct EncKrbPrivPartOnWire {
    #[rasn(tag(explicit(0)))]
    user_data: OctetString,
    #[rasn(tag(explicit(1)))]
    timestamp: Option<KerberosTime>,
    #[rasn(tag(explicit(2)))]
    usec: Option<Microseconds>,
    #[rasn(tag(explicit(3)))]
    seq_number: Option<WireSeqNumber>,
    #[rasn(tag(explicit(4)))]
    s_address: HostAddress,
    #[rasn(tag(explicit(5)))]
    r_address: Option<HostAddress>,
}

impl Decode for EncKrbPrivPart {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let w = EncKrbPrivPartOnWire::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(Self {
            user_data: w.user_data,
            timestamp: w.timestamp,
            usec: w.usec,
            seq_number: w
                .seq_number
                .map(|s| s.value::<D::Error>(decoder.codec()))
                .transpose()?,
            s_address: w.s_address,
            r_address: w.r_address,
        })
    }
}

/// KRB-CRED ::= [APPLICATION 22] SEQUENCE { pvno, msg-type, tickets, enc-part }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 22)))]
pub struct KrbCred {
    /// Protocol version.
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    /// Message type (22).
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    /// Forwarded tickets.
    #[rasn(tag(explicit(2)))]
    pub tickets: SequenceOf<Ticket>,
    /// Encrypted [`EncKrbCredPart`] (key usage 14).
    #[rasn(tag(explicit(3)))]
    pub enc_part: EncryptedData,
}

impl KrbCred {
    /// Protocol version.
    pub const PVNO: i32 = 5;
    /// KRB-CRED msg-type.
    pub const MSG_TYPE: i32 = 22;
}

/// EncKrbCredPart ::= [APPLICATION 29] SEQUENCE { ... }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 29)))]
pub struct EncKrbCredPart {
    /// Per-ticket info aligned with [`KrbCred::tickets`].
    #[rasn(tag(explicit(0)))]
    pub ticket_info: SequenceOf<KrbCredInfo>,
    /// Optional nonce.
    #[rasn(tag(explicit(1)))]
    pub nonce: Option<u32>,
    /// Optional timestamp.
    #[rasn(tag(explicit(2)))]
    pub timestamp: Option<KerberosTime>,
    /// Optional microseconds.
    #[rasn(tag(explicit(3)))]
    pub usec: Option<Microseconds>,
    /// Optional sender address.
    #[rasn(tag(explicit(4)))]
    pub s_address: Option<HostAddress>,
    /// Optional recipient address.
    #[rasn(tag(explicit(5)))]
    pub r_address: Option<HostAddress>,
}

/// KrbCredInfo ::= SEQUENCE { key, prealm, pname, flags, authtime, ... }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KrbCredInfo {
    /// Session key for the forwarded ticket.
    #[rasn(tag(explicit(0)))]
    pub key: EncryptionKey,
    /// Client realm.
    #[rasn(tag(explicit(1)))]
    pub prealm: Option<Realm>,
    /// Client name.
    #[rasn(tag(explicit(2)))]
    pub pname: Option<PrincipalName>,
    /// Ticket flags.
    #[rasn(tag(explicit(3)))]
    pub flags: Option<crate::TicketFlags>,
    /// Auth time.
    #[rasn(tag(explicit(4)))]
    pub authtime: Option<KerberosTime>,
    /// Start time.
    #[rasn(tag(explicit(5)))]
    pub starttime: Option<KerberosTime>,
    /// End time.
    #[rasn(tag(explicit(6)))]
    pub endtime: Option<KerberosTime>,
    /// Renew-till.
    #[rasn(tag(explicit(7)))]
    pub renew_till: Option<KerberosTime>,
    /// Server realm.
    #[rasn(tag(explicit(8)))]
    pub srealm: Option<Realm>,
    /// Server name.
    #[rasn(tag(explicit(9)))]
    pub sname: Option<PrincipalName>,
    /// Addresses.
    #[rasn(tag(explicit(10)))]
    pub caddr: Option<crate::HostAddresses>,
}

/// RFC 3244 `ChangePasswdData`. `Debug` never shows the new password, nor its length.
#[derive(AsnType, Clone, Decode, Encode, PartialEq, Eq, Hash)]
pub struct ChangePasswdData {
    /// New password octets.
    #[rasn(tag(explicit(0)))]
    pub newpasswd: OctetString,
    /// Optional target name.
    #[rasn(tag(explicit(1)))]
    pub targname: Option<PrincipalName>,
    /// Optional target realm.
    #[rasn(tag(explicit(2)))]
    pub targrealm: Option<Realm>,
}

impl std::fmt::Debug for ChangePasswdData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangePasswdData")
            .field("newpasswd", &format_args!("<redacted>"))
            .field("targname", &self.targname)
            .field("targrealm", &self.targrealm)
            .finish()
    }
}
