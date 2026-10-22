use rasn::prelude::*;

use crate::{
    Checksum, EncryptedData, EncryptionKey, HostAddress, KerberosTime, Microseconds, OctetString,
    PrincipalName, Realm, Ticket,
};

#[derive(AsnType, Clone, Debug, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 15)))]
pub struct ApRep {
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    #[rasn(tag(explicit(2)))]
    pub enc_part: EncryptedData,
}

impl ApRep {
    pub const PVNO: i32 = 5;
    pub const MSG_TYPE: i32 = 15;
}

// MIT `ap_rep_msg_type` (`lib/krb5/asn.1/asn1_k_encode.c:760-760`): the msg-type is an immediate with no error, so any INTEGER of up to eight octets decodes and none is kept.
#[derive(AsnType, Decode)]
#[rasn(tag(explicit(application, 15)))]
struct ApRepOnWire {
    #[rasn(tag(explicit(0)))]
    pvno: crate::WireVersion,
    #[rasn(tag(explicit(1)))]
    #[allow(dead_code)]
    msg_type: crate::WireImmediate,
    #[rasn(tag(explicit(2)))]
    enc_part: EncryptedData,
}

impl Decode for ApRep {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let w = ApRepOnWire::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(Self {
            pvno: w.pvno.0,
            msg_type: Self::MSG_TYPE,
            enc_part: w.enc_part,
        })
    }
}

#[derive(AsnType, Clone, Debug, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 27)))]
pub struct EncApRepPart {
    #[rasn(tag(explicit(0)))]
    pub ctime: KerberosTime,
    #[rasn(tag(explicit(1)))]
    pub cusec: Microseconds,
    #[rasn(tag(explicit(2)))]
    pub subkey: Option<EncryptionKey>,
    #[rasn(tag(explicit(3)))]
    pub seq_number: Option<u32>,
}

#[derive(AsnType, Clone, Debug, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 20)))]
pub struct KrbSafe {
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    #[rasn(tag(explicit(2)))]
    pub safe_body: KrbSafeBody,
    #[rasn(tag(explicit(3)))]
    pub cksum: Checksum,
}

impl KrbSafe {
    pub const PVNO: i32 = 5;
    pub const MSG_TYPE: i32 = 20;
}

// MIT safe_msg_type; see docs/parity/b1-client.md
#[derive(AsnType, Decode)]
#[rasn(tag(explicit(application, 20)))]
struct KrbSafeOnWire {
    #[rasn(tag(explicit(0)))]
    pvno: crate::WireVersion,
    #[rasn(tag(explicit(1)))]
    #[allow(dead_code)]
    msg_type: crate::WireImmediate,
    #[rasn(tag(explicit(2)))]
    safe_body: KrbSafeBody,
    #[rasn(tag(explicit(3)))]
    cksum: Checksum,
}

impl Decode for KrbSafe {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let w = KrbSafeOnWire::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(Self {
            pvno: w.pvno.0,
            msg_type: Self::MSG_TYPE,
            safe_body: w.safe_body,
            cksum: w.cksum,
        })
    }
}

#[derive(AsnType, Clone, Debug, PartialEq, Eq, Hash)]
pub struct KrbSafeBody {
    #[rasn(tag(explicit(0)))]
    pub user_data: OctetString,
    #[rasn(tag(explicit(1)))]
    pub timestamp: Option<KerberosTime>,
    #[rasn(tag(explicit(2)))]
    pub usec: Option<Microseconds>,
    #[rasn(tag(explicit(3)))]
    pub seq_number: Option<u32>,
    #[rasn(tag(explicit(4)))]
    pub s_address: HostAddress,
    #[rasn(tag(explicit(5)))]
    pub r_address: Option<HostAddress>,
}

#[derive(AsnType, Clone, Debug, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 21)))]
pub struct KrbPriv {
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    #[rasn(tag(explicit(3)))]
    pub enc_part: EncryptedData,
}

impl KrbPriv {
    pub const PVNO: i32 = 5;
    pub const MSG_TYPE: i32 = 21;
}

// MIT `priv_msg_type` (`lib/krb5/asn.1/asn1_k_encode.c:845-845`): the msg-type is an immediate with no error, so any INTEGER of up to eight octets decodes and none is kept.
#[derive(AsnType, Decode)]
#[rasn(tag(explicit(application, 21)))]
struct KrbPrivOnWire {
    #[rasn(tag(explicit(0)))]
    pvno: crate::WireVersion,
    #[rasn(tag(explicit(1)))]
    #[allow(dead_code)]
    msg_type: crate::WireImmediate,
    #[rasn(tag(explicit(3)))]
    enc_part: EncryptedData,
}

impl Decode for KrbPriv {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let w = KrbPrivOnWire::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(Self {
            pvno: w.pvno.0,
            msg_type: Self::MSG_TYPE,
            enc_part: w.enc_part,
        })
    }
}

#[derive(AsnType, Clone, Debug, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 28)))]
pub struct EncKrbPrivPart {
    #[rasn(tag(explicit(0)))]
    pub user_data: OctetString,
    #[rasn(tag(explicit(1)))]
    pub timestamp: Option<KerberosTime>,
    #[rasn(tag(explicit(2)))]
    pub usec: Option<Microseconds>,
    #[rasn(tag(explicit(3)))]
    pub seq_number: Option<u32>,
    #[rasn(tag(explicit(4)))]
    pub s_address: HostAddress,
    #[rasn(tag(explicit(5)))]
    pub r_address: Option<HostAddress>,
}

// MIT `decode_seqno` (`lib/krb5/asn.1/asn1_k_encode.c:133-146`): an INTEGER from `INT32_MIN` to `0xFFFFFFFF` decodes, a negative one (an old Heimdal's) as the same 32 bits unsigned, and a wider one is `ASN1_OVERFLOW`, which fails the message.
// MIT `encode_seqno` (`asn1_k_encode.c:124-132`): written unsigned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WireSeqNumber(pub(crate) u32);

impl AsnType for WireSeqNumber {
    const TAG: Tag = Tag::INTEGER;
}

impl Decode for WireSeqNumber {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let value = decoder.decode_integer::<i64>(tag, constraints)?;
        i32::try_from(value)
            .map(i32::cast_unsigned)
            .or_else(|_| u32::try_from(value))
            .map(Self)
            .map_err(|_| {
                <D::Error as rasn::de::Error>::custom(
                    "seq-number outside INT32_MIN..=0xFFFFFFFF",
                    decoder.codec(),
                )
            })
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
        u64::from(self.0).encode_with_tag_and_constraints(encoder, tag, constraints, identifier)
    }
}

#[derive(AsnType, Decode, Encode)]
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
            seq_number: w.seq_number.map(|s| s.0),
        })
    }
}

impl Encode for EncApRepPart {
    fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        EncApRepPartOnWire {
            ctime: self.ctime.clone(),
            cusec: self.cusec,
            subkey: self.subkey.clone(),
            seq_number: self.seq_number.map(WireSeqNumber),
        }
        .encode_with_tag_and_constraints(encoder, tag, constraints, identifier)
    }
}

#[derive(AsnType, Decode, Encode)]
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
            seq_number: w.seq_number.map(|s| s.0),
            s_address: w.s_address,
            r_address: w.r_address,
        })
    }
}

impl Encode for KrbSafeBody {
    fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        KrbSafeBodyOnWire {
            user_data: self.user_data.clone(),
            timestamp: self.timestamp.clone(),
            usec: self.usec,
            seq_number: self.seq_number.map(WireSeqNumber),
            s_address: self.s_address.clone(),
            r_address: self.r_address.clone(),
        }
        .encode_with_tag_and_constraints(encoder, tag, constraints, identifier)
    }
}

#[derive(AsnType, Decode, Encode)]
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
            seq_number: w.seq_number.map(|s| s.0),
            s_address: w.s_address,
            r_address: w.r_address,
        })
    }
}

impl Encode for EncKrbPrivPart {
    fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        constraints: Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        EncKrbPrivPartOnWire {
            user_data: self.user_data.clone(),
            timestamp: self.timestamp.clone(),
            usec: self.usec,
            seq_number: self.seq_number.map(WireSeqNumber),
            s_address: self.s_address.clone(),
            r_address: self.r_address.clone(),
        }
        .encode_with_tag_and_constraints(encoder, tag, constraints, identifier)
    }
}

#[derive(AsnType, Clone, Debug, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 22)))]
pub struct KrbCred {
    #[rasn(tag(explicit(0)))]
    pub pvno: i32,
    #[rasn(tag(explicit(1)))]
    pub msg_type: i32,
    #[rasn(tag(explicit(2)))]
    pub tickets: SequenceOf<Ticket>,
    #[rasn(tag(explicit(3)))]
    pub enc_part: EncryptedData,
}

impl KrbCred {
    pub const PVNO: i32 = 5;
    pub const MSG_TYPE: i32 = 22;
}

// MIT `cred_msg_type` (`lib/krb5/asn.1/asn1_k_encode.c:877-877`): the msg-type is an immediate with no error, so any INTEGER of up to eight octets decodes and none is kept.
#[derive(AsnType, Decode)]
#[rasn(tag(explicit(application, 22)))]
struct KrbCredOnWire {
    #[rasn(tag(explicit(0)))]
    pvno: crate::WireVersion,
    #[rasn(tag(explicit(1)))]
    #[allow(dead_code)]
    msg_type: crate::WireImmediate,
    #[rasn(tag(explicit(2)))]
    tickets: SequenceOf<Ticket>,
    #[rasn(tag(explicit(3)))]
    enc_part: EncryptedData,
}

impl Decode for KrbCred {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        constraints: Constraints,
    ) -> Result<Self, D::Error> {
        let w = KrbCredOnWire::decode_with_tag_and_constraints(decoder, tag, constraints)?;
        Ok(Self {
            pvno: w.pvno.0,
            msg_type: Self::MSG_TYPE,
            tickets: w.tickets,
            enc_part: w.enc_part,
        })
    }
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(tag(explicit(application, 29)))]
pub struct EncKrbCredPart {
    #[rasn(tag(explicit(0)))]
    pub ticket_info: SequenceOf<KrbCredInfo>,
    #[rasn(tag(explicit(1)))]
    pub nonce: Option<u32>,
    #[rasn(tag(explicit(2)))]
    pub timestamp: Option<KerberosTime>,
    #[rasn(tag(explicit(3)))]
    pub usec: Option<Microseconds>,
    #[rasn(tag(explicit(4)))]
    pub s_address: Option<HostAddress>,
    #[rasn(tag(explicit(5)))]
    pub r_address: Option<HostAddress>,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KrbCredInfo {
    #[rasn(tag(explicit(0)))]
    pub key: EncryptionKey,
    #[rasn(tag(explicit(1)))]
    pub prealm: Option<Realm>,
    #[rasn(tag(explicit(2)))]
    pub pname: Option<PrincipalName>,
    #[rasn(tag(explicit(3)))]
    pub flags: Option<crate::TicketFlags>,
    #[rasn(tag(explicit(4)))]
    pub authtime: Option<KerberosTime>,
    #[rasn(tag(explicit(5)))]
    pub starttime: Option<KerberosTime>,
    #[rasn(tag(explicit(6)))]
    pub endtime: Option<KerberosTime>,
    #[rasn(tag(explicit(7)))]
    pub renew_till: Option<KerberosTime>,
    #[rasn(tag(explicit(8)))]
    pub srealm: Option<Realm>,
    #[rasn(tag(explicit(9)))]
    pub sname: Option<PrincipalName>,
    #[rasn(tag(explicit(10)))]
    pub caddr: Option<crate::HostAddresses>,
}

/// RFC 3244 `ChangePasswdData`. `Debug` never shows the new password, nor its length.
#[derive(AsnType, Clone, Decode, Encode, PartialEq, Eq, Hash)]
pub struct ChangePasswdData {
    #[rasn(tag(explicit(0)))]
    pub newpasswd: OctetString,
    // MIT setpw_req; see docs/parity/a4-kadmin.md
    #[rasn(tag(explicit(1)))]
    pub targname: PrincipalName,
    #[rasn(tag(explicit(2)))]
    pub targrealm: Realm,
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
