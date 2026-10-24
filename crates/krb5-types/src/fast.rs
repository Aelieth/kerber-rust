use rasn::prelude::*;

use crate::{Checksum, EncryptedData, EncryptionKey, KdcReqBody, KerberosTime, PaData};

pub const ARMOR_AP_REQUEST: i32 = 1;

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KrbFastArmor {
    #[rasn(tag(explicit(0)))]
    pub armor_type: i32,
    #[rasn(tag(explicit(1)))]
    pub armor_value: OctetString,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KrbFastArmoredReq {
    #[rasn(tag(explicit(0)))]
    pub armor: Option<KrbFastArmor>,
    #[rasn(tag(explicit(1)))]
    pub req_checksum: Checksum,
    #[rasn(tag(explicit(2)))]
    pub enc_fast_req: EncryptedData,
}

pub type FastOptions = crate::KerberosFlags;

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KrbFastReq {
    #[rasn(tag(explicit(0)))]
    pub fast_options: FastOptions,
    #[rasn(tag(explicit(1)))]
    pub padata: SequenceOf<PaData>,
    #[rasn(tag(explicit(2)))]
    pub req_body: KdcReqBody,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KrbFastFinished {
    #[rasn(tag(explicit(0)))]
    pub timestamp: KerberosTime,
    #[rasn(tag(explicit(1)))]
    pub usec: crate::Microseconds,
    #[rasn(tag(explicit(2)))]
    pub crealm: crate::Realm,
    #[rasn(tag(explicit(3)))]
    pub cname: crate::PrincipalName,
    #[rasn(tag(explicit(4)))]
    pub ticket_checksum: Checksum,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KrbFastResponse {
    #[rasn(tag(explicit(0)))]
    pub padata: SequenceOf<PaData>,
    #[rasn(tag(explicit(1)))]
    pub strengthen_key: Option<EncryptionKey>,
    #[rasn(tag(explicit(2)))]
    pub finished: Option<KrbFastFinished>,
    #[rasn(tag(explicit(3)))]
    pub nonce: u32,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct KrbFastArmoredRep {
    #[rasn(tag(explicit(0)))]
    pub enc_fast_rep: EncryptedData,
}

// MIT: `SecureCookie` (asn1_k_encode.c:1683-1688)
// untagged SEQUENCE.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct SecureCookie {
    pub time: i32,
    pub data: SequenceOf<crate::PaData>,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum PaFxFast {
    #[rasn(tag(explicit(0)))]
    ArmoredData(KrbFastArmoredReq),
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum PaFxFastRep {
    #[rasn(tag(explicit(0)))]
    ArmoredData(KrbFastArmoredRep),
}

#[must_use]
pub fn fast_options_none() -> FastOptions {
    FastOptions::repeat(false, 32)
}
