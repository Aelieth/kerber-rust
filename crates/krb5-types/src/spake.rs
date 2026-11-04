use rasn::prelude::*;

use crate::EncryptedData;

pub const GROUP_EDWARDS25519: i32 = 1;
pub const GROUP_P256: i32 = 2;
pub const SF_NONE: i32 = 1;

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct SpakeSecondFactor {
    #[rasn(tag(explicit(0)))]
    pub factor_type: i32,
    #[rasn(tag(explicit(1)))]
    pub data: Option<OctetString>,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct SpakeSupport {
    #[rasn(tag(explicit(0)))]
    pub groups: SequenceOf<i32>,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct SpakeChallenge {
    #[rasn(tag(explicit(0)))]
    pub group: i32,
    #[rasn(tag(explicit(1)))]
    pub pubkey: OctetString,
    #[rasn(tag(explicit(2)))]
    pub factors: SequenceOf<SpakeSecondFactor>,
}

#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct SpakeResponse {
    #[rasn(tag(explicit(0)))]
    pub pubkey: OctetString,
    #[rasn(tag(explicit(1)))]
    pub factor: EncryptedData,
}

// MIT: `decode_cntype` (lib/krb5/asn.1/asn1_encode.c:1245-1300)
// MIT: `spake_verify` (plugins/preauth/spake/spake_kdc.c:501-539)
// MIT: `spake_process` (plugins/preauth/spake/spake_client.c:357-359)
// The client takes it as an unexpected message, as it takes a support or a response.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PaSpake {
    Support(SpakeSupport),
    Challenge(SpakeChallenge),
    Response(SpakeResponse),
    EncData(EncryptedData),
    Unknown,
}

#[derive(AsnType, Decode, Encode)]
#[rasn(choice)]
enum PaSpakeKnown {
    #[rasn(tag(explicit(0)))]
    Support(SpakeSupport),
    #[rasn(tag(explicit(1)))]
    Challenge(SpakeChallenge),
    #[rasn(tag(explicit(2)))]
    Response(SpakeResponse),
    #[rasn(tag(explicit(3)))]
    EncData(EncryptedData),
}

impl AsnType for PaSpake {
    const TAG: Tag = Tag::EOC;
    const IS_CHOICE: bool = true;
}

impl Decode for PaSpake {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, D::Error> {
        let element = Any::decode(decoder)?;
        let der = element.as_bytes();
        if der.first().is_some_and(|&id| (0xa0..=0xa3).contains(&id)) {
            let known: PaSpakeKnown = rasn::der::decode(der).map_err(D::Error::from)?;
            return Ok(match known {
                PaSpakeKnown::Support(v) => Self::Support(v),
                PaSpakeKnown::Challenge(v) => Self::Challenge(v),
                PaSpakeKnown::Response(v) => Self::Response(v),
                PaSpakeKnown::EncData(v) => Self::EncData(v),
            });
        }
        Ok(Self::Unknown)
    }

    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        _: Constraints,
    ) -> Result<Self, D::Error> {
        decoder.decode_explicit_prefix(tag)
    }
}

impl Encode for PaSpake {
    fn encode<'b, E: Encoder<'b>>(&self, encoder: &mut E) -> Result<(), E::Error> {
        let known = match self {
            Self::Support(v) => PaSpakeKnown::Support(v.clone()),
            Self::Challenge(v) => PaSpakeKnown::Challenge(v.clone()),
            Self::Response(v) => PaSpakeKnown::Response(v.clone()),
            Self::EncData(v) => PaSpakeKnown::EncData(v.clone()),
            Self::Unknown => {
                return Err(<E::Error as rasn::enc::Error>::custom(
                    "PA-SPAKE has no known choice",
                    encoder.codec(),
                ));
            }
        };
        known.encode(encoder)
    }

    fn encode_with_tag_and_constraints<'b, E: Encoder<'b>>(
        &self,
        encoder: &mut E,
        tag: Tag,
        _: Constraints,
        identifier: Identifier,
    ) -> Result<(), E::Error> {
        encoder
            .encode_explicit_prefix(tag, self, identifier)
            .map(drop)
    }
}
