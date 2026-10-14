//! SPAKE preauth (MIT PA-SPAKE, type 151) message envelopes.
//!
//! Group 2 is P-256. SF-NONE is factor type 1. The factor type is
//! required; the factor data is optional.

use rasn::prelude::*;

use crate::EncryptedData;

/// SPAKE group: edwards25519 (draft-ietf-kitten-krb-spake-preauth).
pub const GROUP_EDWARDS25519: i32 = 1;
/// SPAKE group: P-256.
pub const GROUP_P256: i32 = 2;
/// SPAKE second-factor type SF-NONE (no second factor), MIT iana.h
/// `SPAKE_SF_NONE`.
pub const SF_NONE: i32 = 1;

/// SPAKESecondFactor ::= SEQUENCE { type, data, replacement }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct SpakeSecondFactor {
    /// Second-factor type.
    #[rasn(tag(explicit(0)))]
    pub factor_type: i32,
    /// Factor-specific challenge/response.
    #[rasn(tag(explicit(1)))]
    pub data: Option<OctetString>,
}

/// SPAKESupport ::= SEQUENCE { groups }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct SpakeSupport {
    /// Group numbers the client supports.
    #[rasn(tag(explicit(0)))]
    pub groups: SequenceOf<i32>,
}

/// SPAKEChallenge ::= SEQUENCE { group, pubkey, factors }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct SpakeChallenge {
    /// Selected group.
    #[rasn(tag(explicit(0)))]
    pub group: i32,
    /// KDC SPAKE public share.
    #[rasn(tag(explicit(1)))]
    pub pubkey: OctetString,
    /// Second-factor challenges.
    #[rasn(tag(explicit(2)))]
    pub factors: SequenceOf<SpakeSecondFactor>,
}

/// SPAKEResponse ::= SEQUENCE { pubkey, factor }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct SpakeResponse {
    /// Client SPAKE public share.
    #[rasn(tag(explicit(0)))]
    pub pubkey: OctetString,
    /// Encrypted second-factor response.
    #[rasn(tag(explicit(1)))]
    pub factor: EncryptedData,
}

/// `PA-SPAKE ::= CHOICE { support[0], challenge[1], response[2], encData[3] }`
///
/// MIT `decode_cntype` (`lib/krb5/asn.1/asn1_encode.c:1277-1293`): every CHOICE is extensible, so an element no alternative takes, by its tag or by its constructed bit, decodes as an unknown choice (`SPAKE_MSGTYPE_UNKNOWN`).
/// MIT `spake_verify` (`plugins/preauth/spake/spake_kdc.c:532-535`): the KDC answers an unknown choice with PREAUTH_FAILED.
/// MIT `spake_process` (`plugins/preauth/spake/spake_client.c:357-359`): the client takes it as an unexpected message, as it takes a support or a response.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PaSpake {
    /// Client support advertisement.
    Support(SpakeSupport),
    /// KDC challenge.
    Challenge(SpakeChallenge),
    /// Client response.
    Response(SpakeResponse),
    /// Encrypted data after the SPAKE key is established.
    EncData(EncryptedData),
    /// An alternative MIT does not know; it is never encoded.
    Unknown,
}

/// [`PaSpake`]'s four alternatives, as rasn derives them.
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
        // `[0]` to `[3]`, context-specific and constructed: one of the four.
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
