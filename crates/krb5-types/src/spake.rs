//! SPAKE preauth (MIT PA-SPAKE, type 151) message envelopes.

use rasn::prelude::*;

use crate::EncryptedData;

/// SPAKE group: edwards25519 (draft-ietf-kitten-krb-spake-preauth).
pub const GROUP_EDWARDS25519: i32 = 1;
/// SPAKE group: P-256.
pub const GROUP_P256: i32 = 2;

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

/// PA-SPAKE ::= CHOICE { support[0], challenge[1], response[2], encData[3] }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
#[rasn(choice)]
pub enum PaSpake {
    /// Client support advertisement.
    #[rasn(tag(explicit(0)))]
    Support(SpakeSupport),
    /// KDC challenge.
    #[rasn(tag(explicit(1)))]
    Challenge(SpakeChallenge),
    /// Client response.
    #[rasn(tag(explicit(2)))]
    Response(SpakeResponse),
    /// Encrypted data after the SPAKE key is established.
    #[rasn(tag(explicit(3)))]
    EncData(EncryptedData),
}
