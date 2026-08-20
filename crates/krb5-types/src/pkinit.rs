//! RFC 4556 PKINIT PA-DATA types (AuthPack / PA-PK-AS-REQ / PA-PK-AS-REP).

use rasn::prelude::*;

use crate::{Checksum, KerberosTime, Microseconds, OctetString};

/// PA-PK-AS-REQ ::= SEQUENCE { signedAuthPack, trustedCertifiers, kdcPkId }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaPkAsReq {
    /// CMS SignedData wrapping [`AuthPack`] (DER).
    #[rasn(tag(explicit(0)))]
    pub signed_auth_pack: OctetString,
    /// Optional trusted certifiers (opaque DER).
    #[rasn(tag(explicit(1)))]
    pub trusted_certifiers: Option<SequenceOf<OctetString>>,
    /// Optional KDC public-key identifier.
    #[rasn(tag(explicit(2)))]
    pub kdc_pk_id: Option<OctetString>,
}

/// PKAuthenticator ::= SEQUENCE { cusec, ctime, nonce, paChecksum, … }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PkAuthenticator {
    /// Client microseconds.
    #[rasn(tag(explicit(0)))]
    pub cusec: Microseconds,
    /// Client time.
    #[rasn(tag(explicit(1)))]
    pub ctime: KerberosTime,
    /// Nonce.
    #[rasn(tag(explicit(2)))]
    pub nonce: u32,
    /// Optional checksum of the KDC-REQ-BODY.
    #[rasn(tag(explicit(3)))]
    pub pa_checksum: Option<Checksum>,
}

/// AuthPack ::= SEQUENCE { pkAuthenticator, clientPublicValue, … }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct AuthPack {
    /// PKAuthenticator.
    #[rasn(tag(explicit(0)))]
    pub pk_authenticator: PkAuthenticator,
    /// SubjectPublicKeyInfo DER (client DH/ECDH public value).
    #[rasn(tag(explicit(1)))]
    pub client_public_value: Option<OctetString>,
    /// Optional supported CMS types.
    #[rasn(tag(explicit(2)))]
    pub supported_cms_types: Option<SequenceOf<OctetString>>,
}

/// DHRepInfo ::= SEQUENCE { dhSignedData, serverDHNonce }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct DhRepInfo {
    /// CMS SignedData wrapping ReplyKeyPack / server DH public.
    #[rasn(tag(explicit(0)))]
    pub dh_signed_data: OctetString,
    /// Optional server DH nonce.
    #[rasn(tag(explicit(1)))]
    pub server_dh_nonce: Option<OctetString>,
}

/// PA-PK-AS-REP ::= CHOICE { dhInfo[0], encKeyPack[1] }
///
/// Encoded as a context-tagged wrapper; this struct holds the dhInfo arm.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct PaPkAsRep {
    /// DH reply info.
    #[rasn(tag(explicit(0)))]
    pub dh_info: Option<DhRepInfo>,
    /// Encrypted key pack (CMS EnvelopedData) when DH is not used.
    #[rasn(tag(explicit(1)))]
    pub enc_key_pack: Option<OctetString>,
}

/// ReplyKeyPack ::= SEQUENCE { replyKey, asChecksum }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct ReplyKeyPack {
    /// AS reply key.
    #[rasn(tag(explicit(0)))]
    pub reply_key: crate::EncryptionKey,
    /// Checksum of the corresponding AS-REQ.
    #[rasn(tag(explicit(1)))]
    pub as_checksum: Checksum,
}

/// Anonymous PKINIT well-known client name (`WELLKNOWN/ANONYMOUS`).
#[must_use]
pub fn anonymous_client() -> crate::PrincipalName {
    crate::PrincipalName::new(
        crate::PrincipalName::NT_PRINCIPAL,
        ["WELLKNOWN", "ANONYMOUS"],
    )
}
