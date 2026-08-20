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

/// CMS AlgorithmIdentifier (digest or signature).
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CmsAlgorithmIdentifier {
    /// Object identifier.
    pub algorithm: ObjectIdentifier,
    /// Optional parameters.
    pub parameters: Option<OctetString>,
}

/// CMS EncapsulatedContentInfo.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CmsEncapContentInfo {
    /// eContentType (id-pkinit-authData or id-data).
    pub e_content_type: ObjectIdentifier,
    /// eContent.
    #[rasn(tag(explicit(0)))]
    pub e_content: Option<OctetString>,
}

/// CMS SignerInfo (subjectKeyIdentifier form, no signedAttrs).
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CmsSignerInfo {
    /// version (3 when sid is subjectKeyIdentifier).
    pub version: i32,
    /// subjectKeyIdentifier [0] EXPLICIT (local CMS profile).
    #[rasn(tag(explicit(0)))]
    pub sid: OctetString,
    /// Digest algorithm.
    pub digest_algorithm: CmsAlgorithmIdentifier,
    /// Signature algorithm.
    pub signature_algorithm: CmsAlgorithmIdentifier,
    /// Signature value (SHA-256 of eContent in this implementation).
    pub signature: OctetString,
}

/// CMS SignedData.
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CmsSignedData {
    /// CMSVersion.
    pub version: i32,
    /// DigestAlgorithmIdentifiers.
    pub digest_algorithms: SequenceOf<CmsAlgorithmIdentifier>,
    /// Encapsulated content.
    pub encap_content_info: CmsEncapContentInfo,
    /// SignerInfos.
    pub signer_infos: SequenceOf<CmsSignerInfo>,
}

/// CMS ContentInfo wrapping [`CmsSignedData`].
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct CmsContentInfo {
    /// id-signedData.
    pub content_type: ObjectIdentifier,
    /// SignedData [0] EXPLICIT.
    #[rasn(tag(explicit(0)))]
    pub content: CmsSignedData,
}

fn oid_signed_data() -> ObjectIdentifier {
    ObjectIdentifier::new(&[1, 2, 840, 113_549, 1, 7, 2]).expect("id-signedData")
}

fn oid_pkinit_authdata() -> ObjectIdentifier {
    ObjectIdentifier::new(&[1, 3, 6, 1, 5, 2, 3, 1]).expect("id-pkinit-authData")
}

fn oid_sha256() -> ObjectIdentifier {
    ObjectIdentifier::new(&[2, 16, 840, 1, 101, 3, 4, 2, 1]).expect("id-sha256")
}

/// Wrap `e_content` in a CMS SignedData ContentInfo.
///
/// The SignerInfo signature is SHA-256 of `e_content` (no X.509
/// certificates). Callers that need a raw inner blob should use
/// [`cms_unwrap`].
#[must_use]
pub fn cms_wrap(e_content: &[u8]) -> Vec<u8> {
    let digest = sha256_bytes(e_content);
    let alg = CmsAlgorithmIdentifier {
        algorithm: oid_sha256(),
        parameters: None,
    };
    let sd = CmsSignedData {
        version: 3,
        digest_algorithms: vec![alg.clone()],
        encap_content_info: CmsEncapContentInfo {
            e_content_type: oid_pkinit_authdata(),
            e_content: Some(e_content.to_vec().into()),
        },
        signer_infos: vec![CmsSignerInfo {
            version: 3,
            sid: OctetString::from(digest.clone()),
            digest_algorithm: alg.clone(),
            signature_algorithm: alg,
            signature: digest.into(),
        }],
    };
    let ci = CmsContentInfo {
        content_type: oid_signed_data(),
        content: sd,
    };
    rasn::der::encode(&ci).unwrap_or_else(|_| e_content.to_vec())
}

/// Extract eContent from [`cms_wrap`], or return `der` unchanged if it is not CMS.
#[must_use]
pub fn cms_unwrap(der: &[u8]) -> Vec<u8> {
    if let Ok(ci) = rasn::der::decode::<CmsContentInfo>(der) {
        if let Some(ec) = ci.content.encap_content_info.e_content {
            return ec.to_vec();
        }
    }
    der.to_vec()
}

fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).to_vec()
}
