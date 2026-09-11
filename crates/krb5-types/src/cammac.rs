//! AD-CAMMAC (RFC 4120 / MIT `cammac.asn1`).

use rasn::prelude::*;

use crate::{AuthorizationData, Checksum, PrincipalName};

/// Verifier-MAC ::= SEQUENCE { identifier, kvno, enctype, mac }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct VerifierMac {
    #[rasn(tag(explicit(0)))]
    pub identifier: Option<PrincipalName>,
    #[rasn(tag(explicit(1)))]
    pub kvno: Option<u32>,
    #[rasn(tag(explicit(2)))]
    pub enctype: Option<i32>,
    #[rasn(tag(explicit(3)))]
    pub mac: Checksum,
}

/// AD-CAMMAC ::= SEQUENCE { elements, kdc-verifier, svc-verifier, other-verifiers }
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct Cammac {
    #[rasn(tag(explicit(0)))]
    pub elements: AuthorizationData,
    #[rasn(tag(explicit(1)))]
    pub kdc_verifier: Option<VerifierMac>,
    #[rasn(tag(explicit(2)))]
    pub svc_verifier: Option<VerifierMac>,
    #[rasn(tag(explicit(3)))]
    pub other_verifiers: Option<SequenceOf<VerifierMac>>,
}
