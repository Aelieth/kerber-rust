//! AD-CAMMAC (RFC 4120 / MIT `cammac.asn1`).

use rasn::prelude::*;

use crate::{AuthorizationData, Checksum, PrincipalName, Realm};

/// AD-KDCIssued ::= SEQUENCE { ad-checksum, i-realm, i-sname, elements }
/// (`rfc4120#section-5.2.6.2`).
#[derive(AsnType, Clone, Debug, Decode, Encode, PartialEq, Eq, Hash)]
pub struct AdKdcIssued {
    #[rasn(tag(explicit(0)))]
    pub ad_checksum: Checksum,
    #[rasn(tag(explicit(1)))]
    pub i_realm: Option<Realm>,
    #[rasn(tag(explicit(2)))]
    pub i_sname: Option<PrincipalName>,
    #[rasn(tag(explicit(3)))]
    pub elements: AuthorizationData,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mit_sample_ad_kdcissued_decodes() {
        let der = hex_literal(
            "30 65 A0 0F 30 0D A0 03 02 01 01 A1 06 04 04 31 32 33 34 \
             A1 10 1B 0E 41 54 48 45 4E 41 2E 4D 49 54 2E 45 44 55 \
             A2 1A 30 18 A0 03 02 01 01 A1 11 30 0F 1B 06 68 66 74 73 61 69 1B 05 65 78 74 72 61 \
             A3 24 30 22 30 0F A0 03 02 01 01 A1 08 04 06 66 6F 6F 62 61 72 30 0F A0 03 02 01 01 A1 08 04 06 66 6F 6F 62 61 72",
        );
        let issued: AdKdcIssued = rasn::der::decode(&der).expect("MIT sample");
        assert_eq!(issued.ad_checksum.cksumtype, 1);
        assert_eq!(issued.ad_checksum.checksum.as_ref(), b"1234");
        assert_eq!(
            issued.i_realm.as_ref().map(|r| r.as_bytes()),
            Some(b"ATHENA.MIT.EDU".as_slice())
        );
        assert_eq!(issued.elements.len(), 2);
        assert_eq!(issued.elements[0].ad_data.as_ref(), b"foobar");
    }

    fn hex_literal(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).expect("hex"))
            .collect()
    }
}
