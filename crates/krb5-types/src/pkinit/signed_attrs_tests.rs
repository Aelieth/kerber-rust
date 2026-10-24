use super::cms::{cert_issuer_serial, p256_sign};
use super::*;

#[test]
fn cms_verify_refuses_missing_signed_attrs() {
    let ca = PkinitCa::generate().expect("CA");
    let (cert, key) = ca.client_identity_for("user@KERBER.TEST").expect("id");
    let inner = b"bare-econtent";
    let (issuer, serial) = cert_issuer_serial(&cert).expect("ias");
    let sig = p256_sign(&key, inner).expect("sig");
    let cms = cms_wrap_signed(
        inner,
        &cert,
        &sig,
        &issuer,
        &serial,
        ECONTENT_AUTHDATA,
        None,
        super::cms::OID_ECDSA_SHA256,
    );
    assert_eq!(
        cms_verify_full(&cms, &ca.ca_cert).expect_err("bare"),
        "cms signedAttrs"
    );
}

#[test]
fn cms_unsigned_contentinfo_round_trips() {
    let inner = b"anon-authpack";
    let wrap = cms_wrap_unsigned(inner);
    assert_eq!(
        cms_extract_unsigned(&wrap).as_deref(),
        Some(inner.as_slice())
    );
    assert!(cms_verify_full(&wrap, &[]).is_err());
}

#[test]
fn ecdsa_der_takes_only_its_own_der() {
    use super::cms::ecdsa_der;
    // r = 1, s = 2 as a minimal ECDSA-Sig-Value.
    let ok = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
    assert_eq!(ecdsa_der(&ok), Some((&[1u8][..], &[2u8][..])));
    // A trailing byte, a non-minimal length, a leading-zero INTEGER and a wrong tag are each refused,
    // as OpenSSL's d2i_ECDSA_SIG refuses a signature that is not exactly its own encoding.
    assert_eq!(ecdsa_der(&[&ok[..], &[0x00]].concat()), None);
    assert_eq!(
        ecdsa_der(&[0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]),
        None
    );
    assert_eq!(
        ecdsa_der(&[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x02]),
        None
    );
    assert_eq!(
        ecdsa_der(&[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]),
        None
    );
    assert_eq!(ecdsa_der(&[]), None);
}

#[test]
fn cms_template_walks_the_signeddata_structure() {
    use super::cms::cms_decode_reason;
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if let Ok(len) = u8::try_from(body.len()) {
            out.push(len);
        } else {
            let bytes = body.len().to_be_bytes();
            let start = bytes.iter().position(|b| *b != 0).unwrap();
            out.push(0x80 | u8::try_from(bytes.len() - start).unwrap());
            out.extend_from_slice(&bytes[start..]);
        }
        out.extend_from_slice(body);
        out
    }
    let oid = |v: &[u8]| tlv(0x06, v);
    let signed_data_oid: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
    let authdata: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x01];
    let sha256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    // A minimal SignedData: version, one DigestAlgorithmIdentifier, an encap, no certs, no signers.
    let digest_algs = |inner_tag: u8| tlv(0x31, &tlv(0x30, &tlv(inner_tag, sha256)));
    let build = |algs: &[u8], extra: &[u8]| {
        let mut sd = tlv(0x02, &[0x03]);
        sd.extend(algs.iter().copied());
        sd.extend(tlv(0x30, &oid(authdata)));
        sd.extend(tlv(0x31, &[]));
        sd.extend_from_slice(extra);
        tlv(
            0x30,
            &[oid(signed_data_oid), tlv(0xa0, &tlv(0x30, &sd))].concat(),
        )
    };
    // Well formed: it decodes.
    assert_eq!(cms_decode_reason(&build(&digest_algs(0x06), &[])), None);
    // A trailing element in the SignedData SEQUENCE (part 1).
    assert_eq!(
        cms_decode_reason(&build(&digest_algs(0x06), &tlv(0x05, &[]))),
        Some("sequence length mismatch")
    );
    // A wrong tag inside a DigestAlgorithmIdentifier (part 2).
    assert_eq!(
        cms_decode_reason(&build(&digest_algs(0x05), &[])),
        Some("wrong tag")
    );
}
