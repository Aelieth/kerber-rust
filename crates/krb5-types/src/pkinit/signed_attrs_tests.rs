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
