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
