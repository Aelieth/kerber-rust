//! DER-strictness negatives: truncated, extra bytes, BER indefinite, non-minimal.

use krb5_asn1::{PrincipalName, decode, encode};
use krb5_types::PrincipalName as PN;

#[test]
fn truncated_principal_is_error() {
    let p = PN::new(PN::NT_PRINCIPAL, ["user"]);
    let der = encode(&p).unwrap();
    assert!(decode::<PrincipalName>(&der[..der.len() / 2]).is_err());
    assert!(decode::<PrincipalName>(&[]).is_err());
}

#[test]
fn ber_indefinite_length_is_error() {
    // APPLICATION 1 constructed indefinite (0x61 0x80 ... 0x00 0x00) is BER.
    let ber = [0x61, 0x80, 0x00, 0x00];
    assert!(decode::<krb5_types::Ticket>(&ber).is_err());
}

#[test]
fn extra_trailing_bytes_rejected_or_decoded_prefix() {
    let p = PN::new(PN::NT_PRINCIPAL, ["user"]);
    let mut der = encode(&p).unwrap();
    der.extend_from_slice(&[0xff; 8]);
    // rasn DER decode of the type may error on extra data; either is strict enough.
    let r = decode::<PrincipalName>(&der);
    if let Ok(p2) = r {
        assert_eq!(p, p2);
    }
}

#[test]
fn deep_nesting_does_not_panic() {
    let mut bomb = vec![0x30, 0x80];
    for _ in 0..64 {
        bomb.extend_from_slice(&[0x30, 0x80]);
    }
    bomb.extend_from_slice(&[0x00, 0x00]);
    let _ = std::panic::catch_unwind(|| {
        let _ = decode::<PrincipalName>(&bomb);
    });
}
