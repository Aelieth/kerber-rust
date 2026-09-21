use super::*;
use sha2::{Digest, Sha256};

#[test]
fn rfc8636_other_info_is_stable_and_oid_specific() {
    let client = encode_krb5_principal_name("SU.SE", 1, &["lha"]);
    let server = encode_krb5_principal_name("SU.SE", 2, &["krbtgt", "SU.SE"]);
    let supp = encode_pkinit_supp_pub_info(18, &[0xAA; 10], &[0xBB; 9]);
    let other = encode_rfc8636_other_info(KDF_AH_SHA256_OID, &client, &server, &supp);
    let oid384: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x02, 0x03, 0x06, 0x04];
    let other384 = encode_rfc8636_other_info(oid384, &client, &server, &supp);
    assert_ne!(other, other384);
    assert!(other.starts_with(&[0x30]));
    let z = vec![0u8; 256];
    let mut h = Sha256::new();
    h.update(1u32.to_be_bytes());
    h.update(&z);
    h.update(&other);
    let key: [u8; 32] = h.finalize().into();
    let again = encode_rfc8636_other_info(KDF_AH_SHA256_OID, &client, &server, &supp);
    let mut h2 = Sha256::new();
    h2.update(1u32.to_be_bytes());
    h2.update(&z);
    h2.update(&again);
    let key2: [u8; 32] = h2.finalize().into();
    assert_eq!(key, key2);
}
