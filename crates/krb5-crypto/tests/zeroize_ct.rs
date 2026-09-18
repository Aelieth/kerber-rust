//! Pins Drop+zeroize and the live `ct_eq` sites.
//!
//! Heap `Vec` secrets cannot be read after `Drop` without UB, so those
//! types are pinned by `include_str!` of the `.zeroize()` line. Array
//! `PkinitClient::key` is the same shape. A MAC bit-flip still fails
//! decrypt (behaviour, not timing). Each test is red when the matching
//! `zeroize` / `ct_eq` line is removed.

use krb5_crypto::{
    DerivedKeys, DhKeypair, EncryptionType, Error, KeyUsage, OAKLEY_2048, ProtocolKey, checksum,
    decrypt, derive_keys, dh_generate, encrypt_with_confounder, verify_checksum_type,
};

const KEY_RS: &str = include_str!("../src/key.rs");
const DERIVE_RS: &str = include_str!("../src/derive.rs");
const MODP_RS: &str = include_str!("../src/modp.rs");
const PKINIT_CLIENT_RS: &str = include_str!("../../krb5-protocol/src/as_ex.rs");
const ENCRYPTION_KEY_RS: &str = include_str!("../../krb5-types/src/lib.rs");
const AUTHPACK_RS: &str = include_str!("../../krb5-types/src/pkinit.rs");
const STORE_RS: &str = include_str!("../../krb5-kdc/src/store.rs");
const OPS_RS: &str = include_str!("../src/ops.rs");

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn protocol_key_drop_zeroizes() {
    assert!(
        KEY_RS.contains("impl Drop for ProtocolKey") && KEY_RS.contains("self.bytes.zeroize()"),
        "ProtocolKey Drop must zeroize key bytes"
    );
    let key = ProtocolKey::from_bytes(
        EncryptionType::Aes128CtsHmacSha256128,
        &hex("3705d96080c17728a0e800eab6e0d23c"),
    )
    .unwrap();
    assert_eq!(key.as_bytes().len(), 16);
    drop(key);
}

#[test]
fn derived_keys_drop_zeroizes() {
    assert!(
        DERIVE_RS.contains("impl Drop for DerivedKeys")
            && DERIVE_RS.contains("self.kc.zeroize()")
            && DERIVE_RS.contains("self.ke.zeroize()")
            && DERIVE_RS.contains("self.ki.zeroize()"),
        "DerivedKeys Drop must zeroize kc/ke/ki"
    );
    let key = ProtocolKey::from_bytes(
        EncryptionType::Aes128CtsHmacSha256128,
        &hex("3705d96080c17728a0e800eab6e0d23c"),
    )
    .unwrap();
    let usage = KeyUsage::new(2).unwrap();
    let derived: DerivedKeys = derive_keys(&key, usage).unwrap();
    assert_eq!(derived.kc.len(), 16);
    drop(derived);
}

#[test]
fn dh_keypair_drop_zeroizes() {
    assert!(
        MODP_RS.contains("impl Drop for DhKeypair") && MODP_RS.contains("self.secret.zeroize()"),
        "DhKeypair Drop must zeroize the exponent"
    );
    let kp: DhKeypair = dh_generate(&OAKLEY_2048).unwrap();
    assert!(!kp.secret.is_empty());
    drop(kp);
}

#[test]
fn pkinit_client_drop_zeroizes() {
    assert!(
        PKINIT_CLIENT_RS.contains("impl Drop for PkinitClient")
            && PKINIT_CLIENT_RS.contains("self.key.zeroize()"),
        "PkinitClient Drop must zeroize the P-256 scalar"
    );
}

#[test]
fn encryption_key_drop_zeroizes() {
    assert!(
        ENCRYPTION_KEY_RS.contains("impl Drop for EncryptionKey")
            && ENCRYPTION_KEY_RS.contains("v.zeroize()"),
        "EncryptionKey Drop must zeroize the copied keyvalue"
    );
}

#[test]
fn mac_verify_rejects_one_bit_flip() {
    assert!(
        DERIVE_RS.contains("got.ct_eq(expected)"),
        "mac_verify must compare with ct_eq"
    );
    let usage = KeyUsage::new(2).unwrap();
    let key = ProtocolKey::from_bytes(
        EncryptionType::Aes128CtsHmacSha256128,
        &hex("3705d96080c17728a0e800eab6e0d23c"),
    )
    .unwrap();
    let mut ct =
        encrypt_with_confounder(&key, usage, &hex("7e5895eaf2672435bad817f545a37148"), b"")
            .unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    assert_eq!(decrypt(&key, usage, &ct).unwrap_err(), Error::Integrity);
}

#[test]
fn checksum_bit_flip_is_integrity() {
    assert!(
        OPS_RS.contains("let expected = keyed_checksum_for_type")
            && OPS_RS.contains("mac_verify(mac, &expected)"),
        "verify_checksum_type must compare with mac_verify"
    );
    let usage = KeyUsage::new(2).unwrap();
    let key = ProtocolKey::from_bytes(
        EncryptionType::Aes128CtsHmacSha256128,
        &hex("3705d96080c17728a0e800eab6e0d23c"),
    )
    .unwrap();
    let data = b"one-bit-flip";
    let mut mac = checksum(&key, usage, data).unwrap();
    mac[0] ^= 0x01;
    assert_eq!(
        verify_checksum_type(&key, usage, data, 0, &mac).unwrap_err(),
        Error::Integrity
    );
}

#[test]
fn authpack_pa_checksum_uses_ct_eq() {
    assert!(
        AUTHPACK_RS.contains("authpack_pa_checksum_ok")
            && AUTHPACK_RS.contains("ConstantTimeEq::ct_eq"),
        "authpack_pa_checksum_ok must compare with ct_eq"
    );
}

#[test]
fn password_history_uses_ct_eq() {
    assert!(
        STORE_RS.contains("nk.as_bytes().ct_eq(k.key.as_bytes())"),
        "password-history compare must use ct_eq"
    );
}

#[test]
fn protocol_key_has_no_eq() {
    assert!(
        !KEY_RS.contains("PartialEq") && !KEY_RS.contains("impl Eq"),
        "ProtocolKey must not grow an Eq that invites == on key bytes"
    );
}
