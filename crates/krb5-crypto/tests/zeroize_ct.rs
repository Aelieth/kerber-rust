//! Pins the live `ct_eq` sites and `PkinitClient`'s Drop+zeroize.
//!
//! A one-bit MAC flip fails decrypt and checksum verify: behaviour, not timing.
//! That those compares are constant-time is a check of the source text only,
//! and no test measures timing: one test pins `mac_verify`'s `ct_eq`, another
//! the two lines of `verify_checksum_type`'s keyed compare, and each is red when
//! its text is removed. `PkinitClient::key` is pinned by an `include_str!` of
//! its `.zeroize()` line; the other zeroize-on-drop types are proved by unit
//! tests that see the wiped buffer (`wipe.rs` in `krb5-crypto` and `krb5-types`).

use krb5_crypto::{
    EncryptionType, Error, KeyUsage, ProtocolKey, checksum, decrypt, encrypt_with_confounder,
    verify_checksum_type,
};

const DERIVE_RS: &str = include_str!("../src/derive.rs");
const PKINIT_CLIENT_RS: &str = include_str!("../../krb5-protocol/src/as_ex.rs");
const AUTHPACK_RS: &str = include_str!("../../krb5-types/src/pkinit.rs");
const STORE_RS: &str = include_str!("../../krb5-kdc/src/store/password.rs");
const OPS_RS: &str = include_str!("../src/ops.rs");

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
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
        OPS_RS.contains(
            "    let expected = keyed_checksum_for_type(key, usage, message, ctype)?;\n    \
             mac_verify(mac, &expected)\n}\n"
        ),
        "verify_checksum_type's keyed compare must go through mac_verify"
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
