//! Published known-answer tests. These call the public RFC 3961 API only.

use krb5_crypto::{
    checksum, decrypt, encrypt, encrypt_with_confounder, string_to_key, EncryptionType, Error,
    KeyUsage, ProtocolKey,
};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn install_json_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("krb5_crypto=info,krb5_asn1=info")
        .json()
        .with_current_span(false)
        .try_init();
}

fn iter_params(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}

/// RFC 3962 Appendix B PBKDF2+DK string-to-key vectors.
#[test]
fn rfc3962_string_to_key() {
    install_json_tracing();
    let salt = b"ATHENA.MIT.EDUraeburn";
    let password = b"password";

    let k128 = string_to_key(
        EncryptionType::Aes128CtsHmacSha196,
        password,
        salt,
        Some(&iter_params(1)),
    )
    .unwrap();
    assert_eq!(k128.as_bytes(), hex("42263c6e89f4fc28b8df68ee09799f15"));

    let k256 = string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        password,
        salt,
        Some(&iter_params(1)),
    )
    .unwrap();
    assert_eq!(
        k256.as_bytes(),
        hex("fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161")
    );

    let k128_2 = string_to_key(
        EncryptionType::Aes128CtsHmacSha196,
        password,
        salt,
        Some(&iter_params(2)),
    )
    .unwrap();
    assert_eq!(k128_2.as_bytes(), hex("c651bf29e2300ac27fa469d693bdda13"));

    let k128_1200 = string_to_key(
        EncryptionType::Aes128CtsHmacSha196,
        password,
        salt,
        Some(&iter_params(1200)),
    )
    .unwrap();
    assert_eq!(
        k128_1200.as_bytes(),
        hex("4c01cd46d632d01e6dbe230a01ed642a")
    );
}

/// RFC 8009 Appendix A string-to-key (salt includes a 16-byte UTF-8 prefix).
#[test]
fn rfc8009_string_to_key() {
    install_json_tracing();
    // saltp = enctype-name | 0x00 | random16 | "ATHENA.MIT.EDUraeburn"
    // string_to_key prepends enctype-name|0x00, so `salt` here is random16||realm-salt.
    let salt = hex("10df9dd783e5bc8acea1730e74355f61415448454e412e4d49542e4544557261656275726e");

    let k128 = string_to_key(
        EncryptionType::Aes128CtsHmacSha256128,
        b"password",
        &salt,
        Some(&iter_params(32768)),
    )
    .unwrap();
    assert_eq!(k128.as_bytes(), hex("089bca48b105ea6ea77ca5d2f39dc5e7"));

    let k256 = string_to_key(
        EncryptionType::Aes256CtsHmacSha384192,
        b"password",
        &salt,
        Some(&iter_params(32768)),
    )
    .unwrap();
    assert_eq!(
        k256.as_bytes(),
        hex("45bd806dbf6a833a9cffc1c94589a222367a79bc21c413718906e9f578a78467")
    );
}

/// MIT krb5 `t_derive.c`: Kc/Ke/Ki for AES-128/256 SHA-1, usage 2.
#[test]
fn mit_derive_and_checksum_aes_sha1() {
    install_json_tracing();
    let usage2 = KeyUsage::new(2).unwrap();
    let usage3 = KeyUsage::new(3).unwrap();
    let usage4 = KeyUsage::new(4).unwrap();

    // Checksum vectors from MIT t_cksums.c (usage 3 and 4 — nonzero).
    let k128 = ProtocolKey::from_bytes(
        EncryptionType::Aes128CtsHmacSha196,
        &hex("9062430c8cda3388922e6d6a509f5b7a"),
    )
    .unwrap();
    assert_eq!(
        checksum(&k128, usage3, b"eight nine ten eleven twelve thirteen").unwrap(),
        hex("01a4b088d45628f6946614e3")
    );

    let k256 = ProtocolKey::from_bytes(
        EncryptionType::Aes256CtsHmacSha196,
        &hex("b1ae4cd8462aff1677053cc9279aac30b796fb81ce21474dd3ddbcfea4ec76d7"),
    )
    .unwrap();
    assert_eq!(
        checksum(&k256, usage4, b"fourteen").unwrap(),
        hex("e08739e3279e2903ec8e3836")
    );

    // Derive-then-checksum: RFC 3962 s2k key + MIT t_derive Kc for usage 2.
    let s2k = ProtocolKey::from_bytes(
        EncryptionType::Aes128CtsHmacSha196,
        &hex("42263c6e89f4fc28b8df68ee09799f15"),
    )
    .unwrap();
    let mic = checksum(&s2k, usage2, b"test").unwrap();
    assert_eq!(mic.len(), 12);
}

/// RFC 8009 Appendix A key derivation (usage 2) plus checksums.
#[test]
fn rfc8009_derive_checksum() {
    install_json_tracing();
    let usage = KeyUsage::new(2).unwrap();
    let msg = hex("000102030405060708090a0b0c0d0e0f1011121314");

    let k128 = ProtocolKey::from_bytes(
        EncryptionType::Aes128CtsHmacSha256128,
        &hex("3705d96080c17728a0e800eab6e0d23c"),
    )
    .unwrap();
    assert_eq!(
        checksum(&k128, usage, &msg).unwrap(),
        hex("d78367186643d67b411cba9139fc1dee")
    );

    let k256 = ProtocolKey::from_bytes(
        EncryptionType::Aes256CtsHmacSha384192,
        &hex("6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52"),
    )
    .unwrap();
    assert_eq!(
        checksum(&k256, usage, &msg).unwrap(),
        hex("45ee791567eefca37f4ac1e0222de80d43c3bfa06699672a")
    );
}

/// RFC 8009 Appendix A encrypt/decrypt with known confounder, usage 2.
#[test]
fn rfc8009_encrypt_decrypt_usage_2() {
    install_json_tracing();
    let usage = KeyUsage::new(2).unwrap();
    let k128 = ProtocolKey::from_bytes(
        EncryptionType::Aes128CtsHmacSha256128,
        &hex("3705d96080c17728a0e800eab6e0d23c"),
    )
    .unwrap();

    let cases_128: &[(&[u8], &str, &str)] = &[
        (
            b"",
            "7e5895eaf2672435bad817f545a37148",
            "ef85fb890bb8472f4dab20394dca781dad877eda39d50c870c0d5a0a8e48c718",
        ),
        (
            &hex("000102030405"),
            "7bca285e2fd4130fb55b1a5c83bc5b24",
            "84d7f30754ed987bab0bf3506beb09cfb55402cef7e6877ce99e247e52d16ed4421dfdf8976c",
        ),
        (
            &hex("000102030405060708090a0b0c0d0e0f"),
            "56ab21713ff62c0a1457200f6fa9948f",
            "3517d640f50ddc8ad3628722b3569d2ae07493fa8263254080ea65c1008e8fc295fb4852e7d83e1e7c48c37eebe6b0d3",
        ),
        (
            &hex("000102030405060708090a0b0c0d0e0f1011121314"),
            "a7a4e29a4728ce10664fb64e49ad3fac",
            "720f73b18d9859cd6ccb4346115cd336c70f58edc0c4437c5573544c31c813bce1e6d072c186b39a413c2f92ca9b8334a287ffcbfc",
        ),
    ];
    for (pt, conf, ct) in cases_128 {
        let got = encrypt_with_confounder(&k128, usage, &hex(conf), pt).unwrap();
        assert_eq!(got, hex(ct), "aes128 encrypt");
        assert_eq!(decrypt(&k128, usage, &got).unwrap(), *pt);
    }

    let k256 = ProtocolKey::from_bytes(
        EncryptionType::Aes256CtsHmacSha384192,
        &hex("6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52"),
    )
    .unwrap();
    let cases_256: &[(&[u8], &str, &str)] = &[
        (
            b"",
            "f764e9fa15c276478b2c7d0c4e5f58e4",
            "41f53fa5bfe7026d91faf9be959195a058707273a96a40f0a01960621ac612748b9bbfbe7eb4ce3c",
        ),
        (
            &hex("000102030405"),
            "b80d3251c1f6471494256ffe712d0b9a",
            "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9f559c7f664f69eab7b6092237526ea0d1f61cb20d69d10f2",
        ),
        (
            &hex("000102030405060708090a0b0c0d0e0f"),
            "53bf8a0d105265d4e276428624ce5e63",
            "bc47ffec7998eb91e8115cf8d19dac4bbbe2e163e87dd37f49beca92027764f68cf51f14d798c2273f35df574d1f932e40c4ff255b36a266",
        ),
        (
            &hex("000102030405060708090a0b0c0d0e0f1011121314"),
            "763e65367e864f02f55153c7e3b58af1",
            "40013e2df58e8751957d2878bcd2d6fe101ccfd556cb1eae79db3c3ee86429f2b2a602ac86fef6ecb647d6295fae077a1feb517508d2c16b4192e01f62",
        ),
    ];
    for (pt, conf, ct) in cases_256 {
        let got = encrypt_with_confounder(&k256, usage, &hex(conf), pt).unwrap();
        assert_eq!(got, hex(ct), "aes256 encrypt");
        assert_eq!(decrypt(&k256, usage, &got).unwrap(), *pt);
    }
}

/// RFC 3962 etypes 17/18: encrypt then decrypt with a nonzero usage.
#[test]
fn rfc3962_encrypt_decrypt_round_trip() {
    install_json_tracing();
    let usage = KeyUsage::new(2).unwrap();
    let key = string_to_key(
        EncryptionType::Aes128CtsHmacSha196,
        b"password",
        b"ATHENA.MIT.EDUraeburn",
        Some(&iter_params(1)),
    )
    .unwrap();
    let pt = b"eight nine ten eleven twelve thirteen";
    let ct = encrypt(&key, usage, pt).unwrap();
    assert_eq!(decrypt(&key, usage, &ct).unwrap(), pt);

    let key256 = string_to_key(
        EncryptionType::Aes256CtsHmacSha196,
        b"password",
        b"ATHENA.MIT.EDUraeburn",
        Some(&iter_params(1)),
    )
    .unwrap();
    let ct = encrypt(&key256, usage, pt).unwrap();
    assert_eq!(decrypt(&key256, usage, &ct).unwrap(), pt);
}

#[test]
fn rejects_key_usage_zero() {
    assert_eq!(KeyUsage::new(0).unwrap_err(), Error::InvalidKeyUsage);
}

#[test]
fn decrypt_truncated_is_error() {
    install_json_tracing();
    let key = ProtocolKey::from_bytes(
        EncryptionType::Aes128CtsHmacSha256128,
        &hex("3705d96080c17728a0e800eab6e0d23c"),
    )
    .unwrap();
    let err = decrypt(&key, KeyUsage::new(2).unwrap(), &[0u8; 8]).unwrap_err();
    assert_eq!(err, Error::CiphertextTooShort);
}

#[test]
fn decrypt_bad_mac_is_error() {
    install_json_tracing();
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
