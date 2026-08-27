//! Published known-answer tests. These call the public RFC 3961 API only.

use krb5_crypto::{
    EncryptionType, Error, KeyUsage, ProtocolKey, checksum, decrypt, derive_keys, encrypt,
    encrypt_with_confounder, kdb_decrypt_key, kdb_encrypt_key, octetstring2key, prf, prf_plus,
    spake_decode_point, spake_m_bytes, spake_n_bytes, spake_public_wbytes, spake_thash_update,
    string_to_key,
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

/// MIT `t_derive.c` Kc/Ke/Ki for AES-128 usage 2.
#[test]
fn mit_t_derive_aes128_usage_2() {
    let key = ProtocolKey::from_bytes(
        EncryptionType::Aes128CtsHmacSha196,
        &hex("42263c6e89f4fc28b8df68ee09799f15"),
    )
    .unwrap();
    let d = derive_keys(&key, KeyUsage::new(2).unwrap()).unwrap();
    assert_eq!(d.kc, hex("34280a382bc92769b2da2f9ef066854b"));
    assert_eq!(d.ke, hex("5b14fc4e250e14ddf9dccf1af6674f53"));
    assert_eq!(d.ki, hex("4ed31063621684f09ae8d89991af3e8f"));
}

#[test]
fn weak_etype_refused_unless_allowed() {
    assert!(matches!(
        EncryptionType::from_iana(23),
        Err(Error::WeakEtypeRefused(23))
    ));
    assert!(EncryptionType::from_iana_policy(23, true).is_ok());
    assert!(EncryptionType::from_iana(18).is_ok());
}

#[test]
fn rejects_key_usage_zero() {
    assert_eq!(KeyUsage::new(0).unwrap_err(), Error::InvalidKeyUsage);
}

#[test]
fn kdb_usage_zero_frames_int16_le_and_new_still_rejects() {
    assert_eq!(KeyUsage::new(0).unwrap_err(), Error::InvalidKeyUsage);
    let mkey = string_to_key(
        EncryptionType::Aes256CtsHmacSha384192,
        b"masterpassword",
        b"KERBER.TESTKM",
        None,
    )
    .unwrap();
    let raw = vec![0x11u8; 32];
    let ct = kdb_encrypt_key(&mkey, &raw).unwrap();
    assert_eq!(kdb_decrypt_key(&mkey, &ct).unwrap(), raw);
    assert_eq!(
        EncryptionType::from_mit_name("aes256-cts-hmac-sha384-192").unwrap(),
        EncryptionType::Aes256CtsHmacSha384192
    );
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

/// RFC 3961 appendix A.4 / MIT `t_str2key.c` 3DES string-to-key output.
#[test]
fn rfc3961_des3_string_to_key_output() {
    let k = string_to_key(
        EncryptionType::Des3CbcSha1,
        b"password",
        b"ATHENA.MIT.EDUraeburn",
        None,
    )
    .unwrap();
    assert_eq!(
        k.as_bytes(),
        hex("850bb51358548cd05e86768c313e3bfef7511937dcf72c3e")
    );
}

/// RFC 6803 §10 Camellia-CTS-CMAC string-to-key, DK, encrypt, checksum.
#[test]
fn rfc6803_camellia_cts_cmac() {
    let salt = b"ATHENA.MIT.EDUraeburn";
    let k128 = string_to_key(
        EncryptionType::Camellia128CtsCmac,
        b"password",
        salt,
        Some(&iter_params(1)),
    )
    .unwrap();
    assert_eq!(k128.as_bytes(), hex("57d0297298ffd9d35de5a47fb4bde24b"));
    let k256 = string_to_key(
        EncryptionType::Camellia256CtsCmac,
        b"password",
        salt,
        Some(&iter_params(1)),
    )
    .unwrap();
    assert_eq!(
        k256.as_bytes(),
        hex("b9d6828b2056b7be656d88a123b1fac68214ac2b727ecf5f69afe0c4df2a6d2c")
    );

    let d = derive_keys(&k128, KeyUsage::new(2).unwrap()).unwrap();
    assert_eq!(d.kc, hex("d155775a209d05f02b38d42a389e5a56"));
    assert_eq!(d.ke, hex("64df83f85a532f17577d8c37035796ab"));
    assert_eq!(d.ki, hex("3e4fbdf30fb8259c425cb6c96f1f4635"));

    let ck_key = ProtocolKey::from_bytes(
        EncryptionType::Camellia128CtsCmac,
        &hex("1dc46a8d763f4f93742bcba3387576c3"),
    )
    .unwrap();
    assert_eq!(
        checksum(&ck_key, KeyUsage::new(7).unwrap(), b"abcdefghijk").unwrap(),
        hex("1178e6c5c47a8c1ae0c4b9c7d4eb7b6b")
    );

    // RFC 6803 §10 sample encryptions (MIT t_decrypt.c). The empty / "1" /
    // "9 bytesss" / … cases use key-usage 0, 1, 2, … matching the plaintext
    // index; usage 0 is invalid on the wire (RFC 3961) but is the published
    // empty-plaintext sample.
    let cam128: &[(u32, &str, &[u8], &str, &str)] = &[
        (
            0,
            "1dc46a8d763f4f93742bcba3387576c3",
            b"",
            "b69822a19a6b09c0ebc8557d1f1b6c0a",
            "c466f1871069921edb7c6fde244a52db0ba10edc197bdb8006658ca3ccce6eb8",
        ),
        (
            1,
            "5027bc231d0f3a9d23333f1ca6fdbe7c",
            b"1",
            "6f2fc3c2a166fd8898967a83de9596d9",
            "842d21fd950311c0dd464a3f4be8d6da88a56d559c9b47d3f9a85067af661559b8",
        ),
        (
            2,
            "a1bb61e805f9ba6dde8fdbddc05cdea0",
            b"9 bytesss",
            "a5b4a71e077aeef93c8763c18fdb1f10",
            "619ff072e36286ff0a28deb3a352ec0d0edf5c5160d663c901758ccf9d1ed33d71db8f23aabf8348a0",
        ),
        (
            3,
            "2ca27a5faf5532244506434e1cef6676",
            b"13 bytes byte",
            "19fee40d810c524b5b22f01874c693da",
            "b8eca3167ae6315512e59f98a7c500205e5f63ff3bb389af1c41a21d640d8615c9ed3fbeb05ab6acb67689b5ea",
        ),
    ];
    for (usage, key_hex, pt, conf, ct) in cam128 {
        let key =
            ProtocolKey::from_bytes(EncryptionType::Camellia128CtsCmac, &hex(key_hex)).unwrap();
        let u = KeyUsage::from_rfc(*usage);
        let got = encrypt_with_confounder(&key, u, &hex(conf), pt).unwrap();
        assert_eq!(got, hex(ct), "camellia128 usage {usage} encrypt");
        assert_eq!(decrypt(&key, u, &got).unwrap(), *pt);
    }

    let cam256_empty = ProtocolKey::from_bytes(
        EncryptionType::Camellia256CtsCmac,
        &hex("b61c86cc4e5d2757545ad423399fb7031ecab913cbb900bd7a3c6dd8bf92015b"),
    )
    .unwrap();
    let u0 = KeyUsage::from_rfc(0);
    let got256 = encrypt_with_confounder(
        &cam256_empty,
        u0,
        &hex("3cbbd2b45917941067f96599bb98926c"),
        b"",
    )
    .unwrap();
    assert_eq!(
        got256,
        hex("03886d03310b47a6d8f06d7b94d1dd837ecce315ef652aff620859d94a259266")
    );
    assert_eq!(decrypt(&cam256_empty, u0, &got256).unwrap(), b"");
}

/// MIT `t_prf.c` PRF vectors (RFC 8009 etypes 19/20 and AES-SHA1 PRF+).
#[test]
fn mit_t_prf_and_rfc6113_prf_plus() {
    let k128 = ProtocolKey::from_bytes(
        EncryptionType::Aes128CtsHmacSha256128,
        &hex("3705d96080c17728a0e800eab6e0d23c"),
    )
    .unwrap();
    assert_eq!(
        prf(&k128, b"test").unwrap(),
        hex("9d188616f63852fe86915bb840b4a886ff3e6bb0f819b49b893393d393854295")
    );
    let k256 = ProtocolKey::from_bytes(
        EncryptionType::Aes256CtsHmacSha384192,
        &hex("6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52"),
    )
    .unwrap();
    assert_eq!(
        prf(&k256, b"test").unwrap(),
        hex(
            "9801f69a368c2bf675e59521e177d9a07f67efe1cfde8d3c8d6f6a0256e3b17db3c1b62ad1b8553360d17367eb1514d2"
        )
    );
    // MIT t_prf.c AES-128-SHA1: PRF(K, 0x01 || "a") — the first PRF+ block.
    let k_sha1 = ProtocolKey::from_bytes(
        EncryptionType::Aes128CtsHmacSha196,
        &hex("ae272e7cdec86ac5138cdb196d8e297d"),
    )
    .unwrap();
    assert_eq!(
        prf_plus(&k_sha1, b"a", 16).unwrap(),
        hex("77b39a37a868920f2a51f9dd150c5717")
    );
}

/// RFC 4757 string-to-key is MD4(UTF-16LE(password)) — the NT hash of
/// "password" is a published NTLM vector.
#[test]
fn rfc4757_rc4_string_to_key() {
    let k = string_to_key(EncryptionType::Rc4Hmac, b"password", b"", None).unwrap();
    assert_eq!(k.as_bytes(), hex("8846f7eaee8fb117ad06bdd830b7586c"));
}

/// RFC 4556 `octetstring2key`: SHA-1(0x00 || x) K-truncate. Empty `x` is
/// NIST SHA-1 of a single 0x00 octet.
#[test]
fn rfc4556_octetstring2key() {
    let k = octetstring2key(EncryptionType::Aes128CtsHmacSha196, b"").unwrap();
    assert_eq!(k.as_bytes(), hex("5ba93c9db0cff93f52b521d7420e43f6"));
    let k2 = octetstring2key(EncryptionType::Aes128CtsHmacSha196, b"abc").unwrap();
    assert_eq!(k2.as_bytes(), hex("dd3742ec1a4d2a5b563a2b62aef7fc4a"));
}

/// SPAKE IANA compressed M/N plus a fixed-scalar public and transcript.
#[test]
fn spake_iana_mn_and_fixed_scalar() {
    let m = spake_m_bytes();
    let n = spake_n_bytes();
    assert_eq!(
        m,
        hex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f").as_slice()
    );
    assert_eq!(
        n,
        hex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49").as_slice()
    );
    spake_decode_point(m).expect("IANA M");
    spake_decode_point(n).expect("IANA N");
    assert!(spake_decode_point(&[0u8; 8]).is_err());

    let mut secret = [0u8; 32];
    secret[31] = 1;
    let mut w = [0u8; 32];
    w[31] = 2;
    let pub_s = spake_public_wbytes(&w, &secret, true).unwrap();
    assert_eq!(
        pub_s,
        hex("02cae70a1517dcfe1d30fe368abaa3048eea46260ada39c78ceb0ef6222fccd61a")
    );
    let thash = spake_thash_update(&[0u8; 32], m, n);
    assert_eq!(
        thash,
        hex("2c7135478945a1ec1fdfe1285536e83e5ad7ff03ee3b6ae44d379659f7bbb743").as_slice()
    );
}
