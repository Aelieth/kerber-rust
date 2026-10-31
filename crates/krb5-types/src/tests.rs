use super::*;

fn p256_key(k: [u8; 32]) -> crate::pkinit::IdentityKey {
    crate::pkinit::IdentityKey::P256(zeroize::Zeroizing::new(k))
}

fn te(contents: &[u8]) -> TransitedEncoding {
    TransitedEncoding {
        tr_type: 1,
        contents: OctetString::from(contents.to_vec()),
    }
}

fn hops(contents: &[u8]) -> Vec<String> {
    te(contents).realms_for("", "").expect("expand")
}

#[test]
fn transited_x500_expand_mit_live_fixture() {
    assert_eq!(
        hops(b"EX.COM,B."),
        vec!["EX.COM".to_string(), "B.EX.COM".to_string()]
    );
}

#[test]
fn transited_x500_expand_rfc4120_example() {
    assert_eq!(
        hops(b"EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS."),
        vec![
            "EDU".to_string(),
            "MIT.EDU".to_string(),
            "ATHENA.MIT.EDU".to_string(),
            "WASHINGTON.EDU".to_string(),
            "CS.WASHINGTON.EDU".to_string(),
        ]
    );
}

#[test]
fn transited_x500_overlong_is_err() {
    let spam = te(&vec![b','; 20_000]);
    assert_eq!(
        spam.realms_for("", "").unwrap_err(),
        TransitError::TooManyFields
    );

    let modest = te(format!("{}X.COM", "X.COM,".repeat(199)).as_bytes());
    let hops = modest.realms_for("", "").unwrap();
    assert_eq!(hops.len(), 200);
    assert_eq!(hops[0], "X.COM");

    let mut long_field = b"X.COM,".to_vec();
    long_field.extend(vec![b'A'; 513]);
    assert_eq!(
        te(&long_field).realms_for("", "").unwrap_err(),
        TransitError::FieldTooLong,
        "≤256 commas holding a >512-byte literal field must err"
    );
}

#[test]
fn transited_x500_escaped_marker_still_joins() {
    assert_eq!(
        hops(b"X.COM,C\\."),
        vec!["X.COM".to_string(), "C.X.COM".to_string()],
        "MIT maybe_join: escaped trailing . still suffix-joins"
    );
    assert_eq!(
        hops(b"X.COM,\\/Y"),
        vec!["X.COM".to_string(), "X.COM/Y".to_string()],
        "MIT maybe_join: escaped leading / still prefix-joins"
    );
    assert_eq!(
        hops(b"X.COM,/Y"),
        vec!["X.COM".to_string(), "X.COM/Y".to_string()],
        "unescaped leading / still prefix-joins"
    );
}

#[test]
fn transited_mit_transit_tests_vectors() {
    fn set(xs: &[&str]) -> std::collections::BTreeSet<String> {
        xs.iter().map(|s| (*s).to_string()).collect()
    }
    fn got(crealm: &str, srealm: &str, transit: &[u8]) -> std::collections::BTreeSet<String> {
        te(transit)
            .realms_for(crealm, srealm)
            .expect("expand")
            .into_iter()
            .collect()
    }

    assert_eq!(
        got("ATHENA.MIT.EDU", "HACK.FOOBAR.COM", b",EDU,BLORT.COM,COM,"),
        set(&["MIT.EDU", "EDU", "BLORT.COM", "COM", "FOOBAR.COM"])
    );
    assert_eq!(got("ATHENA.MIT.EDU", "EDU", b","), set(&["MIT.EDU"]));
    assert_eq!(got("EDU", "ATHENA.MIT.EDU", b","), set(&["MIT.EDU"]));
    assert_eq!(
        got("x", "x", b"/COM,/HP,/APOLLO, /COM/DEC"),
        set(&["/COM", "/COM/HP", "/COM/HP/APOLLO", "/COM/DEC"])
    );
    assert_eq!(
        got("x", "x", b"EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS."),
        set(&[
            "EDU",
            "MIT.EDU",
            "ATHENA.MIT.EDU",
            "WASHINGTON.EDU",
            "CS.WASHINGTON.EDU"
        ])
    );
    assert_eq!(
        te(b",EDU,/COM,")
            .realms_for("ATHENA.MIT.EDU", "/COM/HP/APOLLO")
            .unwrap_err(),
        TransitError::BadIntermediates
    );
    assert_eq!(
        got("ATHENA.MIT.EDU", "/COM/HP/APOLLO", b",EDU, /COM,"),
        set(&["EDU", "MIT.EDU", "/COM", "/COM/HP"])
    );
    let edu = got("ATHENA.MIT.EDU", "CS.CMU.EDU", b",EDU,");
    assert_eq!(edu, set(&["EDU", "MIT.EDU", "CMU.EDU"]));
    assert_ne!(edu, set(&["EDU"]), ",EDU, must not be hops {{EDU}} only");
    assert_eq!(
        got("XYZZY.ATHENA.MIT.EDU", "XYZZY.CS.CMU.EDU", b",EDU,"),
        set(&["EDU", "MIT.EDU", "ATHENA.MIT.EDU", "CMU.EDU", "CS.CMU.EDU"])
    );
}

#[test]
fn pkinit_cms_path_validation() {
    let ca = pkinit::PkinitCa::generate().expect("CA");
    let inner = b"path-validation";
    let wrapped = pkinit::cms_wrap(inner, &ca).expect("wrap");
    assert_eq!(
        pkinit::cms_verify(&wrapped, &ca.ca_cert).expect("in-window chain"),
        inner
    );

    let (expired, ekey) = ca
        .client_identity_window("user@KERBER.TEST", b"200101000000Z", b"210101000000Z")
        .expect("expired");
    let cms = pkinit::cms_sign_leaf(inner, &expired, &p256_key(ekey), pkinit::ECONTENT_AUTHDATA)
        .expect("expired cms");
    assert_eq!(
        pkinit::cms_verify(&cms, &ca.ca_cert).expect_err("expired"),
        "cms expired"
    );

    let (ee, ek) = pkinit::PkinitCa::self_signed_end_entity().expect("ee");
    let cms = pkinit::cms_sign_leaf(inner, &ee, &p256_key(ek), pkinit::ECONTENT_AUTHDATA)
        .expect("ee cms");
    assert_eq!(
        pkinit::cms_verify(&cms, &ee).expect_err("non-CA anchor"),
        "cms ca"
    );

    let (wrong, wkey) = ca
        .client_identity_wrong_issuer("user@KERBER.TEST")
        .expect("wrong issuer");
    let cms = pkinit::cms_sign_leaf(inner, &wrong, &p256_key(wkey), pkinit::ECONTENT_AUTHDATA)
        .expect("wrong cms");
    assert_eq!(
        pkinit::cms_verify(&cms, &ca.ca_cert).expect_err("DN mismatch"),
        "cms chain"
    );

    let expired_ca =
        pkinit::PkinitCa::generate_window(b"200101000000Z", b"210101000000Z").expect("expired CA");
    let cms = expired_ca.sign_cms(inner, "user").expect("expired ca cms");
    assert_eq!(
        pkinit::cms_verify(&cms, &expired_ca.ca_cert).expect_err("expired CA"),
        "cms ca expired"
    );

    let noku = pkinit::PkinitCa::generate_no_key_cert_sign().expect("no ku");
    let cms = noku.sign_cms(inner, "user").expect("no ku cms");
    assert_eq!(
        pkinit::cms_verify(&cms, &noku.ca_cert).expect_err("no keyCertSign"),
        "cms ca ku"
    );
    let absent = pkinit::PkinitCa::generate_absent_key_usage().expect("absent ku");
    let cms = absent.sign_cms(inner, "user").expect("absent ku cms");
    assert_eq!(
        pkinit::cms_verify(&cms, &absent.ca_cert).expect("RFC 5280 absent KU"),
        inner
    );
}

const SECRET: [u8; 16] = [
    0x13, 0x37, 0xc0, 0xde, 0x22, 0x5c, 0x0a, 0xa5, 0x9e, 0x41, 0x42, 0x43, 0x7f, 0x00, 0xfe, 0x5a,
];

fn shows(debug: &str, secret: &[u8]) -> bool {
    use std::fmt::Write as _;
    let hex = secret.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    });
    let numbers = format!("{secret:?}");
    let escaped = format!("{:?}", bytes::Bytes::copy_from_slice(secret));
    debug.to_lowercase().contains(&hex)
        || debug.contains(&numbers[1..numbers.len() - 1])
        || debug.contains(&escaped[2..escaped.len() - 1])
        || std::str::from_utf8(secret).is_ok_and(|text| debug.contains(text))
}

fn secret_key() -> EncryptionKey {
    EncryptionKey {
        keytype: 18,
        keyvalue: OctetString::from(SECRET.to_vec()),
    }
}

#[test]
fn an_encryption_keys_debug_shows_its_type_and_length_not_its_octets() {
    let debug = format!("{:?}", secret_key());
    assert!(!shows(&debug, &SECRET), "{debug}");
    assert_eq!(
        debug,
        "EncryptionKey { keytype: 18, keyvalue: <redacted, 16 octets> }"
    );
}

#[test]
fn a_key_holders_debug_shows_no_key_octets() {
    let info = KrbCredInfo {
        key: secret_key(),
        prealm: None,
        pname: None,
        flags: None,
        authtime: None,
        starttime: None,
        endtime: None,
        renew_till: None,
        srealm: None,
        sname: None,
        caddr: None,
    };
    for debug in [format!("{info:?}"), format!("{info:#?}")] {
        assert!(!shows(&debug, &SECRET), "{debug}");
        assert!(debug.contains("<redacted, 16 octets>"), "{debug}");
    }
}

#[test]
fn a_password_changes_debug_shows_no_password() {
    let password = b"correct horse battery staple";
    let data = ChangePasswdData {
        newpasswd: OctetString::from_static(password),
        targname: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["u"]),
        targrealm: ascii("R"),
    };
    let debug = format!("{data:?}");
    assert!(!shows(&debug, password), "{debug}");
    assert!(
        debug.starts_with("ChangePasswdData { newpasswd: <redacted>, targname: PrincipalName {"),
        "{debug}"
    );
}

#[test]
fn a_pac_logon_infos_debug_shows_no_session_key() {
    let sid = pac::RpcSid::dummy_domain();
    let mut info = pac::KerbValidationInfo::for_client("user", "KERBER.TEST", &sid, 1104);
    info.session_key = SECRET;
    let debug = format!("{info:?}");
    assert!(!shows(&debug, &SECRET), "{debug}");
    assert!(debug.contains("session_key: <redacted>"), "{debug}");
}

#[test]
fn a_pkinit_cas_debug_shows_no_private_scalar() {
    let ca = pkinit::PkinitCa::generate().unwrap();
    let debug = format!("{ca:?}");
    assert!(
        !shows(&debug, ca.ca_secret.as_slice()),
        "the CA scalar is in its Debug"
    );
    assert!(debug.contains("ca_secret: <redacted>"), "{debug}");
}

#[test]
fn pa_spake_unknown_choice_decodes() {
    for der in [&[0xa4, 0x02, 0x30, 0x00][..], &[0x81, 0x00][..]] {
        assert_eq!(
            rasn::der::decode::<spake::PaSpake>(der).unwrap(),
            spake::PaSpake::Unknown
        );
    }
    assert!(rasn::der::decode::<spake::PaSpake>(&[0xa2, 0x02, 0x31, 0x00]).is_err());
    assert!(rasn::der::encode(&spake::PaSpake::Unknown).is_err());
}

const MIT_OTP_TOKENINFO_MINIMAL: &str = "30 07 80 05 00 00 00 00 00";
const MIT_OTP_TOKENINFO_MAXIMAL: &str = "30 72 80 05 00 77 00 00 00 81 0B 45 78 61 6D 70 6C 65 63 6F 72 70 82 05 68 61 72 6B 21 83 01 0A 84 01 02 85 09 79 6F 75 72 74 6F 6B 65 6E 86 28 75 72 6E 3A 69 65 74 66 3A 70 61 72 61 6D 73 3A 78 6D 6C 3A 6E 73 3A 6B 65 79 70 72 6F 76 3A 70 73 6B 63 3A 68 6F 74 70 A7 16 30 0B 06 09 60 86 48 01 65 03 04 02 01 30 07 06 05 2B 0E 03 02 1A 88 02 03 E8";
const MIT_PA_OTP_CHALLENGE_MINIMAL: &str =
    "30 15 80 08 6D 69 6E 6E 6F 6E 63 65 A2 09 30 07 80 05 00 00 00 00 00";
const MIT_PA_OTP_CHALLENGE_MAXIMAL: &str = "30 81 A5 80 08 6D 61 78 6E 6F 6E 63 65 81 0B 74 65 73 74 73 65 72 76 69 63 65 A2 7D 30 07 80 05 00 00 00 00 00 30 72 80 05 00 77 00 00 00 81 0B 45 78 61 6D 70 6C 65 63 6F 72 70 82 05 68 61 72 6B 21 83 01 0A 84 01 02 85 09 79 6F 75 72 74 6F 6B 65 6E 86 28 75 72 6E 3A 69 65 74 66 3A 70 61 72 61 6D 73 3A 78 6D 6C 3A 6E 73 3A 6B 65 79 70 72 6F 76 3A 70 73 6B 63 3A 68 6F 74 70 A7 16 30 0B 06 09 60 86 48 01 65 03 04 02 01 30 07 06 05 2B 0E 03 02 1A 88 02 03 E8 83 07 6B 65 79 73 61 6C 74 84 04 31 32 33 34";
const MIT_PA_OTP_REQ_MINIMAL: &str = "30 2C 80 05 00 00 00 00 00 A2 23 A0 03 02 01 00 A1 03 02 01 05 A2 17 04 15 6B 72 62 41 53 4E 2E 31 20 74 65 73 74 20 6D 65 73 73 61 67 65";
const MIT_PA_OTP_REQ_MAXIMAL: &str = "30 81 B9 80 05 00 60 00 00 00 81 05 6E 6F 6E 63 65 A2 23 A0 03 02 01 00 A1 03 02 01 05 A2 17 04 15 6B 72 62 41 53 4E 2E 31 20 74 65 73 74 20 6D 65 73 73 61 67 65 A3 0B 06 09 60 86 48 01 65 03 04 02 01 84 02 03 E8 85 05 66 72 6F 67 73 86 0A 6D 79 66 69 72 73 74 70 69 6E 87 05 68 61 72 6B 21 88 0F 31 39 39 34 30 36 31 30 30 36 30 33 31 37 5A 89 03 33 34 36 8A 01 02 8B 09 79 6F 75 72 74 6F 6B 65 6E 8C 28 75 72 6E 3A 69 65 74 66 3A 70 61 72 61 6D 73 3A 78 6D 6C 3A 6E 73 3A 6B 65 79 70 72 6F 76 3A 70 73 6B 63 3A 68 6F 74 70 8D 0B 45 78 61 6D 70 6C 65 63 6F 72 70";
const MIT_PA_OTP_ENC_REQ: &str = "30 0A 80 08 6B 72 62 35 64 61 74 61";

const OTP_ALG_ID: &str = "urn:ietf:params:xml:ns:keyprov:pskc:hotp";

fn mit_hex(der: &[u8]) -> String {
    der.iter()
        .map(|octet| format!("{octet:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn mit_octets(hex: &str) -> Vec<u8> {
    hex.split_whitespace()
        .map(|octet| u8::from_str_radix(octet, 16).unwrap())
        .collect()
}

fn assert_mit_encoding<T>(value: &T, hex: &str)
where
    T: rasn::Encode + rasn::Decode + PartialEq + std::fmt::Debug,
{
    let der = rasn::der::encode(value).unwrap();
    assert_eq!(mit_hex(&der), hex, "the encoder differs from MIT");
    let decoded: T = rasn::der::decode(&mit_octets(hex)).unwrap();
    assert_eq!(&decoded, value, "decoding MIT's octets gives another value");
}

fn otp_flags(bits: u32) -> KerberosFlags {
    KerberosFlags::from_slice(&bits.to_be_bytes())
}

fn sample_enc_data() -> EncryptedData {
    EncryptedData {
        etype: 0,
        kvno: Some(5),
        cipher: OctetString::from_static(b"krbASN.1 test message"),
    }
}

fn sha256_alg() -> pkinit::CmsAlgorithmIdentifier {
    pkinit::CmsAlgorithmIdentifier {
        algorithm: rasn::types::ObjectIdentifier::new(vec![2, 16, 840, 1, 101, 3, 4, 2, 1])
            .unwrap(),
        parameters: None,
    }
}

fn sha1_alg() -> pkinit::CmsAlgorithmIdentifier {
    pkinit::CmsAlgorithmIdentifier {
        algorithm: rasn::types::ObjectIdentifier::new(vec![1, 3, 14, 3, 2, 26]).unwrap(),
        parameters: None,
    }
}

fn minimal_token_info() -> otp::OtpTokenInfo {
    otp::OtpTokenInfo {
        flags: otp_flags(0),
        vendor: None,
        challenge: None,
        length: None,
        format: None,
        token_id: None,
        alg_id: None,
        supported_hash_alg: None,
        iteration_count: None,
    }
}

fn maximal_token_info() -> otp::OtpTokenInfo {
    otp::OtpTokenInfo {
        flags: otp_flags(
            otp::OTP_FLAG_NEXTOTP
                | otp::OTP_FLAG_COMBINE
                | otp::OTP_FLAG_COLLECT_PIN
                | otp::OTP_FLAG_ENCRYPT_NONCE
                | otp::OTP_FLAG_SEPARATE_PIN
                | otp::OTP_FLAG_CHECK_DIGIT,
        ),
        vendor: Some(OctetString::from_static(b"Examplecorp")),
        challenge: Some(OctetString::from_static(b"hark!")),
        length: Some(10),
        format: Some(otp::OTP_FORMAT_ALPHANUMERIC),
        token_id: Some(OctetString::from_static(b"yourtoken")),
        alg_id: Some(OctetString::from_static(OTP_ALG_ID.as_bytes())),
        supported_hash_alg: Some(vec![sha256_alg(), sha1_alg()]),
        iteration_count: Some(1000),
    }
}

fn maximal_request() -> otp::PaOtpRequest {
    otp::PaOtpRequest {
        flags: otp_flags(otp::OTP_FLAG_NEXTOTP | otp::OTP_FLAG_COMBINE),
        nonce: Some(OctetString::from_static(b"nonce")),
        enc_data: sample_enc_data(),
        hash_alg: Some(sha256_alg()),
        iteration_count: Some(1000),
        otp_value: Some(OctetString::from_static(b"frogs")),
        pin: Some(OctetString::from_static(b"myfirstpin")),
        challenge: Some(OctetString::from_static(b"hark!")),
        time: Some(KerberosTime::from_unix_seconds(771_228_197)),
        counter: Some(OctetString::from_static(b"346")),
        format: Some(otp::OTP_FORMAT_ALPHANUMERIC),
        token_id: Some(OctetString::from_static(b"yourtoken")),
        alg_id: Some(OctetString::from_static(OTP_ALG_ID.as_bytes())),
        vendor: Some(OctetString::from_static(b"Examplecorp")),
    }
}

#[test]
fn otp_tokeninfo_minimal_is_mits_encoding() {
    assert_mit_encoding(&minimal_token_info(), MIT_OTP_TOKENINFO_MINIMAL);
}

#[test]
fn otp_tokeninfo_maximal_is_mits_encoding() {
    assert_mit_encoding(&maximal_token_info(), MIT_OTP_TOKENINFO_MAXIMAL);
}

#[test]
fn pa_otp_challenge_minimal_is_mits_encoding() {
    let challenge = otp::PaOtpChallenge {
        nonce: OctetString::from_static(b"minnonce"),
        service: None,
        token_info: vec![minimal_token_info()],
        salt: None,
        s2kparams: None,
    };
    assert_mit_encoding(&challenge, MIT_PA_OTP_CHALLENGE_MINIMAL);
}

#[test]
fn pa_otp_challenge_maximal_is_mits_encoding() {
    let challenge = otp::PaOtpChallenge {
        nonce: OctetString::from_static(b"maxnonce"),
        service: Some(OctetString::from_static(b"testservice")),
        token_info: vec![minimal_token_info(), maximal_token_info()],
        salt: Some(ascii("keysalt")),
        s2kparams: Some(OctetString::from_static(b"1234")),
    };
    assert_mit_encoding(&challenge, MIT_PA_OTP_CHALLENGE_MAXIMAL);
}

#[test]
fn pa_otp_req_minimal_is_mits_encoding() {
    let request = otp::PaOtpRequest {
        flags: otp_flags(0),
        nonce: None,
        enc_data: sample_enc_data(),
        hash_alg: None,
        iteration_count: None,
        otp_value: None,
        pin: None,
        challenge: None,
        time: None,
        counter: None,
        format: None,
        token_id: None,
        alg_id: None,
        vendor: None,
    };
    assert_mit_encoding(&request, MIT_PA_OTP_REQ_MINIMAL);
}

#[test]
fn pa_otp_req_maximal_is_mits_encoding() {
    assert_mit_encoding(&maximal_request(), MIT_PA_OTP_REQ_MAXIMAL);
}

#[test]
fn pa_otp_enc_request_is_mits_encoding() {
    let enc = otp::PaOtpEncRequest {
        nonce: OctetString::from_static(b"krb5data"),
    };
    assert_mit_encoding(&enc, MIT_PA_OTP_ENC_REQ);
}

#[test]
fn a_pa_otp_requests_debug_shows_no_pin_or_otp_value() {
    let debug = format!("{:?}", maximal_request());
    assert!(!shows(&debug, b"myfirstpin"), "{debug}");
    assert!(!shows(&debug, b"frogs"), "{debug}");
    assert!(
        debug.contains("otp_value: Some(<redacted>), pin: Some(<redacted>)"),
        "{debug}"
    );
}
