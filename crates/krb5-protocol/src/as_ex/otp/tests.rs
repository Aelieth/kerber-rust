//! red at tree bd74009e (the module does not exist there); the responder tests red at tree a1307fd6

use std::collections::VecDeque;

use krb5_asn1::decode;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt};
use krb5_types::k5json::{self, Value};
use krb5_types::otp::{
    OTP_FLAG_COLLECT_PIN, OTP_FLAG_COMBINE, OTP_FLAG_NEXTOTP, OTP_FLAG_NO_COLLECT_PIN,
    OTP_FLAG_SEPARATE_PIN, OTP_FORMAT_BINARY, OtpTokenInfo, PaOtpChallenge, PaOtpEncRequest,
    PaOtpRequest,
};
use krb5_types::{KerberosFlags, OctetString, ku, pa};
use zeroize::Zeroizing;

use super::*;
use crate::as_ex::{AsPrompt, PreauthPrompt, QUESTION_PASSWORD};

fn ti() -> OtpTokenInfo {
    OtpTokenInfo {
        flags: KerberosFlags::from_slice(&[0; 4]),
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

fn flags(f: u32) -> KerberosFlags {
    KerberosFlags::from_slice(&f.to_be_bytes())
}

fn vendor(v: &str) -> OtpTokenInfo {
    OtpTokenInfo {
        vendor: Some(OctetString::from(v.as_bytes().to_vec())),
        ..ti()
    }
}

#[derive(Default)]
struct Script {
    answers: VecDeque<&'static str>,
    asked: Vec<(Option<String>, String)>,
}

impl Script {
    fn of(answers: &[&'static str]) -> Self {
        Self {
            answers: answers.iter().copied().collect(),
            ..Self::default()
        }
    }
}

impl AsPrompt for Script {
    fn password(&mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        panic!("the password is never asked");
    }

    fn preauth(&mut self, p: &PreauthPrompt<'_>) -> Result<Zeroizing<Vec<u8>>, Error> {
        assert!(p.hidden);
        assert_eq!(p.prompt_type, PromptType::Preauth);
        self.asked
            .push((p.banner.map(str::to_owned), p.prompt.to_owned()));
        self.answers
            .pop_front()
            .map(|a| Zeroizing::new(a.as_bytes().to_vec()))
            .ok_or_else(|| Error::File(std::io::Error::other("Cannot read password")))
    }
}

fn armor() -> ProtocolKey {
    ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x5a; 32]).unwrap()
}

fn challenge(tis: Vec<OtpTokenInfo>) -> PaOtpChallenge {
    PaOtpChallenge {
        nonce: vec![9u8; 36].into(),
        service: None,
        token_info: tis,
        salt: None,
        s2kparams: None,
    }
}

fn state_of(chl: PaOtpChallenge) -> OtpState {
    OtpState { chl: Some(chl) }
}

fn run(chl: PaOtpChallenge, ui: &mut Script) -> Result<(PaOtpRequest, Value), ModuleFail> {
    let (pa142, cfg) = process(&state_of(chl), &ResponderItems::default(), ui, &armor())?;
    assert_eq!(pa142.padata_type, pa::OTP_REQUEST);
    Ok((decode(pa142.padata_value.as_ref()).unwrap(), cfg))
}

fn prompts(ui: &Script) -> Vec<(Option<&str>, &str)> {
    ui.asked
        .iter()
        .map(|(b, p)| (b.as_deref(), p.as_str()))
        .collect()
}

#[test]
fn unsupported_tokens_are_dropped_and_none_left_is_an_error() {
    let bad = [
        OtpTokenInfo {
            flags: flags(OTP_FLAG_NEXTOTP),
            ..ti()
        },
        OtpTokenInfo {
            flags: flags(OTP_FLAG_COMBINE),
            ..ti()
        },
        OtpTokenInfo {
            supported_hash_alg: Some(vec![]),
            ..ti()
        },
        OtpTokenInfo {
            iteration_count: Some(0),
            ..ti()
        },
        OtpTokenInfo {
            format: Some(OTP_FORMAT_BASE64),
            ..ti()
        },
        vendor("caf\u{e9}"),
        OtpTokenInfo {
            challenge: Some(vec![7].into()),
            ..ti()
        },
    ];
    for b in &bad {
        assert!(!is_supported(b), "{b:?}");
    }
    let good = [
        ti(),
        OtpTokenInfo {
            flags: flags(OTP_FLAG_COLLECT_PIN | OTP_FLAG_NO_COLLECT_PIN | OTP_FLAG_SEPARATE_PIN),
            ..ti()
        },
        OtpTokenInfo {
            iteration_count: Some(-1),
            length: Some(-1),
            format: Some(OTP_FORMAT_BINARY),
            ..ti()
        },
        OtpTokenInfo {
            vendor: Some(OctetString::from_static(b"")),
            challenge: Some(Vec::new().into()),
            ..ti()
        },
    ];
    for g in &good {
        assert!(is_supported(g), "{g:?}");
    }
    let kept = filter_supported(vec![bad[0].clone(), vendor("A")]).unwrap();
    assert_eq!(kept, vec![vendor("A")]);
    let e = filter_supported(bad.to_vec()).unwrap_err();
    assert_eq!(e.to_string(), "No supported tokens");
}

fn cc(json: &str) -> Value {
    k5json::decode(json.as_bytes()).unwrap()
}

#[test]
fn the_ccache_config_prunes_to_the_single_match() {
    let a = OtpTokenInfo {
        vendor: Some(OctetString::from_static(b"A")),
        alg_id: Some(OctetString::from_static(b"urn:x")),
        ..ti()
    };
    let b = OtpTokenInfo {
        vendor: Some(OctetString::from_static(b"B")),
        token_id: Some(b"t1".to_vec().into()),
        ..ti()
    };
    let anon = ti();
    let cases: [(&str, Vec<OtpTokenInfo>, Vec<OtpTokenInfo>); 7] = [
        (
            r#"{"vendor":"B"}"#,
            vec![a.clone(), b.clone()],
            vec![b.clone()],
        ),
        (
            r#"{"vendor":"A","algID":"urn:x"}"#,
            vec![a.clone(), b.clone()],
            vec![a.clone()],
        ),
        (
            r#"{"vendor":"C"}"#,
            vec![a.clone(), b.clone()],
            vec![a.clone(), b.clone()],
        ),
        (
            r"{}",
            vec![a.clone(), b.clone()],
            vec![a.clone(), b.clone()],
        ),
        (
            r#"{"vendor":"A"}"#,
            vec![a.clone(), anon.clone()],
            vec![a.clone(), anon.clone()],
        ),
        (
            r#"{"vendor":7,"tokenID":"t1"}"#,
            vec![a.clone(), b.clone()],
            vec![a.clone(), b.clone()],
        ),
        (
            r#"{"tokenID":"t1"}"#,
            vec![a.clone(), b.clone()],
            vec![a.clone(), b.clone()],
        ),
    ];
    for (json, from, want) in cases {
        let mut tis = from;
        filter_config(&mut tis, Some(&cc(json)));
        assert_eq!(tis, want, "{json}");
    }
    let mut one = vec![a.clone()];
    filter_config(&mut one, None);
    assert_eq!(one, vec![a]);
}

#[test]
fn a_value_must_have_the_tokens_length_and_format() {
    let t = |len: Option<i32>, fmt: Option<i32>| OtpTokenInfo {
        length: len,
        format: fmt,
        ..ti()
    };
    assert!(value_matches(b"123456", &t(Some(6), Some(0))));
    assert!(!value_matches(b"12345", &t(Some(6), None)));
    assert!(!value_matches(b"12345a", &t(Some(6), Some(0))));
    assert!(value_matches(b"12ab", &t(None, Some(1))));
    assert!(!value_matches(b"12ag", &t(None, Some(1))));
    assert!(value_matches(b"1a\x41", &t(None, Some(2))));
    assert!(!value_matches(b"1a-", &t(None, Some(2))));
    assert!(
        value_matches(b"\x01\xff", &t(None, Some(3))),
        "binary is not checked"
    );
    assert!(value_matches(b"", &t(Some(0), None)));
    assert!(!value_matches(b"x", &t(Some(0), None)));
    let mut ui = Script::of(&["12345"]);
    let f = run(
        challenge(vec![t(Some(6), None), t(Some(6), Some(0))]),
        &mut ui,
    )
    .unwrap_err();
    assert_eq!(f.text, "OTP value doesn't match any token formats");
    assert_eq!(
        Error::PreauthFailed(Box::new(f.error)).to_string(),
        "Pre-authentication failed: OTP value doesn't match any token formats"
    );
}

#[test]
fn strtoul_reads_a_menu_choice_as_c_does() {
    for (s, v, range) in [
        ("2", 2, false),
        (" \t3", 3, false),
        ("+4", 4, false),
        ("0x2", 2, false),
        ("0X1f", 31, false),
        ("010", 8, false),
        ("08", 0, false),
        ("0x", 0, false),
        ("abc", 0, false),
        ("", 0, false),
        ("-1", u64::MAX, false),
        ("2x", 2, false),
        ("99999999999999999999999", u64::MAX, true),
    ] {
        assert_eq!(strtoul_base0(s.as_bytes()), (v, range), "{s:?}");
    }
}

#[test]
fn one_token_asks_for_the_value_alone() {
    let mut ui = Script::of(&["123456"]);
    let (req, cfg) = run(challenge(vec![ti()]), &mut ui).unwrap();
    assert_eq!(prompts(&ui), vec![(None, "Enter OTP Token Value")]);
    assert_eq!(
        req.otp_value.as_ref().map(AsRef::as_ref),
        Some(&b"123456"[..])
    );
    assert_eq!(req.pin, None);
    assert_eq!(config_string(&cfg), None);
}

#[test]
fn one_token_with_a_challenge_shows_it_as_the_banner() {
    let t = OtpTokenInfo {
        challenge: Some(b"8675309".to_vec().into()),
        ..ti()
    };
    let mut ui = Script::of(&["1"]);
    run(challenge(vec![t]), &mut ui).unwrap();
    assert_eq!(
        prompts(&ui),
        vec![(Some("OTP Challenge: 8675309\n"), "Enter OTP Token Value")]
    );
}

#[test]
fn several_tokens_with_a_challenge_choose_first_and_ask_again_until_valid() {
    let a = vendor("Acme");
    let b = OtpTokenInfo {
        vendor: Some(OctetString::from_static(b"Zed")),
        challenge: Some(b"c2".to_vec().into()),
        ..ti()
    };
    let mut ui = Script::of(&["0", "3", "abc", "", "2", "654321"]);
    let (req, cfg) = run(challenge(vec![a, b]), &mut ui).unwrap();
    let menu = "Please choose from the following:\n\t1. Vendor: Acme\n\t2. Vendor: Zed\n";
    let mut want = vec![(Some(menu), "Enter #"); 5];
    want.push((Some("OTP Challenge: c2\n"), "Enter OTP Token Value"));
    assert_eq!(prompts(&ui), want);
    assert_eq!(req.vendor.as_deref(), Some(&b"Zed"[..]));
    assert_eq!(
        config_octets(&cfg).as_deref(),
        Some(r#"{"vendor":"Zed"}"#.as_bytes())
    );
    let mut ui = Script::of(&["99999999999999999999999"]);
    let e = run(
        challenge(vec![
            vendor("A"),
            OtpTokenInfo {
                challenge: Some(b"c".to_vec().into()),
                ..ti()
            },
        ]),
        &mut ui,
    )
    .unwrap_err();
    assert_eq!(e.error.to_string(), "Numerical result out of range");
}

#[test]
fn several_tokens_without_a_challenge_ask_the_value_first_and_filter_by_it() {
    let six = OtpTokenInfo {
        vendor: Some(OctetString::from_static(b"Six")),
        length: Some(6),
        format: Some(OTP_FORMAT_DECIMAL),
        ..ti()
    };
    let eight = OtpTokenInfo {
        vendor: Some(OctetString::from_static(b"Eight")),
        length: Some(8),
        format: Some(OTP_FORMAT_DECIMAL),
        ..ti()
    };
    let hex6 = OtpTokenInfo {
        vendor: Some(OctetString::from_static(b"Hex")),
        length: Some(6),
        format: Some(OTP_FORMAT_HEXADECIMAL),
        ..ti()
    };
    let mut ui = Script::of(&["12345678"]);
    let (req, _) = run(
        challenge(vec![six.clone(), eight.clone(), hex6.clone()]),
        &mut ui,
    )
    .unwrap();
    assert_eq!(
        prompts(&ui),
        vec![(None, "Enter OTP Token Value")],
        "one match: no menu"
    );
    assert_eq!(req.vendor.as_deref(), Some(&b"Eight"[..]));
    assert_eq!(req.format, Some(OTP_FORMAT_DECIMAL));
    let mut ui = Script::of(&["123456", "2"]);
    let (req, _) = run(
        challenge(vec![six.clone(), eight.clone(), hex6.clone()]),
        &mut ui,
    )
    .unwrap();
    assert_eq!(
        prompts(&ui),
        vec![
            (None, "Enter OTP Token Value"),
            (
                Some("Please choose from the following:\n\t1. Vendor: Six\n\t2. Vendor: Hex\n"),
                "Enter #"
            ),
        ]
    );
    assert_eq!(
        req.vendor.as_deref(),
        Some(&b"Hex"[..]),
        "the menu lists only the matches, renumbered"
    );
    let mut ui = Script::of(&["abc"]);
    let e = run(challenge(vec![six, eight]), &mut ui).unwrap_err();
    assert_eq!(
        e.error.to_string(),
        "OTP value doesn't match any token formats"
    );
}

#[test]
fn pins_are_collected_and_placed_by_the_tokens_flags() {
    let sep = OtpTokenInfo {
        flags: flags(OTP_FLAG_COLLECT_PIN | OTP_FLAG_SEPARATE_PIN),
        ..ti()
    };
    let mut ui = Script::of(&["123456", "4321"]);
    let (req, _) = run(challenge(vec![sep]), &mut ui).unwrap();
    assert_eq!(
        prompts(&ui),
        vec![(None, "Enter OTP Token Value"), (None, "OTP Token PIN")]
    );
    assert_eq!(req.pin.as_deref(), Some(&b"4321"[..]));
    assert_eq!(
        req.otp_value.as_ref().map(AsRef::as_ref),
        Some(&b"123456"[..])
    );

    let prefix = OtpTokenInfo {
        flags: flags(OTP_FLAG_COLLECT_PIN),
        ..ti()
    };
    let mut ui = Script::of(&["123456", "4321"]);
    let (req, _) = run(challenge(vec![prefix]), &mut ui).unwrap();
    assert_eq!(req.pin, None);
    assert_eq!(
        req.otp_value.as_ref().map(AsRef::as_ref),
        Some(&b"4321123456"[..]),
        "the PIN prefixes the value (MIT drops the combined value, :654-663)"
    );

    let only_sep = OtpTokenInfo {
        flags: flags(OTP_FLAG_SEPARATE_PIN),
        ..ti()
    };
    let mut ui = Script::of(&["123456", "4321"]);
    let (req, _) = run(challenge(vec![only_sep]), &mut ui).unwrap();
    assert_eq!(ui.asked.len(), 2);
    assert_eq!(req.pin, None);
    assert_eq!(
        req.otp_value.as_ref().map(AsRef::as_ref),
        Some(&b"123456"[..])
    );

    let nopin = OtpTokenInfo {
        flags: flags(OTP_FLAG_NO_COLLECT_PIN),
        ..ti()
    };
    let mut ui = Script::of(&["123456"]);
    run(challenge(vec![nopin]), &mut ui).unwrap();
    assert_eq!(ui.asked.len(), 1);
}

#[test]
fn the_request_carries_the_tokens_fields_and_the_encrypted_nonce() {
    let t = OtpTokenInfo {
        vendor: Some(OctetString::from_static(b"Acme")),
        format: Some(OTP_FORMAT_HEXADECIMAL),
        token_id: Some(b"id1".to_vec().into()),
        alg_id: Some(OctetString::from_static(b"urn:alg")),
        ..ti()
    };
    let mut ui = Script::of(&["abc123"]);
    let (req, cfg) = run(challenge(vec![t]), &mut ui).unwrap();
    assert_eq!(flags_u32(&req.flags), 0);
    assert_eq!(req.nonce, None);
    assert_eq!(
        req.iteration_count,
        Some(0),
        "MIT's calloc leaves 0 and sends it"
    );
    assert_eq!(req.hash_alg, None);
    assert_eq!(req.format, Some(OTP_FORMAT_HEXADECIMAL));
    assert_eq!(req.vendor.as_deref(), Some(&b"Acme"[..]));
    assert_eq!(req.alg_id.as_deref(), Some(&b"urn:alg"[..]));
    assert_eq!(req.token_id.as_ref().map(AsRef::as_ref), Some(&b"id1"[..]));
    assert_eq!(req.enc_data.etype, 18);
    assert_eq!(req.enc_data.kvno, None);
    let plain = decrypt(
        &armor(),
        KeyUsage::new(ku::PA_OTP_REQUEST).unwrap(),
        req.enc_data.cipher.as_ref(),
    )
    .unwrap();
    let enc: PaOtpEncRequest = decode(&plain).unwrap();
    assert_eq!(enc.nonce.as_ref(), &[9u8; 36][..]);
    assert_eq!(
        config_octets(&cfg).as_deref(),
        Some(r#"{"vendor":"Acme","algID":"urn:alg","tokenID":"id1"}"#.as_bytes())
    );
}

#[test]
fn the_default_requests_der_is_mits() {
    let mut ui = Script::of(&["123456"]);
    let (pa142, _) = process(
        &state_of(challenge(vec![ti()])),
        &ResponderItems::default(),
        &mut ui,
        &armor(),
    )
    .unwrap();
    let der = pa142.padata_value.as_ref().to_vec();
    assert_eq!(der[0], 0x30);
    assert_eq!(&der[2..9], &[0x80, 0x05, 0x00, 0, 0, 0, 0]);
    assert_eq!(der[9], 0xa2);
    assert_eq!(
        &der[der.len() - 11..],
        &[
            0x84, 0x01, 0x00, 0x85, 0x06, b'1', b'2', b'3', b'4', b'5', b'6'
        ]
    );
    assert_eq!(&der[11..16], &[0xa0, 0x03, 0x02, 0x01, 0x12]);
    assert_eq!(der.len(), 99);
    assert_eq!(&der[..2], &[0x30, 0x61]);
    assert_eq!(&der[9..11], &[0xa2, 0x4d]);
    assert_eq!(&der[16..20], &[0xa2, 0x46, 0x04, 0x44]);
}

struct Int;
impl AsPrompt for Int {
    fn password(&mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        unreachable!()
    }
    fn preauth(&mut self, _: &PreauthPrompt<'_>) -> Result<Zeroizing<Vec<u8>>, Error> {
        Err(Error::File(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "Password read interrupted",
        )))
    }
}

#[test]
fn a_prompt_that_fails_fails_the_module_and_an_interrupt_stops_it() {
    let mut ui = Script::of(&[]);
    let e = run(challenge(vec![ti()]), &mut ui).unwrap_err();
    assert_eq!(e.error.to_string(), "Cannot read password");
    assert!(!e.interrupted);
    let e = process(
        &state_of(challenge(vec![ti()])),
        &ResponderItems::default(),
        &mut Int,
        &armor(),
    )
    .err()
    .unwrap();
    assert!(e.interrupted);
}

#[test]
fn a_reply_is_cut_to_1023_bytes_and_at_a_nul() {
    let long: &'static str = Box::leak("7".repeat(2000).into_boxed_str());
    let mut ui = Script::of(&[long, "ab\0cd"]);
    let (req, _) = run(challenge(vec![ti()]), &mut ui).unwrap();
    assert_eq!(req.otp_value.as_ref().unwrap().len(), 1023);
    let (req, _) = run(challenge(vec![ti()]), &mut ui).unwrap();
    assert_eq!(req.otp_value.as_ref().unwrap().as_ref(), b"ab");
}

#[test]
fn the_challenge_json_is_mits_in_mits_order() {
    let full = OtpTokenInfo {
        flags: flags(OTP_FLAG_COLLECT_PIN | OTP_FLAG_SEPARATE_PIN),
        vendor: Some(b"Acme".to_vec().into()),
        challenge: Some(b"12 34".to_vec().into()),
        length: Some(6),
        format: Some(OTP_FORMAT_DECIMAL),
        token_id: Some(b"tok\"1".to_vec().into()),
        alg_id: Some(b"urn:ietf:params:xml:ns:keyprov:pskc:hotp".to_vec().into()),
        ..ti()
    };
    let mut chl = challenge(vec![
        full,
        ti(),
        OtpTokenInfo {
            format: Some(OTP_FORMAT_BINARY),
            flags: flags(OTP_FLAG_NEXTOTP),
            ..ti()
        },
    ]);
    chl.service = Some(b"svc".to_vec().into());
    assert_eq!(
        challenge_json(&chl),
        concat!(
            r#"{"service":"svc","tokenInfo":["#,
            r#"{"flags":7,"vendor":"Acme","challenge":"12 34","length":6,"format":0,"tokenID":"tok\"1","algID":"urn:ietf:params:xml:ns:keyprov:pskc:hotp"},"#,
            r#"{"flags":1},"#,
            r#"{"flags":5}"#,
            r#"]}"#
        )
        .as_bytes()
    );
}

#[test]
fn a_responder_answer_is_read_like_mit_and_a_bad_one_goes_to_the_prompts() {
    let ok = |a: &str| decode_answer(Some(a), 2);
    let (at, v, p) = ok(r#"{"tokeninfo":1,"value":"123456","pin":"99"}"#).unwrap();
    assert_eq!(
        (at, v.as_slice(), p.as_deref().map(Vec::as_slice)),
        (1, &b"123456"[..], Some(&b"99"[..]))
    );
    let (at, v, p) = ok(r#"{"tokeninfo":0,"value":""}"#).unwrap();
    assert_eq!((at, v.len(), p), (0, 0, None));
    for bad in [
        r#"{"tokeninfo":2,"value":"x"}"#,
        r#"{"tokeninfo":-1,"value":"x"}"#,
        r#"{"tokeninfo":"0","value":"x"}"#,
        r#"{"value":"x"}"#,
        r#"{"tokeninfo":0}"#,
        r#"{"tokeninfo":0,"value":5}"#,
        r#"{"tokeninfo":0,"value":"x","pin":[]}"#,
        r"[0]",
        r#""x""#,
        "{",
    ] {
        assert!(ok(bad).is_none(), "{bad}");
    }
    assert!(decode_answer(None, 2).is_none());
}

#[test]
fn prep_asks_the_question_with_the_filtered_tokens() {
    let chl = challenge(vec![
        OtpTokenInfo {
            flags: flags(OTP_FLAG_NEXTOTP),
            ..ti()
        },
        vendor("A"),
        vendor("B"),
    ]);
    let pa141 = PaData {
        padata_type: pa::OTP_CHALLENGE,
        padata_value: encode(&chl).unwrap().into(),
    };
    let mut items = ResponderItems::default();
    let mut st = OtpState::default();
    prep_questions(&mut st, &pa141, Some(&cc(r#"{"vendor":"B"}"#)), &mut items).unwrap();
    assert_eq!(items.list_questions(), vec![QUESTION_OTP]);
    assert_eq!(
        items.get_challenge(QUESTION_OTP),
        Some(br#"{"tokenInfo":[{"flags":1,"vendor":"B"}]}"#.as_slice())
    );
    assert_eq!(st.chl.unwrap().token_info, vec![vendor("B")]);
    let none = PaData {
        padata_type: pa::OTP_CHALLENGE,
        padata_value: encode(&challenge(vec![OtpTokenInfo {
            flags: flags(OTP_FLAG_COMBINE),
            ..ti()
        }]))
        .unwrap()
        .into(),
    };
    let e = prep_questions(
        &mut OtpState::default(),
        &none,
        None,
        &mut ResponderItems::default(),
    )
    .unwrap_err();
    assert_eq!(e.to_string(), "No supported tokens");
    let junk = PaData {
        padata_type: pa::OTP_CHALLENGE,
        padata_value: vec![0x30, 0x01].into(),
    };
    assert!(
        prep_questions(
            &mut OtpState::default(),
            &junk,
            None,
            &mut ResponderItems::default()
        )
        .is_err()
    );
}

#[test]
fn the_responder_helpers_round_trip_mits_json_and_the_answer_is_used() {
    let full = OtpTokenInfo {
        flags: flags(OTP_FLAG_COLLECT_PIN | OTP_FLAG_SEPARATE_PIN),
        vendor: Some(b"Acme".to_vec().into()),
        challenge: Some(b"12 34".to_vec().into()),
        length: Some(6),
        format: Some(OTP_FORMAT_DECIMAL),
        token_id: Some(b"t1".to_vec().into()),
        alg_id: Some(b"urn:x".to_vec().into()),
        ..ti()
    };
    let mut chl = challenge(vec![vendor("A"), full]);
    chl.service = Some(b"svc".to_vec().into());
    let pa141 = PaData {
        padata_type: pa::OTP_CHALLENGE,
        padata_value: encode(&chl).unwrap().into(),
    };
    let mut items = ResponderItems::default();
    let mut st = OtpState::default();
    prep_questions(&mut st, &pa141, None, &mut items).unwrap();
    let view = items.otp_get_challenge().unwrap().unwrap();
    assert_eq!(
        view,
        OtpChallengeView {
            service: Some("svc".into()),
            tokeninfo: vec![
                OtpTokenView {
                    flags: 1,
                    format: -1,
                    length: -1,
                    vendor: Some("A".into()),
                    challenge: None,
                    token_id: None,
                    alg_id: None,
                },
                OtpTokenView {
                    flags: 7,
                    format: 0,
                    length: 6,
                    vendor: Some("Acme".into()),
                    challenge: Some("12 34".into()),
                    token_id: Some("t1".into()),
                    alg_id: Some("urn:x".into()),
                },
            ],
        }
    );
    items.otp_set_answer(1, Some("654321"), Some("99")).unwrap();
    assert_eq!(
        items.get_answer(QUESTION_OTP),
        Some(r#"{"tokeninfo":1,"value":"654321","pin":"99"}"#)
    );
    let mut ui = Script::of(&[]);
    let (pa142, cfg) = process(&st, &items, &mut ui, &armor()).unwrap();
    assert!(
        ui.asked.is_empty(),
        "the responder answered, nothing was prompted"
    );
    let req: PaOtpRequest = decode(pa142.padata_value.as_ref()).unwrap();
    assert_eq!(req.vendor.as_ref().map(AsRef::as_ref), Some(&b"Acme"[..]));
    assert_eq!(req.pin.as_ref().map(AsRef::as_ref), Some(&b"99"[..]));
    assert_eq!(
        req.otp_value.as_ref().map(AsRef::as_ref),
        Some(&b"654321"[..])
    );
    assert_eq!(
        config_octets(&cfg).as_deref(),
        Some(r#"{"vendor":"Acme","algID":"urn:x","tokenID":"t1"}"#.as_bytes())
    );
    items.otp_set_answer(0, None, None).unwrap();
    assert_eq!(items.get_answer(QUESTION_OTP), Some(r#"{"tokeninfo":0}"#));

    let mut none = ResponderItems::default();
    assert_eq!(none.otp_get_challenge().unwrap(), None);
    assert_eq!(
        none.otp_set_answer(0, None, None).unwrap_err().to_string(),
        "Invalid argument"
    );
    for bad in [
        "[1]",
        "{}",
        r#"{"tokenInfo":{}}"#,
        r#"{"tokenInfo":[1]}"#,
        r#"{"tokenInfo":[{"vendor":"x"}]}"#,
        r#"{"tokenInfo":[{"flags":1,"vendor":5}]}"#,
        r#"{"service":3,"tokenInfo":[]}"#,
    ] {
        let mut broken = ResponderItems::default();
        broken.ask_question(QUESTION_OTP, Some(bad.as_bytes()));
        assert_eq!(
            broken.otp_get_challenge().unwrap_err().to_string(),
            "Cannot allocate memory",
            "{bad}"
        );
    }
    let mut empty = ResponderItems::default();
    empty.ask_question(QUESTION_OTP, Some(br#"{"tokenInfo":[]}"#));
    let none_listed = empty.otp_get_challenge().unwrap().unwrap().tokeninfo;
    assert_eq!(none_listed.len(), 0);
    empty.ask_question(QUESTION_PASSWORD, Some(b""));
    assert_eq!(empty.get_answer(QUESTION_PASSWORD), None);
}

#[allow(
    clippy::useless_conversion,
    reason = "the octets are a Vec already, so the conversion is a no-op"
)]
fn config_octets(cfg: &Value) -> Option<Vec<u8>> {
    config_string(cfg).map(Into::into)
}

fn octet_token() -> OtpTokenInfo {
    OtpTokenInfo {
        vendor: Some(OctetString::from(b"Acme".to_vec())),
        alg_id: Some(OctetString::from(vec![0xff])),
        token_id: Some(OctetString::from(vec![0x61, 0xff, 0x62])),
        ..ti()
    }
}

#[test]
fn a_token_config_keeps_its_octets_in_pa_config_data() {
    let mut ui = Script::of(&["123456"]);
    let (_, cfg) = run(challenge(vec![octet_token()]), &mut ui).unwrap();
    let mut want = br#"{"vendor":"Acme","algID":""#.to_vec();
    want.push(0xff);
    want.extend_from_slice(br#"","tokenID":"a"#);
    want.extend_from_slice(&[0xff, b'b']);
    want.extend_from_slice(br#""}"#);
    assert_eq!(config_octets(&cfg), Some(want));
}

#[test]
fn a_second_login_reads_the_config_octets_and_prunes_to_the_token_they_name() {
    // MIT: `read_cc_config_in_data` (lib/krb5/krb/get_in_tkt.c:1176-1211)
    // the first login's config comes back as the input cache's octets.
    let mut first = Script::of(&["123456"]);
    let (_, cfg) = run(challenge(vec![octet_token()]), &mut first).unwrap();
    let stored = config_octets(&cfg).unwrap();
    let cc_in = k5json::decode(&stored).unwrap();
    let other = OtpTokenInfo {
        vendor: Some(OctetString::from(b"Beta".to_vec())),
        token_id: Some(OctetString::from(b"b".to_vec())),
        ..ti()
    };
    let pa141 = PaData {
        padata_type: pa::OTP_CHALLENGE,
        padata_value: encode(&challenge(vec![other, octet_token()]))
            .unwrap()
            .into(),
    };
    let mut st = OtpState::default();
    prep_questions(
        &mut st,
        &pa141,
        Some(&cc_in),
        &mut ResponderItems::default(),
    )
    .unwrap();
    assert_eq!(st.chl.unwrap().token_info, vec![octet_token()]);
}

#[test]
fn the_views_return_the_octets_of_mits_c_strings() {
    let mut chl = challenge(vec![OtpTokenInfo {
        challenge: Some(OctetString::from(b"12 34".to_vec())),
        length: Some(6),
        format: Some(OTP_FORMAT_DECIMAL),
        ..octet_token()
    }]);
    chl.service = Some(OctetString::from(b"svc\xff".to_vec()));
    let pa141 = PaData {
        padata_type: pa::OTP_CHALLENGE,
        padata_value: encode(&chl).unwrap().into(),
    };
    let mut items = ResponderItems::default();
    prep_questions(&mut OtpState::default(), &pa141, None, &mut items).unwrap();
    let view = items.otp_get_challenge().unwrap().unwrap();
    assert_eq!(view.service, Some(b"svc\xff".to_vec()));
    let token = &view.tokeninfo[0];
    assert_eq!(token.vendor, Some(b"Acme".to_vec()));
    assert_eq!(token.challenge, Some(b"12 34".to_vec()));
    assert_eq!(token.token_id, Some(vec![0x61, 0xff, 0x62]));
    assert_eq!(token.alg_id, Some(vec![0xff]));
}
