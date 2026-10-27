//! red at tree 964a79a8
//!
//! OTP preauthentication (RFC 6560) on the AS path: the challenge hint, the verdict and its
//! indicators, the wire codes of the failures, and the keyless and FAST variants.

#[path = "common/mod.rs"]
mod common;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use krb5_asn1::{decode, encode};
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt, encrypt};
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented};
use krb5_kdc::{Error, OtpVerdict, OtpVerifier, OtpVerifyRequest, PrincipalStore};
use krb5_protocol::{
    apply_strengthen, armor_key, as_req, as_req_sname, attach_fast, build_fast_armor,
    unwrap_fast_rep,
};
use krb5_testkit::issue_tgt_password;
use krb5_types::otp::{PaOtpChallenge, PaOtpEncRequest, PaOtpRequest};
use krb5_types::{
    EncryptedData, KerberosFlags, KerberosTime, MethodData, PaData, PaEncTsEnc, PrincipalName,
    ascii, err, ku, pa,
};

/// What a [`Scripted`] verifier was asked.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Call {
    token_type: String,
    username: Vec<u8>,
    otp_value: Vec<u8>,
}

/// A verifier that answers from a script, rejecting once the script runs out.
struct Scripted {
    name: &'static str,
    script: Mutex<VecDeque<OtpVerdict>>,
    calls: Mutex<Vec<Call>>,
}

impl Scripted {
    fn new(name: &'static str, verdicts: Vec<OtpVerdict>) -> Arc<Self> {
        Arc::new(Self {
            name,
            script: Mutex::new(verdicts.into()),
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }
}

impl OtpVerifier for Scripted {
    fn name(&self) -> &'static str {
        self.name
    }

    fn verify(&self, req: &OtpVerifyRequest) -> OtpVerdict {
        self.calls.lock().unwrap().push(Call {
            token_type: req.token_type.clone(),
            username: req.username.clone(),
            otp_value: req.otp_value.to_vec(),
        });
        self.script
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(OtpVerdict::Reject)
    }
}

fn put_otp(store: &mut PrincipalStore, verifiers: Vec<Arc<dyn OtpVerifier>>) {
    store.policy.plugins.set_otp_verifiers(verifiers);
}

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

/// The documented test realm, with the `otp` attribute set when one is given.
fn realm(attr: Option<&str>) -> PrincipalStore {
    let (mut store, _) = bootstrap_documented().unwrap();
    if let Some(a) = attr {
        store.set_string(&user(), "otp", Some(a)).unwrap();
    }
    store
}

/// A FAST armor: the ticket and the armor key a request is tunnelled under.
struct Armor {
    ap: krb5_types::ApReq,
    key: ProtocolKey,
}

fn armor(store: &PrincipalStore, nonce: u32) -> Armor {
    let armor_as = issue_tgt_password(store, TEST_USER, TEST_USER_PASSWORD, nonce);
    let sub = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[0x42; 32]).unwrap();
    Armor {
        ap: build_fast_armor(
            armor_as.rep.0.ticket.clone(),
            &armor_as.session_key,
            &ascii(TEST_REALM),
            &user(),
            Some(&sub),
        )
        .unwrap(),
        key: armor_key(&armor_as.session_key, Some(&sub)).unwrap(),
    }
}

fn fast_req(a: &Armor, inner: Vec<PaData>, nonce: u32) -> krb5_types::AsReq {
    let mut req = as_req(user(), TEST_REALM, nonce, None).unwrap();
    attach_fast(&mut req, &a.ap, &a.key, inner).unwrap();
    req
}

fn now() -> u32 {
    KerberosTime::now().unix_seconds()
}

/// The PA-ENC-TS-ENC-shaped plaintext of an OTP nonce: PA-OTP-ENC-REQUEST with `nonce` as the nonce.
fn enc_req_plain(nonce: &[u8]) -> Vec<u8> {
    encode(&PaOtpEncRequest {
        nonce: nonce.to_vec().into(),
    })
    .unwrap()
}

/// A nonce of the armor key's length plus four: a fresh time, then random octets.
fn fresh_nonce(key_len: usize) -> Vec<u8> {
    let mut n = vec![7u8; 4 + key_len];
    n[..4].copy_from_slice(&now().to_be_bytes());
    n
}

/// A PA-OTP-REQUEST whose encData holds `plain` under `key`, carrying `value` as the OTP.
fn pa_otp(key: &ProtocolKey, plain: &[u8], value: &[u8]) -> PaData {
    let usage = KeyUsage::new(ku::PA_OTP_REQUEST).unwrap();
    let cipher = encrypt(key, usage, plain).unwrap();
    let req = PaOtpRequest {
        flags: KerberosFlags::from_slice(&[0; 4]),
        nonce: None,
        enc_data: EncryptedData {
            etype: key.etype().to_iana(),
            kvno: None,
            cipher: cipher.into(),
        },
        hash_alg: None,
        iteration_count: None,
        otp_value: Some(value.to_vec().into()),
        pin: None,
        challenge: None,
        time: None,
        counter: None,
        format: None,
        token_id: None,
        alg_id: None,
        vendor: None,
    };
    PaData {
        padata_type: pa::OTP_REQUEST,
        padata_value: encode(&req).unwrap().into(),
    }
}

/// The inner hint padata of a FAST PREAUTH_REQUIRED or PREAUTH_FAILED error.
fn inner_hints(a: &Armor, e: &Error) -> Vec<PaData> {
    let e_data = match e {
        Error::PreauthRequired { e_data }
        | Error::Protocol {
            e_data: Some(e_data),
            ..
        } => e_data,
        other => panic!("no e_data in {other:?}"),
    };
    let method: MethodData = decode(e_data).unwrap();
    unwrap_fast_rep(&a.key, &Some(method)).unwrap().padata
}

/// The padata types of an unwrapped PREAUTH_REQUIRED hint list (no FAST armor).
fn plain_hint_types(e: &Error) -> Vec<i32> {
    let Error::PreauthRequired { e_data } = e else {
        panic!("not PREAUTH_REQUIRED: {e:?}")
    };
    let method: MethodData = decode(e_data).unwrap();
    method.iter().map(|p| p.padata_type).collect()
}

/// The code, text and detail of a protocol error.
fn code(e: &Error) -> (i32, Option<String>, Option<String>) {
    match e {
        Error::Protocol {
            code, text, detail, ..
        } => (*code, text.clone(), detail.clone()),
        other => panic!("expected Protocol, got {other:?}"),
    }
}

/// Installs verifiers, then runs one AS-REQ with the token built from `plain`.
fn run_with(
    store: &mut PrincipalStore,
    a: &Armor,
    verifiers: Vec<Arc<Scripted>>,
    plain: &[u8],
    n: u32,
) -> Result<krb5_kdc::IssuedAs, Error> {
    store.policy.plugins.set_otp_verifiers(
        verifiers
            .into_iter()
            .map(|v| v as Arc<dyn OtpVerifier>)
            .collect(),
    );
    let result = krb5_kdc::issue_as(store, &fast_req(a, vec![pa_otp(&a.key, plain, b"1")], n));
    store.policy.plugins.clear_otp_verifiers();
    result
}

/// The hint carries the PA-OTP-CHALLENGE only with the attribute and the armor.
#[test]
fn hint_needs_attribute_and_armor() {
    let store = realm(Some("[{}]"));
    let a = armor(&store, 9001);
    let e = krb5_kdc::issue_as(&store, &fast_req(&a, vec![], 9002)).unwrap_err();
    let hints = inner_hints(&a, &e);
    let h = hints
        .iter()
        .find(|p| p.padata_type == pa::OTP_CHALLENGE)
        .expect("141 offered");
    let der = h.padata_value.as_ref();
    // PA-OTP-CHALLENGE: a 49-octet SEQUENCE, the 36-octet nonce, and the token info with flags only.
    assert_eq!(&der[..4], [0x30, 0x31, 0x80, 0x24]);
    assert_eq!(
        &der[der.len() - 11..],
        [0xa2, 0x09, 0x30, 0x07, 0x80, 0x05, 0, 0, 0, 0, 0]
    );
    let ch: PaOtpChallenge = decode(der).unwrap();
    assert_eq!(ch.nonce.len(), 36);
    assert!(u32::from_be_bytes(ch.nonce[..4].try_into().unwrap()).abs_diff(now()) <= 2);
    // The harness realm configures one SPAKE group: MIT's order with SPAKE (settle cell U11).
    let order: Vec<i32> = hints.iter().map(|p| p.padata_type).collect();
    assert_eq!(
        order,
        [
            pa::FX_FAST,
            pa::ETYPE_INFO2,
            pa::OTP_CHALLENGE,
            pa::SPAKE,
            pa::ENCRYPTED_CHALLENGE,
            pa::FX_COOKIE,
            pa::FX_ERROR
        ]
    );
    // With no SPAKE group configured, MIT's order has no SPAKE (settle cell U11).
    let mut bare = realm(Some("[{}]"));
    bare.policy.spake_preauth_groups.clear();
    let bare_a = armor(&bare, 9008);
    let bare_e = krb5_kdc::issue_as(&bare, &fast_req(&bare_a, vec![], 9009)).unwrap_err();
    let bare_order: Vec<i32> = inner_hints(&bare_a, &bare_e)
        .iter()
        .map(|p| p.padata_type)
        .collect();
    assert_eq!(
        bare_order,
        [
            pa::FX_FAST,
            pa::ETYPE_INFO2,
            pa::OTP_CHALLENGE,
            pa::ENCRYPTED_CHALLENGE,
            pa::FX_COOKIE,
            pa::FX_ERROR
        ]
    );
    // Without armor there is no hint.
    let plain = as_req(user(), TEST_REALM, 9003, None).unwrap();
    let e = krb5_kdc::issue_as(&store, &plain).unwrap_err();
    assert!(!plain_hint_types(&e).contains(&pa::OTP_CHALLENGE));
    // With armor but no attribute there is no hint.
    let store = realm(None);
    let a = armor(&store, 9004);
    let e = krb5_kdc::issue_as(&store, &fast_req(&a, vec![], 9005)).unwrap_err();
    assert!(
        !inner_hints(&a, &e)
            .iter()
            .any(|p| p.padata_type == pa::OTP_CHALLENGE)
    );
    // An empty attribute string still offers the hint: MIT's get_string is not NULL for it.
    let store = realm(Some(""));
    let a = armor(&store, 9006);
    let e = krb5_kdc::issue_as(&store, &fast_req(&a, vec![], 9007)).unwrap_err();
    assert!(
        inner_hints(&a, &e)
            .iter()
            .any(|p| p.padata_type == pa::OTP_CHALLENGE)
    );
}

/// The wire codes of the failure paths before any verifier runs.
#[test]
fn wire_codes_of_the_failure_paths() {
    let store = realm(Some("[{}]"));
    let a = armor(&store, 9100);
    let key_len = a.key.as_bytes().len();
    // A stale nonce of the armor's length is 24: the timestamp fallback fails to decode it.
    let mut stale = fresh_nonce(key_len);
    stale[..4].copy_from_slice(&now().saturating_sub(4000).to_be_bytes());
    let (c, _, d) = code(
        &krb5_kdc::issue_as(
            &store,
            &fast_req(&a, vec![pa_otp(&a.key, &enc_req_plain(&stale), b"1")], 9101),
        )
        .unwrap_err(),
    );
    assert_eq!(c, 24, "{d:?}");
    // Garbage plaintext is 24.
    let (c, _, _) = code(
        &krb5_kdc::issue_as(
            &store,
            &fast_req(&a, vec![pa_otp(&a.key, b"garbage", b"1")], 9103),
        )
        .unwrap_err(),
    );
    assert_eq!(c, 24);
    // encData under another key fails the integrity check: 31.
    let other = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[9; 32]).unwrap();
    let bad = pa_otp(&other, &enc_req_plain(&fresh_nonce(key_len)), b"1");
    let (c, _, _) = code(&krb5_kdc::issue_as(&store, &fast_req(&a, vec![bad], 9104)).unwrap_err());
    assert_eq!(c, err::BAD_INTEGRITY);
}

/// The configuration errors are all 24, and none of them runs a verifier.
#[test]
fn config_errors_are_24() {
    for bad in [
        "",
        "{}",
        "[1]",
        r#"[{"type":"nosuch"}]"#,
        r#"[{"indicators":"a"}]"#,
    ] {
        let store = realm(Some(bad));
        let a = armor(&store, 9300);
        let plain = enc_req_plain(&fresh_nonce(a.key.as_bytes().len()));
        let (c, _, _) = code(&run_with_none(&store, &a, &plain, 9301).unwrap_err());
        assert_eq!(c, 24, "{bad:?}");
    }
}

/// Runs one AS-REQ with no verifier installed, for the paths that never reach one.
fn run_with_none(
    store: &PrincipalStore,
    a: &Armor,
    plain: &[u8],
    n: u32,
) -> Result<krb5_kdc::IssuedAs, Error> {
    krb5_kdc::issue_as(store, &fast_req(a, vec![pa_otp(&a.key, plain, b"1")], n))
}

/// The plugins stanza selects the module by name.
#[test]
fn plugins_stanza_selects_otp() {
    let (store, a) = stanza_realm(
        "[{}]",
        "[plugins]\n    kdcpreauth = {\n        disable = otp\n    }\n",
        9600,
    );
    // Disabled: no hint, and a PA 142 is ignored, so the request is the plain 25.
    let e = krb5_kdc::issue_as(&store, &fast_req(&a, vec![], 9601)).unwrap_err();
    assert!(
        !inner_hints(&a, &e)
            .iter()
            .any(|p| p.padata_type == pa::OTP_CHALLENGE)
    );
    let plain = enc_req_plain(&fresh_nonce(32));
    let e = krb5_kdc::issue_as(
        &store,
        &fast_req(&a, vec![pa_otp(&a.key, &plain, b"1")], 9602),
    )
    .unwrap_err();
    assert!(matches!(e, Error::PreauthRequired { .. }), "{e:?}");
    // Enabled alone: the hint stays, and the other modules go.
    let (store, a) = stanza_realm(
        "[{}]",
        "[plugins]\n    kdcpreauth = {\n        enable_only = otp\n    }\n",
        9603,
    );
    let e = krb5_kdc::issue_as(&store, &fast_req(&a, vec![], 9604)).unwrap_err();
    let types: Vec<i32> = inner_hints(&a, &e).iter().map(|p| p.padata_type).collect();
    assert!(
        types.contains(&pa::OTP_CHALLENGE) && !types.contains(&pa::SPAKE),
        "{types:?}"
    );
}

fn stanza_realm(attr: &str, stanza: &str, nonce: u32) -> (PrincipalStore, Armor) {
    let mut store = realm(Some(attr));
    let a = armor(&store, nonce);
    let conf = krb5_config::KdcConf::parse(stanza).unwrap();
    store.apply_kdc_conf(&conf).unwrap();
    (store, a)
}

/// An OTP accepted for the principal issues, and its reply key is the armor key.
#[test]
fn accept_replaces_reply_key_with_the_armor_key() {
    let v = Scripted::new("DEFAULT", vec![OtpVerdict::Accept]);
    let mut store = realm(Some(r#"[{"indicators":["a","b"]}]"#));
    put_otp(&mut store, vec![v.clone()]);
    let a = armor(&store, 9101);
    let plain = enc_req_plain(&fresh_nonce(a.key.as_bytes().len()));
    let req = fast_req(&a, vec![pa_otp(&a.key, &plain, b"123456")], 9102);
    let issued = krb5_kdc::issue_as(&store, &req).expect("OTP login");
    assert_eq!(
        v.calls(),
        vec![Call {
            token_type: "DEFAULT".into(),
            username: format!("{TEST_USER}@{TEST_REALM}").into_bytes(),
            otp_value: b"123456".to_vec(),
        }]
    );
    let fast = unwrap_fast_rep(&a.key, &issued.rep.0.padata).expect("FAST rep");
    let sk = fast.strengthen_key.expect("strengthen key");
    assert_eq!(sk.keytype, a.key.etype().to_iana());
    let reply = apply_strengthen(&sk, &a.key).expect("CF2");
    assert_eq!(reply.as_bytes(), issued.as_rep_key.as_bytes());
    let usage = KeyUsage::new(ku::AS_REP_ENC_PART).unwrap();
    let plain = decrypt(&reply, usage, issued.rep.0.enc_part.cipher.as_ref()).expect("enc part");
    let enc = krb5_asn1::decode_enc_kdc_rep_part(&plain).unwrap();
    assert!(enc.flags.pre_authent());
    assert_eq!(issued.rep.0.enc_part.etype, a.key.etype().to_iana());
    // Key info follows, since the client has a key: ETYPE-INFO2 in the FAST response.
    assert!(
        fast.padata.iter().any(|p| p.padata_type == pa::ETYPE_INFO2),
        "{:?}",
        fast.padata
            .iter()
            .map(|p| p.padata_type)
            .collect::<Vec<_>>()
    );
    // The password key does not open the reply.
    let pw = krb5_testkit::password_key(TEST_USER, TEST_USER_PASSWORD);
    let pw = apply_strengthen(&sk, &pw).unwrap();
    assert!(decrypt(&pw, usage, issued.rep.0.enc_part.cipher.as_ref()).is_err());
}

/// A rejection is the module's verify failure: `finish_verify_padata` writes its one line, and the AS_REQ line follows.
// MIT: `finish_verify_padata` (kdc/kdc_preauth.c:1224-1228)
/// the module's failure is logged once, under its name, with the message of its code.
#[test]
fn a_rejection_is_logged_once_as_the_modules_verify_failure() {
    let v = Scripted::new("DEFAULT", vec![OtpVerdict::Reject]);
    let mut store = realm(Some("[]"));
    put_otp(&mut store, vec![v]);
    let a = armor(&store, 9211);
    let plain = enc_req_plain(&fresh_nonce(32));
    let raw = encode(&fast_req(&a, vec![pa_otp(&a.key, &plain, b"000000")], 9212)).unwrap();
    let (reply, log) = common::kdc_log(|| krb5_kdc::handle_request(&store, &raw));
    assert!(reply.is_ok());
    assert_eq!(
        common::failure_trace(&log),
        [
            "preauth (otp) verify failure: Generic preauthentication failure",
            "AS_REQ PREAUTH_FAILED, Preauthentication failed",
        ]
    );
}

/// The nonce and timestamp checks with a verifier that accepts.
#[test]
fn nonce_and_timestamp_paths() {
    let store = realm(Some("[{}]"));
    let a = armor(&store, 9301);
    let mut store = store;
    let mut run = |plain: &[u8], n: u32| {
        let v = Scripted::new("DEFAULT", vec![OtpVerdict::Accept]);
        put_otp(&mut store, vec![v]);
        krb5_kdc::issue_as(&store, &fast_req(&a, vec![pa_otp(&a.key, plain, b"1")], n))
    };
    // A fresh nonce of the armor's length issues.
    assert!(run(&enc_req_plain(&fresh_nonce(32)), 9302).is_ok());
    // A stale nonce of that length is 24: the timestamp fallback cannot decode it.
    let mut stale = fresh_nonce(32);
    stale[..4].copy_from_slice(&now().saturating_sub(4000).to_be_bytes());
    let (c, _, d) = code(&run(&enc_req_plain(&stale), 9303).unwrap_err());
    assert_eq!(c, 24, "{d:?}");
    // A nonce of another length passes with no clock check (an MIT quirk).
    assert!(run(&enc_req_plain(&[0, 0, 0, 1, 9]), 9304).is_ok());
    // A fresh PA-ENC-TS-ENC issues.
    let ts = |t: u32| {
        encode(&PaEncTsEnc {
            patimestamp: KerberosTime::from_unix_seconds(t),
            pausec: None,
        })
        .unwrap()
    };
    assert!(run(&ts(now()), 9305).is_ok());
    // A stale PA-ENC-TS-ENC is clock skew (37): this port does not read it as a nonce, where MIT issues.
    let (c, _, d) = code(&run(&ts(now() - 4000), 9306).unwrap_err());
    assert_eq!(c, err::SKEW, "{d:?}");
    // Garbage plaintext is 24.
    let (c, _, _) = code(&run(b"garbage", 9307).unwrap_err());
    assert_eq!(c, 24);
    // encData under another key is 31.
    let other = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[9; 32]).unwrap();
    let v = Scripted::new("DEFAULT", vec![OtpVerdict::Accept]);
    put_otp(&mut store, vec![v]);
    let bad = pa_otp(&other, &enc_req_plain(&fresh_nonce(32)), b"1");
    let (c, _, _) = code(&krb5_kdc::issue_as(&store, &fast_req(&a, vec![bad], 9308)).unwrap_err());
    assert_eq!(c, err::BAD_INTEGRITY);
}

/// The config errors never call a verifier, and the token loop stops at the first Accept or Error.
#[test]
fn config_errors_and_token_loop() {
    let go = |attr: &str, verifiers: Vec<Arc<Scripted>>, n: u32| {
        let mut store = realm(Some(attr));
        let a = armor(&store, n);
        let plain = enc_req_plain(&fresh_nonce(32));
        run_with(&mut store, &a, verifiers, &plain, n + 1)
    };
    // An unknown type is 24 before any call.
    let v = Scripted::new("DEFAULT", vec![OtpVerdict::Accept]);
    let e = go(r#"[{"type":"nosuch"}]"#, vec![v.clone()], 9400).unwrap_err();
    assert_eq!(code(&e).0, 24);
    assert_eq!(v.calls(), Vec::<Call>::new());
    // Other bad configs are 24, and none of them calls a verifier.
    for bad in [
        "",
        "{}",
        "[1]",
        r#"[{"indicators":"a"}]"#,
        r#"[{"indicators":[1]}]"#,
        "[{} x",
    ] {
        let v = Scripted::new("DEFAULT", vec![OtpVerdict::Accept]);
        let e = go(bad, vec![v.clone()], 9410).unwrap_err();
        assert_eq!(code(&e).0, 24, "{bad:?}");
        assert!(v.calls().is_empty(), "{bad:?}");
    }
    // An empty array is one empty token, so the DEFAULT type is asked, and with no verifier it fails.
    let e = go("[]", vec![], 9420).unwrap_err();
    assert_eq!(code(&e).0, 24);
    // A Reject passes to the next token, which accepts; the usernames come from the JSON.
    let d = Scripted::new("DEFAULT", vec![OtpVerdict::Reject]);
    let t = Scripted::new("totp", vec![OtpVerdict::Accept]);
    let attr = r#"[{"username":"u1"},{"type":"totp","username":"u2"}]"#;
    assert!(go(attr, vec![d.clone(), t.clone()], 9430).is_ok());
    assert_eq!(d.calls()[0].username, b"u1");
    assert_eq!(t.calls()[0].username, b"u2");
    // An Error fails at once, and the second token's verifier is never called.
    let d = Scripted::new("DEFAULT", vec![OtpVerdict::Error("backend down".into())]);
    let t = Scripted::new("totp", vec![OtpVerdict::Accept]);
    let e = go(attr, vec![d, t.clone()], 9440).unwrap_err();
    assert_eq!(code(&e).0, 24);
    assert_eq!(t.calls(), Vec::<Call>::new());
}

/// The client holds no key of the requested etype at its top kvno: MIT carries ENCTYPE_NULL and
/// the OTP module replaces the reply key.
#[test]
fn keyless_otp_login_issues() {
    let mut store = realm(Some("[{}]"));
    let a = armor(&store, 9500);
    let aes128 = EncryptionType::Aes128CtsHmacSha196;
    store
        .set_keys(
            &user(),
            vec![krb5_kdc::KeyEntry::new(
                aes128,
                krb5_kdc::random_key(aes128).unwrap(),
                0,
            )],
            2,
        )
        .unwrap();
    let mk = |inner: Vec<PaData>, n: u32| {
        let mut req = as_req_sname(
            user(),
            TEST_REALM,
            n,
            None,
            PrincipalName::krbtgt(TEST_REALM),
            vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
        )
        .unwrap();
        attach_fast(&mut req, &a.ap, &a.key, inner).unwrap();
        req
    };
    let v = Scripted::new("DEFAULT", vec![OtpVerdict::Accept]);
    put_otp(&mut store, vec![v]);
    let plain = enc_req_plain(&fresh_nonce(32));
    let issued = krb5_kdc::issue_as(&store, &mk(vec![pa_otp(&a.key, &plain, b"1")], 9502))
        .expect("keyless OTP login");
    let fast = unwrap_fast_rep(&a.key, &issued.rep.0.padata).unwrap();
    assert!(!fast.padata.iter().any(|p| p.padata_type == pa::ETYPE_INFO2));
    let reply = apply_strengthen(&fast.strengthen_key.unwrap(), &a.key).unwrap();
    assert_eq!(reply.as_bytes(), issued.as_rep_key.as_bytes());
}

/// The verdict's indicators are not added: the token's indicators apply, so `require_auth`
/// accepts "a" and "b" and refuses "d" with HIGHER_AUTHENTICATION_REQUIRED.
#[test]
fn indicators_and_require_auth() {
    let run = |require: &str, n: u32| {
        let v = Scripted::new("DEFAULT", vec![OtpVerdict::Accept]);
        let mut store = realm(Some(r#"[{"indicators":["a","b"]}]"#));
        put_otp(&mut store, vec![v]);
        // Before require_auth: the armor TGT is itself a krbtgt service ticket request.
        let a = armor(&store, n);
        store
            .set_string(
                &PrincipalName::krbtgt(TEST_REALM),
                "require_auth",
                Some(require),
            )
            .unwrap();
        let plain = enc_req_plain(&fresh_nonce(32));
        krb5_kdc::issue_as(
            &store,
            &fast_req(&a, vec![pa_otp(&a.key, &plain, b"1")], n + 1),
        )
    };
    assert!(
        run("a", 9800).is_ok(),
        "the token's indicator satisfies require_auth"
    );
    assert!(
        run("b", 9810).is_ok(),
        "the token's second indicator does too"
    );
    let e = run("d", 9820).unwrap_err();
    let (c, text, _) = code(&e);
    assert_eq!(c, err::POLICY);
    assert_eq!(text.as_deref(), Some("HIGHER_AUTHENTICATION_REQUIRED"));
}

/// MIT builds the RADIUS request before any transport, so a User-Name of 0 or over 253 octets, and an
/// OTP value of 0 or over 128 octets, fail the whole request before a verifier runs.
#[test]
fn radius_sizes_fail_before_the_verifier() {
    let plain = enc_req_plain(&fresh_nonce(32));
    // The outcome of one token of the given username and OTP value sizes: issued, and the calls.
    let outcome = |name_len: usize, value_len: usize| -> (bool, usize) {
        let attr = format!("[{{\"username\":\"{}\"}}]", "u".repeat(name_len));
        let mut store = realm(Some(&attr));
        let a = armor(&store, 9600);
        let v = Scripted::new("DEFAULT", vec![OtpVerdict::Accept]);
        put_otp(&mut store, vec![v.clone()]);
        let value = vec![b'1'; value_len];
        let req = fast_req(&a, vec![pa_otp(&a.key, &plain, &value)], 9601);
        let issued = krb5_kdc::issue_as(&store, &req).is_ok();
        (issued, v.calls().len())
    };
    assert_eq!(outcome(0, 1), (false, 0), "an empty username");
    assert_eq!(outcome(1, 1), (true, 1));
    assert_eq!(outcome(253, 1), (true, 1));
    assert_eq!(outcome(254, 1), (false, 0));
    assert_eq!(outcome(1, 0), (false, 0), "an empty OTP value");
    assert_eq!(outcome(1, 127), (true, 1));
    assert_eq!(outcome(1, 128), (true, 1));
    assert_eq!(outcome(1, 129), (false, 0));
}

// `[otp]` in kdc.conf (OTP2). These use `KdcConf::parse` and `apply_kdc_conf` only.

/// The indicators of `[otp]` reach the ticket (settle cell X4): the type's, repeated, replaced by a
/// token's own `indicators` even when empty, and a token that is asked and rejects adds none.
#[test]
fn otp_section_indicators_reach_the_ticket() {
    let kdc = "[otp]\n    DEFAULT = {\n        indicator = typeind\n    }\n    A = {\n        indicator = aind\n    }\n    B = {\n        indicator = bind1\n        indicator = bind2\n    }\n";
    // Whether a login with `attr` under `require_auth` = `require` issues, A rejecting and the rest accepting.
    let issues = |attr: &str, require: &str, n: u32| -> bool {
        let verifiers: Vec<Arc<dyn OtpVerifier>> = vec![
            Scripted::new("DEFAULT", vec![OtpVerdict::Accept]),
            Scripted::new("A", vec![OtpVerdict::Reject]),
            Scripted::new("B", vec![OtpVerdict::Accept]),
        ];
        let mut store = realm(Some(attr));
        put_otp(&mut store, verifiers);
        let a = armor(&store, n);
        store
            .apply_kdc_conf(&krb5_config::KdcConf::parse(kdc).unwrap())
            .unwrap();
        store
            .set_string(
                &PrincipalName::krbtgt(TEST_REALM),
                "require_auth",
                Some(require),
            )
            .unwrap();
        let plain = enc_req_plain(&fresh_nonce(32));
        match krb5_kdc::issue_as(
            &store,
            &fast_req(&a, vec![pa_otp(&a.key, &plain, b"1")], n + 1),
        ) {
            Ok(_) => true,
            Err(e) => {
                let (c, text, _) = code(&e);
                assert_eq!(c, err::POLICY, "{attr} / {require}");
                assert_eq!(text.as_deref(), Some("HIGHER_AUTHENTICATION_REQUIRED"));
                false
            }
        }
    };
    // X4.1: the empty array is DEFAULT, whose indicator applies; one listed value must match.
    assert!(issues("[]", "typeind", 9000));
    assert!(!issues("[]", "other", 9010));
    assert!(issues("[]", "other typeind", 9020));
    // X4.2, X4.3: a token's `indicators` replace the type's, and `[]` leaves none.
    assert!(!issues(r#"[{"indicators":["tok1"]}]"#, "typeind", 9030));
    assert!(issues(r#"[{"indicators":["tok1"]}]"#, "tok1", 9040));
    assert!(!issues(r#"[{"indicators":[]}]"#, "typeind", 9050));
    // X4.4: a repeated `indicator` gives all of them, in the type of the token.
    assert!(issues(r#"[{"type":"B"}]"#, "bind2", 9060));
    assert!(issues(r#"[{"type":"B"}]"#, "bind1", 9070));
    assert!(!issues(r#"[{"type":"B"}]"#, "typeind", 9080));
    // X4.5: A rejects, so only B's indicators are in the ticket.
    assert!(!issues(r#"[{"type":"A"},{"type":"B"}]"#, "aind", 9090));
    assert!(issues(r#"[{"type":"A"},{"type":"B"}]"#, "bind1", 9100));
}

/// `strip_realm` defaults to true for a section and to false for the built-in types (settle cells
/// base A and B, X2.7): the username the verifier sees keeps the realm only without a section or with
/// `strip_realm = false`.
#[test]
fn strip_realm_splits_defined_sections_from_the_builtin_types() {
    let with_realm = format!("{TEST_USER}@{TEST_REALM}").into_bytes();
    let bare = TEST_USER.as_bytes().to_vec();
    // The username a login of `token_type` is given, for the kdc.conf text.
    let username = |kdc: &str, token_type: &'static str, n: u32| -> Vec<u8> {
        let v = Scripted::new(token_type, vec![OtpVerdict::Accept]);
        let mut store = realm(Some(&format!(r#"[{{"type":"{token_type}"}}]"#)));
        put_otp(&mut store, vec![v.clone()]);
        let a = armor(&store, n);
        store
            .apply_kdc_conf(&krb5_config::KdcConf::parse(kdc).unwrap())
            .unwrap();
        let plain = enc_req_plain(&fresh_nonce(32));
        krb5_kdc::issue_as(
            &store,
            &fast_req(&a, vec![pa_otp(&a.key, &plain, b"1")], n + 1),
        )
        .expect("OTP login");
        v.calls().remove(0).username
    };
    // No `[otp]`: the built-in DEFAULT and a verifier's own type keep the realm.
    assert_eq!(username("", "DEFAULT", 9200), with_realm);
    assert_eq!(username("", "totp", 9210), with_realm);
    // A section for the type strips it, by default; `strip_realm = false` keeps it.
    assert_eq!(username("[otp]\n DEFAULT = {\n }\n", "DEFAULT", 9220), bare);
    assert_eq!(username("[otp]\n totp = {\n }\n", "totp", 9230), bare);
    assert_eq!(
        username("[otp]\n R = {\n  strip_realm = false\n }\n", "R", 9240),
        with_realm
    );
    // A section for another type changes nothing for this one.
    assert_eq!(
        username("[otp]\n DEFAULT = {\n }\n", "totp", 9250),
        with_realm
    );
}

/// A `server` or `secret` leaves the whole module out, as `disable = otp` does: no hint, and a
/// PA-OTP-REQUEST is ignored. The other modules stay. A good section keeps the module.
#[test]
fn a_refused_or_bad_section_leaves_the_otp_module_out() {
    let offers_otp = |kdc: &str, n: u32| -> (bool, bool) {
        let (store, a) = stanza_realm("[{}]", kdc, n);
        let e = krb5_kdc::issue_as(&store, &fast_req(&a, vec![], n + 1)).unwrap_err();
        let types: Vec<i32> = inner_hints(&a, &e).iter().map(|p| p.padata_type).collect();
        let plain = enc_req_plain(&fresh_nonce(32));
        let e = krb5_kdc::issue_as(
            &store,
            &fast_req(&a, vec![pa_otp(&a.key, &plain, b"1")], n + 2),
        )
        .unwrap_err();
        // With the module out, a PA 142 is ignored and the request is the plain 25.
        let ignored = matches!(e, Error::PreauthRequired { .. });
        assert!(types.contains(&pa::ENCRYPTED_CHALLENGE), "{types:?}");
        (types.contains(&pa::OTP_CHALLENGE), ignored)
    };
    for out in [
        "[otp]\n DEFAULT = {\n  server = /s/otp.sock\n }\n",
        "[otp]\n A = {\n  secret = secret.file\n }\n",
        "[otp]\n A = {\n  strip_realm = maybe\n }\n",
        "[otp]\n A = {\n  timeout = 5s\n }\n",
    ] {
        assert_eq!(offers_otp(out, 9300), (false, true), "{out:?}");
    }
    for kept in [
        "",
        "[otp]\n DEFAULT = {\n  indicator = x\n  timeout = 7\n  retries = 2\n  strip_realm = no\n }\n",
    ] {
        assert_eq!(offers_otp(kept, 9310), (true, false), "{kept:?}");
    }
}
