//! red at tree bd74009e (the module, AsPrompt and PromptType do not exist there)
//!
//! The client OTP preauth module against this repo's KDC: the prompts, the request, the reply key,
//! the ccache config and the failure that allows no fallback.

#[path = "common/mod.rs"]
mod common;
use common::isolate_host_krb5;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented};
use krb5_kdc::{
    OtpVerdict, OtpVerifier, OtpVerifyRequest, PrincipalStore, register_otp_verifier, serve,
    shared_store,
};
use krb5_protocol::{
    AsOutcome, AsPrompt, AsRequest, AsTicketOpts, Error, FastArmor, KdcAddr, PreauthPrompt,
    PromptType, as_exchange, as_exchange_interactive,
};
use krb5_types::{PrincipalName, ascii, err, pa};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use zeroize::Zeroizing;

/// What the KDC's verifier saw.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Call {
    username: Vec<u8>,
    otp_value: Vec<u8>,
}

/// Accepts `123456` and rejects everything else, and remembers what it was asked.
struct Code {
    calls: Mutex<Vec<Call>>,
}

impl OtpVerifier for Code {
    fn name(&self) -> &'static str {
        "clienttest"
    }

    fn verify(&self, r: &OtpVerifyRequest<'_>) -> OtpVerdict {
        self.calls.lock().unwrap().push(Call {
            username: r.username.to_vec(),
            otp_value: r.otp_value.to_vec(),
        });
        if r.otp_value == b"123456" {
            OtpVerdict::Accept
        } else {
            OtpVerdict::Reject
        }
    }
}

fn verifier() -> &'static Arc<Code> {
    static V: OnceLock<Arc<Code>> = OnceLock::new();
    V.get_or_init(|| {
        let v = Arc::new(Code {
            calls: Mutex::new(Vec::new()),
        });
        register_otp_verifier(v.clone());
        v
    })
}

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

/// A prompter that answers from a script and records what it was asked.
#[derive(Default)]
struct Ui {
    answers: VecDeque<Vec<u8>>,
    password: Option<&'static [u8]>,
    prompts: Vec<(Option<String>, String, bool, PromptType)>,
    passwords: usize,
}

impl Ui {
    fn answering(answers: &[&str]) -> Self {
        Self {
            answers: answers.iter().map(|a| a.as_bytes().to_vec()).collect(),
            ..Self::default()
        }
    }
}

impl AsPrompt for Ui {
    fn password(&mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.passwords += 1;
        self.password
            .map(|p| Zeroizing::new(p.to_vec()))
            .ok_or_else(|| Error::File(std::io::Error::other("the password was asked")))
    }

    fn preauth(&mut self, p: &PreauthPrompt<'_>) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.prompts.push((
            p.banner.map(str::to_owned),
            p.prompt.to_owned(),
            p.hidden,
            p.prompt_type,
        ));
        self.answers
            .pop_front()
            .map(Zeroizing::new)
            .ok_or_else(|| Error::File(std::io::Error::other("Cannot read password")))
    }
}

/// A served realm whose user has the `otp` attribute, and an armor ticket for the user.
fn realm(attr: &str) -> (KdcAddr, FastArmor) {
    isolate_host_krb5();
    let _ = verifier();
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store
        .set_string(&user(), "otp", Some(attr))
        .expect("otp attribute");
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    let port = udp.local_addr().unwrap().port();
    let store = shared(store);
    thread::spawn(move || {
        let _ = serve(store, udp, tcp);
    });
    let kdc = KdcAddr {
        host: "127.0.0.1".into(),
        port,
    };
    let plain = as_exchange(&request(&kdc, None)).expect("password AS for the armor ticket");
    let armor = FastArmor {
        ticket: plain.ticket,
        session: plain.session_key,
        crealm: plain.crealm,
        cname: plain.cname,
    };
    (kdc, armor)
}

fn shared(store: PrincipalStore) -> krb5_kdc::SharedStore {
    shared_store(store)
}

fn request<'a>(kdc: &'a KdcAddr, armor: Option<&'a FastArmor>) -> AsRequest<'a> {
    AsRequest {
        cname: user(),
        realm: TEST_REALM,
        password: TEST_USER_PASSWORD,
        kdc,
        want_spake: false,
        fast_armor: armor,
        pkinit: None,
        canonicalize: false,
        sname: None,
        etypes: None,
        ticket: AsTicketOpts::default(),
    }
}

fn otp_login(kdc: &KdcAddr, armor: &FastArmor, ui: &mut Ui) -> Result<AsOutcome, Error> {
    as_exchange_interactive(&request(kdc, Some(armor)), ui, false)
}

#[test]
fn otp_login_issues_a_tgt_and_never_asks_for_the_password() {
    let (kdc, armor) = realm(r#"[{"type":"clienttest"}]"#);
    let mut ui = Ui::answering(&["123456"]);
    let out = otp_login(&kdc, &armor, &mut ui).expect("OTP login");
    assert_eq!(out.pa_type, Some(pa::OTP_CHALLENGE), "ccache pa_type 141");
    assert!(out.used_fast);
    assert_eq!(out.pa_config, None, "a DEFAULT token records no config");
    assert_eq!(ui.passwords, 0, "OTP replaces the password");
    assert_eq!(
        ui.prompts,
        vec![(
            None,
            "Enter OTP Token Value".to_owned(),
            true,
            PromptType::Preauth
        )]
    );
    let seen = verifier().calls.lock().unwrap().clone();
    assert!(
        seen.contains(&Call {
            username: format!("{TEST_USER}@{TEST_REALM}").into_bytes(),
            otp_value: b"123456".to_vec(),
        }),
        "{seen:?}"
    );
    let _ = (ascii(TEST_REALM), err::PREAUTH_FAILED);
}

#[test]
fn a_wrong_value_is_preauthentication_failed_with_no_fallback() {
    let (kdc, armor) = realm(r#"[{"type":"clienttest"}]"#);
    let mut ui = Ui::answering(&["000000", "123456"]);
    let e = otp_login(&kdc, &armor, &mut ui).expect_err("wrong OTP");
    match e {
        Error::KrbError { code, .. } => assert_eq!(code, err::PREAUTH_FAILED),
        other => panic!("{other:?}"),
    }
    assert_eq!(ui.prompts.len(), 1, "one OTP prompt, none after the 24");
    assert_eq!(ui.passwords, 0, "no fall back to the password mechanisms");
    assert_eq!(ui.answers.len(), 1, "the second answer was never read");
}

#[test]
fn no_prompter_fails_the_module_and_the_password_follows() {
    let (kdc, armor) = realm(r#"[{"type":"clienttest"}]"#);
    // as_exchange has no prompter: the OTP module fails "Cannot read password" and the exchange
    // goes on to the next mechanism, which has the password in the request.
    let out = as_exchange(&request(&kdc, Some(&armor))).expect("falls back to the password");
    assert_eq!(out.pa_type, Some(pa::ENCRYPTED_CHALLENGE));
}

/// MIT `sort_krb5_padata_sequence` (`lib/krb5/krb/get_in_tkt.c:400-471`): `preferred_preauth_types`
/// moves a type to the front of the hint, so encrypted challenge (138) is run before OTP (141).
#[test]
fn preferred_preauth_types_138_runs_encrypted_challenge_before_otp() {
    let (kdc, armor) = realm(r#"[{"type":"clienttest"}]"#);
    krb5_config::isolate_test_krb5();
    let dir = krb5_testkit::scratch_dir("client-otp-preferred");
    let path = dir.join("krb5.conf");
    std::fs::write(
        &path,
        "[libdefaults]\n    default_realm = KERBER.TEST\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n    preferred_preauth_types = 138\n",
    )
    .unwrap();
    krb5_config::set_test_krb5_paths(Some(vec![path]));
    let mut ui = Ui {
        password: Some(TEST_USER_PASSWORD),
        ..Ui::default()
    };
    let out = otp_login(&kdc, &armor, &mut ui).expect("password login through encrypted challenge");
    assert_eq!(out.pa_type, Some(pa::ENCRYPTED_CHALLENGE));
    assert!(ui.prompts.is_empty(), "no OTP prompt: {:?}", ui.prompts);
    assert_eq!(ui.passwords, 1);
}
