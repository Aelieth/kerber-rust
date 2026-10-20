//! red at tree bb1a2afc (one password read, and a read that failed ended the exchange)
//!
//! The AS password is read when a mechanism needs the key, once per mechanism that does: a read that
//! fails is that mechanism's failure and the next one that needs the key reads again; a read that
//! worked is kept; an interrupt ends the exchange at once.
//! MIT `get_as_key` (`lib/krb5/krb/preauth2.c:438-457`): `gak_fct` runs whenever a module wants the key and none is held.
//! MIT `krb5_get_as_key_password` (`lib/krb5/krb/gic_pwd.c:55-97`): `gp->password` is set only by a prompt that returned.
//! MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:684-723`): a module that fails is traced and the next real mechanism runs; the first failure is the one reported; a keyboard interrupt ends the walk.
//! Settled live on kerber-rust-mit-kdc:1.22.2: FAST and plain logins at EOF, a wrong password and a reused one, SIGINT, and a refused support message.

#[path = "common/mod.rs"]
mod common;
use common::isolate_host_krb5;
use krb5_asn1::{decode, encode};
use krb5_crypto::SpakeGroup;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented};
use krb5_kdc::{PrincipalStore, serve, shared_store};
use krb5_protocol::{
    AsOutcome, AsPrompt, AsRequest, AsTicketOpts, Error, FastArmor, KdcAddr, QUESTION_PASSWORD,
    Responder, ResponderItems, as_exchange, as_exchange_interactive,
};
use krb5_types::spake::PaSpake;
use krb5_types::{KrbError, MethodData, PaData, PrincipalName, err, pa};
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use zeroize::Zeroizing;

/// One read the prompter answers with.
#[derive(Clone, Copy)]
enum Read {
    /// This text.
    Text(&'static [u8]),
    /// Input ended: MIT's `KRB5_LIBOS_CANTREADPWD`.
    Eof,
    /// `SIGINT`: MIT's `KRB5_LIBOS_PWDINTR`.
    Interrupt,
}

const RIGHT: Read = Read::Text(TEST_USER_PASSWORD);

/// A prompter that answers the password from a script and counts the reads.
struct Ui {
    reads: VecDeque<Read>,
    passwords: usize,
    responder: Option<Box<dyn Responder>>,
}

impl Ui {
    fn new(reads: &[Read]) -> Self {
        Self {
            reads: reads.iter().copied().collect(),
            passwords: 0,
            responder: None,
        }
    }

    /// A prompter with no reads and a responder that answers the password question, whose calls
    /// are recorded in the returned list (each call's questions, in order).
    fn answering() -> (Self, Calls) {
        let calls = Calls::default();
        let ui = Self {
            responder: Some(Box::new(Answers(calls.clone(), true))),
            ..Self::new(&[])
        };
        (ui, calls)
    }

    /// As [`Ui::answering`], and the responder answers nothing.
    fn listening() -> (Self, Calls) {
        let calls = Calls::default();
        let ui = Self {
            responder: Some(Box::new(Answers(calls.clone(), false))),
            ..Self::new(&[])
        };
        (ui, calls)
    }
}

/// The questions each call of the responder was asked.
type Calls = Arc<Mutex<Vec<Vec<String>>>>;

/// MIT `krb5_responder_fn`: records the questions, checks the password question's challenge is empty,
/// and gives the user's password when it answers.
struct Answers(Calls, bool);

impl Responder for Answers {
    fn respond(&mut self, items: &mut ResponderItems) -> Result<(), Error> {
        self.0.lock().unwrap().push(
            items
                .list_questions()
                .iter()
                .map(|q| (*q).to_owned())
                .collect(),
        );
        assert_eq!(items.get_challenge(QUESTION_PASSWORD), Some(&b""[..]));
        if self.1 {
            items.set_answer(
                QUESTION_PASSWORD,
                Some(std::str::from_utf8(TEST_USER_PASSWORD).unwrap()),
            )?;
        }
        Ok(())
    }
}

impl AsPrompt for Ui {
    fn password(&mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.passwords += 1;
        match self.reads.pop_front() {
            Some(Read::Text(t)) => Ok(Zeroizing::new(t.to_vec())),
            Some(Read::Interrupt) => Err(Error::File(std::io::Error::new(
                ErrorKind::Interrupted,
                "Password read interrupted",
            ))),
            Some(Read::Eof) | None => {
                Err(Error::File(std::io::Error::other("Cannot read password")))
            }
        }
    }

    fn responder(&mut self) -> Option<&mut dyn Responder> {
        match self.responder.as_mut() {
            Some(r) => Some(&mut **r),
            None => None,
        }
    }
}

/// How the test KDC offers SPAKE.
#[derive(Clone, Copy)]
enum Spake {
    /// edwards25519 is permitted and is the optimistic challenge group: the challenge rides in
    /// the hint, as on the lab's KDC.
    Challenge,
    /// edwards25519 is permitted with no optimistic challenge: the client sends support first.
    Support,
    /// Only P-256, which the client's default group does not share: its support message is
    /// refused with `PREAUTH_FAILED`.
    Refuses,
}

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

fn store(spake: Spake) -> PrincipalStore {
    let (mut store, _) = bootstrap_documented().expect("bootstrap");
    store.policy.spake_preauth_groups = match spake {
        Spake::Challenge | Spake::Support => vec![SpakeGroup::Edwards25519],
        Spake::Refuses => vec![SpakeGroup::P256],
    };
    if matches!(spake, Spake::Challenge) {
        store.policy.spake_preauth_kdc_challenge = Some("edwards25519".to_owned());
    }
    store
}

/// A KDC served by [`serve`].
fn kdc(spake: Spake) -> KdcAddr {
    isolate_host_krb5();
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    let port = udp.local_addr().unwrap().port();
    let store = shared_store(store(spake));
    thread::spawn(move || {
        let _ = serve(store, udp, tcp);
    });
    KdcAddr {
        host: "127.0.0.1".into(),
        port,
    }
}

/// A KDC that passes every reply through `rewrite` (UDP only; the client's requests are small).
fn kdc_rewriting(spake: Spake, rewrite: fn(Vec<u8>) -> Vec<u8>) -> KdcAddr {
    isolate_host_krb5();
    let store = store(spake);
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, src)) = udp.recv_from(&mut buf) {
            if let Ok(reply) = krb5_kdc::handle_request(&store, &buf[..n]) {
                let _ = udp.send_to(&rewrite(reply), src);
            }
        }
    });
    KdcAddr {
        host: "127.0.0.1".into(),
        port,
    }
}

/// A KDC (UDP only) that answers from `store` and counts the requests it receives.
fn kdc_counting(store: PrincipalStore) -> (KdcAddr, Arc<AtomicUsize>) {
    isolate_host_krb5();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let seen = Arc::new(AtomicUsize::new(0));
    let count = seen.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok((n, src)) = udp.recv_from(&mut buf) {
            count.fetch_add(1, Ordering::SeqCst);
            if let Ok(reply) = krb5_kdc::handle_request(&store, &buf[..n]) {
                let _ = udp.send_to(&reply, src);
            }
        }
    });
    (
        KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        seen,
    )
}

/// `store(spake)` with the user's REQUIRES_PRE_AUTH cleared: the KDC answers the first request.
fn store_without_preauth(spake: Spake) -> PrincipalStore {
    let mut store = store(spake);
    let attrs = store.get_name(&user()).unwrap().attributes & !krb5_kdc::KDB_REQUIRES_PRE_AUTH;
    store
        .apply_admin_fields(
            &user(),
            krb5_kdc::AdminFields {
                attributes: Some(attrs),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )
        .unwrap();
    store
}

fn request<'a>(
    profile: &'a krb5_config::Krb5Conf,
    kdc: &'a KdcAddr,
    armor: Option<&'a FastArmor>,
) -> AsRequest<'a> {
    AsRequest {
        cname: user(),
        realm: TEST_REALM,
        password: TEST_USER_PASSWORD,
        kdc,
        profile,
        want_spake: false,
        fast_armor: armor,
        pkinit: None,
        canonicalize: false,
        sname: None,
        etypes: None,
        ticket: AsTicketOpts::default(),
    }
}

/// An armor ticket for the user, from a password exchange.
fn armor(profile: &krb5_config::Krb5Conf, kdc: &KdcAddr) -> FastArmor {
    let plain =
        as_exchange(&request(profile, kdc, None)).expect("password AS for the armor ticket");
    FastArmor {
        ticket: plain.ticket,
        session: plain.session_key,
        crealm: plain.crealm,
        cname: plain.cname,
    }
}

/// A login that asks for the password through `ui`.
fn login(
    profile: &krb5_config::Krb5Conf,
    kdc: &KdcAddr,
    armor: Option<&FastArmor>,
    ui: &mut Ui,
) -> Result<AsOutcome, Error> {
    let mut req = request(profile, kdc, armor);
    req.password = b"";
    as_exchange_interactive(&req, ui, false)
}

fn is_cant_read(e: &Error) -> bool {
    matches!(e, Error::PreauthFailed(inner) if inner.to_string() == "Cannot read password")
}

#[test]
fn spake_and_encrypted_challenge_each_read_the_password_under_fast() {
    let profile = krb5_config::isolated_profile();
    let kdc = kdc(Spake::Challenge);
    let armor = armor(&profile, &kdc);
    let mut ui = Ui::new(&[Read::Eof, Read::Eof]);
    let e = login(&profile, &kdc, Some(&armor), &mut ui).expect_err("no password can be read");
    assert_eq!(ui.passwords, 2, "SPAKE asked, then encrypted challenge");
    assert!(is_cant_read(&e), "{e}");
}

#[test]
fn a_failed_read_leaves_the_next_mechanism_to_ask_again_under_fast() {
    let profile = krb5_config::isolated_profile();
    let kdc = kdc(Spake::Challenge);
    let armor = armor(&profile, &kdc);
    let mut ui = Ui::new(&[Read::Eof, RIGHT]);
    let out = login(&profile, &kdc, Some(&armor), &mut ui)
        .expect("encrypted challenge reads the password");
    assert_eq!(out.pa_type, Some(pa::ENCRYPTED_CHALLENGE));
    assert_eq!(ui.passwords, 2);
}

#[test]
fn a_support_first_kdc_reads_after_the_challenge_and_encrypted_challenge_reads_again() {
    let profile = krb5_config::isolated_profile();
    let kdc = kdc(Spake::Support);
    let armor = armor(&profile, &kdc);
    let mut ui = Ui::new(&[Read::Eof, Read::Eof]);
    let e = login(&profile, &kdc, Some(&armor), &mut ui).expect_err("no password can be read");
    assert_eq!(ui.passwords, 2);
    assert!(is_cant_read(&e), "{e}");
    let mut ui = Ui::new(&[Read::Eof, RIGHT]);
    let out = login(&profile, &kdc, Some(&armor), &mut ui)
        .expect("encrypted challenge reads the password");
    assert_eq!(out.pa_type, Some(pa::ENCRYPTED_CHALLENGE));
    assert_eq!(ui.passwords, 2);
}

#[test]
fn spake_and_encrypted_timestamp_each_read_the_password_without_fast() {
    let profile = krb5_config::isolated_profile();
    let kdc = kdc(Spake::Challenge);
    let mut ui = Ui::new(&[Read::Eof, Read::Eof]);
    let e = login(&profile, &kdc, None, &mut ui).expect_err("no password can be read");
    assert_eq!(ui.passwords, 2, "SPAKE asked, then encrypted timestamp");
    assert!(is_cant_read(&e), "{e}");
    let mut ui = Ui::new(&[Read::Eof, RIGHT]);
    let out = login(&profile, &kdc, None, &mut ui).expect("encrypted timestamp reads the password");
    assert_eq!(out.pa_type, Some(pa::ENC_TIMESTAMP));
    assert_eq!(ui.passwords, 2);
}

#[test]
fn a_wrong_password_after_the_response_ends_the_exchange() {
    // SPAKE answers with what was read and allows no fallback: the refusal is the error, and
    // encrypted challenge never asks.
    let profile = krb5_config::isolated_profile();
    let kdc = kdc(Spake::Challenge);
    let armor = armor(&profile, &kdc);
    for armor in [Some(&armor), None] {
        let mut ui = Ui::new(&[Read::Text(b"wrongpw"), RIGHT]);
        let e = login(&profile, &kdc, armor, &mut ui).expect_err("a wrong password");
        assert!(
            matches!(e, Error::KrbError { code, .. } if code == err::PREAUTH_FAILED),
            "{e}"
        );
        assert_eq!(ui.passwords, 1);
    }
}

#[test]
fn an_interrupt_ends_the_exchange_at_once() {
    let profile = krb5_config::isolated_profile();
    let kdc = kdc(Spake::Challenge);
    let armor = armor(&profile, &kdc);
    for armor in [Some(&armor), None] {
        let mut ui = Ui::new(&[Read::Interrupt, RIGHT]);
        let e = login(&profile, &kdc, armor, &mut ui).expect_err("interrupted");
        assert!(
            matches!(&e, Error::File(io) if io.kind() == ErrorKind::Interrupted),
            "{e}"
        );
        assert_eq!(ui.passwords, 1, "no other mechanism asks");
        // An interrupt after a failed read ends it too.
        let mut ui = Ui::new(&[Read::Eof, Read::Interrupt, RIGHT]);
        let e = login(&profile, &kdc, armor, &mut ui).expect_err("interrupted");
        assert!(
            matches!(&e, Error::File(io) if io.kind() == ErrorKind::Interrupted),
            "{e}"
        );
        assert_eq!(ui.passwords, 2);
    }
}

#[test]
fn a_refused_support_message_is_the_error_when_the_next_read_fails() {
    // The client's edwards25519 is not the KDC's P-256: the support message is refused, and
    // MIT keeps that refusal as the error when the mechanism after it fails too.
    let profile = krb5_config::isolated_profile();
    let kdc = kdc(Spake::Refuses);
    let armor = armor(&profile, &kdc);
    for armor in [Some(&armor), None] {
        let mut ui = Ui::new(&[Read::Eof]);
        let e = login(&profile, &kdc, armor, &mut ui).expect_err("no password can be read");
        assert!(
            matches!(e, Error::KrbError { code, .. } if code == err::PREAUTH_FAILED),
            "{e}"
        );
        assert_eq!(ui.passwords, 1);
    }
}

/// The KDC's PA-SPAKE challenge with its public value replaced by one that is no point of the
/// group (edwards25519: y = 2).
fn challenge_with_a_bad_point(reply: Vec<u8>) -> Vec<u8> {
    let Ok(mut e) = decode::<KrbError>(&reply) else {
        return reply;
    };
    let Some(e_data) = e.e_data.as_ref() else {
        return reply;
    };
    let mut method: MethodData = decode(e_data.as_ref()).unwrap();
    for p in &mut method {
        if p.padata_type != pa::SPAKE || p.padata_value.as_ref().is_empty() {
            continue;
        }
        if let Ok(PaSpake::Challenge(mut c)) = decode::<PaSpake>(p.padata_value.as_ref()) {
            let mut bad = vec![0u8; 32];
            bad[0] = 2;
            c.pubkey = bad.into();
            *p = PaData {
                padata_type: pa::SPAKE,
                padata_value: encode(&PaSpake::Challenge(c)).unwrap().into(),
            };
        }
    }
    e.e_data = Some(encode(&method).unwrap().into());
    encode(&e).unwrap()
}

#[test]
fn a_password_that_was_read_is_kept_for_the_next_mechanism() {
    // SPAKE reads the password and fails on the challenge's public value before it answers
    // (MIT `group_result`, EINVAL); encrypted timestamp then uses what was read.
    let profile = krb5_config::isolated_profile();
    let kdc = kdc_rewriting(Spake::Challenge, challenge_with_a_bad_point);
    let mut ui = Ui::new(&[RIGHT]);
    let out =
        login(&profile, &kdc, None, &mut ui).expect("encrypted timestamp reuses the password");
    assert_eq!(out.pa_type, Some(pa::ENC_TIMESTAMP));
    assert_eq!(ui.passwords, 1, "the second mechanism did not ask");
    // A wrong one is kept too; the KDC's refusal ends it, and a later line would not be read.
    let mut ui = Ui::new(&[Read::Text(b"wrongpw"), RIGHT]);
    let e = login(&profile, &kdc, None, &mut ui).expect_err("a wrong password");
    assert!(
        matches!(e, Error::KrbError { code, .. } if code == err::PREAUTH_FAILED),
        "{e}"
    );
    assert_eq!(ui.passwords, 1);
}

/// This test process's client configuration: `body` as krb5.conf.
fn client_conf(body: &str) -> krb5_config::Krb5Conf {
    krb5_config::Krb5Conf::parse(body).unwrap()
}

/// `[plugins] clpreauth` without `module`: the client has no such mechanism.
fn without(module: &str) -> String {
    format!("[plugins]\n    clpreauth = {{\n        disable = {module}\n    }}\n")
}

fn passwords_asked(calls: &Calls) -> Vec<Vec<String>> {
    calls.lock().unwrap().clone()
}

// The responder's password question, settled live on kerber-rust-mit-kdc:1.22.2 with the libkrb5 responder client.
// MIT `fill_response_items` (`lib/krb5/krb/preauth2.c:937-965`): every module with a padata prepares, and the responder is called when one asked.
// MIT `spake_prep_questions` (`plugins/preauth/spake/spake_client.c:119-141`): SPAKE asks `password` for a challenge it can answer, and nothing for a support message or any other.

#[test]
fn spake_alone_asks_the_responder_for_the_password_under_fast() {
    let kdc = kdc(Spake::Challenge);
    let armor = armor(&krb5_config::isolated_profile(), &kdc);
    let profile = client_conf(&without("encrypted_challenge"));
    let (mut ui, calls) = Ui::answering();
    let out =
        login(&profile, &kdc, Some(&armor), &mut ui).expect("SPAKE takes the responder's answer");
    assert_eq!(out.pa_type, Some(pa::SPAKE));
    assert_eq!(passwords_asked(&calls), [["password"]]);
    assert_eq!(ui.passwords, 0, "the answer is the password: no prompt");
}

#[test]
fn a_support_message_asks_nothing_and_the_challenge_that_follows_asks_once() {
    let kdc = kdc(Spake::Support);
    let armor = armor(&krb5_config::isolated_profile(), &kdc);
    let profile = client_conf(&without("encrypted_challenge"));
    let (mut ui, calls) = Ui::answering();
    let out =
        login(&profile, &kdc, Some(&armor), &mut ui).expect("SPAKE takes the responder's answer");
    assert_eq!(out.pa_type, Some(pa::SPAKE));
    assert_eq!(
        passwords_asked(&calls),
        [["password"]],
        "the hint's empty PA-SPAKE asks nothing; the challenge in the 91 asks"
    );
    assert_eq!(ui.passwords, 0);
}

#[test]
fn a_challenge_in_a_group_the_client_does_not_permit_asks_nothing() {
    let kdc = kdc(Spake::Challenge);
    let armor = armor(&krb5_config::isolated_profile(), &kdc);
    let profile = client_conf(&format!(
        "[libdefaults]\n    spake_preauth_groups = P-256\n{}",
        without("encrypted_challenge")
    ));
    let (mut ui, calls) = Ui::answering();
    let e =
        login(&profile, &kdc, Some(&armor), &mut ui).expect_err("no mechanism the KDC would take");
    assert!(
        matches!(e, Error::KrbError { code, .. } if code == err::PREAUTH_FAILED),
        "{e}"
    );
    assert!(passwords_asked(&calls).is_empty(), "no question, no call");
}

#[test]
fn a_responder_that_answers_nothing_leaves_the_prompt_to_ask() {
    let kdc = kdc(Spake::Challenge);
    let armor = armor(&krb5_config::isolated_profile(), &kdc);
    let profile = client_conf(&without("encrypted_challenge"));
    let (mut ui, calls) = Ui::listening();
    ui.reads.push_back(RIGHT);
    let out = login(&profile, &kdc, Some(&armor), &mut ui).expect("SPAKE prompts");
    assert_eq!(out.pa_type, Some(pa::SPAKE));
    assert_eq!(passwords_asked(&calls), [["password"]]);
    assert_eq!(ui.passwords, 1);
}

#[test]
fn spake_and_encrypted_challenge_put_the_password_question_once() {
    let profile = krb5_config::isolated_profile();
    let kdc = kdc(Spake::Challenge);
    let armor = armor(&profile, &kdc);
    let (mut ui, calls) = Ui::answering();
    let out = login(&profile, &kdc, Some(&armor), &mut ui).expect("SPAKE takes the answer");
    assert_eq!(out.pa_type, Some(pa::SPAKE));
    assert_eq!(passwords_asked(&calls), [["password"]]);
}

#[test]
fn without_fast_spake_asks_the_responder_for_the_password() {
    let kdc = kdc(Spake::Challenge);
    let profile = client_conf(&without("encrypted_timestamp"));
    let (mut ui, calls) = Ui::answering();
    let out = login(&profile, &kdc, None, &mut ui).expect("SPAKE takes the responder's answer");
    assert_eq!(out.pa_type, Some(pa::SPAKE));
    assert_eq!(passwords_asked(&calls), [["password"]]);
    assert_eq!(ui.passwords, 0);
}

#[test]
fn without_fast_encrypted_timestamp_asks_the_responder_for_the_password() {
    let kdc = kdc(Spake::Challenge);
    let profile = client_conf(&without("spake"));
    let (mut ui, calls) = Ui::answering();
    let out = login(&profile, &kdc, None, &mut ui).expect("encrypted timestamp takes the answer");
    assert_eq!(out.pa_type, Some(pa::ENC_TIMESTAMP));
    assert_eq!(passwords_asked(&calls), [["password"]]);
    assert_eq!(ui.passwords, 0);
}

#[test]
fn a_password_that_a_module_holds_is_not_asked_for_again_in_the_next_walk() {
    // Encrypted timestamp asks at the hint, SPAKE at the challenge; SPAKE gets the answer and fails
    // on the challenge's public value, and the new walk finds the password held: two calls, not three.
    let profile = krb5_config::isolated_profile();
    let kdc = kdc_rewriting(Spake::Support, challenge_with_a_bad_point);
    let (mut ui, calls) = Ui::answering();
    let out =
        login(&profile, &kdc, None, &mut ui).expect("encrypted timestamp uses the held password");
    assert_eq!(out.pa_type, Some(pa::ENC_TIMESTAMP));
    assert_eq!(passwords_asked(&calls), [["password"], ["password"]]);
    assert_eq!(ui.passwords, 0);
}

// With no prompter, no password from the caller and no answer, the key cannot be got. Settled live
// on kerber-rust-mit-kdc:1.22.2 with a libkrb5 client that passes no password and no prompter.
// MIT `krb5_get_as_key_password` (`lib/krb5/krb/gic_pwd.c:70-72`): `EIO` once the responder has no answer either, and the empty password is no password to try.

#[test]
fn with_no_prompter_and_no_password_every_mechanism_fails_with_eio_and_nothing_is_answered() {
    let profile = krb5_config::isolated_profile();
    let (kdc, seen) = kdc_counting(store(Spake::Challenge));
    let mut req = request(&profile, &kdc, None);
    req.password = b"";
    let e = as_exchange(&req).expect_err("there is no password to make a key from");
    assert!(
        matches!(&e, Error::PreauthFailed(inner) if inner.to_string() == "Input/output error"),
        "SPAKE and then encrypted timestamp fail with EIO, the first failure is the error: {e}"
    );
    assert_eq!(
        seen.load(Ordering::SeqCst),
        1,
        "the hint only: no module answered with a key made from the empty password"
    );
}

#[test]
fn a_refused_support_message_stays_the_error_when_the_next_mechanism_has_no_password() {
    // SPAKE's support message needs no key and the KDC refuses it with PREAUTH_FAILED; encrypted
    // timestamp then has no password, fails with EIO, and the refusal is what is reported.
    let profile = krb5_config::isolated_profile();
    let (kdc, seen) = kdc_counting(store(Spake::Refuses));
    let mut req = request(&profile, &kdc, None);
    req.password = b"";
    let e = as_exchange(&req).expect_err("nothing can answer");
    assert!(
        matches!(&e, Error::KrbError { code, .. } if *code == err::PREAUTH_FAILED),
        "{e}"
    );
    assert_eq!(
        seen.load(Ordering::SeqCst),
        2,
        "the hint and the support message, and no encrypted timestamp"
    );
}

#[test]
fn a_reply_that_needs_a_key_and_has_no_password_is_eio_not_a_guess_at_the_empty_password() {
    let profile = krb5_config::isolated_profile();
    let (kdc, _) = kdc_counting(store_without_preauth(Spake::Challenge));
    let mut req = request(&profile, &kdc, None);
    req.password = b"";
    let e = as_exchange(&req).expect_err("the reply cannot be decrypted");
    assert_eq!(e.to_string(), "Input/output error", "{e:?}");
}

#[test]
fn a_reply_no_module_answered_asks_the_responder_for_the_password() {
    // MIT `decrypt_as_reply` (`lib/krb5/krb/get_in_tkt.c:96-111`): with a responder the password question is put before the key is got, whatever the mechanism.
    let profile = krb5_config::isolated_profile();
    let (kdc, _) = kdc_counting(store_without_preauth(Spake::Challenge));
    let (mut ui, calls) = Ui::answering();
    let mut req = request(&profile, &kdc, None);
    req.password = b"";
    as_exchange_interactive(&req, &mut ui, false).expect("the responder's answer is the password");
    assert_eq!(passwords_asked(&calls), [["password"]]);
    assert_eq!(ui.passwords, 0, "no prompt");
}

#[test]
fn a_fast_reply_no_module_answered_asks_the_responder_for_the_password() {
    let profile = krb5_config::isolated_profile();
    let (kdc, _) = kdc_counting(store_without_preauth(Spake::Challenge));
    let armor = armor(&profile, &kdc);
    let (mut ui, calls) = Ui::answering();
    let mut req = request(&profile, &kdc, Some(&armor));
    req.password = b"";
    as_exchange_interactive(&req, &mut ui, false).expect("the responder's answer is the password");
    assert_eq!(passwords_asked(&calls), [["password"]]);
    assert_eq!(ui.passwords, 0, "no prompt");
}

#[test]
fn a_responder_with_no_answer_leaves_the_reply_key_to_the_prompt() {
    let profile = krb5_config::isolated_profile();
    let (kdc, _) = kdc_counting(store_without_preauth(Spake::Challenge));
    let (mut ui, calls) = Ui::listening();
    ui.reads.push_back(RIGHT);
    let mut req = request(&profile, &kdc, None);
    req.password = b"";
    as_exchange_interactive(&req, &mut ui, false).expect("the prompt reads the password");
    assert_eq!(passwords_asked(&calls), [["password"]]);
    assert_eq!(ui.passwords, 1);
}
