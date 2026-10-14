//! red at tree bd74009e (kinit has no OTP prompts there: it asks for the password); the tests of
//! the password per mechanism (the EOF, refused-support, SIGINT and reuse tests, and the block
//! after `the_trace_has_mits_otp_lines_in_mits_order`) red at tree bb1a2afc (one password read,
//! whose failure ended the exchange)
//!
//! `kinit -T armor` against an `otp` principal: the prompt text, the OTP login, the ccache
//! config, and a wrong value being "Preauthentication failed" with no fallback to the password.
//! MIT `kinit_prompter` (`clients/kinit/kinit.c:622-635`): only a password prompt is noted, so an OTP prompt leaves `pwprompt` false.
//! MIT `k5_kinit` (`clients/kinit/kinit.c:785-793`): so a wrong value is "Preauthentication failed", not "Password incorrect".

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use krb5_crypto::SpakeGroup;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, TEST_USER_PASSWORD, bootstrap_documented};
use krb5_kdc::{OtpVerdict, OtpVerifier, OtpVerifyRequest, PrincipalStore, register_otp_verifier};
use krb5_testkit::scratch_dir;
use krb5_types::PrincipalName;

struct Code(Mutex<Vec<Vec<u8>>>);

impl OtpVerifier for Code {
    fn name(&self) -> &'static str {
        "kinittest"
    }

    fn verify(&self, r: &OtpVerifyRequest<'_>) -> OtpVerdict {
        self.0.lock().unwrap().push(r.otp_value.to_vec());
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
        let v = Arc::new(Code(Mutex::new(Vec::new())));
        register_otp_verifier(v.clone());
        v
    })
}

fn serve(store: PrincipalStore) -> String {
    serve_with(store, None)
}

/// [`serve`], with each reply passed through `rewrite` before the client sees it.
fn serve_with(store: PrincipalStore, rewrite: Option<fn(Vec<u8>) -> Vec<u8>>) -> String {
    let rewrite = rewrite.unwrap_or(|reply| reply);
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    udp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let addr = udp.local_addr().unwrap();
    let store = Arc::new(store);
    let s_udp = store.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 16384];
        while let Ok((n, src)) = udp.recv_from(&mut buf) {
            if let Ok(reply) = krb5_kdc::handle_request(&*s_udp, &buf[..n]) {
                let _ = udp.send_to(&rewrite(reply), src);
            }
        }
    });
    thread::spawn(move || {
        for conn in tcp.incoming() {
            let Ok(mut conn) = conn else { break };
            let store = store.clone();
            thread::spawn(move || {
                let mut len = [0u8; 4];
                if conn.read_exact(&mut len).is_err() {
                    return;
                }
                let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
                if conn.read_exact(&mut req).is_err() {
                    return;
                }
                if let Ok(reply) = krb5_kdc::handle_request(&*store, &req) {
                    let reply = rewrite(reply);
                    let n = u32::try_from(reply.len()).unwrap();
                    let _ = conn.write_all(&n.to_be_bytes());
                    let _ = conn.write_all(&reply);
                }
            });
        }
    });
    format!("127.0.0.1:{}", addr.port())
}

fn otp_realm() -> String {
    let _ = verifier();
    let (mut store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    store
        .set_string(&user, "otp", Some(r#"[{"type":"kinittest"}]"#))
        .unwrap();
    serve(store)
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    cache: Option<krb5_protocol::FileCcache>,
}

/// `krb5-kinit [args]` with `stdin`, in a scratch directory with a krb5.conf naming `kdc`.
fn kinit(kdc: &str, dir: &std::path::Path, args: &[&str], stdin: &str) -> Run {
    kinit_traced(kdc, dir, args, stdin, &dir.join("trace.log"))
}

/// [`kinit`] with `KRB5_TRACE` naming `trace`: a file, or `/dev/stdout` to see the trace lines
/// and the prompts in one stream.
fn kinit_traced(
    kdc: &str,
    dir: &std::path::Path,
    args: &[&str],
    stdin: &str,
    trace: &std::path::Path,
) -> Run {
    kinit_in(kdc, dir, args, stdin, trace, "")
}

/// [`kinit_traced`] with `realm_extra` lines in the realm's block of krb5.conf.
fn kinit_in(
    kdc: &str,
    dir: &std::path::Path,
    args: &[&str],
    stdin: &str,
    trace: &std::path::Path,
    realm_extra: &str,
) -> Run {
    let mut child = spawn_kinit(kdc, dir, args, trace, realm_extra);
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    finish_kinit(child, args)
}

/// `krb5-kinit [args]` started, its stdin a pipe the caller holds.
fn spawn_kinit(
    kdc: &str,
    dir: &std::path::Path,
    args: &[&str],
    trace: &std::path::Path,
    realm_extra: &str,
) -> std::process::Child {
    let conf = dir.join("krb5.conf");
    std::fs::write(
        &conf,
        format!(
            "[libdefaults]\n    default_realm = {TEST_REALM}\n    dns_lookup_kdc = false\n    \
             dns_lookup_realm = false\n[realms]\n    {TEST_REALM} = {{\n        kdc = {kdc}\n{realm_extra}    }}\n"
        ),
    )
    .unwrap();
    Command::new(env!("CARGO_BIN_EXE_krb5-kinit"))
        .args(args)
        .env("KRB5_CONFIG", &conf)
        .env("KRB5_TRACE", trace)
        .env_remove("KRB5_PASSWORD")
        .env_remove("KRB5_NEW_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// What a finished `krb5-kinit` left.
fn finish_kinit(child: std::process::Child, args: &[&str]) -> Run {
    let out = child.wait_with_output().unwrap();
    let cc = args
        .iter()
        .position(|a| *a == "-c")
        .map(|i| std::path::PathBuf::from(args[i + 1]));
    let cache = cc
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| krb5_protocol::FileCcache::parse(&b).ok());
    Run {
        code: out.status.code(),
        stdout: without_test_hook_output(&String::from_utf8_lossy(&out.stdout)),
        stderr: without_test_hook_output(&String::from_utf8_lossy(&out.stderr)),
        cache,
    }
}

/// A `test-hooks` build of kinit adds its own output: one JSON object per structured log line, and
/// an `ok tgt=` line on success. The shipped binary writes neither, so the helper drops them, and a
/// test compares what the prompts and the reply were.
fn without_test_hook_output(text: &str) -> String {
    text.split_inclusive('\n')
        .filter(|line| !line.starts_with("{\"timestamp\"") && !line.starts_with("ok tgt="))
        .collect()
}

/// The armor ccache: the user's own TGT from a password login.
fn armor(kdc: &str, dir: &std::path::Path) -> String {
    let path = dir.join("armor.cc");
    let r = kinit(
        kdc,
        dir,
        &[
            "-c",
            path.to_str().unwrap(),
            &format!("{TEST_USER}@{TEST_REALM}"),
        ],
        &format!("{TEST_USER_PASSWORD_STR}\n"),
    );
    assert_eq!(r.code, Some(0), "armor login: {} {}", r.stdout, r.stderr);
    path.to_str().unwrap().to_owned()
}

const TEST_USER_PASSWORD_STR: &str = "userpassword";

fn config_of(cache: &krb5_protocol::FileCcache, key: &str) -> Option<String> {
    let tgs = format!("krbtgt/{TEST_REALM}@{TEST_REALM}");
    cache
        .get_config(Some(&tgs), key)
        .map(|v| String::from_utf8_lossy(v).into_owned())
}

#[test]
fn an_otp_login_prompts_once_and_records_pa_type_141() {
    assert_eq!(TEST_USER_PASSWORD, TEST_USER_PASSWORD_STR.as_bytes());
    let kdc = otp_realm();
    let dir = scratch_dir("kinit-otp-ok");
    let armor = armor(&kdc, &dir);
    let out = dir.join("out.cc");
    let r = kinit(
        &kdc,
        &dir,
        &[
            "-T",
            &armor,
            "-c",
            out.to_str().unwrap(),
            &format!("{TEST_USER}@{TEST_REALM}"),
        ],
        "123456\n",
    );
    assert_eq!(r.code, Some(0), "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, "Enter OTP Token Value: \n");
    assert_eq!(r.stderr, "");
    let cache = r.cache.expect("ccache");
    assert_eq!(config_of(&cache, "pa_type").as_deref(), Some("141"));
    assert_eq!(
        config_of(&cache, "pa_config_data"),
        None,
        "a DEFAULT token records none"
    );
    assert_eq!(config_of(&cache, "fast_avail").as_deref(), Some("yes"));
}

#[test]
fn a_wrong_value_is_preauthentication_failed_not_password_incorrect() {
    let kdc = otp_realm();
    let dir = scratch_dir("kinit-otp-bad");
    let armor = armor(&kdc, &dir);
    let out = dir.join("out.cc");
    let r = kinit(
        &kdc,
        &dir,
        &[
            "-T",
            &armor,
            "-c",
            out.to_str().unwrap(),
            &format!("{TEST_USER}@{TEST_REALM}"),
        ],
        "000000\nuserpassword\n",
    );
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    assert_eq!(
        r.stdout, "Enter OTP Token Value: \n",
        "the password is never asked"
    );
    assert!(
        r.stderr
            .ends_with("kinit: Preauthentication failed while getting initial credentials\n"),
        "{}",
        r.stderr
    );
    assert!(!r.stderr.contains("Password incorrect"));
    assert!(r.cache.is_none(), "no ccache is written");
}

#[test]
fn eof_at_the_otp_prompt_is_cannot_read_password_after_the_next_mechanism_fails_too() {
    // A KDC with no SPAKE: the hint is OTP and encrypted challenge, as the lab's scratch realm.
    let kdc = spake_realm(Spake::Off, true, None);
    let dir = scratch_dir("kinit-otp-eof");
    let armor = armor(&kdc, &dir);
    let out = dir.join("out.cc");
    let r = kinit(
        &kdc,
        &dir,
        &[
            "-T",
            &armor,
            "-c",
            out.to_str().unwrap(),
            &format!("{TEST_USER}@{TEST_REALM}"),
        ],
        "",
    );
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    assert_eq!(
        r.stdout,
        "Enter OTP Token Value: \nPassword for user@KERBER.TEST: \n"
    );
    assert!(
        r.stderr.ends_with(
            "kinit: Pre-authentication failed: Cannot read password while getting initial credentials\n"
        ),
        "{}",
        r.stderr
    );
    // MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:705-713`): the module's failure is traced with its code and message, and the next mechanism runs.
    let trace = std::fs::read_to_string(dir.join("trace.log")).unwrap();
    assert!(
        trace
            .contains("Preauth module otp (141) (real) returned: -1765328254/Cannot read password"),
        "{trace}"
    );
    // The next mechanism's failed read is traced under its name too (settle Pe1/Pa9).
    assert!(
        trace.contains(
            "Preauth module encrypted_challenge (138) (real) returned: -1765328254/Cannot read password"
        ),
        "{trace}"
    );
}

#[test]
fn a_refused_support_message_is_the_error_when_the_password_then_cannot_be_read() {
    // The default test KDC permits only P-256 and the client's group is edwards25519: SPAKE's
    // support message is refused with PREAUTH_FAILED, the OTP prompt and the password prompt fail
    // at EOF, and the refusal, which MIT saved first, is the error: "Password incorrect" after a
    // password prompt. Settled live on kerber-rust-mit-kdc:1.22.2.
    let kdc = otp_realm();
    let dir = scratch_dir("kinit-otp-eof-refused");
    let armor = armor(&kdc, &dir);
    let _ = std::fs::remove_file(dir.join("trace.log"));
    let out = dir.join("out.cc");
    let r = kinit(
        &kdc,
        &dir,
        &[
            "-T",
            &armor,
            "-c",
            out.to_str().unwrap(),
            &format!("{TEST_USER}@{TEST_REALM}"),
        ],
        "",
    );
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, format!("{OTP_PROMPT}{PROMPT}"));
    assert!(
        r.stderr
            .ends_with("kinit: Password incorrect while getting initial credentials\n"),
        "{}",
        r.stderr
    );
    let trace = trace_lines(&std::fs::read_to_string(dir.join("trace.log")).unwrap());
    assert_eq!(
        count(&trace, "Preauthenticating using KDC method data"),
        2,
        "{trace:#?}"
    );
    let support = at(&trace, "Sending SPAKE support message");
    let refused = at(
        &trace,
        "Received error from KDC: -1765328360/Preauthentication failed",
    );
    let ec = at(
        &trace,
        &format!("Preauth module encrypted_challenge (138) (real) returned: {CANT_READ_CODE}"),
    );
    assert!(support < refused && refused < ec, "{trace:#?}");
}

#[test]
fn without_fast_a_refused_support_message_is_the_error_when_the_password_then_cannot_be_read() {
    // The same refusal with no armor: the encrypted timestamp that follows cannot read the
    // password either, and the refusal is the error (settled live on kerber-rust-mit-kdc:1.22.2).
    let kdc = otp_realm();
    let (r, trace) = plain_login(&kdc, "kinit-pw-refused-plain", "");
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, PROMPT);
    assert!(
        r.stderr
            .ends_with("kinit: Password incorrect while getting initial credentials\n"),
        "{}",
        r.stderr
    );
    let refused = at(
        &trace,
        "Received error from KDC: -1765328360/Preauthentication failed",
    );
    let encts = at(
        &trace,
        &format!("Preauth module encrypted_timestamp (2) (real) returned: {CANT_READ_CODE}"),
    );
    assert!(refused < encts, "{trace:#?}");
}

#[test]
fn the_trace_has_mits_otp_lines_in_mits_order() {
    let kdc = otp_realm();
    let dir = scratch_dir("kinit-otp-trace");
    let armor = armor(&kdc, &dir);
    let _ = std::fs::remove_file(dir.join("trace.log"));
    let out = dir.join("out.cc");
    let r = kinit(
        &kdc,
        &dir,
        &[
            "-T",
            &armor,
            "-c",
            out.to_str().unwrap(),
            &format!("{TEST_USER}@{TEST_REALM}"),
        ],
        "123456\n",
    );
    assert_eq!(r.code, Some(0), "{} {}", r.stdout, r.stderr);
    let trace = std::fs::read_to_string(dir.join("trace.log")).unwrap();
    let lines: Vec<&str> = trace
        .lines()
        .map(|l| l.split_once(": ").map_or(l, |(_, t)| t))
        .collect();
    let at = |needle: &str| {
        lines
            .iter()
            .position(|l| l.starts_with(needle))
            .unwrap_or_else(|| panic!("{needle}: {lines:#?}"))
    };
    let a = at(
        "Processing preauth types: PA-FX-FAST (136), PA-ETYPE-INFO2 (19), PA-OTP-CHALLENGE (141)",
    );
    assert!(a < at("Preauth module otp (141) (real) returned: 0/Success"));
    assert_eq!(
        lines[at("Preauth module otp (141) (real) returned: 0/Success") + 1],
        "Produced preauth for next request: PA-FX-COOKIE (133), PA-OTP-REQUEST (142)"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("AS key determined by preauth: aes256-cts/"))
    );
}

// ---------------------------------------------------------------------------------------------
// The password per mechanism, settled live on kerber-rust-mit-kdc:1.22.2: FAST and plain logins at EOF,
// a wrong password and a reused one, SIGINT.
// MIT `get_as_key` (`lib/krb5/krb/preauth2.c:438-457`): `gak_fct` runs for every module that wants the AS key and finds none held.
// MIT `krb5_get_as_key_password` (`lib/krb5/krb/gic_pwd.c:9-110`): a prompt that fails leaves nothing held, so the next such module asks again, and a password that was read is kept.
// ---------------------------------------------------------------------------------------------

/// How the test KDC offers SPAKE.
#[derive(Clone, Copy)]
enum Spake {
    /// edwards25519 is permitted and is the optimistic challenge group: the challenge rides in the
    /// hint, as on the lab's KDC.
    Challenge,
    /// edwards25519 is permitted with no optimistic challenge: the client sends support first.
    Support,
    /// No group: no PA-SPAKE in the hint.
    Off,
}

/// A served realm whose KDC offers SPAKE as `spake`, with the `otp` attribute on the user if `otp`,
/// and every reply passed through `rewrite`.
fn spake_realm(spake: Spake, otp: bool, rewrite: Option<fn(Vec<u8>) -> Vec<u8>>) -> String {
    let _ = verifier();
    let (mut store, _) = bootstrap_documented().unwrap();
    store.policy.spake_preauth_groups = match spake {
        Spake::Challenge | Spake::Support => vec![SpakeGroup::Edwards25519],
        Spake::Off => Vec::new(),
    };
    if matches!(spake, Spake::Challenge) {
        store.policy.spake_preauth_kdc_challenge = Some("edwards25519".to_owned());
    }
    if otp {
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        store
            .set_string(&user, "otp", Some(r#"[{"type":"kinittest"}]"#))
            .unwrap();
    }
    serve_with(store, rewrite)
}

const OTP_PROMPT: &str = "Enter OTP Token Value: \n";
/// The password prompt, and the newline MIT's prompter prints when the read fails.
const PROMPT: &str = "Password for user@KERBER.TEST: \n";
const CANT_READ: &str =
    "kinit: Pre-authentication failed: Cannot read password while getting initial credentials\n";
const CANT_READ_CODE: &str = "-1765328254/Cannot read password";

/// A trace as MIT prints it, one entry per line without the `[pid] time: ` prefix; a password
/// prompt printed into the same stream is `PROMPT`.
fn trace_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| {
            if l.starts_with("Password for ") {
                "PROMPT".to_owned()
            } else {
                l.split_once(": ").map_or(l, |(_, t)| t).to_owned()
            }
        })
        .collect()
}

/// The position of the one line that starts with `needle`.
fn at(lines: &[String], needle: &str) -> usize {
    let hits: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.starts_with(needle))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(hits.len(), 1, "one line starts {needle:?}: {lines:#?}");
    hits[0]
}

fn count(lines: &[String], needle: &str) -> usize {
    lines.iter().filter(|l| l.starts_with(needle)).count()
}

/// A FAST login of the user, kinit's stdin `stdin`, in a fresh scratch directory; the trace of the
/// login only.
fn fast_login(kdc: &str, name: &str, stdin: &str) -> (Run, Vec<String>) {
    let dir = scratch_dir(name);
    let armor = armor(kdc, &dir);
    let _ = std::fs::remove_file(dir.join("trace.log"));
    let out = dir.join("out.cc");
    let r = kinit(
        kdc,
        &dir,
        &[
            "-T",
            &armor,
            "-c",
            out.to_str().unwrap(),
            &format!("{TEST_USER}@{TEST_REALM}"),
        ],
        stdin,
    );
    let trace = std::fs::read_to_string(dir.join("trace.log")).unwrap_or_default();
    (r, trace_lines(&trace))
}

/// A login with no armor, as [`fast_login`].
fn plain_login(kdc: &str, name: &str, stdin: &str) -> (Run, Vec<String>) {
    let dir = scratch_dir(name);
    let out = dir.join("out.cc");
    let r = kinit(
        kdc,
        &dir,
        &[
            "-c",
            out.to_str().unwrap(),
            &format!("{TEST_USER}@{TEST_REALM}"),
        ],
        stdin,
    );
    let trace = std::fs::read_to_string(dir.join("trace.log")).unwrap_or_default();
    (r, trace_lines(&trace))
}

#[test]
fn each_mechanism_that_needs_the_password_asks_for_it() {
    // OTP, SPAKE and encrypted challenge are offered; the OTP prompt, then the password prompt of
    // SPAKE (after it traced the challenge) and again that of encrypted challenge, all at EOF.
    let kdc = spake_realm(Spake::Challenge, true, None);
    let (r, trace) = fast_login(&kdc, "kinit-pw-otp-spake-ec", "");
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, format!("{OTP_PROMPT}{PROMPT}{PROMPT}"));
    assert!(r.stderr.ends_with(CANT_READ), "{}", r.stderr);
    let otp = at(
        &trace,
        &format!("Preauth module otp (141) (real) returned: {CANT_READ_CODE}"),
    );
    let challenge = at(&trace, "SPAKE challenge received with group 1, pubkey ");
    let spake = at(
        &trace,
        &format!("Preauth module spake (151) (real) returned: {CANT_READ_CODE}"),
    );
    let ec = at(
        &trace,
        &format!("Preauth module encrypted_challenge (138) (real) returned: {CANT_READ_CODE}"),
    );
    assert!(
        otp < challenge && challenge < spake && spake < ec,
        "{trace:#?}"
    );
    assert!(r.cache.is_none(), "no ccache is written");
}

#[test]
fn spake_and_encrypted_challenge_each_ask_under_fast() {
    let kdc = spake_realm(Spake::Challenge, false, None);
    let (r, trace) = fast_login(&kdc, "kinit-pw-spake-ec", "");
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, format!("{PROMPT}{PROMPT}"));
    assert!(r.stderr.ends_with(CANT_READ), "{}", r.stderr);
    let spake = at(
        &trace,
        &format!("Preauth module spake (151) (real) returned: {CANT_READ_CODE}"),
    );
    let ec = at(
        &trace,
        &format!("Preauth module encrypted_challenge (138) (real) returned: {CANT_READ_CODE}"),
    );
    assert!(spake < ec, "{trace:#?}");
    // One walk over the hint: the second mechanism runs with no new hint between.
    assert_eq!(
        count(&trace, "Preauthenticating using KDC method data"),
        1,
        "{trace:#?}"
    );
}

#[test]
fn spake_and_encrypted_timestamp_each_ask_without_fast() {
    let kdc = spake_realm(Spake::Challenge, false, None);
    let (r, trace) = plain_login(&kdc, "kinit-pw-spake-encts", "");
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, format!("{PROMPT}{PROMPT}"));
    assert!(r.stderr.ends_with(CANT_READ), "{}", r.stderr);
    let spake = at(
        &trace,
        &format!("Preauth module spake (151) (real) returned: {CANT_READ_CODE}"),
    );
    let encts = at(
        &trace,
        &format!("Preauth module encrypted_timestamp (2) (real) returned: {CANT_READ_CODE}"),
    );
    assert!(spake < encts, "{trace:#?}");
}

#[test]
fn encrypted_timestamp_alone_traces_its_failed_read() {
    let kdc = spake_realm(Spake::Off, false, None);
    let (r, trace) = plain_login(&kdc, "kinit-pw-encts", "");
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, PROMPT);
    assert!(r.stderr.ends_with(CANT_READ), "{}", r.stderr);
    at(
        &trace,
        &format!("Preauth module encrypted_timestamp (2) (real) returned: {CANT_READ_CODE}"),
    );
}

#[test]
fn a_support_first_kdc_asks_after_the_challenge_and_walks_the_hint_again() {
    // The challenge answers the support message, so SPAKE's failure ends that stage and the
    // method data is walked again: its trace lines come twice.
    let kdc = spake_realm(Spake::Support, false, None);
    let (r, trace) = fast_login(&kdc, "kinit-pw-support-first", "");
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, format!("{PROMPT}{PROMPT}"));
    assert!(r.stderr.ends_with(CANT_READ), "{}", r.stderr);
    assert_eq!(
        count(&trace, "Preauthenticating using KDC method data"),
        2,
        "{trace:#?}"
    );
    let support = at(&trace, "Sending SPAKE support message");
    // The 91 that carries the challenge continues the chosen mechanism, and its padata is shown first.
    let more = at(&trace, "Continuing preauth mech PA-SPAKE (151)");
    let challenge = at(&trace, "SPAKE challenge received with group 1, pubkey ");
    let spake = at(
        &trace,
        &format!("Preauth module spake (151) (real) returned: {CANT_READ_CODE}"),
    );
    let ec = at(
        &trace,
        &format!("Preauth module encrypted_challenge (138) (real) returned: {CANT_READ_CODE}"),
    );
    assert!(
        support < more && more < challenge && challenge < spake && spake < ec,
        "{trace:#?}"
    );
    assert!(
        trace[more + 1].starts_with("Processing preauth types: PA-SPAKE (151)"),
        "{trace:#?}"
    );
}

#[test]
fn the_challenge_is_traced_before_the_prompt_and_each_failure_before_the_next_prompt() {
    // KRB5_TRACE on stdout puts the prompts and the trace lines in one stream, MIT's order:
    // the challenge, the prompt, the module's failure, the prompt, the module's failure.
    let kdc = spake_realm(Spake::Challenge, false, None);
    let dir = scratch_dir("kinit-pw-order");
    let armor = armor(&kdc, &dir);
    let out = dir.join("out.cc");
    let r = kinit_traced(
        &kdc,
        &dir,
        &[
            "-T",
            &armor,
            "-c",
            out.to_str().unwrap(),
            &format!("{TEST_USER}@{TEST_REALM}"),
        ],
        "",
        std::path::Path::new("/dev/stdout"),
    );
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    let lines = trace_lines(&r.stdout);
    let challenge = at(&lines, "SPAKE challenge received with group 1, pubkey ");
    let spake = at(
        &lines,
        &format!("Preauth module spake (151) (real) returned: {CANT_READ_CODE}"),
    );
    let ec = at(
        &lines,
        &format!("Preauth module encrypted_challenge (138) (real) returned: {CANT_READ_CODE}"),
    );
    assert_eq!(lines[challenge + 1], "PROMPT", "{lines:#?}");
    assert_eq!(lines[spake + 1], "PROMPT", "{lines:#?}");
    assert_eq!(lines[spake - 1], "PROMPT", "{lines:#?}");
    assert_eq!(ec, spake + 2, "{lines:#?}");
}

#[test]
fn a_wrong_password_after_the_response_ends_the_exchange() {
    // SPAKE answers with the wrong password and allows no fallback: one prompt, the KDC's refusal,
    // and the next stdin line is never read.
    let kdc = spake_realm(Spake::Challenge, false, None);
    let (r, trace) = fast_login(&kdc, "kinit-pw-wrong-fast", "wrongpw\nuserpassword\n");
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, PROMPT);
    assert!(
        r.stderr
            .ends_with("kinit: Password incorrect while getting initial credentials\n"),
        "{}",
        r.stderr
    );
    assert_eq!(
        count(&trace, "Preauth module encrypted_challenge"),
        0,
        "{trace:#?}"
    );
    let (r, _) = plain_login(&kdc, "kinit-pw-wrong-plain", "wrongpw\nuserpassword\n");
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, PROMPT);
    assert!(
        r.stderr
            .ends_with("kinit: Password incorrect while getting initial credentials\n"),
        "{}",
        r.stderr
    );
}

/// The KDC's PA-SPAKE challenge with its public value replaced by one that is no point of the
/// group (edwards25519: y = 2).
fn challenge_with_a_bad_point(reply: Vec<u8>) -> Vec<u8> {
    use krb5_asn1::{decode, encode};
    use krb5_types::spake::PaSpake;
    use krb5_types::{KrbError, MethodData, PaData, pa};
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
    // SPAKE reads the password and fails on the challenge's public value before it answers; the
    // encrypted timestamp that follows uses what was read and does not prompt again.
    let kdc = spake_realm(Spake::Challenge, false, Some(challenge_with_a_bad_point));
    let (r, trace) = plain_login(&kdc, "kinit-pw-kept", "userpassword\n");
    assert_eq!(r.code, Some(0), "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, PROMPT);
    at(
        &trace,
        "Preauth module spake (151) (real) returned: 22/Invalid argument",
    );
    at(
        &trace,
        "Preauth module encrypted_timestamp (2) (real) returned: 0/Success",
    );
    assert_eq!(
        config_of(&r.cache.expect("ccache"), "pa_type").as_deref(),
        Some("2")
    );
    // A wrong one is kept too: the refusal ends the exchange and the next line is never read.
    let (r, _) = plain_login(&kdc, "kinit-pw-kept-wrong", "wrongpw\nuserpassword\n");
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    assert!(
        r.stderr
            .ends_with("kinit: Password incorrect while getting initial credentials\n"),
        "{}",
        r.stderr
    );
}

/// `krb5-kinit` with its stdin held open until the password prompt shows, then `SIGINT`.
fn interrupted_login(kdc: &str, dir: &std::path::Path, args: &[&str]) -> (Run, Vec<String>) {
    let mut child = spawn_kinit(kdc, dir, args, &dir.join("trace.log"), "");
    let mut seen = Vec::new();
    {
        let stdout = child.stdout.as_mut().unwrap();
        let mut chunk = [0u8; 256];
        while !String::from_utf8_lossy(&seen).contains("Password for ") {
            let n = stdout.read(&mut chunk).unwrap();
            assert!(n > 0, "kinit ended before it asked for the password");
            seen.extend_from_slice(&chunk[..n]);
        }
    }
    // The prompter holds SIGINT off before it shows the prompt, so the signal waits for the read.
    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let mut r = finish_kinit(child, args);
    r.stdout = without_test_hook_output(&String::from_utf8_lossy(&seen)) + &r.stdout;
    let trace = std::fs::read_to_string(dir.join("trace.log")).unwrap_or_default();
    (r, trace_lines(&trace))
}

#[test]
fn an_interrupt_at_a_password_prompt_ends_the_exchange_at_once() {
    // MIT: KRB5_LIBOS_PWDINTR is traced under the module that asked, and no other mechanism runs;
    // the message is the code's own, not wrapped as a preauthentication failure.
    let kdc = spake_realm(Spake::Challenge, false, None);
    let dir = scratch_dir("kinit-pw-intr-fast");
    let armor = armor(&kdc, &dir);
    let _ = std::fs::remove_file(dir.join("trace.log"));
    let out = dir.join("out.cc");
    let (r, trace) = interrupted_login(
        &kdc,
        &dir,
        &[
            "-T",
            &armor,
            "-c",
            out.to_str().unwrap(),
            &format!("{TEST_USER}@{TEST_REALM}"),
        ],
    );
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, PROMPT);
    assert!(
        r.stderr
            .ends_with("kinit: Password read interrupted while getting initial credentials\n"),
        "{}",
        r.stderr
    );
    assert!(
        !r.stderr.contains("Pre-authentication failed"),
        "an interrupt is not wrapped: {}",
        r.stderr
    );
    at(
        &trace,
        "Preauth module spake (151) (real) returned: -1765328252/Password read interrupted",
    );
    assert_eq!(
        count(&trace, "Preauth module encrypted_challenge"),
        0,
        "{trace:#?}"
    );
    let dir = scratch_dir("kinit-pw-intr-plain");
    let out = dir.join("out.cc");
    let (r, trace) = interrupted_login(
        &kdc,
        &dir,
        &[
            "-c",
            out.to_str().unwrap(),
            &format!("{TEST_USER}@{TEST_REALM}"),
        ],
    );
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    assert!(
        r.stderr
            .ends_with("kinit: Password read interrupted while getting initial credentials\n"),
        "{}",
        r.stderr
    );
    assert!(
        !r.stderr.contains("Pre-authentication failed"),
        "an interrupt is not wrapped: {}",
        r.stderr
    );
    at(
        &trace,
        "Preauth module spake (151) (real) returned: -1765328252/Password read interrupted",
    );
    assert_eq!(
        count(&trace, "Preauth module encrypted_timestamp"),
        0,
        "{trace:#?}"
    );
}

/// `kinit_prompted` as the library runs it: the armor from a password login, and the library
/// reading the same krb5.conf as the binary does.
fn library_login(
    kdc: &str,
    name: &str,
    prompt: &mut dyn FnMut() -> Result<zeroize::Zeroizing<Vec<u8>>, krb5_client::errmsg::Krb5Error>,
    otp: Option<krb5_client::PreauthPrompter<'_>>,
) -> Result<krb5_client::KinitResult, Box<dyn std::error::Error + Send + Sync>> {
    let dir = scratch_dir(name);
    let armor = armor(kdc, &dir);
    krb5_config::isolate_test_krb5();
    krb5_config::set_test_krb5_paths(Some(vec![dir.join("krb5.conf")]));
    let port = kdc.rsplit(':').next().unwrap().parse().unwrap();
    let armor = krb5_config::CcSpec::File(std::path::PathBuf::from(armor));
    krb5_client::kinit_prompted(
        &krb5_protocol::KdcAddr {
            host: "127.0.0.1".into(),
            port,
        },
        &format!("{TEST_USER}@{TEST_REALM}"),
        prompt,
        &krb5_config::CcSpec::File(dir.join("out.cc")),
        krb5_client::KinitParams {
            armor_ccache: Some(&armor),
            preauth_prompter: otp,
            ..krb5_client::KinitParams::default()
        },
    )
}

#[test]
fn a_password_prompt_that_failed_does_not_fail_a_login_the_next_mechanism_answers() {
    // SPAKE's prompt fails and encrypted challenge's returns the password: the login is
    // the encrypted challenge's, not the failed prompt's error (settle Pa3).
    let kdc = spake_realm(Spake::Challenge, false, None);
    let mut calls = 0;
    let mut prompt = || {
        calls += 1;
        if calls == 1 {
            Err(krb5_client::errmsg::Krb5Error::new(
                krb5_client::errmsg::Code::Other,
                "Cannot read password",
            ))
        } else {
            Ok(zeroize::Zeroizing::new(TEST_USER_PASSWORD.to_vec()))
        }
    };
    let done = library_login(&kdc, "kinit-pw-lib-ec", &mut prompt, None).expect("login");
    assert_eq!(done.as_out.pa_type, Some(138));
    assert_eq!(calls, 2);
}

#[test]
fn an_otp_prompt_that_failed_does_not_fail_a_login_spake_answers() {
    // The OTP prompt fails at EOF, SPAKE reads the password and answers (settle Pe3, with SPAKE
    // taking the password that encrypted challenge took there).
    let kdc = spake_realm(Spake::Challenge, true, None);
    let otp_calls = std::cell::Cell::new(0);
    let otp_prompt = |_: &krb5_protocol::PreauthPrompt<'_>| {
        otp_calls.set(otp_calls.get() + 1);
        Err(krb5_cli::PromptError::CantRead)
    };
    let mut calls = 0;
    let mut prompt = || {
        calls += 1;
        Ok(zeroize::Zeroizing::new(TEST_USER_PASSWORD.to_vec()))
    };
    let done = library_login(
        &kdc,
        "kinit-pw-lib-otp",
        &mut prompt,
        Some(krb5_client::PreauthPrompter(&otp_prompt)),
    )
    .expect("login");
    assert_eq!(done.as_out.pa_type, Some(151));
    assert_eq!((otp_calls.get(), calls), (1, 1));
}

#[test]
fn the_first_failure_is_the_message_even_when_a_later_prompt_fails_differently() {
    // The OTP prompt fails, then both password prompts fail with another text: MIT keeps the
    // first failure of a real mechanism and reports it (settle Pe5).
    let kdc = spake_realm(Spake::Challenge, true, None);
    let otp_prompt = |_: &krb5_protocol::PreauthPrompt<'_>| Err(krb5_cli::PromptError::CantRead);
    let mut prompt = || {
        Err(krb5_client::errmsg::Krb5Error::new(
            krb5_client::errmsg::Code::Other,
            "Password mismatch",
        ))
    };
    let result = library_login(
        &kdc,
        "kinit-pw-lib-first",
        &mut prompt,
        Some(krb5_client::PreauthPrompter(&otp_prompt)),
    );
    let e = result.err().expect("nothing can be read");
    assert_eq!(
        e.to_string(),
        "Pre-authentication failed: Cannot read password"
    );
}

// Encrypted timestamp, which the realm disables (`disable_encrypted_timestamp = true`). It is a
// module like the others: it traces that it ignores the padata, fails with `KRB5_PREAUTH_FAILED`
// and its message, and the walk goes on; what the exchange reports is the first failure.
// MIT `encts_process` (`lib/krb5/krb/preauth_encts.c:68-73`): `TRACE_PREAUTH_ENC_TS_DISABLED`, then `KRB5_PREAUTH_FAILED` "Encrypted timestamp is disabled".
// MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:703-724`): the first failure of a real type is saved and reported wrapped.

const ENCTS_OFF: &str = "Ignoring encrypted timestamp because it is disabled";
const ENCTS_OFF_RETURNED: &str = "Preauth module encrypted_timestamp (2) (real) returned: -1765328174/Encrypted timestamp is disabled";

/// A login with no armor in a realm that disables encrypted timestamp.
fn disabled_login(kdc: &str, name: &str, stdin: &str) -> (Run, Vec<String>) {
    let dir = scratch_dir(name);
    let out = dir.join("out.cc");
    let r = kinit_in(
        kdc,
        &dir,
        &[
            "-c",
            out.to_str().unwrap(),
            &format!("{TEST_USER}@{TEST_REALM}"),
        ],
        stdin,
        &dir.join("trace.log"),
        "        disable_encrypted_timestamp = true\n",
    );
    let trace = std::fs::read_to_string(dir.join("trace.log")).unwrap_or_default();
    (r, trace_lines(&trace))
}

#[test]
fn a_disabled_encrypted_timestamp_is_traced_and_fails_its_module() {
    let kdc = spake_realm(Spake::Off, false, None);
    let (r, trace) = disabled_login(&kdc, "kinit-encts-off", "");
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, "", "a disabled module asks for no key");
    assert!(
        r.stderr.ends_with(
            "kinit: Pre-authentication failed: Encrypted timestamp is disabled while getting initial credentials\n"
        ),
        "{}",
        r.stderr
    );
    let ignoring = at(&trace, ENCTS_OFF);
    let returned = at(&trace, ENCTS_OFF_RETURNED);
    assert_eq!(returned, ignoring + 1, "{trace:#?}");
}

#[test]
fn the_first_failure_is_reported_when_encrypted_timestamp_is_disabled_after_it() {
    // SPAKE's prompt fails at EOF; the disabled module fails next. MIT keeps the first failure, so
    // the message is the read's, and the exchange is not a "Password incorrect".
    let kdc = spake_realm(Spake::Challenge, false, None);
    let (r, trace) = disabled_login(&kdc, "kinit-encts-off-after-spake", "");
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, PROMPT);
    assert!(r.stderr.ends_with(CANT_READ), "{}", r.stderr);
    let spake = at(
        &trace,
        &format!("Preauth module spake (151) (real) returned: {CANT_READ_CODE}"),
    );
    let ignoring = at(&trace, ENCTS_OFF);
    let returned = at(&trace, ENCTS_OFF_RETURNED);
    assert!(spake < ignoring && ignoring < returned, "{trace:#?}");
}

#[test]
fn a_refused_support_message_is_the_error_when_encrypted_timestamp_is_disabled() {
    // The default test KDC refuses the client's support message with PREAUTH_FAILED; the disabled
    // module fails after it and asked for no password, so the refusal is the error and no prompt shows.
    let kdc = otp_realm();
    let (r, trace) = disabled_login(&kdc, "kinit-encts-off-refused", "");
    assert_eq!(r.code, Some(1), "{} {}", r.stdout, r.stderr);
    assert_eq!(r.stdout, "");
    assert!(
        r.stderr
            .ends_with("kinit: Preauthentication failed while getting initial credentials\n"),
        "{}",
        r.stderr
    );
    let refused = at(
        &trace,
        "Received error from KDC: -1765328360/Preauthentication failed",
    );
    let returned = at(&trace, ENCTS_OFF_RETURNED);
    assert!(refused < returned, "{trace:#?}");
}

/// A realm whose user needs no preauth: the KDC answers the first request with the AS-REP.
fn no_preauth_realm() -> String {
    let (mut store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let attrs = store.get_name(&user).unwrap().attributes & !krb5_kdc::KDB_REQUIRES_PRE_AUTH;
    store
        .apply_admin_fields(
            &user,
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
    serve(store)
}

/// A login of the user with the trace on stdout, in a realm whose user needs no preauth; `fast`
/// adds the armor.
fn no_preauth_login(name: &str, fast: bool, stdin: &str) -> (Run, Vec<String>) {
    let kdc = no_preauth_realm();
    let dir = scratch_dir(name);
    let armor_cc = fast.then(|| armor(&kdc, &dir));
    let out = dir.join("out.cc");
    let who = format!("{TEST_USER}@{TEST_REALM}");
    let mut args = vec!["-c", out.to_str().unwrap()];
    if let Some(a) = &armor_cc {
        args.extend(["-T", a]);
    }
    args.push(&who);
    let r = kinit_traced(
        &kdc,
        &dir,
        &args,
        stdin,
        std::path::Path::new("/dev/stdout"),
    );
    let lines = trace_lines(&r.stdout);
    (r, lines)
}

#[test]
fn a_reply_no_module_answered_is_traced_before_its_key_is_asked_for() {
    // MIT `decrypt_as_reply` (`lib/krb5/krb/get_in_tkt.c:96-123`): the reply's padata is traced, then
    // "Getting AS key", and only then does `gak_fct` prompt; the read that fails is the error as it is.
    for fast in [false, true] {
        let (r, lines) = no_preauth_login("kinit-reply-key-order", fast, "");
        assert_eq!(r.code, Some(1), "{fast}: {} {}", r.stdout, r.stderr);
        let produced = at(&lines, "Produced preauth for next request: (empty)");
        let gak = at(&lines, "Getting AS key, salt ");
        assert_eq!(gak, produced + 1, "{fast}: {lines:#?}");
        assert_eq!(lines[gak + 1], "PROMPT", "{fast}: {lines:#?}");
        assert!(
            r.stderr
                .ends_with("kinit: Cannot read password while getting initial credentials\n"),
            "{fast}: {}",
            r.stderr
        );
    }
}
