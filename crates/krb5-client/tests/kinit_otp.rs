//! red at tree bd74009e (kinit has no OTP prompts there: it asks for the password)
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
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    udp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let addr = udp.local_addr().unwrap();
    let store = Arc::new(store);
    let s_udp = store.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 16384];
        while let Ok((n, src)) = udp.recv_from(&mut buf) {
            if let Ok(reply) = krb5_kdc::handle_request(&*s_udp, &buf[..n]) {
                let _ = udp.send_to(&reply, src);
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
    let conf = dir.join("krb5.conf");
    std::fs::write(
        &conf,
        format!(
            "[libdefaults]\n    default_realm = {TEST_REALM}\n    dns_lookup_kdc = false\n    \
             dns_lookup_realm = false\n[realms]\n    {TEST_REALM} = {{\n        kdc = {kdc}\n    }}\n"
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_krb5-kinit"))
        .args(args)
        .env("KRB5_CONFIG", &conf)
        .env("KRB5_TRACE", dir.join("trace.log"))
        .env_remove("KRB5_PASSWORD")
        .env_remove("KRB5_NEW_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
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
    let kdc = otp_realm();
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
