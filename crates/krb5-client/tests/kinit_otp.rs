use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use krb5_crypto::SpakeGroup;
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented};
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
}

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
    finish_kinit(child)
}

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

fn finish_kinit(child: std::process::Child) -> Run {
    let out = child.wait_with_output().unwrap();
    Run {
        code: out.status.code(),
        stdout: without_test_hook_output(&String::from_utf8_lossy(&out.stdout)),
        stderr: without_test_hook_output(&String::from_utf8_lossy(&out.stderr)),
    }
}

fn without_test_hook_output(text: &str) -> String {
    text.split_inclusive('\n')
        .filter(|line| !line.starts_with("{\"timestamp\"") && !line.starts_with("ok tgt="))
        .collect()
}

#[derive(Clone, Copy)]
enum Spake {
    Challenge,
    Off,
}

fn spake_realm(spake: Spake, otp: bool, rewrite: Option<fn(Vec<u8>) -> Vec<u8>>) -> String {
    let _ = verifier();
    let (mut store, _) = bootstrap_documented().unwrap();
    store.policy.spake_preauth_groups = match spake {
        Spake::Challenge => vec![SpakeGroup::Edwards25519],
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

const PROMPT: &str = "Password for user@KERBER.TEST: \n";
const CANT_READ: &str =
    "kinit: Pre-authentication failed: Cannot read password while getting initial credentials\n";
const CANT_READ_CODE: &str = "-1765328254/Cannot read password";

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

// MIT encts_process; see docs/parity/b1-client-preauth.md

const ENCTS_OFF: &str = "Ignoring encrypted timestamp because it is disabled";
const ENCTS_OFF_RETURNED: &str = "Preauth module encrypted_timestamp (2) (real) returned: -1765328174/Encrypted timestamp is disabled";

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
