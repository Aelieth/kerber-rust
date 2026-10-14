//! `kinit -k -t` with a keytab that cannot be read: the request is made, and the keytab fails where
//! a key is asked of it.
//! MIT `krb5_init_creds_set_keytab` (`lib/krb5/krb/gic_keytab.c:209-213`): a keytab whose entries cannot be listed is traced and is no error yet.
//! MIT `get_as_key_keytab` (`lib/krb5/krb/gic_keytab.c:68-71`): the lookup's error is the key callback's: a preauth module's failure, or the reply's decrypt.
//! Live oracle: MIT 1.22.2's kinit beside this one, a nonexistent, an empty, a bad-version and a
//! directory keytab, for a principal that does and one that does not require preauthentication.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented};
use krb5_kdc::{KDB_REQUIRES_PRE_AUTH, PrincipalStore};
use krb5_testkit::scratch_dir;
use krb5_types::PrincipalName;

/// Serve `store` on UDP and TCP at one ephemeral port; returns `host:port` and the count of
/// requests it has answered.
fn serve(store: PrincipalStore) -> (String, Arc<AtomicUsize>) {
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    udp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let addr = udp.local_addr().unwrap();
    let store = Arc::new(store);
    let asked = Arc::new(AtomicUsize::new(0));
    let (s_udp, c_udp) = (store.clone(), asked.clone());
    thread::spawn(move || {
        let mut buf = [0u8; 16384];
        while let Ok((n, src)) = udp.recv_from(&mut buf) {
            c_udp.fetch_add(1, Ordering::SeqCst);
            if let Ok(reply) = krb5_kdc::handle_request(&*s_udp, &buf[..n]) {
                let _ = udp.send_to(&reply, src);
            }
        }
    });
    let c_tcp = asked.clone();
    thread::spawn(move || {
        for conn in tcp.incoming() {
            let Ok(mut conn) = conn else { break };
            let (store, counted) = (store.clone(), c_tcp.clone());
            thread::spawn(move || {
                let mut len = [0u8; 4];
                if conn.read_exact(&mut len).is_err() {
                    return;
                }
                let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
                if conn.read_exact(&mut req).is_err() {
                    return;
                }
                counted.fetch_add(1, Ordering::SeqCst);
                if let Ok(reply) = krb5_kdc::handle_request(&*store, &req) {
                    let n = u32::try_from(reply.len()).unwrap();
                    let _ = conn.write_all(&n.to_be_bytes());
                    let _ = conn.write_all(&reply);
                }
            });
        }
    });
    (format!("127.0.0.1:{}", addr.port()), asked)
}

/// The documented realm's `user`, with or without `+requires_preauth`.
fn realm(requires_preauth: bool) -> PrincipalStore {
    let (mut store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut attrs = store.get_name(&user).unwrap().attributes;
    if requires_preauth {
        attrs |= KDB_REQUIRES_PRE_AUTH;
    } else {
        attrs &= !KDB_REQUIRES_PRE_AUTH;
    }
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
    store
}

/// A `test-hooks` build of kinit adds its own output: one JSON object per structured log line, and
/// an `ok tgt=` line on success. The shipped binary writes neither, so a test compares what the
/// command printed without them.
fn without_test_hook_output(text: &str) -> String {
    text.split_inclusive('\n')
        .filter(|line| !line.starts_with("{\"timestamp\"") && !line.starts_with("ok tgt="))
        .collect()
}

/// What a run of `krb5-kinit` printed.
struct Run {
    code: Option<i32>,
    /// Standard output and error.
    output: String,
    /// The `KRB5_TRACE` file.
    trace: String,
}

/// `krb5-kinit -k -t keytab user@KERBER.TEST` against the KDC at `kdc`, whose client config adds
/// `libdefaults` lines.
fn kinit_k(kdc: &str, keytab: &str, libdefaults: &str) -> Run {
    let dir = scratch_dir("kp-kinit-keytab");
    let conf = dir.join("krb5.conf");
    std::fs::write(
        &conf,
        format!(
            "[libdefaults]\n    default_realm = {TEST_REALM}\n    dns_lookup_kdc = false\n    \
             dns_lookup_realm = false\n{libdefaults}[realms]\n    {TEST_REALM} = {{\n        kdc = {kdc}\n    }}\n"
        ),
    )
    .unwrap();
    let trace = dir.join("trace.log");
    let out = Command::new(env!("CARGO_BIN_EXE_krb5-kinit"))
        .arg("-c")
        .arg(dir.join("cc"))
        .arg("-k")
        .arg("-t")
        .arg(keytab)
        .arg(format!("{TEST_USER}@{TEST_REALM}"))
        .env("KRB5_CONFIG", &conf)
        .env("KRB5_TRACE", &trace)
        .env_remove("KRB5_KTNAME")
        .env_remove("KRB5_PASSWORD")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let mut output = without_test_hook_output(&String::from_utf8_lossy(&out.stdout));
    output.push_str(&without_test_hook_output(&String::from_utf8_lossy(
        &out.stderr,
    )));
    let trace = std::fs::read_to_string(&trace).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!(
        "krb5-kinit rc={:?}\n{output}--- trace\n{trace}",
        out.status.code()
    );
    Run {
        code: out.status.code(),
        output,
        trace,
    }
}

/// The keytab files that cannot be read as MIT's `krb5_ktfileint_open` fails them, and the text
/// each is.
fn unreadable_keytabs() -> Vec<(String, &'static str)> {
    let dir = scratch_dir("kp-kinit-keytab-files");
    let empty = dir.join("empty.keytab");
    std::fs::write(&empty, b"").unwrap();
    let bad_version = dir.join("badver.keytab");
    std::fs::write(&bad_version, [0x05u8, 0x3f]).unwrap();
    vec![
        (
            dir.join("nonexistent.keytab").display().to_string(),
            "NOTFOUND",
        ),
        (
            empty.display().to_string(),
            "Unsupported key table format version number",
        ),
        (
            bad_version.display().to_string(),
            "Unsupported key table format version number",
        ),
        (dir.display().to_string(), "Is a directory"),
    ]
}

/// A reply that no preauth answered is decrypted with the keytab's key, and that is where an
/// unreadable keytab fails: after a request was made, with the keytab's own message.
/// MIT `decrypt_as_reply` (`lib/krb5/krb/get_in_tkt.c:115-123`): `gak_fct`'s error is returned as it is.
#[test]
fn an_unreadable_keytab_fails_a_reply_that_needs_its_key_after_the_request_is_made() {
    for (keytab, text) in unreadable_keytabs() {
        let (kdc, asked) = serve(realm(false));
        let run = kinit_k(&kdc, &keytab, "");
        let want = if text == "NOTFOUND" {
            format!("Key table file '{keytab}' not found")
        } else {
            text.to_owned()
        };
        assert_eq!(run.code, Some(1), "{keytab}: {}", run.output);
        assert_eq!(
            run.output.trim_end(),
            format!("krb5-kinit: {want} while getting initial credentials"),
            "{keytab}"
        );
        assert_eq!(
            asked.load(Ordering::SeqCst),
            1,
            "{keytab}: the request was made"
        );
        assert!(
            run.trace.contains("Couldn't lookup etypes in keytab:")
                && run.trace.contains("Sending unauthenticated request")
                && run.trace.contains("Getting AS key, salt")
                && run.trace.contains(&format!(
                    "Retrieving {TEST_USER}@{TEST_REALM} from FILE:{keytab} (vno 0, enctype"
                )),
            "{keytab}: {}",
            run.trace
        );
    }
}

/// The text kinit prints for the keytab `keytab` that `unreadable_keytabs` pairs with `text`.
fn keytab_message(keytab: &str, text: &str) -> String {
    if text == "NOTFOUND" {
        format!("Key table file '{keytab}' not found")
    } else {
        text.to_owned()
    }
}

/// A KDC that asks for preauthentication gets its request, and the encrypted-timestamp module is
/// the one that wants the key: its failure is the keytab's, and with no other mechanism to try
/// the exchange ends "Pre-authentication failed: <the keytab's message>".
/// MIT `get_as_key` (`lib/krb5/krb/preauth2.c:438-457`): a module that wants the key gets `gak_fct`'s error as its own.
/// MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:716-723`): with no real mechanism answered, the first failure is wrapped as "Pre-authentication failed: <message>".
#[test]
fn an_unreadable_keytab_fails_the_encrypted_timestamp_module_that_wants_its_key() {
    for (keytab, text) in unreadable_keytabs() {
        let (kdc, asked) = serve(realm(true));
        // No SPAKE group is permitted, so the hint's SPAKE has no module and encrypted timestamp is
        // the one mechanism MIT's client has for it.
        let run = kinit_k(&kdc, &keytab, "    spake_preauth_groups = bogus\n");
        let message = keytab_message(&keytab, text);
        assert_eq!(run.code, Some(1), "{keytab}: {}", run.output);
        assert_eq!(
            run.output.trim_end(),
            format!(
                "krb5-kinit: Pre-authentication failed: {message} while getting initial credentials"
            ),
            "{keytab}"
        );
        assert_eq!(
            asked.load(Ordering::SeqCst),
            1,
            "{keytab}: one request, answered by the hint"
        );
        assert!(
            run.trace.contains("Couldn't lookup etypes in keytab:")
                && run
                    .trace
                    .contains("Preauthenticating using KDC method data")
                && run
                    .trace
                    .contains("Preauth module encrypted_timestamp (2) (real) returned:"),
            "{keytab}: {}",
            run.trace
        );
        // MIT `krb5_kt_get_entry` (`lib/krb5/keytab/ktfns.c:57-80`): the lookup is traced, a failure included, before the module gets the error.
        // The line reads "Retrieving <client> from FILE:<keytab> (vno 0, enctype <etype>) with result: <code>/<message>".
        let lookup = run
            .trace
            .lines()
            .find(|l| {
                l.contains(&format!(
                    "Retrieving {TEST_USER}@{TEST_REALM} from FILE:{keytab} (vno 0, enctype"
                ))
            })
            .unwrap_or_default();
        assert!(
            lookup.contains(") with result: ") && lookup.ends_with(&format!("/{message}")),
            "{keytab}: the module's key lookup is traced with the keytab's failure: {}",
            run.trace
        );
    }
}

/// With SPAKE permitted, the hint is answered first by SPAKE's support message, which needs no key,
/// and the KDC refuses it: that refusal, not the keytab's failure, is the exchange's error, after
/// the encrypted-timestamp module has failed for the key too.
/// MIT `init_creds_step_request` (`lib/krb5/krb/get_in_tkt.c:1349-1352`): a `KDC_ERR_PREAUTH_FAILED` the KDC sent is the error saved, and it is the one reported when the mechanisms after it fail.
#[test]
fn a_spake_support_the_kdc_refuses_is_the_error_over_the_keytabs_failure() {
    for (keytab, _) in unreadable_keytabs() {
        let (kdc, asked) = serve(realm(true));
        let run = kinit_k(&kdc, &keytab, "");
        assert_eq!(run.code, Some(1), "{keytab}: {}", run.output);
        assert_eq!(
            run.output.trim_end(),
            "krb5-kinit: Preauthentication failed while getting initial credentials",
            "{keytab}"
        );
        assert_eq!(
            asked.load(Ordering::SeqCst),
            2,
            "{keytab}: the first request and SPAKE's support message"
        );
        assert!(
            run.trace.contains("Sending SPAKE support message")
                && run
                    .trace
                    .contains("Preauth module encrypted_timestamp (2) (real) returned:"),
            "{keytab}: {}",
            run.trace
        );
    }
}
