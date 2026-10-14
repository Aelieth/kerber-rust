//! `kinit -k -t` with a keytab whose des3 key has bad parity: the key loads, and its first use fails as MIT's does.
//! MIT `validate_and_schedule` (`lib/crypto/builtin/enc_provider/des3.c:33-53`): every encryption and decryption under such a key returns `KRB5DES_BAD_KEYPAR`, "DES key has bad parity".
//! MIT `get_as_key_keytab` (`lib/krb5/krb/gic_keytab.c:33-80`): the keytab's key is taken as it is, whatever its parity.
//! Live oracle: MIT 1.22.2's kinit beside this one, a principal that does and one that does not require preauthentication, the keytab MIT's `ktadd` wrote with the parity bit of one octet flipped.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use krb5_client::Keytab;
use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented, documented_admin_id};
use krb5_kdc::{AdminFields, KDB_REQUIRES_PRE_AUTH, PrincipalStore};
use krb5_testkit::scratch_dir;
use krb5_types::{PrincipalName, ascii};

const DES3: EncryptionType = EncryptionType::Des3CbcSha1;
const USER: &str = "des3user";

/// Serve `store` on UDP and TCP at one ephemeral port; returns `host:port` and the count of requests it has answered.
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

/// The documented realm with a user whose only key is des3, with or without `+requires_preauth`, and the key.
fn realm(requires_preauth: bool) -> (PrincipalStore, PrincipalName, ProtocolKey) {
    let (mut store, acl) = bootstrap_documented().unwrap();
    store.policy.allow_des3 = true;
    store
        .set_string(
            &PrincipalName::krbtgt(TEST_REALM),
            "session_enctypes",
            Some("des3-cbc-sha1"),
        )
        .unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [USER]);
    store
        .create_password_etypes(&acl, &documented_admin_id(), &user, b"des3-secret", &[DES3])
        .unwrap();
    let mut attrs = store.get_name(&user).unwrap().attributes;
    if requires_preauth {
        attrs |= KDB_REQUIRES_PRE_AUTH;
    } else {
        attrs &= !KDB_REQUIRES_PRE_AUTH;
    }
    store
        .apply_admin_fields(
            &user,
            AdminFields {
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
    let key = string_to_key(DES3, b"des3-secret", user.default_salt(TEST_REALM), None).unwrap();
    (store, user, key)
}

/// A keytab file holding `key` for the user.
fn keytab_of(key: ProtocolKey) -> String {
    let dir = scratch_dir("kp-kinit-des3-keytab");
    let path = dir.join("user.keytab");
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [USER]);
    Keytab::single(ascii(TEST_REALM), user, 1, key)
        .write_file(&path)
        .unwrap();
    path.display().to_string()
}

/// `key` with the parity bit of one octet flipped.
fn with_bad_parity(key: &ProtocolKey) -> ProtocolKey {
    let mut bytes = key.as_bytes().to_vec();
    bytes[3] ^= 1;
    ProtocolKey::from_bytes(DES3, &bytes).expect("a 24-octet key loads, whatever its parity")
}

/// A `test-hooks` build of kinit adds its own output: one JSON object per structured log line, and an `ok tgt=` line on success.
fn without_test_hook_output(text: &str) -> String {
    text.split_inclusive('\n')
        .filter(|line| !line.starts_with("{\"timestamp\"") && !line.starts_with("ok tgt="))
        .collect()
}

/// What a run of `krb5-kinit` printed.
struct Run {
    code: Option<i32>,
    output: String,
}

/// `krb5-kinit -k -t keytab des3user@KERBER.TEST` against the KDC at `kdc`, limited to des3.
fn kinit_k(kdc: &str, keytab: &str) -> Run {
    let dir = scratch_dir("kp-kinit-des3");
    let conf = dir.join("krb5.conf");
    std::fs::write(
        &conf,
        format!(
            "[libdefaults]\n    default_realm = {TEST_REALM}\n    dns_lookup_kdc = false\n    dns_lookup_realm = false\n    \
             allow_weak_crypto = true\n    default_tkt_enctypes = des3-cbc-sha1\n    spake_preauth_groups = bogus\n\
             [realms]\n    {TEST_REALM} = {{\n        kdc = {kdc}\n    }}\n"
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_krb5-kinit"))
        .arg("-c")
        .arg(dir.join("cc"))
        .arg("-k")
        .arg("-t")
        .arg(keytab)
        .arg(format!("{USER}@{TEST_REALM}"))
        .env("KRB5_CONFIG", &conf)
        .env_remove("KRB5_KTNAME")
        .env_remove("KRB5_PASSWORD")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let mut output = without_test_hook_output(&String::from_utf8_lossy(&out.stdout));
    output.push_str(&without_test_hook_output(&String::from_utf8_lossy(
        &out.stderr,
    )));
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("krb5-kinit rc={:?}\n{output}", out.status.code());
    Run {
        code: out.status.code(),
        output,
    }
}

/// The same keytab with a good key logs in, so the refusals below are the key's parity and nothing else.
#[test]
fn a_keytab_key_of_good_parity_logs_in() {
    for preauth in [false, true] {
        let (store, _, key) = realm(preauth);
        let (kdc, _) = serve(store);
        let run = kinit_k(&kdc, &keytab_of(key));
        assert_eq!(run.code, Some(0), "preauth {preauth}: {}", run.output);
    }
}

/// With no preauthentication the reply is decrypted with the keytab's key, which is refused: after the request was made, with MIT's message.
/// MIT `decrypt_as_reply` (`lib/krb5/krb/get_in_tkt.c:115-134`): `krb5_kdc_rep_decrypt_proc` fails with the key's code, and kinit prints "DES key has bad parity while getting initial credentials".
#[test]
fn a_keytab_key_of_bad_parity_fails_the_reply_that_needs_it() {
    let (store, _, key) = realm(false);
    let (kdc, asked) = serve(store);
    let run = kinit_k(&kdc, &keytab_of(with_bad_parity(&key)));
    assert_eq!(run.code, Some(1), "{}", run.output);
    assert_eq!(
        run.output.trim_end(),
        "krb5-kinit: DES key has bad parity while getting initial credentials"
    );
    assert_eq!(asked.load(Ordering::SeqCst), 1, "the request was made");
}

/// With preauthentication the encrypted-timestamp module wants the key and fails with it; with no other mechanism the exchange ends
/// "Pre-authentication failed: <the key's message>", and no second request is made.
/// MIT `encts_process` (`lib/krb5/krb/preauth_encts.c:87-97`): `krb5_encrypt_helper` fails with the key's code, the module's failure.
/// MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:716-723`): with no real mechanism answered, the first failure is wrapped as "Pre-authentication failed: <message>".
#[test]
fn a_keytab_key_of_bad_parity_fails_the_encrypted_timestamp_module() {
    let (store, _, key) = realm(true);
    let (kdc, asked) = serve(store);
    let run = kinit_k(&kdc, &keytab_of(with_bad_parity(&key)));
    assert_eq!(run.code, Some(1), "{}", run.output);
    assert_eq!(
        run.output.trim_end(),
        "krb5-kinit: Pre-authentication failed: DES key has bad parity while getting initial credentials"
    );
    assert_eq!(
        asked.load(Ordering::SeqCst),
        1,
        "one request, answered by the hint"
    );
}
