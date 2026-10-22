//! `krb5-kprop` as MIT's `kprop`: the dump file `kdb5_util dump` wrote, sent with a ticket one AS exchange gets from a KDC as `host/<this host>`, its checks and its lines as MIT's.

#![allow(
    clippy::disallowed_methods,
    reason = "a test sets up its own profile and environment"
)]

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use krb5_admin::{kpropd_recv_dump, kpropd_recvauth, kpropd_send_ack};
use krb5_crypto::ProtocolKey;
use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented, documented_admin_id};
use krb5_kdc::{serve, shared_store};
use krb5_protocol::{AcceptorConfig, Keytab, ReplayCache};
use krb5_testkit::scratch_dir;
use krb5_types::PrincipalName;

const KPROP: &str = env!("CARGO_BIN_EXE_krb5-kprop");

struct Realm {
    dir: PathBuf,
    conf: PathBuf,
    keytab: PathBuf,
    other_keytab: PathBuf,
    me: String,
    replica_keys: Vec<ProtocolKey>,
}

fn host(name: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", name])
}

fn realm(tag: &str) -> Realm {
    realm_with(tag, false, "")
}

fn realm_with(tag: &str, requires_preauth: bool, libdefaults: &str) -> Realm {
    let dir = scratch_dir(tag);
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    let port = udp.local_addr().unwrap().port();
    let conf = dir.join("krb5.conf");
    std::fs::write(
        &conf,
        format!(
            "[libdefaults]\n    default_realm = {TEST_REALM}\n    qualify_shortname = kerber.test\n    \
             dns_lookup_kdc = false\n    dns_lookup_realm = false\n{libdefaults}\
             [realms]\n    {TEST_REALM} = {{\n        kdc = 127.0.0.1:{port}\n    }}\n"
        ),
    )
    .unwrap();
    let me = krb5_config::local_host_name(&krb5_config::Krb5Conf::load_file(&conf).unwrap());
    let (mut store, acl) = bootstrap_documented().unwrap();
    let actor = documented_admin_id();
    for name in [me.as_str(), "127.0.0.1", "other.kerber.test"] {
        store.create_host(&acl, &actor, &host(name)).unwrap();
    }
    let me_name = host(&me);
    let mut attrs = store.get_name(&me_name).unwrap().attributes;
    if requires_preauth {
        attrs |= krb5_kdc::KDB_REQUIRES_PRE_AUTH;
    } else {
        attrs &= !krb5_kdc::KDB_REQUIRES_PRE_AUTH;
    }
    store
        .apply_admin_fields(
            &me_name,
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
    let keytab_of = |name: &str, file: &str| {
        let ent = store.get_name(&host(name)).unwrap();
        let best = ent.best_key().unwrap();
        let path = dir.join(file);
        Keytab::single(
            krb5_types::ascii(TEST_REALM),
            host(name),
            best.kvno,
            best.key.clone(),
        )
        .write_file(&path)
        .unwrap();
        path
    };
    let keytab = keytab_of(&me, "kprop.keytab");
    let other_keytab = keytab_of("other.kerber.test", "other.keytab");
    let replica_keys = store
        .get_name(&host("127.0.0.1"))
        .unwrap()
        .keys
        .iter()
        .map(|k| k.key.clone())
        .collect();
    let store = shared_store(store);
    thread::spawn(move || {
        let _ = serve(store, udp, tcp);
    });
    Realm {
        dir,
        conf,
        keytab,
        other_keytab,
        me,
        replica_keys,
    }
}

impl Realm {
    fn dump(&self, name: &str, body: &[u8]) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::write(ok_of(&path), [0u8]).unwrap();
        path
    }

    fn kpropd(&self) -> (u16, JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let keys = self.replica_keys.clone();
        let allowed = [format!("host/{}@{TEST_REALM}", self.me)];
        let join = thread::spawn(move || {
            krb5_config::isolate_test_krb5();
            let (mut stream, _) = listener.accept().unwrap();
            let mut auth = kpropd_recvauth(
                &mut stream,
                &keys,
                Some(&host("127.0.0.1")),
                Some(TEST_REALM),
                Some(allowed.as_slice()),
                &ReplayCache::new(),
                &AcceptorConfig::default(),
            )
            .unwrap();
            let dump = kpropd_recv_dump(&mut stream, &mut auth).unwrap();
            kpropd_send_ack(&mut stream, &mut auth, dump.len() as u64).unwrap();
            dump
        });
        (port, join)
    }

    fn kprop_traced(&self, args: &[&str], trace: &Path) -> Output {
        Command::new(KPROP)
            .args(args)
            .env("KRB5_CONFIG", &self.conf)
            .env("KRB5_TRACE", trace)
            .env_remove("KRB5_KTNAME")
            .env_remove("KRB5_KDC_PROFILE")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn kprop(&self, args: &[&str]) -> Output {
        Command::new(KPROP)
            .args(args)
            .env("KRB5_CONFIG", &self.conf)
            .env_remove("KRB5_KTNAME")
            .env_remove("KRB5_TRACE")
            .env_remove("KRB5_KDC_PROFILE")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
}

fn ok_of(dump: &Path) -> PathBuf {
    let mut ok = dump.as_os_str().to_os_string();
    ok.push(".dump_ok");
    PathBuf::from(ok)
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn kprop_sends_the_dump_file_and_marks_the_replica() {
    let r = realm("kprop-file-sends");
    let body: Vec<u8> = (0..70_000u32)
        .flat_map(|i| u8::try_from(i % 251).unwrap().to_be_bytes())
        .collect();
    let dump = r.dump("dump", &body);
    let (port, kpropd) = r.kpropd();
    let port = port.to_string();
    let out = r.kprop(&[
        "-d",
        "-s",
        s(&r.keytab),
        "-P",
        &port,
        "-f",
        s(&dump),
        "127.0.0.1",
    ]);
    assert_eq!(text(&out.stderr), "");
    assert_eq!(
        text(&out.stdout),
        "32768 bytes sent.\n65536 bytes sent.\n70000 bytes sent.\n\
         Database propagation to 127.0.0.1: SUCCEEDED\n"
    );
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(kpropd.join().expect("kpropd"), body);
    let mark = r.dir.join("dump.127.0.0.1.last_prop");
    assert_eq!(std::fs::read(&mark).unwrap(), [0u8]);
    assert_eq!(
        std::fs::metadata(&mark).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let _ = std::fs::remove_dir_all(&r.dir);
}

#[test]
fn kprop_refuses_a_dump_without_a_mark_no_older_than_itself() {
    let r = realm("kprop-file-mark");
    let dump = r.dump("dump", b"kdb5_util load_dump version 7\n");
    let run = |file: &Path| r.kprop(&["-s", s(&r.keytab), "-P", "9", "-f", s(file), "127.0.0.1"]);
    let missing = r.dir.join("nodump");
    let out = run(&missing);
    assert_eq!(
        text(&out.stderr),
        format!(
            "{KPROP}: No such file or directory while trying to open {}\n",
            s(&missing)
        )
    );
    assert_eq!(out.status.code(), Some(1));
    std::fs::remove_file(ok_of(&dump)).unwrap();
    let out = run(&dump);
    assert_eq!(
        text(&out.stderr),
        format!(
            "{KPROP}: No such file or directory while trying to stat {}\n",
            s(&ok_of(&dump))
        )
    );
    assert_eq!(out.status.code(), Some(1));
    std::fs::write(ok_of(&dump), [0u8]).unwrap();
    let earlier = SystemTime::now() - Duration::from_secs(3600);
    File::options()
        .write(true)
        .open(ok_of(&dump))
        .unwrap()
        .set_modified(earlier)
        .unwrap();
    let out = run(&dump);
    assert_eq!(
        text(&out.stderr),
        format!(
            "{KPROP}: '{}' more recent than '{}'.\n",
            s(&dump),
            s(&ok_of(&dump))
        )
    );
    assert_eq!(out.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&r.dir);
}

#[test]
fn kprop_refuses_a_locked_dump() {
    let r = realm("kprop-file-locked");
    let dump = r.dump("dump", b"kdb5_util load_dump version 7\n");
    let held = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&dump)
        .unwrap();
    let guard = krb5_kdc::lock_file_exclusive(&held).unwrap();
    let out = r.kprop(&["-s", s(&r.keytab), "-P", "9", "-f", s(&dump), "127.0.0.1"]);
    assert_eq!(text(&out.stderr), format!("{KPROP}: database locked\n"));
    assert_eq!(out.status.code(), Some(1));
    drop(guard);
    let _ = std::fs::remove_dir_all(&r.dir);
}

#[test]
fn kprop_names_a_failure_as_mits_com_err() {
    let r = realm("kprop-file-failures");
    let dump = r.dump("dump", b"kdb5_util load_dump version 7\n");
    let out = r.kprop(&[
        "-s",
        s(&r.other_keytab),
        "-P",
        "9",
        "-f",
        s(&dump),
        "127.0.0.1",
    ]);
    assert_eq!(
        text(&out.stderr),
        format!("{KPROP}: Key table entry not found while getting initial credentials\n\n")
    );
    assert_eq!(out.status.code(), Some(1));
    let out = r.kprop(&[
        "-s",
        s(&r.keytab),
        "-P",
        "9",
        "-f",
        s(&dump),
        "nohost.invalid",
    ]);
    assert_eq!(
        text(&out.stderr),
        format!(
            "{KPROP}: Server not found in Kerberos database while getting initial credentials\n\n"
        )
    );
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port().to_string();
    drop(closed);
    let out = r.kprop(&["-s", s(&r.keytab), "-P", &port, "-f", s(&dump), "127.0.0.1"]);
    assert_eq!(
        text(&out.stderr),
        format!("{KPROP}: Connection refused while connecting to server\n")
    );
    assert_eq!(out.status.code(), Some(1));
    let _ = std::fs::remove_dir_all(&r.dir);
}

#[test]
fn kprop_prints_mits_usage() {
    let r = realm("kprop-file-usage");
    let usage = format!(
        "\nUsage: {KPROP} [-r realm] [-f file] [-d] [-P port] [-s keytab] replica_host\n\n"
    );
    for (args, complaint) in [
        (&[][..], String::new()),
        (&["a", "b"][..], String::new()),
        (
            &["-x", "a"][..],
            format!("{KPROP}: invalid option -- 'x'\n"),
        ),
        (
            &["a", "-f"][..],
            format!("{KPROP}: option requires an argument -- 'f'\n"),
        ),
    ] {
        let out = r.kprop(args);
        assert_eq!(text(&out.stderr), format!("{complaint}{usage}"), "{args:?}");
        assert_eq!(out.status.code(), Some(1), "{args:?}");
    }
    let _ = std::fs::remove_dir_all(&r.dir);
}

fn read_msg(stream: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).unwrap();
    let mut msg = vec![0u8; usize::try_from(u32::from_be_bytes(len)).unwrap()];
    stream.read_exact(&mut msg).unwrap();
    msg
}

#[test]
fn kprop_asks_for_the_replicas_name_as_mits_in_tkt_service_parses_it() {
    let r = realm("kprop-file-sname");
    let dump = r.dump("dump", b"kdb5_util load_dump version 7\n");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let kpropd = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_msg(&mut stream);
        read_msg(&mut stream);
        stream.write_all(&[0]).unwrap();
        let ap: krb5_types::ApReq = krb5_asn1::decode(&read_msg(&mut stream)).unwrap();
        ap.ticket.sname
    });
    let out = r.kprop(&["-s", s(&r.keytab), "-P", &port, "-f", s(&dump), "127.0.0.1"]);
    let sname = kpropd.join().expect("fake kpropd");
    assert_eq!(sname.name_type, PrincipalName::NT_PRINCIPAL);
    assert_eq!(sname.components_joined(), "host/127.0.0.1");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let _ = std::fs::remove_dir_all(&r.dir);
}

fn unreadable_keytabs(dir: &Path) -> Vec<(PathBuf, &'static str)> {
    let empty = dir.join("empty.keytab");
    std::fs::write(&empty, b"").unwrap();
    let bad_version = dir.join("badver.keytab");
    std::fs::write(&bad_version, [0x05u8, 0x3f]).unwrap();
    vec![
        (dir.join("nonexistent.keytab"), "No such file or directory"),
        (empty, "Unsupported key table format version number"),
        (bad_version, "Unsupported key table format version number"),
        (dir.to_path_buf(), "Is a directory"),
    ]
}

/// MIT `decrypt_as_reply` (`lib/krb5/krb/get_in_tkt.c:115-123`): `gak_fct`'s error is returned as it is.
#[test]
fn kprop_with_an_unreadable_keytab_makes_the_request_and_fails_the_reply_that_needs_its_key() {
    let r = realm_with("kprop-file-unreadable-reply", false, "");
    let dump = r.dump("dump", b"kdb5_util load_dump version 7\n");
    for (keytab, message) in unreadable_keytabs(&r.dir) {
        let trace = r.dir.join("trace.log");
        let out = r.kprop_traced(
            &["-s", s(&keytab), "-P", "9", "-f", s(&dump), "127.0.0.1"],
            &trace,
        );
        assert_eq!(
            text(&out.stderr),
            format!("{KPROP}: {message} while getting initial credentials\n\n"),
            "{}",
            keytab.display()
        );
        assert_eq!(out.status.code(), Some(1));
        let trace = std::fs::read_to_string(&trace).unwrap();
        for line in [
            "Couldn't lookup etypes in keytab:",
            "Sending unauthenticated request",
            "Received answer (",
            "Getting AS key, salt",
            &format!(
                "Retrieving host/{}@{TEST_REALM} from FILE:{}",
                r.me,
                keytab.display()
            ),
        ] {
            assert!(trace.contains(line), "{line}: {trace}");
        }
    }
    let _ = std::fs::remove_dir_all(&r.dir);
}

/// MIT `get_as_key` (`lib/krb5/krb/preauth2.c:438-457`): a module that wants the key gets `gak_fct`'s error as its own.
#[test]
fn kprop_with_an_unreadable_keytab_fails_the_preauth_module_that_wants_its_key() {
    let r = realm_with(
        "kprop-file-unreadable-preauth",
        true,
        "    spake_preauth_groups = bogus\n",
    );
    let dump = r.dump("dump", b"kdb5_util load_dump version 7\n");
    for (keytab, _) in unreadable_keytabs(&r.dir) {
        let trace = r.dir.join("trace.log");
        let out = r.kprop_traced(
            &["-s", s(&keytab), "-P", "9", "-f", s(&dump), "127.0.0.1"],
            &trace,
        );
        assert_eq!(
            text(&out.stderr),
            format!(
                "{KPROP}: Generic preauthentication failure while getting initial credentials\n\n"
            ),
            "{}",
            keytab.display()
        );
        assert_eq!(out.status.code(), Some(1));
        let trace = std::fs::read_to_string(&trace).unwrap();
        for line in [
            "Sending unauthenticated request",
            "Preauthenticating using KDC method data",
            "Preauth module encrypted_timestamp (2) (real) returned:",
        ] {
            assert!(trace.contains(line), "{line}: {trace}");
        }
    }
    let _ = std::fs::remove_dir_all(&r.dir);
}

/// With SPAKE permitted, the KDC's refusal of the support message is the exchange's error, as kprop's `com_err` prints it, "Preauthentication failed", over the keytab's failure.
/// MIT `init_creds_step_request` (`lib/krb5/krb/get_in_tkt.c:1349-1352`): a `KDC_ERR_PREAUTH_FAILED` the KDC sent is the error saved, and the one reported when the mechanisms after it fail.
#[test]
fn kprop_with_an_unreadable_keytab_reports_the_kdcs_refusal_of_spakes_support() {
    let r = realm_with("kprop-file-unreadable-spake", true, "");
    let dump = r.dump("dump", b"kdb5_util load_dump version 7\n");
    for (keytab, _) in unreadable_keytabs(&r.dir) {
        let trace = r.dir.join("trace.log");
        let out = r.kprop_traced(
            &["-s", s(&keytab), "-P", "9", "-f", s(&dump), "127.0.0.1"],
            &trace,
        );
        assert_eq!(
            text(&out.stderr),
            format!("{KPROP}: Preauthentication failed while getting initial credentials\n\n"),
            "{}",
            keytab.display()
        );
        let trace = std::fs::read_to_string(&trace).unwrap();
        assert!(trace.contains("Sending SPAKE support message"), "{trace}");
    }
    let _ = std::fs::remove_dir_all(&r.dir);
}
