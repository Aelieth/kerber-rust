//! `krb5-kprop` as MIT's `kprop`: the dump file `kdb5_util dump` wrote, sent with a ticket one AS
//! exchange gets from a KDC as `host/<this host>`, its checks and its lines as MIT's.
//! MIT `main` (`kprop/kprop.c:90-120`): tickets, the dump, the connection, sendauth, the transfer, then the `.last_prop` mark and the line on standard output.
//! Live oracle: MIT kprop beside this one, settled case by case, and
//! `scripts/kprop-reverse-gate.sh`.

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
use krb5_protocol::{Keytab, ReplayCache};
use krb5_testkit::scratch_dir;
use krb5_types::PrincipalName;

const KPROP: &str = env!("CARGO_BIN_EXE_krb5-kprop");

/// A realm on a KDC in this process, with `host/<this host>` (kprop's own principal, its key in
/// `keytab`) and `host/127.0.0.1` (the replica's, its keys in `replica_keys`).
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
    let dir = scratch_dir(tag);
    let (udp, tcp) = krb5_testkit::loopback_udp_tcp();
    let port = udp.local_addr().unwrap().port();
    let conf = dir.join("krb5.conf");
    std::fs::write(
        &conf,
        format!(
            "[libdefaults]\n    default_realm = {TEST_REALM}\n    qualify_shortname = kerber.test\n    \
             dns_lookup_kdc = false\n    dns_lookup_realm = false\n\
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
    /// A dump file and its `.dump_ok` mark, the mark written after the dump as `kdb5_util dump`
    /// writes it.
    fn dump(&self, name: &str, body: &[u8]) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::write(ok_of(&path), [0u8]).unwrap();
        path
    }

    /// One kpropd connection, as `host/127.0.0.1`, that lets kprop's own principal in: what
    /// it received.
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
            )
            .unwrap();
            let dump = kpropd_recv_dump(&mut stream, &mut auth).unwrap();
            kpropd_send_ack(&mut stream, &mut auth, dump.len() as u64).unwrap();
            dump
        });
        (port, join)
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

/// MIT `xmit_database` (`kprop/kprop.c:409-544`): the dump goes whole, its total printed after each block under `-d`, and the replica's acknowledgement ends it.
/// MIT `update_last_prop_file` (`kprop/kprop.c:573-596`): then `<dump>.<replica>.last_prop` holds one NUL, mode 0600, and kprop prints `SUCCEEDED`.
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

/// MIT `open_database` (`kprop/kprop.c:337-386`): after the tickets, a dump that does not open, has no `.dump_ok` mark, or is newer than it stops kprop with MIT's line, before any connection.
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

/// MIT `open_database` (`kprop/kprop.c:356-360`): a dump another process holds locked is "database locked".
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

/// MIT `get_tickets` (`kprop/kprop.c:195-208`): a keytab with no key for kprop's own principal, and a replica the KDC has no `host/` principal for, stop kprop with the error's table text and MIT's newline.
/// MIT `open_connection` (`kprop/kprop.c:231-264`): a port nothing listens on is the connection's error.
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

/// MIT `parse_args` (`kprop/kprop.c:122-152`): `getopt`'s complaint, then the usage between blank lines, exit 1, for a bad option and for a count of hosts other than one.
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

/// One length-prefixed message off `stream`.
fn read_msg(stream: &mut TcpStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).unwrap();
    let mut msg = vec![0u8; usize::try_from(u32::from_be_bytes(len)).unwrap()];
    stream.read_exact(&mut msg).unwrap();
    msg
}

/// MIT `get_tickets` (`kprop/kprop.c:188-204`): the replica's `host/` name goes to `krb5_get_init_creds_keytab` unparsed, without its realm.
/// MIT `build_in_tkt_name` (`lib/krb5/krb/get_in_tkt.c:484-495`): parsed back there, it is NT-PRINCIPAL, the type the KDC copies into the ticket kprop presents.
#[test]
fn kprop_asks_for_the_replicas_name_as_mits_in_tkt_service_parses_it() {
    let r = realm("kprop-file-sname");
    let dump = r.dump("dump", b"kdb5_util load_dump version 7\n");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let kpropd = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        // The two version strings, sendauth's answer, then the AP-REQ; the connection then goes.
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
