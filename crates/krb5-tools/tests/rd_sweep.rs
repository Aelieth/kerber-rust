//! `rd-sweep`, run as the gates run it. `cases` and `judge` keep what the decode sweep and
//! `scripts/rd-priv-oracle-gate.sh` read; `kpasswd` writes the same cases as RFC 3244 frames and
//! `judge-explicit` answers them with kadmind's kpasswd acceptor; `kadmind` writes AP-REQs for
//! kadmind's services and `judge-kdb` answers them with its GSS acceptor over the KDB keytab.
//!
//! The ciphertext of a case differs from run to run (a fresh confounder, the clock), so what is
//! pinned is what does not: the ids and kinds in order (`data/rd-sweep-cases.ids`), the key line,
//! the answers the Rust acceptor gives, and the bytes `judge` prints for them.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Output;

use krb5_asn1::decode;
use krb5_crypto::{EncryptionType, KeyUsage, ProtocolKey, decrypt};
use krb5_kdc::principals::{kadmin_admin, kadmin_changepw, kadmin_history};
use krb5_kdc::testrealm::{
    TEST_REALM, TEST_USER, bootstrap_documented, documented_admin_id, documented_host,
};
use krb5_types::{ApReq, ChangePasswdData, EncKrbPrivPart, KrbPriv, ku};

/// The authenticator's subkey the cases carry (`SUBKEY` in `rd-sweep.rs`).
const SUBKEY: [u8; 32] = [0x45; 32];
/// The master password the test realm's dump is wrapped in.
const MASTER_PASSWORD: &str = "rd-sweep-test-master";

fn sweep(args: &[&str]) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_rd-sweep"))
        .args(args)
        .output()
        .expect("run rd-sweep")
}

fn ok_stdout(args: &[&str]) -> String {
    let out = sweep(args);
    assert!(
        out.status.success(),
        "rd-sweep {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf-8")
}

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("hex"))
        .collect()
}

/// The rows, one per line, each ended by a newline.
fn lines_of(rows: impl IntoIterator<Item = String>) -> String {
    let mut out = String::new();
    for row in rows {
        out.push_str(&row);
        out.push('\n');
    }
    out
}

/// The `(id, Rust answer)` of each `PART` line of a judge's output.
fn part_answers(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() == 4 && f[0] == "PART" {
                Some((f[1].to_owned(), f[3].strip_prefix("Rust ")?.to_owned()))
            } else {
                None
            }
        })
        .collect()
}

/// The `Rust` answers of `judge` against an empty MIT file: every case parts, and says what it answered.
fn rust_answers(cases: &Path) -> Vec<(String, String)> {
    let empty = cases.with_extension("none");
    std::fs::write(&empty, "").expect("write");
    let out = sweep(&[
        "judge",
        cases.to_str().expect("path"),
        empty.to_str().expect("path"),
    ]);
    part_answers(&String::from_utf8(out.stdout).expect("utf-8"))
}

/// `cases` is the decode sweep's: the same 646 ids and kinds in the same order, the service key line,
/// and for each case the fields the oracle reads.
#[test]
fn cases_keep_the_decode_sweeps_ids_kinds_and_key_line() {
    let text = ok_stdout(&["cases"]);
    let mut lines = text.lines();
    assert_eq!(
        lines.next(),
        Some(
            "#key 18 1 4343434343434343434343434343434343434343434343434343434343434343 host/oracle.kerber.test@KERBER.TEST"
        )
    );
    let mut ids = String::new();
    for line in lines {
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 4, "{line}");
        assert!(matches!(f[1], "req" | "priv" | "safe"), "{line}");
        assert_eq!((f[3] == "-"), f[1] == "req", "{line}");
        ids.push_str(f[0]);
        ids.push('\t');
        ids.push_str(f[1]);
        ids.push('\n');
    }
    assert_eq!(ids, include_str!("data/rd-sweep-cases.ids"));
    assert_eq!(ids.lines().count(), 646);
}

/// `judge` prints a `SAME` or `PART` line for every case and the count, and exits 1 when any parts.
/// The Rust acceptor accepts 69 of the 646 cases, the pristine three among them, as MIT does
/// (`scripts/rd-priv-oracle-gate.sh`).
#[test]
fn judge_prints_same_and_part_lines_and_exits_one_on_a_part() {
    let dir = scratch("rd-sweep-judge");
    let cases = dir.join("cases.tsv");
    std::fs::write(&cases, ok_stdout(&["cases"])).expect("write");
    let answers = rust_answers(&cases);
    assert_eq!(answers.len(), 646);
    let accepts = answers.iter().filter(|(_, a)| a == "0").count();
    assert_eq!(accepts, 69, "accepted cases");
    for pristine in ["ap-req/pristine", "krb-priv/pristine", "krb-safe/pristine"] {
        assert!(
            answers.contains(&(pristine.to_owned(), "0".to_owned())),
            "{pristine}"
        );
    }
    let mit = dir.join("mit.tsv");
    let rows = lines_of(answers.iter().map(|(id, a)| format!("{id}\t{a}")));
    std::fs::write(&mit, &rows).expect("write");
    let (c, m) = (cases.to_str().expect("path"), mit.to_str().expect("path"));
    let out = sweep(&["judge", c, m]);
    assert_eq!(out.status.code(), Some(0));
    let same = lines_of(answers.iter().map(|(id, a)| format!("SAME\t{id}\t{a}")));
    assert_eq!(
        String::from_utf8(out.stdout).expect("utf-8"),
        format!("{same}0 of 646 cases part from MIT\n")
    );
    // One answer MIT gives otherwise.
    std::fs::write(
        &mit,
        rows.replacen("ap-req/pristine\t0", "ap-req/pristine\tkrb5:99", 1),
    )
    .expect("write");
    let out = sweep(&["judge", c, m]);
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8(out.stdout).expect("utf-8");
    assert_eq!(text.lines().filter(|l| l.starts_with("PART")).count(), 1);
    assert!(
        text.contains("PART\tap-req/pristine\tMIT krb5:99\tRust 0\n"),
        "{text}"
    );
    assert!(text.ends_with("1 of 646 cases part from MIT\n"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A keytab of `kadmin/changepw` with these keys, in this order, at kvno 7, and the realm's name.
fn keytab_with(dir: &Path, keys: &[EncryptionType]) -> PathBuf {
    let mut kt: Option<krb5_protocol::Keytab> = None;
    for &e in keys {
        let key = krb5_kdc::random_key(e).expect("key");
        let one =
            krb5_protocol::Keytab::single(krb5_types::ascii(TEST_REALM), kadmin_changepw(), 7, key);
        match kt.as_mut() {
            Some(k) => k.entries.extend(one.entries),
            None => kt = Some(one),
        }
    }
    let path = dir.join("cpw.keytab");
    kt.expect("a key").write_file(&path).expect("write keytab");
    path
}

fn frames(args: &[&str]) -> Vec<(String, Vec<u8>)> {
    ok_stdout(args)
        .lines()
        .map(|l| {
            let (id, hex) = l.split_once('\t').expect("id TAB hex");
            (id.to_owned(), unhex(hex))
        })
        .collect()
}

/// The AP-REQ and the KRB-PRIV of a frame, its version checked: `[plen][vno][aplen][AP-REQ][KRB-PRIV]`.
fn split_frame(f: &[u8], vno: u16) -> (ApReq, KrbPriv) {
    assert_eq!(
        usize::from(u16::from_be_bytes([f[0], f[1]])),
        f.len(),
        "plen"
    );
    assert_eq!(u16::from_be_bytes([f[2], f[3]]), vno, "version");
    let aplen = usize::from(u16::from_be_bytes([f[4], f[5]]));
    (
        decode(&f[6..6 + aplen]).expect("AP-REQ"),
        decode(&f[6 + aplen..]).expect("KRB-PRIV"),
    )
}

fn priv_part(p: &KrbPriv) -> EncKrbPrivPart {
    let subkey =
        ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &SUBKEY).expect("key");
    let plain = decrypt(
        &subkey,
        KeyUsage::new(ku::KRB_PRIV_ENC_PART).expect("usage"),
        p.enc_part.cipher.as_ref(),
    )
    .expect("decrypt");
    decode(&plain).expect("EncKrbPrivPart")
}

/// `kpasswd` writes the cases as kpasswd frames for the keytab's entry: a ticket for `kadmin/changepw`
/// in that entry's enctype and kvno, the pristine request first, the receiver address when given.
#[test]
fn kpasswd_writes_the_cases_as_frames_for_a_keytab_entry() {
    let dir = scratch("rd-sweep-kpasswd");
    let kt = keytab_with(
        &dir,
        &[
            EncryptionType::Aes256CtsHmacSha196,
            EncryptionType::Aes128CtsHmacSha196,
        ],
    );
    let kt = kt.to_str().expect("path");
    let all = frames(&["kpasswd", kt, "ra4user", "raddr=10.1.2.3"]);
    assert_eq!(all[0].0, "ap-req/pristine");
    assert_eq!(all[1].0, "krb-priv/pristine");
    assert_eq!(all[0].1, all[1].1, "the two pristine requests are one");
    let ids: std::collections::HashSet<&String> = all.iter().map(|(i, _)| i).collect();
    assert_eq!(ids.len(), all.len(), "the ids are distinct");
    let (ap, priv_msg) = split_frame(&all[0].1, 1);
    assert_eq!(ap.ticket.sname.unparse(), "kadmin/changepw");
    assert_eq!(
        (ap.ticket.enc_part.etype, ap.ticket.enc_part.kvno),
        (18, Some(7))
    );
    let part = priv_part(&priv_msg);
    assert_eq!(part.user_data.as_ref(), b"rd-sweep");
    let r = part.r_address.expect("receiver address");
    assert_eq!((r.addr_type, r.address.as_ref()), (2, &[10, 1, 2, 3][..]));
    // No `raddr` leaves the KRB-PRIV without one; `entry=1` seals the ticket in the second key.
    let (_, p) = split_frame(&frames(&["kpasswd", kt, "ra4user"])[0].1, 1);
    assert!(priv_part(&p).r_address.is_none());
    let (ap, _) = split_frame(&frames(&["kpasswd", kt, "ra4user", "entry=1"])[0].1, 1);
    assert_eq!(
        (ap.ticket.enc_part.etype, ap.ticket.enc_part.kvno),
        (17, Some(7))
    );
    // An entry the keytab lacks, a bad address and an unknown option are refused.
    for bad in [
        &["entry=2"][..],
        &["raddr=10.1.2"],
        &["raddr=10.1.2.300"],
        &["frobnicate"],
    ] {
        let mut args = vec!["kpasswd", kt, "ra4user"];
        args.extend_from_slice(bad);
        assert_eq!(sweep(&args).status.code(), Some(2), "{bad:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// With `setpw` the version is 0xff80, the user data a ChangePasswdData for the client, and the
/// ChangePasswdData itself is broken in `setpw/*` cases, one of them naming no target.
#[test]
fn kpasswd_setpw_frames_carry_a_change_passwd_data() {
    let dir = scratch("rd-sweep-setpw");
    let kt = keytab_with(&dir, &[EncryptionType::Aes256CtsHmacSha196]);
    let all = frames(&["kpasswd", kt.to_str().expect("path"), "ra4user", "setpw"]);
    let (_, priv_msg) = split_frame(&all[0].1, 0xff80);
    let cpd: ChangePasswdData =
        decode(priv_part(&priv_msg).user_data.as_ref()).expect("ChangePasswdData");
    assert_eq!(cpd.targname.unparse(), "ra4user");
    assert_eq!(cpd.targrealm.as_bytes(), TEST_REALM.as_bytes());
    assert!(all.iter().any(|(id, _)| id == "setpw/no-target"));
    assert!(
        all.iter()
            .filter(|(id, _)| id.starts_with("setpw/"))
            .count()
            > 10
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `judge-explicit` runs each frame through kadmind's kpasswd acceptor over the realm of an MIT
/// dump and names the answer `0`, `req` or `priv`; it parts from an MIT answer of another class.
#[test]
fn judge_explicit_answers_each_frame_with_the_kpasswd_acceptor() {
    let dir = scratch("rd-sweep-explicit");
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let dump = dir.join("realm.dump");
    std::fs::write(
        &dump,
        krb5_kdc::dump_store(&store, MASTER_PASSWORD.as_bytes()).expect("dump"),
    )
    .expect("write");
    // The keytab `kadmin.local ktadd -norandkey kadmin/changepw` writes: every key, in the database's order.
    let mut kt: Option<krb5_protocol::Keytab> = None;
    for k in &store.get_name(&kadmin_changepw()).expect("changepw").keys {
        let one = krb5_protocol::Keytab::single(
            krb5_types::ascii(TEST_REALM),
            kadmin_changepw(),
            k.kvno,
            k.key.clone(),
        );
        match kt.as_mut() {
            Some(all) => all.entries.extend(one.entries),
            None => kt = Some(one),
        }
    }
    let kt = kt.expect("keys");
    let kt_path = dir.join("cpw.keytab");
    kt.write_file(&kt_path).expect("write keytab");
    let frames_path = dir.join("frames.tsv");
    std::fs::write(
        &frames_path,
        ok_stdout(&["kpasswd", kt_path.to_str().expect("path"), TEST_USER]),
    )
    .expect("write");
    let password = MASTER_PASSWORD;
    let args = |mit: &Path| -> Vec<String> {
        [
            "judge-explicit",
            frames_path.to_str().expect("path"),
            mit.to_str().expect("path"),
            dump.to_str().expect("path"),
            password,
        ]
        .map(str::to_owned)
        .to_vec()
    };
    let run = |mit: &Path| {
        let a = args(mit);
        sweep(&a.iter().map(String::as_str).collect::<Vec<_>>())
    };
    let none = dir.join("none.tsv");
    std::fs::write(&none, "").expect("write");
    let answers: HashMap<String, String> =
        part_answers(&String::from_utf8(run(&none).stdout).expect("utf-8"))
            .into_iter()
            .collect();
    let n = std::fs::read_to_string(&frames_path)
        .expect("read")
        .lines()
        .count();
    assert_eq!(answers.len(), n, "every frame is answered");
    assert_eq!(answers["ap-req/pristine"], "0");
    assert_eq!(answers["krb-priv/pristine"], "0");
    let class = |c: &str| answers.values().filter(|a| *a == c).count();
    assert!(class("req") > 0 && class("priv") > 0, "both refusals occur");
    assert_eq!(
        class("0") + class("req") + class("priv"),
        n,
        "no other answer"
    );
    // MIT's answers, detail after a colon and all, agree; one of another class parts.
    let mit = dir.join("mit.tsv");
    let rows = lines_of(answers.iter().map(|(id, a)| {
        let detail = if a == "0" {
            "0".to_owned()
        } else {
            format!("{a}:krb5:1")
        };
        format!("{id}\t{detail}")
    }));
    std::fs::write(&mit, &rows).expect("write");
    let out = run(&mit);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8(out.stdout)
            .expect("utf-8")
            .ends_with(&format!("0 of {n} cases part from MIT\n"))
    );
    std::fs::write(
        &mit,
        rows.replacen("ap-req/pristine\t0", "ap-req/pristine\treq:krb5:35", 1),
    )
    .expect("write");
    let out = run(&mit);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8(out.stdout)
            .expect("utf-8")
            .contains("PART\tap-req/pristine\tMIT req:krb5:35\tRust 0\n")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `kadmind` writes AP-REQs for a keytab's services, each sealed in each of its keys, at the wrong kvno and
/// under the wrong cleartext server, and `judge-kdb` answers each as kadmind's GSS acceptor does over the KDB
/// keytab: with no name (RPCSEC_GSS), as `kadmin/admin` and as `kadmin/changepw` (AUTH_GSSAPI's names).
#[test]
fn kadmind_cases_are_answered_as_the_acceptor_reads_the_kdb_keytab() {
    let dir = scratch("rd-sweep-kadmind");
    let (mut store, acl) = bootstrap_documented().expect("bootstrap");
    store
        .create_host(&acl, &documented_admin_id(), &kadmin_history())
        .expect("history");
    let dump = dir.join("realm.dump");
    std::fs::write(
        &dump,
        krb5_kdc::dump_store(&store, MASTER_PASSWORD.as_bytes()).expect("dump"),
    )
    .expect("write");
    // The keytab `kadmin.local ktadd -norandkey` writes for each service: every key, in the database's order.
    let mut kt: Option<krb5_protocol::Keytab> = None;
    for name in [
        kadmin_admin(),
        kadmin_changepw(),
        kadmin_history(),
        documented_host(),
    ] {
        for k in &store.get_name(&name).expect("service").keys {
            let one = krb5_protocol::Keytab::single(
                krb5_types::ascii(TEST_REALM),
                name.clone(),
                k.kvno,
                k.key.clone(),
            );
            match kt.as_mut() {
                Some(all) => all.entries.extend(one.entries),
                None => kt = Some(one),
            }
        }
    }
    let kt_path = dir.join("ka.keytab");
    kt.expect("keys")
        .write_file(&kt_path)
        .expect("write keytab");
    let cases_path = dir.join("cases.tsv");
    std::fs::write(
        &cases_path,
        ok_stdout(&["kadmind", kt_path.to_str().expect("path"), TEST_USER]),
    )
    .expect("write");
    let cases = std::fs::read_to_string(&cases_path).expect("read");
    let n = cases.lines().count();
    let none = dir.join("none.tsv");
    std::fs::write(&none, "").expect("write");
    let run = |mit: &Path| {
        sweep(&[
            "judge-kdb",
            cases_path.to_str().expect("path"),
            mit.to_str().expect("path"),
            dump.to_str().expect("path"),
            MASTER_PASSWORD,
        ])
    };
    let answers: HashMap<String, String> =
        part_answers(&String::from_utf8(run(&none).stdout).expect("utf-8"))
            .into_iter()
            .collect();
    assert_eq!(answers.len(), n, "every case is answered, each id once");
    // noname|kadmin/admin|kadmin/changepw: MIT's `krb5_rd_req` with no server and with each name.
    let want = |id: &str, a: &str| assert_eq!(answers[id], a, "{id}");
    want("kadmin/admin", "0|0|krb5:35");
    want("kadmin/changepw", "0|krb5:35|0");
    want("kadmin/history", "0|krb5:35|krb5:35");
    want("host/testhost.kerber.test", "0|krb5:35|krb5:35");
    want("kadmin/admin/kvno0", "0|0|krb5:35");
    want("kadmin/admin/kvno99", "krb5:44|krb5:44|krb5:35");
    want("kadmin/admin/as=nosuch/service", "krb5:35|0|krb5:35");
    want("kadmin/admin/realm=OTHER.REALM", "krb5:35|0|krb5:35");
    want(
        "kadmin/admin/as=host/testhost.kerber.test",
        "krb5:31|0|krb5:35",
    );
    want("kadmin/admin/as=kadmin/changepw", "krb5:31|0|krb5:31");
    want("kadmin/changepw/as=kadmin/admin", "krb5:31|krb5:31|0");
    // A ticket sealed in a key after the first finds no permitted key, whatever name is asked for.
    for svc in [
        "kadmin/admin",
        "kadmin/changepw",
        "kadmin/history",
        "host/testhost.kerber.test",
    ] {
        for k in 1..=3 {
            want(
                &format!("{svc}/key{k}"),
                "other:-1780008418|other:-1780008418|other:-1780008418",
            );
        }
    }
    // MIT's answers, agreeing, are all `SAME`; one that differs is a `PART`.
    let mit = dir.join("mit.tsv");
    let rows = lines_of(
        answers
            .iter()
            .map(|(id, a)| format!("{id}\t{}", a.replace('|', "\t"))),
    );
    std::fs::write(&mit, &rows).expect("write");
    let out = run(&mit);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).expect("utf-8");
    assert_eq!(text.lines().filter(|l| l.starts_with("SAME")).count(), n);
    assert!(text.ends_with(&format!("0 of {n} cases part from MIT\n")));
    std::fs::write(
        &mit,
        rows.replacen(
            "kadmin/admin\t0\t0\tkrb5:35",
            "kadmin/admin\t0\tkrb5:35\tkrb5:35",
            1,
        ),
    )
    .expect("write");
    let out = run(&mit);
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8(out.stdout).expect("utf-8");
    assert!(
        text.contains("PART\tkadmin/admin\tMIT 0|krb5:35|krb5:35\tRust 0|0|krb5:35\n"),
        "{text}"
    );
    assert!(text.ends_with(&format!("1 of {n} cases part from MIT\n")));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A kadmind on a loopback socket over the documented realm (four keys on each service), stopped on drop.
struct Kadmind {
    addr: std::net::SocketAddr,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Kadmind {
    fn new(store: krb5_kdc::PrincipalStore, acl: krb5_kdc::Acl) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&stop);
        let shared = krb5_kdc::shared_dump(store);
        let thread = std::thread::spawn(move || {
            let mut kadmind = krb5_admin::Kadmind::new(
                shared,
                acl,
                None,
                krb5_protocol::AcceptorConfig::default(),
            );
            let rpc = [listener];
            let sockets = krb5_kdc::net_server::Sockets {
                rpc: &rpc,
                ..krb5_kdc::net_server::Sockets::default()
            };
            let _ = krb5_admin::serve_kadmind_until(
                &mut kadmind,
                &sockets,
                &flag,
                std::time::Duration::from_millis(20),
            );
        });
        Self {
            addr,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Kadmind {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// `kadmind-init` forges a ticket in one key of a service and makes an INIT call with it: the first key
/// of `kadmin/admin` completes the context, every later one is refused (over RPCSEC_GSS `AUTH_REJECTEDCRED`,
/// over AUTH_GSSAPI a `GSS_S_FAILURE` init_res), and the AUTH_GSSAPI credential of `kadmin/changepw` takes
/// its own first key. MIT's kadmind answers the same (`scripts/kadmin-mit-gate.sh`, `kadmin-rust-gate.sh`).
#[test]
fn kadmind_init_is_accepted_in_the_first_key_and_refused_in_a_later_one() {
    let dir = scratch("rd-sweep-kadmind-init");
    let (store, acl) = bootstrap_documented().expect("bootstrap");
    let mut kt: Option<krb5_protocol::Keytab> = None;
    for name in [kadmin_admin(), kadmin_changepw()] {
        for k in &store.get_name(&name).expect("service").keys {
            let one = krb5_protocol::Keytab::single(
                krb5_types::ascii(TEST_REALM),
                name.clone(),
                k.kvno,
                k.key.clone(),
            );
            match kt.as_mut() {
                Some(all) => all.entries.extend(one.entries),
                None => kt = Some(one),
            }
        }
    }
    let kt_path = dir.join("ka.keytab");
    kt.expect("keys")
        .write_file(&kt_path)
        .expect("write keytab");
    let served = Kadmind::new(store, acl);
    let addr = served.addr.to_string();
    let init = |opts: &[&str]| {
        let mut args = vec![
            "kadmind-init",
            addr.as_str(),
            kt_path.to_str().expect("path"),
            TEST_USER,
        ];
        args.extend_from_slice(opts);
        ok_stdout(&args)
    };
    for (flavor, refused) in [
        ("rpcsec", "DENIED auth_stat=2 AUTH_REJECTEDCRED"),
        ("agss", "ACCEPTED gss_major=851968 GSS_S_FAILURE handle=4B"),
    ] {
        let first = init(&[&format!("flavor={flavor}")]);
        assert!(
            first.contains(&format!(
                "flavor={flavor}: ACCEPTED gss_major=0 GSS_S_COMPLETE "
            )),
            "{first}"
        );
        for later in 1..4 {
            let line = init(&[&format!("entry={later}"), &format!("flavor={flavor}")]);
            assert!(
                line.contains(&format!("entry={later} etype="))
                    && line
                        .trim_end()
                        .ends_with(&format!("flavor={flavor}: {refused}")),
                "{line}"
            );
        }
    }
    let changepw = init(&["service=kadmin/changepw", "flavor=agss"]);
    assert!(changepw.contains("ACCEPTED gss_major=0 "), "{changepw}");
    let out = sweep(&[
        "kadmind-init",
        addr.as_str(),
        kt_path.to_str().expect("path"),
        TEST_USER,
        "entry=9",
    ]);
    assert_eq!(out.status.code(), Some(2), "a key the keytab lacks");
    let _ = std::fs::remove_dir_all(&dir);
}
