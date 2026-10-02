//! Units for the `kadmin.local` session: the verbs' texts, the prompts, the `ss` loop and the
//! stdio. The command line and the exit status run as a process in `tests/cli_stdin.rs`; the
//! texts are MIT 1.22.2's own, settled live for the same commands.

use std::cell::RefCell;
use std::io::{self, Write};
use std::rc::Rc;

use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented};
use krb5_types::PrincipalName;

use super::*;

#[derive(Clone, Default)]
struct Capture(Rc<RefCell<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Capture {
    fn take(&self) -> String {
        String::from_utf8_lossy(&self.take_bytes()).into_owned()
    }

    fn take_bytes(&self) -> Vec<u8> {
        std::mem::take(&mut *self.0.borrow_mut())
    }
}

/// Input that hands out its parts in turn: bytes, or a caught `SIGINT` where MIT's handler
/// would run.
struct Script(std::collections::VecDeque<Option<Vec<u8>>>);

impl Script {
    fn new(parts: &[Option<&[u8]>]) -> Self {
        Self(parts.iter().map(|p| p.map(<[u8]>::to_vec)).collect())
    }
}

impl io::Read for Script {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = {
            let have = io::BufRead::fill_buf(self)?;
            let n = have.len().min(out.len());
            out[..n].copy_from_slice(&have[..n]);
            n
        };
        io::BufRead::consume(self, n);
        Ok(n)
    }
}

impl io::BufRead for Script {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        while self
            .0
            .front()
            .is_some_and(|p| p.as_ref().is_some_and(Vec::is_empty))
        {
            self.0.pop_front();
        }
        if matches!(self.0.front(), Some(None)) {
            self.0.pop_front();
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                krb5_cli::Caught(krb5_cli::Signal::SIGINT),
            ));
        }
        Ok(self.0.front().and_then(Option::as_deref).unwrap_or(&[]))
    }

    fn consume(&mut self, n: usize) {
        if let Some(Some(bytes)) = self.0.front_mut() {
            bytes.drain(..n.min(bytes.len()));
        }
    }
}

/// Input whose first line, once read, is followed by a real `SIGINT`: Ctrl-C while that line's
/// request runs.
struct SigintAfterLine {
    bytes: &'static [u8],
    raised: bool,
}

impl io::Read for SigintAfterLine {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.bytes.len().min(out.len());
        out[..n].copy_from_slice(&self.bytes[..n]);
        io::BufRead::consume(self, n);
        Ok(n)
    }
}

impl io::BufRead for SigintAfterLine {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Ok(self.bytes)
    }

    fn consume(&mut self, n: usize) {
        let (taken, rest) = self.bytes.split_at(n.min(self.bytes.len()));
        self.bytes = rest;
        if !self.raised && taken.contains(&b'\n') {
            self.raised = true;
            nix::sys::signal::raise(krb5_cli::Signal::SIGINT).unwrap();
        }
    }
}

struct Rig {
    out: Capture,
    err: Capture,
    io: Io,
    h: Option<Handle>,
}

impl Rig {
    fn new(input: &str) -> Self {
        let (store, _) = bootstrap_documented().unwrap();
        Self::with_store(store, input.as_bytes())
    }

    fn with_store(store: PrincipalStore, input: &[u8]) -> Self {
        let out = Capture::default();
        let err = Capture::default();
        let io = Io {
            out: Stdout::new(Box::new(out.clone()), false),
            err: Box::new(err.clone()),
            input: Box::new(io::Cursor::new(input.to_vec())),
            tty_in: false,
            script_mode: false,
            exit_status: 0,
            interrupted: false,
        };
        let h = Handle {
            store,
            realm: TEST_REALM.to_owned(),
            caller: format!("root/admin@{TEST_REALM}"),
            open: Open {
                db: PathBuf::from("/nonexistent/principal"),
                stash: PathBuf::from("/nonexistent/stash"),
                conf: None,
                keysalts: Vec::new(),
                typed: None,
                stamp: None,
            },
        };
        Self {
            out,
            err,
            io,
            h: Some(h),
        }
    }

    /// One `-q` line; (stdout, stderr).
    fn q(&mut self, line: &str) -> (String, String) {
        let mut s = Session {
            io: &mut self.io,
            h: self.h.take().unwrap(),
            locked: false,
            abort: false,
        };
        if let Some(ss::Unrun::NotFound { lead, word }) = ss::execute_line(&mut s, line) {
            ss::perror(s.io, ss::COMMAND_NOT_FOUND, &format!("{lead}{word}"));
        }
        self.h = Some(s.h);
        let _ = self.io.out.flush();
        (self.out.take(), self.err.take())
    }

    /// The interactive loop over the rig's input; (stdout, stderr).
    fn listen(&mut self) -> (String, String) {
        let (out, err) = self.listen_bytes();
        (out, String::from_utf8_lossy(&err).into_owned())
    }

    /// [`Self::listen`] with stderr as the bytes written.
    fn listen_bytes(&mut self) -> (String, Vec<u8>) {
        let mut s = Session {
            io: &mut self.io,
            h: self.h.take().unwrap(),
            locked: false,
            abort: false,
        };
        ss::listen(&mut s);
        self.h = Some(s.h);
        let _ = self.io.out.flush();
        (self.out.take(), self.err.take_bytes())
    }

    fn store(&self) -> &PrincipalStore {
        &self.h.as_ref().unwrap().store
    }

    /// A rig on the documented realm saved in a scratch directory, opened as `kadmin.local`
    /// opens a database: a change is written there, and a failed one read back from it.
    fn on_disk(tag: &str) -> (Self, PathBuf) {
        let dir = krb5_testkit::scratch_dir(tag);
        let _ = std::fs::create_dir_all(&dir);
        let (db, stash) = (dir.join("principal"), dir.join("stash"));
        let (store, _) = bootstrap_documented().unwrap();
        krb5_kdc::save_store(&store, &db, &stash).unwrap();
        let mut rig = Self::with_store(krb5_kdc::load_store(&db, &stash).unwrap(), b"");
        let open = &mut rig.h.as_mut().unwrap().open;
        open.db = db;
        open.stash = stash;
        (rig, dir)
    }
}

fn n(s: &str) -> PrincipalName {
    krb5_types::principal_from_unparsed(s, TEST_REALM)
        .unwrap()
        .0
}

#[test]
fn ss_parse_quotes_like_parse_c() {
    assert_eq!(
        ss::parse("addpol -maxlife \"1d \" tws").unwrap(),
        ["addpol", "-maxlife", "1d ", "tws"]
    );
    assert_eq!(ss::parse("addpol \"a\"\"b\"").unwrap(), ["addpol", "a\"b"]);
    assert_eq!(ss::parse("getpol \"\"").unwrap(), ["getpol", ""]);
    assert_eq!(ss::parse("  getpol\ttws  ").unwrap(), ["getpol", "tws"]);
    assert_eq!(
        ss::parse("getpol \"tws").unwrap_err(),
        "Unbalanced quotes in command line"
    );
}

#[test]
fn addprinc_texts_policy_notice_and_duplicate() {
    let mut r = Rig::new("");
    let (out, err) = r.q("addprinc -randkey svc1");
    assert_eq!(out, "Principal \"svc1@KERBER.TEST\" created.\n");
    assert_eq!(
        err,
        "No policy specified for svc1@KERBER.TEST; defaulting to no policy\n"
    );
    let (out, err) = r.q("addprinc -randkey svc1");
    assert_eq!(out, "");
    assert_eq!(
        err,
        "No policy specified for svc1@KERBER.TEST; defaulting to no policy\nadd_principal: \
         Principal or policy already exists while creating \"svc1@KERBER.TEST\".\n"
    );
    r.q("addpol default");
    let (_, err) = r.q("addprinc -randkey svc2");
    assert_eq!(
        err,
        "No policy specified for svc2@KERBER.TEST; assigning \"default\"\n"
    );
    assert_eq!(
        r.store().get_name(&n("svc2")).unwrap().pw_policy.as_deref(),
        Some("default")
    );
    let (_, err) = r.q("addprinc -randkey -clearpolicy svc3");
    assert_eq!(err, "");
    let (_, err) = r.q("addprinc -randkey -policy nopol svc4");
    assert_eq!(err, "WARNING: policy \"nopol\" does not exist\n");
}

#[test]
fn addprinc_prompts_twice_reads_the_reply_and_refuses_a_mismatch() {
    let mut r = Rig::new("pw-two\npw-two\npw-a\npw-b\n");
    let (out, _) = r.q("addprinc p2");
    assert_eq!(
        out,
        "Enter password for principal \"p2@KERBER.TEST\": \nRe-enter password for principal \
         \"p2@KERBER.TEST\": \nPrincipal \"p2@KERBER.TEST\" created.\n"
    );
    let (_, err) = r.q("addprinc p3");
    assert!(
        err.ends_with(
            "add_principal: Password mismatch while reading password for \"p3@KERBER.TEST\".\n"
        ),
        "{err}"
    );
    let (_, err) = r.q("addprinc p4");
    assert!(
        err.ends_with(
            "add_principal: Cannot read password while reading password for \"p4@KERBER.TEST\".\n"
        ),
        "{err}"
    );
    assert!(r.store().get_name(&n("p3")).is_none());
}

/// MIT `kadm5_create_principal_3`: `passwd_check` runs before the entry exists, so a refused
/// password creates nothing; `-randkey` skips it.
#[test]
fn addprinc_rejected_password_creates_no_principal() {
    let mut r = Rig::new("");
    r.q("addpol -minlength 8 p8");
    let (_, err) = r.q("addprinc -pw short -policy p8 pqshort");
    assert!(
        err.contains("Password is too short while creating"),
        "{err}"
    );
    r.q("addprinc -pw pqname -policy p8 pqname");
    let (_, err) = r.q("addprinc -pw \"\" nopolempty");
    assert!(
        err.contains("add_principal: Empty passwords are not allowed while creating"),
        "{err}"
    );
    r.q("addprinc -pw longenough -policy p8 pqok");
    r.q("addprinc -randkey -policy p8 pqrand");
    let st = r.store();
    assert!(st.get_name(&n("pqshort")).is_none(), "min_length");
    assert!(st.get_name(&n("pqname")).is_none(), "princ module");
    assert!(st.get_name(&n("nopolempty")).is_none(), "empty module");
    assert_eq!(
        st.get_name(&n("pqok")).unwrap().pw_policy.as_deref(),
        Some("p8")
    );
    assert!(
        st.get_name(&n("pqrand")).is_some(),
        "randkey skips passwd_check"
    );
}

#[test]
fn addprinc_options_and_usage() {
    let mut r = Rig::new("");
    r.q(
        "addprinc -randkey -kvno 5 -maxlife \"2 hours\" -maxrenewlife 7days -expire \"2030-01-01 \
         00:00:00 UTC\" +requires_preauth -allow_tix z1",
    );
    let p = r.store().get_name(&n("z1")).unwrap();
    assert!(p.keys.iter().all(|k| k.kvno == 5));
    assert_eq!((p.max_life, p.max_renewable_life), (7_200, 7 * 86_400));
    assert_eq!(p.expiration, 1_893_456_000);
    assert_eq!(
        p.attributes,
        krb5_kdc::KDB_REQUIRES_PRE_AUTH | krb5_kdc::KDB_DISALLOW_ALL_TIX
    );
    r.q("addprinc -nokey n1");
    assert!(r.store().get_name(&n("n1")).unwrap().keys.is_empty());
    let (out, err) = r.q("addprinc -bogus x1");
    assert_eq!(out, "");
    assert!(
        err.starts_with("usage: add_principal [options] principal\n"),
        "{err}"
    );
    let (_, err) = r.q("addprinc -randkey a@b@c");
    assert!(
        err.starts_with(
            "add_principal: Malformed representation of principal while parsing principal\n"
        ),
        "{err}"
    );
    let (_, err) = r.q("addprinc -x a=b -randkey x2");
    assert!(
        err.ends_with(
            "add_principal: Unsupported argument \"a=b\" for db2 while creating \
             \"x2@KERBER.TEST\".\n"
        ),
        "{err}"
    );
    assert!(r.store().get_name(&n("x2")).is_none());
}

#[test]
fn modprinc_prints_modified_and_applies_each_field() {
    let mut r = Rig::new("");
    let (out, _) = r.q("modprinc -maxrenewlife 7days user");
    assert_eq!(out, "Principal \"user@KERBER.TEST\" modified.\n");
    assert_eq!(
        r.store().get_name(&n("user")).unwrap().max_renewable_life,
        7 * 86_400
    );
    r.q("modprinc -allow_tix user");
    assert_ne!(
        r.store().get_name(&n("user")).unwrap().attributes & krb5_kdc::KDB_DISALLOW_ALL_TIX,
        0
    );
    r.q("modprinc +allow_tix user");
    assert_eq!(
        r.store().get_name(&n("user")).unwrap().attributes & krb5_kdc::KDB_DISALLOW_ALL_TIX,
        0
    );
    r.q("modprinc -kvno 7 user");
    assert!(
        r.store()
            .get_name(&n("user"))
            .unwrap()
            .keys
            .iter()
            .all(|k| k.kvno == 7)
    );
    let (_, err) = r.q("modprinc nosuch");
    assert_eq!(
        err,
        "modify_principal: Principal does not exist while getting \"nosuch@KERBER.TEST\".\n"
    );
    let (_, err) = r.q("modprinc -randkey user");
    assert!(err.starts_with("usage: modify_principal [options] principal\n"));
    let (_, err) = r.q("modprinc -expire bogus-date user");
    assert!(err.starts_with("Invalid date specification \"bogus-date\".\nusage:"));
    let (out, _) = r.q("modprinc user");
    assert_eq!(out, "Principal \"user@KERBER.TEST\" modified.\n");
}

#[test]
fn cpw_texts() {
    let mut r = Rig::new("pw-3\npw-3\npw-a\npw-b\n");
    let (out, _) = r.q("cpw -randkey user");
    assert_eq!(out, "Key for \"user@KERBER.TEST\" randomized.\n");
    let (out, _) = r.q("cpw -pw pw-new-1 user");
    assert_eq!(out, "Password for \"user@KERBER.TEST\" changed.\n");
    let (out, _) = r.q("cpw user");
    assert!(
        out.ends_with("Password for \"user@KERBER.TEST\" changed.\n"),
        "{out}"
    );
    let (_, err) = r.q("cpw user");
    assert_eq!(
        err,
        "change_password: Password mismatch while reading password for \"user@KERBER.TEST\".\n"
    );
    let (_, err) = r.q("cpw -randkey nosuch");
    assert_eq!(
        err,
        "change_password: Principal does not exist while randomizing key for \
         \"nosuch@KERBER.TEST\".\n"
    );
    let (_, err) = r.q("cpw");
    assert_eq!(
        err,
        format!(
            "change_password: missing principal name\n{}",
            texts::CPW_USAGE
        )
    );
    let (_, err) = r.q("cpw -bogus user");
    assert_eq!(
        err,
        format!(
            "change_password: unrecognized option -bogus\n{}",
            texts::CPW_USAGE
        )
    );
    r.q("cpw -randkey -keepold -e aes128-cts-hmac-sha1-96:normal user");
    let p = r.store().get_name(&n("user")).unwrap();
    let top = p.keys.iter().map(|k| k.kvno).max().unwrap();
    let newest: Vec<_> = p.keys.iter().filter(|k| k.kvno == top).collect();
    assert_eq!(newest.len(), 1);
    assert_eq!(
        newest[0].etype,
        krb5_crypto::EncryptionType::Aes128CtsHmacSha196
    );
    assert!(
        p.keys.iter().any(|k| k.kvno < top),
        "-keepold keeps the old keys"
    );
}

/// MIT `kdb_get_hist_key` creates `kadmin/history` with its own committed puts before
/// `passwd_check`, settled live: a `cpw` refused for its length still leaves it in the database.
#[test]
fn cpw_refused_for_quality_keeps_kadmin_history() {
    let (mut r, dir) = Rig::on_disk("kadmin-local-hist");
    r.q("addpol -minlength 8 -history 2 hpol");
    r.q("addprinc -pw hist-initial-secret -policy hpol hu");
    let (_, err) = r.q("cpw -pw sh hu");
    assert_eq!(
        err,
        "change_password: Password is too short while changing password for \
         \"hu@KERBER.TEST\".\n"
    );
    let (out, _) = r.q("getprinc kadmin/history");
    assert!(
        out.contains("Principal: kadmin/history@KERBER.TEST\n"),
        "{out}"
    );
    let on_disk = krb5_kdc::load_store(&dir.join("principal"), &dir.join("stash")).unwrap();
    assert!(
        on_disk
            .get_name(&krb5_kdc::principals::kadmin_history())
            .is_some()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn getprinc_and_terse() {
    let mut r = Rig::new("");
    let (out, _) = r.q("getprinc user");
    assert!(out.starts_with("Principal: user@KERBER.TEST\n"), "{out}");
    assert!(out.ends_with("Policy: [none]\n"), "{out}");
    let first_vno = out.lines().find(|l| l.contains("vno")).unwrap();
    assert!(first_vno.starts_with("Key: vno "), "{first_vno}");
    let (out, _) = r.q("getprinc -terse user");
    assert!(out.starts_with("\"user@KERBER.TEST\"\t"), "{out}");
    assert_eq!(out.matches('\n').count(), 1);
    let (_, err) = r.q("getprinc nosuch");
    assert_eq!(
        err,
        "get_principal: Principal does not exist while retrieving \"nosuch@KERBER.TEST\".\n"
    );
    let (_, err) = r.q("getprinc a b c");
    assert_eq!(err, "usage: get_principal [-terse] principal\n");
}

#[test]
fn getprinc_incoming_trust_uses_foreign_realm_id() {
    let (mut store, acl) = bootstrap_documented().unwrap();
    let key = krb5_crypto::ProtocolKey::from_bytes(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        &[0x11u8; 32],
    )
    .unwrap();
    store
        .create_interrealm_key(
            &acl,
            &krb5_kdc::testrealm::documented_admin_id(),
            "AD.KERBER.TEST",
            key,
        )
        .unwrap();
    let mut r = Rig::with_store(store, b"");
    let (out, err) = r.q("getprinc krbtgt/KERBER.TEST@AD.KERBER.TEST");
    assert_eq!(err, "");
    assert!(
        out.starts_with("Principal: krbtgt/KERBER.TEST@AD.KERBER.TEST\n"),
        "{out}"
    );
}

#[test]
fn delete_prompts_unless_forced() {
    let mut r = Rig::new("no\nyes\n");
    r.q("addpol keep");
    let (out, err) = r.q("delpol keep");
    assert_eq!(
        out,
        "Are you sure you want to delete the policy \"keep\"? (yes/no): "
    );
    assert_eq!(err, "Policy \"keep\" not deleted.\n");
    assert!(r.store().policies().contains_key("keep"));
    r.q("delpol keep");
    assert!(!r.store().policies().contains_key("keep"));
    let (_, err) = r.q("delpol -force nosuch");
    assert_eq!(
        err,
        "delete_policy:: Policy does not exist while deleting policy \"nosuch\"\n"
    );
    let (_, err) = r.q("delprinc user");
    assert_eq!(err, "Principal \"user@KERBER.TEST\" not deleted\n");
    let (out, _) = r.q("delprinc -force user");
    assert_eq!(
        out,
        "Principal \"user@KERBER.TEST\" deleted.\nMake sure that you have removed this \
         principal from all ACLs before reusing.\n"
    );
    let (_, err) = r.q("delprinc -force K/M");
    assert_eq!(
        err,
        "delete_principal: Cannot change protected principal while deleting principal \
         \"K/M@KERBER.TEST\"\n"
    );
    let (_, err) = r.q("delprinc -force a b");
    assert_eq!(err, "usage: delete_principal [-force] principal\n");
}

#[test]
fn script_mode_asks_nothing_and_counts_errors() {
    let mut r = Rig::new("");
    r.io.script_mode = true;
    let (out, err) = r.q("addprinc -randkey sm1");
    assert_eq!((out.as_str(), err.as_str()), ("", ""));
    assert_eq!(r.io.exit_status, 0);
    r.q("delprinc sm1");
    assert!(
        r.store().get_name(&n("sm1")).is_none(),
        "no question in script mode"
    );
    let (_, err) = r.q("getprinc nosuch");
    assert!(err.starts_with("get_principal: Principal does not exist"));
    assert_eq!(r.io.exit_status, 1);
}

#[test]
fn quoted_interval_keeps_trailing_whitespace() {
    let mut r = Rig::new("");
    r.q("addpol -maxlife \"1d \" tws");
    assert_eq!(r.store().policies().get("tws").unwrap().pw_max_life, 86_400);
    let (_, err) = r.q("addpol -maxlife \"42 \" tws2");
    assert!(
        err.starts_with(
            "Invalid date specification \"42 \".\nusage; add_policy [options] policy\n"
        ),
        "{err}"
    );
    assert!(!r.store().policies().contains_key("tws2"));
}

#[test]
fn policy_verbs_and_getpol_layouts() {
    let mut r = Rig::new("");
    r.q(
        "addpol -minlength 8 -minclasses 2 -history 3 -maxlife \"30 days\" -minlife 1h \
         -maxfailure 5 -failurecountinterval 60s -lockoutduration 10m -allowedkeysalts \
         aes256-cts-hmac-sha1-96:normal pfull",
    );
    let (out, _) = r.q("getpol pfull");
    assert_eq!(
        out,
        "Policy: pfull\nMaximum password life: 30 days 00:00:00\nMinimum password life: 0 \
         days 01:00:00\nMinimum password length: 8\nMinimum number of password character \
         classes: 2\nNumber of old keys kept: 3\nMaximum password failures before lockout: \
         5\nPassword failure count reset interval: 0 days 00:01:00\nPassword lockout \
         duration: 0 days 00:10:00\nAllowed key/salt types: aes256-cts-hmac-sha1-96:normal\n"
    );
    let (out, _) = r.q("getpol -terse pfull");
    assert_eq!(
        out,
        "\"pfull\"\t2592000\t3600\t8\t2\t3\t0\t5\t60\t600\taes256-cts-hmac-sha1-96:normal\n"
    );
    let (_, err) = r.q("addpol pfull");
    assert_eq!(
        err,
        "add_policy: Principal or policy already exists while creating policy \"pfull\".\n"
    );
    let (_, err) = r.q("addpol");
    assert!(
        err.starts_with("add_policy: parser lost count!\nusage; add_policy"),
        "{err}"
    );
    r.q("modpol -allowedkeysalts - pfull");
    assert_eq!(
        r.store().policies().get("pfull").unwrap().allowed_keysalts,
        None
    );
    let (_, err) = r.q("modpol -minlength 10 nosuch");
    assert_eq!(
        err,
        "modify_policy: Policy does not exist while modifying policy \"nosuch\".\n"
    );
    let (out, _) = r.q("listpols p*");
    assert_eq!(out, "pfull\n");
}

#[test]
fn ktadd_honours_e_and_reports_each_entry() {
    let dir = krb5_testkit::scratch_dir("kadmin-cli-ktadd");
    let _ = std::fs::create_dir_all(&dir);
    let kt = dir.join("kt");
    let mut r = Rig::new("");
    r.q("addprinc -randkey HTTP/kc.kerber.test");
    let before = r.store().get_name(&n("HTTP/kc.kerber.test")).unwrap().keys[0].kvno;
    let (out, err) = r.q(&format!(
        "ktadd -k {} -e aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal \
         HTTP/kc.kerber.test@KERBER.TEST",
        kt.display()
    ));
    assert_eq!(err, "");
    let want = |e: &str| {
        format!(
            "Entry for principal HTTP/kc.kerber.test@KERBER.TEST with kvno {}, encryption \
             type {e} added to keytab WRFILE:{}.\n",
            before + 1,
            kt.display()
        )
    };
    assert_eq!(
        out,
        want("aes256-cts-hmac-sha1-96") + &want("aes128-cts-hmac-sha1-96")
    );
    let tab = krb5_protocol::Keytab::parse(&std::fs::read(&kt).unwrap()).unwrap();
    assert_eq!(tab.entries.len(), 2);
    assert!(tab.entries.iter().all(|e| e.kvno == before + 1));
    let (_, err) = r.q(&format!("ktadd -k {} nosuch", kt.display()));
    assert_eq!(err, "kadmin.local: Principal nosuch does not exist.\n");
    let (_, err) = r.q(&format!(
        "ktadd -k {} -norandkey -e aes128-cts-hmac-sha1-96 user",
        kt.display()
    ));
    assert_eq!(err, "cannot specify keysaltlist when not changing key\n");
    let (out, err) = r.q(&format!("ktadd -k {} -glob us*", kt.display()));
    assert!(
        out.contains("Entry for principal user@KERBER.TEST with kvno"),
        "{out}"
    );
    assert_eq!(err, "kadmin.local: Principal us* does not exist.\n");
    let (out, _) = r.q(&format!("ktremove -k {} HTTP/kc.kerber.test", kt.display()));
    assert_eq!(out.lines().count(), 2, "{out}");
    let (_, err) = r.q(&format!(
        "ktremove -k {} HTTP/kc.kerber.test all",
        kt.display()
    ));
    assert_eq!(
        err,
        format!(
            "kadmin.local: No entry for principal HTTP/kc.kerber.test exists in keytab \
             WRFILE:{}\n",
            kt.display()
        )
    );
    let (_, err) = r.q(&format!("ktremove -k {}/none user", dir.display()));
    assert_eq!(
        err,
        format!(
            "kadmin.local: Keytab WRFILE:{}/none does not exist.\n",
            dir.display()
        )
    );
    let (_, err) = r.q("ktadd");
    assert_eq!(err, texts::KTADD_USAGE);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ktadd_refuses_an_unparseable_keytab_and_keeps_it() {
    let dir = krb5_testkit::scratch_dir("kadmin-cli-kt-refuse");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("bad.keytab");
    std::fs::write(&path, b"not-a-keytab").unwrap();
    let mut r = Rig::new("");
    let (_, err) = r.q(&format!("ktadd -k {} -norandkey user", path.display()));
    assert!(err.ends_with("while adding key to keytab\n"), "{err}");
    assert_eq!(std::fs::read(&path).unwrap(), b"not-a-keytab");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn strings_purgekeys_rename_alias_privs() {
    let mut r = Rig::new("");
    let (out, _) = r.q("setstr user k1 v1");
    assert_eq!(out, "Attribute set for principal \"user@KERBER.TEST\".\n");
    let (out, _) = r.q("getstrs user");
    assert_eq!(out, "k1: v1\n");
    let (out, _) = r.q("delstr user k1");
    assert_eq!(
        out,
        "Attribute removed from principal \"user@KERBER.TEST\".\n"
    );
    let (out, _) = r.q("getstrs user");
    assert_eq!(out, "(No string attributes.)\n");
    let (_, err) = r.q("setstr nosuch k v");
    assert_eq!(
        err,
        "set_string: Principal does not exist while setting attribute on principal \
         \"nosuch@KERBER.TEST\"\n"
    );
    r.q("cpw -randkey -keepold user");
    let (out, _) = r.q("purgekeys user");
    assert_eq!(out, "Old keys for principal \"user@KERBER.TEST\" purged.\n");
    let (out, _) = r.q("purgekeys -all user");
    assert_eq!(
        out,
        "All keys for principal \"user@KERBER.TEST\" removed.\n"
    );
    assert!(r.store().get_name(&n("user")).unwrap().keys.is_empty());
    r.q("addprinc -randkey old1");
    let (out, _) = r.q("renprinc -force old1 new1");
    assert_eq!(
        out,
        "Principal \"old1@KERBER.TEST\" renamed to \"new1@KERBER.TEST\".\nMake sure that you \
         have removed the old principal from all ACLs before reusing.\n"
    );
    let (_, err) = r.q("renprinc -force nosuch x");
    assert_eq!(
        err,
        "rename_principal: No such entry in the database while renaming principal \
         \"nosuch@KERBER.TEST\" to \"x@KERBER.TEST\"\n"
    );
    let (out, _) = r.q("alias al1 new1");
    assert_eq!(
        out,
        "Principal \"al1@KERBER.TEST\" aliased to \"new1@KERBER.TEST\".\n"
    );
    let (out, _) = r.q("getprivs");
    assert_eq!(out, "current privileges: INQUIRE ADD MODIFY DELETE\n");
}

#[test]
fn listen_prompts_and_reports_unknown_requests() {
    let mut r = Rig::new("nosuch x\n\n# c\nlistprincs us*\nq\nlistprincs\n");
    let (out, err) = r.listen();
    assert_eq!(
        out,
        "kadmin.local:  kadmin.local:  kadmin.local:  kadmin.local:  user@KERBER.TEST\n\
         kadmin.local:  "
    );
    assert_eq!(
        err,
        "kadmin.local: Unknown request \"nosuch\".  Type \"?\" for a request list.\n\
         kadmin.local: Unknown request \"#\".  Type \"?\" for a request list.\n"
    );
    assert_eq!(r.io.exit_status, 0);
}

#[test]
fn listen_reads_a_line_that_is_not_utf8() {
    let (store, _) = bootstrap_documented().unwrap();
    let mut r = Rig::with_store(store, b"\xff\nlistprincs us*\nq\n");
    let (out, err) = r.listen_bytes();
    assert_eq!(
        out,
        "kadmin.local:  kadmin.local:  user@KERBER.TEST\nkadmin.local:  "
    );
    assert_eq!(
        err,
        b"kadmin.local: Unknown request \"\xff\".  Type \"?\" for a request list.\n"
    );
    assert_eq!(r.io.exit_status, 0);
}

#[test]
fn a_request_line_that_is_not_utf8_is_refused_whole() {
    let (store, _) = bootstrap_documented().unwrap();
    let mut r = Rig::with_store(store, b"addprinc -randkey caf\xe9\nq\n");
    let (out, err) = r.listen();
    assert_eq!(out, "kadmin.local:  kadmin.local:  ");
    assert_eq!(
        err,
        "kadmin.local: Request line is not valid UTF-8; it was not run.\n"
    );
    assert!(r.store().ids().iter().all(|id| !id.starts_with("caf")));
}

#[test]
fn sigint_at_the_prompt_prints_a_newline_and_prompts_again() {
    let mut r = Rig::new("");
    r.io.input = Box::new(Script::new(&[
        None,
        None,
        Some(b"listprincs us*\n"),
        Some(b"q\n"),
    ]));
    let (out, err) = r.listen();
    assert_eq!(
        out,
        "kadmin.local:  \nkadmin.local:  \nkadmin.local:  user@KERBER.TEST\nkadmin.local:  "
    );
    assert_eq!(err, "");
    assert_eq!(r.io.exit_status, 0);
}

#[test]
fn sigint_while_a_request_runs_is_a_newline_before_the_next_prompt() {
    let mut r = Rig::new("");
    r.io.input = Box::new(SigintAfterLine {
        bytes: b"listprincs us*\nq\n",
        raised: false,
    });
    let (out, err) = r.listen();
    assert_eq!(out, "kadmin.local:  user@KERBER.TEST\n\nkadmin.local:  ");
    assert_eq!(err, "");
}

#[test]
fn sigint_at_a_confirmation_drops_the_request_quietly() {
    let mut r = Rig::new("");
    r.io.input = Box::new(Script::new(&[
        Some(b"delprinc user\n"),
        None,
        Some(b"listprincs us*\n"),
        Some(b"q\n"),
    ]));
    let (out, err) = r.listen();
    assert_eq!(
        out,
        "kadmin.local:  Are you sure you want to delete the principal \"user@KERBER.TEST\"? \
         (yes/no): \nkadmin.local:  user@KERBER.TEST\nkadmin.local:  "
    );
    assert_eq!(err, "");
}

#[test]
fn sigint_at_a_password_prompt_is_an_interrupted_read() {
    let mut r = Rig::new("");
    r.io.input = Box::new(Script::new(&[
        Some(b"addprinc pz1\n"),
        None,
        Some(b"listprincs pz*\n"),
        Some(b"q\n"),
    ]));
    let (out, err) = r.listen();
    assert_eq!(
        out,
        "kadmin.local:  Enter password for principal \"pz1@KERBER.TEST\": \nkadmin.local:  \
         kadmin.local:  "
    );
    assert!(
        err.ends_with(
            "add_principal: Password read interrupted while reading password for \
             \"pz1@KERBER.TEST\".\n"
        ),
        "{err}"
    );
}

#[test]
fn keytab_names_resolve_as_krb5_kt_resolve_reads_them() {
    use kt_cmds::{KtType, resolve};
    fn kind(name: &str) -> Result<(&'static str, &str), &'static str> {
        resolve(name).map(|(ty, residual)| (ty.prefix(), residual))
    }
    assert_eq!(kind("/s/kt/a:b"), Ok(("FILE", "/s/kt/a:b")));
    assert_eq!(kind("X:y"), Ok(("FILE", "X:y")));
    assert_eq!(kind("kt/plain"), Ok(("FILE", "kt/plain")));
    assert_eq!(kind("WRFILE:kt/w"), Ok(("WRFILE", "kt/w")));
    assert_eq!(kind("MEMORY:m1"), Ok(("MEMORY", "m1")));
    assert_eq!(kind("kt/a:b"), Err("Unknown Key table type"));
    assert_eq!(kind("BOGUS:/x"), Err("Unknown Key table type"));
    assert!(matches!(resolve("FILE:x"), Ok((KtType::File, "x"))));
    let (_, err) = Rig::new("").q("ktadd -k BOGUS:/x user");
    assert_eq!(
        err,
        "kadmin.local: Unknown Key table type while resolving keytab BOGUS:/x\n"
    );
}

#[test]
fn query_escape_and_unknown_command() {
    let mut r = Rig::new("");
    let (_, err) = r.q("nosuchcmd arg");
    assert_eq!(err, "kadmin.local: Command not found nosuchcmd\n");
    let mut s = Session {
        io: &mut r.io,
        h: r.h.take().unwrap(),
        locked: false,
        abort: false,
    };
    assert!(matches!(
        ss::execute_line(&mut s, "!echo x"),
        Some(ss::Unrun::EscapeDisabled)
    ));
    assert!(ss::execute_line(&mut s, "listprincs \"x").is_none());
    let _ = s.io.out.flush();
    assert_eq!(
        r.err.take(),
        "kadmin.local: Unbalanced quotes in command line\n"
    );
}

#[test]
fn list_requests_is_mit_s_table() {
    let mut r = Rig::new("");
    let (out, _) = r.q("?");
    assert!(
        out.starts_with(
            "Available kadmin.local requests:\n\nadd_principal, addprinc, ank\n                \
             \x20        Add principal\n"
        ),
        "{out}"
    );
    assert!(
        out.contains("\nget_principal, getprinc  Get principal\n"),
        "{out}"
    );
    assert!(
        out.ends_with("\nquit, exit, q            Exit program.\n"),
        "{out}"
    );
}

#[test]
fn stdout_is_buffered_like_c_stdio() {
    let raw = Capture::default();
    let mut block = Stdout::new(Box::new(raw.clone()), false);
    block.write_all(b"a\nb").unwrap();
    assert_eq!(raw.take(), "", "a pipe buffers by block");
    block.flush().unwrap();
    assert_eq!(raw.take(), "a\nb");
    let mut line = Stdout::new(Box::new(raw.clone()), true);
    line.write_all(b"a\nb").unwrap();
    assert_eq!(raw.take(), "a\n", "a terminal flushes each line");
    line.write_raw(b"raw ");
    line.flush().unwrap();
    assert_eq!(raw.take(), "raw b", "a child's output passes the buffer");
}

#[test]
fn keysalt_lists_skip_what_mit_skips() {
    use krb5_crypto::EncryptionType as E;
    let sep = [',', ' ', '\t'];
    assert_eq!(
        string_to_keysalts(
            "aes256-cts-hmac-sha1-96:normal,aes128-cts-hmac-sha1-96:normal",
            &sep
        ),
        [E::Aes256CtsHmacSha196, E::Aes128CtsHmacSha196]
    );
    assert_eq!(
        string_to_keysalts("aes256-cts", &sep),
        [E::Aes256CtsHmacSha196]
    );
    assert_eq!(string_to_keysalts("nosuch:normal", &sep), []);
    assert_eq!(string_to_keysalts("aes256-cts:bogus", &sep), []);
    assert_eq!(
        string_to_keysalts("AES256-CTS-HMAC-SHA1-96:NORMAL,aes128-cts:NoRealm", &sep),
        [E::Aes256CtsHmacSha196, E::Aes128CtsHmacSha196]
    );
    assert_eq!(atoi(" -12x"), -12);
    assert_eq!(atoi("abc"), 0);
}

#[test]
fn db2_arguments_like_configure_context() {
    assert!(matches!(db2_arg("dbname=/x"), Db2Arg::DbName("/x")));
    assert!(matches!(db2_arg("temporary"), Db2Arg::Other));
    assert!(matches!(db2_arg("bogus"), Db2Arg::Unsupported));
    assert!(matches!(db2_arg("a=b"), Db2Arg::Unsupported));
}

#[test]
fn default_principal_from_the_ccache_is_its_first_name_slash_admin() {
    let dir = krb5_testkit::scratch_dir("kadmin-cli-cc");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("cc");
    let realm = krb5_types::try_ascii("OTHER.TEST").unwrap();
    krb5_protocol::FileCcache::new((realm, n("alice/x")), Vec::new())
        .write_file(&path)
        .unwrap();
    let cc = krb5_config::CcSpec::File(path);
    let o = Opts::default();
    assert_eq!(
        default_princstr(&o, TEST_REALM, Some(&cc), None).as_deref(),
        Some("alice/admin@OTHER.TEST")
    );
    let anon = Opts {
        use_anonymous: true,
        ..Opts::default()
    };
    assert_eq!(
        default_princstr(&anon, TEST_REALM, Some(&cc), None).as_deref(),
        Some("WELLKNOWN/ANONYMOUS@KERBER.TEST")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn startup_refuses_conflicting_options_like_mit() {
    let (mut io, out, err) = {
        let r = Rig::new("");
        (r.io, r.out, r.err)
    };
    let argv = |a: &[&str]| -> Vec<String> {
        std::iter::once("kadmin.local")
            .chain(a.iter().copied())
            .map(str::to_owned)
            .collect()
    };
    assert!(startup(&argv(&["-c", "x", "-k"]), &mut io).is_none());
    assert_eq!(err.take(), texts::startup_usage(WHOAMI));
    assert!(startup(&argv(&["-q", "listprincs", "extra"]), &mut io).is_none());
    assert_eq!(
        err.take(),
        format!(
            "kadmin.local: -q is exclusive with command-line query{}",
            texts::startup_usage(WHOAMI)
        )
    );
    assert!(startup(&argv(&["-Z"]), &mut io).is_none());
    assert_eq!(
        err.take(),
        format!(
            "kadmin.local: invalid option -- 'Z'\n{}",
            texts::startup_usage(WHOAMI)
        )
    );
    assert_eq!(out.take(), "");
}
