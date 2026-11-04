//! Units for the `kadmin.local` session: the verbs' texts, the prompts, the `ss` loop and the stdio. The command line and the exit status run as a process in `tests/cli_stdin.rs`; the texts are MIT 1.22.2's own, settled live for the same commands.

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
            ctx: krb5_config::ClientContext::default(),
        };
        Self {
            out,
            err,
            io,
            h: Some(h),
        }
    }

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

    fn listen(&mut self) -> (String, String) {
        let (out, err) = self.listen_bytes();
        (out, String::from_utf8_lossy(&err).into_owned())
    }

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

/// MIT `kadm5_create_principal_3`: `passwd_check` runs before the entry exists, so a refused password creates nothing; `-randkey` skips it.
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
