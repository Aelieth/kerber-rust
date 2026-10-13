//! `PasswordCell`: the password is read when a module wants the key, kept once it is read, and not
//! kept when the read fails.

use std::collections::VecDeque;
use std::io::ErrorKind;

use super::*;

/// A prompter answering from a script: `Ok(text)`, or an error of that kind.
struct Script {
    reads: VecDeque<Result<&'static [u8], ErrorKind>>,
    asked: usize,
}

impl Script {
    fn new(reads: &[Result<&'static [u8], ErrorKind>]) -> Self {
        Self {
            reads: reads.iter().copied().collect(),
            asked: 0,
        }
    }
}

impl AsPrompt for Script {
    fn password(&mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.asked += 1;
        match self.reads.pop_front() {
            Some(Ok(text)) => Ok(Zeroizing::new(text.to_vec())),
            Some(Err(kind)) => Err(Error::File(std::io::Error::new(kind, "no reply"))),
            None => Err(Error::File(std::io::Error::other("Cannot read password"))),
        }
    }
}

#[test]
fn a_read_that_fails_holds_nothing_and_the_next_get_asks_again() {
    let mut ui = Script::new(&[Err(ErrorKind::Other), Ok(b"secret")]);
    let mut cell = PasswordCell::new(Some(&mut ui), b"", false);
    let f = cell.get().expect_err("the first read fails");
    assert_eq!(
        (f.code, f.text.as_str(), f.interrupted),
        (CANTREADPWD, "no reply", false)
    );
    assert_eq!(
        cell.get().expect("the second read works").as_slice(),
        b"secret"
    );
    drop(cell);
    assert_eq!(ui.asked, 2);
}

#[test]
fn a_read_that_worked_is_kept_and_not_asked_again() {
    let mut ui = Script::new(&[Ok(b"secret"), Ok(b"another")]);
    let mut cell = PasswordCell::new(Some(&mut ui), b"", false);
    assert_eq!(cell.get().unwrap().as_slice(), b"secret");
    assert_eq!(cell.get().unwrap().as_slice(), b"secret");
    drop(cell);
    assert_eq!(ui.asked, 1);
}

#[test]
fn an_interrupted_read_is_an_interrupt_with_the_codes_own_text() {
    let mut ui = Script::new(&[Err(ErrorKind::Interrupted)]);
    let mut cell = PasswordCell::new(Some(&mut ui), b"", false);
    let f = cell.get().expect_err("interrupted");
    assert!(f.interrupted);
    assert_eq!(f.code, PWDINTR);
    assert!(matches!(&f.error, Error::File(io) if io.kind() == ErrorKind::Interrupted));
}

#[test]
fn a_read_that_fails_is_a_message_the_exchange_reports_as_it_is() {
    let f = ModuleFail::from_read(Error::File(std::io::Error::other("Cannot read password")));
    assert_eq!(f.error.to_string(), "Cannot read password");
    assert_eq!(
        Error::PreauthFailed(Box::new(f.error)).to_string(),
        "Pre-authentication failed: Cannot read password"
    );
}

#[test]
fn the_responders_answer_is_the_password_with_no_prompt_and_stays_it() {
    let mut ui = Script::new(&[Ok(b"typed")]);
    let mut cell = PasswordCell::new(Some(&mut ui), b"", false);
    cell.offer(Some("answered"));
    assert_eq!(cell.get().unwrap().as_slice(), b"answered");
    // A later round's answer does not replace the password a module already used.
    cell.offer(Some("other"));
    assert_eq!(cell.get().unwrap().as_slice(), b"answered");
    drop(cell);
    assert_eq!(ui.asked, 0);
}

#[test]
fn a_round_with_no_answer_asks_the_prompter() {
    let mut ui = Script::new(&[Ok(b"typed")]);
    let mut cell = PasswordCell::new(Some(&mut ui), b"", false);
    cell.offer(Some("answered"));
    cell.offer(None);
    assert_eq!(cell.get().unwrap().as_slice(), b"typed");
}

#[test]
fn with_no_prompter_the_supplied_password_is_the_password() {
    let mut cell = PasswordCell::new(None, b"given", false);
    assert_eq!(cell.get().unwrap().as_slice(), b"given");
    assert_eq!(cell.get().unwrap().as_slice(), b"given");
}

#[test]
fn the_ui_of_a_cell_with_no_prompter_cannot_read() {
    let mut cell = PasswordCell::new(None, b"given", false);
    let e = cell.ui().password().expect_err("no prompter");
    assert_eq!(ModuleFail::from_read(e).code, CANTREADPWD);
}

#[test]
fn the_password_question_is_asked_until_a_module_holds_the_password() {
    let mut ui = Script::new(&[Ok(b"secret")]);
    let mut cell = PasswordCell::new(Some(&mut ui), b"", false);
    assert!(cell.asks_question());
    cell.offer(Some("answered"));
    assert!(
        cell.asks_question(),
        "an answer no module has used is not a held password"
    );
    cell.get().unwrap();
    assert!(
        !cell.asks_question(),
        "a held password is not asked for again"
    );
}

#[test]
fn a_keytab_or_a_supplied_password_without_a_prompter_asks_nothing() {
    let mut ui = Script::new(&[]);
    assert!(!PasswordCell::new(Some(&mut ui), b"", true).asks_question());
    assert!(!PasswordCell::new(None, b"given", false).asks_question());
    assert!(PasswordCell::new(None, b"", false).asks_question());
    assert!(PasswordCell::new(Some(&mut ui), b"given", false).asks_question());
}

#[test]
fn with_no_prompter_and_no_password_the_key_cannot_be_got() {
    let mut cell = PasswordCell::new(None, b"", false);
    let f = cell.get().expect_err("nothing to get a password from");
    assert_eq!(
        (f.code, f.text.as_str(), f.interrupted),
        (EIO, "Input/output error", false)
    );
    assert_eq!(
        Error::PreauthFailed(Box::new(f.error)).to_string(),
        "Pre-authentication failed: Input/output error"
    );
    assert!(
        cell.get().is_err(),
        "the empty password is not kept as a password"
    );
}

#[test]
fn a_responders_answer_is_the_password_when_there_is_no_prompter() {
    let mut cell = PasswordCell::new(None, b"", false);
    cell.offer(Some("answered"));
    assert_eq!(cell.get().unwrap().as_slice(), b"answered");
}

#[test]
fn a_failure_no_module_wraps_is_the_error_the_prompter_gave() {
    let read = ModuleFail::from_read(Error::File(std::io::Error::other("Cannot read password")));
    assert!(matches!(read.unwrapped(), Error::File(io)
            if io.kind() == ErrorKind::Other && io.to_string() == "Cannot read password"));
    let interrupt = ModuleFail::from_read(Error::File(std::io::Error::new(
        ErrorKind::Interrupted,
        "Password read interrupted",
    )));
    assert!(
        matches!(interrupt.unwrapped(), Error::File(io) if io.kind() == ErrorKind::Interrupted)
    );
    assert_eq!(
        ModuleFail::no_password().unwrapped().to_string(),
        "Input/output error"
    );
}

/// A keytab that could not be read fails every key a module or the reply asks of it with the
/// keytab's own error, asks the responder nothing, and never reads a password.
/// MIT `get_as_key_keytab` (`lib/krb5/krb/gic_keytab.c:68-71`): the lookup's error is the callback's, in its code and message.
#[test]
fn an_unreadable_keytab_fails_every_key_with_its_error_and_reads_no_password() {
    let failure = KeytabFailure {
        code: 2,
        text: "Key table file '/etc/none' not found".into(),
    };
    let mut ui = Script::new(&[Ok(b"never read")]);
    let mut cell =
        PasswordCell::new(Some(&mut ui), b"", true).with_unreadable_keytab(Some(&failure));
    assert!(!cell.asks_question());
    assert_eq!(cell.unreadable_keytab(), Some(&failure));
    for _ in 0..2 {
        let f = cell.get().expect_err("the keytab cannot be read");
        assert_eq!(
            (f.code, f.text.as_str(), f.interrupted),
            (2, "Key table file '/etc/none' not found", false)
        );
        assert_eq!(
            Error::PreauthFailed(Box::new(f.error.clone())).to_string(),
            "Pre-authentication failed: Key table file '/etc/none' not found"
        );
        assert!(
            matches!(f.unwrapped(), Error::Keytab { code: 2, ref text } if text == "Key table file '/etc/none' not found")
        );
    }
    drop(cell);
    assert_eq!(ui.asked, 0);
}
