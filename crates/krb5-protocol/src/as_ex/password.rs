//! The AS key callback of one AS exchange: a preauth module asks for the key when it needs it.
//!
//! MIT gives every clpreauth module `get_as_key`, which runs `krb5_get_as_key_password` when no key
//! is held yet. That prompts when no password has been read, and keeps the password it read. A
//! prompt that fails keeps nothing, so the next module that wants the key prompts again. With no
//! password, no responder answer and no prompter at all, the key cannot be got: `EIO`.

use std::io::ErrorKind;

use zeroize::Zeroizing;

use super::AsPrompt;
use super::responder::Responder;
use crate::error::Error;
use crate::trace::{self, ERROR_TABLE_BASE_KRB5};

/// MIT `KRB5_LIBOS_CANTREADPWD` (`krb5_err.et`): "Cannot read password".
pub(super) const CANTREADPWD: i64 = ERROR_TABLE_BASE_KRB5 + 130;
/// MIT `KRB5_LIBOS_PWDINTR` (`krb5_err.et`): "Password read interrupted".
pub(super) const PWDINTR: i64 = ERROR_TABLE_BASE_KRB5 + 132;
/// MIT `KRB5_PREAUTH_FAILED` (`krb5_err.et`): "Generic preauthentication failure".
pub(super) const KRB5_PREAUTH_FAILED: i64 = ERROR_TABLE_BASE_KRB5 + 210;
/// `EIO` (errno 5), whose message is "Input/output error".
pub(super) const EIO: i64 = 5;

/// How a real preauth module failed. An interrupted prompt stops every mechanism, any other failure
/// moves on to the next one.
/// MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:684-698`): a module's code is traced, and a keyboard interrupt ends the walk.
#[derive(Debug)]
pub(super) struct ModuleFail {
    /// The error for the caller.
    pub(super) error: Error,
    /// MIT's `krb5_error_code`, for the trace line `Preauth module <name> (<type>) (real) returned: <code>/<text>`.
    pub(super) code: i64,
    /// The message MIT has set for that code, for the same line.
    pub(super) text: String,
    /// `KRB5_LIBOS_PWDINTR`.
    pub(super) interrupted: bool,
}

impl ModuleFail {
    /// A failure with MIT's `code` and its message.
    pub(super) fn new(code: i64, text: &str) -> Self {
        Self {
            error: Error::Message(text.into()),
            code,
            text: text.into(),
            interrupted: false,
        }
    }

    /// A prompt that did not read: `KRB5_LIBOS_PWDINTR` for an interrupt, else
    /// `KRB5_LIBOS_CANTREADPWD` with the reader's message.
    /// MIT `krb5_prompter_posix` (`lib/krb5/os/prompter.c:93-100`): a reply that does not read is one of those two codes.
    pub(super) fn from_read(e: Error) -> Self {
        match e {
            Error::File(io) if io.kind() == ErrorKind::Interrupted => Self {
                text: io.to_string(),
                error: Error::File(io),
                code: PWDINTR,
                interrupted: true,
            },
            Error::File(io) => Self::new(CANTREADPWD, &io.to_string()),
            other => Self {
                text: other.to_string(),
                error: other,
                code: CANTREADPWD,
                interrupted: false,
            },
        }
    }

    /// A key wanted with no password to get it from: the caller gave none, the responder had no
    /// answer and there is no prompter to ask.
    /// MIT `krb5_get_as_key_password` (`lib/krb5/krb/gic_pwd.c:70-72`): `gp->password` is still NULL and the prompter is NULL, so `EIO`.
    pub(super) fn no_password() -> Self {
        Self::new(EIO, "Input/output error")
    }

    /// The failure as the exchange's own error, for a key that no module asked for (the reply's).
    /// A read that failed is the `Error::File` the prompter gave, as `Error::File` kinds tell an
    /// interrupt from the rest.
    /// MIT `decrypt_as_reply` (`lib/krb5/krb/get_in_tkt.c:115-123`): `gak_fct`'s error is returned as it is, not wrapped as a preauth failure.
    pub(super) fn unwrapped(self) -> Error {
        match self.error {
            Error::Message(_) if self.code == CANTREADPWD => {
                Error::File(std::io::Error::other(self.text))
            }
            other => other,
        }
    }

    /// Encrypted timestamp, which the realm disables: the module traces that it ignores the
    /// padata and fails with `KRB5_PREAUTH_FAILED` and that message.
    /// MIT `encts_process` (`lib/krb5/krb/preauth_encts.c:68-73`): `TRACE_PREAUTH_ENC_TS_DISABLED`, then `KRB5_PREAUTH_FAILED` with "Encrypted timestamp is disabled".
    pub(super) fn encts_disabled() -> Self {
        trace::preauth_enc_ts_disabled();
        Self {
            error: Error::EnctsDisabled,
            code: KRB5_PREAUTH_FAILED,
            text: Error::EnctsDisabled.to_string(),
            interrupted: false,
        }
    }

    /// The trace line of this failure for the module `name` that answered `patype`.
    /// MIT `process_pa_data` (`lib/krb5/krb/preauth2.c:685-686`): `TRACE_PREAUTH_PROCESS` prints the module's return code with its message.
    pub(super) fn trace(&self, name: &str, patype: i32) {
        trace::preauth_process(name, patype, true, self.code, Some(&self.text));
    }
}

/// The prompter of an exchange that was given none.
struct NoPrompt;

impl AsPrompt for NoPrompt {
    fn password(&mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        Err(Error::File(std::io::Error::other("Cannot read password")))
    }
}

/// The AS password of one exchange, read when a module first needs the key and kept once it is read.
/// MIT `get_as_key` (`lib/krb5/krb/preauth2.c:438-457`): `gak_fct` runs whenever a module wants the key and none is held.
/// MIT `krb5_get_as_key_password` (`lib/krb5/krb/gic_pwd.c:9-110`): a prompt that fails returns its error and leaves `gp->password` unset; one that reads keeps it for every later module.
pub(super) struct PasswordCell<'p, 'g> {
    prompt: Option<&'p mut dyn AsPrompt>,
    /// The password the caller supplied, used when there is no prompter. Empty is no password: the
    /// type cannot tell it from MIT's NULL.
    given: &'g [u8],
    /// Whether a module that wants the key asks the responder for the password.
    asks: bool,
    /// This round's responder answer to the password question.
    answer: Option<Zeroizing<Vec<u8>>>,
    /// The password a prompt read, or the responder's answer once a module used it.
    got: Option<Zeroizing<Vec<u8>>>,
    none: NoPrompt,
}

impl<'p, 'g> PasswordCell<'p, 'g> {
    /// `keytab` is true when the exchange has the client's keys, which need no password.
    /// MIT `krb5_get_as_key_password` (`lib/krb5/krb/gic_pwd.c:30-38`): the password question is asked unless the caller gave a password with no prompter, or a keytab.
    pub(super) fn new(prompt: Option<&'p mut dyn AsPrompt>, given: &'g [u8], keytab: bool) -> Self {
        let asks = !keytab && (prompt.is_some() || given.is_empty());
        Self {
            prompt,
            given,
            asks,
            answer: None,
            got: None,
            none: NoPrompt,
        }
    }

    /// Whether a module that wants the key puts the password question to the responder now: no
    /// module has the password yet.
    /// MIT `krb5_get_as_key_password` (`lib/krb5/krb/gic_pwd.c:30-38`): `need_as_key` returns without a question once `gp->password` is set.
    pub(super) fn asks_question(&self) -> bool {
        self.asks && self.got.is_none()
    }

    /// The responder's answer to the password question of the round that begins. A module that
    /// then wants the key and has no password takes it.
    /// MIT `krb5_get_as_key_password` (`lib/krb5/krb/gic_pwd.c:55-66`): a responder's answer to the password question is the password, with no prompt.
    pub(super) fn offer(&mut self, answer: Option<&str>) {
        self.answer = answer.map(|a| Zeroizing::new(a.as_bytes().to_vec()));
    }

    /// The password for a module that wants the AS key: the one already held, the responder's answer,
    /// else a read through the prompter, else the caller's. A read that fails is the module's failure
    /// and holds nothing.
    /// MIT `krb5_get_as_key_password` (`lib/krb5/krb/gic_pwd.c:55-97`): `gp->password` is set only by the answer or by a prompt that returned.
    ///
    /// # Errors
    ///
    /// The module's failure when the prompter cannot read: [`ModuleFail::from_read`]; `EIO` when
    /// there is no prompter and the caller gave no password: [`ModuleFail::no_password`].
    pub(super) fn get(&mut self) -> Result<Zeroizing<Vec<u8>>, ModuleFail> {
        if self.got.is_none() {
            self.got.clone_from(&self.answer);
        }
        if let Some(held) = &self.got {
            return Ok(held.clone());
        }
        let Some(prompt) = self.prompt.as_deref_mut() else {
            // MIT `krb5_get_as_key_password` (`lib/krb5/krb/gic_pwd.c:70-72`): no password and no prompter is `EIO`; the empty password is not a password to try.
            if self.given.is_empty() {
                return Err(ModuleFail::no_password());
            }
            return Ok(Zeroizing::new(self.given.to_vec()));
        };
        let read = prompt.password().map_err(ModuleFail::from_read)?;
        self.got = Some(read.clone());
        Ok(read)
    }

    /// The responder of the exchange's prompter, if it has one.
    pub(super) fn responder(&mut self) -> Option<&mut dyn Responder> {
        self.prompt.as_deref_mut().and_then(|p| p.responder())
    }

    /// The prompter a module's own prompts go through.
    pub(super) fn ui(&mut self) -> &mut dyn AsPrompt {
        match self.prompt.as_deref_mut() {
            Some(p) => p,
            None => &mut self.none,
        }
    }
}

#[cfg(test)]
mod tests;
