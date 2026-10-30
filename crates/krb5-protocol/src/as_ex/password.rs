use std::io::ErrorKind;

use zeroize::Zeroizing;

use super::AsPrompt;
use super::responder::Responder;
use crate::error::Error;
use crate::keytab::KeytabFailure;
use crate::trace::{self, ERROR_TABLE_BASE_KRB5};

// MIT: `KRB5_LIBOS_CANTREADPWD` (krb5_err.et)
pub(super) const CANTREADPWD: i64 = ERROR_TABLE_BASE_KRB5 + 130;
// MIT: `KRB5_LIBOS_PWDINTR` (krb5_err.et)
pub(super) const PWDINTR: i64 = ERROR_TABLE_BASE_KRB5 + 132;
// MIT: `KRB5_PREAUTH_FAILED` (krb5_err.et)
pub(super) const KRB5_PREAUTH_FAILED: i64 = ERROR_TABLE_BASE_KRB5 + 210;
// MIT: `KRB5DES_BAD_KEYPAR` (krb5_err.et:251-251)
pub(super) const DES_BAD_KEYPAR: i64 = ERROR_TABLE_BASE_KRB5 + 186;
// MIT: `KRB5DES_WEAK_KEY` (krb5_err.et:252-252)
pub(super) const DES_WEAK_KEY: i64 = ERROR_TABLE_BASE_KRB5 + 187;
// MIT: `KRB5_ERR_BAD_S2K_PARAMS` (krb5_err.et:337-337)
pub(super) const BAD_S2K_PARAMS: i64 = ERROR_TABLE_BASE_KRB5 + 244;
pub(super) const EIO: i64 = 5;

#[derive(Debug)]
pub(super) struct ModuleFail {
    pub(super) error: Error,
    pub(super) code: i64,
    pub(super) text: String,
    pub(super) interrupted: bool,
}

impl ModuleFail {
    pub(super) fn new(code: i64, text: &str) -> Self {
        Self {
            error: Error::Message(text.into()),
            code,
            text: text.into(),
            interrupted: false,
        }
    }

    /// A key MIT refuses: the walk goes on to the next mechanism.
    pub(super) fn key_refused(e: Error) -> Self {
        let code = match e {
            Error::DesWeakKey => DES_WEAK_KEY,
            Error::BadS2kParams => BAD_S2K_PARAMS,
            _ => DES_BAD_KEYPAR,
        };
        Self {
            text: e.to_string(),
            error: e,
            code,
            interrupted: false,
        }
    }

    // MIT: `krb5_prompter_posix` (lib/krb5/os/prompter.c:93-100)
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

    // MIT: `get_as_key_keytab` (lib/krb5/krb/gic_keytab.c:68-71)
    pub(super) fn keytab(f: &KeytabFailure) -> Self {
        Self {
            error: Error::Keytab {
                code: f.code,
                text: f.text.clone(),
            },
            code: f.code,
            text: f.text.clone(),
            interrupted: false,
        }
    }

    pub(super) fn no_password() -> Self {
        Self::new(EIO, "Input/output error")
    }

    pub(super) fn unwrapped(self) -> Error {
        match self.error {
            Error::Message(_) if self.code == CANTREADPWD => {
                Error::File(std::io::Error::other(self.text))
            }
            other => other,
        }
    }

    pub(super) fn encts_disabled() -> Self {
        trace::preauth_enc_ts_disabled();
        Self {
            error: Error::EnctsDisabled,
            code: KRB5_PREAUTH_FAILED,
            text: Error::EnctsDisabled.to_string(),
            interrupted: false,
        }
    }

    pub(super) fn trace(&self, name: &str, patype: i32) {
        trace::preauth_process(name, patype, true, self.code, Some(&self.text));
    }
}

struct NoPrompt;

impl AsPrompt for NoPrompt {
    fn password(&mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        Err(Error::File(std::io::Error::other("Cannot read password")))
    }
}

pub(super) struct PasswordCell<'p, 'g> {
    prompt: Option<&'p mut dyn AsPrompt>,
    given: &'g [u8],
    asks: bool,
    answer: Option<Zeroizing<Vec<u8>>>,
    got: Option<Zeroizing<Vec<u8>>>,
    unreadable: Option<KeytabFailure>,
    none: NoPrompt,
}

impl<'p, 'g> PasswordCell<'p, 'g> {
    pub(super) fn new(prompt: Option<&'p mut dyn AsPrompt>, given: &'g [u8], keytab: bool) -> Self {
        let asks = !keytab && (prompt.is_some() || given.is_empty());
        Self {
            prompt,
            given,
            asks,
            answer: None,
            got: None,
            unreadable: None,
            none: NoPrompt,
        }
    }

    // MIT: `krb5_init_creds_set_keytab` (lib/krb5/krb/gic_keytab.c:209-213)
    pub(super) fn with_unreadable_keytab(mut self, failure: Option<&KeytabFailure>) -> Self {
        self.unreadable = failure.cloned();
        self
    }

    pub(super) fn unreadable_keytab(&self) -> Option<&KeytabFailure> {
        self.unreadable.as_ref()
    }

    pub(super) fn asks_question(&self) -> bool {
        self.asks && self.got.is_none()
    }

    pub(super) fn offer(&mut self, answer: Option<&str>) {
        self.answer = answer.map(|a| Zeroizing::new(a.as_bytes().to_vec()));
    }

    /// Failed read holds nothing: the next module asks again.
    pub(super) fn get(&mut self) -> Result<Zeroizing<Vec<u8>>, ModuleFail> {
        if let Some(failure) = &self.unreadable {
            return Err(ModuleFail::keytab(failure));
        }
        if self.got.is_none() {
            self.got.clone_from(&self.answer);
        }
        if let Some(held) = &self.got {
            return Ok(held.clone());
        }
        let Some(prompt) = self.prompt.as_deref_mut() else {
            if self.given.is_empty() {
                return Err(ModuleFail::no_password());
            }
            return Ok(Zeroizing::new(self.given.to_vec()));
        };
        let read = prompt.password().map_err(ModuleFail::from_read)?;
        self.got = Some(read.clone());
        Ok(read)
    }

    pub(super) fn responder(&mut self) -> Option<&mut dyn Responder> {
        self.prompt.as_deref_mut().and_then(|p| p.responder())
    }

    pub(super) fn ui(&mut self) -> &mut dyn AsPrompt {
        match self.prompt.as_deref_mut() {
            Some(p) => p,
            None => &mut self.none,
        }
    }
}

#[cfg(test)]
mod tests;
