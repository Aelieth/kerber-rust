//! Password prompts: MIT `krb5_prompter_posix` (`lib/krb5/os/prompter.c`) and
//! `krb5_read_password` (`lib/krb5/os/read_pwd.c`).

use std::io::{self, BufRead, IsTerminal as _, Write};

use nix::sys::termios::{LocalFlags, SetArg, Termios, tcgetattr, tcsetattr};
use zeroize::Zeroizing;

/// Why a prompt got no password.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PromptError {
    /// Input ended or failed before a line, or the terminal could not be set up.
    /// MIT `KRB5_LIBOS_CANTREADPWD` (`krb5_err.et:176-176`): the text.
    #[error("Cannot read password")]
    CantRead,
    /// The verify reply differs from the first.
    /// MIT `KRB5_LIBOS_BADPWDMATCH` (`krb5_err.et:177-177`): the text.
    #[error("Password mismatch")]
    Mismatch,
}

/// Prompts written to `output`, replies read from `input` one line each, so the rest of
/// `input` stays for whoever reads it next.
pub struct Prompter<R, W> {
    input: R,
    output: W,
    terminal: bool,
}

impl Prompter<io::StdinLock<'static>, io::Stdout> {
    /// Prompts on stdout, replies from stdin, echo off while a reply is typed on a terminal.
    #[must_use]
    pub fn stdio() -> Self {
        Self::terminal(io::stdin().lock(), io::stdout())
    }
}

impl<R: BufRead, W: Write> Prompter<R, W> {
    /// Prompts on `output`, replies from `input`; no terminal is touched.
    #[must_use]
    pub const fn new(input: R, output: W) -> Self {
        Self {
            input,
            output,
            terminal: false,
        }
    }

    /// As [`Self::new`] for an `input` that reads stdin (a held [`io::StdinLock`]): when stdin
    /// is a terminal, its echo is off while each reply is typed.
    #[must_use]
    pub const fn terminal(input: R, output: W) -> Self {
        Self {
            input,
            output,
            terminal: true,
        }
    }

    /// One hidden prompt: `prompt` and `: `, a line read with the terminal's echo off, then a
    /// newline. The reply is the line without its `\n`.
    /// MIT `krb5_prompter_posix` (`prompter.c:78-92`): the prompt and `: ` on stdout, flushed,
    /// the reply read with `fgets`, and `\n` printed after a hidden reply, tty or not.
    /// MIT `krb5_prompter_posix` (`prompter.c:93-104`): end of input is
    /// `KRB5_LIBOS_CANTREADPWD`; only the `\n` is cut, so a `\r` stays in the reply.
    ///
    /// # Errors
    ///
    /// [`PromptError::CantRead`] when input ends or fails before a line, or the terminal's
    /// echo cannot be turned off.
    pub fn hidden(&mut self, prompt: &str) -> Result<Zeroizing<Vec<u8>>, PromptError> {
        let echo = if self.terminal {
            EchoOff::on_stdin()?
        } else {
            None
        };
        let _ = write!(self.output, "{prompt}: ");
        let _ = self.output.flush();
        let mut line = Zeroizing::new(Vec::with_capacity(1024));
        let read = self.input.read_until(b'\n', &mut line);
        let _ = writeln!(self.output);
        let _ = self.output.flush();
        drop(echo);
        match read {
            Ok(0) | Err(_) => Err(PromptError::CantRead),
            Ok(_) => {
                if line.last() == Some(&b'\n') {
                    line.pop();
                }
                Ok(line)
            }
        }
    }

    /// `prompt`, then `verify` when given; the two replies must match.
    /// MIT `krb5_read_password` (`read_pwd.c:41-77`): two hidden prompts and
    /// `KRB5_LIBOS_BADPWDMATCH` when the replies differ.
    ///
    /// # Errors
    ///
    /// [`PromptError::CantRead`] as [`Self::hidden`]; [`PromptError::Mismatch`] when the
    /// verify reply differs.
    pub fn password(
        &mut self,
        prompt: &str,
        verify: Option<&str>,
    ) -> Result<Zeroizing<Vec<u8>>, PromptError> {
        let first = self.hidden(prompt)?;
        let Some(verify) = verify else {
            return Ok(first);
        };
        let second = self.hidden(verify)?;
        if *first == *second {
            Ok(first)
        } else {
            Err(PromptError::Mismatch)
        }
    }
}

/// [`Prompter::hidden`] on stdin and stdout.
///
/// # Errors
///
/// As [`Prompter::hidden`].
pub fn prompt_hidden(prompt: &str) -> Result<Zeroizing<Vec<u8>>, PromptError> {
    Prompter::stdio().hidden(prompt)
}

/// [`Prompter::password`] on stdin and stdout: what `kdb5_util create` and `kadmin.local
/// addprinc` ask.
///
/// # Errors
///
/// As [`Prompter::password`].
pub fn read_password(
    prompt: &str,
    verify: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>, PromptError> {
    Prompter::stdio().password(prompt, verify)
}

/// A terminal stdin with echo off; the saved settings come back when this drops.
struct EchoOff {
    saved: Termios,
}

impl EchoOff {
    /// `None` when stdin is not a terminal (a pipe or a file): nothing to hide.
    /// MIT `setup_tty` (`prompter.c:159-189`): on a terminal, `ECHO` and `ECHONL` off and
    /// `ISIG` and `ICANON` on, and a failure to get or set the mode is
    /// `KRB5_LIBOS_CANTREADPWD`.
    fn on_stdin() -> Result<Option<Self>, PromptError> {
        let stdin = io::stdin();
        if !stdin.is_terminal() {
            return Ok(None);
        }
        let saved = tcgetattr(&stdin).map_err(|_| PromptError::CantRead)?;
        let mut hidden = saved.clone();
        hidden
            .local_flags
            .remove(LocalFlags::ECHO | LocalFlags::ECHONL);
        hidden
            .local_flags
            .insert(LocalFlags::ISIG | LocalFlags::ICANON);
        tcsetattr(&stdin, SetArg::TCSANOW, &hidden).map_err(|_| PromptError::CantRead)?;
        Ok(Some(Self { saved }))
    }
}

impl Drop for EchoOff {
    /// MIT `restore_tty` (`prompter.c:192-207`): the saved mode back once the reply is read.
    fn drop(&mut self) {
        let _ = tcsetattr(io::stdin(), SetArg::TCSANOW, &self.saved);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KDB5_PROMPT: &str = "Enter KDC database master key";
    const KDB5_VERIFY: &str = "Re-enter KDC database master key to verify";

    fn run(input: &[u8], verify: Option<&str>) -> (Result<Vec<u8>, PromptError>, String) {
        let mut out = Vec::new();
        let got = Prompter::new(input, &mut out)
            .password(KDB5_PROMPT, verify)
            .map(|pw| pw.to_vec());
        (got, String::from_utf8(out).unwrap())
    }

    #[test]
    fn piped_password_twice_reads_one_line_per_prompt() {
        let (got, out) = run(b"master\nmaster\n", Some(KDB5_VERIFY));
        assert_eq!(got.unwrap(), b"master");
        assert_eq!(
            out,
            "Enter KDC database master key: \nRe-enter KDC database master key to verify: \n"
        );
    }

    #[test]
    fn piped_mismatch_is_mit_worded() {
        let (got, out) = run(b"master\nother\n", Some(KDB5_VERIFY));
        let e = got.unwrap_err();
        assert_eq!(e, PromptError::Mismatch);
        assert_eq!(e.to_string(), "Password mismatch");
        assert!(out.ends_with("to verify: \n"));
    }

    #[test]
    fn end_of_input_before_the_verify_line() {
        let (got, out) = run(b"master\n", Some(KDB5_VERIFY));
        let e = got.unwrap_err();
        assert_eq!(e, PromptError::CantRead);
        assert_eq!(e.to_string(), "Cannot read password");
        assert!(out.ends_with("to verify: \n"));
        assert_eq!(run(b"", None).0, Err(PromptError::CantRead));
    }

    #[test]
    fn only_the_newline_is_cut() {
        assert_eq!(run(b"pw\r\n", None).0.unwrap(), b"pw\r");
        assert_eq!(run(b"no-newline", None).0.unwrap(), b"no-newline");
        assert_eq!(run(b"\n", None).0.unwrap(), b"");
    }

    #[test]
    fn the_rest_of_the_input_stays_unread() {
        let mut input = &b"first\nsecond\nlistprincs\n"[..];
        let mut out = Vec::new();
        {
            let mut p = Prompter::new(&mut input, &mut out);
            assert_eq!(p.hidden("Password for a").unwrap().as_slice(), b"first");
            assert_eq!(p.hidden("Password for b").unwrap().as_slice(), b"second");
        }
        assert_eq!(input, b"listprincs\n");
        assert_eq!(out, b"Password for a: \nPassword for b: \n");
    }
}
