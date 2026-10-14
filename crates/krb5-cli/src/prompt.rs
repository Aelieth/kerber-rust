//! Password prompts: MIT `krb5_prompter_posix` (`lib/krb5/os/prompter.c`) and
//! `krb5_read_password` (`lib/krb5/os/read_pwd.c`).

use std::io::{self, BufRead, IsTerminal as _, Write};

use nix::sys::signal::Signal;
use nix::sys::termios::{LocalFlags, SetArg, Termios, tcgetattr, tcsetattr};
use zeroize::{Zeroize, Zeroizing};

use crate::stdin::{LineEnd, SignalCatch, Stdin, fgets};

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
    /// `SIGINT` (Ctrl-C) came while the reply was read.
    /// MIT `KRB5_LIBOS_PWDINTR` (`krb5_err.et:178-178`): the text.
    #[error("Password read interrupted")]
    Interrupted,
}

/// Prompts written to `output`, replies read from `input` one line each, so the rest of
/// `input` stays for whoever reads it next.
pub struct Prompter<R, W> {
    input: R,
    output: W,
    terminal: bool,
}

impl Prompter<Stdin, io::Stdout> {
    /// Prompts on stdout, replies from stdin read a byte at a time, echo off while a reply is
    /// typed on a terminal.
    #[must_use]
    pub fn stdio() -> Self {
        Self::terminal(Stdin::unbuffered(), io::stdout())
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

    /// As [`Self::new`] for an `input` that reads stdin (a [`Stdin`]): when stdin is a
    /// terminal, its echo is off while each reply is typed.
    #[must_use]
    pub const fn terminal(input: R, output: W) -> Self {
        Self {
            input,
            output,
            terminal: true,
        }
    }

    /// One hidden prompt: `prompt` and `: `, a line read with the terminal's echo off and
    /// `SIGINT` caught, then a newline. The reply is the line without its `\n`.
    /// MIT `krb5_prompter_posix` (`prompter.c:78-92`): the prompt and `: ` on stdout, flushed,
    /// the reply read with `fgets`, and `\n` printed after a hidden reply, tty or not.
    /// MIT `krb5_prompter_posix` (`prompter.c:93-104`): end of input is
    /// `KRB5_LIBOS_CANTREADPWD`, a read `SIGINT` cut short `KRB5_LIBOS_PWDINTR`, and the
    /// terminal's mode comes back either way; only the `\n` is cut, so a `\r` stays in the reply.
    ///
    /// # Errors
    ///
    /// [`PromptError::CantRead`] when input ends or fails before a line, or the terminal's
    /// echo cannot be turned off; [`PromptError::Interrupted`] when `SIGINT` comes while the
    /// reply is read from a [`Stdin`].
    pub fn hidden(&mut self, prompt: &str) -> Result<Zeroizing<Vec<u8>>, PromptError> {
        self.hidden_with(None, prompt, usize::MAX)
    }

    /// [`Self::hidden`] with an optional `banner` and a reply buffer of `size` bytes (`usize::MAX`
    /// for none). The banner and a newline come first. With a finite `size` a reply is at most
    /// `size - 1` bytes and is cut at its first NUL; when no newline comes before that NUL, the rest
    /// of the input line is read and dropped, so a NUL before the newline drops the next line too.
    /// MIT `krb5_prompter_posix` (`lib/krb5/os/prompter.c:53-56`): the banner goes to stdout, then a newline, before any prompt.
    /// MIT `krb5_prompter_posix` (`lib/krb5/os/prompter.c:98-112`): `strchr` finds the newline up to the reply's NUL, and with none the input line is read away.
    ///
    /// # Errors
    ///
    /// As [`Self::hidden`].
    pub fn hidden_with(
        &mut self,
        banner: Option<&str>,
        prompt: &str,
        size: usize,
    ) -> Result<Zeroizing<Vec<u8>>, PromptError> {
        if let Some(banner) = banner {
            let _ = writeln!(self.output, "{banner}");
        }
        let sigint = SignalCatch::new(&[Signal::SIGINT]);
        let echo = if self.terminal {
            EchoOff::on_stdin()?
        } else {
            None
        };
        let _ = write!(self.output, "{prompt}: ");
        let _ = self.output.flush();
        let mut line = Zeroizing::new(Vec::with_capacity(1024));
        let read = fgets(&mut self.input, size, &mut line);
        let _ = writeln!(self.output);
        let _ = self.output.flush();
        if size != usize::MAX && matches!(read, LineEnd::Read) {
            let text = line.iter().position(|&b| b == 0).unwrap_or(line.len());
            if !line[..text].contains(&b'\n') {
                drop_rest_of_line(&mut self.input);
            }
        }
        drop(echo);
        drop(sigint);
        match read {
            LineEnd::Read => {
                if size == usize::MAX {
                    if line.last() == Some(&b'\n') {
                        line.pop();
                    }
                } else {
                    let text = line.iter().position(|&b| b == 0).unwrap_or(line.len());
                    let end = line[..text]
                        .iter()
                        .position(|&b| b == b'\n')
                        .unwrap_or(text);
                    line[end..].zeroize();
                    line.truncate(end);
                }
                Ok(line)
            }
            LineEnd::Caught(Signal::SIGINT) => Err(PromptError::Interrupted),
            LineEnd::Caught(_) | LineEnd::End | LineEnd::Failed => Err(PromptError::CantRead),
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

/// Reads and drops input up to and including its next newline, or to the end of the input.
/// MIT `krb5_prompter_posix` (`lib/krb5/os/prompter.c:107-110`): `getc` reads to a newline or EOF.
fn drop_rest_of_line<R: BufRead>(input: &mut R) {
    loop {
        let mut rest = Zeroizing::new(Vec::new());
        match fgets(input, 1024, &mut rest) {
            LineEnd::Read if rest.last() != Some(&b'\n') => {}
            _ => break,
        }
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

    #[test]
    fn sigint_while_the_reply_is_read_is_an_interrupted_read() {
        let session = crate::SignalCatch::new(&[Signal::SIGINT]);
        nix::sys::signal::raise(Signal::SIGINT).unwrap();
        let mut out = Vec::new();
        let got = Prompter::new(Stdin::unbuffered(), &mut out).password(KDB5_PROMPT, None);
        drop(session);
        let e = got.unwrap_err();
        assert_eq!(e, PromptError::Interrupted);
        assert_eq!(e.to_string(), "Password read interrupted");
        assert_eq!(out, b"Enter KDC database master key: \n");
    }

    #[test]
    fn a_banner_comes_first_and_a_long_line_is_cut_and_flushed() {
        let mut input = &b"0123456789\nnext\n"[..];
        let mut out = Vec::new();
        {
            let mut p = Prompter::new(&mut input, &mut out);
            let got = p.hidden_with(Some("B1\nB2"), "Enter #", 6).unwrap();
            assert_eq!(got.as_slice(), b"01234");
            assert_eq!(p.hidden_with(None, "Next", 6).unwrap().as_slice(), b"next");
        }
        assert_eq!(out, b"B1\nB2\nEnter #: \nNext: \n");
        let mut long = vec![b'x'; 2000];
        long.extend_from_slice(b"\nafter\n");
        let mut input = &long[..];
        let mut p = Prompter::new(&mut input, Vec::new());
        assert_eq!(
            p.hidden_with(None, "P", 1024).unwrap().as_slice(),
            &long[..1023]
        );
        assert_eq!(p.hidden_with(None, "Q", 1024).unwrap().as_slice(), b"after");
    }

    #[test]
    fn a_reply_is_cut_at_its_first_nul_and_no_size_keeps_the_whole_line() {
        // A NUL before the newline cuts the reply, and the newline search (MIT `strchr`) stops at the
        // NUL, so the line that follows is read away with the rest of this one.
        let mut input = &b"ab\0cd\nnext\nX\n"[..];
        let mut out = Vec::new();
        {
            let mut p = Prompter::new(&mut input, &mut out);
            assert_eq!(p.hidden_with(None, "P", 1024).unwrap().as_slice(), b"ab");
            assert_eq!(p.hidden_with(None, "Q", 1024).unwrap().as_slice(), b"X");
        }
        // A carriage return is kept.
        let got = Prompter::new(&b"ab\r\n"[..], &mut out).hidden_with(None, "P", 1024);
        assert_eq!(got.unwrap().as_slice(), b"ab\r");
        // Without a size the whole line is the reply, NULs and all.
        let line = b"a\0b\n";
        let got = Prompter::new(&line[..], &mut out).hidden("P").unwrap();
        assert_eq!(got.as_slice(), b"a\0b");
    }

    #[test]
    fn a_banner_that_ends_in_a_newline_leaves_a_blank_line_before_the_prompt() {
        let menu = "Please choose from the following:\n\t1. Vendor: Acme\n\t2. Vendor: Zed\n";
        let challenge = "OTP Challenge: 8675309\n";
        let mut out = Vec::new();
        {
            let mut p = Prompter::new(&b"2\n654321\n"[..], &mut out);
            let choice = p.hidden_with(Some(menu), "Enter #", 1024).unwrap();
            assert_eq!(choice.as_slice(), b"2");
            let got = p.hidden_with(Some(challenge), "Enter OTP Token Value", 1024);
            assert_eq!(got.unwrap().as_slice(), b"654321");
        }
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Please choose from the following:\n\t1. Vendor: Acme\n\t2. Vendor: Zed\n\nEnter #: \n\
             OTP Challenge: 8675309\n\nEnter OTP Token Value: \n"
        );
    }
}
