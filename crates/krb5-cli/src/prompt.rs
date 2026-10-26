use std::io::{self, BufRead, IsTerminal as _, Write};

use nix::sys::signal::Signal;
use nix::sys::termios::{LocalFlags, SetArg, Termios, tcgetattr, tcsetattr};
use zeroize::{Zeroize, Zeroizing};

use crate::stdin::{LineEnd, SignalCatch, Stdin, fgets};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
// MIT: `KRB5_LIBOS_CANTREADPWD` (lib/krb5/error_tables/krb5_err.et:176-176)
// MIT: `KRB5_LIBOS_BADPWDMATCH` (lib/krb5/error_tables/krb5_err.et:177-177)
// MIT: `KRB5_LIBOS_PWDINTR` (lib/krb5/error_tables/krb5_err.et:178-178)
pub enum PromptError {
    #[error("Cannot read password")]
    CantRead,
    #[error("Password mismatch")]
    Mismatch,
    #[error("Password read interrupted")]
    Interrupted,
}

pub struct Prompter<R, W> {
    input: R,
    output: W,
    terminal: bool,
}

impl Prompter<Stdin, io::Stdout> {
    #[must_use]
    pub fn stdio() -> Self {
        Self::terminal(Stdin::unbuffered(), io::stdout())
    }
}

impl<R: BufRead, W: Write> Prompter<R, W> {
    #[must_use]
    pub const fn new(input: R, output: W) -> Self {
        Self {
            input,
            output,
            terminal: false,
        }
    }

    #[must_use]
    pub const fn terminal(input: R, output: W) -> Self {
        Self {
            input,
            output,
            terminal: true,
        }
    }

    /// A hidden prompt clears `ECHO` and `ECHONL` on a terminal and restores them after.
    // MIT: `krb5_prompter_posix` (lib/krb5/os/prompter.c:32-125)
    pub fn hidden(&mut self, prompt: &str) -> Result<Zeroizing<Vec<u8>>, PromptError> {
        self.hidden_with(None, prompt, usize::MAX)
    }

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

pub fn prompt_hidden(prompt: &str) -> Result<Zeroizing<Vec<u8>>, PromptError> {
    Prompter::stdio().hidden(prompt)
}

// MIT: `krb5_read_password` (lib/krb5/os/read_pwd.c:41-77)
pub fn read_password(
    prompt: &str,
    verify: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>, PromptError> {
    Prompter::stdio().password(prompt, verify)
}

struct EchoOff {
    saved: Termios,
}

impl EchoOff {
    // MIT: `setup_tty` (lib/krb5/os/prompter.c:159-189)
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
    // MIT: `restore_tty` (lib/krb5/os/prompter.c:192-207)
    fn drop(&mut self) {
        let _ = tcsetattr(io::stdin(), SetArg::TCSANOW, &self.saved);
    }
}

fn drop_rest_of_line<R: BufRead>(input: &mut R) {
    loop {
        let mut rest = Zeroizing::new(Vec::new());
        match fgets(input, 1024, &mut rest) {
            LineEnd::Read if rest.last() != Some(&b'\n') => {}
            _ => break,
        }
    }
}
