//! The C stdio `kadmin.local` writes through, so its streams interleave as MIT's do: stdout
//! buffered as glibc buffers it (by line on a terminal, by block otherwise), stderr unbuffered.

use std::io::{self, Write};

/// glibc's buffer for a pipe or a file (`st_blksize`).
const BLOCK: usize = 4096;

/// stdout with glibc's buffering.
pub(crate) struct Stdout {
    raw: Box<dyn Write>,
    buf: Vec<u8>,
    line: bool,
}

impl Stdout {
    /// `raw` is the unbuffered descriptor; `line` when it is a terminal.
    pub(crate) fn new(raw: Box<dyn Write>, line: bool) -> Self {
        Self {
            raw,
            buf: Vec::new(),
            line,
        }
    }

    /// Bytes written to the descriptor itself, as MIT's pager process writes them: they pass
    /// what is still buffered.
    pub(crate) fn write_raw(&mut self, bytes: &[u8]) {
        let _ = self.raw.write_all(bytes);
        let _ = self.raw.flush();
    }

    fn drain(&mut self, upto: usize) -> io::Result<()> {
        let rest = self.buf.split_off(upto);
        let head = std::mem::replace(&mut self.buf, rest);
        self.raw.write_all(&head)?;
        self.raw.flush()
    }

    /// Before a read from a terminal: glibc flushes line-buffered output when stdin needs input.
    pub(crate) fn flush_for_input(&mut self) {
        if self.line {
            let _ = self.flush();
        }
    }
}

impl Write for Stdout {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        if self.line {
            if let Some(nl) = self.buf.iter().rposition(|&b| b == b'\n') {
                self.drain(nl + 1)?;
            }
        } else if self.buf.len() >= BLOCK {
            self.drain(self.buf.len())?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain(self.buf.len())
    }
}

/// The session's streams and MIT's message helpers.
pub(crate) struct Io {
    pub(crate) out: Stdout,
    pub(crate) err: Box<dyn Write>,
    pub(crate) input: Box<dyn io::BufRead>,
    /// stdin is a terminal: password replies are read with echo off.
    pub(crate) tty_in: bool,
    /// MIT `script_mode`: the command came after the options on the command line.
    pub(crate) script_mode: bool,
    pub(crate) exit_status: i32,
}

impl Io {
    /// MIT `info` (`kadmin.c:76-85`): printed only outside script mode.
    pub(crate) fn info(&mut self, text: &str) {
        if !self.script_mode {
            let _ = self.out.write_all(text.as_bytes());
        }
    }

    /// stdout, as `printf`.
    pub(crate) fn print(&mut self, text: &str) {
        let _ = self.out.write_all(text.as_bytes());
    }

    /// MIT `error` (`kadmin.c:89-98`): stderr, and in script mode the exit status becomes 1.
    pub(crate) fn error(&mut self, text: &str) {
        if self.script_mode {
            self.exit_status = 1;
        }
        let _ = self.err.write_all(text.as_bytes());
    }

    /// stderr, as `fprintf(stderr, …)`: no effect on the exit status.
    pub(crate) fn eprint(&mut self, text: &str) {
        let _ = self.err.write_all(text.as_bytes());
    }

    /// MIT `extended_com_err_fn` (`kadmin.c:228-242`): `prog: message text` through `error`.
    pub(crate) fn com_err(&mut self, prog: &str, message: Option<&str>, text: &str) {
        match message {
            Some(m) => self.error(&format!("{prog}: {m} ")),
            None => self.error(&format!("{prog}: ")),
        }
        self.eprint(text);
        self.error("\n");
    }

    /// One line from stdin, as `fgets` reads it: the newline kept, `None` at the end of input.
    pub(crate) fn read_line(&mut self) -> Option<Vec<u8>> {
        self.out.flush_for_input();
        let mut line = Vec::new();
        match self.input.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line),
        }
    }

    /// A reply as `fgets(buf, size, stdin)` reads it: at most `size - 1` bytes, up to and
    /// including a newline; the rest of a longer line stays for the next read.
    pub(crate) fn fgets(&mut self, size: usize) -> Option<Vec<u8>> {
        self.out.flush_for_input();
        let mut line = Vec::new();
        while line.len() + 1 < size {
            let Some(&b) = self.input.fill_buf().ok().and_then(|buf| buf.first()) else {
                break;
            };
            self.input.consume(1);
            line.push(b);
            if b == b'\n' {
                break;
            }
        }
        (!line.is_empty()).then_some(line)
    }

    /// MIT `krb5_read_password` (`read_pwd.c:41-77`): `prompt`, then `verify` when given, echo
    /// off on a terminal.
    pub(crate) fn read_password(
        &mut self,
        prompt: &str,
        verify: Option<&str>,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, krb5_cli::PromptError> {
        let input: &mut dyn io::BufRead = &mut *self.input;
        if self.tty_in {
            krb5_cli::Prompter::terminal(input, &mut self.out).password(prompt, verify)
        } else {
            krb5_cli::Prompter::new(input, &mut self.out).password(prompt, verify)
        }
    }
}
