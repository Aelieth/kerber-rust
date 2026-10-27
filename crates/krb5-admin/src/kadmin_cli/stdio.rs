//! glibc's stdio buffering, so the streams interleave as MIT's.

use std::io::{self, Write};

const BLOCK: usize = 4096;

pub(crate) struct Stdout {
    raw: Box<dyn Write>,
    buf: Vec<u8>,
    line: bool,
}

impl Stdout {
    pub(crate) fn new(raw: Box<dyn Write>, line: bool) -> Self {
        Self {
            raw,
            buf: Vec::new(),
            line,
        }
    }

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

pub(crate) struct Io {
    pub(crate) out: Stdout,
    pub(crate) err: Box<dyn Write>,
    pub(crate) input: Box<dyn io::BufRead>,
    pub(crate) tty_in: bool,
    pub(crate) script_mode: bool,
    pub(crate) exit_status: i32,
    pub(crate) interrupted: bool,
}

const BUFSIZ: usize = 8192;

pub(crate) enum LineRead {
    Line(Vec<u8>),
    End,
    Caught,
}

impl Io {
    // MIT: `info` (kadmin.c:76-85)
    pub(crate) fn info(&mut self, text: &str) {
        if !self.script_mode {
            let _ = self.out.write_all(text.as_bytes());
        }
    }

    pub(crate) fn print(&mut self, text: &str) {
        let _ = self.out.write_all(text.as_bytes());
    }

    // MIT: `error` (kadmin.c:89-98)
    pub(crate) fn error(&mut self, text: &str) {
        if self.script_mode {
            self.exit_status = 1;
        }
        let _ = self.err.write_all(text.as_bytes());
    }

    pub(crate) fn eprint(&mut self, text: &str) {
        let _ = self.err.write_all(text.as_bytes());
    }

    pub(crate) fn eprint_bytes(&mut self, bytes: &[u8]) {
        let _ = self.err.write_all(bytes);
    }

    // MIT: `extended_com_err_fn` (kadmin.c:228-242)
    pub(crate) fn com_err(&mut self, prog: &str, message: Option<&str>, text: &str) {
        match message {
            Some(m) => self.error(&format!("{prog}: {m} ")),
            None => self.error(&format!("{prog}: ")),
        }
        self.eprint(text);
        self.error("\n");
    }

    pub(crate) fn read_line(&mut self) -> LineRead {
        self.out.flush_for_input();
        let mut line = Vec::new();
        match krb5_cli::fgets(&mut *self.input, BUFSIZ, &mut line) {
            krb5_cli::LineEnd::Read => LineRead::Line(line),
            krb5_cli::LineEnd::Caught(_) => LineRead::Caught,
            krb5_cli::LineEnd::End | krb5_cli::LineEnd::Failed => LineRead::End,
        }
    }

    /// As `fgets`: `size - 1` bytes, newline kept, the rest left for the next read.
    pub(crate) fn fgets(&mut self, size: usize) -> Option<Vec<u8>> {
        self.out.flush_for_input();
        let mut line = Vec::new();
        match krb5_cli::fgets(&mut *self.input, size, &mut line) {
            krb5_cli::LineEnd::Read => Some(line),
            krb5_cli::LineEnd::Caught(_) => {
                self.interrupted = true;
                None
            }
            krb5_cli::LineEnd::End | krb5_cli::LineEnd::Failed => None,
        }
    }

    // MIT: `krb5_read_password` (read_pwd.c:41-77)
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
