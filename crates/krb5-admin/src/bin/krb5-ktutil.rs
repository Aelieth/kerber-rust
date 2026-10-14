//! MIT `ktutil`: a list of keytab entries read, edited and written through the requests of its
//! `ss` subsystem.
//!
//! Requests are read from stdin after the `ktutil:  ` prompt until `quit` or the end of input.
//! Arguments after the program name are not read, and ktutil exits 0 whatever its requests did.
//! `addent -password` reads the password from stdin (the next line of a piped stream); a
//! `test-hooks` build takes `KRB5_PASSWORD` when it is set. Never from argv. A request that fails
//! prints MIT's line on stderr.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::fmt::Write as _;
use std::io::{self, BufRead, IsTerminal as _, Write};
use std::path::Path;

use krb5_cli::{LineEnd, Prompter, Signal, SignalCatch, Stdin, fgets, line_mode, take_caught};
use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_protocol::{Keytab, KeytabEntry, KeytabSlot, parse_principal};
use zeroize::Zeroizing;

/// The name ktutil's requests and errors carry, and its prompt's.
const WHOAMI: &str = "ktutil";

/// C's `BUFSIZ`: a request line is read `BUFSIZ - 1` bytes at a time.
const BUFSIZ: usize = 8192;

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    // MIT `main` (`kadmin/ktutil/ktutil.c:49-53`): `krb5_init_context` fails with the program name and "while initializing krb5", then exits 1.
    if let Err(e) = krb5_config::init_profile() {
        let prog = argv.first().map_or(WHOAMI, String::as_str);
        eprintln!("{prog}: {} while initializing krb5", e.init_text());
        std::process::exit(1);
    }
    // MIT `krb5_init_context_profile` (`lib/krb5/krb/init_ctx.c:209-217`): the context's `KRB5_TRACE` opens with it; no ktutil request traces.
    krb5_protocol::trace::init();
    let mut kt = empty_list();
    // stdout is line-buffered on a terminal and fully buffered otherwise ([`FullyBuffered`]); the prompt flushes it.
    let mut out: Box<dyn Write> = if io::stdout().is_terminal() {
        Box::new(io::stdout().lock())
    } else {
        FullyBuffered::stdout()
    };
    let status = run_ktutil(&argv, &mut kt, &mut Stdin::unbuffered(), &mut out);
    drop(out);
    std::process::exit(status);
}

/// Arguments after the program name are not a one-shot command. The request loop runs, and the
/// process status is 0 whatever the requests did.
fn run_ktutil(
    _argv: &[String],
    kt: &mut Keytab,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> i32 {
    // MIT `main` (`kadmin/ktutil/ktutil.c:43-62`): `argc` is unused, `ss_listen` runs, and the process exits 0.
    listen(kt, input, out);
    0
}

/// A stream written as C stdio writes one it buffers whole: bytes wait until the buffer is past
/// `block`, a full block goes out when more bytes come, and the rest at a flush.
struct FullyBuffered<W: Write> {
    inner: W,
    buf: Vec<u8>,
    block: usize,
}

impl FullyBuffered<Box<dyn Write>> {
    /// stdout, its buffer as glibc sizes it: `st_blksize` when that is smaller than `BUFSIZ`.
    fn stdout() -> Box<dyn Write> {
        use std::os::fd::AsFd as _;
        use std::os::unix::fs::MetadataExt as _;
        let file = io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .ok()
            .map(std::fs::File::from);
        let block = file
            .as_ref()
            .and_then(|f| f.metadata().ok())
            .and_then(|m| usize::try_from(m.blksize()).ok())
            .filter(|&b| b > 0 && b < BUFSIZ)
            .unwrap_or(BUFSIZ);
        let inner: Box<dyn Write> = match file {
            Some(f) => Box::new(f),
            None => Box::new(io::stdout()),
        };
        Box::new(Self {
            inner,
            buf: Vec::with_capacity(block),
            block,
        })
    }
}

impl<W: Write> Write for FullyBuffered<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        while self.buf.len() > self.block {
            self.inner.write_all(&self.buf[..self.block])?;
            self.buf.drain(..self.block);
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.write_all(&self.buf)?;
        self.buf.clear();
        self.inner.flush()
    }
}

impl<W: Write> Drop for FullyBuffered<W> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// A list with no entries, written as a version 2 keytab.
fn empty_list() -> Keytab {
    Keytab {
        version: 0x0502,
        entries: Vec::new(),
        skipped_unknown_etype: 0,
        unparsed: Vec::new(),
    }
}

/// Whether the request loop goes on after a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    Next,
    Quit,
}

/// A request's handler: the list, the request's words, stdin for its replies, stdout. An error is
/// the line MIT prints on stderr for it, without its newline.
type Run = fn(&mut Keytab, &[String], &mut dyn BufRead, &mut dyn Write) -> Result<Flow, Vec<u8>>;

/// One request: its names, its one-line description, and what runs it.
struct Request {
    names: &'static [&'static str],
    info: &'static str,
    run: Run,
}

/// The `ktutil_cmds` table (`ktutil_ct.ct`), in its order.
const REQUESTS: &[Request] = &[
    Request {
        names: &["clear_list", "clear"],
        info: "Clear the current keylist.",
        run: clear_list,
    },
    Request {
        names: &["read_kt", "rkt"],
        info: "Read a krb5 keytab into the current keylist.",
        run: read_kt,
    },
    Request {
        names: &["read_st", "rst"],
        info: "Deprecated and removed.",
        run: read_st,
    },
    Request {
        names: &["write_kt", "wkt"],
        info: "Write the current keylist to a krb5 keytab.",
        run: write_kt,
    },
    Request {
        names: &["write_st", "wst"],
        info: "Deprecated and removed.",
        run: write_st,
    },
    Request {
        names: &["add_entry", "addent"],
        info: "Add an entry to the current keylist.",
        run: add_entry,
    },
    Request {
        names: &["delete_entry", "delent"],
        info: "Delete an entry from the current keylist.",
        run: delete_entry,
    },
    Request {
        names: &["list", "l"],
        info: "List the current keylist.",
        run: list,
    },
    Request {
        names: &["list_requests", "lr", "?"],
        info: "List available requests.",
        run: list_requests,
    },
    Request {
        names: &["quit", "exit", "q"],
        info: "Exit program.",
        run: quit,
    },
];

/// The prompt, then one request line, until `quit` or the end of input. `SIGINT` is caught through
/// the loop and `SIGCONT` while the prompt waits: either prints a newline and prompts again.
fn listen(kt: &mut Keytab, input: &mut dyn BufRead, out: &mut dyn Write) {
    // MIT `ss_listen` (`util/ss/listen.c:99-108`): `SIGINT` is caught for the whole loop.
    let _sigint = SignalCatch::new(&[Signal::SIGINT]);
    let mut raw = Vec::new();
    loop {
        // MIT `listen_int_handler` (`util/ss/listen.c:60-63`): a newline, then back at the prompt.
        if take_caught().is_some() {
            let _ = out.write_all(b"\n");
        }
        let read = {
            // MIT `ss_listen` (`util/ss/listen.c:116-129`): `SIGCONT` is caught while the prompt waits, then one line is read.
            let _sigcont = SignalCatch::new(&[Signal::SIGCONT]);
            line_mode();
            // MIT `ss_create_invocation` (`util/ss/invocation.c:91-96`): the prompt is the subsystem name, a colon, and two spaces.
            let _ = write!(out, "{WHOAMI}:  ");
            // MIT `readline` (`util/ss/listen.c:44-46`): the prompt is written and stdout is flushed.
            let _ = out.flush();
            fgets(input, BUFSIZ, &mut raw)
        };
        match read {
            LineEnd::Read => {}
            LineEnd::Caught(_) => {
                let _ = out.write_all(b"\n");
                continue;
            }
            LineEnd::End | LineEnd::Failed => break,
        }
        // The line as a C string: up to its first `\r`, `\n`, or a NUL before them.
        // MIT `readline` (`util/ss/listen.c:46-49`): `fgets` of `BUFSIZ`, then cut at the first `\r` or `\n`.
        let end = raw
            .iter()
            .position(|&b| b == b'\r' || b == b'\n' || b == 0)
            .unwrap_or(raw.len());
        match execute_line(kt, &raw[..end], input, out) {
            Ok(Flow::Next) => {}
            Ok(Flow::Quit) => break,
            Err(mut line) => {
                line.push(b'\n');
                let _ = io::stderr().lock().write_all(&line);
            }
        }
    }
    let _ = out.flush();
}

/// One request line. A line that starts with `!` is passed over: no shell is run. A line that is
/// not UTF-8 is refused when its first word names a request; an unknown one is reported byte for byte.
fn execute_line(
    kt: &mut Keytab,
    line: &[u8],
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT `ss_execute_line` (`util/ss/execute_cmd.c:175-187`): leading blanks are skipped, and a `!` line is given to the shell unless escapes are disabled.
    let start = line
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(line.len());
    let trimmed = &line[start..];
    // This port passes a `!` line over and runs no shell.
    if trimmed.first() == Some(&b'!') {
        return Ok(Flow::Next);
    }
    let Ok(text) = std::str::from_utf8(trimmed) else {
        // Not MIT: a non-UTF-8 line that names a request is refused; an unknown one is echoed as bytes.
        return not_utf8(trimmed);
    };
    let argv = krb5_admin::ss_parse(text).map_err(|msg| format!("{WHOAMI}: {msg}").into_bytes())?;
    let Some(name) = argv.first() else {
        return Ok(Flow::Next);
    };
    match REQUESTS.iter().find(|r| r.names.contains(&name.as_str())) {
        Some(r) => (r.run)(kt, &argv, input, out),
        None => {
            // MIT `ss_listen` (`util/ss/listen.c:143-155`): an unknown request is named by its first word, cut at the first blank.
            Err(unknown_request(trimmed))
        }
    }
}

/// `Unknown request "<word>".  Type "?" for a request list.`, the word the line's first, cut at
/// its first blank, byte for byte.
fn unknown_request(trimmed: &[u8]) -> Vec<u8> {
    let word = trimmed
        .split(|&b| b == b' ' || b == b'\t')
        .next()
        .unwrap_or_default();
    let mut text = format!("{WHOAMI}: Unknown request \"").into_bytes();
    text.extend_from_slice(word);
    text.extend_from_slice(b"\".  Type \"?\" for a request list.");
    text
}

/// A request line that is not UTF-8. Names and paths here are UTF-8, so a line whose first word
/// names a request is refused whole; any other is an unknown request, byte for byte.
fn not_utf8(trimmed: &[u8]) -> Result<Flow, Vec<u8>> {
    let lossy: String = trimmed.iter().copied().map(char::from).collect();
    let first = krb5_admin::ss_parse(&lossy)
        .ok()
        .and_then(|argv| argv.into_iter().next());
    match first {
        Some(word) if REQUESTS.iter().any(|r| r.names.contains(&word.as_str())) => {
            Err(format!("{WHOAMI}: Request line is not valid UTF-8; it was not run.").into_bytes())
        }
        _ => Err(unknown_request(trimmed)),
    }
}

/// `clear_list`: the list emptied.
fn clear_list(
    kt: &mut Keytab,
    argv: &[String],
    _input: &mut dyn BufRead,
    _out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT `ktutil_clear_list` (`kadmin/ktutil/ktutil.c:70-77`): no argument, else "invalid arguments"; the list is freed.
    if argv.len() != 1 {
        return Err(format!("{}: invalid arguments", argv[0]).into_bytes());
    }
    *kt = empty_list();
    Ok(Flow::Next)
}

/// `read_kt`: a keytab's entries added to the list.
fn read_kt(
    kt: &mut Keytab,
    argv: &[String],
    _input: &mut dyn BufRead,
    _out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT `ktutil_read_v5` (`kadmin/ktutil/ktutil.c:85-91`): one argument, and a failure names the keytab.
    let [cmd, path] = argv else {
        return Err(format!("{}: must specify keytab to read", argv[0]).into_bytes());
    };
    // Not MIT: the argument is a filesystem path; MIT 1.22.2 resolves a keytab name.
    let other = krb5_protocol::read_secret_file(Path::new(path))
        .and_then(|bytes| Keytab::parse(&bytes))
        .map_err(|e| {
            format!("{cmd}: {} while reading keytab \"{path}\"", strerror(&e)).into_bytes()
        })?;
    kt.merge(other);
    Ok(Flow::Next)
}

/// `read_st`: srvtabs are no longer read.
fn read_st(
    _kt: &mut Keytab,
    argv: &[String],
    _input: &mut dyn BufRead,
    _out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT `ktutil_read_v4` (`kadmin/ktutil/ktutil.c:96-98`): the request only says srvtabs are no longer read.
    Err(format!("{}: reading srvtabs is no longer supported", argv[0]).into_bytes())
}

/// `write_kt`: each entry added to a keytab.
fn write_kt(
    kt: &mut Keytab,
    argv: &[String],
    _input: &mut dyn BufRead,
    _out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT `ktutil_write_v5` (`kadmin/ktutil/ktutil.c:106-112`): one argument, and a failure names the keytab.
    let [cmd, path] = argv else {
        return Err(format!("{}: must specify keytab to write", argv[0]).into_bytes());
    };
    // MIT `ktutil_write_keytab` (`kadmin/ktutil/ktutil_funcs.c:336-358`): each entry is added to the keytab, made at version 2 or keeping its own.
    kt.add_to_file(Path::new(path)).map_err(|e| {
        format!("{cmd}: {} while writing keytab \"{path}\"", strerror(&e)).into_bytes()
    })?;
    Ok(Flow::Next)
}

/// `write_st`: srvtabs are no longer written.
fn write_st(
    _kt: &mut Keytab,
    argv: &[String],
    _input: &mut dyn BufRead,
    _out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT `ktutil_write_v4` (`kadmin/ktutil/ktutil.c:117-119`): the request only says srvtabs are no longer written.
    Err(format!("{}: writing srvtabs is no longer supported", argv[0]).into_bytes())
}

/// `add_entry`: one entry from a password or a hex key ([`addent`]).
fn add_entry(
    kt: &mut Keytab,
    argv: &[String],
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    let args: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
    addent(kt, &argv[0], &args, input, out)
        .map(|()| Flow::Next)
        .map_err(String::into_bytes)
}

/// `delete_entry`: the entry at a slot taken out of the list.
fn delete_entry(
    kt: &mut Keytab,
    argv: &[String],
    _input: &mut dyn BufRead,
    _out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT `ktutil_delete_entry` (`kadmin/ktutil/ktutil.c:184-190`): one argument read by `atoi`; no such entry is `EINVAL`.
    let [cmd, slot] = argv else {
        return Err(format!("{}: must specify entry to delete", argv[0]).into_bytes());
    };
    let n = atoi(slot);
    usize::try_from(n)
        .ok()
        .and_then(|slot| kt.remove_slot(slot).ok())
        .ok_or_else(|| format!("{cmd}: Invalid argument while deleting entry {n}").into_bytes())?;
    Ok(Flow::Next)
}

/// `list`: the list, `-t` adding each entry's timestamp, `-e` its enctype and `-k` its key.
fn list(
    kt: &mut Keytab,
    argv: &[String],
    _input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT `ktutil_list` (`kadmin/ktutil/ktutil.c:203-218`): only `-t`, `-k` and `-e`, else the usage line before anything is printed.
    let (mut show_time, mut show_keys, mut show_enctype) = (false, false, false);
    for arg in &argv[1..] {
        match arg.as_str() {
            "-t" => show_time = true,
            "-k" => show_keys = true,
            "-e" => show_enctype = true,
            _ => {
                let cmd = &argv[0];
                return Err(format!("{cmd}: usage: {cmd} [-t] [-k] [-e]").into_bytes());
            }
        }
    }
    let (text, failed) = format_list(kt, show_time, show_enctype, show_keys);
    let _ = out.write_all(text.as_bytes());
    match failed {
        Some(why) => Err(format!("{}: {why}", argv[0]).into_bytes()),
        None => Ok(Flow::Next),
    }
}

/// The list as [`list`] prints it, and the error that ended it early.
fn format_list(
    kt: &Keytab,
    show_time: bool,
    show_enctype: bool,
    show_keys: bool,
) -> (String, Option<&'static str>) {
    let mut out = String::new();
    // MIT `ktutil_list` (`kadmin/ktutil/ktutil.c:221-227`): the header, with the timestamp columns only for `-t`.
    if show_time {
        out.push_str("slot KVNO Timestamp         Principal\n");
        out.push_str(
            "---- ---- ----------------- ---------------------------------------------------\n",
        );
    } else {
        out.push_str("slot KVNO Principal\n");
        out.push_str(
            "---- ---- ---------------------------------------------------------------------\n",
        );
    }
    for (i, slot) in kt.slots().iter().enumerate() {
        let (kvno, princ, timestamp, enctype, key) = match slot {
            KeytabSlot::Entry(e) => (
                e.kvno,
                e.name
                    .unparse_with_realm(&String::from_utf8_lossy(e.realm.as_bytes())),
                e.timestamp,
                Some(e.key.etype().to_mit_name()),
                Some(e.key.as_bytes()),
            ),
            KeytabSlot::Unparsed(raw) => match Keytab::unparsed_meta(raw, kt.version) {
                Some((kvno, princ, ts, _)) => {
                    (kvno, princ, ts, None, Keytab::unparsed_key(raw, kt.version))
                }
                None => continue,
            },
        };
        // `%4d` of the unsigned kvno: one past `i32::MAX` prints negative.
        let _ = write!(out, "{:4} {:4} ", i + 1, kvno.cast_signed());
        if show_time {
            // MIT `krb5_timestamp_to_sfstring` (`lib/krb5/krb/str_conv.c:242-250`): the first format that fits, then `pad` fills out to `buflen - 1`.
            if let Some(text) =
                krb5_types::timestamp::timestamp_to_sfstring(timestamp, 18, Some(b' '))
            {
                let _ = write!(out, "{text} ");
            }
        }
        let _ = write!(out, "{princ:>40}");
        if show_enctype {
            // MIT `ktutil_list` (`kadmin/ktutil/ktutil.c:251-260`): an enctype with no name ends the listing after the principal, with the conversion's error.
            let Some(name) = enctype else {
                return (
                    out,
                    Some("Invalid argument While converting enctype to string"),
                );
            };
            let _ = write!(out, " ({name}) ");
        }
        if show_keys {
            out.push_str(" (0x");
            out.push_str(&hex(key.unwrap_or_default()));
            out.push(')');
        }
        out.push('\n');
    }
    (out, None)
}

/// `list_requests`: each request's names, the description at column 25. No pager is run.
#[allow(clippy::unnecessary_wraps)]
fn list_requests(
    _kt: &mut Keytab,
    _argv: &[String],
    _input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT `ss_list_requests` (`util/ss/list_rqs.c:74-102`): the names joined, the description at column 25.
    let mut text = format!("Available {WHOAMI} requests:\n\n");
    for r in REQUESTS {
        let names = r.names.join(", ");
        if names.len() > 23 {
            text.push_str(&names);
            text.push('\n');
            text.push_str(&" ".repeat(25));
        } else {
            let _ = write!(text, "{names:<25}");
        }
        text.push_str(r.info);
        text.push('\n');
    }
    let _ = out.write_all(text.as_bytes());
    Ok(Flow::Next)
}

/// `quit`: the request loop ends.
#[allow(clippy::unnecessary_wraps)]
fn quit(
    _kt: &mut Keytab,
    _argv: &[String],
    _input: &mut dyn BufRead,
    _out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT `ss_quit` (`util/ss/listen.c:180-182`): the subsystem is aborted.
    Ok(Flow::Quit)
}

/// The OS error text as C `strerror` gives it, without Rust's `(os error N)`.
fn strerror(e: &io::Error) -> String {
    let s = e.to_string();
    s.rfind(" (os error ")
        .map_or_else(|| s.clone(), |i| s[..i].to_owned())
}

/// C `atoi`, glibc's `(int) strtol`: the blanks of C's `isspace` skipped, an optional sign and the
/// leading digits, 0 when there are none; a value past a `long` is its bound, and the `int` is
/// the `long`'s low 32 bits.
fn atoi(s: &str) -> i32 {
    let s = s.trim_start_matches([' ', '\t', '\n', '\u{b}', '\u{c}', '\r']);
    let (negative, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let long = digits
        .bytes()
        .take_while(u8::is_ascii_digit)
        .fold(0i64, |n, d| {
            let d = i64::from(d - b'0');
            if negative {
                n.saturating_mul(10).saturating_sub(d)
            } else {
                n.saturating_mul(10).saturating_add(d)
            }
        });
    u32::try_from(long & 0xffff_ffff).unwrap_or(0).cast_signed()
}

/// `addent`: one keytab entry from a password or a hex key, `cmd` the name the request was given.
fn addent(
    kt: &mut Keytab,
    cmd: &str,
    args: &[&str],
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<(), String> {
    let (mut use_pass, mut use_key) = (0u32, 0u32);
    let (mut princ, mut kvno, mut enctype) = (None, None, None);
    let mut i = 0;
    // MIT `ktutil_add_entry` (`kadmin/ktutil/ktutil.c:132-160`): `-p`, `-k`, `-e`, `-password`, `-key`, `-s` and `-f` are read, and any other word is passed over.
    while i < args.len() {
        match args[i] {
            "-p" => {
                i += 1;
                princ = args.get(i).copied();
            }
            "-k" => {
                i += 1;
                kvno = args.get(i).map(|v| atoi(v));
            }
            "-e" => {
                i += 1;
                enctype = args.get(i).copied();
            }
            "-password" => use_pass += 1,
            "-key" => use_key += 1,
            // Not MIT: `-s` and `-f` are refused; MIT 1.22.2 takes a salt or fetches etype-info.
            opt @ ("-f" | "-s") => return Err(format!("{cmd}: {opt} is not supported")),
            _ => {}
        }
        i += 1;
    }
    // MIT `ktutil_add_entry` (`kadmin/ktutil/ktutil.c:162-171`): the usage line unless a principal, a kvno and one of `-password` or `-key`; an enctype unless `-f`.
    let (Some(spec), Some(kvno), 1) = (princ, kvno, use_pass + use_key) else {
        return Err(format!(
            "usage: {cmd} (-key | -password) -p principal -k kvno [-e enctype] [-f|-s salt]"
        ));
    };
    let Some(enctype) = enctype else {
        return Err("enctype must be specified if not using -f".into());
    };
    // MIT `ktutil_add_entry` (`kadmin/ktutil/ktutil.c:173-176`): a failure of the entry is reported "while adding new entry".
    let fail = |e: &dyn std::fmt::Display| format!("{cmd}: {e} while adding new entry");
    // MIT `ktutil_add` (`kadmin/ktutil/ktutil_funcs.c:159-172`): the name takes the default realm, and an unknown enctype is `KRB5_BAD_ENCTYPE`.
    let (name, realm) = with_default_realm(spec)
        .and_then(|spec| parse_principal(&spec))
        .map_err(|e| fail(&e))?;
    // MIT `KRB5_BAD_ENCTYPE` (`lib/krb5/error_tables/krb5_err.et:254-254`): the text is "Bad encryption type".
    let etype = EncryptionType::from_mit_name(enctype).map_err(|_| fail(&"Bad encryption type"))?;
    let full = name.unparse_with_realm(&realm);
    let key = if use_key == 1 {
        // MIT `ktutil_add` (`kadmin/ktutil/ktutil_funcs.c:205-215`): `Key for <name> (hex): ` and one `fgets`; an odd byte count drops the last byte, an even count writes `0` over it.
        let _ = write!(out, "Key for {full} (hex): ");
        // A terminal shows the prompt at once; MIT's `printf` leaves it in the line buffer until a newline.
        if io::stdout().is_terminal() {
            let _ = out.flush();
        }
        let mut line = Zeroizing::new(Vec::new());
        match fgets(input, BUFSIZ, &mut line) {
            LineEnd::Read => {}
            LineEnd::Caught(_) => {
                // MIT `listen_int_handler` (`util/ss/listen.c:60-63`): a newline, then back at the prompt.
                let _ = out.write_all(b"\n");
                return Ok(());
            }
            LineEnd::End | LineEnd::Failed => return Err("addent: Error reading key.".into()),
        }
        let len = line.iter().position(|&b| b == 0).unwrap_or(line.len());
        let mut digits = Zeroizing::new(Vec::with_capacity(len));
        digits.extend_from_slice(&line[..len]);
        if digits.len().is_multiple_of(2) {
            if let Some(last) = digits.last_mut() {
                *last = b'0';
            }
        } else {
            digits.pop();
        }
        if digits.is_empty() {
            return Err("addent: Error reading key.".into());
        }
        let raw = hex_decode(&digits).ok_or("addent: Illegal character in key.")?;
        // Not MIT: a `-key` whose length is not the enctype's is refused; MIT 1.22.2 stores it.
        if raw.len() != etype.key_len() {
            return Err(fail(&"protocol key length does not match etype"));
        }
        ProtocolKey::from_bytes(etype, &raw).map_err(|e| fail(&e))?
    } else {
        let pw = match krb5_config::env_password() {
            Some(pw) => Zeroizing::new(pw),
            // MIT `ktutil_add` (`kadmin/ktutil/ktutil_funcs.c:187-190`): `Password for <name>`, asked once.
            None => Prompter::terminal(&mut *input, io::stdout())
                .hidden(&format!("Password for {full}"))
                .map_err(|e| fail(&e))?,
        };
        let salt = name.default_salt(&realm);
        string_to_key(etype, pw.as_slice(), salt, Some(&4096u32.to_be_bytes()))
            .map_err(|e| fail(&e))?
    };
    let kvno = kvno.cast_unsigned();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(0));
    kt.entries.push(KeytabEntry {
        realm: krb5_types::ascii(&realm),
        name,
        timestamp,
        kvno,
        key,
    });
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Hex digits, two to a byte. `None` for an odd count or any other byte. The buffer is the key's
/// exact length and is wiped on drop.
fn hex_decode(digits: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    // MIT `k5_hex_decode` (`util/support/hex.c:96-109`): an odd count or a byte that is not a hex digit is `EINVAL`.
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    let n = digits.len() / 2;
    let mut out = Zeroizing::new(Vec::with_capacity(n));
    for pair in digits.as_chunks::<2>().0 {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push(hi * 16 + lo);
    }
    Some(out)
}

/// One hex digit, `None` for any other byte.
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// `spec`, with krb5.conf's `default_realm` when it names no realm.
fn with_default_realm(spec: &str) -> Result<String, String> {
    // MIT `krb5_parse_name_flags` (`lib/krb5/krb/parse.c:198-211`): a name with no realm takes the default realm.
    let parsed = krb5_types::parse_name_ex(spec, "", false).map_err(|e| e.to_string())?;
    if parsed.has_realm {
        return Ok(spec.to_owned());
    }
    let realm = krb5_config::load_krb5_conf()
        .and_then(|c| c.default_realm)
        .ok_or_else(|| krb5_config::Error::NoDefaultRealm.to_string())?;
    Ok(format!("{spec}@{realm}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_crypto::ProtocolKey;
    use krb5_types::{PrincipalName, ascii};

    /// `input` run through the request loop: what it printed on stdout.
    fn run_lines(kt: &mut Keytab, input: &[u8]) -> String {
        let mut out = Vec::new();
        listen(kt, &mut io::Cursor::new(input), &mut out);
        String::from_utf8(out).unwrap()
    }

    /// One request line, `input` answering its prompts: its error line, if any.
    fn fails(kt: &mut Keytab, line: &str, input: &[u8]) -> Option<String> {
        execute_line(
            kt,
            line.as_bytes(),
            &mut io::Cursor::new(input),
            &mut Vec::new(),
        )
        .err()
        .map(|e| String::from_utf8(e).unwrap())
    }

    fn entry(name: &str, kvno: u32) -> KeytabEntry {
        KeytabEntry {
            realm: ascii("KERBER.TEST"),
            name: PrincipalName::new(PrincipalName::NT_PRINCIPAL, [name]),
            timestamp: 1_700_000_000,
            kvno,
            key: ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[3u8; 32]).unwrap(),
        }
    }

    /// A non-empty argv is not a one-shot command: the loop still prompts, a failed request does
    /// not change the status, and the list is whatever stdin did.
    #[test]
    fn a_nonempty_argv_is_ignored_and_the_loop_exits_0() {
        let mut kt = empty_list();
        kt.entries.push(entry("user", 1));
        let mut out = Vec::new();
        let rc = run_ktutil(
            &["ktutil".to_owned(), "clear".to_owned()],
            &mut kt,
            &mut io::Cursor::new(b"bogus word\n"),
            &mut out,
        );
        assert_eq!(rc, 0, "the loop exits 0 even when a request fails");
        assert_eq!(out, b"ktutil:  ktutil:  ");
        assert_eq!(kt.entries.len(), 1, "argv clear was not a command");
        assert_eq!(
            fails(&mut kt, "bogus word", b"").as_deref(),
            Some("ktutil: Unknown request \"bogus\".  Type \"?\" for a request list.")
        );
        assert_eq!(atoi("  -12x"), -12);
    }

    /// MIT `ss_listen` (`util/ss/listen.c:115-132`): the prompt comes before each read, and the end of input or `quit` ends the loop.
    /// MIT `ss_list_requests` (`util/ss/list_rqs.c:74-102`): the names joined, the description at column 25.
    #[test]
    fn each_request_line_follows_the_prompt() {
        let mut kt = empty_list();
        assert_eq!(run_lines(&mut kt, b"q\nlist\n"), "ktutil:  ");
        assert_eq!(run_lines(&mut kt, b""), "ktutil:  ");
        assert_eq!(run_lines(&mut kt, b"\nexit\n"), "ktutil:  ktutil:  ");
        let out = run_lines(&mut kt, b"?\nquit\n");
        assert_eq!(
            out,
            "ktutil:  Available ktutil requests:\n\n\
             clear_list, clear        Clear the current keylist.\n\
             read_kt, rkt             Read a krb5 keytab into the current keylist.\n\
             read_st, rst             Deprecated and removed.\n\
             write_kt, wkt            Write the current keylist to a krb5 keytab.\n\
             write_st, wst            Deprecated and removed.\n\
             add_entry, addent        Add an entry to the current keylist.\n\
             delete_entry, delent     Delete an entry from the current keylist.\n\
             list, l                  List the current keylist.\n\
             list_requests, lr, ?     List available requests.\n\
             quit, exit, q            Exit program.\n\
             ktutil:  "
        );
    }

    /// MIT `ktutil_list` (`kadmin/ktutil/ktutil.c:221-269`): the header, then the slot and kvno in 4 columns, `-t`'s time, the principal in 40, `-e`'s enctype between spaces and `-k`'s key in hex.
    #[test]
    fn the_list_is_mits_table() {
        let mut kt = empty_list();
        kt.entries.push(entry("user", 2));
        let princ = format!("{:>40}", "user@KERBER.TEST");
        let (text, failed) = format_list(&kt, false, true, false);
        assert_eq!(failed, None);
        assert_eq!(
            text,
            format!(
                "slot KVNO Principal\n\
                 ---- ---- ---------------------------------------------------------------------\n\
                 \x20  1    2 {princ} (aes256-cts-hmac-sha1-96) \n"
            )
        );
        let (keys, _) = format_list(&kt, false, true, true);
        assert!(
            keys.ends_with(&format!(
                "{princ} (aes256-cts-hmac-sha1-96)  (0x{})\n",
                "03".repeat(32)
            )),
            "{keys}"
        );
        let (timed, _) = format_list(&kt, true, false, false);
        let mut lines = timed.lines();
        assert_eq!(lines.next(), Some("slot KVNO Timestamp         Principal"));
        assert_eq!(
            lines.next(),
            Some("---- ---- ----------------- ---------------------------------------------------")
        );
        let row = lines.next().unwrap();
        assert_eq!(row.len(), 10 + 18 + 40, "{row:?}");
        assert!(row.ends_with(&princ), "{row:?}");
        assert_eq!(
            fails(&mut kt, "l -K", b""),
            Some("l: usage: l [-t] [-k] [-e]".into())
        );
    }

    /// MIT `ss_execute_line` (`util/ss/execute_cmd.c:175-192`): leading blanks are skipped, a `!` line is not a request, and the parsed words name one.
    /// MIT `ss_listen` (`util/ss/listen.c:143-155`): an unknown request is reported with the line's first word, cut at its first blank.
    #[test]
    fn a_line_is_an_ss_request() {
        let mut kt = empty_list();
        let unknown =
            |w: &str| format!("ktutil: Unknown request \"{w}\".  Type \"?\" for a request list.");
        assert_eq!(fails(&mut kt, "nope", b""), Some(unknown("nope")));
        assert_eq!(fails(&mut kt, " \tfoo bar", b""), Some(unknown("foo")));
        assert_eq!(fails(&mut kt, "# comment", b""), Some(unknown("#")));
        assert_eq!(fails(&mut kt, "\"foo bar\"", b""), Some(unknown("\"foo")));
        assert_eq!(fails(&mut kt, "!echo hi", b""), None);
        assert_eq!(fails(&mut kt, "", b""), None);
        assert_eq!(
            fails(&mut kt, "rkt \"x", b""),
            Some("ktutil: Unbalanced quotes in command line".into())
        );
        let raw = |line: &[u8]| {
            execute_line(&mut empty_list(), line, &mut io::empty(), &mut Vec::new()).err()
        };
        assert_eq!(
            raw(b"\xff x"),
            Some(b"ktutil: Unknown request \"\xff\".  Type \"?\" for a request list.".to_vec())
        );
        assert_eq!(
            raw(b"rkt /tmp/\xff"),
            Some(b"ktutil: Request line is not valid UTF-8; it was not run.".to_vec())
        );
    }

    /// Live MIT 1.22.2 ktutil: each failure's line names the request as it was typed.
    #[test]
    fn failures_are_mit_s_lines() {
        let mut kt = empty_list();
        let dir = krb5_testkit::scratch_dir("ktutil-lines");
        let missing = dir.join("no-such.kt");
        let missing = missing.to_str().unwrap();
        let mut fails = |line: &str, input: &[u8]| fails(&mut kt, line, input).unwrap_or_default();
        assert_eq!(fails("rkt", b""), "rkt: must specify keytab to read");
        assert_eq!(
            fails("read_kt a b", b""),
            "read_kt: must specify keytab to read"
        );
        assert_eq!(
            fails(&format!("rkt {missing}"), b""),
            format!("rkt: No such file or directory while reading keytab \"{missing}\"")
        );
        assert_eq!(
            fails("rst x", b""),
            "rst: reading srvtabs is no longer supported"
        );
        assert_eq!(
            fails("write_st", b""),
            "write_st: writing srvtabs is no longer supported"
        );
        assert_eq!(fails("wkt", b""), "wkt: must specify keytab to write");
        assert_eq!(
            fails("write_kt a b", b""),
            "write_kt: must specify keytab to write"
        );
        assert_eq!(fails("clear x", b""), "clear: invalid arguments");
        assert_eq!(fails("delent", b""), "delent: must specify entry to delete");
        assert_eq!(
            fails("delete_entry 9", b""),
            "delete_entry: Invalid argument while deleting entry 9"
        );
        assert_eq!(
            fails("add_entry", b""),
            "usage: add_entry (-key | -password) -p principal -k kvno [-e enctype] [-f|-s salt]"
        );
        assert_eq!(
            fails("addent -password -p plain@R.TEST -k 1", b""),
            "enctype must be specified if not using -f"
        );
        assert_eq!(
            fails("addent -password -p plain@R.TEST -k 1 -e no-such-type", b""),
            "addent: Bad encryption type while adding new entry"
        );
        assert_eq!(
            fails(
                "addent -key -p plain@R.TEST -k 1 -e aes256-cts-hmac-sha1-96",
                b"zz\n"
            ),
            "addent: Illegal character in key."
        );
        assert_eq!(
            fails(
                "addent -password -p plain@R.TEST -k 1 -e aes256 -s salt",
                b""
            ),
            "addent: -s is not supported"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// MIT `ktutil_clear_list` (`kadmin/ktutil/ktutil.c:70-77`): the list is emptied.
    /// MIT `ktutil_delete_entry` (`kadmin/ktutil/ktutil.c:184-190`): the entry at the slot leaves the list.
    #[test]
    fn clear_and_delete_change_the_list() {
        let mut kt = empty_list();
        kt.entries.extend([entry("a", 1), entry("b", 2)]);
        assert_eq!(fails(&mut kt, "delent 1", b""), None);
        assert_eq!(kt.entries.len(), 1);
        assert_eq!(fails(&mut kt, "clear_list", b""), None);
        assert!(kt.entries.is_empty());
    }

    #[test]
    fn addent_password_is_the_next_line_of_the_command_stream() {
        if krb5_config::env_password().is_some() {
            // A test-hooks build with KRB5_PASSWORD set takes it instead of the prompt.
            return;
        }
        // Live MIT 1.22.2 ktutil: `Password for user@REALM: `, the reply read from the next
        // line of stdin, the rest of the stream left for the next command.
        let mut kt = empty_list();
        let input =
            b"addent -password -p user@R.TEST -k 3 -e aes256-cts-hmac-sha1-96\nsecret\nq\nnope\n";
        assert_eq!(run_lines(&mut kt, input), "ktutil:  ktutil:  ");
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        let salt = name.default_salt("R.TEST");
        let want = string_to_key(
            EncryptionType::Aes256CtsHmacSha196,
            b"secret",
            salt,
            Some(&4096u32.to_be_bytes()),
        )
        .unwrap();
        assert_eq!(kt.entries.len(), 1);
        assert_eq!(kt.entries[0].kvno, 3);
        assert_eq!(kt.entries[0].key.as_bytes(), want.as_bytes());
        // Live MIT 1.22.2: end of input at the prompt is "addent: Cannot read password while
        // adding new entry", and no entry is added.
        let line = "addent -password -p user@R.TEST -k 4 -e aes256-cts-hmac-sha1-96";
        assert_eq!(
            fails(&mut kt, line, b""),
            Some("addent: Cannot read password while adding new entry".into())
        );
        assert_eq!(kt.entries.len(), 1);
    }

    struct InjectedErr {
        kind: io::ErrorKind,
        n: u32,
    }
    impl io::Read for InjectedErr {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            self.n += 1;
            assert!(self.n < 8, "IO error must break the stdin loop");
            Err(io::Error::new(self.kind, "injected"))
        }
    }

    #[test]
    fn stdin_read_error_ends_the_loop() {
        let mut kt = empty_list();
        let mut out = Vec::new();
        listen(
            &mut kt,
            &mut io::BufReader::new(InjectedErr {
                kind: io::ErrorKind::Other,
                n: 0,
            }),
            &mut out,
        );
        assert_eq!(out, b"ktutil:  ");
    }

    /// MIT `ktutil_write_keytab` (`kadmin/ktutil/ktutil_funcs.c:336-358`): `wkt` adds each entry to the keytab: a missing file is made at version 2, an existing one keeps its version, one that is no keytab is MIT's line, and an empty list opens no file.
    #[test]
    fn wkt_adds_to_the_file_as_mit_s_does() {
        let dir = krb5_testkit::scratch_dir("ktutil-wkt");
        let run = |kt: &mut Keytab, line: String| fails(kt, &line, b"");
        let mut kt = empty_list();
        let none = dir.join("none.kt");
        assert_eq!(run(&mut kt, format!("wkt {}", none.display())), None);
        assert!(!none.exists(), "an empty list opens no file");
        let v1 = dir.join("v1.kt");
        let mut old = empty_list();
        old.version = 0x0501;
        old.entries.push(entry("a", 300));
        std::fs::write(&v1, old.to_bytes()).unwrap();
        let new = dir.join("new.kt");
        assert_eq!(run(&mut kt, format!("rkt {}", v1.display())), None);
        assert_eq!(run(&mut kt, format!("wkt {}", new.display())), None);
        assert_eq!(std::fs::read(&new).unwrap()[..2], [5, 2]);
        let mut more = empty_list();
        more.entries.push(entry("b", 2));
        assert_eq!(run(&mut more, format!("wkt {}", v1.display())), None);
        let back = std::fs::read(&v1).unwrap();
        assert_eq!(back[..2], [5, 1]);
        assert_eq!(Keytab::parse(&back).unwrap().entries.len(), 2);
        let junk = dir.join("junk.kt");
        std::fs::write(&junk, b"hello").unwrap();
        assert_eq!(
            run(&mut more, format!("wkt {}", junk.display())),
            Some(format!(
                "wkt: Unsupported key table format version number while writing keytab \"{}\"",
                junk.display()
            ))
        );
        assert_eq!(
            run(&mut more, format!("rkt {}", junk.display())),
            Some(format!(
                "rkt: Unsupported key table format version number while reading keytab \"{}\"",
                junk.display()
            ))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// MIT `ktutil_list` (`kadmin/ktutil/ktutil.c:251-260`): an enctype with no name ends `-e`'s listing after the entry's principal, with the conversion's error; without `-e` the entry is listed.
    #[test]
    fn an_unknown_enctype_ends_the_listing_under_e() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u16.to_be_bytes());
        let realm = b"KERBER.TEST";
        body.extend_from_slice(&u16::try_from(realm.len()).unwrap().to_be_bytes());
        body.extend_from_slice(realm);
        let user = b"user";
        body.extend_from_slice(&u16::try_from(user.len()).unwrap().to_be_bytes());
        body.extend_from_slice(user);
        body.extend_from_slice(&1i32.to_be_bytes());
        body.extend_from_slice(&1u32.to_be_bytes());
        body.push(7);
        body.extend_from_slice(&99u16.to_be_bytes());
        body.extend_from_slice(&16u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 16]);
        body.extend_from_slice(&7u32.to_be_bytes());
        let mut rec = i32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        rec.extend_from_slice(&body);
        let mut kt = empty_list();
        kt.unparsed.push((0, zeroize::Zeroizing::new(rec)));
        kt.entries.push(entry("user", 1));
        let princ = format!("{:>40}", "user@KERBER.TEST");
        let (text, failed) = format_list(&kt, false, false, false);
        assert_eq!(failed, None);
        assert!(
            text.contains(&format!("   1    7 {princ}\n   2    1 {princ}\n")),
            "{text}"
        );
        let (text, failed) = format_list(&kt, false, true, false);
        assert_eq!(
            failed,
            Some("Invalid argument While converting enctype to string")
        );
        assert!(text.ends_with(&format!("   1    7 {princ}")), "{text}");
        assert_eq!(
            fails(&mut kt, "list -e", b""),
            Some("list: Invalid argument While converting enctype to string".into())
        );
        assert_eq!(fails(&mut kt, "delent 1", b""), None);
        assert_eq!(kt.unparsed.len(), 0);
        assert_eq!(kt.entries.len(), 1);
    }

    /// MIT `ktutil_add` (`kadmin/ktutil/ktutil_funcs.c:205-233`): the key prompt on stdout; the line's last byte dropped for an odd count, else made a `0`; `addent` in both failure lines.
    /// MIT `ktutil_add_entry` (`kadmin/ktutil/ktutil.c:162-171`): one of `-password` and `-key`, once.
    #[test]
    fn a_key_line_is_read_as_mits() {
        let add = "add_entry -key -p plain@R.TEST -k -1 -e aes256-cts-hmac-sha1-96";
        let mut kt = empty_list();
        let mut out = Vec::new();
        let digits = format!("{}\n", "03".repeat(32));
        assert_eq!(
            execute_line(
                &mut kt,
                add.as_bytes(),
                &mut io::Cursor::new(digits),
                &mut out
            ),
            Ok(Flow::Next)
        );
        assert_eq!(out, b"Key for plain@R.TEST (hex): ");
        assert_eq!(kt.entries[0].key.as_bytes(), [3u8; 32]);
        assert_eq!(kt.entries[0].kvno, u32::MAX);
        let (text, _) = format_list(&kt, false, false, false);
        assert!(text.contains("\n   1   -1 "), "{text}");
        let mut last_zero = [3u8; 32];
        last_zero[31] = 0;
        for line in [format!("{}0\n", "03".repeat(31)), "03".repeat(32)] {
            let mut kt = empty_list();
            assert_eq!(fails(&mut kt, add, line.as_bytes()), None);
            assert_eq!(kt.entries[0].key.as_bytes(), last_zero, "{line:?}");
        }
        let mut kt = empty_list();
        assert_eq!(
            fails(&mut kt, add, b"zz\n"),
            Some("addent: Illegal character in key.".into())
        );
        assert_eq!(
            fails(&mut kt, add, b"\n"),
            Some("addent: Error reading key.".into())
        );
        assert_eq!(
            fails(&mut kt, add, b""),
            Some("addent: Error reading key.".into())
        );
        assert_eq!(
            fails(&mut kt, add, b"\x00303\n"),
            Some("addent: Error reading key.".into())
        );
        assert!(kt.entries.is_empty());
        assert_eq!(
            fails(
                &mut kt,
                "addent -password -password -p a -k 1 -e aes256",
                b""
            ),
            Some(
                "usage: addent (-key | -password) -p principal -k kvno [-e enctype] [-f|-s salt]"
                    .into()
            )
        );
    }

    /// glibc `atoi`: `strtol`'s `long`, its bound past its range, cut to the `int`'s 32 bits.
    #[test]
    fn atoi_is_glibcs() {
        assert_eq!(atoi("  -12x"), -12);
        assert_eq!(atoi(" \t12x"), 12);
        assert_eq!(atoi("+7"), 7);
        assert_eq!(atoi("x1"), 0);
        assert_eq!(atoi("-1"), -1);
        assert_eq!(atoi("4294967295"), -1);
        assert_eq!(atoi("99999999999"), 1_215_752_191);
        assert_eq!(atoi("99999999999999999999"), -1);
        assert_eq!(atoi("-99999999999999999999"), 0);
        let mut kt = empty_list();
        assert_eq!(
            fails(&mut kt, "delent 99999999999", b""),
            Some("delent: Invalid argument while deleting entry 1215752191".into())
        );
    }

    /// C stdio's full buffering: a full buffer goes out when more bytes come, the rest at a flush.
    /// MIT `readline` (`util/ss/listen.c:46-49`): a NUL ends the request line as it ends a C string.
    #[test]
    fn stdout_is_sent_as_c_stdio_sends_it() {
        let mut fb = FullyBuffered {
            inner: Vec::new(),
            buf: Vec::new(),
            block: 4,
        };
        fb.write_all(b"abcd").unwrap();
        assert_eq!(fb.inner, b"");
        fb.write_all(b"efghij").unwrap();
        assert_eq!(fb.inner, b"abcdefgh");
        fb.flush().unwrap();
        assert_eq!(fb.inner, b"abcdefghij");
        let mut kt = empty_list();
        assert_eq!(run_lines(&mut kt, b"q\0junk\nlist\n"), "ktutil:  ");
    }
}
