//! MIT `ktutil`: keytab entries read, edited and written through `ss`.
//! `addent -password` reads stdin, never argv.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![allow(
    clippy::disallowed_methods,
    reason = "a program reads its profile and environment when it starts"
)]

use std::fmt::Write as _;
use std::io::{self, BufRead, IsTerminal as _, Write};
use std::path::Path;

use krb5_cli::{LineEnd, Prompter, Signal, SignalCatch, Stdin, fgets, line_mode, take_caught};
use krb5_config::Krb5Conf;
use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_protocol::{Keytab, KeytabEntry, KeytabSlot, parse_principal};
use zeroize::Zeroizing;

const WHOAMI: &str = "ktutil";

const BUFSIZ: usize = 8192;

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let profile = krb5_config::init_profile().unwrap_or_else(|e| {
        let prog = argv.first().map_or(WHOAMI, String::as_str);
        eprintln!("{prog}: {} while initializing krb5", e.init_text());
        std::process::exit(1);
    });
    krb5_protocol::trace::init();
    let mut kt = empty_list();
    let mut out: Box<dyn Write> = if io::stdout().is_terminal() {
        Box::new(io::stdout().lock())
    } else {
        FullyBuffered::stdout()
    };
    let status = run_ktutil(&argv, &mut kt, &profile, &mut Stdin::unbuffered(), &mut out);
    drop(out);
    std::process::exit(status);
}

fn run_ktutil(
    _argv: &[String],
    kt: &mut Keytab,
    profile: &Krb5Conf,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> i32 {
    listen(kt, profile, input, out);
    0
}

struct FullyBuffered<W: Write> {
    inner: W,
    buf: Vec<u8>,
    block: usize,
}

impl FullyBuffered<Box<dyn Write>> {
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

fn empty_list() -> Keytab {
    Keytab {
        version: 0x0502,
        entries: Vec::new(),
        skipped_unknown_etype: 0,
        unparsed: Vec::new(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    Next,
    Quit,
}

type Run = fn(
    &mut Keytab,
    &Krb5Conf,
    &[String],
    &mut dyn BufRead,
    &mut dyn Write,
) -> Result<Flow, Vec<u8>>;

struct Request {
    names: &'static [&'static str],
    info: &'static str,
    run: Run,
}

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

fn listen(kt: &mut Keytab, profile: &Krb5Conf, input: &mut dyn BufRead, out: &mut dyn Write) {
    // MIT: `ss_listen` (util/ss/listen.c:99-108)
    let _sigint = SignalCatch::new(&[Signal::SIGINT]);
    let mut raw = Vec::new();
    loop {
        // MIT: `listen_int_handler` (util/ss/listen.c:60-63)
        if take_caught().is_some() {
            let _ = out.write_all(b"\n");
        }
        let read = {
            let _sigcont = SignalCatch::new(&[Signal::SIGCONT]);
            line_mode();
            // MIT: `ss_create_invocation` (util/ss/invocation.c:91-96)
            let _ = write!(out, "{WHOAMI}:  ");
            // MIT: `readline` (util/ss/listen.c:44-46)
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
        let end = raw
            .iter()
            .position(|&b| b == b'\r' || b == b'\n' || b == 0)
            .unwrap_or(raw.len());
        match execute_line(kt, profile, &raw[..end], input, out) {
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

fn execute_line(
    kt: &mut Keytab,
    profile: &Krb5Conf,
    line: &[u8],
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT: `ss_execute_line` (util/ss/execute_cmd.c:175-187)
    let start = line
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(line.len());
    let trimmed = &line[start..];
    if trimmed.first() == Some(&b'!') {
        return Ok(Flow::Next);
    }
    let Ok(text) = std::str::from_utf8(trimmed) else {
        return not_utf8(trimmed);
    };
    let argv = krb5_admin::ss_parse(text).map_err(|msg| format!("{WHOAMI}: {msg}").into_bytes())?;
    let Some(name) = argv.first() else {
        return Ok(Flow::Next);
    };
    match REQUESTS.iter().find(|r| r.names.contains(&name.as_str())) {
        Some(r) => (r.run)(kt, profile, &argv, input, out),
        None => {
            // MIT: `ss_listen` (util/ss/listen.c:143-155)
            Err(unknown_request(trimmed))
        }
    }
}

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

fn clear_list(
    kt: &mut Keytab,
    _profile: &Krb5Conf,
    argv: &[String],
    _input: &mut dyn BufRead,
    _out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT: `ktutil_clear_list` (kadmin/ktutil/ktutil.c:70-77)
    if argv.len() != 1 {
        return Err(format!("{}: invalid arguments", argv[0]).into_bytes());
    }
    *kt = empty_list();
    Ok(Flow::Next)
}

fn read_kt(
    kt: &mut Keytab,
    _profile: &Krb5Conf,
    argv: &[String],
    _input: &mut dyn BufRead,
    _out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT: `ktutil_read_v5` (kadmin/ktutil/ktutil.c:85-91)
    let [cmd, path] = argv else {
        return Err(format!("{}: must specify keytab to read", argv[0]).into_bytes());
    };
    let other = krb5_protocol::read_secret_file(Path::new(path))
        .and_then(|bytes| Keytab::parse(&bytes))
        .map_err(|e| {
            format!("{cmd}: {} while reading keytab \"{path}\"", strerror(&e)).into_bytes()
        })?;
    kt.merge(other);
    Ok(Flow::Next)
}

fn read_st(
    _kt: &mut Keytab,
    _profile: &Krb5Conf,
    argv: &[String],
    _input: &mut dyn BufRead,
    _out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT: `ktutil_read_v4` (kadmin/ktutil/ktutil.c:96-98)
    Err(format!("{}: reading srvtabs is no longer supported", argv[0]).into_bytes())
}

fn write_kt(
    kt: &mut Keytab,
    _profile: &Krb5Conf,
    argv: &[String],
    _input: &mut dyn BufRead,
    _out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT: `ktutil_write_v5` (kadmin/ktutil/ktutil.c:106-112)
    let [cmd, path] = argv else {
        return Err(format!("{}: must specify keytab to write", argv[0]).into_bytes());
    };
    // MIT: `ktutil_write_keytab` (kadmin/ktutil/ktutil_funcs.c:336-358)
    kt.add_to_file(Path::new(path)).map_err(|e| {
        format!("{cmd}: {} while writing keytab \"{path}\"", strerror(&e)).into_bytes()
    })?;
    Ok(Flow::Next)
}

fn write_st(
    _kt: &mut Keytab,
    _profile: &Krb5Conf,
    argv: &[String],
    _input: &mut dyn BufRead,
    _out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT: `ktutil_write_v4` (kadmin/ktutil/ktutil.c:117-119)
    Err(format!("{}: writing srvtabs is no longer supported", argv[0]).into_bytes())
}

fn add_entry(
    kt: &mut Keytab,
    profile: &Krb5Conf,
    argv: &[String],
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    let args: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
    addent(kt, profile, &argv[0], &args, input, out)
        .map(|()| Flow::Next)
        .map_err(String::into_bytes)
}

fn delete_entry(
    kt: &mut Keytab,
    _profile: &Krb5Conf,
    argv: &[String],
    _input: &mut dyn BufRead,
    _out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT: `ktutil_delete_entry` (kadmin/ktutil/ktutil.c:184-190)
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

fn list(
    kt: &mut Keytab,
    _profile: &Krb5Conf,
    argv: &[String],
    _input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT: `ktutil_list` (kadmin/ktutil/ktutil.c:203-218)
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

fn format_list(
    kt: &Keytab,
    show_time: bool,
    show_enctype: bool,
    show_keys: bool,
) -> (String, Option<&'static str>) {
    let mut out = String::new();
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
        let _ = write!(out, "{:4} {:4} ", i + 1, kvno.cast_signed());
        if show_time {
            // MIT: `krb5_timestamp_to_sfstring` (lib/krb5/krb/str_conv.c:242-250)
            if let Some(text) =
                krb5_types::timestamp::timestamp_to_sfstring(timestamp, 18, Some(b' '))
            {
                let _ = write!(out, "{text} ");
            }
        }
        let _ = write!(out, "{princ:>40}");
        if show_enctype {
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

#[allow(clippy::unnecessary_wraps)]
fn list_requests(
    _kt: &mut Keytab,
    _profile: &Krb5Conf,
    _argv: &[String],
    _input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT: `ss_list_requests` (util/ss/list_rqs.c:74-102)
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

#[allow(clippy::unnecessary_wraps)]
fn quit(
    _kt: &mut Keytab,
    _profile: &Krb5Conf,
    _argv: &[String],
    _input: &mut dyn BufRead,
    _out: &mut dyn Write,
) -> Result<Flow, Vec<u8>> {
    // MIT: `ss_quit` (util/ss/listen.c:180-182)
    Ok(Flow::Quit)
}

fn strerror(e: &io::Error) -> String {
    let s = e.to_string();
    s.rfind(" (os error ")
        .map_or_else(|| s.clone(), |i| s[..i].to_owned())
}

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

fn addent(
    kt: &mut Keytab,
    profile: &Krb5Conf,
    cmd: &str,
    args: &[&str],
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<(), String> {
    let (mut use_pass, mut use_key) = (0u32, 0u32);
    let (mut princ, mut kvno, mut enctype) = (None, None, None);
    let mut i = 0;
    // MIT: `ktutil_add_entry` (kadmin/ktutil/ktutil.c:132-160)
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
            // Not MIT: no `-s` salt or `-f` fetch.
            opt @ ("-f" | "-s") => return Err(format!("{cmd}: {opt} is not supported")),
            _ => {}
        }
        i += 1;
    }
    let (Some(spec), Some(kvno), 1) = (princ, kvno, use_pass + use_key) else {
        return Err(format!(
            "usage: {cmd} (-key | -password) -p principal -k kvno [-e enctype] [-f|-s salt]"
        ));
    };
    let Some(enctype) = enctype else {
        return Err("enctype must be specified if not using -f".into());
    };
    let fail = |e: &dyn std::fmt::Display| format!("{cmd}: {e} while adding new entry");
    // MIT: `ktutil_add` (kadmin/ktutil/ktutil_funcs.c:159-172)
    let (name, realm) = with_default_realm(spec, profile)
        .and_then(|spec| parse_principal(&spec))
        .map_err(|e| fail(&e))?;
    // MIT: `KRB5_BAD_ENCTYPE` (lib/krb5/error_tables/krb5_err.et:254-254)
    let etype = EncryptionType::from_mit_name(enctype).map_err(|_| fail(&"Bad encryption type"))?;
    let full = name.unparse_with_realm(&realm);
    let key = if use_key == 1 {
        let _ = write!(out, "Key for {full} (hex): ");
        if io::stdout().is_terminal() {
            let _ = out.flush();
        }
        let mut line = Zeroizing::new(Vec::new());
        match fgets(input, BUFSIZ, &mut line) {
            LineEnd::Read => {}
            LineEnd::Caught(_) => {
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
        // Not MIT: a `-key` of the wrong length is refused; 1.22.2 stores it.
        if raw.len() != etype.key_len() {
            return Err(fail(&"protocol key length does not match etype"));
        }
        ProtocolKey::from_bytes(etype, &raw).map_err(|e| fail(&e))?
    } else {
        let pw = match krb5_config::env_password() {
            Some(pw) => Zeroizing::new(pw),
            None => Prompter::terminal(&mut *input, io::stdout())
                .hidden(&format!("Password for {full}"))
                .map_err(|e| fail(&e))?,
        };
        let salt = name.default_salt(&realm);
        string_to_key(etype, pw.as_slice(), salt, None).map_err(|e| fail(&e))?
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

fn hex_decode(digits: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    // MIT: `k5_hex_decode` (util/support/hex.c:96-109)
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

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn with_default_realm(spec: &str, profile: &Krb5Conf) -> Result<String, String> {
    let parsed = krb5_types::parse_name_ex(spec, "", false).map_err(|e| e.to_string())?;
    if parsed.has_realm {
        return Ok(spec.to_owned());
    }
    let realm = profile
        .default_realm
        .clone()
        .ok_or_else(|| krb5_config::Error::NoDefaultRealm.to_string())?;
    Ok(format!("{spec}@{realm}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_crypto::ProtocolKey;
    use krb5_types::{PrincipalName, ascii};

    fn fails(kt: &mut Keytab, line: &str, input: &[u8]) -> Option<String> {
        execute_line(
            kt,
            &krb5_config::isolated_profile(),
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
}
