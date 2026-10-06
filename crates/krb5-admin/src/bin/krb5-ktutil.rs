//! MIT-style ktutil: rkt/list/wkt/addent/delent on an in-memory keytab.
//!
//! Commands from argv (one shot) or stdin. `addent -password` prompts and reads the password
//! from stdin, the next line of a piped command stream, as MIT's does; a `test-hooks` build (the
//! gates') takes `KRB5_PASSWORD` when it is set. Never from argv. A failed command prints the
//! line MIT's prints; the stdin loop exits 0 whatever its commands did, as MIT's, and a failed
//! one-shot command exits 1.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::fmt::Write as _;
use std::io::{self, BufRead, Write};
use std::path::Path;

use krb5_cli::Prompter;
use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_protocol::{Keytab, KeytabEntry, KeytabSlot, parse_principal};
use zeroize::Zeroizing;

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    // MIT `main` (`ktutil.c:49-53`): the library context before the first request; a profile it
    // refuses ends ktutil.
    if let Err(e) = krb5_config::init_profile() {
        let prog = argv.first().map_or("ktutil", String::as_str);
        eprintln!("{prog}: {} while initializing krb5", e.init_text());
        std::process::exit(1);
    }
    let args: Vec<String> = argv.into_iter().skip(1).collect();
    let mut kt = Keytab {
        version: 0x0502,
        entries: Vec::new(),
        skipped_unknown_etype: 0,
        unparsed: Vec::new(),
    };
    let mut input = io::stdin().lock();
    if args.is_empty() {
        // MIT `main` (`ktutil.c:60-62`): the command loop, then exit 0 whatever it ran.
        run_stdin_reader(&mut kt, &mut input);
        return;
    }
    if let Err(line) = run_line(&mut kt, &args.join(" "), &mut input) {
        eprintln!("{line}");
        std::process::exit(1);
    }
}

enum LineOutcome {
    Next,
    Quit,
}

#[cfg(test)]
fn run_stdin<I, S>(kt: &mut Keytab, lines: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut failed = false;
    for line in lines {
        match run_line(kt, line.as_ref(), &mut io::empty()) {
            Ok(LineOutcome::Next) => {}
            Ok(LineOutcome::Quit) => break,
            Err(line) => {
                eprintln!("{line}");
                failed = true;
            }
        }
    }
    failed
}

/// Run the commands read from `reader`, which also answers their prompts; whether one failed.
/// MIT `ss_listen` (`listen.c:120-155`): a read failure ends the loop with no message, and a line
/// that is no request is an unknown request named by its first word, bytes as read.
fn run_stdin_reader<R: BufRead>(kt: &mut Keytab, mut reader: R) -> bool {
    let mut failed = false;
    let mut raw = Vec::new();
    loop {
        raw.clear();
        match reader.read_until(b'\n', &mut raw) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => {
                failed = true;
                break;
            }
        }
        let Ok(line) = std::str::from_utf8(&raw) else {
            let word = raw
                .split(u8::is_ascii_whitespace)
                .find(|w| !w.is_empty())
                .unwrap_or_default();
            let mut err = io::stderr().lock();
            let _ = err.write_all(b"ktutil: Unknown request \"");
            let _ = err.write_all(word);
            let _ = err.write_all(b"\".  Type \"?\" for a request list.\n");
            failed = true;
            continue;
        };
        match run_line(kt, line, &mut reader) {
            Ok(LineOutcome::Next) => {}
            Ok(LineOutcome::Quit) => break,
            Err(line) => {
                eprintln!("{line}");
                failed = true;
            }
        }
    }
    failed
}

/// One command; `input` answers its prompts. A failure is the line MIT's ktutil prints for it:
/// the command's name, then what went wrong.
fn run_line(kt: &mut Keytab, line: &str, input: &mut dyn BufRead) -> Result<LineOutcome, String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(LineOutcome::Next);
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    let Some((&cmd, args)) = parts.split_first() else {
        return Ok(LineOutcome::Next);
    };
    match cmd {
        "q" | "quit" | "exit" => Ok(LineOutcome::Quit),
        "rkt" => {
            // MIT `ktutil_read_v5` (`ktutil.c:85-91`): one argument, and a failure names the keytab.
            let [path] = args else {
                return Err(format!("{cmd}: must specify keytab to read"));
            };
            let other = std::fs::read(path)
                .and_then(|bytes| Keytab::parse(&bytes))
                .map_err(|e| format!("{cmd}: {} while reading keytab \"{path}\"", strerror(&e)))?;
            kt.version = other.version;
            kt.merge(other);
            Ok(LineOutcome::Next)
        }
        "wkt" => {
            // MIT `ktutil_write_v5` (`ktutil.c:106-112`): one argument, and a failure names the keytab.
            let [path] = args else {
                return Err(format!("{cmd}: must specify keytab to write"));
            };
            kt.write_file(Path::new(path))
                .map_err(|e| format!("{cmd}: {} while writing keytab \"{path}\"", strerror(&e)))?;
            Ok(LineOutcome::Next)
        }
        "list" | "l" => {
            print!(
                "{}",
                format_list(
                    kt,
                    args.contains(&"-t"),
                    args.contains(&"-e"),
                    args.contains(&"-K"),
                )
            );
            Ok(LineOutcome::Next)
        }
        "delent" => {
            // MIT `ktutil_delete_entry` (`ktutil.c:184-190`): one argument read by atoi; no such entry is EINVAL.
            let [slot] = args else {
                return Err(format!("{cmd}: must specify entry to delete"));
            };
            let n = atoi(slot);
            usize::try_from(n)
                .ok()
                .and_then(|slot| kt.remove_slot(slot).ok())
                .ok_or_else(|| format!("{cmd}: Invalid argument while deleting entry {n}"))?;
            Ok(LineOutcome::Next)
        }
        "addent" => addent(kt, args, input).map(|()| LineOutcome::Next),
        // MIT `ss_listen` (`listen.c:143-155`): an unknown request names its first word.
        other => Err(format!(
            "ktutil: Unknown request \"{other}\".  Type \"?\" for a request list."
        )),
    }
}

/// The OS error text as C `strerror` gives it, without Rust's `(os error N)`.
fn strerror(e: &io::Error) -> String {
    let s = e.to_string();
    s.rfind(" (os error ")
        .map_or_else(|| s.clone(), |i| s[..i].to_owned())
}

/// C `atoi`: an optional sign and the leading digits; 0 when there are none.
fn atoi(s: &str) -> i64 {
    let s = s.trim_start();
    let (sign, digits) = match s.strip_prefix('-') {
        Some(rest) => (-1, rest),
        None => (1, s.strip_prefix('+').unwrap_or(s)),
    };
    let n = digits
        .bytes()
        .take_while(u8::is_ascii_digit)
        .fold(0i64, |n, d| {
            n.saturating_mul(10).saturating_add(i64::from(d - b'0'))
        });
    sign * n
}

fn format_list(kt: &Keytab, show_t: bool, show_e: bool, show_k: bool) -> String {
    let mut out = String::from("slot KVNO Principal\n");
    for (i, slot) in kt.slots().iter().enumerate() {
        match slot {
            KeytabSlot::Entry(e) => {
                let princ = format!(
                    "{}@{}",
                    e.name.components_joined(),
                    String::from_utf8_lossy(e.realm.as_bytes())
                );
                let _ = write!(out, "{:>4} {:>4} {princ}", i + 1, e.kvno);
                if show_t {
                    let _ = write!(out, " t={}", e.timestamp);
                }
                if show_e {
                    let _ = write!(out, " {}", e.key.etype().to_mit_name());
                }
                if show_k {
                    let _ = write!(out, " ({})", hex(e.key.as_bytes()));
                }
            }
            KeytabSlot::Unparsed(raw) => match Keytab::unparsed_meta(raw, kt.version) {
                Some((kvno, princ, ts, enctype)) => {
                    let _ = write!(out, "{:>4} {:>4} {princ}", i + 1, kvno);
                    if show_t {
                        let _ = write!(out, " t={ts}");
                    }
                    if show_e {
                        let _ = write!(out, " Unknown ({enctype})");
                    }
                    if show_k {
                        let _ = write!(out, " (-)");
                    }
                }
                None => {
                    let _ = write!(out, "{:>4}    - (unparsed)", i + 1);
                }
            },
        }
        out.push('\n');
    }
    out
}

/// `addent`: one keytab entry from a password or a hex key.
/// MIT `ktutil_add_entry` (`ktutil.c:132-160`): `-p`, `-k`, `-e`, `-password`, `-key`, `-s` and `-f` are read, any other word is passed over.
fn addent(kt: &mut Keytab, args: &[&str], input: &mut dyn BufRead) -> Result<(), String> {
    let (mut use_pass, mut use_key) = (false, false);
    let (mut princ, mut kvno, mut enctype) = (None, None, None);
    let mut i = 0;
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
            "-password" => use_pass = true,
            "-key" => use_key = true,
            // A salt from the KDC or the command line is not built here: refused, not passed over.
            opt @ ("-f" | "-s") => return Err(format!("addent: {opt} is not supported")),
            _ => {}
        }
        i += 1;
    }
    // MIT `ktutil_add_entry` (`ktutil.c:162-171`): the usage line unless a principal, a kvno and one of -password or -key; an enctype unless -f.
    let (Some(spec), Some(kvno), true) = (princ, kvno, use_pass != use_key) else {
        return Err(
            "usage: addent (-key | -password) -p principal -k kvno [-e enctype] [-f|-s salt]"
                .into(),
        );
    };
    let Some(enctype) = enctype else {
        return Err("enctype must be specified if not using -f".into());
    };
    // MIT `ktutil_add_entry` (`ktutil.c:173-176`): a failure of the entry is reported "while adding new entry".
    let fail = |e: &dyn std::fmt::Display| format!("addent: {e} while adding new entry");
    // MIT `ktutil_add` (`ktutil_funcs.c:159-173`): the name takes the default realm, and an unknown enctype is `KRB5_BAD_ENCTYPE`.
    let (name, realm) = with_default_realm(spec)
        .and_then(|spec| parse_principal(&spec))
        .map_err(|e| fail(&e))?;
    // MIT `KRB5_BAD_ENCTYPE` (`krb5_err.et:254-254`): the text.
    let etype = EncryptionType::from_mit_name(enctype).map_err(|_| fail(&"Bad encryption type"))?;
    let full = name.unparse_with_realm(&realm);
    let key = if use_key {
        // MIT `ktutil_add` (`ktutil_funcs.c:204-233`): `Key for <name> (hex): ` and a line of stdin, a `0` after an odd digit count.
        print!("Key for {full} (hex): ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        input
            .read_line(&mut line)
            .map_err(|e| fail(&strerror(&e)))?;
        let mut digits = line.strip_suffix('\n').unwrap_or(&line).to_owned();
        if digits.is_empty() {
            return Err("addent: Error reading key.".into());
        }
        if !digits.len().is_multiple_of(2) {
            digits.push('0');
        }
        let raw = hex_decode(&digits).ok_or("addent: Illegal character in key.")?;
        ProtocolKey::from_bytes(etype, &raw).map_err(|e| fail(&e))?
    } else {
        let pw = match krb5_config::env_password() {
            Some(pw) => Zeroizing::new(pw),
            // MIT `ktutil_add` (`ktutil_funcs.c:182-192`): `Password for <name>`, asked once, unechoed on a terminal.
            None => Prompter::terminal(&mut *input, io::stdout())
                .hidden(&format!("Password for {full}"))
                .map_err(|e| fail(&e))?,
        };
        let salt = name.default_salt(&realm);
        string_to_key(etype, pw.as_slice(), salt, Some(&4096u32.to_be_bytes()))
            .map_err(|e| fail(&e))?
    };
    let kvno = u32::try_from(kvno.rem_euclid(1 << 32)).unwrap_or(0);
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

/// Hex digits, two to a byte; `None` for any other character.
fn hex_decode(digits: &str) -> Option<Vec<u8>> {
    if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    digits
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// `spec`, with krb5.conf's `default_realm` when it names no realm.
/// MIT `krb5_parse_name_flags` (`krb/parse.c:198-211`): a name with no realm takes the default realm.
fn with_default_realm(spec: &str) -> Result<String, String> {
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

    #[test]
    fn run_line_list_e_prints_etype() {
        let key = ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[3u8; 32]).unwrap();
        let mut kt = Keytab {
            version: 0x0502,
            entries: vec![KeytabEntry {
                realm: ascii("KERBER.TEST"),
                name: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
                timestamp: 1_700_000_000,
                kvno: 2,
                key,
            }],
            skipped_unknown_etype: 0,
            unparsed: Vec::new(),
        };
        run_line(&mut kt, "list -e", &mut io::empty()).unwrap();
        let text = format_list(&kt, false, true, false);
        assert!(text.contains("user@KERBER.TEST"), "{text}");
        assert!(text.contains("aes256-cts-hmac-sha1-96"), "{text}");
        assert!(text.contains("   2"), "{text}");
        assert!(run_line(&mut kt, "nope", &mut io::empty()).is_err());
    }

    fn empty_kt() -> Keytab {
        Keytab {
            version: 0x0502,
            entries: Vec::new(),
            skipped_unknown_etype: 0,
            unparsed: Vec::new(),
        }
    }

    #[test]
    fn stdin_nope_then_quit_runs_both() {
        let mut kt = empty_kt();
        assert!(run_stdin(&mut kt, ["nope", "q"]));
        let mut kt = empty_kt();
        assert!(run_stdin(&mut kt, ["nope", "quit"]));
        let mut kt = empty_kt();
        assert!(run_stdin(&mut kt, ["nope", "exit"]));
    }

    #[test]
    fn stdin_quit_stops_before_later_failure() {
        let mut kt = empty_kt();
        assert!(!run_stdin(&mut kt, ["q"]));
        let mut kt = empty_kt();
        assert!(!run_stdin(&mut kt, ["q", "nope"]));
        assert!(matches!(
            run_line(&mut kt, "quit", &mut io::empty()),
            Ok(LineOutcome::Quit)
        ));
    }

    #[test]
    fn stdin_invalid_utf8_is_reported_and_skipped() {
        let mut kt = empty_kt();
        assert!(run_stdin_reader(
            &mut kt,
            std::io::Cursor::new(b"\xff\nq\n")
        ));
        let mut kt = empty_kt();
        assert!(run_stdin_reader(
            &mut kt,
            std::io::Cursor::new(b"\xff\nnope\nq\n")
        ));
    }

    #[test]
    fn failures_are_mit_s_lines() {
        // Live MIT 1.22.2 ktutil, each line on stderr with the loop's exit status 0.
        let mut kt = empty_kt();
        let dir = krb5_testkit::scratch_dir("ktutil-lines");
        let missing = dir.join("no-such.kt");
        let missing = missing.to_str().unwrap();
        let mut fails = |line: &str, input: &[u8]| {
            run_line(&mut kt, line, &mut io::Cursor::new(input))
                .err()
                .unwrap_or_default()
        };
        assert_eq!(
            fails("nope", b""),
            "ktutil: Unknown request \"nope\".  Type \"?\" for a request list."
        );
        assert_eq!(fails("rkt", b""), "rkt: must specify keytab to read");
        assert_eq!(
            fails(&format!("rkt {missing}"), b""),
            format!("rkt: No such file or directory while reading keytab \"{missing}\"")
        );
        assert_eq!(fails("wkt", b""), "wkt: must specify keytab to write");
        assert_eq!(fails("delent", b""), "delent: must specify entry to delete");
        assert_eq!(
            fails("delent 9", b""),
            "delent: Invalid argument while deleting entry 9"
        );
        assert_eq!(
            fails("addent", b""),
            "usage: addent (-key | -password) -p principal -k kvno [-e enctype] [-f|-s salt]"
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

    #[test]
    fn addent_password_is_the_next_line_of_the_command_stream() {
        if krb5_config::env_password().is_some() {
            // A test-hooks build with KRB5_PASSWORD set takes it instead of the prompt.
            return;
        }
        // Live MIT 1.22.2 ktutil: `Password for user@REALM: `, the reply read from the next
        // line of stdin, the rest of the stream left for the next command.
        let mut kt = empty_kt();
        let input =
            b"addent -password -p user@R.TEST -k 3 -e aes256-cts-hmac-sha1-96\nsecret\nq\nnope\n";
        assert!(!run_stdin_reader(&mut kt, io::Cursor::new(&input[..])));
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
        let Err(e) = run_line(&mut kt, line, &mut io::empty()) else {
            panic!("addent took a password from an empty stream");
        };
        assert_eq!(e, "addent: Cannot read password while adding new entry");
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
    fn stdin_read_error_breaks() {
        let mut kt = empty_kt();
        let failed = run_stdin_reader(
            &mut kt,
            io::BufReader::new(InjectedErr {
                kind: io::ErrorKind::Other,
                n: 0,
            }),
        );
        assert!(failed);
    }

    #[test]
    fn list_numbers_unparsed_slots() {
        let mut kt = empty_kt();
        kt.entries.push(KeytabEntry {
            realm: ascii("KERBER.TEST"),
            name: PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]),
            timestamp: 1,
            kvno: 1,
            key: ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha196, &[3u8; 32]).unwrap(),
        });
        kt.unparsed
            .push((0, zeroize::Zeroizing::new(vec![0, 0, 0, 4, 0, 0, 0, 0])));
        let text = format_list(&kt, false, false, false);
        assert!(text.contains("   1    - (unparsed)"), "{text}");
        assert!(text.contains("   2    1 user@KERBER.TEST"), "{text}");
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
        kt.unparsed.clear();
        kt.unparsed.push((0, zeroize::Zeroizing::new(rec)));
        let text = format_list(&kt, false, true, false);
        assert!(
            text.contains("   1    7 user@KERBER.TEST Unknown (99)"),
            "{text}"
        );
        assert!(text.contains("   2    1 user@KERBER.TEST"), "{text}");
        run_line(&mut kt, "delent 1", &mut io::empty()).unwrap();
        assert_eq!(kt.unparsed, [] as [(usize, zeroize::Zeroizing<Vec<u8>>); 0]);
        assert_eq!(kt.entries.len(), 1);
    }
}
