//! MIT-style ktutil: rkt/list/wkt/addent/delent on an in-memory keytab.
//!
//! Commands from argv (one shot) or stdin. `addent -password` prompts and reads the password
//! from stdin, the next line of a piped command stream, as MIT's does; a `test-hooks` build (the
//! gates') takes `KRB5_PASSWORD` when it is set. Never from argv.

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
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut kt = Keytab {
        version: 0x0502,
        entries: Vec::new(),
        skipped_unknown_etype: 0,
        unparsed: Vec::new(),
    };
    let mut input = io::stdin().lock();
    if args.is_empty() {
        std::process::exit(run_stdin_reader(&mut kt, &mut input));
    }
    if let Err(e) = run_line(&mut kt, &args.join(" "), &mut input) {
        eprintln!("ktutil: {e}");
        std::process::exit(1);
    }
}

enum LineOutcome {
    Next,
    Quit,
}

#[cfg(test)]
fn run_stdin<I, S>(kt: &mut Keytab, lines: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut failed = false;
    for line in lines {
        match run_line(kt, line.as_ref(), &mut io::empty()) {
            Ok(LineOutcome::Next) => {}
            Ok(LineOutcome::Quit) => break,
            Err(e) => {
                eprintln!("ktutil: {e}");
                failed = true;
            }
        }
    }
    i32::from(failed)
}

/// Run the commands read from `reader`, which also answers their prompts.
fn run_stdin_reader<R: BufRead>(kt: &mut Keytab, mut reader: R) -> i32 {
    let mut failed = false;
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                eprintln!("ktutil: {e}");
                failed = true;
                if e.kind() == io::ErrorKind::InvalidData {
                    continue;
                }
                break;
            }
        }
        match run_line(kt, &line, &mut reader) {
            Ok(LineOutcome::Next) => {}
            Ok(LineOutcome::Quit) => break,
            Err(e) => {
                eprintln!("ktutil: {e}");
                failed = true;
            }
        }
    }
    i32::from(failed)
}

/// One command; `input` answers its prompts.
fn run_line(kt: &mut Keytab, line: &str, input: &mut dyn BufRead) -> Result<LineOutcome, String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(LineOutcome::Next);
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts.first().copied() {
        Some("q" | "quit" | "exit") => Ok(LineOutcome::Quit),
        Some("rkt") => {
            let path = parts.get(1).ok_or("rkt <file>")?;
            let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
            let other = Keytab::parse(&bytes).map_err(|e| e.to_string())?;
            kt.version = other.version;
            kt.merge(other);
            Ok(LineOutcome::Next)
        }
        Some("wkt") => {
            let path = parts.get(1).ok_or("wkt <file>")?;
            kt.write_file(Path::new(path)).map_err(|e| e.to_string())?;
            Ok(LineOutcome::Next)
        }
        Some("list" | "l") => {
            print!(
                "{}",
                format_list(
                    kt,
                    parts.contains(&"-t"),
                    parts.contains(&"-e"),
                    parts.contains(&"-K"),
                )
            );
            Ok(LineOutcome::Next)
        }
        Some("delent") => {
            let slot: usize = parts
                .get(1)
                .ok_or("delent <slot>")?
                .parse()
                .map_err(|_| "delent slot")?;
            kt.remove_slot(slot).map_err(|e| e.to_string())?;
            Ok(LineOutcome::Next)
        }
        Some("addent") => addent(kt, &parts[1..], input).map(|()| LineOutcome::Next),
        Some(other) => Err(format!("unknown command {other}")),
        None => Ok(LineOutcome::Next),
    }
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

fn addent(kt: &mut Keytab, args: &[&str], input: &mut dyn BufRead) -> Result<(), String> {
    let mut password = false;
    let mut hexkey = false;
    let mut princ = None::<String>;
    let mut kvno = 1u32;
    let mut etype = EncryptionType::Aes256CtsHmacSha196;
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "-password" => password = true,
            "-key" => hexkey = true,
            "-p" => {
                i += 1;
                princ = args.get(i).map(|s| (*s).to_owned());
            }
            "-k" => {
                i += 1;
                kvno = args
                    .get(i)
                    .ok_or("-k <kvno>")?
                    .parse()
                    .map_err(|_| "kvno")?;
            }
            "-e" => {
                i += 1;
                etype = EncryptionType::from_mit_name(args.get(i).ok_or("-e <etype>")?)
                    .map_err(|e| e.to_string())?;
            }
            other => return Err(format!("addent: unknown {other}")),
        }
        i += 1;
    }
    let spec = princ.ok_or("addent -p principal")?;
    let (name, realm) = parse_principal(&spec)?;
    let full = name.unparse_with_realm(&realm);
    let key = if hexkey {
        // MIT `ktutil_add` (`ktutil_funcs.c:204-206`): `Key for <name> (hex): `, then one line of stdin.
        print!("Key for {full} (hex): ");
        let _ = io::stdout().flush();
        let mut s = String::new();
        input.read_line(&mut s).map_err(|e| e.to_string())?;
        let raw = parse_hex(s.trim())?;
        ProtocolKey::from_bytes(etype, &raw).map_err(|e| e.to_string())?
    } else if password {
        let pw = match krb5_config::env_password() {
            Some(pw) => Zeroizing::new(pw),
            // MIT `ktutil_add` (`ktutil_funcs.c:182-192`): `Password for <name>`, asked once, unechoed on a terminal.
            None => Prompter::terminal(&mut *input, io::stdout())
                .hidden(&format!("Password for {full}"))
                // MIT `ktutil_add_entry` (`ktutil.c:173-176`): a failure is reported "while adding new entry".
                .map_err(|e| format!("addent: {e} while adding new entry"))?,
        };
        let salt = name.default_salt(&realm);
        string_to_key(etype, pw.as_slice(), salt, Some(&4096u32.to_be_bytes()))
            .map_err(|e| e.to_string())?
    } else {
        return Err("addent needs -password or -key".into());
    };
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

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "hex".to_string()))
        .collect()
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
    fn stdin_nope_then_quit_exits_1() {
        let mut kt = empty_kt();
        assert_eq!(run_stdin(&mut kt, ["nope", "q"]), 1);
        let mut kt = empty_kt();
        assert_eq!(run_stdin(&mut kt, ["nope", "quit"]), 1);
        let mut kt = empty_kt();
        assert_eq!(run_stdin(&mut kt, ["nope", "exit"]), 1);
    }

    #[test]
    fn stdin_quit_stops_before_later_failure() {
        let mut kt = empty_kt();
        assert_eq!(run_stdin(&mut kt, ["q"]), 0);
        let mut kt = empty_kt();
        assert_eq!(run_stdin(&mut kt, ["q", "nope"]), 0);
        assert!(matches!(
            run_line(&mut kt, "quit", &mut io::empty()),
            Ok(LineOutcome::Quit)
        ));
    }

    #[test]
    fn stdin_invalid_utf8_exits_1() {
        let mut kt = empty_kt();
        let rc = run_stdin_reader(&mut kt, std::io::Cursor::new(b"\xff\nq\n"));
        assert_eq!(rc, 1);
        let mut kt = empty_kt();
        let rc = run_stdin_reader(&mut kt, std::io::Cursor::new(b"\xff\nnope\nq\n"));
        assert_eq!(rc, 1);
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
        assert_eq!(run_stdin_reader(&mut kt, io::Cursor::new(&input[..])), 0);
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
        let rc = run_stdin_reader(
            &mut kt,
            io::BufReader::new(InjectedErr {
                kind: io::ErrorKind::Other,
                n: 0,
            }),
        );
        assert_eq!(rc, 1);
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
        kt.unparsed.push((0, vec![0, 0, 0, 4, 0, 0, 0, 0]));
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
        kt.unparsed.push((0, rec));
        let text = format_list(&kt, false, true, false);
        assert!(
            text.contains("   1    7 user@KERBER.TEST Unknown (99)"),
            "{text}"
        );
        assert!(text.contains("   2    1 user@KERBER.TEST"), "{text}");
        run_line(&mut kt, "delent 1", &mut io::empty()).unwrap();
        assert_eq!(kt.unparsed, [] as [(usize, Vec<u8>); 0]);
        assert_eq!(kt.entries.len(), 1);
    }
}
