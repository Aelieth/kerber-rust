//! MIT's `util/ss`.

use std::fmt::Write as _;
use std::io::Write as _;

use super::{Io, LineRead, Session, WHOAMI, kt_cmds, pol_cmds, princ_cmds};

type Verb = fn(&mut Session<'_>, &[String]);

struct Request {
    names: &'static [&'static str],
    info: &'static str,
    run: Verb,
}

const REQUESTS: &[Request] = &[
    Request {
        names: &["add_principal", "addprinc", "ank"],
        info: "Add principal",
        run: princ_cmds::addprinc,
    },
    Request {
        names: &["delete_principal", "delprinc"],
        info: "Delete principal",
        run: princ_cmds::delprinc,
    },
    Request {
        names: &["modify_principal", "modprinc"],
        info: "Modify principal",
        run: princ_cmds::modprinc,
    },
    Request {
        names: &["rename_principal", "renprinc"],
        info: "Rename principal",
        run: princ_cmds::renprinc,
    },
    Request {
        names: &["add_alias", "alias"],
        info: "Add alias",
        run: princ_cmds::addalias,
    },
    Request {
        names: &["change_password", "cpw"],
        info: "Change password",
        run: princ_cmds::cpw,
    },
    Request {
        names: &["get_principal", "getprinc"],
        info: "Get principal",
        run: princ_cmds::getprinc,
    },
    Request {
        names: &[
            "list_principals",
            "listprincs",
            "get_principals",
            "getprincs",
        ],
        info: "List principals",
        run: princ_cmds::getprincs,
    },
    Request {
        names: &["add_policy", "addpol"],
        info: "Add policy",
        run: pol_cmds::addpol,
    },
    Request {
        names: &["modify_policy", "modpol"],
        info: "Modify policy",
        run: pol_cmds::modpol,
    },
    Request {
        names: &["delete_policy", "delpol"],
        info: "Delete policy",
        run: pol_cmds::delpol,
    },
    Request {
        names: &["get_policy", "getpol"],
        info: "Get policy",
        run: pol_cmds::getpol,
    },
    Request {
        names: &["list_policies", "listpols", "get_policies", "getpols"],
        info: "List policies",
        run: pol_cmds::getpols,
    },
    Request {
        names: &["get_privs", "getprivs"],
        info: "Get privileges",
        run: princ_cmds::getprivs,
    },
    Request {
        names: &["ktadd", "xst"],
        info: "Add entry(s) to a keytab",
        run: kt_cmds::ktadd,
    },
    Request {
        names: &["ktremove", "ktrem"],
        info: "Remove entry(s) from a keytab",
        run: kt_cmds::ktremove,
    },
    Request {
        names: &["lock"],
        info: "Lock database exclusively (use with extreme caution!)",
        run: princ_cmds::lock,
    },
    Request {
        names: &["unlock"],
        info: "Release exclusive database lock",
        run: princ_cmds::unlock,
    },
    Request {
        names: &["purgekeys"],
        info: "Purge previously retained old keys from a principal",
        run: princ_cmds::purgekeys,
    },
    Request {
        names: &["get_strings", "getstrs"],
        info: "Show string attributes on a principal",
        run: princ_cmds::getstrings,
    },
    Request {
        names: &["set_string", "setstr"],
        info: "Set a string attribute on a principal",
        run: princ_cmds::setstring,
    },
    Request {
        names: &["del_string", "delstr"],
        info: "Delete a string attribute on a principal",
        run: princ_cmds::delstring,
    },
    Request {
        names: &["list_requests", "lr", "?"],
        info: "List available requests.",
        run: list_requests,
    },
    Request {
        names: &["quit", "exit", "q"],
        info: "Exit program.",
        run: quit_request,
    },
];

fn quit_request(s: &mut Session<'_>, _argv: &[String]) {
    s.abort = true;
}

// MIT: `ss_page_stdin` (pager.c:69-110)
/// Past the buffer, as MIT's pager writes it; no pager runs.
fn list_requests(s: &mut Session<'_>, _argv: &[String]) {
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
    s.io.out.write_raw(text.as_bytes());
}

// MIT: `check_request_table` (execute_cmd.c:56-79)
fn dispatch(s: &mut Session<'_>, argv: &[String]) -> bool {
    let Some(name) = argv.first() else {
        return true;
    };
    match REQUESTS.iter().find(|r| r.names.contains(&name.as_str())) {
        Some(r) => {
            (r.run)(s, argv);
            true
        }
        None => false,
    }
}

// MIT: `ss_execute_command` (execute_cmd.c:134-151)
pub(crate) fn execute_command(s: &mut Session<'_>, argv: &[String]) -> bool {
    dispatch(s, argv)
}

pub(crate) enum Unrun {
    NotFound { lead: String, word: String },
    EscapeDisabled,
}

pub(crate) fn execute_line(s: &mut Session<'_>, line: &str) -> Option<Unrun> {
    let trimmed = line.trim_start_matches([' ', '\t']);
    if trimmed.starts_with('!') {
        return Some(Unrun::EscapeDisabled);
    }
    let mut argv = match parse(trimmed) {
        Ok(argv) => argv,
        Err(msg) => {
            s.io.com_err(WHOAMI, None, msg);
            return None;
        }
    };
    if argv.is_empty() || dispatch(s, &argv) {
        return None;
    }
    Some(Unrun::NotFound {
        lead: line[..line.len() - trimmed.len()].to_owned(),
        word: argv.swap_remove(0),
    })
}

// MIT: `ss_perror` (error.c:66-69)
pub(crate) fn perror(io: &mut Io, code: &str, shown: &str) {
    io.com_err(WHOAMI, Some(code), shown);
}

pub(crate) const COMMAND_NOT_FOUND: &str = "Command not found";
pub(crate) const ESCAPE_DISABLED: &str = "Shell escapes are disabled";

// MIT: `ss_parse` (util/ss/parse.c:57-169)
/// Blanks split words; `"` quotes in a word, `""` is one; an open quote errors.
pub fn parse(line: &str) -> Result<Vec<String>, &'static str> {
    let mut argv = Vec::new();
    let mut cur = String::new();
    let mut in_token = false;
    let mut quoted = false;
    let mut it = line.chars().peekable();
    while let Some(c) = it.next() {
        if quoted {
            if c != '"' {
                cur.push(c);
            } else if it.peek() == Some(&'"') {
                it.next();
                cur.push('"');
            } else {
                quoted = false;
            }
        } else if c == '"' {
            quoted = true;
            in_token = true;
        } else if c == ' ' || c == '\t' {
            if in_token {
                argv.push(std::mem::take(&mut cur));
                in_token = false;
            }
        } else {
            in_token = true;
            cur.push(c);
        }
    }
    if quoted {
        return Err("Unbalanced quotes in command line");
    }
    if in_token {
        argv.push(cur);
    }
    Ok(argv)
}

/// Until `quit` or end of input; `SIGINT` re-prompts, a running request finishes
/// first.
pub(crate) fn listen(s: &mut Session<'_>) {
    let _sigint = krb5_cli::SignalCatch::new(&[krb5_cli::Signal::SIGINT]);
    s.abort = false;
    while !s.abort {
        if krb5_cli::take_caught().is_some() {
            s.io.print("\n");
        }
        let read = {
            let _sigcont = krb5_cli::SignalCatch::new(&[krb5_cli::Signal::SIGCONT]);
            if s.io.tty_in {
                krb5_cli::line_mode();
            }
            s.io.print(&format!("{WHOAMI}:  "));
            let _ = s.io.out.flush();
            s.io.read_line()
        };
        let raw = match read {
            LineRead::Line(raw) => raw,
            LineRead::Caught => {
                s.io.print("\n");
                continue;
            }
            LineRead::End => break,
        };
        let end = raw
            .iter()
            .position(|&b| b == b'\r' || b == b'\n')
            .unwrap_or(raw.len());
        match std::str::from_utf8(&raw[..end]) {
            Ok(line) => {
                if let Some(Unrun::NotFound { word, .. }) = execute_line(s, line) {
                    unknown_request(s.io, word.as_bytes());
                }
            }
            Err(_) => not_utf8(s, &raw[..end]),
        }
        if std::mem::take(&mut s.io.interrupted) {
            s.io.print("\n");
        }
    }
}

fn unknown_request(io: &mut Io, word: &[u8]) {
    let mut text = format!("{WHOAMI}: Unknown request \"").into_bytes();
    text.extend_from_slice(word);
    text.extend_from_slice(b"\".  Type \"?\" for a request list.\n");
    io.eprint_bytes(&text);
}

/// Non-UTF-8 names are refused; an unknown request is echoed byte for byte.
fn not_utf8(s: &mut Session<'_>, raw: &[u8]) {
    let bytes: String = raw.iter().copied().map(char::from).collect();
    let trimmed = bytes.trim_start_matches([' ', '\t']);
    if trimmed.starts_with('!') {
        return;
    }
    let argv = match parse(trimmed) {
        Ok(argv) => argv,
        Err(msg) => {
            s.io.com_err(WHOAMI, None, msg);
            return;
        }
    };
    let Some(first) = argv.first() else {
        return;
    };
    if REQUESTS.iter().any(|r| r.names.contains(&first.as_str())) {
        s.io.error(&format!(
            "{WHOAMI}: Request line is not valid UTF-8; it was not run.\n"
        ));
        return;
    }
    let word: Vec<u8> = first
        .chars()
        .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
        .collect();
    unknown_request(s.io, &word);
}
