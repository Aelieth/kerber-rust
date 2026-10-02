//! The `ss` subsystem `kadmin.local` runs its commands in (`util/ss`): the request table,
//! line parsing, the prompt loop, `list_requests` and the `!` shell escape.

use std::fmt::Write as _;
use std::io::Write as _;

use super::{Io, Session, WHOAMI, kt_cmds, pol_cmds, princ_cmds};

type Verb = fn(&mut Session<'_>, &[String]);

/// One request: its names, its one-line description, and what runs it.
struct Request {
    names: &'static [&'static str],
    info: &'static str,
    run: Verb,
}

/// The `kadmin_cmds` table (`kadmin_ct.ct`), in its order.
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

/// MIT `ss_quit` (`listen.c:180-183`): the command loop ends after this request.
fn quit_request(s: &mut Session<'_>, _argv: &[String]) {
    s.abort = true;
}

/// MIT `ss_list_requests` (`list_rqs.c:24-114`): each request's names, the description at
/// column 25 (on a line of its own when the names run past 23).
/// MIT `ss_page_stdin` (`pager.c:69-110`): the list is copied to stdout as the pager process
/// writes it there, past what stdout still buffers; no pager is run.
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

/// MIT `check_request_table` (`execute_cmd.c:56-79`): run the request `argv[0]` names; false
/// when no request has that name.
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

/// MIT `ss_execute_command` (`execute_cmd.c:134-151`): the command line's own words, unparsed.
pub(crate) fn execute_command(s: &mut Session<'_>, argv: &[String]) -> bool {
    dispatch(s, argv)
}

/// What `ss_execute_line` returns for a line it did not run.
pub(crate) enum Unrun {
    /// `SS_ET_COMMAND_NOT_FOUND`: the line's leading blanks and its first word as the parse
    /// left it, which is what `ss_perror` and `ss_listen` print.
    NotFound { lead: String, word: String },
    /// `SS_ET_ESCAPE_DISABLED`: a `!` shell escape.
    EscapeDisabled,
}

/// MIT `ss_execute_line` (`execute_cmd.c:170-201`): the line parsed and run. A `!` line is not
/// given to the shell: this port runs as MIT's `ss` does when `ss_disable_escape` is set.
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

/// MIT `ss_perror` (`error.c:66-69`): `kadmin.local: <error> <text>`.
pub(crate) fn perror(io: &mut Io, code: &str, shown: &str) {
    io.com_err(WHOAMI, Some(code), shown);
}

/// `ss_err.et`: the text of `SS_ET_COMMAND_NOT_FOUND`.
pub(crate) const COMMAND_NOT_FOUND: &str = "Command not found";
/// `ss_err.et`: the text of `SS_ET_ESCAPE_DISABLED`.
pub(crate) const ESCAPE_DISABLED: &str = "Shell escapes are disabled";

/// MIT `ss_parse` (`util/ss/parse.c:57-169`): words split on blanks; `"` quotes, inside a word
/// too, and `""` within quotes is one `"`; an open quote is `Unbalanced quotes in command line`.
pub(crate) fn parse(line: &str) -> Result<Vec<String>, &'static str> {
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

/// MIT `ss_listen` (`listen.c:67-169`): an unknown request is reported; until `quit` or the end
/// of input.
/// MIT `readline` (`listen.c:32-50`): the prompt, flushed, and one line up to its `\r` or `\n`.
pub(crate) fn listen(s: &mut Session<'_>) {
    s.abort = false;
    while !s.abort {
        s.io.print(&format!("{WHOAMI}:  "));
        let _ = s.io.out.flush();
        let Some(raw) = s.io.read_line() else {
            break;
        };
        let line = String::from_utf8_lossy(&raw);
        let line = match line.find(['\r', '\n']) {
            Some(end) => &line[..end],
            None => &line[..],
        };
        if let Some(Unrun::NotFound { word, .. }) = execute_line(s, line) {
            s.io.com_err(
                WHOAMI,
                None,
                &format!("Unknown request \"{word}\".  Type \"?\" for a request list."),
            );
        }
    }
}
