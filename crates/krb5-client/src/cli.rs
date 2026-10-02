//! getopt-compatible CLI parsing for kinit/klist/kvno/kdestroy.

pub use krb5_cli::{LongOpt, Opt, getopt};
use krb5_protocol::{CcacheCred, FileCcache};

/// What `kinit` does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KinitAction {
    /// Initial credentials with a password.
    #[default]
    InitPw,
    /// Initial credentials with a keytab (`-k`).
    InitKt,
    /// Renew the cache's TGT (`-R`).
    Renew,
    /// Validate the cache's TGT (`-v`).
    Validate,
}

/// Parsed `kinit` argv.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KinitArgs {
    /// `-V`.
    pub verbose: bool,
    /// What to do: the last of `-k`, `-R` and `-v`, else a password.
    pub action: KinitAction,
    /// `-k` (also forced by `-t` / `-i`).
    pub keytab: bool,
    /// `-R`.
    pub renew: bool,
    /// `-v`.
    pub validate: bool,
    /// `-i`.
    pub client_keytab: bool,
    /// `-t keytab`.
    pub keytab_path: Option<String>,
    /// `-c cache`.
    pub ccache: Option<String>,
    /// `-r`, in seconds.
    pub rlife: Option<u64>,
    /// `-l`, in seconds.
    pub lifetime: Option<u64>,
    /// `-s`, in seconds from now.
    pub starttime: Option<u64>,
    /// `-f` / `-F`.
    pub forwardable: Option<bool>,
    /// `-p` / `-P`.
    pub proxiable: Option<bool>,
    /// `-a` / `-A`.
    pub addresses: Option<bool>,
    /// `-S service`.
    pub service: Option<String>,
    /// `-E`.
    pub enterprise: bool,
    /// `-n`.
    pub anonymous: bool,
    /// `-C`.
    pub canonicalize: bool,
    /// `-X` values.
    pub pa_attrs: Vec<String>,
    /// `-T armor_ccache`.
    pub armor_ccache: Option<String>,
    /// `-X X509_user_identity=`.
    pub pkinit_identity: Option<String>,
    /// `-X X509_anchors=`.
    pub pkinit_anchors: Option<String>,
    /// The client principal.
    pub principal: Option<String>,
    /// MIT's notices printed before any work ("keytab specified, forcing -k").
    pub notices: Vec<String>,
    /// The gates' options, in a `test-hooks` build only.
    #[cfg(feature = "test-hooks")]
    pub gate: KinitGateArgs,
}

/// The gates' `kinit` options, in a `test-hooks` build only: `--spake` (send PA-SPAKE first),
/// `--fast` (no effect), `--armor-ccache` (`-T`), `--pkinit` / `--pkinit-anchors`
/// (`-X X509_user_identity=` / `-X X509_anchors=`), and the positional form
/// `[kdc-host] principal [ccache [service]]`.
#[cfg(feature = "test-hooks")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KinitGateArgs {
    /// `--spake`.
    pub want_spake: bool,
    /// A first argument with no `@` before a principal: the KDC host (`host[:port]`).
    pub kdc_host: Option<String>,
    /// The ccache after the principal.
    pub pos_ccache: Option<String>,
    /// The service after the ccache.
    pub pos_service: Option<String>,
}

/// Why a `kinit` argv is not run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KinitParseError {
    /// `-4`: "Kerberos 4 is no longer supported", exit 3.
    Krb4,
    /// The usage text, after these lines.
    Usage(UsageError),
}

/// MIT `usage` (`kinit.c:139-179`): the usage text, `prog` naming the program.
#[must_use]
pub fn kinit_usage(prog: &str) -> String {
    format!(
        "Usage: {prog} [-V] [-l lifetime] [-s start_time] [-r renewable_life]\n\
         \t[-f | -F] [-p | -P] [-n] [-a | -A] [-C] [-E]\n\
         \t[--request-pac | --no-request-pac]\n\
         \t[-v] [-R] [-k [-i|-t keytab_file]] [-c cachename]\n\
         \t[-S service_name] [-I input_ccache] [-T ticket_armor_cache]\n\
         \t[-X <attribute>[=<value>]] [principal]\n\
         \n    options:\n\
         \t-V verbose\n\
         \t-l lifetime\n\
         \t-s start time\n\
         \t-r renewable lifetime\n\
         \t-f forwardable\n\
         \t-F not forwardable\n\
         \t-p proxiable\n\
         \t-P not proxiable\n\
         \t-n anonymous\n\
         \t-a include addresses\n\
         \t-A do not include addresses\n\
         \t-v validate\n\
         \t-R renew\n\
         \t-C canonicalize\n\
         \t-E client is enterprise principal name\n\
         \t-k use keytab\n\
         \t-i use default client keytab (with -k)\n\
         \t-t filename of keytab to use\n\
         \t-c Kerberos 5 cache name\n\
         \t-S service\n\
         \t-I input credential cache\n\
         \t-T armor credential cache\n\
         \t-X <attribute>[=<value>]\n\
         \t--{{,no}}-request-pac request KDC include/exclude a PAC\n"
    )
}

/// MIT `kinit`'s options without an argument value, as `getopt_long` takes them.
const KINIT_OPTSTRING: &str = "r:fpFPn54aAVl:s:c:kit:T:RS:vX:CE";

fn kinit_longs() -> Vec<LongOpt> {
    let long = |name, short| LongOpt {
        name,
        takes_arg: false,
        short: Some(short),
    };
    let longs = vec![
        long("noforwardable", 'F'),
        long("noproxiable", 'P'),
        long("addresses", 'a'),
        long("forwardable", 'f'),
        long("proxiable", 'p'),
        long("noaddresses", 'A'),
        long("canonicalize", 'C'),
        long("enterprise", 'E'),
    ];
    #[cfg(feature = "test-hooks")]
    let longs = {
        let mut longs = longs;
        longs.extend([
            LongOpt {
                name: "spake",
                takes_arg: false,
                short: None,
            },
            LongOpt {
                name: "fast",
                takes_arg: false,
                short: None,
            },
            LongOpt {
                name: "armor-ccache",
                takes_arg: true,
                short: Some('T'),
            },
            LongOpt {
                name: "pkinit",
                takes_arg: true,
                short: None,
            },
            LongOpt {
                name: "pkinit-anchors",
                takes_arg: true,
                short: None,
            },
        ]);
        longs
    };
    longs
}

/// Parse `kinit` arguments after argv0.
/// MIT `parse_options` (`kinit.c:221-411`): the option table, a bad lifetime or start time, an
/// option given twice, `-f` with `-F` and the other pairs, `-t` or `-i` forcing `-k` with a
/// notice, and one principal at most.
///
/// # Errors
///
/// [`KinitParseError::Krb4`] for `-4`; [`KinitParseError::Usage`] with MIT's lines for every
/// refusal above.
pub fn parse_kinit(args: &[String]) -> Result<KinitArgs, KinitParseError> {
    let (opts, rest) = getopt(args, KINIT_OPTSTRING, &kinit_longs())
        .map_err(|e| KinitParseError::Usage(UsageError::Getopt(e)))?;
    let mut out = KinitArgs::default();
    let mut lines = Vec::new();
    let mut not = (false, false, false);
    let mut yes = (false, false, false);
    for o in opts {
        let arg = o.arg.clone().unwrap_or_default();
        #[cfg(feature = "test-hooks")]
        if gate_long(&mut out, &o) {
            continue;
        }
        match o.flag {
            'V' => out.verbose = true,
            'l' => match krb5_config::parse_deltat(&arg).filter(|&s| s != 0) {
                Some(s) => out.lifetime = Some(s),
                None => lines.push(format!("Bad lifetime value {arg}")),
            },
            'r' => match krb5_config::parse_deltat(&arg).filter(|&s| s != 0) {
                Some(s) => out.rlife = Some(s),
                None => lines.push(format!("Bad lifetime value {arg}")),
            },
            'f' => yes.0 = true,
            'F' => not.0 = true,
            'p' => yes.1 = true,
            'P' => not.1 = true,
            'n' => out.anonymous = true,
            'a' => yes.2 = true,
            'A' => not.2 = true,
            's' => match krb5_config::parse_deltat(&arg).filter(|&s| s != 0) {
                Some(s) => out.starttime = Some(s),
                None => lines.push(format!("Bad start time value {arg}")),
            },
            'S' => out.service = Some(arg),
            'k' => out.action = KinitAction::InitKt,
            'i' => out.client_keytab = true,
            't' if out.keytab_path.is_some() => lines.push("Only one -t option allowed.".into()),
            't' => out.keytab_path = Some(arg),
            'T' if out.armor_ccache.is_some() => lines.push("Only one armor_ccache".into()),
            'T' => out.armor_ccache = Some(arg),
            'R' => out.action = KinitAction::Renew,
            'v' => out.action = KinitAction::Validate,
            'c' if out.ccache.is_some() => lines.push("Only one -c option allowed".into()),
            'c' => out.ccache = Some(arg),
            'X' => {
                apply_x_attr(&mut out, &arg);
                out.pa_attrs.push(arg);
            }
            'C' => out.canonicalize = true,
            'E' => out.enterprise = true,
            '4' => return Err(KinitParseError::Krb4),
            _ => {}
        }
    }
    if yes.0 && not.0 {
        lines.push("Only one of -f and -F allowed".into());
    }
    if yes.1 && not.1 {
        lines.push("Only one of -p and -P allowed".into());
    }
    if yes.2 && not.2 {
        lines.push("Only one of -a and -A allowed".into());
    }
    out.forwardable = (yes.0 || not.0).then_some(yes.0);
    out.proxiable = (yes.1 || not.1).then_some(yes.1);
    out.addresses = (yes.2 || not.2).then_some(yes.2);
    if out.keytab_path.is_some() && out.client_keytab {
        lines.push("Only one of -t and -i allowed".into());
    }
    if (out.keytab_path.is_some() || out.client_keytab) && out.action != KinitAction::InitKt {
        out.action = KinitAction::InitKt;
        out.notices.push("keytab specified, forcing -k".into());
    }
    let rest = kinit_positionals(&mut out, rest);
    if let Some(extra) = rest.get(1) {
        lines.push(format!("Extra arguments (starting with \"{extra}\")."));
    }
    if !lines.is_empty() {
        return Err(KinitParseError::Usage(UsageError::Lines(lines)));
    }
    out.principal = rest.into_iter().next();
    out.keytab = out.action == KinitAction::InitKt;
    out.renew = out.action == KinitAction::Renew;
    out.validate = out.action == KinitAction::Validate;
    Ok(out)
}

/// The gates' long options, in a `test-hooks` build.
#[cfg(feature = "test-hooks")]
fn gate_long(out: &mut KinitArgs, o: &Opt) -> bool {
    match o.long {
        Some("spake") => out.gate.want_spake = true,
        Some("fast") => {}
        Some("pkinit") => out.pkinit_identity = o.arg.as_deref().map(strip_file_spec),
        Some("pkinit-anchors") => out.pkinit_anchors = o.arg.as_deref().map(strip_file_spec),
        _ => return false,
    }
    true
}

/// The gates' positional form `[kdc-host] principal [ccache [service]]`, in a `test-hooks` build;
/// a release build takes one principal.
fn kinit_positionals(out: &mut KinitArgs, rest: Vec<String>) -> Vec<String> {
    #[cfg(feature = "test-hooks")]
    {
        let mut rest = rest;
        if rest.len() >= 2 && !rest[0].contains('@') && rest[1].contains('@') {
            out.gate.kdc_host = Some(rest.remove(0));
        }
        if rest.len() >= 3 {
            out.gate.pos_service = Some(rest.remove(2));
        }
        if rest.len() >= 2 {
            out.gate.pos_ccache = Some(rest.remove(1));
        }
        rest
    }
    #[cfg(not(feature = "test-hooks"))]
    {
        let _ = out;
        rest
    }
}

fn apply_x_attr(out: &mut KinitArgs, v: &str) {
    if let Some(p) = v
        .strip_prefix("X509_user_identity=")
        .or_else(|| v.strip_prefix("X509_user_identity"))
    {
        let p = p.strip_prefix('=').unwrap_or(p);
        if !p.is_empty() {
            out.pkinit_identity = Some(strip_file_spec(p));
        }
    }
    if let Some(p) = v.strip_prefix("X509_anchors=") {
        out.pkinit_anchors = Some(strip_file_spec(p));
    }
}

fn strip_file_spec(s: &str) -> String {
    s.strip_prefix("FILE:").unwrap_or(s).to_owned()
}

/// Parsed `klist` argv.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KlistArgs {
    /// The name argument: the cache (`-c`, the default mode) or keytab (`-k`) to list.
    pub ccache: Option<String>,
    /// `-k`: list a keytab.
    pub keytab: bool,
    /// `-f`.
    pub flags: bool,
    /// `-e`.
    pub etype: bool,
    /// `-s`.
    pub silent: bool,
    /// `-d`.
    pub adtype: bool,
    /// `-t`.
    pub times: bool,
    /// `-K`.
    pub keys: bool,
    /// `-a`.
    pub addresses: bool,
    /// `-n`.
    pub no_resolve: bool,
    /// `-i`.
    pub client_keytab: bool,
    /// `-l`.
    pub list_all: bool,
    /// `-A`.
    pub show_all: bool,
    /// `-C`.
    pub config: bool,
}

/// Why a `klist` argv is not run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KlistParseError {
    /// `-4`: "Kerberos 4 is no longer supported", exit 3.
    Krb4,
    /// The usage text, after these lines.
    Usage(UsageError),
}

/// MIT `usage` (`klist.c:81-108`): the usage text, `prog` naming the program.
#[must_use]
pub fn klist_usage(prog: &str) -> String {
    format!(
        "Usage: {prog} [-e] [-V] [[-c] [-l] [-A] [-d] [-f] [-s] [-a [-n]]] [-k [-i] [-t] [-K]] [-C] [name]\n\
         \t-c specifies credentials cache\n\
         \t-k specifies keytab\n\
         \t   (Default is credentials cache)\n\
         \t-i uses default client keytab if no name given\n\
         \t-l lists credential caches in collection\n\
         \t-A shows content of all credential caches\n\
         \t-e shows the encryption type\n\
         \t-V shows the Kerberos version and exits\n\
         \toptions for credential caches:\n\
         \t\t-d shows the submitted authorization data types\n\
         \t\t-f shows credentials flags\n\
         \t\t-s sets exit status based on valid tgt existence\n\
         \t\t-a displays the address list\n\
         \t\t\t-n do not reverse-resolve\n\
         \toptions for keytabs:\n\
         \t\t-t shows keytab entry timestamps\n\
         \t\t-K shows keytab entry keys\n\
         \t\t-C includes configuration data entries\n"
    )
}

/// Parse `klist` arguments after argv0.
/// MIT `main` (`klist.c:137-218`): the options `dfetKsnacki45lAC` (`-V` is not taken), `-c` and
/// `-k` choosing the mode once, the options each mode refuses, and one name at most.
///
/// # Errors
///
/// [`KlistParseError::Krb4`] for `-4`; [`KlistParseError::Usage`] for an option `klist` does not
/// take, a second mode, an option the mode refuses, `-n` without `-a`, `-l` with `-A` or `-s`, or a
/// second name.
pub fn parse_klist(args: &[String]) -> Result<KlistArgs, KlistParseError> {
    let usage = |lines: Vec<String>| KlistParseError::Usage(UsageError::Lines(lines));
    let (opts, rest) = getopt(args, "dfetKsnacki45lAC", &[])
        .map_err(|e| KlistParseError::Usage(UsageError::Getopt(e)))?;
    let mut out = KlistArgs::default();
    let mut mode_set = false;
    for o in opts {
        match o.flag {
            'd' => out.adtype = true,
            'f' => out.flags = true,
            'e' => out.etype = true,
            't' => out.times = true,
            'K' => out.keys = true,
            's' => out.silent = true,
            'n' => out.no_resolve = true,
            'a' => out.addresses = true,
            'c' | 'k' if mode_set => return Err(usage(Vec::new())),
            'c' => mode_set = true,
            'k' => {
                mode_set = true;
                out.keytab = true;
            }
            'i' => out.client_keytab = true,
            '4' => return Err(KlistParseError::Krb4),
            'l' => out.list_all = true,
            'A' => out.show_all = true,
            'C' => out.config = true,
            _ => {}
        }
    }
    if out.no_resolve && !out.addresses {
        return Err(usage(Vec::new()));
    }
    let refused = if out.keytab {
        out.flags || out.silent || out.addresses || out.show_all || out.list_all
    } else {
        out.times || out.keys || (out.show_all && out.list_all) || (out.silent && out.list_all)
    };
    if refused {
        return Err(usage(Vec::new()));
    }
    if let Some(extra) = rest.get(1) {
        return Err(usage(vec![format!(
            "Extra arguments (starting with \"{extra}\")."
        )]));
    }
    out.ccache = rest.into_iter().next();
    Ok(out)
}

/// Why an argv is refused: the lines a tool prints before its usage text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UsageError {
    /// glibc `getopt`'s own complaint, printed as `<argv0>: <text>`.
    Getopt(String),
    /// The tool's own lines, each printed as is.
    Lines(Vec<String>),
}

impl UsageError {
    /// The lines to print on stderr before the usage text, `argv0` naming the program as invoked.
    #[must_use]
    pub fn lines(&self, argv0: &str) -> Vec<String> {
        match self {
            Self::Getopt(text) => vec![format!("{argv0}: {text}")],
            Self::Lines(lines) => lines.clone(),
        }
    }
}

/// `progname` as MIT's tools take it from `argv[0]`: the part after the last `/`.
#[must_use]
pub fn progname(argv0: &str) -> &str {
    argv0.rsplit('/').next().unwrap_or(argv0)
}

/// Parsed `kvno` argv.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KvnoArgs {
    /// `-c ccache`.
    pub ccache: Option<String>,
    /// `-e etype`.
    pub etype: Option<String>,
    /// `-k keytab`.
    pub keytab: Option<String>,
    /// `-q`.
    pub quiet: bool,
    /// `-u`: the service names are NT-UNKNOWN.
    pub unknown: bool,
    /// `-S sname`: each argument is a host for `sname`.
    pub sname: Option<String>,
    /// `-C`.
    pub canonicalize: bool,
    /// `-I` / `-U for_user` (S4U2Self).
    pub for_user: Option<String>,
    /// `-U`: `for_user` is an enterprise name.
    pub for_user_enterprise: bool,
    /// `-P` (S4U2Proxy after S4U2Self).
    pub proxy: bool,
    /// `--cached-only`.
    pub cached_only: bool,
    /// `--no-store`.
    pub no_store: bool,
    /// `--out-cache ccache`.
    pub out_cache: Option<String>,
    /// `--u2u ccache`.
    pub u2u: Option<String>,
    /// The service names.
    pub services: Vec<String>,
    /// The gates' options, in a `test-hooks` build only.
    #[cfg(feature = "test-hooks")]
    pub gate: KvnoGateArgs,
}

/// The gates' `kvno` options: request shapes MIT's `kvno` cannot send. A `test-hooks` build only.
#[cfg(feature = "test-hooks")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KvnoGateArgs {
    /// A first argument with no `/` or `@` before a service: the KDC host (`host[:port]`).
    pub kdc_host: Option<String>,
    /// `--disable-transited-check`: KDC option bit 26.
    pub disable_transited_check: bool,
    /// `--body-realm REALM`: one TGS-REQ with that `body.realm`, no referral chase.
    pub body_realm: Option<String>,
    /// `--renew`: KDC option RENEW on that request.
    pub renew: bool,
    /// `--renew-ticket`: RENEW the cached service ticket.
    pub renew_ticket: bool,
}

/// MIT `xusage` (`kvno.c:41-52`): the usage text, `prog` naming the program.
#[must_use]
pub fn kvno_usage(prog: &str) -> String {
    format!(
        "usage: {prog} [-c ccache] [-e etype] [-k keytab] [-q] [-u | -S sname]\n\
         \t[[{{-F cert_file | {{-I | -U}} for_user}} [-P]] | --u2u ccache]\n\
         \t[--cached-only] [--no-store] [--out-cache] service1 service2 ..."
    )
}

fn kvno_longs() -> Vec<LongOpt> {
    let longs = vec![
        LongOpt {
            name: "cached-only",
            takes_arg: false,
            short: None,
        },
        LongOpt {
            name: "no-store",
            takes_arg: false,
            short: None,
        },
        LongOpt {
            name: "out-cache",
            takes_arg: true,
            short: None,
        },
        LongOpt {
            name: "u2u",
            takes_arg: true,
            short: None,
        },
    ];
    #[cfg(feature = "test-hooks")]
    let longs = {
        let mut longs = longs;
        longs.extend([
            LongOpt {
                name: "disable-transited-check",
                takes_arg: false,
                short: None,
            },
            LongOpt {
                name: "body-realm",
                takes_arg: true,
                short: None,
            },
            LongOpt {
                name: "renew",
                takes_arg: false,
                short: None,
            },
            LongOpt {
                name: "renew-ticket",
                takes_arg: false,
                short: None,
            },
        ]);
        longs
    };
    longs
}

/// Parse `kvno` arguments after argv0.
/// MIT `main` (`kvno.c:65-179`): the option table `uCc:e:hk:qPS:I:U:F:` and `--cached-only`,
/// `--no-store`, `--out-cache`, `--u2u`, and the exclusions checked before any work.
///
/// # Errors
///
/// [`UsageError`] for an option MIT's `kvno` does not take or that lacks its argument, `-h`,
/// `-u` with `-S`, `--u2u` with `-I` / `-U`, `-P` without `-I` / `-U`, or no service; a
/// `test-hooks` build also refuses `--renew` or `--renew-ticket` without `--body-realm`.
pub fn parse_kvno(args: &[String]) -> Result<KvnoArgs, UsageError> {
    let (opts, rest) =
        getopt(args, "uCc:e:hk:qPS:I:U:", &kvno_longs()).map_err(UsageError::Getopt)?;
    let mut out = KvnoArgs::default();
    let mut lines = Vec::new();
    for o in opts {
        match (o.long, o.flag) {
            (Some("cached-only"), _) => out.cached_only = true,
            (Some("no-store"), _) => out.no_store = true,
            (Some("out-cache"), _) => out.out_cache = o.arg,
            (Some("u2u"), _) => out.u2u = o.arg,
            #[cfg(feature = "test-hooks")]
            (Some("disable-transited-check"), _) => out.gate.disable_transited_check = true,
            #[cfg(feature = "test-hooks")]
            (Some("body-realm"), _) => out.gate.body_realm = o.arg,
            #[cfg(feature = "test-hooks")]
            (Some("renew"), _) => out.gate.renew = true,
            #[cfg(feature = "test-hooks")]
            (Some("renew-ticket"), _) => out.gate.renew_ticket = true,
            (Some(name), _) => {
                return Err(UsageError::Getopt(format!(
                    "unrecognized option '--{name}'"
                )));
            }
            (None, 'C') => out.canonicalize = true,
            (None, 'c') => out.ccache = o.arg,
            (None, 'e') => out.etype = o.arg,
            (None, 'k') => out.keytab = o.arg,
            (None, 'q') => out.quiet = true,
            (None, 'P') => out.proxy = true,
            (None, 'S') => {
                out.sname = o.arg;
                if out.unknown {
                    lines.push("Options -u and -S are mutually exclusive".to_owned());
                    return Err(UsageError::Lines(lines));
                }
            }
            (None, 'u') => {
                out.unknown = true;
                if out.sname.is_some() {
                    lines.push("Options -u and -S are mutually exclusive".to_owned());
                    return Err(UsageError::Lines(lines));
                }
            }
            (None, 'I') => {
                out.for_user = o.arg;
                out.for_user_enterprise = false;
            }
            (None, 'U') => {
                out.for_user = o.arg;
                out.for_user_enterprise = true;
            }
            (None, _) => return Err(UsageError::Lines(lines)),
        }
    }
    if out.u2u.is_some() && out.for_user.is_some() {
        lines.push("Options --u2u and -I|-U|-F are mutually exclusive".to_owned());
        return Err(UsageError::Lines(lines));
    }
    if out.proxy && out.for_user.is_none() {
        lines.push(
            "Option -P (constrained delegation) requires option -I|-U|-F (protocol transition)"
                .to_owned(),
        );
        return Err(UsageError::Lines(lines));
    }
    let mut pos = rest;
    #[cfg(feature = "test-hooks")]
    {
        if pos.len() >= 2 && !pos[0].contains('/') && !pos[0].contains('@') {
            out.gate.kdc_host = Some(pos.remove(0));
        }
        if (out.gate.renew || out.gate.renew_ticket) && out.gate.body_realm.is_none() {
            lines.push("kvno: --renew and --renew-ticket require --body-realm".to_owned());
            return Err(UsageError::Lines(lines));
        }
    }
    if pos.is_empty() {
        return Err(UsageError::Lines(lines));
    }
    out.services = std::mem::take(&mut pos);
    Ok(out)
}

/// Parsed `kdestroy` argv.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KdestroyArgs {
    /// `-c`.
    pub ccache: Option<String>,
}

/// Parse `kdestroy` arguments after argv0.
///
/// # Errors
///
/// Unknown option or missing argument.
pub fn parse_kdestroy(args: &[String]) -> Result<KdestroyArgs, String> {
    let (opts, _rest) = getopt(args, "c:", &[])?;
    let mut out = KdestroyArgs::default();
    for o in opts {
        if o.flag == 'c' {
            out.ccache = o.arg;
        } else {
            return Err(format!("invalid option -- '{}'", o.flag));
        }
    }
    Ok(out)
}

/// MIT `klist.c` `check_ccache`: 0 if usable, 1 otherwise.
#[must_use]
pub fn check_ccache(cc: &FileCcache, now: u32) -> i32 {
    let realm = cc.primary.0.as_bytes();
    let mut found_tgt = false;
    let mut found_current_tgt = false;
    let mut found_current_cred = false;
    for cred in cc.list() {
        if is_local_tgt(cred, realm) {
            found_tgt = true;
            if cred.endtime > now {
                found_current_tgt = true;
            }
        } else if cred.endtime > now {
            found_current_cred = true;
        }
    }
    if found_tgt {
        i32::from(!found_current_tgt)
    } else {
        i32::from(!found_current_cred)
    }
}

fn is_local_tgt(cred: &CcacheCred, realm: &[u8]) -> bool {
    let s = &cred.server.1;
    cred.server.0.as_bytes() == realm
        && s.name_string.len() == 2
        && s.name_string[0].as_bytes() == b"krbtgt"
        && s.name_string[1].as_bytes() == realm
}

/// `Password for <principal>: ` — the `krb5_get_init_creds_password`
/// prompt, read through [`read_prompt_line`].
/// MIT `krb5_get_as_key_password` (`gic_pwd.c:96-96`): the reply to the `Password for`
/// prompt becomes the password.
///
/// # Errors
///
/// The message `failed to read password from stdin` when stdin ends or cannot be read.
pub fn read_password_line(principal: &str) -> Result<Vec<u8>, String> {
    read_prompt_line(&format!("Password for {principal}"))
}

/// One hidden prompt, `prompt` and `: ` on stdout, through the shared MIT prompter
/// [`krb5_cli::prompt_hidden`].
///
/// # Errors
///
/// The message `failed to read password from stdin` when stdin ends or cannot be read.
pub fn read_prompt_line(prompt: &str) -> Result<Vec<u8>, String> {
    krb5_cli::prompt_hidden(prompt)
        .map(|reply| reply.to_vec())
        .map_err(|_| "failed to read password from stdin".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_crypto::{EncryptionType, ProtocolKey};
    use krb5_protocol::{CcacheKeyblock, realm};
    use krb5_types::PrincipalName;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn kinit_kt_cluster_is_keytab_plus_path() {
        let a = parse_kinit(&s(&["-kt", "/tmp/user.keytab", "user@KERBER.TEST"])).unwrap();
        assert!(a.keytab);
        assert_eq!(a.keytab_path.as_deref(), Some("/tmp/user.keytab"));
        assert_eq!(a.principal.as_deref(), Some("user@KERBER.TEST"));
        assert_eq!(a.notices, Vec::<String>::new());
    }

    #[test]
    fn kinit_clustered_fe_is_not_kinit() {
        let e = parse_kinit(&s(&["-fe"])).unwrap_err();
        assert_eq!(
            e,
            KinitParseError::Usage(UsageError::Getopt("invalid option -- 'e'".into()))
        );
    }

    /// Live MIT 1.22.2 `kinit`: the refusals, with the usage text
    /// and exit 2; `-t` without `-k` forces it with a notice.
    #[test]
    fn kinit_refuses_as_mit() {
        let lines = |v: &[&str]| match parse_kinit(&s(v)) {
            Err(KinitParseError::Usage(u)) => u.lines("kinit"),
            other => panic!("{other:?}"),
        };
        #[cfg(not(feature = "test-hooks"))]
        assert_eq!(
            lines(&["alice", "bob"]),
            ["Extra arguments (starting with \"bob\")."]
        );
        assert_eq!(
            lines(&["-f", "-F", "alice"]),
            ["Only one of -f and -F allowed"]
        );
        assert_eq!(
            lines(&["-l", "bogus", "alice"]),
            ["Bad lifetime value bogus"]
        );
        assert_eq!(
            lines(&["-c", "a", "-c", "b", "alice"]),
            ["Only one -c option allowed"]
        );
        assert_eq!(
            lines(&["-t", "a", "-i", "alice"]),
            ["Only one of -t and -i allowed"]
        );
        let forced = parse_kinit(&s(&["-t", "/etc/krb5.keytab", "host/x"])).unwrap();
        assert!(forced.keytab);
        assert_eq!(forced.notices, ["keytab specified, forcing -k"]);
        assert_eq!(parse_kinit(&s(&["-4"])), Err(KinitParseError::Krb4));
        let r = parse_kinit(&s(&["-R"])).unwrap();
        assert!(r.renew && r.principal.is_none());
        let last = parse_kinit(&s(&["-R", "-k", "-v"])).unwrap();
        assert_eq!(last.action, KinitAction::Validate);
        assert!(kinit_usage("kinit").starts_with("Usage: kinit [-V] [-l lifetime]"));
    }

    /// The gates' kinit options are not MIT's: a release build refuses them.
    #[cfg(not(feature = "test-hooks"))]
    #[test]
    fn kinit_release_has_no_gate_options() {
        for opt in ["--spake", "--fast"] {
            assert_eq!(
                parse_kinit(&s(&[opt, "alice"])).unwrap_err(),
                KinitParseError::Usage(UsageError::Getopt(format!("unrecognized option '{opt}'")))
            );
        }
        for opt in ["--pkinit", "--pkinit-anchors", "--armor-ccache"] {
            assert!(
                parse_kinit(&s(&[opt, "FILE:/x", "alice"])).is_err(),
                "{opt}"
            );
        }
    }

    #[test]
    fn klist_fe_cluster() {
        let a = parse_klist(&s(&["-fe", "-c", "/tmp/cc"])).unwrap();
        assert!(a.flags && a.etype);
        assert_eq!(a.ccache.as_deref(), Some("/tmp/cc"));
        assert!(!a.silent);
    }

    #[test]
    fn klist_s_cluster_with_c() {
        let a = parse_klist(&s(&["-sc", "/tmp/cc"])).unwrap();
        assert!(a.silent);
        assert_eq!(a.ccache.as_deref(), Some("/tmp/cc"));
    }

    /// Live MIT 1.22.2 `kvno`: its option table, every service named.
    #[test]
    fn kvno_takes_mit_option_table() {
        let a = parse_kvno(&s(&[
            "-c",
            "FILE:/tmp/cc",
            "-e",
            "aes128-cts",
            "-k",
            "/etc/krb5.keytab",
            "-q",
            "-C",
            "--cached-only",
            "--no-store",
            "--out-cache",
            "FILE:/tmp/out",
            "host/x",
            "bob",
        ]))
        .unwrap();
        assert_eq!(a.ccache.as_deref(), Some("FILE:/tmp/cc"));
        assert_eq!(a.etype.as_deref(), Some("aes128-cts"));
        assert_eq!(a.keytab.as_deref(), Some("/etc/krb5.keytab"));
        assert!(a.quiet && a.canonicalize && a.cached_only && a.no_store);
        assert_eq!(a.out_cache.as_deref(), Some("FILE:/tmp/out"));
        assert_eq!(a.services, s(&["host/x", "bob"]));
        let u = parse_kvno(&s(&["-u", "host/x"])).unwrap();
        assert!(u.unknown);
        let sn = parse_kvno(&s(&["-S", "host", "client2.kerber.test"])).unwrap();
        assert_eq!(sn.sname.as_deref(), Some("host"));
        let i = parse_kvno(&s(&["-I", "alice", "-P", "host/x"])).unwrap();
        assert_eq!(i.for_user.as_deref(), Some("alice"));
        assert!(i.proxy && !i.for_user_enterprise);
        let e = parse_kvno(&s(&["-U", "victim@A.TEST", "user@C.TEST"])).unwrap();
        assert!(e.for_user_enterprise);
        let w = parse_kvno(&s(&["--u2u", "FILE:/tmp/host", "host/x"])).unwrap();
        assert_eq!(w.u2u.as_deref(), Some("FILE:/tmp/host"));
    }

    /// Live MIT 1.22.2 `kvno`: the refusals before any work, each followed by the usage text.
    #[test]
    fn kvno_refuses_as_mit() {
        let lines = |v: &[&str]| parse_kvno(&s(v)).unwrap_err().lines("kvno");
        assert_eq!(
            lines(&["-u", "-S", "host", "x"]),
            ["Options -u and -S are mutually exclusive"]
        );
        assert_eq!(
            lines(&["--u2u", "FILE:/tmp/h", "-U", "alice", "x"]),
            ["Options --u2u and -I|-U|-F are mutually exclusive"]
        );
        assert_eq!(
            lines(&["-P", "host/x"]),
            ["Option -P (constrained delegation) requires option -I|-U|-F (protocol transition)"]
        );
        assert_eq!(lines(&[]), Vec::<String>::new());
        assert_eq!(lines(&["-h"]), Vec::<String>::new());
        assert_eq!(lines(&["-Z", "host/x"]), ["kvno: invalid option -- 'Z'"]);
        assert!(kvno_usage("kvno").starts_with("usage: kvno [-c ccache] [-e etype] [-k keytab]"));
    }

    /// The gates' kvno options are not MIT's: a release build refuses them, and a first argument
    /// without `/` or `@` is a service like any other.
    #[cfg(not(feature = "test-hooks"))]
    #[test]
    fn kvno_release_has_no_gate_options() {
        for opt in ["--disable-transited-check", "--renew", "--renew-ticket"] {
            assert_eq!(
                parse_kvno(&s(&[opt, "host/x@R"])).unwrap_err(),
                UsageError::Getopt(format!("unrecognized option '{opt}'"))
            );
        }
        assert_eq!(
            parse_kvno(&s(&["--body-realm", "R", "host/x@R"])).unwrap_err(),
            UsageError::Getopt("unrecognized option '--body-realm'".into())
        );
        let a = parse_kvno(&s(&["127.0.0.1", "host/x@R"])).unwrap();
        assert_eq!(a.services, s(&["127.0.0.1", "host/x@R"]));
    }

    /// A `test-hooks` build takes the gates' options.
    #[cfg(feature = "test-hooks")]
    #[test]
    fn kvno_gate_options_in_a_test_hooks_build() {
        let a = parse_kvno(&s(&[
            "--disable-transited-check",
            "-c",
            "/tmp/cc",
            "host/x@R",
        ]))
        .unwrap();
        assert!(a.gate.disable_transited_check);
        let n = parse_kvno(&s(&[
            "--renew",
            "--body-realm",
            "B.TEST",
            "127.0.0.1:90",
            "krbtgt/C.TEST@C.TEST",
        ]))
        .unwrap();
        assert!(n.gate.renew);
        assert_eq!(n.gate.body_realm.as_deref(), Some("B.TEST"));
        assert_eq!(n.gate.kdc_host.as_deref(), Some("127.0.0.1:90"));
        assert_eq!(n.services, s(&["krbtgt/C.TEST@C.TEST"]));
        let t = parse_kvno(&s(&["--renew-ticket", "--body-realm", "K", "host/x@K"])).unwrap();
        assert!(t.gate.renew_ticket);
        let missing = parse_kvno(&s(&["--renew", "host/x@R"])).unwrap_err();
        assert_eq!(
            missing.lines("kvno"),
            ["kvno: --renew and --renew-ticket require --body-realm"]
        );
    }

    /// A `test-hooks` build takes the gates' positional form and long options.
    #[cfg(feature = "test-hooks")]
    #[test]
    fn kinit_gate_options_in_a_test_hooks_build() {
        let a = parse_kinit(&s(&[
            "127.0.0.1",
            "user@KERBER.TEST",
            "/tmp/cc",
            "host/svc",
        ]))
        .unwrap();
        assert_eq!(a.gate.kdc_host.as_deref(), Some("127.0.0.1"));
        assert_eq!(a.principal.as_deref(), Some("user@KERBER.TEST"));
        assert_eq!(a.gate.pos_ccache.as_deref(), Some("/tmp/cc"));
        assert_eq!(a.gate.pos_service.as_deref(), Some("host/svc"));
        let p = parse_kinit(&s(&[
            "--spake",
            "--pkinit",
            "FILE:/u.pem",
            "--pkinit-anchors",
            "FILE:/ca.pem",
            "--armor-ccache",
            "/a",
            "user@R",
        ]))
        .unwrap();
        assert!(p.gate.want_spake);
        assert_eq!(p.pkinit_identity.as_deref(), Some("/u.pem"));
        assert_eq!(p.pkinit_anchors.as_deref(), Some("/ca.pem"));
        assert_eq!(p.armor_ccache.as_deref(), Some("/a"));
    }

    #[test]
    fn kinit_mit_flags() {
        let a = parse_kinit(&s(&[
            "-r", "7d", "-l", "5m", "-f", "-p", "-a", "-S", "host/x", "-E", "user@R",
        ]))
        .unwrap();
        assert_eq!(a.rlife, Some(7 * 86_400));
        assert_eq!(a.lifetime, Some(300));
        assert_eq!(a.forwardable, Some(true));
        assert_eq!(a.proxiable, Some(true));
        assert_eq!(a.addresses, Some(true));
        assert_eq!(a.service.as_deref(), Some("host/x"));
        assert!(a.enterprise);
        assert_eq!(a.principal.as_deref(), Some("user@R"));
        let b = parse_kinit(&s(&["-C", "-s", "1h", "--noforwardable", "user@R"])).unwrap();
        assert!(b.canonicalize);
        assert_eq!(b.starttime, Some(3600));
        assert_eq!(b.forwardable, Some(false));
        let v = parse_kinit(&s(&["-v", "user@R"])).unwrap();
        assert!(v.validate);
        assert!(!v.renew);
        let t = parse_kinit(&s(&["-T", "FILE:/a", "-X", "X509_anchors=FILE:/ca", "-V"])).unwrap();
        assert_eq!(t.armor_ccache.as_deref(), Some("FILE:/a"));
        assert_eq!(t.pkinit_anchors.as_deref(), Some("/ca"));
        assert!(t.verbose);
    }

    fn sample(end: u32, server: PrincipalName) -> CcacheCred {
        let realm = realm("KERBER.TEST");
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        let key = ProtocolKey::from_bytes(EncryptionType::Aes128CtsHmacSha196, &[0u8; 16]).unwrap();
        CcacheCred {
            client: (realm.clone(), user),
            server: (realm, server),
            key: CcacheKeyblock::from_protocol(&key),
            authtime: 1_700_000_000,
            starttime: 1_700_000_000,
            endtime: end,
            renew_till: 0,
            is_skey: 0,
            ticket_flags: 0,
            addresses: Vec::new(),
            authdata: Vec::new(),
            ticket: Vec::new(),
            second_ticket: Vec::new(),
        }
    }

    #[test]
    fn check_ccache_uses_local_tgt_not_service() {
        let now = 1_700_100_000;
        let live_tgt = sample(now + 100, PrincipalName::krbtgt("KERBER.TEST"));
        let cc = FileCcache::new(live_tgt.client.clone(), vec![live_tgt]);
        assert_eq!(check_ccache(&cc, now), 0);

        let dead_tgt = sample(now - 1, PrincipalName::krbtgt("KERBER.TEST"));
        let live_svc = sample(
            now + 100,
            PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc"]),
        );
        let mixed = FileCcache::new(dead_tgt.client.clone(), vec![dead_tgt, live_svc]);
        assert_eq!(check_ccache(&mixed, now), 1);

        let only_svc = sample(
            now + 100,
            PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "svc"]),
        );
        let svc_cc = FileCcache::new(only_svc.client.clone(), vec![only_svc]);
        assert_eq!(check_ccache(&svc_cc, now), 0);
    }
}
