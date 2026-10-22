pub use krb5_cli::{LongOpt, Opt, getopt, getopt_each};
use krb5_protocol::{CcacheCred, FileCcache};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KinitAction {
    #[default]
    InitPw,
    InitKt,
    Renew,
    Validate,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KinitArgs {
    pub verbose: bool,
    pub action: KinitAction,
    pub keytab: bool,
    pub renew: bool,
    pub validate: bool,
    pub client_keytab: bool,
    pub keytab_path: Option<String>,
    pub ccache: Option<String>,
    pub rlife: Option<u64>,
    pub lifetime: Option<u64>,
    pub starttime: Option<i64>,
    pub forwardable: Option<bool>,
    pub proxiable: Option<bool>,
    pub addresses: Option<bool>,
    pub service: Option<String>,
    pub enterprise: bool,
    pub anonymous: bool,
    pub canonicalize: bool,
    // MIT `add_preauth_opt` (`clients/kinit/kinit.c:196-219`): the attribute is what precedes the first `=`.
    pub pa_opts: Vec<(String, String)>,
    pub armor_ccache: Option<String>,
    pub in_ccache: Option<String>,
    pub request_pac: Option<bool>,
    pub pkinit_identity: Option<String>,
    pub pkinit_anchors: Vec<String>,
    pub principal: Option<String>,
    pub notices: Vec<String>,
    #[cfg(feature = "test-hooks")]
    pub gate: KinitGateArgs,
}

#[cfg(feature = "test-hooks")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KinitGateArgs {
    pub want_spake: bool,
    pub kdc_host: Option<String>,
    pub pos_ccache: Option<String>,
    pub pos_service: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KinitParseError {
    // MIT `parse_options` (`kinit.c:359-361`): `-4` exits at once, after what the loop printed.
    Krb4(UsageError),
    Usage(UsageError),
}

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

const KINIT_OPTSTRING: &str = "r:fpFPn54aAVl:s:c:kI:it:T:RS:vX:CE";

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
        LongOpt {
            name: "request-pac",
            takes_arg: false,
            short: None,
        },
        LongOpt {
            name: "no-request-pac",
            takes_arg: false,
            short: None,
        },
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

pub fn parse_kinit(args: &[String]) -> Result<KinitArgs, KinitParseError> {
    let (each, rest) = getopt_each(args, KINIT_OPTSTRING, &kinit_longs());
    let mut out = KinitArgs::default();
    let mut lines = Vec::new();
    let mut not = (false, false, false);
    let mut yes = (false, false, false);
    let mut pac = (false, false);
    for o in each {
        let o = match o {
            Ok(o) => o,
            Err(e) => {
                lines.push(UsageLine::Getopt(e));
                continue;
            }
        };
        let arg = o.arg.clone().unwrap_or_default();
        #[cfg(feature = "test-hooks")]
        if gate_long(&mut out, &o) {
            continue;
        }
        match o.long {
            Some("request-pac") => {
                pac.0 = true;
                continue;
            }
            Some("no-request-pac") => {
                pac.1 = true;
                continue;
            }
            _ => {}
        }
        match o.flag {
            'V' => out.verbose = true,
            'l' => match krb5_config::parse_deltat(&arg).filter(|&s| s != 0) {
                Some(s) => out.lifetime = Some(s),
                None => lines.push(own(format!("Bad lifetime value {arg}"))),
            },
            'r' => match krb5_config::parse_deltat(&arg).filter(|&s| s != 0) {
                Some(s) => out.rlife = Some(s),
                None => lines.push(own(format!("Bad lifetime value {arg}"))),
            },
            'f' => yes.0 = true,
            'F' => not.0 = true,
            'p' => yes.1 = true,
            'P' => not.1 = true,
            'n' => out.anonymous = true,
            'a' => yes.2 = true,
            'A' => not.2 = true,
            's' => match start_time(&arg) {
                Some(s) => out.starttime = Some(s),
                None => lines.push(own(format!("Bad start time value {arg}"))),
            },
            'S' => out.service = Some(arg),
            'k' => out.action = KinitAction::InitKt,
            'i' => out.client_keytab = true,
            't' if out.keytab_path.is_some() => lines.push(own("Only one -t option allowed.")),
            't' => out.keytab_path = Some(arg),
            'T' if out.armor_ccache.is_some() => lines.push(own("Only one armor_ccache")),
            'T' => out.armor_ccache = Some(arg),
            'R' => out.action = KinitAction::Renew,
            'v' => out.action = KinitAction::Validate,
            'c' if out.ccache.is_some() => lines.push(own("Only one -c option allowed")),
            'c' => out.ccache = Some(arg),
            'I' if out.in_ccache.is_some() => lines.push(own("Only one -I option allowed")),
            'I' => out.in_ccache = Some(arg),
            'X' => {
                let (attr, value) = arg.split_once('=').unwrap_or((&arg, "yes"));
                let opt = (attr.to_owned(), value.to_owned());
                apply_x_attr(&mut out, &opt.0, &opt.1);
                out.pa_opts.push(opt);
            }
            'C' => out.canonicalize = true,
            'E' => out.enterprise = true,
            '4' => return Err(KinitParseError::Krb4(UsageError::Each(lines))),
            _ => {}
        }
    }
    if yes.0 && not.0 {
        lines.push(own("Only one of -f and -F allowed"));
    }
    if yes.1 && not.1 {
        lines.push(own("Only one of -p and -P allowed"));
    }
    if yes.2 && not.2 {
        lines.push(own("Only one of -a and -A allowed"));
    }
    if pac.0 && pac.1 {
        lines.push(own(
            "Only one of --request-pac and --no-request-pac allowed",
        ));
    }
    out.forwardable = (yes.0 || not.0).then_some(yes.0);
    out.proxiable = (yes.1 || not.1).then_some(yes.1);
    out.addresses = (yes.2 || not.2).then_some(yes.2);
    out.request_pac = (pac.0 || pac.1).then_some(pac.0);
    if out.keytab_path.is_some() && out.client_keytab {
        lines.push(own("Only one of -t and -i allowed"));
    }
    if (out.keytab_path.is_some() || out.client_keytab) && out.action != KinitAction::InitKt {
        out.action = KinitAction::InitKt;
        out.notices.push("keytab specified, forcing -k".into());
    }
    let rest = kinit_positionals(&mut out, rest);
    if let Some(extra) = rest.get(1) {
        lines.push(own(format!("Extra arguments (starting with \"{extra}\").")));
    }
    if !lines.is_empty() {
        return Err(KinitParseError::Usage(UsageError::Each(lines)));
    }
    out.principal = rest.into_iter().next();
    out.keytab = out.action == KinitAction::InitKt;
    out.renew = out.action == KinitAction::Renew;
    out.validate = out.action == KinitAction::Validate;
    Ok(out)
}

#[cfg(feature = "test-hooks")]
fn gate_long(out: &mut KinitArgs, o: &Opt) -> bool {
    match o.long {
        Some("spake") => out.gate.want_spake = true,
        Some("fast") => {}
        Some("pkinit") => out.pkinit_identity.clone_from(&o.arg),
        Some("pkinit-anchors") => out.pkinit_anchors.extend(o.arg.as_deref().map(file_spec)),
        _ => return false,
    }
    true
}

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

fn apply_x_attr(out: &mut KinitArgs, attr: &str, value: &str) {
    match attr {
        "X509_user_identity" if out.pkinit_identity.is_none() => {
            out.pkinit_identity = Some(value.to_owned());
        }
        "X509_anchors" => out.pkinit_anchors.push(value.to_owned()),
        _ => {}
    }
}

#[cfg(feature = "test-hooks")]
fn file_spec(s: &str) -> String {
    if s.contains(':') {
        s.to_owned()
    } else {
        format!("FILE:{s}")
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KlistArgs {
    pub ccache: Option<String>,
    pub keytab: bool,
    pub flags: bool,
    pub etype: bool,
    pub silent: bool,
    pub adtype: bool,
    pub times: bool,
    pub keys: bool,
    pub addresses: bool,
    pub no_resolve: bool,
    pub client_keytab: bool,
    pub list_all: bool,
    pub show_all: bool,
    pub config: bool,
    pub version: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KlistParseError {
    Krb4,
    Usage(UsageError),
}

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

pub fn parse_klist(args: &[String]) -> Result<KlistArgs, KlistParseError> {
    let usage = |lines: Vec<String>| KlistParseError::Usage(UsageError::Lines(lines));
    let (opts, rest) = getopt(args, "dfetKsnacki45lAVC", &[])
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
            'V' => out.version = true,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UsageError {
    Getopt(String),
    Lines(Vec<String>),
    Each(Vec<UsageLine>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UsageLine {
    Getopt(String),
    Own(String),
}

pub fn own(text: impl Into<String>) -> UsageLine {
    UsageLine::Own(text.into())
}

impl UsageError {
    #[must_use]
    pub fn lines(&self, argv0: &str) -> Vec<String> {
        match self {
            Self::Getopt(text) => vec![format!("{argv0}: {text}")],
            Self::Lines(lines) => lines.clone(),
            Self::Each(lines) => lines
                .iter()
                .map(|line| match line {
                    UsageLine::Getopt(text) => format!("{argv0}: {text}"),
                    UsageLine::Own(text) => text.clone(),
                })
                .collect(),
        }
    }
}

#[must_use]
pub fn progname(argv0: &str) -> &str {
    argv0.rsplit('/').next().unwrap_or(argv0)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KvnoArgs {
    pub ccache: Option<String>,
    pub etype: Option<String>,
    pub keytab: Option<String>,
    pub quiet: bool,
    pub unknown: bool,
    pub sname: Option<String>,
    pub canonicalize: bool,
    pub for_user: Option<String>,
    pub for_user_enterprise: bool,
    pub proxy: bool,
    pub cached_only: bool,
    pub no_store: bool,
    pub out_cache: Option<String>,
    pub u2u: Option<String>,
    pub services: Vec<String>,
    #[cfg(feature = "test-hooks")]
    pub gate: KvnoGateArgs,
}

#[cfg(feature = "test-hooks")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KvnoGateArgs {
    pub kdc_host: Option<String>,
    pub disable_transited_check: bool,
    pub body_realm: Option<String>,
    pub renew: bool,
    pub renew_ticket: bool,
}

// MIT `xusage` (`kvno.c:41-52`): the usage text, `prog` naming the program.
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
            (None, 'I') => out.for_user = o.arg,
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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KdestroyArgs {
    pub ccache: Option<String>,
}

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

fn start_time(arg: &str) -> Option<i64> {
    match krb5_types::deltat::parse(arg) {
        Ok(d) if d != 0 => Some(i64::from(d)),
        _ => {
            let abs = krb5_types::timestamp::string_to_timestamp(arg).filter(|&t| t != 0)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let now = u32::try_from(now & 0xffff_ffff).unwrap_or(0);
            Some(i64::from(abs.wrapping_sub(now).cast_signed()))
        }
    }
}

// MIT krb5_get_as_key_password; see docs/parity/b1-client-preauth.md
pub fn read_password_line(
    principal: &str,
) -> Result<zeroize::Zeroizing<Vec<u8>>, krb5_cli::PromptError> {
    krb5_cli::prompt_hidden(&format!("Password for {principal}"))
}

/// The reply is wiped when dropped.
pub fn read_prompt_line(prompt: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    krb5_cli::prompt_hidden(prompt).map_err(|e| e.to_string())
}
