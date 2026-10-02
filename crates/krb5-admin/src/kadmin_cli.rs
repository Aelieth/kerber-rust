//! `kadmin.local`: MIT's `kadmin/cli` (`kadmin.c`, `kadmin/cli/keytab.c`, `ss_wrapper.c`) over the
//! local principal store, and the `ss` command loop it runs in.
//!
//! The command line, the three modes (`-q QUERY`, a command after the options, or commands read
//! from stdin at the `kadmin.local:  ` prompt), the verbs, their messages and the exit status
//! are MIT's. The verbs call the store's kadm5 functions directly, as `kadmin.local` calls
//! `libkadm5srv`: no ACL and no `LOCKDOWN_KEYS` check (those are kadmind's).

mod kt_cmds;
mod pol_cmds;
mod princ_cmds;
mod show;
mod ss;
mod stdio;
mod texts;

use std::io::{self, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use krb5_kdc::{Error, PrincipalStore};
use krb5_types::PrincipalName;
use zeroize::Zeroizing;

pub(crate) use stdio::{Io, LineRead, Stdout};

/// The name every message is prefixed with: MIT's `whoami`, the program's base name, which an
/// installed `kadmin.local` is.
pub(crate) const WHOAMI: &str = "kadmin.local";

/// MIT `kadmin_startup` (`kadmin.c:288-607`): the options `kadmin` and `kadmin.local` share.
const OPTSTRING: &str = "+x:r:p:knq:w:d:s:mc:t:e:ON";

/// Run `kadmin.local` with this process's arguments and standard streams.
///
/// Returns the exit status: 1 when the command line or the database cannot be used, or a
/// command-line or `-q` command is unknown, or a script-mode command reports an error; else 0
/// (a `-q` query that fails still exits 0, as MIT's does).
#[must_use]
pub fn kadmin_local_main() -> i32 {
    let argv: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let stdout = io::stdout();
    let line = stdout.is_terminal();
    let mut io = Io {
        out: Stdout::new(Box::new(stdout), line),
        err: Box::new(io::stderr()),
        input: Box::new(krb5_cli::Stdin::unbuffered()),
        tty_in: io::stdin().is_terminal(),
        script_mode: false,
        exit_status: 0,
        interrupted: false,
    };
    let rc = run(&argv, &mut io);
    let _ = io.out.flush();
    rc
}

/// An open database and the identity changes are recorded under.
pub(crate) struct Handle {
    pub(crate) store: PrincipalStore,
    /// `params.realm`: `-r`, else the default realm.
    pub(crate) realm: String,
    /// `current_caller`: the principal name the session runs as, with its realm.
    pub(crate) caller: String,
    open: Open,
}

/// How the database was opened, to open it again after a failed change.
struct Open {
    db: PathBuf,
    stash: PathBuf,
    conf: Option<krb5_config::KdcConf>,
    keysalts: Vec<krb5_crypto::EncryptionType>,
    /// `-m`: the master key typed at startup; without a stash file the database is read-only.
    typed: Option<(Zeroizing<Vec<u8>>, krb5_crypto::EncryptionType)>,
    read_only: bool,
}

/// The session: the streams, the database, and the `ss` loop's state.
pub(crate) struct Session<'a> {
    pub(crate) io: &'a mut Io,
    pub(crate) h: Handle,
    /// MIT `locked`: `lock` was run and not yet undone.
    pub(crate) locked: bool,
    /// MIT `ss_quit`: leave the command loop.
    pub(crate) abort: bool,
}

impl Handle {
    /// MIT `kadmin_parse_name` (`kadmin.c:202-225`): a name without a realm takes `params.realm`.
    pub(crate) fn parse_name(&self, spec: &str) -> Result<(PrincipalName, String), &'static str> {
        krb5_types::principal_from_unparsed(spec, &self.realm).map_err(|_| texts::MALFORMED)
    }

    /// Pick up another process's change (kadmind), as each MIT call reads the database.
    pub(crate) fn refresh(&mut self) -> Result<(), Error> {
        self.store.reload_if_stale()
    }

    /// One kadm5 change, applied whole: the steps run on the store in memory with its saves
    /// held, and the database is written once at the end; when a step or the write fails, the
    /// store is read back from the database, so nothing of the change remains but what MIT
    /// commits with its own put (the `kadmin/history` a password change under a policy creates).
    pub(crate) fn mutate<T>(
        &mut self,
        f: impl FnOnce(&mut PrincipalStore, &str) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.refresh()?;
        if self.open.read_only {
            return Err(Error::Db {
                kind: io::ErrorKind::ReadOnlyFilesystem,
                text: "No stash file: the database was opened with -m and is read-only".to_owned(),
            });
        }
        let caller = self.caller.clone();
        self.store.hold_saves(true);
        let done = f(&mut self.store, &caller);
        self.store.hold_saves(false);
        let saved = match (&done, &self.store.persist_paths) {
            (Ok(_), Some((db, stash))) => {
                krb5_kdc::save_store(&self.store, db, stash).map_err(Error::from)
            }
            _ => Ok(()),
        };
        if (done.is_err() || saved.is_err())
            && let Ok(store) = self.open.load()
        {
            self.store = store;
        }
        saved?;
        done
    }

    /// `K/M@params.realm`, which `kadm5_delete_principal` refuses to delete.
    pub(crate) fn is_master(&self, name: &PrincipalName, realm: &str) -> bool {
        realm == self.realm && name.components_joined() == "K/M"
    }

    pub(crate) fn db_path(&self) -> &Path {
        &self.open.db
    }
}

impl Open {
    /// The store as the database holds it, with the realm's kdc.conf and krb5.conf applied.
    fn load(&self) -> Result<PrincipalStore, String> {
        let mut store = match &self.typed {
            Some((pw, etype)) if !self.stash.exists() => {
                let text = std::fs::read_to_string(&self.db).map_err(|e| self.cannot_open(&e))?;
                krb5_kdc::load_dump_etype(&text, pw, *etype)
                    .map_err(|_| texts::BAD_MASTER_KEY.to_owned())?
            }
            _ => krb5_kdc::load_store(&self.db, &self.stash).map_err(|e| self.load_text(e))?,
        };
        if let Some(conf) = &self.conf {
            store.apply_kdc_conf(conf).map_err(|e| e.to_string())?;
        }
        if let Some(conf) = krb5_config::load_krb5_conf() {
            store.apply_libdefaults(&conf);
        }
        if !self.keysalts.is_empty() {
            store.policy.supported_enctypes.clone_from(&self.keysalts);
        }
        Ok(store)
    }

    /// MIT `open_db` (`kdb_db2.c:365-394`): the db2 module's text for a database it cannot open.
    fn cannot_open(&self, e: &io::Error) -> String {
        format!(
            "Cannot open DB2 database '{}': {}",
            self.db.display(),
            texts::strerror(e)
        )
    }

    fn load_text(&self, e: krb5_kdc::PersistError) -> String {
        match e {
            krb5_kdc::PersistError::Io(e) => self.cannot_open(&e),
            krb5_kdc::PersistError::Crypto(_) => texts::BAD_MASTER_KEY.to_owned(),
            krb5_kdc::PersistError::Format(_) | krb5_kdc::PersistError::UnknownDbLibrary(_) => {
                format!(
                    "Cannot open DB2 database '{}': Inappropriate file type or format",
                    self.db.display()
                )
            }
        }
    }
}

/// What the command line asked for.
struct Startup {
    handle: Handle,
    request: Option<String>,
    args: Vec<String>,
    ccache_name: Option<String>,
}

/// MIT `main` (`ss_wrapper.c:41-77`): start up, run the one command or the command loop, quit.
pub(crate) fn run(argv: &[String], io: &mut Io) -> i32 {
    let Some(start) = startup(argv, io) else {
        return 1;
    };
    let Startup {
        handle,
        request,
        args,
        ccache_name,
    } = start;
    let mut s = Session {
        io,
        h: handle,
        locked: false,
        abort: false,
    };
    if !args.is_empty() {
        if !ss::execute_command(&mut s, &args) {
            ss::perror(s.io, ss::COMMAND_NOT_FOUND, &args[0]);
            s.io.exit_status = 1;
        }
    } else if let Some(request) = request {
        match ss::execute_line(&mut s, &request) {
            Some(ss::Unrun::NotFound { lead, word }) => {
                ss::perror(s.io, ss::COMMAND_NOT_FOUND, &format!("{lead}{word}"));
                s.io.exit_status = 1;
            }
            Some(ss::Unrun::EscapeDisabled) => {
                ss::perror(s.io, ss::ESCAPE_DISABLED, &request);
                s.io.exit_status = 1;
            }
            None => {}
        }
    } else {
        ss::listen(&mut s);
    }
    quit(&mut s, ccache_name.is_some());
    s.io.exit_status
}

/// MIT `quit` (`kadmin.c:610-633`): give up a held lock, and warn that `-c` credentials stay.
fn quit(s: &mut Session<'_>, ccache: bool) {
    s.locked = false;
    if ccache && !s.io.script_mode {
        s.io.eprint("\n\x07\x07\x07Administration credentials NOT DESTROYED.\n");
    }
}

/// The options MIT's `kadmin_startup` collects.
#[derive(Default)]
struct Opts {
    db_args: Vec<String>,
    realm: Option<String>,
    princstr: Option<String>,
    ccache_name: Option<String>,
    use_keytab: bool,
    use_anonymous: bool,
    keytab_name: Option<String>,
    query: Option<String>,
    mkey_from_kbd: bool,
    keysalts: Vec<krb5_crypto::EncryptionType>,
}

/// glibc prefixes its option errors with `argv[0]` as given; the installed name is MIT's.
fn getopt_prog(argv0: &str) -> &str {
    if Path::new(argv0).file_name().and_then(|n| n.to_str()) == Some(WHOAMI) {
        argv0
    } else {
        WHOAMI
    }
}

/// MIT `kadmin_startup` (`kadmin.c:288-607`): the options, the principal to run as, the
/// `Authenticating as principal …` line and the database. `None` after printing why the
/// program exits 1.
fn startup(argv: &[String], io: &mut Io) -> Option<Startup> {
    let usage = |io: &mut Io| io.error(&texts::startup_usage(WHOAMI));
    let prog = getopt_prog(argv.first().map_or("", String::as_str));
    let (opts, args) = match krb5_cli::getopt(argv.get(1..).unwrap_or_default(), OPTSTRING, &[]) {
        Ok(v) => v,
        Err(msg) => {
            io.eprint(&format!("{prog}: {msg}\n"));
            usage(io);
            return None;
        }
    };
    let mut o = Opts::default();
    for opt in opts {
        let arg = opt.arg.unwrap_or_default();
        match opt.flag {
            'x' => o.db_args.push(arg),
            'r' => o.realm = Some(arg),
            'p' => o.princstr = Some(arg),
            'c' => o.ccache_name = Some(arg),
            'k' => o.use_keytab = true,
            'n' => o.use_anonymous = true,
            't' => o.keytab_name = Some(arg),
            'q' => o.query = Some(arg),
            'd' => o.db_args.push(format!("dbname={arg}")),
            'm' => o.mkey_from_kbd = true,
            'e' => o.keysalts = string_to_keysalts(&arg, &[',', ' ', '\t']),
            _ => {}
        }
    }
    if (o.ccache_name.is_some() && o.use_keytab)
        || (o.keytab_name.is_some() && !o.use_keytab)
        || (o.ccache_name.is_some() && o.use_anonymous)
        || (o.use_anonymous && o.use_keytab)
    {
        usage(io);
        return None;
    }
    if o.query.is_some() && !args.is_empty() {
        io.error(&format!(
            "{WHOAMI}: -q is exclusive with command-line query"
        ));
        usage(io);
        return None;
    }
    io.script_mode = !args.is_empty();
    let krb5_conf = krb5_config::load_krb5_conf();
    let Some(realm) = o
        .realm
        .clone()
        .or_else(|| krb5_conf.as_ref().and_then(|c| c.default_realm.clone()))
    else {
        io.error(&format!("{WHOAMI}: unable to get default realm\n"));
        return None;
    };
    let ccache = match resolve_ccache(o.ccache_name.as_deref(), krb5_conf.as_ref()) {
        Ok(cc) => cc,
        Err(msg) => {
            let what = o.ccache_name.as_ref().map_or_else(
                || "while opening default credentials cache".to_owned(),
                |n| format!("while opening credentials cache {n}"),
            );
            io.com_err(WHOAMI, Some(&msg), &what);
            return None;
        }
    };
    let princstr = match o.princstr.clone() {
        Some(p) => p,
        None => {
            default_princstr(&o, &realm, ccache.as_ref(), krb5_conf.as_ref()).or_else(|| {
                io.error(&format!(
                    "{WHOAMI}: unable to figure out a principal name\n"
                ));
                None
            })?
        }
    };
    klog_init(io, &krb5_conf_paths_with_kdc());
    if o.ccache_name.is_some() {
        io.info(&format!(
            "Authenticating as principal {princstr} with existing credentials.\n"
        ));
    } else if o.use_anonymous {
        io.info(&format!(
            "Authenticating as principal {princstr} with password; anonymous requested.\n"
        ));
    } else if o.use_keytab {
        match &o.keytab_name {
            Some(kt) => io.info(&format!(
                "Authenticating as principal {princstr} with keytab {kt}.\n"
            )),
            None => io.info(&format!(
                "Authenticating as principal {princstr} with default keytab.\n"
            )),
        }
    } else {
        io.info(&format!(
            "Authenticating as principal {princstr} with password.\n"
        ));
    }
    let handle = match kadm5_init(io, &o, &realm, &princstr) {
        Ok(h) => h,
        Err((msg, bad_params)) => {
            io.com_err(
                WHOAMI,
                Some(&msg),
                &format!("while initializing {WHOAMI} interface"),
            );
            if bad_params {
                usage(io);
            }
            return None;
        }
    };
    Some(Startup {
        handle,
        request: o.query,
        args,
        ccache_name: o.ccache_name,
    })
}

/// The ccache `kadmin_startup` opens: `-c`, else the default. `Ok(None)` for one this port
/// cannot read (`KEYRING`), which has no principal for it either.
fn resolve_ccache(
    name: Option<&str>,
    conf: Option<&krb5_config::Krb5Conf>,
) -> Result<Option<krb5_config::CcSpec>, String> {
    let raw = match name {
        Some(n) => n.to_owned(),
        None => std::env::var("KRB5CCNAME")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| conf.and_then(|c| c.default_ccache_name.clone()))
            .unwrap_or_else(|| "FILE:/tmp/krb5cc_%{uid}".to_owned()),
    };
    if let Some((ty, _)) = raw.split_once(':')
        && matches!(ty, "KEYRING" | "API" | "MSLSA")
    {
        return Ok(None);
    }
    let expanded = if name.is_some() {
        raw
    } else {
        krb5_config::expand_ccache_params(&raw).map_err(|e| e.to_string())?
    };
    krb5_config::parse_ccspec(&expanded)
        .map(Some)
        .map_err(|_| krb5_config::KRB5_CC_UNKNOWN_TYPE.to_owned())
}

/// `krb5_cc_get_principal`: the ccache's default principal, `None` when it has none to give.
fn ccache_principal(cc: &krb5_config::CcSpec) -> Option<String> {
    let parsed = match cc {
        krb5_config::CcSpec::File(p) => {
            krb5_protocol::FileCcache::parse(&std::fs::read(p).ok()?).ok()?
        }
        krb5_config::CcSpec::Dir(r) => {
            let p = krb5_protocol::dir_cache_path(r).ok()?;
            krb5_protocol::FileCcache::parse(&std::fs::read(p).ok()?).ok()?
        }
        krb5_config::CcSpec::Kcm(n) => krb5_protocol::kcm_load(n).ok()?,
        krb5_config::CcSpec::Memory(_) => return None,
    };
    let (realm, name) = parsed.primary;
    Some(name.unparse_with_realm(&String::from_utf8_lossy(realm.as_bytes())))
}

/// The first `c` in `s` that no backslash escapes, as `kadmin_startup` scans an unparsed name.
fn unescaped(s: &str, c: u8) -> Option<usize> {
    let b = s.as_bytes();
    (0..b.len()).find(|&i| b[i] == c && (i == 0 || b[i - 1] != b'\\'))
}

/// MIT `kadmin_startup` (`kadmin.c:395-472`): the principal to run as when `-p` is not given.
fn default_princstr(
    o: &Opts,
    realm: &str,
    ccache: Option<&krb5_config::CcSpec>,
    conf: Option<&krb5_config::Krb5Conf>,
) -> Option<String> {
    if o.use_anonymous {
        return Some(format!("WELLKNOWN/ANONYMOUS@{realm}"));
    }
    let cc_princ = ccache.and_then(ccache_principal);
    if o.ccache_name.is_some()
        && let Some(p) = &cc_princ
    {
        return Some(p.clone());
    }
    if o.use_keytab {
        return Some(host_princstr(conf));
    }
    if let Some(canon) = cc_princ {
        let (primary, prealm) = match unescaped(&canon, b'@').filter(|&i| i > 0) {
            Some(i) => (&canon[..i], Some(&canon[i + 1..])),
            None => (canon.as_str(), None),
        };
        let primary = match unescaped(primary, b'/').filter(|&i| i > 0) {
            Some(i) => &primary[..i],
            None => primary,
        };
        return Some(match prealm {
            Some(r) => format!("{primary}/admin@{r}"),
            None => format!("{primary}/admin"),
        });
    }
    if let Some(user) = std::env::var_os("USER") {
        return Some(format!("{}/admin@{realm}", user.to_string_lossy()));
    }
    let pw = nix::unistd::User::from_uid(nix::unistd::getuid()).ok()??;
    Some(format!("{}/admin@{realm}", pw.name))
}

/// `krb5_sname_to_principal(NULL, "host", KRB5_NT_SRV_HST)`: `host/` and the local host name,
/// lowercased, in the realm `[domain_realm]` maps it to, else the referral (empty) realm. The
/// name is not canonicalized through DNS.
fn host_princstr(conf: Option<&krb5_config::Krb5Conf>) -> String {
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let realm = conf
        .and_then(|c| krb5_config::host_to_realm(&c.domain_realm, &host))
        .unwrap_or_default();
    format!("host/{host}@{realm}")
}

/// kdc.conf, then the krb5.conf files: the profile a KDC-side context reads.
fn krb5_conf_paths_with_kdc() -> Vec<PathBuf> {
    let mut paths = vec![krb5_config::kdc_conf_path()];
    paths.extend(krb5_config::krb5_conf_paths());
    paths
}

/// Every value of `[section] key` in `files`, in order, as MIT's `profile_get_values` collects
/// them (subsections skipped).
fn profile_values(files: &[PathBuf], section: &str, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    for file in files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        let mut current = String::new();
        let mut depth = 0usize;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if depth == 0
                && let Some(name) = line.strip_prefix('[').and_then(|l| l.split(']').next())
            {
                name.trim().clone_into(&mut current);
                continue;
            }
            if line.starts_with('}') {
                depth = depth.saturating_sub(1);
                continue;
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let v = v.trim();
            if v.starts_with('{') {
                depth += 1;
                continue;
            }
            if depth == 0 && current == section && k.trim() == key {
                out.push(v.to_owned());
            }
        }
    }
    out
}

/// MIT `krb5_klog_init` (`logger.c:232-336`): the `admin_server` log files are opened (created
/// 0640), and one that cannot be is reported; `kadmin.local` itself writes nothing to them.
fn klog_init(io: &mut Io, files: &[PathBuf]) {
    let mut specs = profile_values(files, "logging", "admin_server");
    if specs.is_empty() {
        specs = profile_values(files, "logging", "default");
    }
    for spec in specs {
        let spec = spec.trim();
        let (Some(head), Some(path)) = (spec.get(..4), spec.get(5..)) else {
            continue;
        };
        if !head.eq_ignore_ascii_case("FILE") {
            continue;
        }
        let append = spec.as_bytes().get(4) == Some(&b':');
        if !append && spec.as_bytes().get(4) != Some(&b'=') {
            continue;
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).append(append);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o640);
        }
        if let Err(e) = opts.open(path) {
            io.eprint(&format!(
                "Couldn't open log file {path}: {}\n",
                texts::strerror(&e)
            ));
        }
    }
}

/// MIT `kadm5_init` (`server_init.c:158-275`): for `kadmin.local`, the realm's parameters, the
/// db2 module's arguments, the database, the caller's name and the master key. The error is
/// the `com_err` text, and whether MIT also prints the usage (`KADM5_BAD_SERVER_PARAMS`).
fn kadm5_init(
    io: &mut Io,
    o: &Opts,
    realm: &str,
    princstr: &str,
) -> Result<Handle, (String, bool)> {
    if o.mkey_from_kbd && (o.ccache_name.is_some() || o.use_keytab) {
        return Err((
            "Illegal configuration parameter for local KADM5 client".to_owned(),
            true,
        ));
    }
    let paths = krb5_config::KdcPaths::resolve(Some(realm)).map_err(|e| (e.to_string(), false))?;
    let mut db = paths.database_name.clone();
    for arg in &o.db_args {
        match db2_arg(arg) {
            Db2Arg::DbName(name) => db = PathBuf::from(name),
            Db2Arg::Other => {}
            Db2Arg::Unsupported => {
                let shown = arg.split_once('=').map_or(arg.as_str(), |(opt, _)| opt);
                return Err((format!("Unsupported argument \"{shown}\" for db2"), false));
            }
        }
    }
    let mut open = Open {
        db,
        stash: paths.key_stash_file.clone(),
        conf: paths.conf.clone(),
        keysalts: o.keysalts.clone(),
        typed: None,
        read_only: false,
    };
    if let Err(e) = std::fs::File::open(&open.db) {
        return Err((open.cannot_open(&e), false));
    }
    let caller = krb5_types::principal_from_unparsed(princstr, realm)
        .map(|(n, r)| n.unparse_with_realm(&r))
        .map_err(|_| (texts::MALFORMED.to_owned(), false))?;
    if o.mkey_from_kbd {
        let pw = io
            .read_password("Enter KDC database master key", None)
            .map_err(|e| (e.to_string(), false))?;
        let etype =
            krb5_kdc::master_etype(paths.master_key_type.as_deref()).map_err(|e| (e, false))?;
        open.read_only = !open.stash.exists();
        open.typed = Some((pw, etype));
        let text = std::fs::read_to_string(&open.db).map_err(|e| (open.cannot_open(&e), false))?;
        if let Some((pw, etype)) = &open.typed
            && krb5_kdc::load_dump_etype(&text, pw, *etype).is_err()
        {
            return Err((texts::BAD_MASTER_KEY.to_owned(), false));
        }
    } else if let Err(e) = std::fs::read(&open.stash) {
        return Err((
            format!("Can not fetch master key (error: {}).", texts::strerror(&e)),
            false,
        ));
    }
    let mut store = open.load().map_err(|e| (e, false))?;
    if open.read_only {
        store.persist_paths = None;
    }
    Ok(Handle {
        store,
        realm: realm.to_owned(),
        caller,
        open,
    })
}

/// What a `-x` argument is to the db2 module.
enum Db2Arg<'a> {
    DbName(&'a str),
    Other,
    Unsupported,
}

/// MIT `configure_context` (`kdb_db2.c:202-262`): a db2 argument is `dbname=NAME`, or one of
/// `temporary`, `merge_nra`, `hash=…`, `unlockiter`, `lockiter`; any other is refused.
fn db2_arg(arg: &str) -> Db2Arg<'_> {
    match arg.split_once('=') {
        Some(("dbname", name)) => Db2Arg::DbName(name),
        Some(("hash", _)) => Db2Arg::Other,
        None if matches!(arg, "temporary" | "merge_nra" | "unlockiter" | "lockiter") => {
            Db2Arg::Other
        }
        Some(_) | None => Db2Arg::Unsupported,
    }
}

/// MIT `krb5_string_to_keysalts` (`kadm5/str_conv.c:319-366`): the enctypes of a keysalt list;
/// a tuple naming an unknown enctype or salt type is skipped, a repeat is dropped.
pub(crate) fn string_to_keysalts(s: &str, seps: &[char]) -> Vec<krb5_crypto::EncryptionType> {
    let mut out = Vec::new();
    for tuple in s.split(|c| seps.contains(&c)).filter(|t| !t.is_empty()) {
        let (etype, salt) = match tuple.split_once(':') {
            Some((e, s)) => (e, Some(s)),
            None => (tuple, None),
        };
        if salt.is_some_and(|s| !matches!(s, "normal" | "norealm" | "onlyrealm" | "special")) {
            continue;
        }
        if let Ok(e) = krb5_crypto::EncryptionType::from_mit_name(etype)
            && !out.contains(&e)
        {
            out.push(e);
        }
    }
    out
}

/// C `atoi`: optional blanks and sign, then digits; 0 when there are none.
pub(crate) fn atoi(s: &str) -> i64 {
    let t = s.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let mut n: i64 = 0;
    for b in digits.bytes().take_while(u8::is_ascii_digit) {
        n = n.wrapping_mul(10).wrapping_add(i64::from(b - b'0'));
    }
    if neg { n.wrapping_neg() } else { n }
}

#[cfg(test)]
mod tests;
