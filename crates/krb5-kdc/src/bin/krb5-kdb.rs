//! MIT `kdb5_util`: create, stash, dump, load and destroy the KDC database.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::disallowed_methods,
    reason = "a program reads its profile and environment when it starts"
)]

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead as _, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use krb5_cli::{MitArgs, MitOpt, Placement, Prompter, getopt};
use krb5_config::{IpropParams, KdcPaths};
use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_kdc::{
    CreateError, DbUpdate, DbWrite, DumpError, DumpFile, DumpPrincipal, FullLoad, IpropHeaderError,
    IpropRole, KDB_DUMP_VERSION, LoadError, Lockout, LoggedWrite, PersistError, PrincipalStore,
    Ulog, UlogLast, add_admin_principals, create_realm_db, create_store, dump_current_in_ulog,
    load_dump_with_key, master_key_from_password, parse_dump, save_store_with_master, stash_keys,
    string_to_enctype, update_store, write_stash,
};
use zeroize::{Zeroize as _, Zeroizing};

// MIT: `usage` (kadmin/dbutil/kdb5_util.c:77-107)
const USAGE: &str = "Usage: kdb5_util [-r realm] [-d dbname] [-k mkeytype] [-kv mkeyVNO]
\t        [-M mkeyname] [-m] [-sf stashfilename] [-P password]
\t        [-x db_args]* cmd [cmd_options]
\tcreate  [-s]
\tdestroy [-f]
\tstash   [-f keyfile]
\tdump    [-b7|-r13|-r18] [-verbose]
\t        [-mkey_convert] [-new_mkey_file mkey_file]
\t        [-rev] [-recurse] [filename [princs...]]
\tload    [-b7|-r13|-r18] [-hash] [-verbose] [-update] filename
\tark     [-e etype_list] principal
\tadd_mkey [-e etype] [-s]
\tuse_mkey kvno [time]
\tlist_mkeys
\tupdate_princ_encryption [-f] [-n] [-v] [princ-pattern]
\tpurge_mkeys [-f] [-n] [-v]
\ttabdump [-H] [-c] [-e] [-n] [-o outfile] dumptype

where,
\t[-x db_args]* - any number of database specific arguments.
\t\t\tLook at each database documentation for supported arguments
";

// MIT: `main` (kadmin/dbutil/kdb5_util.c:228-296)
const GLOBALS: &[MitOpt] = &[
    MitOpt::value("-P"),
    MitOpt::value("-d"),
    MitOpt::value("-x"),
    MitOpt::value("-r"),
    MitOpt::value("-k"),
    MitOpt::value("-kv"),
    MitOpt::value("-M"),
    MitOpt::value("-sf"),
    MitOpt::flag("-m"),
];

// MIT: `KRB5_KDC_MKEY_1` (include/kdb.h:312-312)
const MKEY_PROMPT: &str = "Enter KDC database master key";
// MIT: `KRB5_KDC_MKEY_2` (include/kdb.h:313-313)
const MKEY_VERIFY: &str = "Re-enter KDC database master key to verify";
// MIT: `krb5_def_fetch_mkey_list` (lib/kdb/kdb_default.c:455-458)
const BAD_MASTER_KEY: &str = "Unable to decrypt latest master key with the provided master key\n";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Command {
    Create,
    Destroy,
    Stash,
    Dump,
    Load,
    Unsupported,
    #[cfg(feature = "test-hooks")]
    Hook,
}

impl Command {
    fn lookup(name: &str) -> Option<Self> {
        Some(match name {
            "create" => Self::Create,
            "destroy" => Self::Destroy,
            "stash" => Self::Stash,
            "dump" => Self::Dump,
            "load" => Self::Load,
            "ark"
            | "add_mkey"
            | "use_mkey"
            | "list_mkeys"
            | "update_princ_encryption"
            | "purge_mkeys"
            | "tabdump" => Self::Unsupported,
            #[cfg(feature = "test-hooks")]
            "addpol" | "setstr" | "alias" | "setlastpwd" => Self::Hook,
            _ => return None,
        })
    }
}

struct Util {
    progname: String,
    realm: Option<String>,
    paths: KdcPaths,
    db_args: DbArgs,
    etype: Option<EncryptionType>,
    password: Option<Zeroizing<String>>,
    manual: bool,
    kvno: Option<u32>,
    exit_status: u8,
    iprop: IpropParams,
    ulog: Option<Ulog>,
}

struct DbArgs {
    file: PathBuf,
    temporary: bool,
    unsupported: Option<String>,
}

impl DbArgs {
    // MIT: `configure_context` (plugins/kdb/db2/kdb_db2.c:221-246)
    /// An unknown `-x` argument is refused by its option name.
    fn parse(opts: &[(&str, Option<String>)], configured: &Path) -> Self {
        let mut args = Self {
            file: configured.to_path_buf(),
            temporary: false,
            unsupported: None,
        };
        for (name, value) in opts {
            let v = value.as_deref().unwrap_or_default();
            match *name {
                "-d" => args.file = PathBuf::from(v),
                "-x" => match v.split_once('=') {
                    Some(("dbname", path)) => args.file = PathBuf::from(path),
                    None if v == "temporary" => args.temporary = true,
                    Some(("hash", _)) => {}
                    None if matches!(v, "merge_nra" | "lockiter" | "unlockiter") => {}
                    other => {
                        let opt = other.map_or(v, |(opt, _)| opt);
                        args.unsupported.get_or_insert_with(|| opt.to_owned());
                    }
                },
                _ => {}
            }
        }
        args
    }

    // MIT: `ctx_dbsuffix` (plugins/kdb/db2/kdb_db2.c:292-303)
    fn open_file(&self) -> PathBuf {
        if self.temporary {
            with_suffix(&self.file, "~")
        } else {
            self.file.clone()
        }
    }
}

impl Util {
    // MIT: `extended_com_err_fn` (kadmin/dbutil/kdb5_util.c:165-179)
    fn com_err(&self, message: &str, context: &str) {
        err_line(&format!("{}: {message} {context}", self.progname));
    }

    fn com_err0(&self, context: &str) {
        err_line(&format!("{}: {context}", self.progname));
    }

    fn failed(&mut self) -> u8 {
        self.exit_status = self.exit_status.saturating_add(1);
        self.exit_status
    }

    fn db(&self) -> &Path {
        &self.paths.database_name
    }
}

fn main() -> ExitCode {
    let mut argv: Vec<String> = std::env::args().collect();
    let progname = argv
        .first()
        .map_or("kdb5_util", |a| a.rsplit('/').next().unwrap_or(a))
        .to_owned();
    let code = run(progname, argv.get(1..).unwrap_or_default());
    // The arguments may hold `-P`'s password.
    argv.zeroize();
    ExitCode::from(code)
}

fn err_line(line: &str) {
    let _ = writeln!(io::stderr(), "{line}");
}

fn out_line(line: &str) {
    let mut out = io::stdout();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

fn usage() -> u8 {
    let _ = io::stderr().write_all(USAGE.as_bytes());
    1
}

fn strerror(e: &io::Error) -> String {
    let s = e.to_string();
    s.rfind(" (os error ")
        .map_or_else(|| s.clone(), |i| s[..i].to_owned())
}

fn persist_text(e: &PersistError) -> String {
    match e {
        PersistError::Io(io) => strerror(io),
        other => other.to_string(),
    }
}

// MIT: `krb5_def_store_mkey_list` (lib/kdb/kdb_default.c:143-147)
/// Keytab written to `<keyfile>_tmp`: a missing directory names that file.
fn stash_write_text(path: &Path, e: &PersistError) -> String {
    match e {
        PersistError::Io(io) if io.kind() == io::ErrorKind::NotFound => {
            format!("Key table file '{}_tmp' not found", path.display())
        }
        other => persist_text(other),
    }
}

/// C `atoi` wraps: blanks, a sign, then digits.
fn c_atoi(s: &str) -> u32 {
    let t = s.trim_start();
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let mut n: u32 = 0;
    for b in digits.bytes().take_while(u8::is_ascii_digit) {
        n = n.wrapping_mul(10).wrapping_add(u32::from(b - b'0'));
    }
    if neg { n.wrapping_neg() } else { n }
}

/// Last `-P` kept; the table sees an empty value: no other copy remains.
fn take_password(args: &[String]) -> (Option<Zeroizing<String>>, Vec<String>) {
    let mut password = None;
    let mut line = Vec::with_capacity(args.len());
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        line.push(arg.clone());
        let Some(opt) = GLOBALS.iter().find(|o| o.name == arg) else {
            continue;
        };
        if !opt.takes_value {
            continue;
        }
        let Some(value) = it.next() else {
            break;
        };
        if opt.name == "-P" {
            password = Some(Zeroizing::new(value.clone()));
            line.push(String::new());
        } else {
            line.push(value.clone());
        }
    }
    (password, line)
}

fn run(progname: String, args: &[String]) -> u8 {
    // MIT: `main` (kadmin/dbutil/kdb5_util.c:214-218)
    let _profile_read = krb5_config::ReadOnce::start();
    if let Err(e) = krb5_config::init_kdc_profile() {
        err_line(&format!(
            "{progname}: {} while initializing Kerberos code",
            e.init_text()
        ));
        return 1;
    }
    let (password, args) = take_password(args);
    let Ok(parsed) = MitArgs::parse(&args, GLOBALS, Placement::Anywhere) else {
        return usage();
    };
    for (name, value) in &parsed.opts {
        let v = value.as_deref().unwrap_or_default();
        let bad = match *name {
            "-k" if string_to_enctype(v).is_err() => "is an invalid enctype",
            "-kv" if c_atoi(v) == 0 => "is an invalid mkeyVNO",
            _ => continue,
        };
        err_line(&format!("{progname}: Invalid argument : {v} {bad}"));
        return 1;
    }
    let Some(command) = parsed.operands.first().and_then(|c| Command::lookup(c)) else {
        return usage();
    };
    if command == Command::Unsupported {
        return usage();
    }
    let mut paths = match KdcPaths::resolve(parsed.value("-r")) {
        Ok(p) => p,
        Err(e @ krb5_config::Error::NoDefaultRealm) => {
            err_line(&format!("{progname}: {e} while getting default realm"));
            return 1;
        }
        Err(e) => {
            err_line(&format!(
                "{progname}: {e} while retrieving configuration parameters"
            ));
            return 1;
        }
    };
    let db_args = DbArgs::parse(&parsed.opts, &paths.database_name);
    if let Some(d) = parsed.value("-d") {
        paths.database_name = PathBuf::from(d);
    }
    if let Some(sf) = parsed.value("-sf") {
        paths.key_stash_file = PathBuf::from(sf);
    }
    let realm = paths.realm.clone();
    if let Some(m) = parsed.value("-M")
        && m != "K/M"
        && realm.as_deref().is_none_or(|r| m != format!("K/M@{r}"))
    {
        return usage();
    }
    let kvno = parsed.value("-kv").map(c_atoi);
    let iprop = IpropParams::load(realm.as_deref().unwrap_or_default(), &paths.database_name);
    if kvno.is_some_and(|k| k != 1) && command != Command::Create {
        return usage();
    }
    // MIT: `kadm5_get_config_params` (lib/kadm5/alt_prof.c:546-551)
    let etype = if let Some(k) = parsed.value("-k") {
        string_to_enctype(k).ok()
    } else {
        let configured = krb5_kdc::master_etype(paths.master_key_type.as_deref()).ok();
        if configured.is_none() {
            err_line(&format!(
                "{progname}: Program lacks support for key type while setting up enctype 0"
            ));
        }
        configured
    };
    let mut util = Util {
        progname,
        realm,
        paths,
        db_args,
        etype,
        password,
        manual: parsed.flag("-m"),
        kvno,
        exit_status: 0,
        iprop,
        ulog: None,
    };
    let cmd_args = &parsed.operands;
    match command {
        Command::Create => create(&mut util, cmd_args),
        Command::Load => load(&mut util, cmd_args),
        Command::Destroy | Command::Stash | Command::Dump => {
            let db = match open_db_and_mkey(&mut util) {
                Ok(db) => db,
                Err(code) => return code,
            };
            match command {
                Command::Destroy => destroy(&mut util, cmd_args),
                Command::Stash => stash(&mut util, cmd_args, db),
                _ => dump(&mut util, cmd_args),
            }
        }
        Command::Unsupported => usage(),
        #[cfg(feature = "test-hooks")]
        Command::Hook => hooks::command(&util, cmd_args),
    }
}

fn sub_options(args: &[String], optstring: &str) -> Result<Vec<krb5_cli::Opt>, u8> {
    let name = args.first().map_or("", String::as_str);
    match getopt(args.get(1..).unwrap_or_default(), optstring, &[]) {
        Ok((opts, _)) => Ok(opts),
        Err(e) => {
            err_line(&format!("{name}: {e}"));
            Err(usage())
        }
    }
}

// MIT: `kdb5_create` (kadmin/dbutil/kdb5_create.c:142-336)
fn create(util: &mut Util, args: &[String]) -> u8 {
    let opts = match sub_options(args, "sW") {
        Ok(o) => o,
        Err(code) => return code,
    };
    let do_stash = opts.iter().any(|o| o.flag == 's');
    let Some(realm) = util.realm.clone() else {
        util.com_err(
            "Configuration file does not specify default realm",
            "while getting default realm",
        );
        return 1;
    };
    let db = util.db().to_path_buf();
    out_line(&format!(
        "Initializing database '{}' for realm '{realm}',\nmaster key name 'K/M@{realm}'",
        db.display()
    ));
    // MIT: `kadm5_init` (lib/kadm5/srv/server_init.c:222-228)
    if util.iprop.missing_required()
        || krb5_kdc::realm_kadm5_params_missing(&util.paths, &realm, false)
    {
        util.com_err(
            krb5_config::MISSING_CONF_PARAMS,
            "while initializing the Kerberos admin interface",
        );
        return util.failed();
    }
    #[cfg(feature = "test-hooks")]
    let hooked = hooks::master_password();
    #[cfg(not(feature = "test-hooks"))]
    let hooked: Option<Zeroizing<String>> = None;
    let master = if let Some(pw) = util.password.clone().or(hooked) {
        derive_master(util, &realm, pw.as_bytes())
    } else {
        out_line("You will be prompted for the database Master Password.");
        out_line("It is important that you NOT FORGET this password.");
        match krb5_cli::read_password(MKEY_PROMPT, Some(MKEY_VERIFY)) {
            Ok(pw) => derive_master(util, &realm, &pw),
            Err(e) => {
                util.com_err(&e.to_string(), "while reading master key from keyboard");
                return util.failed();
            }
        }
    };
    let Some(master) = master else {
        util.com_err(
            "Bad encryption type",
            "while transforming master key from password",
        );
        return util.failed();
    };
    let creating = format!("while creating database '{}'", db.display());
    if let Some(arg) = &util.db_args.unsupported {
        util.com_err(
            &format!("Unsupported argument \"{arg}\" for db2"),
            &creating,
        );
        return util.failed();
    }
    let file = util.db_args.open_file();
    let kdc = match realm_kdc_conf(util, &realm) {
        Ok(k) => k,
        Err(e) => {
            util.com_err(&e, "while retrieving configuration parameters");
            return util.failed();
        }
    };
    let mkvno = u16::try_from(util.kvno.unwrap_or(1)).unwrap_or(1);
    let mut store = match create_realm_db(&realm, kdc.as_ref(), &master, mkvno) {
        Ok(s) => s,
        Err(e) => {
            util.com_err(&e.to_string(), "while adding entries to the database");
            return util.failed();
        }
    };
    // MIT: `ctx_create_db` (plugins/kdb/db2/kdb_db2.c:710-716)
    // A temporary database's leftover files are destroyed before it is created.
    if util.db_args.temporary {
        let _ = destroy_file(&file);
        for suffix in [".kadm5", ".kadm5.lock"] {
            let _ = fs::remove_file(with_suffix(&file, suffix));
        }
    }
    match create_store(&store, &file, &master) {
        Ok(()) => {}
        Err(CreateError::Create(e)) => {
            let why = if e.kind() == io::ErrorKind::AlreadyExists {
                format!(
                    "Cannot open DB2 database '{}': {}",
                    file.display(),
                    strerror(&e)
                )
            } else {
                strerror(&e)
            };
            util.com_err(&why, &creating);
            return util.failed();
        }
        Err(CreateError::Persist(e)) => {
            util.com_err(&persist_text(&e), &creating);
            return util.failed();
        }
        Err(CreateError::Lock(e)) => {
            util.com_err(&e.to_string(), &creating);
            return util.failed();
        }
    }
    let stash = util.paths.key_stash_file.clone();
    if do_stash && let Err(e) = write_stash(&stash, &realm, &master, u32::from(mkvno)) {
        util.com_err(&stash_write_text(&stash, &e), "while storing key");
        out_line("Warning: couldn't stash master key.");
        return util.failed();
    }
    if !kadm5_create(util, &mut store, kdc.as_ref(), &master, mkvno, &file) {
        if !do_stash {
            let _ = fs::remove_file(&stash);
        }
        return util.failed();
    }
    if util.iprop.enabled {
        match Ulog::map(&util.iprop.logfile, util.iprop.ulogsize) {
            Ok(log) => {
                if let Err(e) = log.init_header() {
                    err_line(&format!("create: {e} while initializing update log"));
                    return util.failed();
                }
            }
            Err(e) => {
                err_line(&format!("create: {e} while creating update log"));
                return util.failed();
            }
        }
    }
    if !do_stash {
        let _ = fs::remove_file(&stash);
    }
    util.exit_status
}

// MIT: `kadm5_create_magic_princs` (kadmin/dbutil/kadm5_create.c:91-116)
fn kadm5_create(
    util: &Util,
    store: &mut PrincipalStore,
    kdc: Option<&krb5_config::KdcConf>,
    master: &ProtocolKey,
    mkvno: u16,
    db: &Path,
) -> bool {
    let specs = krb5_config::LogSpecs::load("admin_server");
    krb5_log::klog::init(&util.progname, &specs.specs, specs.debug);
    if let Err(e) = store.init_pwqual(kdc) {
        util.com_err(
            &strerror(&e),
            "while initializing the Kerberos admin interface",
        );
        krb5_log::klog::close();
        return false;
    }
    if let Err(e) = add_admin_principals(store, mkvno) {
        util.com_err(&e.to_string(), "while creating principal");
        krb5_log::klog::close();
        return false;
    }
    #[cfg(feature = "test-hooks")]
    if let Err(e) = hooks::seed(store) {
        util.com_err(&e.to_string(), "while adding entries to the database");
        krb5_log::klog::close();
        return false;
    }
    if let Err(e) = save_store_with_master(store, db, master, DbWrite::InPlace) {
        util.com_err(&persist_text(&e), "while adding entries to the database");
        krb5_log::klog::close();
        return false;
    }
    krb5_log::klog::close();
    true
}

fn derive_master(util: &Util, realm: &str, password: &[u8]) -> Option<ProtocolKey> {
    util.etype
        .and_then(|etype| master_key_from_password(realm, password, etype).ok())
}

fn realm_kdc_conf(util: &Util, realm: &str) -> Result<Option<krb5_config::KdcConf>, String> {
    if util.paths.conf.is_none() {
        return Ok(None);
    }
    krb5_config::KdcConf::load_file_for_realm(&util.paths.profile, realm)
        .map(Some)
        .map_err(|e| match e {
            krb5_config::Error::Io(e) => strerror(&e),
            e => e.to_string(),
        })
}

struct OpenDb {
    realm: String,
    km: DumpPrincipal,
    mkey: Option<ProtocolKey>,
}

// MIT: `open_db_and_mkey` (kadmin/dbutil/kdb5_util.c:369-485)
fn open_db_and_mkey(util: &mut Util) -> Result<OpenDb, u8> {
    let db = util.db_args.open_file();
    if let Some(arg) = &util.db_args.unsupported {
        util.com_err(
            &format!("Unsupported argument \"{arg}\" for db2"),
            "while initializing database",
        );
        return Err(util.failed());
    }
    let cannot_open = |why: &str| format!("Cannot open DB2 database '{}': {why}", db.display());
    let text = match read_db_text(util, &db) {
        Ok((t, _)) => t,
        Err(why) => {
            util.com_err(&why, "while initializing database");
            return Err(util.failed());
        }
    };
    let dump = match parse_dump(&text) {
        Ok(d) => d,
        Err(e) => {
            util.com_err(&cannot_open(&e.to_string()), "while initializing database");
            return Err(util.failed());
        }
    };
    let realm = util
        .realm
        .clone()
        .or_else(|| dump.realm().ok().map(str::to_owned))
        .unwrap_or_default();
    let Some(km) = dump.princ(&format!("K/M@{realm}")).cloned() else {
        util.com_err(
            "No such entry in the database",
            "while retrieving master entry",
        );
        return Err(util.failed());
    };
    let mkey = fetch_mkey(util, &realm, &km)?;
    if mkey.is_some() && util.iprop.enabled {
        let Ok(log) = Ulog::map(&util.iprop.logfile, util.iprop.ulogsize) else {
            err_line(&format!("{}: Could not map log", util.progname));
            return Err(util.failed());
        };
        util.ulog = Some(log);
    }
    Ok(OpenDb { realm, km, mkey })
}

// MIT: `krb5_db2_open` (plugins/kdb/db2/kdb_db2.c:1194-1198)
fn read_db_text(util: &Util, db: &Path) -> Result<(String, HashMap<String, Lockout>), String> {
    let cannot_open = |why: &str| format!("Cannot open DB2 database '{}': {why}", db.display());
    krb5_kdc::check_openable(db).map_err(|e| open_text(db, &e))?;
    let (bytes, lockout) = krb5_kdc::read_db_and_lockout_locked(db).map_err(|e| match e {
        PersistError::Lock(lock) => lock.to_string(),
        other => open_text(db, &other),
    })?;
    if bytes.starts_with(b"kdb5_util load_dump version ") {
        let text = String::from_utf8(bytes).map_err(|_| cannot_open("dump is not UTF-8"))?;
        return Ok((text, lockout));
    }
    let stash = &util.paths.key_stash_file;
    let store = krb5_kdc::load_store(db, stash).map_err(|e| open_text(db, &e))?;
    let mkey = krb5_kdc::read_stash(stash, db).map_err(|e| cannot_open(&persist_text(&e)))?;
    let text =
        krb5_kdc::dump_store_with_key(&store, &mkey).map_err(|e| cannot_open(&e.to_string()))?;
    Ok((text, HashMap::new()))
}

// MIT: `open_db` (plugins/kdb/db2/kdb_db2.c:386-389)
fn open_text(db: &Path, e: &PersistError) -> String {
    match e {
        PersistError::Unopenable { .. } => e.to_string(),
        other => format!(
            "Cannot open DB2 database '{}': {}",
            db.display(),
            persist_text(other)
        ),
    }
}

fn fetch_mkey(util: &mut Util, realm: &str, km: &DumpPrincipal) -> Result<Option<ProtocolKey>, u8> {
    let key = if let Some(pw) = util.password.clone() {
        if util.etype.is_none() {
            util.com_err(
                "Program lacks support for key type",
                "while setting up enctype 0",
            );
        }
        let Some(key) = derive_master(util, realm, pw.as_bytes()) else {
            util.com_err(
                "Bad encryption type",
                "while transforming master key from password",
            );
            return Err(util.failed());
        };
        key
    } else if util.manual {
        let typed = Prompter::stdio().hidden(MKEY_PROMPT);
        let key = match typed {
            Ok(pw) => {
                derive_master(util, realm, &pw).ok_or_else(|| "Bad encryption type".to_owned())
            }
            Err(e) => Err(e.to_string()),
        };
        match key {
            Ok(k) => k,
            Err(why) => {
                util.com_err(&why, "while reading master key");
                util.com_err0("Warning: proceeding without master key");
                util.failed();
                return Ok(None);
            }
        }
    } else {
        match read_stash_key(&util.paths.key_stash_file, km) {
            Ok(k) => k,
            Err(why) => {
                util.com_err(
                    &format!("Can not fetch master key (error: {why})."),
                    "while reading master key",
                );
                util.com_err0("Warning: proceeding without master key");
                util.failed();
                return Ok(None);
            }
        }
    };
    if !km.opens_with(&key) {
        util.com_err(BAD_MASTER_KEY, "while getting master key list");
        util.com_err0("Warning: proceeding without master key list");
        util.failed();
        return Ok(None);
    }
    Ok(Some(key))
}

fn read_stash_key(path: &Path, km: &DumpPrincipal) -> Result<ProtocolKey, String> {
    let bytes = krb5_protocol::read_stash_file(path).map_err(|e| strerror(&e))?;
    let keys = stash_keys(&bytes);
    let pick = keys.iter().position(|k| km.opens_with(k)).unwrap_or(0);
    keys.into_iter()
        .nth(pick)
        .ok_or_else(|| "Stored master key is corrupted".to_owned())
}

// MIT: `kdb5_stash` (kadmin/dbutil/kdb5_stash.c:65-137)
fn stash(util: &mut Util, args: &[String], db: OpenDb) -> u8 {
    let opts = match sub_options(args, "f:") {
        Ok(o) => o,
        Err(code) => return code,
    };
    let keyfile = opts
        .iter()
        .rev()
        .find(|o| o.flag == 'f')
        .and_then(|o| o.arg.clone())
        .map_or_else(|| util.paths.key_stash_file.clone(), PathBuf::from);
    let key = if let Some(k) = db.mkey {
        out_line("Using existing stashed keys to update stash file.");
        k
    } else {
        if util.etype.is_none() {
            util.com_err(
                "Program lacks support for key type",
                "while setting up enctype 0",
            );
            return util.failed();
        }
        let typed = match Prompter::stdio().hidden(MKEY_PROMPT) {
            Ok(pw) => pw,
            Err(e) => {
                util.com_err(&e.to_string(), "while reading master key");
                return util.failed();
            }
        };
        let Some(key) = derive_master(util, &db.realm, &typed) else {
            util.com_err("Bad encryption type", "while reading master key");
            return util.failed();
        };
        if !db.km.opens_with(&key) {
            util.com_err(BAD_MASTER_KEY, "while getting master key list");
            return util.failed();
        }
        key
    };
    let kvno = db.km.keys.first().map_or(1, |k| k.kvno);
    if let Err(e) = write_stash(&keyfile, &db.realm, &key, kvno) {
        util.com_err(&stash_write_text(&keyfile, &e), "while storing key");
        return util.failed();
    }
    0
}

// MIT: `dump_db` (kadmin/dbutil/dump.c:1137-1361)
fn dump(util: &mut Util, args: &[String]) -> u8 {
    let mut version = KDB_DUMP_VERSION;
    let (mut verbose, mut rev, mut conditional) = (false, false, false);
    let mut iprop: Option<Iprop> = None;
    let mut i = 1;
    while let Some(a) = args.get(i) {
        match a.as_str() {
            "-b7" | "-r13" | "-mkey_convert" | "-new_mkey_file" => return usage(),
            "-ov" => {
                err_line("OV dump format not supported");
                return util.failed();
            }
            "-r18" => version = 6,
            "-c" => conditional = true,
            "-verbose" => verbose = true,
            "-rev" => rev = true,
            "-recurse" => {}
            // `-i` without iprop enabled is refused.
            s if s.starts_with("-i") => {
                if !util.iprop.enabled {
                    err_line("Iprop not enabled");
                    return util.failed();
                }
                iprop = Some(if c_atoi(&s[2..]) == 0 {
                    Iprop::V0
                } else {
                    Iprop::X1
                });
            }
            _ => break,
        }
        i += 1;
    }
    let ofile = args.get(i);
    let names = args.get(i + 1..).unwrap_or_default();
    if let Some(f) = ofile
        && conditional
    {
        if iprop.is_none() {
            util.com_err0(
                "Conditional dump is an undocumented option for use only for iprop dumps",
            );
            return util.failed();
        }
        if current_dump_sno_in_ulog(util, Path::new(f)) {
            return util.exit_status;
        }
    }
    let to_file = ofile.filter(|f| f.as_str() != "-");
    if to_file.is_some_and(|f| f.starts_with('-')) {
        return usage();
    }
    let last = match iprop {
        Some(_) => match util.ulog.as_ref().map(Ulog::get_last) {
            Some(Ok(last)) => Some(last),
            Some(Err(e)) => {
                util.com_err(&e.to_string(), "while reading update log header");
                return util.failed();
            }
            None => {
                util.com_err(
                    "Generic update log error",
                    "while reading update log header",
                );
                return util.failed();
            }
        },
        None => None,
    };
    let current = match read_db_text(util, &util.db_args.open_file()).and_then(|(text, lockout)| {
        let mut dump = parse_dump(&text).map_err(|e| e.to_string())?;
        // MIT: `klmdb_iterate` (plugins/kdb/lmdb/kdb_lmdb.c:841-888)
        // MIT: `k5beta7_common` (kadmin/dbutil/dump.c:340-344)
        for p in &mut dump.princs {
            if iprop.is_some() {
                p.last_success = 0;
                p.last_failed = 0;
                p.fail_auth_count = 0;
            } else if let Some(l) = lockout.get(&p.name) {
                p.last_success = l.last_success;
                p.last_failed = l.last_failed;
                p.fail_auth_count = l.fail_auth_count;
            }
        }
        Ok(dump)
    }) {
        Ok(d) => d,
        Err(why) => {
            util.com_err(&why, &format!("performing {} dump", version_name(version)));
            return util.failed();
        }
    };
    let mut princs: Vec<&DumpPrincipal> = current
        .princs
        .iter()
        .filter(|p| name_matches(util, &p.name, names))
        .collect();
    // MIT: `ctx_iterate` (plugins/kdb/db2/kdb_db2.c:1109-1137)
    princs.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    if rev {
        princs.reverse();
    }
    let mut text = match (iprop, last) {
        (Some(Iprop::V0), Some(l)) => {
            format!("iprop {} {} {}\n", l.sno, l.time.seconds, l.time.useconds)
        }
        (Some(Iprop::X1), Some(l)) => format!(
            "ipropx 1 {} {} {}\n",
            l.sno, l.time.seconds, l.time.useconds
        ),
        _ => format!("kdb5_util load_dump version {version}\n"),
    };
    for p in &princs {
        text.push_str(&p.record());
        text.push('\n');
    }
    // MIT: `iprop_version` (kadmin/dbutil/dump.c:1046-1055)
    let policy_version = if iprop == Some(Iprop::V0) { 5 } else { version };
    if names.is_empty() {
        for pol in &current.policies {
            text.push_str(&DumpFile::policy_record(pol, policy_version));
            text.push('\n');
        }
    }
    if let Some(f) = to_file {
        if let Err(code) = write_dump_file(util, Path::new(f), &text) {
            return code;
        }
    } else {
        let mut out = io::stdout();
        let _ = out.write_all(text.as_bytes());
        let _ = out.flush();
    }
    if verbose {
        for p in &princs {
            err_line(&p.name);
        }
    }
    util.exit_status
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Iprop {
    V0,
    X1,
}

fn current_dump_sno_in_ulog(util: &Util, file: &Path) -> bool {
    util.ulog
        .as_ref()
        .is_some_and(|log| dump_current_in_ulog(file, log))
}

// MIT: `parse_iprop_header` (kadmin/dbutil/dump.c:1089-1101)
fn iprop_header_last(util: &Util, line: &str) -> Option<UlogLast> {
    match krb5_kdc::parse_iprop_header(line) {
        Ok((_, last)) => Some(last),
        Err(IpropHeaderError::UnknownVersion(v)) => {
            err_line(&format!(
                "{}: Unknown iprop dump version {v}",
                util.progname
            ));
            None
        }
        Err(IpropHeaderError::NotIprop) => {
            err_line("Invalid iprop header");
            None
        }
        Err(IpropHeaderError::Short) => None,
    }
}

// MIT: `prep_ok_file` (kadmin/dbutil/dump.c:171-208)
// MIT: `create_ofile` (kadmin/dbutil/dump.c:133-155)
// MIT: `finish_ofile` (kadmin/dbutil/dump.c:159-167)
// MIT: `update_ok_file` (kadmin/dbutil/dump.c:214-219)
fn write_dump_file(util: &mut Util, path: &Path, text: &str) -> Result<(), u8> {
    let mut ok_name = path.as_os_str().to_os_string();
    ok_name.push(".dump_ok");
    let ok_path = PathBuf::from(ok_name);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // `O_NOFOLLOW`, so a planted symlink is not emptied; MIT's `O_TRUNC` would.
        opts.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let ok = match krb5_protocol::create_labeled(&ok_path, || opts.open(&ok_path)) {
        Ok(f) => f,
        Err(e) => {
            util.com_err(
                &strerror(&e),
                &format!("while creating 'ok' file, '{}'", ok_path.display()),
            );
            return Err(util.failed());
        }
    };
    let marked = match krb5_kdc::lock_file_exclusive(&ok) {
        Ok(guard) => guard,
        Err(e) => {
            util.com_err(
                &strerror(&e),
                &format!("while locking 'ok' file, '{}'", ok_path.display()),
            );
            return Err(util.failed());
        }
    };
    if let Err(e) = krb5_protocol::write_fresh_secret_file(path, text.as_bytes()) {
        util.com_err(&strerror(&e), "while allocating temporary filename dump");
        return Err(1);
    }
    let _ = (&ok).write_all(&[0]);
    drop(marked);
    Ok(())
}

// MIT: `name_matches` (kadmin/dbutil/dump.c:221-257)
fn name_matches(util: &Util, name: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }
    for pat in patterns {
        let re = match krb5_types::ere::Ere::new(pat.as_bytes()) {
            Ok(re) => re,
            Err(code) => {
                let why = krb5_types::ere::regerror(code);
                util.com_err0(&format!("regular expression error: {why}"));
                return false;
            }
        };
        match re.is_whole_match(name.as_bytes()) {
            Some(true) => return true,
            Some(false) => {}
            None => {
                util.com_err0("regular expression match error: back-references are not supported");
                return false;
            }
        }
    }
    false
}

// MIT: `r1_8_version` (kadmin/dbutil/dump.c:1026-1035)
// MIT: `r1_11_version` (kadmin/dbutil/dump.c:1036-1045)
fn version_name(version: u32) -> &'static str {
    if version == KDB_DUMP_VERSION {
        "Kerberos version 5 release 1.11"
    } else {
        "Kerberos version 5 release 1.8"
    }
}

// MIT: `load_db` (kadmin/dbutil/dump.c:1382-1610)
fn load(util: &mut Util, args: &[String]) -> u8 {
    let mut want: Option<u32> = None;
    let (mut verbose, mut update, mut iprop_load) = (false, false, false);
    let mut i = 1;
    while let Some(a) = args.get(i) {
        match a.as_str() {
            "-b7" | "-r13" => return usage(),
            "-i" => {
                if !util.iprop.enabled {
                    err_line("Iprop not enabled");
                    return 1;
                }
                iprop_load = true;
            }
            "-ov" => {
                err_line("OV dump format not supported");
                return 1;
            }
            "-r18" => want = Some(6),
            "-verbose" => verbose = true,
            "-update" => update = true,
            "-hash" => {}
            _ => break,
        }
        i += 1;
    }
    if args.len().saturating_sub(i) != 1 {
        return usage();
    }
    let file = args[i].as_str();
    let bytes = match fs::read(file) {
        Ok(b) => b,
        Err(e) => {
            util.com_err(&strerror(&e), &format!("while opening {file}"));
            return 1;
        }
    };
    let Some(version) = dump_version(util, &bytes, want, iprop_load, file) else {
        return 1;
    };
    if util.iprop.enabled {
        let Ok(log) = Ulog::map(&util.iprop.logfile, util.iprop.ulogsize) else {
            err_line("Could not open iprop ulog");
            return 1;
        };
        util.ulog = Some(log);
    }
    let iprop_last = if iprop_load && !update {
        let line = bytes.split(|&b| b == b'\n').next().unwrap_or_default();
        match iprop_header_last(util, &String::from_utf8_lossy(line)) {
            Some(last) => Some(last),
            None => return 1,
        }
    } else {
        None
    };
    if let Some(arg) = &util.db_args.unsupported {
        let context = if update {
            "while opening database"
        } else {
            "while creating database"
        };
        util.com_err(&format!("Unsupported argument \"{arg}\" for db2"), context);
        return 1;
    }
    let target = if update {
        let Some(update) = open_update(util) else {
            return 1;
        };
        Some(update)
    } else {
        None
    };
    let Ok(text) = String::from_utf8(bytes) else {
        restore_failed(util, file, version, "line 1: dump is not UTF-8");
        return 1;
    };
    let dump = match parse_dump(&text) {
        Ok(d) => d,
        Err(e) => {
            restore_failed(util, file, version, &dump_error_text(&e));
            return 1;
        }
    };
    if dump.princs.is_empty() {
        return load_policies_only(util, target, &dump, verbose, iprop_last);
    }
    let Some((key, from_hook)) = load_master_key(util, &dump) else {
        return 1;
    };
    let loaded = match load_dump_with_key(&text, &key) {
        Ok(s) => s,
        Err(e) => {
            restore_failed(util, file, version, &dump_error_text(&e));
            return 1;
        }
    };
    let realm = loaded.realm().to_owned();
    if let Some(mut update) = target {
        let legacy = match legacy_stash(util, &update) {
            Ok(legacy) => legacy,
            Err(code) => return code,
        };
        if !lock_permanently(util, &mut update) {
            return 1;
        }
        let mut store = match update.store(&key, legacy.as_deref().map(Vec::as_slice)) {
            Ok(Some(current)) => current,
            Ok(None) => {
                let mut empty = PrincipalStore::new(loaded.realm());
                empty.set_domain_sid(loaded.domain_sid().clone());
                empty
            }
            Err(e) => {
                util.com_err(&open_text(update.db(), &e), "while opening database");
                return 1;
            }
        };
        if let Some(log) = util.ulog.take() {
            store.set_ulog(log, IpropRole::Primary);
        }
        // MIT: `process_k5beta7_princ` (kadmin/dbutil/dump.c:691-694)
        // A loaded record's lockout is written; the others keep theirs.
        let order: Vec<&str> = dump.princs.iter().map(|p| p.name.as_str()).collect();
        if let Err(e) = update_store(&mut store, &loaded, &order) {
            util.com_err(&e.to_string(), "while creating policy");
            return 1;
        }
        let first = dump.princs.first().map_or("", |p| p.name.as_str());
        // MIT: `krb5_db_put_principal` (lib/kdb/kdb5.c:987-999)
        // An unconvertible record fails the load before the database is written.
        let prepared = match store.prepare_log() {
            Ok(p) => p,
            Err(e) => {
                util.com_err(&e.to_string(), &format!("while storing {first}"));
                return 1;
            }
        };
        match store.write_logged(prepared, || update.write_store(&store, &key)) {
            Ok(()) => {}
            Err(LoggedWrite::Write(e)) => {
                util.com_err(&persist_text(&e), &format!("while storing {first}"));
                return 1;
            }
            Err(LoggedWrite::Before(e) | LoggedWrite::After(e)) => {
                util.com_err(&e.to_string(), &format!("while storing {first}"));
                return 1;
            }
        }
        if !update_unlock(util, update) {
            return 1;
        }
    } else {
        let Some(full) = create_temporary(util) else {
            return 1;
        };
        if let Err(e) = full.finish_store(&loaded, &key, iprop_load, load_log(util, iprop_last)) {
            load_failed(util, &e);
            return 1;
        }
    }
    if from_hook {
        let kvno = dump
            .princ(&format!("K/M@{realm}"))
            .and_then(|km| km.keys.first())
            .map_or(1, |k| k.kvno);
        let stash = util.paths.key_stash_file.clone();
        if let Err(e) = write_stash(&stash, &realm, &key, kvno) {
            util.com_err(&stash_write_text(&stash, &e), "while storing key");
            return 1;
        }
    }
    if verbose {
        for p in &dump.princs {
            err_line(&p.name);
        }
        for pol in &dump.policies {
            let name = pol.split('\t').next().unwrap_or_default();
            err_line(&format!("created policy {name}"));
        }
    }
    0
}

// MIT: `restore_dump` (kadmin/dbutil/dump.c:1364-1379)
fn load_policies_only(
    util: &mut Util,
    target: Option<DbUpdate>,
    dump: &DumpFile,
    verbose: bool,
    iprop_last: Option<UlogLast>,
) -> u8 {
    let records = dump.policy_records();
    let header = format!("kdb5_util load_dump version {KDB_DUMP_VERSION}\n");
    if let Some(mut update) = target {
        let legacy = match legacy_stash(util, &update) {
            Ok(legacy) => legacy,
            Err(code) => return code,
        };
        if !lock_permanently(util, &mut update) {
            return 1;
        }
        let (current, empty) = match update.text(legacy.as_deref().map(Vec::as_slice)) {
            Ok(Some(text)) => (text, false),
            Ok(None) => (header, true),
            Err(e) => {
                util.com_err(&open_text(update.db(), &e), "while opening database");
                return 1;
            }
        };
        if (empty || !records.is_empty())
            && let Err(e) = update.write_text(&merge_policy_records(&current, &records))
        {
            util.com_err(&persist_text(&e), "while creating policy");
            return 1;
        }
        // MIT: `krb5_db_create_policy` (lib/kdb/kdb5.c:2440-2457)
        if !records.is_empty()
            && let Some(log) = &util.ulog
            && let Err(e) = log.init_header()
        {
            util.com_err(&e.to_string(), "while creating policy");
            return 1;
        }
        if !update_unlock(util, update) {
            return 1;
        }
    } else {
        let Some(full) = create_temporary(util) else {
            return 1;
        };
        let mut text = header;
        for r in &records {
            text.push_str(r);
            text.push('\n');
        }
        if let Err(e) = full.finish(&text, &[], false, load_log(util, iprop_last)) {
            load_failed(util, &e);
            return 1;
        }
    }
    if verbose {
        for pol in &dump.policies {
            let name = pol.split('\t').next().unwrap_or_default();
            err_line(&format!("created policy {name}"));
        }
    }
    0
}

// MIT: `load_db` (kadmin/dbutil/dump.c:1529-1532)
/// A full load's puts are not logged; the log restarts around the promotion.
fn load_log(util: &Util, last: Option<UlogLast>) -> Option<krb5_kdc::LoadLog<'_>> {
    util.ulog
        .as_ref()
        .map(|ulog| krb5_kdc::LoadLog { ulog, last })
}

// MIT: `load_db` (kadmin/dbutil/dump.c:1509-1516)
fn open_update(util: &Util) -> Option<DbUpdate> {
    let db = util.db_args.open_file();
    match DbUpdate::open(&db) {
        Ok(update) => Some(update),
        Err(e @ PersistError::Lock(_)) => {
            util.com_err(&e.to_string(), "while opening database");
            None
        }
        Err(e) => {
            util.com_err(&open_text(&db, &e), "while opening database");
            None
        }
    }
}

/// Temporary database made after the key is read: the prompt holds no lock.
// MIT: `load_db` (kadmin/dbutil/dump.c:1492-1508)
fn create_temporary(util: &Util) -> Option<FullLoad> {
    match FullLoad::create(&util.db_args.file) {
        Ok(full) => Some(full),
        Err(e) => {
            load_failed(util, &e);
            None
        }
    }
}

/// A legacy database's stash is read before the permanent lock.
// MIT: `krb5_db_def_fetch_mkey` (lib/kdb/kdb_default.c:384-390)
fn legacy_stash(util: &Util, update: &DbUpdate) -> Result<Option<Zeroizing<Vec<u8>>>, u8> {
    if !update.legacy() {
        return Ok(None);
    }
    match fs::read(&util.paths.key_stash_file) {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(e) => {
            util.com_err(
                &format!("Can not fetch master key (error: {}).", strerror(&e)),
                "while reading master key",
            );
            Err(1)
        }
    }
}

/// `principal.kadm5.lock` stays removed until the update's lock is released.
fn lock_permanently(util: &Util, update: &mut DbUpdate) -> bool {
    match update.lock_permanently() {
        Ok(()) => true,
        Err(e) => {
            util.com_err(&persist_text(&e), "while permanently locking database");
            false
        }
    }
}

// MIT: `load_db` (kadmin/dbutil/dump.c:1546-1549)
fn update_unlock(util: &Util, update: DbUpdate) -> bool {
    match update.unlock() {
        Ok(()) => true,
        Err(e) => {
            util.com_err(&persist_text(&e), "while unlocking database");
            false
        }
    }
}

// MIT: `load_db` (kadmin/dbutil/dump.c:1503-1507)
// MIT: `load_db` (kadmin/dbutil/dump.c:1562-1568)
// MIT: `load_db` (kadmin/dbutil/dump.c:1554-1559)
// MIT: `load_db` (kadmin/dbutil/dump.c:1579-1585)
fn load_failed(util: &Util, e: &LoadError) {
    match e {
        LoadError::Create(e) => util.com_err(&persist_text(e), "while creating database"),
        LoadError::Promote(e) => {
            util.com_err(&persist_text(e), "while making newly loaded database live");
        }
        LoadError::Reinit(e) => util.com_err(&e.to_string(), "while reinitializing update log"),
        LoadError::SetLast(e) => util.com_err(&e.to_string(), "while writing update log header"),
    }
}

// MIT: `process_k5beta7_policy` (kadmin/dbutil/dump.c:820-822)
fn merge_policy_records(current: &str, records: &[String]) -> String {
    let name = |line: &str| {
        line.strip_prefix("policy\t")
            .and_then(|rest| rest.split('\t').next())
            .map(str::to_owned)
    };
    let mut lines: Vec<String> = current.lines().map(str::to_owned).collect();
    for rec in records {
        let want = name(rec);
        match lines.iter().position(|l| want.is_some() && name(l) == want) {
            Some(i) => lines[i].clone_from(rec),
            None => lines.push(rec.clone()),
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

// MIT: `load_db` (kadmin/dbutil/dump.c:1447-1475)
fn dump_version(
    util: &Util,
    bytes: &[u8],
    want: Option<u32>,
    iprop: bool,
    file: &str,
) -> Option<u32> {
    if bytes.is_empty() {
        err_line(&format!(
            "{}: can't read dump header in {file}",
            util.progname
        ));
        return None;
    }
    let end = bytes
        .iter()
        .position(|&b| b == b'\n')
        .map_or(bytes.len(), |p| p + 1);
    let header = &bytes[..end];
    let version = match want {
        _ if iprop => header.starts_with(b"iprop").then_some(KDB_DUMP_VERSION),
        Some(v) => {
            let expect = format!("kdb5_util load_dump version {v}\n");
            header.starts_with(expect.as_bytes()).then_some(v)
        }
        None => [6, KDB_DUMP_VERSION]
            .into_iter()
            .find(|v| header == format!("kdb5_util load_dump version {v}\n").as_bytes()),
    };
    if version.is_none() {
        err_line(&format!("{}: dump header bad in {file}", util.progname));
    }
    version
}

fn dump_error_text(e: &DumpError) -> String {
    match e {
        DumpError::Format(s) | DumpError::Crypto(s) => s.clone(),
        DumpError::Io(io) => strerror(io),
    }
}

// MIT: `restore_dump` (kadmin/dbutil/dump.c:1364-1379)
// MIT: `load_db` (kadmin/dbutil/dump.c:1540-1543)
fn restore_failed(util: &Util, file: &str, version: u32, why: &str) {
    let progname = &util.progname;
    let (line, detail) = why
        .strip_prefix("line ")
        .and_then(|rest| rest.split_once(": "))
        .and_then(|(n, d)| n.parse::<usize>().ok().map(|n| (n, d)))
        .map_or((None, why), |(n, d)| (Some(n), d));
    match line {
        Some(n) => {
            err_line(&format!("{file}({n}): {detail}"));
            err_line(&format!("{progname}: error processing line {n} of {file}"));
        }
        None => err_line(&format!("{progname}: {detail}")),
    }
    err_line(&format!(
        "{progname}: {} restore failed",
        version_name(version)
    ));
}

fn load_master_key(util: &mut Util, dump: &DumpFile) -> Option<(ProtocolKey, bool)> {
    let realm = dump.realm().map(str::to_owned).unwrap_or_default();
    let km = dump.princ(&format!("K/M@{realm}"));
    let opens = |k: &ProtocolKey| km.is_none_or(|km| km.opens_with(k));
    let etype = dump.master_etype().or(util.etype);
    let derive = |pw: &[u8]| etype.and_then(|e| master_key_from_password(&realm, pw, e).ok());
    let (key, from_hook) = if let Some(pw) = util.password.clone() {
        (derive(pw.as_bytes()), false)
    } else if util.manual {
        match Prompter::stdio().hidden(MKEY_PROMPT) {
            Ok(pw) => (derive(&pw), false),
            Err(e) => {
                util.com_err(&e.to_string(), "while reading master key");
                return None;
            }
        }
    } else {
        match krb5_protocol::read_stash_file(&util.paths.key_stash_file) {
            Ok(bytes) => {
                let found = stash_keys(&bytes).into_iter().find(|k| opens(k));
                if found.is_none() {
                    util.com_err(BAD_MASTER_KEY, "while getting master key list");
                }
                return found.map(|k| (k, false));
            }
            Err(e) if e.kind() != io::ErrorKind::NotFound => {
                util.com_err(
                    &format!("Can not fetch master key (error: {}).", strerror(&e)),
                    "while reading master key",
                );
                return None;
            }
            Err(_) => {}
        }
        #[cfg(feature = "test-hooks")]
        let hooked = hooks::master_password();
        #[cfg(not(feature = "test-hooks"))]
        let hooked: Option<Zeroizing<String>> = None;
        let Some(pw) = hooked else {
            util.com_err(
                "Can not fetch master key (error: No such file or directory).",
                "while reading master key",
            );
            return None;
        };
        (derive(pw.as_bytes()), true)
    };
    let Some(key) = key else {
        util.com_err(
            "Bad encryption type",
            "while transforming master key from password",
        );
        return None;
    };
    if !opens(&key) {
        util.com_err(BAD_MASTER_KEY, "while getting master key list");
        return None;
    }
    Some((key, from_hook))
}

// MIT: `kdb5_destroy` (kadmin/dbutil/kdb5_destroy.c:41-92)
fn destroy(util: &mut Util, args: &[String]) -> u8 {
    let opts = match sub_options(args, "f") {
        Ok(o) => o,
        Err(code) => return code,
    };
    let db = util.db().to_path_buf();
    if !opts.iter().any(|o| o.flag == 'f') {
        let mut out = io::stdout();
        let _ = write!(
            out,
            "Deleting KDC database stored in '{}', are you sure?\n(type 'yes' to confirm)? ",
            db.display()
        );
        let _ = out.flush();
        let mut line = Vec::new();
        let read = io::stdin().lock().read_until(b'\n', &mut line);
        if !matches!(read, Ok(n) if n > 0) || line != b"yes\n" {
            return util.failed();
        }
        out_line(&format!("OK, deleting database '{}'...", db.display()));
    }
    if let Err(e) = destroy_database(&util.db_args.open_file()) {
        util.com_err(
            &strerror(&e),
            &format!("deleting database '{}'", db.display()),
        );
        return util.failed();
    }
    if util.iprop.enabled {
        util.ulog = None;
        let _ = fs::remove_file(&util.iprop.logfile);
    }
    out_line(&format!("** Database '{}' destroyed.", db.display()));
    util.exit_status
}

// MIT: `krb5_db2_destroy` (plugins/kdb/db2/kdb_db2.c:1227-1271)
// MIT: `klmdb_destroy` (plugins/kdb/lmdb/kdb_lmdb.c:683-709)
fn destroy_database(file: &Path) -> io::Result<()> {
    let lockout = krb5_kdc::lockout_path(file);
    for zeroed in [file, lockout.as_path()] {
        if fs::symlink_metadata(zeroed).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(link_refused(zeroed));
        }
    }
    destroy_file(file)?;
    for suffix in [".ok", ".kadm5", ".kadm5.lock"] {
        match fs::remove_file(with_suffix(file, suffix)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    match destroy_file(&krb5_kdc::lockout_path(file)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    Ok(())
}

fn link_refused(path: &Path) -> io::Error {
    let e = io::Error::from_raw_os_error(nix::libc::ELOOP);
    io::Error::new(e.kind(), format!("{}: {}", path.display(), strerror(&e)))
}

/// `O_NOFOLLOW`: a symlink is not zeroed; MIT zeroes the link's target.
// MIT: `destroy_file` (plugins/kdb/db2/kdb_db2.c:619-682)
fn destroy_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    const BUFSIZ: usize = 8192;
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(nix::libc::ELOOP) {
                link_refused(path)
            } else {
                e
            }
        })?;
    let mut buf = [0u8; BUFSIZ];
    loop {
        let pos = f.stream_position()?;
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if buf[..n].iter().any(|&b| b != 0) {
            f.seek(SeekFrom::Start(pos))?;
            f.write_all(&[0u8; BUFSIZ][..n])?;
        }
    }
    buf.zeroize();
    f.sync_all()?;
    drop(f);
    fs::remove_file(path)
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(feature = "test-hooks")]
mod hooks {
    use krb5_kdc::testrealm::TEST_USER;
    use krb5_kdc::{IpropRole, NamedPolicy, PrincipalStore, load_store};
    use krb5_types::PrincipalName;
    use zeroize::Zeroizing;

    use super::{Util, err_line, out_line, usage};

    /// `KRB5_MASTER_PASSWORD` stands in for `-P` only in a test-hooks build.
    pub(super) fn master_password() -> Option<Zeroizing<String>> {
        std::env::var("KRB5_MASTER_PASSWORD")
            .ok()
            .map(Zeroizing::new)
    }

    pub(super) fn seed(store: &mut PrincipalStore) -> Result<(), krb5_kdc::Error> {
        match (
            std::env::var("KRB5_TEST_USER_PASSWORD"),
            std::env::var("KRB5_TEST_ADMIN_PASSWORD"),
        ) {
            (Ok(user), Ok(admin)) => {
                krb5_kdc::seed_test_principals(store, user.as_bytes(), admin.as_bytes())
            }
            _ => Ok(()),
        }
    }

    pub(super) fn command(util: &Util, args: &[String]) -> u8 {
        let result = match (args.first().map(String::as_str), args.len()) {
            (Some("addpol"), 2) => addpol(util, &args[1]),
            (Some("setstr"), 4) => setstr(util, &args[1], &args[2], &args[3]),
            (Some("alias"), 3) => alias(util, &args[1], &args[2]),
            (Some("setlastpwd"), 3) => setlastpwd(util, &args[1], &args[2]),
            _ => return usage(),
        };
        match result {
            Ok(line) => {
                out_line(&line);
                0
            }
            Err((code, why)) => {
                err_line(&format!("{}: {why}", util.progname));
                code
            }
        }
    }

    type Hook = Result<String, (u8, String)>;

    fn with_store(
        util: &Util,
        f: impl FnOnce(&mut krb5_kdc::PrincipalStore) -> Result<(), (u8, String)>,
    ) -> Result<(), (u8, String)> {
        let (db, stash) = (util.db_args.open_file(), &util.paths.key_stash_file);
        let mut store = load_store(&db, stash).map_err(|e| (1, format!("load store: {e}")))?;
        if util.iprop.enabled {
            store
                .map_ulog(&util.iprop.logfile, util.iprop.ulogsize, IpropRole::Primary)
                .map_err(|e| (1, format!("{e} while mapping update log")))?;
        }
        store
            .change(f)
            .map_err(|e| (1, format!("save store: {e}")))?
    }

    fn addpol(util: &Util, name: &str) -> Hook {
        if name.is_empty() {
            return Err((2, "empty policy name".into()));
        }
        with_store(util, |store| {
            store
                .put_policy(NamedPolicy {
                    name: name.to_owned(),
                    min_length: 8,
                    min_classes: 2,
                    history: 1,
                    max_fail: 1,
                    pw_failcnt_interval: 0,
                    pw_lockout_duration: 0,
                    pw_min_life: 0,
                    pw_max_life: 0,
                    allowed_keysalts: None,
                })
                .map_err(|e| (1, format!("put policy: {e}")))?;
            let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
            if store.get_name(&user).is_some() {
                store
                    .set_principal_policy(&user, Some(name.to_owned()))
                    .map_err(|e| (1, format!("bind policy: {e}")))?;
            }
            Ok(())
        })?;
        Ok(format!("ok addpol name={name}"))
    }

    fn setstr(util: &Util, princ: &str, key: &str, value: &str) -> Hook {
        if key.is_empty() {
            return Err((2, "empty setstr key".into()));
        }
        let (name, _) =
            krb5_types::principal_from_unparsed(princ, "").map_err(|e| (2, e.to_string()))?;
        with_store(util, |store| {
            store
                .set_string(&name, key, Some(value))
                .map_err(|e| (1, format!("setstr: {e}")))
        })?;
        Ok(format!("ok setstr {princ} {key}"))
    }

    fn alias(util: &Util, alias: &str, target: &str) -> Hook {
        with_store(util, |store| {
            let realm = store.realm().to_owned();
            let parse = |s: &str| {
                krb5_types::principal_from_unparsed(s, &realm).map_err(|e| (2, e.to_string()))
            };
            let (a, a_realm) = parse(alias)?;
            let (t, t_realm) = parse(target)?;
            store
                .create_alias_in(&a, &a_realm, &t, &t_realm, &format!("kadmin/admin@{realm}"))
                .map_err(|e| (1, format!("alias: {e}")))
        })?;
        Ok(format!("ok alias {alias} {target}"))
    }

    fn setlastpwd(util: &Util, princ: &str, secs: &str) -> Hook {
        let ts: u32 = secs
            .parse()
            .map_err(|_| (2, "setlastpwd wants unix seconds".to_owned()))?;
        let (name, _) =
            krb5_types::principal_from_unparsed(princ, "").map_err(|e| (2, e.to_string()))?;
        with_store(util, |store| {
            store
                .set_last_pwd_unix(&name, ts)
                .map_err(|e| (1, format!("setlastpwd: {e}")))
        })?;
        Ok(format!("ok setlastpwd {princ} {ts}"))
    }
}
