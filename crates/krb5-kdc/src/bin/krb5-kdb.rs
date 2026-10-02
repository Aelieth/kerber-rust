//! MIT `kdb5_util`: create, stash, dump, load and destroy the KDC database.
//!
//! `kdb5_util [-r realm] [-d dbname] [-k mkeytype] [-kv mkeyVNO] [-M mkeyname] [-m]
//! [-sf stashfilename] [-P password] [-x db_args]* cmd [cmd_options]`, the global options
//! anywhere on the line as MIT's `main` (`kadmin/dbutil/kdb5_util.c`) takes them. The realm is
//! `-r`, else krb5.conf's `default_realm`; the database, stash and master key type are kdc.conf's
//! for that realm ([`krb5_config::KdcPaths`]), `-d` / `-sf` / `-k` name others. Messages, prompts
//! and exit statuses are MIT's.
//!
//! - `create [-s] [-W]`: `K/M`, `krbtgt`, `kadmin/admin` and `kadmin/changepw`
//!   ([`krb5_kdc::create_realm`]); the master password is `-P`, else asked twice on the
//!   terminal (one line each from a pipe). `-s` keeps the stash; without it no stash is left.
//! - `stash [-f keyfile]`: a new stash file from the stashed (or typed) master key.
//! - `dump [-r18] [-verbose] [-rev] [-recurse] [filename [principals...]]`: the database as
//!   stored, keys still wrapped; principals are whole-name regular expressions.
//! - `load [-r18] [-hash] [-verbose] [-update] filename`: a full load replaces the database
//!   with a new file; `-update` merges the records into it. The dump's keys are opened with
//!   `-P`, else (`-m`) a typed master password, else the stash.
//! - `destroy [-f]`.
//!
//! Of db2's `-x` arguments, `dbname=` and `temporary` name the database file, and `hash=`,
//! `merge_nra`, `lockiter` and `unlockiter` change nothing this store keeps. MIT's other
//! commands, `-b7` / `-r13` / iprop dumps, master key conversion, `-M` other than `K/M` and `-kv`
//! outside `create` are refused.
//!
//! With the `test-hooks` feature the gates' commands `addpol`, `setstr`, `alias` and
//! `setlastpwd` are added, `KRB5_MASTER_PASSWORD` stands in for `-P` on `create` and for a
//! missing stash on `load` (which then writes it), and `create` seeds `user@`, `admin@` and the
//! test hosts when `KRB5_TEST_USER_PASSWORD` and `KRB5_TEST_ADMIN_PASSWORD` are set.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::io::{self, BufRead as _, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use krb5_cli::{MitArgs, MitOpt, Placement, Prompter, getopt};
use krb5_config::KdcPaths;
use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_kdc::{
    CreateError, DbLock, DbLockMode, DumpError, DumpFile, DumpPrincipal, KDB_DUMP_VERSION,
    LoadError, PersistError, create_realm, create_store, kdc_conf_for_realm, load_dump_with_key,
    master_key_from_password, parse_dump, save_dump_text_locked, save_store_locked, stash_keys,
    string_to_enctype, update_store, write_stash,
};
use zeroize::{Zeroize as _, Zeroizing};

/// MIT `usage` (`kadmin/dbutil/kdb5_util.c:77-107`): the text, on stderr, then exit status 1.
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

/// MIT `main` (`kadmin/dbutil/kdb5_util.c:228-296`): the global options, taken wherever they stand.
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

/// MIT `KRB5_KDC_MKEY_1` (`include/kdb.h:312-312`): the master password prompt.
const MKEY_PROMPT: &str = "Enter KDC database master key";
/// MIT `KRB5_KDC_MKEY_2` (`include/kdb.h:313-313`): the prompt that verifies it.
const MKEY_VERIFY: &str = "Re-enter KDC database master key to verify";
/// MIT `krb5_def_fetch_mkey_list` (`lib/kdb/kdb_default.c:455-458`): the message for a master key that opens no `K/M` key.
const BAD_MASTER_KEY: &str = "Unable to decrypt latest master key with the provided master key\n";

/// The commands, MIT's and (with test hooks) the gates' own.
/// MIT `main` (`kadmin/dbutil/kdb5_util.c:298-302`): a missing command, or one `cmd_table` does not name, is the usage.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Command {
    Create,
    Destroy,
    Stash,
    Dump,
    Load,
    /// An MIT command this port does not implement.
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

/// What every command shares: MIT's globals after `main` has read them.
struct Util {
    progname: String,
    realm: Option<String>,
    /// The realm's paths; `database_name` is MIT's `global_params.dbname` (`-d`, else kdc.conf),
    /// the name the messages give.
    paths: KdcPaths,
    db_args: DbArgs,
    /// The master key type; `None` when kdc.conf's `master_key_type` names no enctype.
    etype: Option<EncryptionType>,
    /// `-P`, wiped when dropped.
    password: Option<Zeroizing<String>>,
    manual: bool,
    kvno: Option<u32>,
    exit_status: u8,
}

/// db2's database arguments: every `-x`, and the `dbname=` each `-d` adds, in command-line order.
/// MIT `main` (`kadmin/dbutil/kdb5_util.c:233-249`): `-d` names the database and adds `dbname=` to the arguments.
struct DbArgs {
    /// The last `dbname=`: the database file db2 opens, else kdc.conf's.
    file: PathBuf,
    /// `temporary`: db2 opens the temporary database beside it, `<file>~`.
    temporary: bool,
    /// The first argument db2 does not take, by the name MIT gives it.
    unsupported: Option<String>,
}

impl DbArgs {
    /// MIT `configure_context` (`plugins/kdb/db2/kdb_db2.c:221-246`): `dbname=` and `temporary` name the file; `hash=`, `merge_nra`, `lockiter` and `unlockiter` set what db2 alone keeps; any other is refused by its option name.
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

    /// The file db2 opens: the temporary one when `temporary` was given.
    /// MIT `ctx_dbsuffix` (`plugins/kdb/db2/kdb_db2.c:292-303`): a temporary database's files carry a `~`.
    fn open_file(&self) -> PathBuf {
        if self.temporary {
            with_suffix(&self.file, "~")
        } else {
            self.file.clone()
        }
    }
}

impl Util {
    /// MIT `extended_com_err_fn` (`kadmin/dbutil/kdb5_util.c:165-179`): `progname: message context`.
    fn com_err(&self, message: &str, context: &str) {
        err_line(&format!("{}: {message} {context}", self.progname));
    }

    /// The same with no error code: `progname: context`.
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

/// The OS error text as C `strerror` gives it, without Rust's `(os error N)`.
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

/// Why a stash could not be written.
/// MIT `krb5_def_store_mkey_list` (`lib/kdb/kdb_default.c:143-147`): the keytab is written to `<keyfile>_tmp`, so a missing directory is that file not found.
fn stash_write_text(path: &Path, e: &PersistError) -> String {
    match e {
        PersistError::Io(io) if io.kind() == io::ErrorKind::NotFound => {
            format!("Key table file '{}_tmp' not found", path.display())
        }
        other => persist_text(other),
    }
}

/// C `atoi`: leading blanks, a sign, then digits up to the first other character.
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

/// `-P`'s password, taken before the option table reads the line: it is held so that it is
/// wiped when dropped, and the table is handed the line with an empty value in its place, so
/// no other copy of it is made. The scan is the table's own: an option the table names takes
/// the next argument as its value, wherever it stands. With several `-P`, the last one counts
/// and the others are wiped.
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
    let (password, args) = take_password(args);
    let Ok(parsed) = MitArgs::parse(&args, GLOBALS, Placement::Anywhere) else {
        return usage();
    };
    // MIT `main` (`kadmin/dbutil/kdb5_util.c:267-281`): `-k` and `-kv` are checked as they are read.
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
    // MIT `main` (`kadmin/dbutil/kdb5_util.c:304-322`): the realm, then the realm's parameters.
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
    if kvno.is_some_and(|k| k != 1) && command != Command::Create {
        return usage();
    }
    // MIT `kadm5_get_config_params` (`lib/kadm5/alt_prof.c:546-551`): a `master_key_type` that names no enctype leaves the type 0.
    // MIT `main` (`kadmin/dbutil/kdb5_util.c:330-335`): a type other than `ENCTYPE_UNKNOWN` that is no valid enctype is reported, so 0 is, and stays the type.
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

/// glibc `getopt` over a command's own arguments; a bad option is reported under the command's
/// name, then MIT's usage.
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

/// MIT `kdb5_create` (`kadmin/dbutil/kdb5_create.c:142-336`): a new database for the realm.
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
    let store = create_realm(&realm, kdc.as_ref(), &master, mkvno);
    #[cfg(feature = "test-hooks")]
    let store = store.and_then(|mut s| {
        hooks::seed(&mut s)?;
        Ok(s)
    });
    let store = match store {
        Ok(s) => s,
        Err(e) => {
            util.com_err(&e.to_string(), "while adding entries to the database");
            return util.failed();
        }
    };
    // MIT `ctx_create_db` (`plugins/kdb/db2/kdb_db2.c:710-716`): a temporary database's leftover files are destroyed before it is created.
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
    if do_stash {
        if let Err(e) = write_stash(&stash, &realm, &master, u32::from(mkvno)) {
            util.com_err(&stash_write_text(&stash, &e), "while storing key");
            out_line("Warning: couldn't stash master key.");
            return util.failed();
        }
    } else {
        // MIT `kdb5_create` (`kadmin/dbutil/kdb5_create.c:299-333`): the stash is always written for `kadm5_create`, then removed unless `-s`.
        let _ = fs::remove_file(&stash);
    }
    util.exit_status
}

/// The master key from a password, of the configured type; `None` when that type is unset
/// because kdc.conf named no enctype, or the key cannot be made.
fn derive_master(util: &Util, realm: &str, password: &[u8]) -> Option<ProtocolKey> {
    util.etype
        .and_then(|etype| master_key_from_password(realm, password, etype).ok())
}

/// kdc.conf's settings for `realm` alone; `None` when there is no KDC profile.
fn realm_kdc_conf(util: &Util, realm: &str) -> Result<Option<krb5_config::KdcConf>, String> {
    if util.paths.conf.is_none() {
        return Ok(None);
    }
    let text = fs::read_to_string(&util.paths.profile).map_err(|e| strerror(&e))?;
    kdc_conf_for_realm(&text, realm)
        .map(Some)
        .map_err(|e| e.to_string())
}

/// The opened database: its realm, the master entry, and the master key when one was fetched and
/// opens that entry. A dump reads the records again under the lock.
struct OpenDb {
    realm: String,
    km: DumpPrincipal,
    mkey: Option<ProtocolKey>,
}

/// MIT `open_db_and_mkey` (`kadmin/dbutil/kdb5_util.c:369-485`): open the database and find its
/// master entry, then fetch the master key from `-P`, the keyboard (`-m`) or the stash and check
/// it against that entry. A key that cannot be fetched or does not match is a warning: the
/// command still runs, without it, and the exit status is raised.
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
        Ok(t) => t,
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
    Ok(OpenDb { realm, km, mkey })
}

/// The database file as dump text, read holding the database's lock shared; a legacy ciphertext
/// database is opened with the stash and written out as dump text. The error is the whole text.
/// MIT `krb5_db2_open` (`plugins/kdb/db2/kdb_db2.c:1194-1198`): a database that does not open is named; then a missing lock file is the system's or the policy lock's own text.
fn read_db_text(util: &Util, db: &Path) -> Result<String, String> {
    let cannot_open = |why: &str| format!("Cannot open DB2 database '{}': {why}", db.display());
    fs::File::open(db).map_err(|e| cannot_open(&strerror(&e)))?;
    let bytes = krb5_kdc::read_db_locked(db).map_err(|e| match e {
        PersistError::Lock(lock) => lock.to_string(),
        other => cannot_open(&persist_text(&other)),
    })?;
    if bytes.starts_with(b"kdb5_util load_dump version ") {
        return String::from_utf8(bytes).map_err(|_| cannot_open("dump is not UTF-8"));
    }
    let stash = &util.paths.key_stash_file;
    let store = krb5_kdc::load_store(db, stash).map_err(|e| cannot_open(&persist_text(&e)))?;
    let mkey = krb5_kdc::read_stash(stash, db).map_err(|e| cannot_open(&persist_text(&e)))?;
    krb5_kdc::dump_store_with_key(&store, &mkey).map_err(|e| cannot_open(&e.to_string()))
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

/// The stash's master key: the one that opens `km` when the stash holds several candidates
/// (a legacy raw stash), else the first.
fn read_stash_key(path: &Path, km: &DumpPrincipal) -> Result<ProtocolKey, String> {
    let bytes = fs::read(path).map_err(|e| strerror(&e))?;
    let keys = stash_keys(&bytes);
    let pick = keys.iter().position(|k| km.opens_with(k)).unwrap_or(0);
    keys.into_iter()
        .nth(pick)
        .ok_or_else(|| "Stored master key is corrupted".to_owned())
}

/// MIT `kdb5_stash` (`kadmin/dbutil/kdb5_stash.c:65-137`): write the master key to the stash
/// file (or `-f keyfile`), typing it when the database's could not be fetched.
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

/// MIT `dump_db` (`kadmin/dbutil/dump.c:1137-1361`): write the database's records, as stored,
/// to a new file (with its `.dump_ok` mark) or to standard output.
fn dump(util: &mut Util, args: &[String]) -> u8 {
    let mut version = KDB_DUMP_VERSION;
    let (mut verbose, mut rev, mut conditional) = (false, false, false);
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
            s if s.starts_with("-i") => return usage(),
            _ => break,
        }
        i += 1;
    }
    let ofile = args.get(i);
    let names = args.get(i + 1..).unwrap_or_default();
    if ofile.is_some() && conditional {
        util.com_err0("Conditional dump is an undocumented option for use only for iprop dumps");
        return util.failed();
    }
    let to_file = ofile.filter(|f| f.as_str() != "-");
    if to_file.is_some_and(|f| f.starts_with('-')) {
        return usage();
    }
    // MIT `dump_db` (`kadmin/dbutil/dump.c:1334-1347`): the records are read holding the database's lock shared, taken once the master key is in hand, so no writer waits on a typed key.
    let current = match read_db_text(util, &util.db_args.open_file())
        .and_then(|text| parse_dump(&text).map_err(|e| e.to_string()))
    {
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
    // MIT `ctx_iterate` (`plugins/kdb/db2/kdb_db2.c:1109-1137`): the db2 cursor walks the btree in key order, the unparsed names' bytes; `-rev` walks it back.
    princs.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    if rev {
        princs.reverse();
    }
    let mut text = format!("kdb5_util load_dump version {version}\n");
    for p in &princs {
        text.push_str(&p.record());
        text.push('\n');
    }
    // MIT `dump_db` (`kadmin/dbutil/dump.c:1340-1347`): no policies when principals were named.
    if names.is_empty() {
        for pol in &current.policies {
            text.push_str(&DumpFile::policy_record(pol, version));
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

/// The dump to a named file.
/// MIT `prep_ok_file` (`kadmin/dbutil/dump.c:171-208`): the `.dump_ok` mark is opened first, mode 0600.
/// MIT `create_ofile` (`kadmin/dbutil/dump.c:133-155`): the dump is written to a new temporary file.
/// MIT `finish_ofile` (`kadmin/dbutil/dump.c:159-167`): the temporary file is renamed into place.
/// MIT `update_ok_file` (`kadmin/dbutil/dump.c:214-219`): then the mark gets its one byte.
fn write_dump_file(util: &mut Util, path: &Path, text: &str) -> Result<(), u8> {
    let mut ok_name = path.as_os_str().to_os_string();
    ok_name.push(".dump_ok");
    let ok_path = PathBuf::from(ok_name);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let ok = match opts.open(&ok_path) {
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

/// MIT `name_matches` (`kadmin/dbutil/dump.c:221-257`): a principal is dumped when no names were
/// given or one of them, as an extended regular expression, matches the whole name.
fn name_matches(util: &Util, name: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }
    for pat in patterns {
        match regex_automata::meta::Regex::new(&format!("^(?:{pat})$")) {
            Ok(re) => {
                if re.is_match(name) {
                    return true;
                }
            }
            Err(e) => {
                let why = e.to_string();
                let first = why.lines().next().unwrap_or_default();
                util.com_err0(&format!("regular expression error: {first}"));
                return false;
            }
        }
    }
    false
}

/// The name of the dump format that failed to load.
/// MIT `r1_8_version` (`kadmin/dbutil/dump.c:1026-1035`): version 6 is `Kerberos version 5 release 1.8`.
/// MIT `r1_11_version` (`kadmin/dbutil/dump.c:1036-1045`): version 7 is `Kerberos version 5 release 1.11`.
fn version_name(version: u32) -> &'static str {
    if version == KDB_DUMP_VERSION {
        "Kerberos version 5 release 1.11"
    } else {
        "Kerberos version 5 release 1.8"
    }
}

/// MIT `load_db` (`kadmin/dbutil/dump.c:1382-1610`): load a dump file into a new database that
/// replaces the live one, or (`-update`) into the live one.
///
/// MIT copies the records with their keys still wrapped; this port opens them, so it needs the
/// master key that opens the dump: `-P`'s, else (`-m`) a typed one, else the stash's. A dump
/// with no principal record has no key to open.
fn load(util: &mut Util, args: &[String]) -> u8 {
    let mut want: Option<u32> = None;
    let (mut verbose, mut update) = (false, false);
    let mut i = 1;
    while let Some(a) = args.get(i) {
        match a.as_str() {
            "-b7" | "-r13" | "-i" => return usage(),
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
    let Some(version) = dump_version(util, &bytes, want, file) else {
        return 1;
    };
    // MIT `load_db` (`kadmin/dbutil/dump.c:1492-1516`): the database is created (or opened with `-update`) with the `-x` arguments before any record is read.
    if let Some(arg) = &util.db_args.unsupported {
        let context = if update {
            "while opening database"
        } else {
            "while creating database"
        };
        util.com_err(&format!("Unsupported argument \"{arg}\" for db2"), context);
        return 1;
    }
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
        return load_policies_only(util, &dump, update, verbose);
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
    if update {
        let db = util.db_args.open_file();
        let first = dump.princs.first().map_or("", |p| p.name.as_str());
        let Some(lock) = update_lock(util, &db) else {
            return 1;
        };
        let current = fs::read_to_string(&db).map_err(|e| {
            format!(
                "Cannot open DB2 database '{}': {}",
                db.display(),
                strerror(&e)
            )
        });
        let mut store =
            match current.and_then(|t| load_dump_with_key(&t, &key).map_err(|e| e.to_string())) {
                Ok(s) => s,
                Err(why) => {
                    util.com_err(&why, "while opening database");
                    return 1;
                }
            };
        update_store(&mut store, &loaded);
        if let Err(e) = save_store_locked(&store, &db, &key, &lock) {
            util.com_err(&persist_text(&e), &format!("while storing {first}"));
            return 1;
        }
        if !update_unlock(util, &lock) {
            return 1;
        }
    } else if let Err(e) = krb5_kdc::load_store_full(&loaded, &util.db_args.file, &key) {
        load_failed(util, &e);
        return 1;
    }
    if from_hook {
        let kvno = dump
            .princ(&format!("K/M@{}", loaded.realm()))
            .and_then(|km| km.keys.first())
            .map_or(1, |k| k.kvno);
        let stash = util.paths.key_stash_file.clone();
        if let Err(e) = write_stash(&stash, loaded.realm(), &key, kvno) {
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

/// A dump with no principal record: a full load leaves a database that holds only the dump's
/// policies (none for a header alone), and `-update` creates or replaces each of them in the
/// live database. No key is opened, so no master key is fetched.
/// MIT `restore_dump` (`kadmin/dbutil/dump.c:1364-1379`): the records are read to the end of the file, however few.
fn load_policies_only(util: &mut Util, dump: &DumpFile, update: bool, verbose: bool) -> u8 {
    let records = dump.policy_records();
    if update {
        let db = util.db_args.open_file();
        let Some(lock) = update_lock(util, &db) else {
            return 1;
        };
        let current = match fs::read(&db).map(String::from_utf8) {
            Ok(Ok(t)) if t.starts_with("kdb5_util load_dump version ") => t,
            _ => {
                util.com_err(
                    &format!(
                        "Cannot open DB2 database '{}': Inappropriate file type or format",
                        db.display()
                    ),
                    "while opening database",
                );
                return 1;
            }
        };
        if !records.is_empty()
            && let Err(e) =
                save_dump_text_locked(&db, &merge_policy_records(&current, &records), &lock)
        {
            util.com_err(&persist_text(&e), "while creating policy");
            return 1;
        }
        if !update_unlock(util, &lock) {
            return 1;
        }
    } else {
        let mut text = format!("kdb5_util load_dump version {KDB_DUMP_VERSION}\n");
        for r in &records {
            text.push_str(r);
            text.push('\n');
        }
        if let Err(e) = krb5_kdc::load_text_full(&util.db_args.file, &text, "ulog 1\n") {
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

/// The database's permanent lock for `load -update`: the database must open, then its lock
/// files, then `principal.kadm5.lock` is removed until the lock is let go, so no other process
/// opens the database meanwhile, and a load that stops before it ends leaves it unusable.
/// MIT `load_db` (`kadmin/dbutil/dump.c:1509-1527`): the database is opened, then locked permanently; a refused lock is reported.
fn update_lock(util: &Util, db: &Path) -> Option<DbLock> {
    if let Err(e) = fs::File::open(db) {
        util.com_err(
            &format!(
                "Cannot open DB2 database '{}': {}",
                db.display(),
                strerror(&e)
            ),
            "while opening database",
        );
        return None;
    }
    let lock = match DbLock::open(db) {
        Ok(lock) => lock,
        Err(e) => {
            util.com_err(&e.to_string(), "while opening database");
            return None;
        }
    };
    if let Err(e) = lock.lock(DbLockMode::Permanent) {
        util.com_err(&e.to_string(), "while permanently locking database");
        return None;
    }
    Some(lock)
}

/// Let go of `load -update`'s permanent lock: `principal.kadm5.lock` is made again.
/// MIT `load_db` (`kadmin/dbutil/dump.c:1546-1549`): the permanent lock is let go once the records are in.
fn update_unlock(util: &Util, lock: &DbLock) -> bool {
    match lock.unlock() {
        Ok(()) => true,
        Err(e) => {
            util.com_err(&e.to_string(), "while unlocking database");
            false
        }
    }
}

/// A full load that failed: making its temporary database, or making that database live.
/// MIT `load_db` (`kadmin/dbutil/dump.c:1503-1507`): a temporary database that cannot be made is reported while creating the database.
/// MIT `load_db` (`kadmin/dbutil/dump.c:1562-1568`): one that cannot be made live is reported while making the newly loaded database live.
fn load_failed(util: &Util, e: &LoadError) {
    match e {
        LoadError::Create(e) => util.com_err(&persist_text(e), "while creating database"),
        LoadError::Promote(e) => {
            util.com_err(&persist_text(e), "while making newly loaded database live");
        }
    }
}

/// `current` dump text with each of `records` in place of the policy of its name, else added.
/// MIT `process_k5beta7_policy` (`kadmin/dbutil/dump.c:820-822`): a policy is created, else replaced.
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

/// MIT `load_db` (`kadmin/dbutil/dump.c:1447-1475`): the header names the dump's format, or must
/// be the one `-r18` asks for. Only the r1.8 and r1.11 formats load here.
fn dump_version(util: &Util, bytes: &[u8], want: Option<u32>, file: &str) -> Option<u32> {
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

/// A dump that does not load: the record's own message, the line it was on, and the format.
/// MIT `restore_dump` (`kadmin/dbutil/dump.c:1364-1379`): a record that fails is reported with its line number.
/// MIT `load_db` (`kadmin/dbutil/dump.c:1540-1543`): then the format that failed to restore.
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

/// The master key that opens the dump being loaded, and whether it came from the test hook
/// (which also writes the missing stash). `None` after the failure is reported.
/// MIT `open_db_and_mkey` (`kadmin/dbutil/kdb5_util.c:411-452`): a `-P` password, else one typed for `-m`, else the stash.
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
        match fs::read(&util.paths.key_stash_file) {
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

/// MIT `kdb5_destroy` (`kadmin/dbutil/kdb5_destroy.c:41-92`): delete the database, after a
/// typed `yes` unless `-f`.
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
    out_line(&format!("** Database '{}' destroyed.", db.display()));
    util.exit_status
}

/// Remove the database: the file itself zeroed and unlinked, then the lock and policy files
/// db2 keeps beside it should any be there (this store keeps neither), then the update log,
/// which this store always keeps and MIT's only with iprop.
/// MIT `krb5_db2_destroy` (`plugins/kdb/db2/kdb_db2.c:1227-1271`): `destroy_file` on the database, then the lock file and the policy database and its lock are unlinked.
/// MIT `kdb5_destroy` (`kadmin/dbutil/kdb5_destroy.c:85-87`): the update log is unlinked, its error ignored.
fn destroy_database(file: &Path) -> io::Result<()> {
    destroy_file(file)?;
    for suffix in [".ok", ".kadm5", ".kadm5.lock"] {
        match fs::remove_file(with_suffix(file, suffix)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    let _ = fs::remove_file(with_suffix(file, ".ulog"));
    Ok(())
}

/// Zero `path` and unlink it: each block that is not all zeros already is overwritten with
/// zeros, and the file is synced before it is removed.
/// MIT `destroy_file` (`plugins/kdb/db2/kdb_db2.c:619-682`): `BUFSIZ` blocks are read, those with a nonzero byte written over with zeros, then `fsync` and `unlink`.
fn destroy_file(path: &Path) -> io::Result<()> {
    const BUFSIZ: usize = 8192;
    let mut f = fs::OpenOptions::new().read(true).write(true).open(path)?;
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

/// `path` with `suffix` appended to its last component.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// The gates' own commands and environment, outside MIT's `kdb5_util`.
#[cfg(feature = "test-hooks")]
mod hooks {
    use krb5_kdc::testrealm::TEST_USER;
    use krb5_kdc::{NamedPolicy, PrincipalStore, load_store};
    use krb5_types::PrincipalName;
    use zeroize::Zeroizing;

    use super::{Util, err_line, out_line, usage};

    /// `KRB5_MASTER_PASSWORD`: the master password `create` takes instead of a `-P` or the
    /// prompts, and `load` takes when there is no stash.
    pub(super) fn master_password() -> Option<Zeroizing<String>> {
        std::env::var("KRB5_MASTER_PASSWORD")
            .ok()
            .map(Zeroizing::new)
    }

    /// The gates' principals beside a new realm, when `KRB5_TEST_USER_PASSWORD` and
    /// `KRB5_TEST_ADMIN_PASSWORD` are set.
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
        store
            .change(f)
            .map_err(|e| (1, format!("save store: {e}")))?
    }

    /// A named policy, bound to `user` when that principal exists.
    fn addpol(util: &Util, name: &str) -> Hook {
        if name.is_empty() {
            return Err((2, "empty policy name".into()));
        }
        with_store(util, |store| {
            store.put_policy(NamedPolicy {
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
            });
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

    /// A string attribute (`KRB5_TL_STRING_ATTRS`).
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

    /// An alias stub naming `target`.
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

    /// Backdate `KRB5_TL_LAST_PWD_CHANGE`.
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
