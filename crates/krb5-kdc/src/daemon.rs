//! What `krb5kdc` and `kadmind` share as daemons (`kdc/main.c`, `kadmin/server/ovsec_kadmd.c`,
//! `lib/apputils/net-server.c`): leaving the terminal, the pid file, and the signals.

use std::fs::File;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use krb5_log::klog::{self, Severity, os_error_text};

use crate::{PrincipalStore, open_store};

/// Why a daemon could not open its realm's database.
#[derive(Debug, PartialEq, Eq)]
pub enum OpenFailure {
    /// The database or a database argument; MIT reports it while initializing the database.
    Database(String),
    /// The master key; MIT reports it while fetching the master key.
    MasterKey(String),
}

/// The database file the `-d` / `-x` arguments name, else `default`.
/// MIT `configure_context` (`plugins/kdb/db2/kdb_db2.c:226-276`): `dbname=` names the file,
/// `temporary` is that name with `~`, `merge_nra` and `hash=` are accepted, and anything else is
/// an unsupported argument.
///
/// # Errors
///
/// MIT's message for the first argument it does not take.
pub fn database_path(default: &Path, db_args: &[String]) -> Result<PathBuf, String> {
    let mut db = default.to_path_buf();
    let mut temporary = false;
    for a in db_args {
        match a.split_once('=') {
            Some(("dbname", v)) => db = PathBuf::from(v),
            Some(("hash", _)) => {}
            None if a == "temporary" => temporary = true,
            None if a == "merge_nra" => {}
            Some((opt, _)) => return Err(format!("Unsupported argument \"{opt}\" for db2")),
            None => return Err(format!("Unsupported argument \"{a}\" for db2")),
        }
    }
    if temporary {
        let mut s = db.into_os_string();
        s.push("~");
        db = PathBuf::from(s);
    }
    Ok(db)
}

/// Open the realm's database as MIT's daemons do: the database arguments, the database file,
/// then the master key from the stash; `mkey_name` is the master key principal (`-M`).
/// MIT `open_db` (`plugins/kdb/db2/kdb_db2.c:386-389`): a database that will not open is named
/// in the error.
/// MIT `krb5_db_def_fetch_mkey` (`lib/kdb/kdb_default.c:384-390`): a stash that cannot be read
/// is "Can not fetch master key (error: …)."
///
/// # Errors
///
/// [`OpenFailure`] with MIT's message.
pub fn open_database(
    paths: &krb5_config::KdcPaths,
    db_args: &[String],
    mkey_name: &str,
) -> Result<PrincipalStore, OpenFailure> {
    let db = database_path(&paths.database_name, db_args).map_err(OpenFailure::Database)?;
    if let Err(e) = File::open(&db) {
        return Err(OpenFailure::Database(format!(
            "Cannot open DB2 database '{}': {}",
            db.display(),
            os_error_text(&e)
        )));
    }
    if mkey_name != "K/M" {
        return Err(OpenFailure::MasterKey(
            "Can not fetch master key (error: Key table entry not found).".into(),
        ));
    }
    if let Err(e) = File::open(&paths.key_stash_file) {
        return Err(OpenFailure::MasterKey(format!(
            "Can not fetch master key (error: {}).",
            os_error_text(&e)
        )));
    }
    let lib = paths.conf.as_ref().and_then(|c| c.db_library.as_deref());
    open_store(lib, &db, &paths.key_stash_file).map_err(|e| OpenFailure::Database(e.to_string()))
}

/// Whether the realm's database or stash is named relative to the current directory, so that a
/// daemon must open it again once [`detach`] has moved it to `/`: the name then means what it
/// means to MIT's daemons, which open the realm after `daemon()`.
/// MIT `main` (`kdc/main.c:1016-1016`): the realms are initialized again after `daemon(0, 0)`.
#[must_use]
pub fn names_relative_database(paths: &krb5_config::KdcPaths, db_args: &[String]) -> bool {
    database_path(&paths.database_name, db_args).is_ok_and(|db| db.is_relative())
        || paths.key_stash_file.is_relative()
}

/// Leave the terminal: fork, the parent exits 0, the child starts a new session in `/` with its
/// standard streams on `/dev/null`. Call it before any thread is started.
/// MIT `main` (`kdc/main.c:996-999`): `daemon(0, 0)` unless `-n`, after the sockets are bound.
///
/// # Errors
///
/// The OS error of `daemon(3)`; the process has not forked.
pub fn detach() -> io::Result<()> {
    nix::unistd::daemon(false, false).map_err(io::Error::from)
}

/// Write the process id and a newline to `path`, replacing what was there.
/// MIT `write_pid_file` (`kdc/main.c:834-847`): `fopen(path, "w")`, `"%ld\n"`, the open, write
/// or close error returned.
///
/// # Errors
///
/// The OS error of creating, writing or closing `path`.
pub fn write_pid_file(path: &Path) -> io::Result<()> {
    let mut f = File::create(path)?;
    writeln!(f, "{}", std::process::id())?;
    f.flush()
}

/// The signals a daemon answers: SIGINT, SIGTERM and SIGQUIT end its loop, SIGHUP reopens its
/// log files, and SIGPIPE stays ignored, as the Rust runtime sets it.
/// MIT `loop_setup_signals` (`lib/apputils/net-server.c:263-286`): the three end the loop, SIGPIPE
/// is ignored and SIGHUP resets, all set up before the network.
#[derive(Clone)]
pub struct Signals {
    stop: Arc<AtomicBool>,
    hup: Arc<AtomicBool>,
}

impl Signals {
    /// Install the handlers, before the sockets are bound; they stay in place across [`detach`].
    /// A handler that cannot be installed leaves that signal's default.
    #[must_use]
    pub fn install() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let hup = Arc::new(AtomicBool::new(false));
        for sig in [
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGQUIT,
        ] {
            let _ = signal_hook::flag::register(sig, Arc::clone(&stop));
        }
        let _ = signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&hup));
        Self { stop, hup }
    }

    /// The flag SIGINT, SIGTERM and SIGQUIT set.
    #[must_use]
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    /// Whether SIGINT, SIGTERM or SIGQUIT arrived.
    #[must_use]
    pub fn stop_requested(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Start the thread that answers each SIGHUP, after [`detach`]: a debug line, then the log
    /// files reopened, so logrotate's `systemctl reload` moves the daemon to a new file.
    /// MIT `do_reset` (`lib/apputils/net-server.c:246-254`): the debug line, `krb5_klog_reopen`,
    /// then the daemon's reset hook.
    /// MIT `reset_for_hangup` (`kdc/kdc_util.c:1915-1922`): the KDC's hook refreshes each realm's
    /// database module configuration; kadmind has none.
    /// MIT `krb5_db_refresh_config` (`lib/kdb/kdb5.c:2714-2723`): a module without
    /// `refresh_config`, as every module MIT ships, does nothing.
    pub fn spawn_log_reopener(&self) {
        let hup = Arc::clone(&self.hup);
        let stop = Arc::clone(&self.stop);
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if hup.swap(false, Ordering::Relaxed) {
                    klog::syslog(Severity::Debug, "Got signal to reset");
                    klog::reopen();
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn a_relative_database_or_stash_is_opened_again_after_detaching() {
        let paths = |db: &str, stash: &str| krb5_config::KdcPaths {
            profile: PathBuf::from("/nonexistent/kdc.conf"),
            conf: None,
            realm: Some("R".into()),
            database_name: PathBuf::from(db),
            key_stash_file: PathBuf::from(stash),
            acl_file: None,
            master_key_type: None,
        };
        let none: &[String] = &[];
        assert!(!names_relative_database(
            &paths("/s/principal", "/s/stash"),
            none
        ));
        assert!(names_relative_database(
            &paths("db/principal", "/s/stash"),
            none
        ));
        assert!(names_relative_database(
            &paths("/s/principal", "db/stash"),
            none
        ));
        let dbname = ["dbname=db/other".to_owned()];
        assert!(names_relative_database(
            &paths("/s/principal", "/s/stash"),
            &dbname
        ));
        let absolute = ["dbname=/s/other".to_owned()];
        assert!(!names_relative_database(
            &paths("db/principal", "/s/stash"),
            &absolute
        ));
    }

    #[test]
    fn sighup_reopens_the_log_and_leaves_the_daemon_running() {
        let dir = krb5_testkit::scratch_dir("krb5-kdc-sighup");
        let log = dir.join("kdc.log");
        let rotated = dir.join("kdc.log.1");
        klog::init("krb5kdc", &[format!("FILE:{}", log.display())], true);
        let signals = Signals::install();
        signals.spawn_log_reopener();
        klog::syslog(Severity::Info, "before the rotation");
        std::fs::rename(&log, &rotated).unwrap();
        signal_hook::low_level::raise(signal_hook::consts::SIGHUP).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !log.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        klog::syslog(Severity::Info, "after the rotation");
        klog::close();
        let old = std::fs::read_to_string(&rotated).unwrap();
        let new = std::fs::read_to_string(&log).unwrap();
        assert!(old.contains("(info): before the rotation\n"), "{old}");
        assert!(old.contains("(debug): Got signal to reset\n"), "{old}");
        assert!(new.contains("(info): after the rotation\n"), "{new}");
        assert!(!signals.stop_requested());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
