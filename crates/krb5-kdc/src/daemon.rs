//! What `krb5kdc` and `kadmind` share as daemons (`kdc/main.c`, `kadmin/server/ovsec_kadmd.c`,
//! `lib/apputils/net-server.c`): leaving the terminal, the pid file, and the signals.

use std::fs::File;
use std::io::{self, Write as _};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use krb5_log::klog::os_error_text;

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

/// Open the realm's database as MIT's daemons do: the database arguments, the database file
/// (one that is no database this store reads is refused, as [`crate::check_openable`] judges
/// it) and its lock files, then the master key from the stash; `mkey_name` is the master key
/// principal (`-M`).
/// MIT `open_db` (`plugins/kdb/db2/kdb_db2.c:386-389`): a database that will not open is named
/// in the error.
/// MIT `krb5_db2_open` (`plugins/kdb/db2/kdb_db2.c:1181-1199`): the lock files open with the database, before any master key is fetched.
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
    match crate::check_openable(&db) {
        Ok(()) => {}
        Err(crate::PersistError::Io(e)) => {
            return Err(OpenFailure::Database(format!(
                "Cannot open DB2 database '{}': {}",
                db.display(),
                os_error_text(&e)
            )));
        }
        Err(e) => return Err(OpenFailure::Database(e.to_string())),
    }
    if let Err(e) = crate::DbLock::open(&db) {
        return Err(OpenFailure::Database(e.to_string()));
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

/// Write the process id and a newline to `path`, replacing what was there, never through a
/// symlink (`O_NOFOLLOW`): MIT's `fopen(path, "w")` empties a link's target.
/// MIT `write_pid_file` (`kdc/main.c:834-847`): `fopen(path, "w")`, `"%ld\n"`, the open, write
/// or close error returned.
///
/// # Errors
///
/// The OS error of creating, writing or closing `path`; `ELOOP` for a symlink there.
pub fn write_pid_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    writeln!(f, "{}", std::process::id())?;
    f.flush()
}

/// The filter of a program's JSON log (`[logging] json`, a stream MIT's programs do not have):
/// `default`, the program's own. A `test-hooks` build (the gates') takes `RUST_LOG` first; a release
/// build reads no such variable, as MIT's `krb5kdc`, `kadmind`, `kprop` and `kpropd` read none.
#[must_use]
pub fn json_log_filter(default: &str) -> tracing_subscriber::EnvFilter {
    #[cfg(feature = "test-hooks")]
    if let Ok(filter) = tracing_subscriber::EnvFilter::try_from_default_env() {
        return filter;
    }
    tracing_subscriber::EnvFilter::new(default)
}

/// The signals a daemon answers: SIGINT, SIGTERM and SIGQUIT end its loop, SIGHUP reopens its
/// log files, and SIGPIPE stays ignored, as the Rust runtime sets it. Each also writes a byte to
/// a pipe the daemon's loop waits on, as verto's signal events wake MIT's loop.
/// MIT `loop_setup_signals` (`lib/apputils/net-server.c:263-286`): the three end the loop, SIGPIPE
/// is ignored and SIGHUP resets, all set up before the network.
#[derive(Clone)]
pub struct Signals {
    stop: Arc<AtomicBool>,
    hup: Arc<AtomicBool>,
    /// The pipe's read end, when the pipe was made and every signal writes to it.
    wake: Option<Arc<OwnedFd>>,
}

impl Signals {
    /// Install the handlers, before the sockets are bound; they stay in place across [`detach`].
    /// A handler that cannot be installed leaves that signal's default; a wake pipe that cannot
    /// be made, or that a signal cannot write to, leaves the loop looking at the flags each
    /// second instead.
    #[must_use]
    pub fn install() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let hup = Arc::new(AtomicBool::new(false));
        let ends = [
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGQUIT,
        ];
        for sig in ends {
            let _ = signal_hook::flag::register(sig, Arc::clone(&stop));
        }
        let _ = signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&hup));
        // Registered after the flags, so a byte on the pipe follows its flag.
        let wake = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC | nix::fcntl::OFlag::O_NONBLOCK)
            .ok()
            .and_then(|(read, write)| {
                let all = ends
                    .into_iter()
                    .chain([signal_hook::consts::SIGHUP])
                    .all(|sig| {
                        write
                            .try_clone()
                            .is_ok_and(|w| signal_hook::low_level::pipe::register(sig, w).is_ok())
                    });
                all.then(|| Arc::new(read))
            });
        Self { stop, hup, wake }
    }

    /// The wake pipe's read end, when there is one.
    pub(crate) fn wake_fd(&self) -> Option<&OwnedFd> {
        self.wake.as_deref()
    }

    /// Whether a SIGHUP came since the last call.
    pub(crate) fn take_hup(&self) -> bool {
        self.hup.swap(false, Ordering::Relaxed)
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_log::klog::{self, Severity};
    use std::time::{Duration, Instant};

    /// The JSON log's filter, printed by a child of this test that runs with `RUST_LOG` set.
    #[test]
    fn json_log_filter_child() {
        if std::env::var_os("KERBER_JSON_FILTER_CHILD").is_some() {
            println!("filter=[{}]", json_log_filter("krb5_kdc=info"));
        }
    }

    /// `RUST_LOG` filters the JSON log only in a `test-hooks` build; a release build keeps the
    /// program's own filter whatever the environment says.
    #[test]
    fn json_log_filter_reads_rust_log_only_in_a_test_hooks_build() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "daemon::tests::json_log_filter_child",
                "--exact",
                "--nocapture",
            ])
            .env("KERBER_JSON_FILTER_CHILD", "1")
            .env("RUST_LOG", "krb5_kdc=trace")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        let want = if cfg!(feature = "test-hooks") {
            "filter=[krb5_kdc=trace]"
        } else {
            "filter=[krb5_kdc=info]"
        };
        assert!(text.contains(want), "{want} not in {text}");
    }

    /// MIT's `fopen(path, "w")` empties a symlink's target; the pid file is never written through
    /// one, which stays, its target as it was.
    #[test]
    fn a_pid_file_is_never_written_through_a_symlink() {
        let dir = krb5_testkit::scratch_dir("krb5-pid-link");
        let (link, victim) = (dir.join("krb5kdc.pid"), dir.join("victim"));
        std::fs::write(&victim, b"keep\n").unwrap();
        let old = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        std::fs::File::options()
            .write(true)
            .open(&victim)
            .unwrap()
            .set_times(
                std::fs::FileTimes::new()
                    .set_modified(old)
                    .set_accessed(old),
            )
            .unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let err = write_pid_file(&link).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(nix::libc::ELOOP), "{err}");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep\n");
        assert_eq!(std::fs::metadata(&victim).unwrap().modified().unwrap(), old);
    }

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

    /// A database file that is no database stops the daemon with MIT's open text (settled live
    /// on MIT 1.22.2), before the stash is looked at; a missing one with the system's text, and
    /// an MIT db2 one with the way over.
    #[test]
    fn a_database_file_that_is_no_database_stops_the_daemon_with_mit_s_text() {
        let dir = krb5_testkit::scratch_dir("daemon-open-db");
        let db = dir.join("principal");
        let paths = krb5_config::KdcPaths {
            profile: dir.join("kdc.conf"),
            conf: None,
            realm: Some("R".into()),
            database_name: db.clone(),
            key_stash_file: dir.join("no-stash"),
            acl_file: None,
            master_key_type: None,
        };
        let open = || open_database(&paths, &[], "K/M").map(|_| ());
        let refused = |why: &str| {
            Err(OpenFailure::Database(format!(
                "Cannot open DB2 database '{}': {why}",
                db.display()
            )))
        };
        assert_eq!(open(), refused("No such file or directory"));
        std::fs::write(&db, "not a database\n").unwrap();
        assert_eq!(open(), refused("Invalid argument"));
        // MIT 1.22.2's btree header (settled live): named with the way over.
        let mut db2 = vec![0x62, 0x31, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x10];
        db2.resize(8192, 0);
        std::fs::write(&db, &db2).unwrap();
        assert_eq!(
            open(),
            refused(
                "This is an MIT db2 database; dump it with the old installation's kdb5_util, \
                 then kdb5_util load here (docs/install.md, Upgrading an MIT realm)"
            )
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The database's lock files open with it, before the stash is looked at, as MIT's daemons
    /// open them (settled live on MIT 1.22.2 with no stash either: `No such file or directory`,
    /// `KADM5 administration database lock file missing`, while initializing the database).
    #[test]
    fn a_database_without_its_lock_files_stops_the_daemon_before_the_stash() {
        let dir = krb5_testkit::scratch_dir("daemon-open-locks");
        let db = dir.join("principal");
        let paths = krb5_config::KdcPaths {
            profile: dir.join("kdc.conf"),
            conf: None,
            realm: Some("R".into()),
            database_name: db.clone(),
            key_stash_file: dir.join("no-stash"),
            acl_file: None,
            master_key_type: None,
        };
        let (store, _) = crate::testrealm::bootstrap_documented().unwrap();
        crate::save_store(&store, &db, &dir.join("stash")).unwrap();
        let open = || open_database(&paths, &[], "K/M").map(|_| ());
        let ok = crate::suffixed(&db, crate::SUFFIX_LOCK);
        std::fs::rename(&ok, dir.join("ok.away")).unwrap();
        assert_eq!(
            open(),
            Err(OpenFailure::Database("No such file or directory".into()))
        );
        std::fs::rename(dir.join("ok.away"), &ok).unwrap();
        std::fs::remove_file(crate::suffixed(&db, crate::SUFFIX_POLICY_LOCK)).unwrap();
        assert_eq!(
            open(),
            Err(OpenFailure::Database(
                "KADM5 administration database lock file missing".into()
            ))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The loop on a daemon's signals: SIGHUP reopens the log and leaves it serving, SIGTERM ends
    /// it with MIT's line.
    #[test]
    fn sighup_reopens_the_log_and_leaves_the_daemon_running() {
        use crate::net_server::{Dispatch, Klog, Log, Reply, Sockets, Wake, run};

        struct NoApp;
        impl Dispatch for NoApp {
            fn dispatch(
                &mut self,
                _local: std::net::SocketAddr,
                _remote: std::net::SocketAddr,
                _request: &[u8],
                _is_tcp: bool,
                _log: &mut dyn Log,
            ) -> Reply {
                Reply::Nothing
            }

            fn make_toolong_error(&mut self) -> Result<Vec<u8>, String> {
                Err(String::new())
            }
        }

        let dir = krb5_testkit::scratch_dir("krb5-kdc-sighup");
        let log = dir.join("kdc.log");
        let rotated = dir.join("kdc.log.1");
        klog::init("krb5kdc", &[format!("FILE:{}", log.display())], true);
        let signals = Signals::install();
        assert!(signals.wake_fd().is_some(), "the wake pipe");
        klog::syslog(Severity::Info, "before the rotation");
        std::fs::rename(&log, &rotated).unwrap();
        std::thread::scope(|s| {
            let served = s.spawn(|| {
                run(
                    &mut NoApp,
                    &Sockets::default(),
                    crate::net_server::MAX_STREAM_DATA_CONNECTIONS,
                    crate::net_server::MAX_REQUEST,
                    &Wake::Signals(&signals),
                    &mut Klog,
                )
            });
            signal_hook::low_level::raise(signal_hook::consts::SIGHUP).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while !log.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(!served.is_finished(), "still serving after SIGHUP");
            klog::syslog(Severity::Info, "after the rotation");
            signal_hook::low_level::raise(signal_hook::consts::SIGTERM).unwrap();
            assert_eq!(served.join().unwrap().unwrap(), Vec::<i32>::new());
        });
        klog::close();
        let old = std::fs::read_to_string(&rotated).unwrap();
        let new = std::fs::read_to_string(&log).unwrap();
        assert!(old.contains("(info): before the rotation\n"), "{old}");
        assert!(old.contains("(debug): Got signal to reset\n"), "{old}");
        assert!(new.contains("(info): after the rotation\n"), "{new}");
        assert!(
            new.contains("(debug): Got signal to request exit\n"),
            "{new}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
