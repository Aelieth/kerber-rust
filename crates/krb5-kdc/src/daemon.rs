//! Daemon setup shared by the KDC and kadmind.

#[cfg(feature = "daemon")]
use std::io::{self, Write as _};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use krb5_log::klog::os_error_text;

use crate::{PrincipalStore, open_store};

#[derive(Debug, PartialEq, Eq)]
pub enum OpenFailure {
    Database(String),
    MasterKey(String),
}

// MIT: `configure_context` (plugins/kdb/db2/kdb_db2.c:226-276)
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

// MIT: `open_db` (plugins/kdb/db2/kdb_db2.c:386-389)
// MIT: `krb5_db2_open` (plugins/kdb/db2/kdb_db2.c:1181-1199)
// MIT: `krb5_db_def_fetch_mkey` (lib/kdb/kdb_default.c:384-390)
pub fn open_database(
    paths: &krb5_config::KdcPaths,
    db_args: &[String],
    mkey_name: &str,
) -> Result<PrincipalStore, OpenFailure> {
    let db = prepare_database(paths, db_args)?;
    refuse_other_mkey(mkey_name)?;
    if let Err(e) = krb5_protocol::read_stash_file(&paths.key_stash_file) {
        return Err(OpenFailure::MasterKey(format!(
            "Can not fetch master key (error: {}).",
            os_error_text(&e)
        )));
    }
    let lib = paths.conf.as_ref().and_then(|c| c.db_library.as_deref());
    open_store(lib, &db, &paths.key_stash_file).map_err(|e| OpenFailure::Database(e.to_string()))
}

fn prepare_database(
    paths: &krb5_config::KdcPaths,
    db_args: &[String],
) -> Result<PathBuf, OpenFailure> {
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
    Ok(db)
}

fn refuse_other_mkey(mkey_name: &str) -> Result<(), OpenFailure> {
    if mkey_name != "K/M" {
        return Err(OpenFailure::MasterKey(
            "Can not fetch master key (error: Key table entry not found).".into(),
        ));
    }
    Ok(())
}

fn open_prepared(db: &Path, key: &krb5_crypto::ProtocolKey) -> Result<PrincipalStore, OpenFailure> {
    match crate::load_store_with_master(db, key) {
        Ok(store) => Ok(store),
        Err(crate::PersistError::Crypto(s)) if s == "integrity check failed" => {
            Err(OpenFailure::MasterKey(BAD_MASTER_KEY.into()))
        }
        Err(crate::PersistError::Crypto(s)) => {
            Err(OpenFailure::MasterKey(format!("persist crypto: {s}")))
        }
        Err(e) => Err(OpenFailure::Database(e.to_string())),
    }
}

// MIT: `krb5_def_fetch_mkey_list` (lib/kdb/kdb_default.c:454-458)
const BAD_MASTER_KEY: &str = "Unable to decrypt latest master key with the provided master key";

// MIT: `init_realm` (kdc/main.c:393-396)
#[must_use]
pub fn mkey_log_context(error: &str, realm: &str, mkey_name: &str) -> String {
    if error == BAD_MASTER_KEY {
        format!("while fetching master keys list for realm {realm}")
    } else {
        format!("while fetching master key {mkey_name} for realm {realm}")
    }
}

#[must_use]
pub fn manual_master_key(manual: bool, paths: &krb5_config::KdcPaths) -> bool {
    if !manual {
        return false;
    }
    #[cfg(feature = "test-hooks")]
    #[allow(clippy::disallowed_methods, reason = "a test-hooks build's override")]
    if std::env::var_os("KRB5_KDC_STASH").is_some() {
        return false;
    }
    paths
        .conf
        .as_ref()
        .is_none_or(|c| c.key_stash_file.is_none())
}

// MIT: `main` (kadmin/server/ovsec_kadmd.c:386-388)
#[must_use]
/// kadmind -m prompts even with a stash.
pub fn kadmind_mkey_from_kbd(manual: bool) -> bool {
    if !manual {
        return false;
    }
    #[cfg(feature = "test-hooks")]
    if std::env::var_os("KRB5_KDC_STASH").is_some() {
        return false;
    }
    true
}

#[must_use]
pub fn copy_persist_master(store: &PrincipalStore) -> Option<krb5_crypto::ProtocolKey> {
    store.persist_master.as_ref().map(|(_, key)| key.clone())
}

pub fn open_database_with_password(
    paths: &krb5_config::KdcPaths,
    db_args: &[String],
    mkey_name: &str,
    realm: &str,
) -> Result<PrincipalStore, OpenFailure> {
    let db = prepare_database(paths, db_args)?;
    refuse_other_mkey(mkey_name)?;
    let password = krb5_cli::prompt_hidden("Enter KDC database master key")
        .map_err(|e| OpenFailure::MasterKey(e.to_string()))?;
    let etype =
        crate::master_etype(paths.master_key_type.as_deref()).map_err(OpenFailure::MasterKey)?;
    let key = crate::master_key_from_password(realm, password.as_slice(), etype)
        .map_err(|e| OpenFailure::MasterKey(e.to_string()))?;
    open_prepared(&db, &key)
}

pub fn open_database_with_key(
    paths: &krb5_config::KdcPaths,
    db_args: &[String],
    mkey_name: &str,
    key: &krb5_crypto::ProtocolKey,
) -> Result<PrincipalStore, OpenFailure> {
    let db = prepare_database(paths, db_args)?;
    refuse_other_mkey(mkey_name)?;
    open_prepared(&db, key)
}

// MIT: `main` (kdc/main.c:1016-1016)
#[must_use]
/// A relative name is opened again after detach.
pub fn names_relative_database(paths: &krb5_config::KdcPaths, db_args: &[String]) -> bool {
    database_path(&paths.database_name, db_args).is_ok_and(|db| db.is_relative())
        || paths.key_stash_file.is_relative()
}

// MIT: `main` (kdc/main.c:996-999)
/// Forks via daemon(3); call it before any thread is started.
#[cfg(feature = "daemon")]
pub fn detach() -> io::Result<()> {
    nix::unistd::daemon(false, false).map_err(io::Error::from)
}

// MIT: `write_pid_file` (kdc/main.c:834-847)
/// The pid file refuses a symlink; MIT empties its target.
#[cfg(feature = "daemon")]
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

#[must_use]
#[cfg(feature = "daemon")]
pub fn json_log_filter(default: &str) -> tracing_subscriber::EnvFilter {
    #[cfg(feature = "test-hooks")]
    if let Ok(filter) = tracing_subscriber::EnvFilter::try_from_default_env() {
        return filter;
    }
    tracing_subscriber::EnvFilter::new(default)
}

// MIT: `loop_setup_signals` (lib/apputils/net-server.c:263-286)
#[derive(Clone)]
#[cfg(feature = "daemon")]
pub struct Signals {
    stop: Arc<AtomicBool>,
    hup: Arc<AtomicBool>,
    wake: Option<Arc<OwnedFd>>,
}

#[cfg(feature = "daemon")]
impl Signals {
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

    pub(crate) fn wake_fd(&self) -> Option<&OwnedFd> {
        self.wake.as_deref()
    }

    pub(crate) fn take_hup(&self) -> bool {
        self.hup.swap(false, Ordering::Relaxed)
    }

    #[must_use]
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    #[must_use]
    pub fn stop_requested(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}

/// A programmatic stop for [`net_server::run`](crate::net_server::run)'s loop: `Shutdown::trigger`
/// wakes the poll through a self-pipe, else the loop polls the flag.
#[derive(Clone)]
pub struct Shutdown {
    stop: Arc<AtomicBool>,
    read: Option<Arc<OwnedFd>>,
    write: Option<Arc<OwnedFd>>,
}

impl Shutdown {
    #[must_use]
    pub fn new() -> Self {
        let (read, write) = match nix::unistd::pipe2(
            nix::fcntl::OFlag::O_CLOEXEC | nix::fcntl::OFlag::O_NONBLOCK,
        ) {
            Ok((r, w)) => (Some(Arc::new(r)), Some(Arc::new(w))),
            Err(_) => (None, None),
        };
        Self {
            stop: Arc::new(AtomicBool::new(false)),
            read,
            write,
        }
    }

    /// Stop the loop and wake it now.
    pub fn trigger(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(w) = &self.write {
            let _ = nix::unistd::write(w.as_ref(), &[0u8]);
        }
    }

    #[must_use]
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    pub(crate) fn wake_fd(&self) -> Option<&OwnedFd> {
        self.read.as_deref()
    }

    pub(crate) fn stop_requested(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "a test sets up its own profile and environment"
)]
mod tests {
    use super::*;

    use std::time::Duration;

    /// MIT's `fopen(path, "w")` empties a symlink's target; the pid file is never written through one, which stays, its target as it was.
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
}
