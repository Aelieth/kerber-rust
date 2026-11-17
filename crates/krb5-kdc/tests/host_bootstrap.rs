//! A host's first start: a failed first commit keeps its stash, marked, and the next start settles it.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use krb5_kdc::host::{
    HostChange, HostPaths, KerberosStore, KerberosStoreError, LoadedRealm, MemoryRealm,
};
use krb5_kdc::{Error, PrincipalStore, open_or_create_host};

const REALM: &str = "BOOT.TEST";

/// The first commit answers `Failed`, after committing when `lands`.
#[derive(Default)]
struct FirstAnswerLost {
    inner: MemoryRealm,
    lands: bool,
    answered: AtomicBool,
    commits: AtomicUsize,
}

impl KerberosStore for FirstAnswerLost {
    fn load(&self) -> Result<LoadedRealm, KerberosStoreError> {
        self.inner.load()
    }

    fn commit_change(&self, change: HostChange) -> Result<(), KerberosStoreError> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        if self.answered.swap(true, Ordering::SeqCst) {
            return self.inner.commit(change.batch);
        }
        if self.lands {
            self.inner.commit(change.batch)?;
        }
        Err(KerberosStoreError::Failed("the answer was lost".to_owned()))
    }
}

fn paths(dir: &Path) -> (krb5_config::KdcPaths, HostPaths) {
    let kdc = krb5_config::KdcPaths {
        profile: dir.join("kdc.conf"),
        conf: None,
        realm: Some(REALM.to_owned()),
        database_name: dir.join("principal"),
        key_stash_file: dir.join("stash"),
        acl_file: None,
        master_key_type: None,
    };
    let host = HostPaths {
        stash: dir.join("host.stash"),
        lockout: dir.join("host.lockout"),
    };
    (kdc, host)
}

fn open(dir: &Path, host: Arc<dyn KerberosStore>) -> Result<PrincipalStore, Error> {
    let (kdc, host_paths) = paths(dir);
    let profile = krb5_config::ProfileSet::from_structs(REALM, krb5_config::Krb5Conf::new(), None);
    open_or_create_host(&kdc, &profile, None, host, &host_paths).map(|(store, _)| store)
}

fn marker(dir: &Path) -> PathBuf {
    dir.join("host.stash.bootstrap")
}

fn failed_first(dir: &Path, lands: bool) -> Arc<FirstAnswerLost> {
    let host = Arc::new(FirstAnswerLost {
        lands,
        ..FirstAnswerLost::default()
    });
    let first = open(dir, Arc::clone(&host) as Arc<dyn KerberosStore>);
    assert!(
        matches!(first, Err(Error::Host(KerberosStoreError::Failed(_)))),
        "{:?}",
        first.err()
    );
    assert!(dir.join("host.stash").exists() && marker(dir).exists());
    host
}

#[test]
fn a_first_commit_that_failed_retries_with_its_stash() {
    let dir = krb5_testkit::scratch_dir("host-boot-retry");
    let host = failed_first(&dir, false);
    let stash = std::fs::read(dir.join("host.stash")).unwrap();
    let store = open(&dir, Arc::clone(&host) as Arc<dyn KerberosStore>).unwrap();
    assert_eq!(std::fs::read(dir.join("host.stash")).unwrap(), stash);
    assert!(!marker(&dir).exists());
    assert!(store.get(&format!("K/M@{REALM}")).is_some());
    let rows = host.inner.load().unwrap().principals;
    assert!(rows.iter().any(|p| p.name == "K/M"), "{}", rows.len());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_first_commit_that_landed_opens_at_the_next_start() {
    let dir = krb5_testkit::scratch_dir("host-boot-landed");
    let host = failed_first(&dir, true);
    let rows = host.inner.load().unwrap().principals.len();
    let (kdc, host_paths) = paths(&dir);
    let profile = krb5_config::ProfileSet::from_structs(REALM, krb5_config::Krb5Conf::new(), None);
    let (_, boot) = open_or_create_host(
        &kdc,
        &profile,
        None,
        Arc::clone(&host) as Arc<dyn KerberosStore>,
        &host_paths,
    )
    .unwrap();
    assert!(boot.created.is_empty(), "{:?}", boot.created);
    assert_eq!(host.commits.load(Ordering::SeqCst), 1);
    assert_eq!(host.inner.load().unwrap().principals.len(), rows);
    assert!(!marker(&dir).exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_unmarked_or_mismatched_stash_beside_an_empty_host_is_refused() {
    let dir = krb5_testkit::scratch_dir("host-boot-unmarked");
    open(&dir, Arc::new(MemoryRealm::default())).unwrap();
    let stash = std::fs::read(dir.join("host.stash")).unwrap();
    let empty = || Arc::new(MemoryRealm::default()) as Arc<dyn KerberosStore>;
    let refused = open(&dir, empty());
    assert!(
        matches!(refused, Err(Error::StashWithoutHostRealm { .. })),
        "{:?}",
        refused.err()
    );
    std::fs::write(marker(&dir), format!("kerber-rust bootstrap {REALM} 00\n")).unwrap();
    let refused = open(&dir, empty());
    assert!(
        matches!(refused, Err(Error::StashWithoutHostRealm { .. })),
        "{:?}",
        refused.err()
    );
    assert_eq!(std::fs::read(dir.join("host.stash")).unwrap(), stash);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_marker_has_the_stashs_mode_and_owner() {
    let dir = krb5_testkit::scratch_dir("host-boot-mode");
    failed_first(&dir, false);
    let (stash, mark) = (
        std::fs::metadata(dir.join("host.stash")).unwrap(),
        std::fs::metadata(marker(&dir)).unwrap(),
    );
    assert_eq!(mark.mode() & 0o777, 0o600);
    assert_eq!(mark.uid(), stash.uid());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_marker_with_no_stash_is_refused() {
    let dir = krb5_testkit::scratch_dir("host-boot-nostash");
    failed_first(&dir, false);
    std::fs::remove_file(dir.join("host.stash")).unwrap();
    let host = Arc::new(MemoryRealm::default());
    let refused = open(&dir, Arc::clone(&host) as Arc<dyn KerberosStore>);
    assert!(
        matches!(refused, Err(Error::BootstrapMarkerWithoutStash { .. })),
        "{:?}",
        refused.err()
    );
    assert!(marker(&dir).exists() && !dir.join("host.stash").exists());
    assert_eq!(host.load().unwrap().principals.len(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}
