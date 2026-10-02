//! The database's lock files and lock: what creates them, what a database without them does,
//! the age every write moves, and who waits for whom.
//! MIT `ctx_create_db` (`plugins/kdb/db2/kdb_db2.c:697-732`): creating a database makes `principal.ok`, then the policy lock file, `O_EXCL`.
//! MIT `ctx_init` (`plugins/kdb/db2/kdb_db2.c:488-501`): opening a database needs `principal.ok`; no open creates it.
//! MIT `ctx_update_age` (`plugins/kdb/db2/kdb_db2.c:590-598`): every write moves `principal.ok`'s mtime strictly forward.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use krb5_kdc::testrealm::bootstrap_documented;
use krb5_kdc::{
    CreateError, DbLock, DbLockError, DbLockMode, PersistError, SUFFIX_LOCK, SUFFIX_POLICY_LOCK,
    create_store, load_store, save_store, suffixed,
};
use krb5_testkit::scratch_dir;
use krb5_types::PrincipalName;

fn saved(tag: &str) -> (PathBuf, PathBuf) {
    let dir = scratch_dir(tag);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (store, _) = bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    (db, stash)
}

fn lock_text(db: &Path, stash: &Path) -> String {
    match load_store(db, stash) {
        Err(e @ PersistError::Lock(_)) => e.to_string(),
        other => panic!("{:?}", other.map(|_| ())),
    }
}

fn age(db: &Path) -> i64 {
    std::fs::metadata(suffixed(db, SUFFIX_LOCK))
        .unwrap()
        .mtime()
}

#[test]
fn a_new_database_gets_both_lock_files_and_one_without_them_does_not_open() {
    let (db, stash) = saved("krb5-lock-files");
    for f in [
        suffixed(&db, SUFFIX_LOCK),
        suffixed(&db, SUFFIX_POLICY_LOCK),
    ] {
        let m = std::fs::metadata(&f).unwrap();
        assert_eq!(m.len(), 0, "{}", f.display());
        assert_eq!(m.mode() & 0o777, 0o600, "{}", f.display());
    }
    assert!(load_store(&db, &stash).is_ok());
    let pol = suffixed(&db, SUFFIX_POLICY_LOCK);
    std::fs::rename(&pol, db.with_extension("away")).unwrap();
    assert_eq!(
        lock_text(&db, &stash),
        "KADM5 administration database lock file missing"
    );
    std::fs::rename(db.with_extension("away"), &pol).unwrap();
    std::fs::remove_file(suffixed(&db, SUFFIX_LOCK)).unwrap();
    assert_eq!(lock_text(&db, &stash), "No such file or directory");
    // A save is no open: it refuses an existing database without its lock files too.
    let (store, _) = bootstrap_documented().unwrap();
    assert!(matches!(
        save_store(&store, &db, &stash),
        Err(PersistError::Lock(_))
    ));
    assert!(!suffixed(&db, SUFFIX_LOCK).exists());
}

#[test]
fn create_makes_both_lock_files_and_a_stale_policy_lock_file_fails_it() {
    let (store, _) = bootstrap_documented().unwrap();
    let master = krb5_kdc::random_key(krb5_crypto::EncryptionType::Aes256CtsHmacSha196).unwrap();
    let dir = scratch_dir("krb5-lock-create");
    let db = dir.join("principal");
    create_store(&store, &db, &master).unwrap();
    assert!(suffixed(&db, SUFFIX_LOCK).exists());
    assert!(suffixed(&db, SUFFIX_POLICY_LOCK).exists());
    match create_store(&store, &db, &master) {
        Err(CreateError::Create(e)) => assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists),
        other => panic!("{other:?}"),
    }
    // MIT, settled live: a policy lock file already there fails the create with "File exists"
    // and leaves the database file it made.
    let dir = scratch_dir("krb5-lock-stale");
    let db = dir.join("principal");
    std::fs::write(suffixed(&db, SUFFIX_POLICY_LOCK), b"").unwrap();
    match create_store(&store, &db, &master) {
        Err(e @ CreateError::Lock(_)) => assert_eq!(e.to_string(), "File exists"),
        other => panic!("{other:?}"),
    }
    assert!(db.exists());
    assert!(suffixed(&db, SUFFIX_LOCK).exists());
}

#[test]
fn every_save_moves_the_age_strictly_forward() {
    let (db, stash) = saved("krb5-lock-age");
    let store = load_store(&db, &stash).unwrap();
    let mut last = age(&db);
    for _ in 0..3 {
        save_store(&store, &db, &stash).unwrap();
        let now = age(&db);
        assert!(now > last, "{now} after {last}");
        last = now;
    }
}

#[test]
fn a_reader_sees_another_writers_save_whatever_the_files_size() {
    let (db, stash) = saved("krb5-lock-stamp");
    let mut reader = load_store(&db, &stash).unwrap();
    let mut writer = load_store(&db, &stash).unwrap();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["stamped"]);
    let realm = writer.realm().to_owned();
    writer
        .insert_new_randkey(&name, &realm, &[], "test@KERBER.TEST")
        .unwrap();
    save_store(&writer, &db, &stash).unwrap();
    reader.reload_if_stale().unwrap();
    assert!(reader.get_name(&name).is_some());
}

/// A write that left the age where it was (a writer that may not set `principal.ok`'s times)
/// and the database in an inode the reader read before is still read again: the file's change
/// time moved.
#[test]
fn a_reader_sees_a_write_that_kept_the_age_and_the_inode() {
    use nix::sys::stat::{UtimensatFlags, utimensat};
    use nix::sys::time::TimeSpec;
    let (db, stash) = saved("krb5-lock-ctime");
    let mut reader = load_store(&db, &stash).unwrap();
    let ok = std::fs::metadata(suffixed(&db, SUFFIX_LOCK)).unwrap();
    let age = TimeSpec::new(ok.mtime(), ok.mtime_nsec());
    let kept = db.with_extension("kept");
    std::fs::hard_link(&db, &kept).unwrap();
    let mut writer = load_store(&db, &stash).unwrap();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["in-place"]);
    let realm = writer.realm().to_owned();
    writer
        .insert_new_randkey(&name, &realm, &[], "test@KERBER.TEST")
        .unwrap();
    std::fs::write(&kept, std::fs::read(&db).unwrap()).unwrap();
    std::fs::rename(&kept, &db).unwrap();
    utimensat(
        nix::fcntl::AT_FDCWD,
        &suffixed(&db, SUFFIX_LOCK),
        &age,
        &age,
        UtimensatFlags::FollowSymlink,
    )
    .unwrap();
    reader.reload_if_stale().unwrap();
    assert!(reader.get_name(&name).is_some());
}

#[test]
fn a_write_holder_makes_a_read_wait_and_a_read_holder_does_not() {
    let (db, stash) = saved("krb5-lock-wait");
    // Another process's lock: OFD locks on another open file description conflict with ours.
    let other = Arc::new(DbLock::open(&db).unwrap());
    let read = |db: PathBuf, stash: PathBuf| {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || tx.send(load_store(&db, &stash).is_ok()).unwrap());
        rx
    };
    let held = other.hold(DbLockMode::Shared).unwrap();
    assert_eq!(
        read(db.clone(), stash.clone()).recv_timeout(Duration::from_secs(5)),
        Ok(true)
    );
    drop(held);
    let held = other.hold(DbLockMode::Exclusive).unwrap();
    let rx = read(db.clone(), stash.clone());
    assert!(rx.recv_timeout(Duration::from_millis(400)).is_err());
    drop(held);
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(true));
}

#[test]
fn the_lock_texts_are_mits() {
    assert_eq!(
        DbLockError::CantLock.to_string(),
        "Insufficient access to lock database"
    );
    assert_eq!(
        DbLockError::NoLockFile.to_string(),
        "KADM5 administration database lock file missing"
    );
}
