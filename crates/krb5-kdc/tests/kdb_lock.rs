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
        .change(|s| s.insert_new_randkey(&name, &realm, &[], "test@KERBER.TEST"))
        .unwrap()
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
        .change(|s| s.insert_new_randkey(&name, &realm, &[], "test@KERBER.TEST"))
        .unwrap()
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

/// Two handles on one database (two open file descriptions, as two processes have) changing it
/// at once: each change waits for the other's lock, starts from what the other saved, and
/// nothing is lost.
#[test]
fn two_handles_changing_at_once_lose_nothing() {
    let (db, stash) = saved("krb5-lock-two");
    let n = 25;
    let side = |tag: &'static str, db: PathBuf, stash: PathBuf| {
        std::thread::spawn(move || {
            let mut store = load_store(&db, &stash).unwrap();
            let realm = store.realm().to_owned();
            for i in 0..n {
                let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [format!("{tag}{i}")]);
                store
                    .change(|s| s.insert_new_randkey(&name, &realm, &[], "test@KERBER.TEST"))
                    .unwrap()
                    .unwrap();
            }
        })
    };
    let a = side("a", db.clone(), stash.clone());
    let b = side("b", db.clone(), stash.clone());
    a.join().unwrap();
    b.join().unwrap();
    let all = load_store(&db, &stash).unwrap();
    for tag in ["a", "b"] {
        for i in 0..n {
            let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [format!("{tag}{i}")]);
            assert!(all.get_name(&name).is_some(), "{tag}{i} lost");
        }
    }
}

/// The lost update P9 closes: a store read before another writer saved changes the database, and
/// its change keeps the other writer's, because it reads the database again under the lock.
#[test]
fn a_stale_stores_change_keeps_another_writers_save() {
    let (db, stash) = saved("krb5-lock-stale-write");
    let mut stale = load_store(&db, &stash).unwrap();
    let mut other = load_store(&db, &stash).unwrap();
    let realm = other.realm().to_owned();
    let x = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["x"]);
    let y = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["y"]);
    other
        .change(|s| s.insert_new_randkey(&x, &realm, &[], "test@KERBER.TEST"))
        .unwrap()
        .unwrap();
    assert!(stale.get_name(&x).is_none());
    stale
        .change(|s| s.insert_new_randkey(&y, &realm, &[], "test@KERBER.TEST"))
        .unwrap()
        .unwrap();
    let all = load_store(&db, &stash).unwrap();
    assert!(all.get_name(&x).is_some() && all.get_name(&y).is_some());
}

/// A change that makes no mutation writes nothing: the database file and its age stay.
#[test]
fn a_change_with_no_mutation_writes_nothing() {
    let (db, stash) = saved("krb5-lock-noop");
    let mut store = load_store(&db, &stash).unwrap();
    let (ino, before) = (std::fs::metadata(&db).unwrap().ino(), age(&db));
    store.change(|_| Ok::<(), ()>(())).unwrap().unwrap();
    assert_eq!(std::fs::metadata(&db).unwrap().ino(), ino);
    assert_eq!(age(&db), before);
}

/// A mutation of a store with a database outside a change is refused, so nothing can be saved
/// without reading the database again under the exclusive lock first.
#[test]
fn a_mutation_outside_a_change_is_refused() {
    let (db, stash) = saved("krb5-lock-guard");
    let mut store = load_store(&db, &stash).unwrap();
    let realm = store.realm().to_owned();
    let z = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["z"]);
    let err = store
        .insert_new_randkey(&z, &realm, &[], "test@KERBER.TEST")
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("outside the database's exclusive lock"),
        "{err}"
    );
    assert!(load_store(&db, &stash).unwrap().get_name(&z).is_none());
}

/// A change that panics leaves the store as a change found it: a later mutation outside a change
/// is still refused, the half-made change is read away, and the next change saves.
#[test]
fn a_change_that_panics_leaves_the_store_guarded() {
    let (db, stash) = saved("krb5-lock-panic");
    let mut store = load_store(&db, &stash).unwrap();
    let realm = store.realm().to_owned();
    let half = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["half"]);
    let whole = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["whole"]);
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        store.change(|s| -> Result<(), krb5_kdc::Error> {
            s.insert_new_randkey(&half, &realm, &[], "test@KERBER.TEST")?;
            panic!("inside the change");
        })
    }));
    assert!(panicked.is_err());
    assert!(
        store
            .insert_new_randkey(&whole, &realm, &[], "test@KERBER.TEST")
            .is_err()
    );
    store.reload_if_stale().unwrap();
    assert!(store.get_name(&half).is_none());
    store
        .change(|s| s.insert_new_randkey(&whole, &realm, &[], "test@KERBER.TEST"))
        .unwrap()
        .unwrap();
    let on_disk = load_store(&db, &stash).unwrap();
    assert!(on_disk.get_name(&whole).is_some() && on_disk.get_name(&half).is_none());
}

/// A test hook writes through the locked change as every writer does (kadmin-rust-gate's
/// `krb5-kdb setlastpwd`): a store that already has the database open, as a running kadmind
/// has, reads the hook's write on its next look.
#[cfg(feature = "test-hooks")]
#[test]
fn a_hook_write_is_read_by_a_store_already_open() {
    let (db, stash) = saved("krb5-lock-hook");
    let mut running = load_store(&db, &stash).unwrap();
    let conf = db.with_extension("conf");
    std::fs::write(&conf, "[libdefaults]\n default_realm = KERBER.TEST\n").unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_krb5-kdb"))
        .args(["setlastpwd", "user", "1000000000"])
        .env("KRB5_KDC_DB", &db)
        .env("KRB5_KDC_STASH", &stash)
        .env("KRB5_CONFIG", &conf)
        .env("KRB5_KDC_PROFILE", db.with_extension("none"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    running.reload_if_stale().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let p = running.get_name(&user).unwrap();
    let last = p
        .tl_data
        .iter()
        .find(|t| t.ty == krb5_kdc::TL_LAST_PWD_CHANGE)
        .unwrap();
    assert_eq!(last.contents, 1_000_000_000_u32.to_le_bytes());
}

/// kadmin.local's `lock`: the exclusive lock is held across changes until `unlock`, and another
/// process's change waits for it.
#[test]
fn the_session_lock_holds_another_writer_off_until_unlock() {
    let (db, stash) = saved("krb5-lock-session");
    let mut session = load_store(&db, &stash).unwrap();
    session.lock_database().unwrap();
    let realm = session.realm().to_owned();
    let mine = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["mine"]);
    session
        .change(|s| s.insert_new_randkey(&mine, &realm, &[], "test@KERBER.TEST"))
        .unwrap()
        .unwrap();
    let (tx, rx) = mpsc::channel();
    let (db2, stash2) = (db.clone(), stash.clone());
    let t = std::thread::spawn(move || {
        let mut other = load_store(&db2, &stash2).unwrap();
        let realm = other.realm().to_owned();
        let theirs = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["theirs"]);
        other
            .change(|s| s.insert_new_randkey(&theirs, &realm, &[], "test@KERBER.TEST"))
            .unwrap()
            .unwrap();
        tx.send(()).unwrap();
    });
    assert!(rx.recv_timeout(Duration::from_millis(400)).is_err());
    session.unlock_database().unwrap();
    rx.recv_timeout(Duration::from_secs(10)).unwrap();
    t.join().unwrap();
    let all = load_store(&db, &stash).unwrap();
    let theirs = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["theirs"]);
    assert!(all.get_name(&mine).is_some() && all.get_name(&theirs).is_some());
}

/// A `load -update` that stops while it holds the permanent lock leaves `principal.kadm5.lock`
/// gone, so the database does not open again until an administrator makes the file (MIT 3g).
#[test]
fn a_permanent_lock_never_let_go_leaves_the_database_unusable() {
    let (db, stash) = saved("krb5-lock-perm-kill");
    {
        let lock = DbLock::open(&db).unwrap();
        lock.lock(DbLockMode::Permanent).unwrap();
    }
    assert_eq!(
        lock_text(&db, &stash),
        "KADM5 administration database lock file missing"
    );
    std::fs::File::create(suffixed(&db, SUFFIX_POLICY_LOCK)).unwrap();
    assert!(load_store(&db, &stash).is_ok());
}
