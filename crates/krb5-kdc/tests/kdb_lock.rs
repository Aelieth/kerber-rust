//! The database's lock files and lock: what creates them, what a database without them does,
//! the age every write moves, and who waits for whom.
// MIT: `ctx_create_db` (plugins/kdb/db2/kdb_db2.c:697-732)
//! creating a database makes `principal.ok`, then the policy lock file, `O_EXCL`.
// MIT: `ctx_init` (plugins/kdb/db2/kdb_db2.c:488-501)
//! opening a database needs `principal.ok`; no open creates it.
// MIT: `ctx_update_age` (plugins/kdb/db2/kdb_db2.c:590-598)
//! every write moves `principal.ok`'s mtime strictly forward.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use krb5_kdc::testrealm::bootstrap_documented;
use krb5_kdc::{
    DbLock, DbLockMode, PersistError, SUFFIX_LOCK, SUFFIX_POLICY_LOCK, create_store, load_store,
    save_store, suffixed,
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

/// A symlink planted at `link` (as a non-root owner of the KDC directory may plant one) to a file
/// with known bytes and an old modification time; the target, its bytes and its time.
fn plant_link(link: &Path) -> (PathBuf, Vec<u8>, std::time::SystemTime) {
    let victim = link.with_file_name(format!(
        "{}.victim",
        link.file_name().unwrap().to_string_lossy()
    ));
    let bytes = b"not the realm's\n".to_vec();
    std::fs::write(&victim, &bytes).unwrap();
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
    let _ = std::fs::remove_file(link);
    std::os::unix::fs::symlink(&victim, link).unwrap();
    (victim, bytes, old)
}

/// The link is still at `link`, and its target `victim` keeps its bytes and modification time.
fn assert_untouched(link: &Path, victim: &Path, bytes: &[u8], mtime: std::time::SystemTime) {
    assert!(
        std::fs::symlink_metadata(link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "{}",
        link.display()
    );
    assert_eq!(
        std::fs::read(victim).unwrap(),
        bytes,
        "{}",
        victim.display()
    );
    assert_eq!(
        std::fs::metadata(victim).unwrap().modified().unwrap(),
        mtime,
        "{}",
        victim.display()
    );
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

/// MIT's create opens `principal.ok` `O_CREAT | O_TRUNC`, emptying a symlink's target; this
/// create refuses the link and makes nothing.
#[test]
fn create_refuses_a_symlink_planted_as_principal_ok() {
    let (store, _) = bootstrap_documented().unwrap();
    let master = krb5_kdc::random_key(krb5_crypto::EncryptionType::Aes256CtsHmacSha196).unwrap();
    let dir = scratch_dir("krb5-lock-link-create");
    let db = dir.join("principal");
    let ok = suffixed(&db, SUFFIX_LOCK);
    let (victim, bytes, mtime) = plant_link(&ok);
    let err = create_store(&store, &db, &master).unwrap_err().to_string();
    assert!(
        err.contains("principal.ok: Too many levels of symbolic links"),
        "{err}"
    );
    assert_untouched(&ok, &victim, &bytes, mtime);
    assert!(!db.exists(), "nothing else made");
}

/// MIT opens a symlinked lock file and locks its target; this open refuses the link and names
/// it, rather than reporting the policy lock file missing.
#[test]
fn opening_the_database_refuses_a_symlink_planted_as_either_lock_file() {
    for (tag, suffix) in [("ok", SUFFIX_LOCK), ("pol", SUFFIX_POLICY_LOCK)] {
        let (db, stash) = saved(&format!("krb5-lock-link-open-{tag}"));
        let lock = suffixed(&db, suffix);
        let (victim, bytes, mtime) = plant_link(&lock);
        let err = lock_text(&db, &stash);
        assert!(
            err.contains(&format!("{suffix}: Too many levels of symbolic links")),
            "{suffix}: {err}"
        );
        assert_untouched(&lock, &victim, &bytes, mtime);
    }
}

/// MIT retimes `principal.ok` by name with `utime`, so a symlink planted there has its target
/// retimed; this write leaves the link and its target as they are.
#[test]
fn moving_the_age_never_retimes_a_symlink_planted_as_principal_ok() {
    let (db, _) = saved("krb5-lock-link-age");
    let lock = DbLock::open(&db).unwrap();
    let ok = suffixed(&db, SUFFIX_LOCK);
    let (victim, bytes, mtime) = plant_link(&ok);
    lock.lock(DbLockMode::Exclusive).unwrap();
    lock.update_age();
    lock.unlock().unwrap();
    assert_untouched(&ok, &victim, &bytes, mtime);
}
