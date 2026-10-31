//! The KDC's lockout attributes in `principal.lockout` beside the database, as MIT's KDC keeps
//! them in its database: written in place by the KDC alone and never into the database or its
//! update log, kept across a restart, merged by every reader, kept by admin changes that do not
//! set them, replaced by a plain load and kept by an iprop load; `kdb5_util create` and `load`
//! make the file and `destroy` removes it.
// MIT: `krb5_db2_lockout_audit` (plugins/kdb/db2/lockout.c:141-222)
//! the KDC writes the three attributes it changed.
// MIT: `klmdb_update_lockout` (plugins/kdb/lmdb/kdb_lmdb.c:1054-1121)
//! only the lockout record is written.

#![cfg(unix)]

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented, documented_admin_id};
use krb5_kdc::{
    Acl, AdminFields, Error, KDB_DISALLOW_ALL_TIX, Lockout, NamedPolicy, PrincipalStore,
    SUFFIX_LOCK, issue_as, load_store, load_store_full, lockout_path, lockout_records, read_stash,
    save_store, suffixed,
};
use krb5_protocol::{as_req, pa_enc_timestamp, pa_enc_timestamp_at};
use krb5_testkit::scratch_dir;
use krb5_types::{AsReq, KerberosTime, PrincipalName, err};

fn name(n: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [n])
}

fn id(n: &str) -> String {
    format!("{n}@{TEST_REALM}")
}

/// The documented realm saved to a scratch database, `user@` under a policy of three failures.
fn saved(tag: &str) -> (PathBuf, PathBuf, Acl) {
    let dir = scratch_dir(tag);
    let (db, stash) = (dir.join("principal"), dir.join("stash"));
    let (mut store, acl) = bootstrap_documented().unwrap();
    store
        .put_policy(NamedPolicy {
            name: "lock3".into(),
            min_length: 1,
            min_classes: 1,
            history: 0,
            max_fail: 3,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
            pw_min_life: 0,
            pw_max_life: 0,
            allowed_keysalts: None,
        })
        .unwrap();
    store
        .set_principal_policy(&name(TEST_USER), Some("lock3".into()))
        .unwrap();
    save_store(&store, &db, &stash).unwrap();
    (db, stash, acl)
}

fn good(store: &PrincipalStore, who: &str) -> AsReq {
    let key = store
        .get_name(&name(who))
        .unwrap()
        .best_key()
        .unwrap()
        .key
        .clone();
    as_req(
        name(who),
        TEST_REALM,
        1,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap()
}

/// A wrong password: the timestamp under a key of zeros, a distinct one each time.
fn bad(who: &str, n: i64) -> AsReq {
    let zeros = krb5_crypto::ProtocolKey::from_bytes(
        krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
        &[0u8; 32],
    )
    .unwrap();
    let ts = KerberosTime::now().add_seconds(n).unwrap();
    as_req(
        name(who),
        TEST_REALM,
        1,
        Some(vec![pa_enc_timestamp_at(&zeros, &ts).unwrap()]),
    )
    .unwrap()
}

fn locked_out(e: &Error) -> bool {
    matches!(e, Error::Protocol { code, text, .. }
        if *code == err::CLIENT_REVOKED && text.as_deref() == Some("LOCKED_OUT"))
}

fn record(db: &Path, who: &str) -> Option<Lockout> {
    lockout_records(db).get(&id(who)).copied()
}

#[test]
fn the_kdc_writes_only_its_records_in_place_and_a_restart_keeps_the_lock() {
    let (db, stash, _) = saved("lockout-restart");
    let side = lockout_path(&db);
    let ulog = suffixed(&db, ".ulog");
    let ok = suffixed(&db, SUFFIX_LOCK);
    // The realm's update log, as a primary with iprop would keep it; the KDC never maps it.
    drop(krb5_kdc::Ulog::map(&ulog, 100).unwrap());
    let kdc = load_store(&db, &stash).unwrap();
    let serial = kdc.serial();
    let (db_bytes, ulog_bytes) = (std::fs::read(&db).unwrap(), std::fs::read(&ulog).unwrap());
    let (side_ino, ok_age) = (
        std::fs::metadata(&side).unwrap().ino(),
        std::fs::metadata(&ok).unwrap().mtime_nsec(),
    );
    for n in 1..=3 {
        assert!(issue_as(&kdc, &bad(TEST_USER, n)).is_err());
    }
    let refused = issue_as(&kdc, &good(&kdc, TEST_USER)).unwrap_err();
    assert!(locked_out(&refused), "{refused:?}");
    let rec = record(&db, TEST_USER).unwrap();
    assert_eq!(rec.fail_auth_count, 3);
    assert!(rec.last_failed > 0);
    assert_eq!(
        std::fs::read(&db).unwrap(),
        db_bytes,
        "the database is untouched"
    );
    assert_eq!(
        std::fs::read(&ulog).unwrap(),
        ulog_bytes,
        "nothing is logged"
    );
    assert_eq!(
        std::fs::metadata(&side).unwrap().ino(),
        side_ino,
        "written in place"
    );
    assert_eq!(
        std::fs::metadata(&ok).unwrap().mtime_nsec(),
        ok_age,
        "the database's age does not move"
    );
    let again = load_store(&db, &stash).unwrap();
    let refused = issue_as(&again, &good(&again, TEST_USER)).unwrap_err();
    assert!(locked_out(&refused), "after a restart: {refused:?}");
    let p = again.get_name(&name(TEST_USER)).unwrap();
    assert_eq!(p.fail_auth_count, 3);
    assert_eq!(
        p.attributes & KDB_DISALLOW_ALL_TIX,
        0,
        "a lockout disables nothing"
    );
    assert_eq!(again.serial(), serial);
}

/// The user's record line in `db`'s side file, as bytes, and its offset.
fn user_line(db: &Path) -> (Vec<u8>, usize) {
    let text = std::fs::read(lockout_path(db)).unwrap();
    let tail = format!(" {}\n", id(TEST_USER));
    let end = text
        .windows(tail.len())
        .position(|w| w == tail.as_bytes())
        .unwrap();
    let start = text[..end].iter().rposition(|&b| b == b'\n').unwrap() + 1;
    (text, start)
}

/// A record that a crash tore in the middle of an update (a digit of the new count written, the
/// rest not) is no record: the principal's values are the database's, never a mixed one.
#[test]
fn a_record_torn_by_a_crash_reads_as_none() {
    let (db, stash, _) = saved("lockout-torn-record");
    let kdc = load_store(&db, &stash).unwrap();
    for n in 1..=2 {
        assert!(issue_as(&kdc, &bad(TEST_USER, n)).is_err());
    }
    assert_eq!(record(&db, TEST_USER).unwrap().fail_auth_count, 2);
    let (mut text, start) = user_line(&db);
    let last_count_digit = start + 2 * 11 + 9;
    assert_eq!(text[last_count_digit], b'2');
    text[last_count_digit] = b'7';
    std::fs::write(lockout_path(&db), &text).unwrap();
    assert_eq!(record(&db, TEST_USER), None, "no record, not a count of 7");
    let again = load_store(&db, &stash).unwrap();
    assert_eq!(
        again.fail_auth_of(again.get_name(&name(TEST_USER)).unwrap()),
        0,
        "the database's own count"
    );
}

/// A full load writes `principal.lockout` anew and renames it over the old file, as a database
/// save does, so a load cut short leaves the old file whole; the old file's mode is kept.
#[test]
fn a_full_load_writes_a_new_side_file_and_renames_it_over_the_old() {
    use std::os::unix::fs::PermissionsExt as _;
    let (db, stash, _) = saved("lockout-load-rename");
    let side = lockout_path(&db);
    std::fs::set_permissions(&side, std::fs::Permissions::from_mode(0o640)).unwrap();
    let before = std::fs::metadata(&side).unwrap();
    let master = read_stash(&stash, &db).unwrap();
    let store = load_store(&db, &stash).unwrap();
    load_store_full(&store, &db, &master, false, None).unwrap();
    let after = std::fs::metadata(&side).unwrap();
    assert_ne!(
        after.ino(),
        before.ino(),
        "never emptied and written in place"
    );
    assert_eq!(after.mode() & 0o777, 0o640);
    assert!(record(&db, TEST_USER).is_some());
}

/// A symlink planted as `principal.lockout` (by a less-privileged owner of the directory) is
/// never followed: lockout counting stays off, readers find no record, and the tools refuse,
/// its target left as it was.
#[test]
fn a_symlink_planted_as_the_side_file_is_never_followed() {
    let (db, stash, _) = saved("lockout-symlink");
    let side = lockout_path(&db);
    let victim = side.with_file_name("victim");
    let content = std::fs::read(&side).unwrap();
    std::fs::write(&victim, &content).unwrap();
    std::fs::remove_file(&side).unwrap();
    std::os::unix::fs::symlink(&victim, &side).unwrap();
    let kdc = load_store(&db, &stash).unwrap();
    assert!(issue_as(&kdc, &bad(TEST_USER, 1)).is_err());
    assert_eq!(kdc.fail_auth_of(kdc.get_name(&name(TEST_USER)).unwrap()), 0);
    assert!(lockout_records(&db).is_empty(), "never read through it");
    let mut admin = load_store(&db, &stash).unwrap();
    let refused = admin
        .change(|s| s.admin_unlock(&name(TEST_USER)))
        .unwrap_err()
        .to_string();
    assert!(
        refused.contains("Too many levels of symbolic links"),
        "{refused}"
    );
    let master = read_stash(&stash, &db).unwrap();
    assert!(load_store_full(&admin, &db, &master, false, None).is_err());
    assert_eq!(
        std::fs::read(&victim).unwrap(),
        content,
        "never written through"
    );
    assert!(
        std::fs::symlink_metadata(&side)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn admin_changes_keep_the_counts_unless_they_set_them() {
    let (db, stash, acl) = saved("lockout-admin");
    let kdc = load_store(&db, &stash).unwrap();
    for n in 1..=2 {
        assert!(issue_as(&kdc, &bad(TEST_USER, n)).is_err());
    }
    let mut admin = load_store(&db, &stash).unwrap();
    admin
        .change(|s| {
            s.apply_admin_fields(
                &name(TEST_USER),
                AdminFields {
                    max_life: Some(3600),
                    ..AdminFields::default()
                },
            )
        })
        .unwrap()
        .unwrap();
    assert_eq!(record(&db, TEST_USER).unwrap().fail_auth_count, 2);
    admin
        .change(|s| s.admin_unlock(&name(TEST_USER)))
        .unwrap()
        .unwrap();
    let unlocked = record(&db, TEST_USER).unwrap();
    assert_eq!(unlocked.fail_auth_count, 0);
    assert!(unlocked.last_failed > 0, "an unlock keeps the last failure");
    admin
        .change(|s| s.create_password(&acl, &documented_admin_id(), &name("newp"), b"New-pw-123"))
        .unwrap()
        .unwrap();
    assert_eq!(record(&db, "newp"), None);
    assert!(issue_as(&kdc, &bad(TEST_USER, 3)).is_err());
    admin
        .change(|s| {
            s.rename(
                &acl,
                &documented_admin_id(),
                &name(TEST_USER),
                &name("moved"),
            )
        })
        .unwrap()
        .unwrap();
    assert_eq!(record(&db, TEST_USER), None);
    assert_eq!(
        record(&db, "moved").unwrap().fail_auth_count,
        1,
        "the count moves"
    );
    admin
        .change(|s| s.delete(&acl, &documented_admin_id(), &name("moved")))
        .unwrap()
        .unwrap();
    assert_eq!(record(&db, "moved"), None);
}

#[test]
fn a_full_load_replaces_the_counts_and_an_iprop_load_keeps_them() {
    let (db, stash, _) = saved("lockout-load");
    let master = read_stash(&stash, &db).unwrap();
    let kdc = load_store(&db, &stash).unwrap();
    assert!(issue_as(&kdc, &bad(TEST_USER, 1)).is_err());
    let snapshot = load_store(&db, &stash).unwrap();
    assert!(issue_as(&kdc, &bad(TEST_USER, 2)).is_err());
    assert_eq!(record(&db, TEST_USER).unwrap().fail_auth_count, 2);
    load_store_full(&snapshot, &db, &master, false, None).unwrap();
    assert_eq!(record(&db, TEST_USER).unwrap().fail_auth_count, 1);
    let kdc = load_store(&db, &stash).unwrap();
    assert!(issue_as(&kdc, &bad(TEST_USER, 3)).is_err());
    load_store_full(&snapshot, &db, &master, true, None).unwrap();
    assert_eq!(record(&db, TEST_USER).unwrap().fail_auth_count, 2);
}

/// A scratch realm whose kdc.conf names its database, and `kdb5_util` (a link to the binary).
struct Realm {
    dir: PathBuf,
    db: PathBuf,
}

impl Realm {
    fn new(tag: &str) -> Self {
        let dir = scratch_dir(tag);
        let db = dir.join("principal");
        std::fs::write(
            dir.join("krb5.conf"),
            "[libdefaults]\n    default_realm = KL.TEST\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("kdc.conf"),
            format!(
                "[realms]\n    KL.TEST = {{\n        database_name = {}\n        key_stash_file = {}\n        master_key_type = aes256-cts-hmac-sha1-96\n    }}\n",
                db.display(),
                dir.join("stash").display()
            ),
        )
        .unwrap();
        std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_krb5-kdb"), dir.join("kdb5_util")).unwrap();
        let realm = Self { dir, db };
        let out = realm.run(&["-P", "p8-master", "create", "-s"]);
        assert_eq!(out.status.code(), Some(0), "{}", err_text(&out));
        realm
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(self.dir.join("kdb5_util"));
        cmd.args(args)
            .current_dir(&self.dir)
            .env("KRB5_CONFIG", self.dir.join("krb5.conf"))
            .env("KRB5_KDC_PROFILE", self.dir.join("kdc.conf"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for v in [
            "KRB5_KDC_DB",
            "KRB5_KDC_STASH",
            "KRB5_MASTER_ETYPE",
            "KRB5_MASTER_PASSWORD",
        ] {
            cmd.env_remove(v);
        }
        cmd.output().unwrap()
    }
}

impl Drop for Realm {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn err_text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A destroy zeroes `principal.lockout` before it unlinks it; a symlink planted there stops the
/// destroy before anything is changed, the link and its target left as they were.
#[test]
fn destroy_refuses_a_symlink_planted_as_the_side_file() {
    let realm = Realm::new("lockout-kdb5-util-link");
    let side = lockout_path(&realm.db);
    let victim = realm.dir.join("victim");
    std::fs::write(&victim, b"not the realm's\n").unwrap();
    let old = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
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
    std::fs::remove_file(&side).unwrap();
    std::os::unix::fs::symlink(&victim, &side).unwrap();
    let db = std::fs::read(&realm.db).unwrap();
    let out = realm.run(&["destroy", "-f"]);
    assert_eq!(out.status.code(), Some(1), "{}", err_text(&out));
    assert!(
        err_text(&out).contains("principal.lockout: Too many levels of symbolic links"),
        "{}",
        err_text(&out)
    );
    assert!(
        std::fs::symlink_metadata(&side)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&victim).unwrap(), b"not the realm's\n");
    assert_eq!(std::fs::metadata(&victim).unwrap().modified().unwrap(), old);
    assert_eq!(
        std::fs::read(&realm.db).unwrap(),
        db,
        "the database is not destroyed"
    );
}
