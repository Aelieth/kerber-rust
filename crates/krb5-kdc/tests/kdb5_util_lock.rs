//! `kdb5_util` and the database's lock files, with the texts and files settled live against MIT
//! 1.22.2: `create` makes both, a database without either does not open, a full `load` goes
//! through a temporary database and makes `principal.ok` again only when it is missing, and
//! `load -update` takes the permanent lock, which makes `principal.kadm5.lock` anew and is let go
//! on every failure. `-update` judges the database before it fetches any master key, and no load
//! holds a lock while it waits for one.
// MIT: `load_db` (kadmin/dbutil/dump.c:1509-1526)
//! an update opens the database, then locks it permanently, before any record is read.
// MIT: `ctx_create_db` (plugins/kdb/db2/kdb_db2.c:697-732)
//! `create` makes `principal.ok`, the database, then the policy lock file `O_EXCL`.
// MIT: `osa_adb_get_lock` (plugins/kdb/db2/adb_openclose.c:265-283)
//! the permanent lock removes the policy lock file.
// MIT: `osa_adb_release_lock` (plugins/kdb/db2/adb_openclose.c:299-307)
//! letting it go creates the file again.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use krb5_kdc::{SUFFIX_LOCK, SUFFIX_POLICY_LOCK, suffixed};
use krb5_testkit::scratch_dir;

/// A scratch realm whose kdc.conf names its database, and `kdb5_util` (a link to the binary, so
/// messages carry MIT's program name).
struct Realm {
    dir: PathBuf,
    db: PathBuf,
}

impl Realm {
    fn new(name: &str) -> Self {
        let dir = scratch_dir(name);
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
        Self { dir, db }
    }

    fn command(&self, args: &[&str]) -> Command {
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
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    fn create(&self) {
        let out = self.run(&["-P", "p9-master", "create", "-s"]);
        assert_eq!(out.status.code(), Some(0), "{}", err(&out));
    }

    fn ok(&self) -> PathBuf {
        suffixed(&self.db, SUFFIX_LOCK)
    }

    fn pol(&self) -> PathBuf {
        suffixed(&self.db, SUFFIX_POLICY_LOCK)
    }
}

impl Drop for Realm {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn err(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A symlink planted at `link` (as a non-root owner of the KDC directory may plant one) to a file
/// with known bytes and an old modification time; the target, its bytes and its time.
fn plant_link(link: &Path) -> (PathBuf, Vec<u8>, std::time::SystemTime) {
    let victim = link.with_file_name(format!(
        "{}.victim",
        link.file_name().unwrap().to_string_lossy()
    ));
    std::fs::write(&victim, b"not the realm's\n").unwrap();
    let (bytes, old) = plant_link_to(link, &victim);
    (victim, bytes, old)
}

/// A symlink planted at `link` to the existing file `victim`, given an old modification time;
/// the target's bytes and its time.
fn plant_link_to(link: &Path, victim: &Path) -> (Vec<u8>, std::time::SystemTime) {
    let bytes = std::fs::read(victim).unwrap();
    let old = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
    std::fs::File::options()
        .write(true)
        .open(victim)
        .unwrap()
        .set_times(
            std::fs::FileTimes::new()
                .set_modified(old)
                .set_accessed(old),
        )
        .unwrap();
    let _ = std::fs::remove_file(link);
    std::os::unix::fs::symlink(victim, link).unwrap();
    (bytes, old)
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

/// MIT's dump opens its `.dump_ok` mark `O_CREAT | O_TRUNC`, emptying a symlink's target; this
/// dump refuses the link before it writes anything.
#[test]
fn dump_refuses_a_symlink_planted_as_its_mark() {
    let realm = Realm::new("kdb5-util-link-mark");
    realm.create();
    let dump = realm.dir.join("realm.dump");
    let mark = realm.dir.join("realm.dump.dump_ok");
    let (victim, bytes, mtime) = plant_link(&mark);
    let out = realm.run(&["dump", dump.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1), "{}", err(&out));
    assert!(
        err(&out).contains("Too many levels of symbolic links while creating 'ok' file"),
        "{}",
        err(&out)
    );
    assert_untouched(&mark, &victim, &bytes, mtime);
    assert!(!dump.exists());
}

/// MIT's destroy zeroes the database file through a symlink (here to a copy of the realm's
/// database, which opens); this destroy refuses the link and changes nothing.
#[test]
fn destroy_refuses_a_symlink_planted_as_the_database() {
    let realm = Realm::new("kdb5-util-link-destroy");
    realm.create();
    let victim = realm.dir.join("principal.saved");
    std::fs::rename(&realm.db, &victim).unwrap();
    let (bytes, mtime) = plant_link_to(&realm.db, &victim);
    let out = realm.run(&["destroy", "-f"]);
    assert_eq!(out.status.code(), Some(1), "{}", err(&out));
    assert!(
        err(&out).contains("principal: Too many levels of symbolic links"),
        "{}",
        err(&out)
    );
    assert_untouched(&realm.db, &victim, &bytes, mtime);
    for lock in [realm.ok(), realm.pol()] {
        assert!(lock.exists(), "{}: nothing destroyed", lock.display());
    }
}
