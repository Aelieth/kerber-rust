//! `kdb5_util` and the database's lock files, with the texts and files settled live against MIT
//! 1.22.2: `create` makes both, a database without either does not open, a full `load` goes
//! through a temporary database and makes `principal.ok` again only when it is missing, and
//! `load -update` takes the permanent lock, which makes `principal.kadm5.lock` anew and is let go
//! on every failure. `-update` judges the database before it fetches any master key, and no load
//! holds a lock while it waits for one.
//! MIT `load_db` (`kadmin/dbutil/dump.c:1509-1526`): an update opens the database, then locks it permanently, before any record is read.
//! MIT `ctx_create_db` (`plugins/kdb/db2/kdb_db2.c:697-732`): `create` makes `principal.ok`, the database, then the policy lock file `O_EXCL`.
//! MIT `osa_adb_get_lock` (`plugins/kdb/db2/adb_openclose.c:265-283`): the permanent lock removes the policy lock file.
//! MIT `osa_adb_release_lock` (`plugins/kdb/db2/adb_openclose.c:299-307`): letting it go creates the file again.

#![cfg(unix)]

use std::os::unix::fs::MetadataExt as _;
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

    /// `kdb5_util` with `input` on its standard input (a typed master password).
    fn run_with(&self, args: &[&str], input: &str) -> Output {
        use std::io::Write as _;
        let mut child = self.command(args).stdin(Stdio::piped()).spawn().unwrap();
        let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
        child.wait_with_output().unwrap()
    }

    /// The realm's dump, written by its own `kdb5_util dump`.
    fn dump(&self, name: &str) -> PathBuf {
        let dump = self.dir.join(name);
        let out = self.run(&["dump", dump.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(0), "{}", err(&out));
        dump
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

    fn ls(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("principal"))
            .collect();
        names.sort();
        names
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

fn ino(p: &Path) -> u64 {
    std::fs::metadata(p).unwrap().ino()
}

/// The inode with its ctime, as `DbStamp` compares them: a file removed and made again may be
/// given the freed inode, but not the old ctime.
fn stamp(p: &Path) -> (u64, i64, i64) {
    let m = std::fs::metadata(p).unwrap();
    (m.ino(), m.ctime(), m.ctime_nsec())
}

#[test]
fn create_makes_both_lock_files_and_a_stale_policy_lock_file_fails_it() {
    let realm = Realm::new("kdb-lock-create");
    realm.create();
    for f in [realm.ok(), realm.pol()] {
        let m = std::fs::metadata(&f).unwrap();
        assert_eq!((m.len(), m.mode() & 0o777), (0, 0o600), "{}", f.display());
    }
    let stale = Realm::new("kdb-lock-create-stale");
    std::fs::write(stale.pol(), b"").unwrap();
    let out = stale.run(&["-P", "p9-master", "create", "-s"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        err(&out),
        format!(
            "kdb5_util: File exists while creating database '{}'\n",
            stale.db.display()
        )
    );
    assert!(stale.db.exists(), "MIT leaves the database file it made");
    std::fs::remove_file(stale.pol()).unwrap();
    let out = stale.run(&["-P", "p9-master", "create", "-s"]);
    assert_eq!(
        err(&out),
        format!(
            "kdb5_util: Cannot open DB2 database '{0}': File exists while creating database '{0}'\n",
            stale.db.display()
        )
    );
}

#[test]
fn a_database_without_its_lock_files_does_not_open() {
    let realm = Realm::new("kdb-lock-missing");
    realm.create();
    let dump = realm.dir.join("base.dump");
    assert!(
        realm
            .run(&["dump", dump.to_str().unwrap()])
            .status
            .success()
    );
    let ok = realm.ok();
    std::fs::rename(&ok, realm.dir.join("ok.away")).unwrap();
    for args in [vec!["dump", "/nonexistent/x"], vec!["stash", "-f", "s2"]] {
        let out = realm.run(&args);
        assert_eq!(
            err(&out),
            "kdb5_util: No such file or directory while initializing database\n",
            "{args:?}"
        );
    }
    let out = realm.run(&["load", "-update", dump.to_str().unwrap()]);
    assert_eq!(
        err(&out),
        "kdb5_util: No such file or directory while opening database\n"
    );
    std::fs::rename(realm.dir.join("ok.away"), &ok).unwrap();
    std::fs::remove_file(realm.pol()).unwrap();
    let missing = "KADM5 administration database lock file missing";
    let out = realm.run(&["dump", "/nonexistent/x"]);
    assert_eq!(
        err(&out),
        format!("kdb5_util: {missing} while initializing database\n")
    );
    let out = realm.run(&["load", "-update", dump.to_str().unwrap()]);
    assert_eq!(
        err(&out),
        format!("kdb5_util: {missing} while opening database\n")
    );
    let out = realm.run(&["load", dump.to_str().unwrap()]);
    assert_eq!(
        err(&out),
        format!("kdb5_util: {missing} while making newly loaded database live\n")
    );
    assert_eq!(
        realm.ls(),
        [
            "principal",
            "principal.lockout",
            "principal.ok",
            "principal.ulog"
        ]
    );
}

#[test]
fn a_full_load_promotes_a_temporary_database_and_keeps_the_lock_files() {
    let realm = Realm::new("kdb-lock-load");
    realm.create();
    let dump = realm.dir.join("base.dump");
    assert!(
        realm
            .run(&["dump", dump.to_str().unwrap()])
            .status
            .success()
    );
    let (ok, pol, db) = (ino(&realm.ok()), ino(&realm.pol()), ino(&realm.db));
    let out = realm.run(&["load", dump.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", err(&out));
    assert_eq!((ino(&realm.ok()), ino(&realm.pol())), (ok, pol));
    assert_ne!(ino(&realm.db), db, "the database is a new file");
    assert_eq!(
        realm.ls(),
        [
            "principal",
            "principal.kadm5.lock",
            "principal.lockout",
            "principal.ok",
            "principal.ulog"
        ]
    );
    // MIT D: a load makes a missing principal.ok again.
    std::fs::remove_file(realm.ok()).unwrap();
    assert!(
        realm
            .run(&["load", dump.to_str().unwrap()])
            .status
            .success()
    );
    assert!(realm.ok().exists());
    // MIT D: into an empty directory, both lock files come with the database.
    let empty = Realm::new("kdb-lock-load-empty");
    std::fs::copy(realm.dir.join("stash"), empty.dir.join("stash")).unwrap();
    let out = empty.run(&["load", dump.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", err(&out));
    assert_eq!(
        empty.ls(),
        [
            "principal",
            "principal.kadm5.lock",
            "principal.lockout",
            "principal.ok",
            "principal.ulog"
        ]
    );
}

#[test]
fn load_update_takes_the_permanent_lock_and_makes_the_policy_lock_file_anew() {
    let realm = Realm::new("kdb-lock-update");
    realm.create();
    let dump = realm.dir.join("base.dump");
    assert!(
        realm
            .run(&["dump", dump.to_str().unwrap()])
            .status
            .success()
    );
    let (ok, pol) = (ino(&realm.ok()), stamp(&realm.pol()));
    let out = realm.run(&["load", "-update", dump.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", err(&out));
    assert_eq!(ino(&realm.ok()), ok);
    assert_ne!(
        stamp(&realm.pol()),
        pol,
        "MIT 2j: a new principal.kadm5.lock"
    );
    assert_eq!(
        std::fs::metadata(realm.pol()).unwrap().mode() & 0o777,
        0o600
    );
}

/// MIT P1 / P3 (promote-cells-p9.txt): a full load into a directory whose database file alone is
/// gone (a replica between two transfers), or whose `principal.ok` is gone with it, makes the
/// database live: the policy lock file there is opened and locked, not made again.
#[test]
fn a_full_load_beside_a_removed_databases_lock_files_loads() {
    let realm = Realm::new("kdb-lock-reload");
    realm.create();
    let dump = realm.dir.join("base.dump");
    assert!(
        realm
            .run(&["dump", dump.to_str().unwrap()])
            .status
            .success()
    );
    for ok_too in [false, true] {
        std::fs::remove_file(&realm.db).unwrap();
        if ok_too {
            std::fs::remove_file(realm.ok()).unwrap();
        }
        let pol = ino(&realm.pol());
        let out = realm.run(&["load", dump.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(0), "{}", err(&out));
        assert_eq!(ino(&realm.pol()), pol);
        assert!(realm.ok().exists());
        let again = realm.dir.join("again.dump");
        let out = realm.run(&["dump", again.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(0), "{}", err(&out));
    }
}

/// MIT `dump_db` reads the records under the shared lock only once the master key is in hand: a
/// writer is not held off while `-m` waits for the key to be typed, and the dump holds its write.
#[test]
fn a_dump_waiting_for_a_typed_master_key_holds_no_lock() {
    use std::io::{Read as _, Write as _};
    let realm = Realm::new("kdb-lock-mdump");
    realm.create();
    let out_file = realm.dir.join("m.dump");
    let mut dump = realm
        .command(&["-m", "dump", out_file.to_str().unwrap()])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let mut prompt = Vec::new();
    let mut stdout = dump.stdout.take().unwrap();
    let mut byte = [0_u8];
    while !prompt.ends_with(b"master key: ") && stdout.read(&mut byte).unwrap() == 1 {
        prompt.push(byte[0]);
    }
    let mut writer = krb5_kdc::load_store(&realm.db, &realm.dir.join("stash")).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let name =
            krb5_types::PrincipalName::new(krb5_types::PrincipalName::NT_PRINCIPAL, ["typing"]);
        let realm = writer.realm().to_owned();
        let made = writer.change(|s| s.insert_new_randkey(&name, &realm, &[], "test@KL.TEST"));
        tx.send(matches!(made, Ok(Ok(())))).unwrap();
    });
    let written = rx.recv_timeout(std::time::Duration::from_secs(5));
    dump.stdin
        .take()
        .unwrap()
        .write_all(b"p9-master\n")
        .unwrap();
    let out = dump.wait_with_output().unwrap();
    assert_eq!(
        written,
        Ok(true),
        "a writer waited on the master key prompt"
    );
    assert_eq!(out.status.code(), Some(0), "{}", err(&out));
    assert!(
        std::fs::read_to_string(&out_file)
            .unwrap()
            .contains("typing@KL.TEST")
    );
}

/// MIT 1.22.2 (settled live) opens an empty `principal` as an empty database, and `load -update`
/// fills it, with the dump's records or with a dump of policies alone, then makes
/// `principal.kadm5.lock` anew. This update took the permanent lock, failed on the empty file and
/// returned with `principal.kadm5.lock` removed.
#[test]
fn load_update_fills_an_empty_database_and_makes_the_policy_lock_file_anew() {
    let realm = Realm::new("kdb-lock-update-empty");
    realm.create();
    let dump = realm.dump("base.dump");
    let stash = realm.dir.join("stash");
    let ids = krb5_kdc::load_store(&realm.db, &stash).unwrap().ids();
    std::fs::write(&realm.db, b"").unwrap();
    let pol = stamp(&realm.pol());
    let out = realm.run(&["load", "-update", dump.to_str().unwrap()]);
    assert!(realm.pol().exists(), "principal.kadm5.lock: {}", err(&out));
    assert_ne!(stamp(&realm.pol()), pol, "a new principal.kadm5.lock");
    assert_eq!(out.status.code(), Some(0), "{}", err(&out));
    assert_eq!(krb5_kdc::load_store(&realm.db, &stash).unwrap().ids(), ids);
    let policy = "policy\tp1\t0\t0\t8\t1\t1\t0\t0\t0\t0\t0\t0\t0\t-\t0";
    std::fs::write(
        realm.dir.join("p1.dump"),
        format!("kdb5_util load_dump version 7\n{policy}\n"),
    )
    .unwrap();
    std::fs::write(realm.dir.join("h.dump"), "kdb5_util load_dump version 7\n").unwrap();
    for (file, body) in [
        ("p1.dump", format!("{policy}\n")),
        ("h.dump", String::new()),
    ] {
        std::fs::write(&realm.db, b"").unwrap();
        let out = realm.run(&["load", "-update", file]);
        assert_eq!(out.status.code(), Some(0), "{file}: {}", err(&out));
        assert_eq!(
            std::fs::read_to_string(&realm.db).unwrap(),
            format!("kdb5_util load_dump version 7\n{body}"),
            "{file}"
        );
        assert!(realm.pol().exists(), "{file}");
    }
}

/// Once `load -update` holds the permanent lock, every failure lets it go: the update is one
/// write of the whole database, so the database is as it was and `principal.kadm5.lock` is made
/// again, where MIT leaves it removed once a restore under the lock fails. Here the dump's master
/// key does not open the database, and the database's update log may not be written. This update
/// returned from both with `principal.kadm5.lock` removed.
#[test]
fn load_update_lets_the_permanent_lock_go_on_every_failure() {
    use std::os::unix::fs::PermissionsExt as _;
    let realm = Realm::new("kdb-lock-update-fail");
    realm.create();
    let own = realm.dump("own.dump");
    let other = Realm::new("kdb-lock-update-fail-other");
    let out = other.run(&["-P", "other-master", "create", "-s"]);
    assert_eq!(out.status.code(), Some(0), "{}", err(&out));
    let foreign = other.dump("other.dump");
    let before = std::fs::read(&realm.db).unwrap();
    let pol = stamp(&realm.pol());
    let out = realm.run(&[
        "-P",
        "other-master",
        "load",
        "-update",
        foreign.to_str().unwrap(),
    ]);
    let text = err(&out);
    assert!(
        realm.pol().exists(),
        "principal.kadm5.lock made again: {text}"
    );
    assert_ne!(stamp(&realm.pol()), pol);
    assert_eq!(out.status.code(), Some(1));
    let head = format!(
        "kdb5_util: Cannot open DB2 database '{}': ",
        realm.db.display()
    );
    assert!(text.starts_with(&head), "{text}");
    assert!(text.ends_with(" while opening database\n"), "{text}");
    assert_eq!(std::fs::read(&realm.db).unwrap(), before);
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let ulog = suffixed(&realm.db, ".ulog");
    std::fs::set_permissions(&ulog, std::fs::Permissions::from_mode(0o444)).unwrap();
    let out = realm.run(&["load", "-update", own.to_str().unwrap()]);
    assert!(realm.pol().exists(), "principal.kadm5.lock made again");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        err(&out).starts_with("kdb5_util: Permission denied while storing "),
        "{}",
        err(&out)
    );
    assert_eq!(std::fs::read(&realm.db).unwrap(), before);
}

/// The permanent lock reopens the database read-write before it removes `principal.kadm5.lock`,
/// as MIT's does: a user who may not write the database is refused with MIT's text (settled live
/// as an unprivileged user on root's 0644 files) and nothing changes. This update removed the
/// lock file, then failed at the write and left it removed.
#[test]
fn load_update_reopens_the_database_before_it_removes_the_policy_lock_file() {
    use std::os::unix::fs::PermissionsExt as _;
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let realm = Realm::new("kdb-lock-update-ro");
    realm.create();
    let dump = realm.dump("base.dump");
    std::fs::set_permissions(&realm.db, std::fs::Permissions::from_mode(0o444)).unwrap();
    let pol = ino(&realm.pol());
    let out = realm.run(&["load", "-update", dump.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        err(&out),
        format!(
            "kdb5_util: Cannot open DB2 database '{}': Permission denied while permanently locking \
             database\n",
            realm.db.display()
        )
    );
    assert_eq!(ino(&realm.pol()), pol, "principal.kadm5.lock never removed");
}

/// A database that `-update` cannot open is reported before any master key is fetched, as MIT
/// reports it (settled live: MIT's `load` reads no master key and prints nothing on standard
/// output): a database file that is no database, is missing or lacks a lock file, each with `-m`.
/// This load asked for the master key first. A full load reads the key before it makes its
/// temporary database, so that it holds no lock while it waits: a directory that is not there is
/// reported after the prompt, where MIT prints none.
#[test]
fn a_database_that_does_not_open_is_reported_before_the_master_key_prompt() {
    let realm = Realm::new("kdb-lock-load-noprompt");
    realm.create();
    let dump = realm.dump("base.dump");
    let dump = dump.to_str().unwrap();
    let db = realm.db.display().to_string();
    let files = [realm.db.clone(), realm.ok(), realm.pol()];
    let kept: Vec<Vec<u8>> = files.iter().map(|f| std::fs::read(f).unwrap()).collect();
    let cases = [
        (
            &files[0],
            Some("not a database\n"),
            format!("Cannot open DB2 database '{db}': Invalid argument while opening database"),
        ),
        (
            &files[0],
            None,
            format!(
                "Cannot open DB2 database '{db}': No such file or directory while opening database"
            ),
        ),
        (
            &files[1],
            None,
            "No such file or directory while opening database".to_owned(),
        ),
        (
            &files[2],
            None,
            "KADM5 administration database lock file missing while opening database".to_owned(),
        ),
    ];
    for (file, written, refused) in &cases {
        match written {
            Some(bytes) => std::fs::write(file, bytes).unwrap(),
            None => std::fs::remove_file(file).unwrap(),
        }
        let out = realm.run_with(&["-m", "load", "-update", dump], "p9-master\n");
        assert_eq!(out.status.code(), Some(1), "{refused}");
        assert_eq!(text_of(&out.stdout), "", "{refused}: no prompt");
        assert_eq!(err(&out), format!("kdb5_util: {refused}\n"));
        for (f, bytes) in files.iter().zip(&kept) {
            std::fs::write(f, bytes).unwrap();
        }
    }
    let gone = realm.dir.join("gone").join("principal");
    let out = realm.run_with(
        &["-m", "-d", gone.to_str().unwrap(), "load", dump],
        "p9-master\n",
    );
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text_of(&out.stdout),
        "Enter KDC database master key: \n",
        "the key before the temporary database"
    );
    assert_eq!(
        err(&out),
        "kdb5_util: No such file or directory while creating database\n"
    );
    // Where the database opens, the dump's keys still need the master key: -m asks for it.
    let out = realm.run_with(&["-m", "load", "-update", dump], "p9-master\n");
    assert_eq!(out.status.code(), Some(0), "{}", err(&out));
    assert_eq!(text_of(&out.stdout), "Enter KDC database master key: \n");
}

fn text_of(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A legacy `KDB3` database is a database this store reads with its stash: `load -update` merges
/// the dump into it, writes it out as dump text and makes `principal.kadm5.lock` anew. This
/// update took the permanent lock, failed on the binary file and left the lock file removed.
#[test]
fn load_update_into_a_legacy_database_writes_it_out_as_dump_text() {
    let realm = Realm::new("kdb-lock-update-kdb3");
    realm.create();
    let dump = realm.dump("base.dump");
    let stash = realm.dir.join("stash");
    let store = krb5_kdc::load_store(&realm.db, &stash).unwrap();
    let master = krb5_kdc::read_stash(&stash, &realm.db).unwrap();
    let ids = store.ids();
    std::fs::write(&stash, master.as_bytes()).unwrap();
    krb5_kdc::save_store_legacy_kdb3(&store, &realm.db, &stash).unwrap();
    drop(store);
    assert!(std::fs::read(&realm.db).unwrap().starts_with(b"KDB3"));
    let pol = stamp(&realm.pol());
    let out = realm.run(&["load", "-update", dump.to_str().unwrap()]);
    assert!(realm.pol().exists(), "principal.kadm5.lock: {}", err(&out));
    assert_ne!(stamp(&realm.pol()), pol, "a new principal.kadm5.lock");
    assert_eq!(out.status.code(), Some(0), "{}", err(&out));
    assert!(
        std::fs::read(&realm.db)
            .unwrap()
            .starts_with(b"kdb5_util load_dump version 7\n")
    );
    assert_eq!(krb5_kdc::load_store(&realm.db, &stash).unwrap().ids(), ids);
}

/// A legacy `KDB3` database opens only with its stash: with none, `-update` names the master key
/// it cannot fetch with MIT's text for a missing stash (settled live: MIT's `kdb5_util` says
/// `Can not fetch master key (error: No such file or directory).` while reading the master key),
/// before the permanent lock, so nothing changes. This update took the lock and named the
/// database.
#[test]
fn load_update_into_a_legacy_database_without_its_stash_names_the_master_key() {
    let realm = Realm::new("kdb-lock-update-kdb3-nostash");
    realm.create();
    let dump = realm.dump("base.dump");
    let stash = realm.dir.join("stash");
    let store = krb5_kdc::load_store(&realm.db, &stash).unwrap();
    let master = krb5_kdc::read_stash(&stash, &realm.db).unwrap();
    std::fs::write(&stash, master.as_bytes()).unwrap();
    krb5_kdc::save_store_legacy_kdb3(&store, &realm.db, &stash).unwrap();
    drop(store);
    std::fs::remove_file(&stash).unwrap();
    let before = std::fs::read(&realm.db).unwrap();
    let pol = ino(&realm.pol());
    let out = realm.run(&["-P", "p9-master", "load", "-update", dump.to_str().unwrap()]);
    assert_eq!(
        ino(&realm.pol()),
        pol,
        "principal.kadm5.lock never removed: {}",
        err(&out)
    );
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        err(&out),
        "kdb5_util: Can not fetch master key (error: No such file or directory). while reading \
         master key\n"
    );
    assert_eq!(std::fs::read(&realm.db).unwrap(), before);
}

/// A load waiting for a typed master key holds no lock (MIT's load reads no key): kpropd's or
/// iprop's full load into the same database goes ahead meanwhile, and so does a writer while
/// `-update` waits, its `principal.kadm5.lock` still there. A full load held its temporary
/// database's lock through the prompt.
#[test]
fn a_load_waiting_for_a_typed_master_key_holds_no_lock() {
    use std::io::{Read as _, Write as _};
    for update in [false, true] {
        let realm = Realm::new(if update {
            "kdb-lock-mload-update"
        } else {
            "kdb-lock-mload-full"
        });
        realm.create();
        let dump = realm.dump("base.dump");
        let mut args = vec!["-m", "load"];
        if update {
            args.push("-update");
        }
        args.push(dump.to_str().unwrap());
        let mut load = realm.command(&args).stdin(Stdio::piped()).spawn().unwrap();
        let mut prompt = Vec::new();
        let mut stdout = load.stdout.take().unwrap();
        let mut byte = [0_u8];
        while !prompt.ends_with(b"master key: ") && stdout.read(&mut byte).unwrap() == 1 {
            prompt.push(byte[0]);
        }
        let stash = realm.dir.join("stash");
        let mut store = krb5_kdc::load_store(&realm.db, &stash).unwrap();
        let master = krb5_kdc::read_stash(&stash, &realm.db).unwrap();
        let db = realm.db.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let done = if update {
                let name = krb5_types::PrincipalName::new(
                    krb5_types::PrincipalName::NT_PRINCIPAL,
                    ["typing"],
                );
                let realm = store.realm().to_owned();
                let made =
                    store.change(|s| s.insert_new_randkey(&name, &realm, &[], "test@KL.TEST"));
                matches!(made, Ok(Ok(())))
            } else {
                krb5_kdc::load_store_full(&store, &db, &master, false).is_ok()
            };
            let _ = tx.send(done);
        });
        let went_ahead = rx.recv_timeout(std::time::Duration::from_secs(5));
        let policy_lock_there = realm.pol().exists();
        load.stdin
            .take()
            .unwrap()
            .write_all(b"p9-master\n")
            .unwrap();
        let out = load.wait_with_output().unwrap();
        assert_eq!(
            went_ahead,
            Ok(true),
            "update {update}: held off by the prompt"
        );
        assert!(policy_lock_there, "update {update}");
        assert_eq!(out.status.code(), Some(0), "{}", err(&out));
    }
}
