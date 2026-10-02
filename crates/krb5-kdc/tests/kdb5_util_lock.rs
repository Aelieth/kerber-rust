//! `kdb5_util` and the database's lock files, with the texts and files settled live against MIT
//! 1.22.2: `create` makes both, a database without either does not open, a full `load` goes
//! through a temporary database and makes `principal.ok` again only when it is missing, and
//! `load -update` takes the permanent lock, which makes `principal.kadm5.lock` anew.
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

fn ino(p: &Path) -> u64 {
    std::fs::metadata(p).unwrap().ino()
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
    assert_eq!(realm.ls(), ["principal", "principal.ok", "principal.ulog"]);
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
    let (ok, pol) = (ino(&realm.ok()), ino(&realm.pol()));
    let out = realm.run(&["load", "-update", dump.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{}", err(&out));
    assert_eq!(ino(&realm.ok()), ok);
    assert_ne!(ino(&realm.pol()), pol, "MIT 2j: a new principal.kadm5.lock");
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
