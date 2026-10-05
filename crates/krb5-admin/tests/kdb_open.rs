//! `kadmin.local` on a database file it does not read: the open fails with MIT's text before the
//! master key is asked for, with the stash as with `-m` (settled live on MIT 1.22.2).
//! MIT `kadm5_init` (`lib/kadm5/srv/server_init.c:234-256`): the database is opened before the caller's name is parsed and the master key fetched.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use krb5_testkit::scratch_dir;

/// The documented test realm saved as a database a kdc.conf names, as `kadmin.local` finds it.
fn realm(tag: &str) -> PathBuf {
    let dir = scratch_dir(tag);
    let (store, _) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    krb5_kdc::save_store(&store, &dir.join("principal"), &dir.join("stash")).unwrap();
    std::fs::write(
        dir.join("krb5.conf"),
        "[libdefaults]\n default_realm = KERBER.TEST\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("kdc.conf"),
        format!(
            "[realms]\n KERBER.TEST = {{\n  database_name = {}\n  key_stash_file = {}\n }}\n",
            dir.join("principal").display(),
            dir.join("stash").display()
        ),
    )
    .unwrap();
    dir
}

fn kadmin_local(dir: &Path, args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_krb5-kadmin-local"))
        .args(args)
        .env("KRB5_CONFIG", dir.join("krb5.conf"))
        .env("KRB5_KDC_PROFILE", dir.join("kdc.conf"))
        .env(
            "KRB5CCNAME",
            format!("FILE:{}", dir.join("no-cc").display()),
        )
        .env("USER", "tester")
        .env_remove("KRB5_KDC_DB")
        .env_remove("KRB5_KDC_STASH")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    child.wait_with_output().unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn a_database_file_that_is_no_database_is_refused_before_the_master_key() {
    let dir = realm("kadmin-local-not-a-database");
    let db = dir.join("principal");
    std::fs::write(&db, "not a database\n").unwrap();
    let refused = format!(
        "kadmin.local: Cannot open DB2 database '{}': Invalid argument while initializing \
         kadmin.local interface\n",
        db.display()
    );
    for args in [
        &["-r", "KERBER.TEST", "-q", "listprincs"][..],
        &["-r", "KERBER.TEST", "-m", "-q", "listprincs"][..],
    ] {
        let out = kadmin_local(&dir, args, "master\n");
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        assert_eq!(text(&out.stderr), refused, "{args:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// MIT 1.22.2's own db2 headers (settled live): a btree `principal` from `kdb5_util create`, a
/// hash one from `-x hash=true`. Either is named with the way over and left as it was.
#[test]
fn an_mit_db2_database_is_named_with_the_way_over_before_the_master_key() {
    let dir = realm("kadmin-local-mit-db2");
    let db = dir.join("principal");
    let refused = format!(
        "kadmin.local: Cannot open DB2 database '{}': This is an MIT db2 database; dump it with \
         the old installation's kdb5_util, then kdb5_util load here (docs/install.md, Upgrading \
         an MIT realm) while initializing kadmin.local interface\n",
        db.display()
    );
    let btree = [0x62, 0x31, 0x05, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x10];
    let hash = [
        0x00, 0x06, 0x15, 0x61, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x04, 0xd2,
    ];
    for head in [&btree[..], &hash[..]] {
        let mut db2 = head.to_vec();
        db2.resize(8192, 0);
        std::fs::write(&db, &db2).unwrap();
        for args in [
            &["-r", "KERBER.TEST", "-q", "listprincs"][..],
            &["-r", "KERBER.TEST", "-m", "-q", "listprincs"][..],
        ] {
            let out = kadmin_local(&dir, args, "master\n");
            assert_eq!(out.status.code(), Some(1), "{args:?}");
            assert_eq!(text(&out.stderr), refused, "{args:?}");
        }
        assert_eq!(std::fs::read(&db).unwrap(), db2, "left as it was");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The database's lock files open with it, before the master key is typed or read, as MIT's
/// `kadm5_init` opens them (settled live on MIT 1.22.2): with `-m` no prompt is printed, and with
/// no stash the missing lock file is named, not the stash.
#[test]
fn a_database_without_its_lock_files_is_refused_before_the_master_key() {
    let dir = realm("kadmin-local-no-lock-files");
    let db = dir.join("principal");
    let pol = dir.join("principal.kadm5.lock");
    let ok = dir.join("principal.ok");
    std::fs::remove_file(dir.join("stash")).unwrap();
    let authenticating = "Authenticating as principal tester/admin@KERBER.TEST with password.\n";
    for (gone, refused) in [
        (&pol, "KADM5 administration database lock file missing"),
        (&ok, "No such file or directory"),
    ] {
        let kept = std::fs::read(gone).unwrap();
        std::fs::remove_file(gone).unwrap();
        for args in [
            &["-r", "KERBER.TEST", "-q", "listprincs"][..],
            &["-r", "KERBER.TEST", "-m", "-q", "listprincs"][..],
        ] {
            let out = kadmin_local(&dir, args, "master\n");
            assert_eq!(out.status.code(), Some(1), "{args:?}");
            assert_eq!(text(&out.stdout), authenticating, "{args:?}: no prompt");
            assert_eq!(
                text(&out.stderr),
                format!("kadmin.local: {refused} while initializing kadmin.local interface\n"),
                "{args:?}"
            );
        }
        std::fs::write(gone, kept).unwrap();
    }
    assert!(db.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// kprop judges the database before it reads the stash, as the dump MIT's kprop sends opens the
/// database before it fetches the master key (settled live: MIT's `kdb5_util dump` names a
/// database file that is no database, not the missing stash). With the realm's database, the
/// missing stash is named, before anything is sent.
#[test]
fn kprop_judges_the_database_before_it_reads_the_stash() {
    let dir = realm("kprop-database-first");
    let db = dir.join("principal");
    let stash = dir.join("stash");
    std::fs::remove_file(&stash).unwrap();
    let kprop = || {
        Command::new(env!("CARGO_BIN_EXE_krb5-kprop"))
            .arg("127.0.0.1")
            .env("KRB5_CONFIG", dir.join("krb5.conf"))
            .env("KRB5_KDC_PROFILE", dir.join("kdc.conf"))
            .env_remove("KRB5_KDC_DB")
            .env_remove("KRB5_KDC_STASH")
            .env_remove("KRB5_MASTER_PASSWORD")
            .env_remove("KRB5_KPROP_KEYTAB")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let kept = std::fs::read(&db).unwrap();
    std::fs::write(&db, "not a database\n").unwrap();
    let out = kprop();
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        text(&out.stderr),
        format!(
            "krb5-kprop: load store: Cannot open DB2 database '{}': Invalid argument\n",
            db.display()
        )
    );
    std::fs::write(&db, kept).unwrap();
    let out = kprop();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).starts_with(&format!("krb5-kprop: stash {}: ", stash.display())),
        "{}",
        text(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
