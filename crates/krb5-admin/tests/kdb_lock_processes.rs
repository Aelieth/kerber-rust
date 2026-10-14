//! Two `kadmin.local` processes changing one database at once lose nothing: each change takes
//! the database's exclusive lock, reads the database again under it and writes it once, as MIT's
//! put does under `principal.ok` and `principal.kadm5.lock`.
//! MIT `krb5_db2_put_principal` (`plugins/kdb/db2/kdb_db2.c:828-854`): a put locks the database exclusively, writes, moves the age and unlocks.

use std::path::{Path, PathBuf};
use std::process::Command;

use krb5_kdc::KDB_DISALLOW_ALL_TIX;
use krb5_testkit::scratch_dir;
use krb5_types::PrincipalName;

/// The documented test realm saved as a database a kdc.conf names, as `kadmin.local` finds it.
fn realm(tag: &str) -> PathBuf {
    let dir = scratch_dir(tag);
    let _ = std::fs::create_dir_all(&dir);
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

fn kadmin_local(dir: &Path, query: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_krb5-kadmin-local"))
        .args(["-r", "KERBER.TEST", "-q", query])
        .env("KRB5_CONFIG", dir.join("krb5.conf"))
        .env("KRB5_KDC_PROFILE", dir.join("kdc.conf"))
        .env(
            "KRB5CCNAME",
            format!("FILE:{}", dir.join("no-cc").display()),
        )
        .env("USER", "tester")
        .output()
        .unwrap()
}

/// Run `query(tag, i)` for i in 0..n in each of two concurrent sequences of processes.
fn race(dir: &Path, n: usize, query: fn(&str, usize) -> String) {
    let side = |tag: &'static str| {
        let dir = dir.to_path_buf();
        std::thread::spawn(move || {
            for i in 0..n {
                let out = kadmin_local(&dir, &query(tag, i));
                assert!(
                    out.status.success(),
                    "{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        })
    };
    let (a, b) = (side("a"), side("b"));
    a.join().unwrap();
    b.join().unwrap();
}

#[test]
fn two_kadmin_local_processes_lose_no_principal_and_no_modification() {
    let dir = realm("kdb-lock-procs");
    let n = 12;
    race(&dir, n, |tag, i| format!("addprinc -randkey {tag}{i}"));
    race(&dir, n, |tag, i| format!("modprinc -allow_tix {tag}{i}"));
    let db = krb5_kdc::load_store(&dir.join("principal"), &dir.join("stash")).unwrap();
    for tag in ["a", "b"] {
        for i in 0..n {
            let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [format!("{tag}{i}")]);
            let p = db
                .get_name(&name)
                .unwrap_or_else(|| panic!("{tag}{i} lost"));
            assert_ne!(
                p.attributes & KDB_DISALLOW_ALL_TIX,
                0,
                "{tag}{i}: -allow_tix lost"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
