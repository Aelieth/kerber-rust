//! Process-level stdin exit codes for `ktutil` / `kadmin.local`.

use krb5_testkit::scratch_dir;
use std::io::Write;
use std::process::{Command, Stdio};

struct Realm {
    dir: std::path::PathBuf,
}

impl Realm {
    fn new(tag: &str) -> Self {
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
        Self { dir }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_krb5-kadmin-local"));
        cmd.env("KRB5_CONFIG", self.dir.join("krb5.conf"))
            .env("KRB5_KDC_PROFILE", self.dir.join("kdc.conf"))
            .env(
                "KRB5CCNAME",
                format!("FILE:{}", self.dir.join("no-cc").display()),
            )
            .env("USER", "tester");
        cmd
    }

    fn run(&self, args: &[&str], input: &[u8]) -> std::process::Output {
        let mut child = self
            .cmd()
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(input)
            .expect("write");
        child.wait_with_output().expect("wait")
    }
}

impl Drop for Realm {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn kadmin_local_exit_status_is_mit_s() {
    let realm = Realm::new("kadmin-exit");
    let out = realm.run(&["-q", "getprinc nosuch"], b"");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        text(&out.stdout),
        "Authenticating as principal tester/admin@KERBER.TEST with password.\n"
    );
    assert_eq!(
        text(&out.stderr),
        "get_principal: Principal does not exist while retrieving \"nosuch@KERBER.TEST\".\n"
    );
    let out = realm.run(&["-q", "nope"], b"");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(text(&out.stderr), "kadmin.local: Command not found nope\n");
    let out = realm.run(&["getprinc", "nosuch"], b"");
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(text(&out.stdout), "", "script mode prints no banner");
    let out = realm.run(&["addprinc", "-randkey", "sm1"], b"");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        (text(&out.stdout), text(&out.stderr)),
        (String::new(), String::new())
    );
    let out = realm.run(&["nope"], b"");
    assert_eq!(out.status.code(), Some(1));
    let out = realm.run(&["-Z"], b"");
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).starts_with("kadmin.local: invalid option -- 'Z'\nUsage: "));
    let out = realm.run(&[], b"nope\nq\n");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        text(&out.stdout),
        "Authenticating as principal tester/admin@KERBER.TEST with password.\nkadmin.local:  \
         kadmin.local:  "
    );
    assert_eq!(
        text(&out.stderr),
        "kadmin.local: Unknown request \"nope\".  Type \"?\" for a request list.\n"
    );
    let out = realm.run(&[], b"q\nnope\n");
    assert_eq!(
        (out.status.code(), text(&out.stderr)),
        (Some(0), String::new())
    );
    let out = realm.run(&[], b"\xff\nlistprincs us*\n");
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).contains("user@KERBER.TEST\n"));
}

#[test]
fn kadmin_local_explicit_principal_takes_the_realm() {
    let realm = Realm::new("kadmin-explicit-p");
    let out = realm.run(&["-p", "admin/admin", "-q", "addprinc -randkey pq1"], b"");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).starts_with("Authenticating as principal admin/admin with password.\n"),
        "{}",
        text(&out.stdout)
    );
    let modified = |realm: &Realm| {
        let out = realm.run(&["-q", "getprinc pq1"], b"");
        text(&out.stdout)
            .lines()
            .find_map(|l| l.strip_prefix("Last modified: "))
            .and_then(|l| l.rsplit_once(" ("))
            .map(|(_, by)| by.trim_end_matches(')').to_owned())
    };
    assert_eq!(modified(&realm).as_deref(), Some("admin/admin@KERBER.TEST"));
    let out = realm.run(
        &[
            "-p",
            "joe/admin@OTHER.TEST",
            "-q",
            "modprinc -maxlife 1h pq1",
        ],
        b"",
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(modified(&realm).as_deref(), Some("joe/admin@OTHER.TEST"));
}

#[test]
fn kadmin_local_refuses_a_realm_value_kadm5_cannot_convert() {
    let realm = Realm::new("kadmin-params");
    let kdc_conf = realm.dir.join("kdc.conf");
    let stanza = std::fs::read_to_string(&kdc_conf).unwrap();
    for line in [
        "default_principal_expiration = garbage",
        "default_principal_flags = +preauth,+bogus",
        "master_key_type = bogus-enctype",
        "supported_enctypes = bogus:normal",
    ] {
        std::fs::write(
            &kdc_conf,
            stanza.replace(" }\n", &format!("  {line}\n }}\n")),
        )
        .unwrap();
        let out = realm.run(&["-q", "getprinc K/M"], b"");
        assert_eq!(out.status.code(), Some(1), "{line}");
        assert_eq!(
            text(&out.stderr),
            "kadmin.local: Required parameters in kdc.conf missing while initializing kadmin.local interface\n",
            "{line}"
        );
    }
}
