//! Local kadm5 verbs against a dump/stash (MIT `kadmin.local`).
//!
//! Usage: krb5-kadmin.local [-q command]
//! DB: `KRB5_KDC_DB` + `KRB5_KDC_STASH`. Passwords from `KRB5_PASSWORD`.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::io::{self, BufRead};
use std::path::PathBuf;

use krb5_admin::{AdminSession, KadminArgs, parse_kadmin_args};
use krb5_kdc::{Acl, load_store};
use krb5_protocol::{Keytab, parse_principal};
use krb5_types::PrincipalName;

fn main() {
    let mut queued = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "-q" {
            if let Some(c) = args.next() {
                queued.push(c);
            }
        } else {
            eprintln!("usage: krb5-kadmin.local [-q command]");
            std::process::exit(2);
        }
    }
    let (db, stash) = db_and_stash();
    let mut store = load_store(&db, &stash).unwrap_or_else(|e| {
        eprintln!("kadmin.local: load: {e}");
        std::process::exit(1);
    });
    if let Some(path) = krb5_config::kdc_conf_path()
        && let Ok(c) = krb5_config::KdcConf::load_file(&path)
        && let Err(e) = store.apply_kdc_conf(&c)
    {
        eprintln!("kadmin.local: kdc.conf: {e}");
        std::process::exit(1);
    }
    if let Some(c) = krb5_config::load_krb5_conf() {
        store.apply_libdefaults(&c);
    }
    let actor = std::env::var("KRB5_KADMIN_PRINCIPAL")
        .unwrap_or_else(|_| format!("admin@{}", store.realm()));
    // MIT kadmin.local does not read kadm5.acl (`KRB5_ACL_FILE` is kadmind-only).
    let acl = Acl::parse("* *e\n").unwrap_or_else(|e| {
        eprintln!("kadmin.local: acl: {e}");
        std::process::exit(1);
    });
    let mut sess = AdminSession::local(&mut store, &acl, actor);
    if queued.is_empty() {
        std::process::exit(run_stdin_reader(&mut sess, io::stdin().lock()));
    }
    for c in queued {
        match run(&mut sess, &c) {
            Ok(LineOutcome::Next) => {}
            Ok(LineOutcome::Quit) => break,
            Err(e) => {
                eprintln!("kadmin.local: {e}");
                std::process::exit(1);
            }
        }
    }
    drop(sess);
}

fn db_and_stash() -> (PathBuf, PathBuf) {
    let db = std::env::var("KRB5_KDC_DB").unwrap_or_else(|_| {
        eprintln!("kadmin.local: set KRB5_KDC_DB");
        std::process::exit(2);
    });
    let stash = std::env::var("KRB5_KDC_STASH").unwrap_or_else(|_| {
        eprintln!("kadmin.local: set KRB5_KDC_STASH");
        std::process::exit(2);
    });
    (PathBuf::from(db), PathBuf::from(stash))
}

enum LineOutcome {
    Next,
    Quit,
}

#[cfg(test)]
fn run_stdin<I, S>(sess: &mut AdminSession<'_>, lines: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut failed = false;
    for line in lines {
        match run(sess, line.as_ref()) {
            Ok(LineOutcome::Next) => {}
            Ok(LineOutcome::Quit) => break,
            Err(e) => {
                eprintln!("kadmin.local: {e}");
                failed = true;
            }
        }
    }
    i32::from(failed)
}

fn run_stdin_reader<R: BufRead>(sess: &mut AdminSession<'_>, reader: R) -> i32 {
    let mut failed = false;
    for line in reader.lines() {
        let line = match line {
            Ok(s) => s,
            Err(e) => {
                eprintln!("kadmin.local: {e}");
                failed = true;
                if e.kind() == io::ErrorKind::InvalidData {
                    continue;
                }
                break;
            }
        };
        match run(sess, &line) {
            Ok(LineOutcome::Next) => {}
            Ok(LineOutcome::Quit) => break,
            Err(e) => {
                eprintln!("kadmin.local: {e}");
                failed = true;
            }
        }
    }
    i32::from(failed)
}

fn run(sess: &mut AdminSession<'_>, line: &str) -> Result<LineOutcome, String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(LineOutcome::Next);
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts.first().copied() {
        Some("q" | "quit" | "exit") => Ok(LineOutcome::Quit),
        Some("listprincs" | "list_principals") => {
            for id in sess.list_ids() {
                println!("{id}");
            }
            Ok(LineOutcome::Next)
        }
        Some("getprinc" | "get_principal") => {
            let spec = parts.get(1).ok_or("getprinc <name>")?;
            let name = parse_name(sess, spec)?;
            let p = sess.get_principal_id(&name).map_err(|e| e.to_string())?;
            println!("Principal: {p}");
            Ok(LineOutcome::Next)
        }
        Some("addprinc" | "add_principal") => {
            let a = parse_kadmin_args(&parts[1..])?;
            let name = parse_name(sess, &a.name)?;
            if a.randkey {
                if a.etypes.is_empty() {
                    sess.create_randkey(&name).map_err(|e| e.to_string())?;
                } else {
                    sess.create_randkey_etypes(&name, &a.etypes)
                        .map_err(|e| e.to_string())?;
                }
            } else {
                let pw = a.pw.clone().map_or_else(password, Ok)?;
                if a.etypes.is_empty() {
                    sess.create_password(&name, pw.as_bytes())
                        .map_err(|e| e.to_string())?;
                } else {
                    sess.create_password_etypes(&name, pw.as_bytes(), &a.etypes)
                        .map_err(|e| e.to_string())?;
                }
            }
            apply_optional_fields(sess, &name, &a).map(|()| LineOutcome::Next)
        }
        Some("delprinc" | "delete_principal") => {
            let spec = parts.get(1).ok_or("delprinc <name>")?;
            let name = parse_name(sess, spec)?;
            sess.delete(&name)
                .map_err(|e| e.to_string())
                .map(|()| LineOutcome::Next)
        }
        Some("cpw" | "change_password") => {
            let a = parse_kadmin_args(&parts[1..])?;
            let name = parse_name(sess, &a.name)?;
            if a.randkey {
                sess.chrand(&name)
                    .map_err(|e| e.to_string())
                    .map(|()| LineOutcome::Next)
            } else {
                let pw = a.pw.clone().map_or_else(password, Ok)?;
                sess.change_password(&name, pw.as_bytes())
                    .map_err(|e| e.to_string())
                    .map(|()| LineOutcome::Next)
            }
        }
        Some("ktadd") => {
            let a = parse_kadmin_args(&parts[1..])?;
            let ktpath = a.ktpath.as_deref().ok_or("ktadd -k <file> <name>")?;
            let name = parse_name(sess, &a.name)?;
            let path = std::path::Path::new(ktpath);
            sess.ktadd_local(&name, !a.norandkey, |added| merge_write_keytab(path, added))
                .map(|_| LineOutcome::Next)
                .map_err(|e| e.to_string())
        }
        Some("modprinc" | "modify_principal") => {
            let a = parse_kadmin_args(&parts[1..])?;
            let name = parse_name(sess, &a.name)?;
            apply_optional_fields(sess, &name, &a).map(|()| LineOutcome::Next)
        }
        Some("addpol" | "add_policy") => {
            let n = parts.get(1).ok_or("addpol <name>")?;
            sess.add_policy(n);
            Ok(LineOutcome::Next)
        }
        Some("getpol" | "get_policy") => {
            let n = parts.get(1).ok_or("getpol <name>")?;
            let p = sess.get_policy(n).map_err(|e| e.to_string())?;
            println!("Policy: {p}");
            Ok(LineOutcome::Next)
        }
        Some("setstr") => {
            let princ = parts.get(1).ok_or("setstr <princ> <key> <val>")?;
            let key = parts.get(2).ok_or("setstr key")?;
            let val = parts.get(3).ok_or("setstr val")?;
            let name = parse_name(sess, princ)?;
            sess.set_string_attr(&name, key, val)
                .map_err(|e| e.to_string())
                .map(|()| LineOutcome::Next)
        }
        Some("getstrs") => {
            let spec = parts.get(1).ok_or("getstrs <name>")?;
            let name = parse_name(sess, spec)?;
            for (k, v) in sess.string_attrs(&name).map_err(|e| e.to_string())? {
                println!("{k}: {v}");
            }
            Ok(LineOutcome::Next)
        }
        Some(other) => Err(format!("unknown {other}")),
        None => Ok(LineOutcome::Next),
    }
}

fn merge_write_keytab(path: &std::path::Path, added: &Keytab) -> Result<(), String> {
    let mut kt = match std::fs::read(path) {
        Ok(b) => Keytab::parse(&b).map_err(|e| e.to_string())?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Keytab::default(),
        Err(e) => return Err(e.to_string()),
    };
    let n = kt.entries.len();
    for e in &added.entries {
        kt.entries.push(krb5_protocol::KeytabEntry {
            realm: e.realm.clone(),
            name: e.name.clone(),
            timestamp: e.timestamp,
            kvno: e.kvno,
            key: e.key.clone(),
        });
    }
    kt.unparsed.extend(
        added
            .unparsed
            .iter()
            .map(|(i, b)| (i.saturating_add(n), b.clone())),
    );
    if kt.version == 0 {
        kt.version = 0x0502;
    }
    kt.write_file(path).map_err(|e| e.to_string())
}

fn parse_name(sess: &AdminSession<'_>, spec: &str) -> Result<PrincipalName, String> {
    let full = if spec.contains('@') {
        spec.to_owned()
    } else {
        format!("{}@{}", spec, sess.realm())
    };
    parse_principal(&full).map(|(n, _)| n)
}

fn password() -> Result<String, String> {
    std::env::var("KRB5_PASSWORD").map_err(|_| "set KRB5_PASSWORD".into())
}

fn apply_optional_fields(
    sess: &mut AdminSession<'_>,
    name: &PrincipalName,
    a: &KadminArgs,
) -> Result<(), String> {
    if a.attr_set != 0 || a.attr_clear != 0 {
        let mut attrs = sess.principal_attributes(name).map_err(|e| e.to_string())?;
        attrs |= a.attr_set;
        attrs &= !a.attr_clear;
        sess.modify_attributes(name, Some(attrs))
            .map_err(|e| e.to_string())?;
    }
    if let Some(pol) = &a.policy {
        sess.set_policy(name, pol).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sess_pair() -> (krb5_kdc::PrincipalStore, krb5_kdc::Acl) {
        krb5_kdc::bootstrap_documented().unwrap()
    }

    #[test]
    fn unknown_verb_is_error() {
        let (mut store, acl) = sess_pair();
        let mut sess = AdminSession::local(&mut store, &acl, krb5_kdc::documented_admin_id());
        assert!(run(&mut sess, "nope").is_err());
    }

    #[test]
    fn getstrs_prints_set_attr() {
        let (mut store, acl) = sess_pair();
        let mut sess = AdminSession::local(&mut store, &acl, krb5_kdc::documented_admin_id());
        run(&mut sess, "setstr user m5k m5v").unwrap();
        run(&mut sess, "getstrs user").unwrap();
        let attrs = sess
            .string_attrs(&krb5_types::PrincipalName::new(
                krb5_types::PrincipalName::NT_PRINCIPAL,
                ["user"],
            ))
            .unwrap();
        assert!(
            attrs.iter().any(|(k, v)| k == "m5k" && v == "m5v"),
            "{attrs:?}"
        );
    }

    #[test]
    fn stdin_nope_then_quit_exits_1() {
        let (mut store, acl) = sess_pair();
        let mut sess = AdminSession::local(&mut store, &acl, krb5_kdc::documented_admin_id());
        assert_eq!(run_stdin(&mut sess, ["nope", "q"]), 1);
        assert_eq!(run_stdin(&mut sess, ["nope", "quit"]), 1);
        assert_eq!(run_stdin(&mut sess, ["nope", "exit"]), 1);
    }

    #[test]
    fn stdin_quit_stops_before_later_failure() {
        let (mut store, acl) = sess_pair();
        let mut sess = AdminSession::local(&mut store, &acl, krb5_kdc::documented_admin_id());
        assert_eq!(run_stdin(&mut sess, ["q"]), 0);
        assert_eq!(run_stdin(&mut sess, ["q", "nope"]), 0);
        assert!(matches!(run(&mut sess, "quit"), Ok(LineOutcome::Quit)));
    }

    #[test]
    fn stdin_invalid_utf8_exits_1() {
        let (mut store, acl) = sess_pair();
        let mut sess = AdminSession::local(&mut store, &acl, krb5_kdc::documented_admin_id());
        let rc = run_stdin_reader(&mut sess, std::io::Cursor::new(b"\xff\nq\n"));
        assert_eq!(rc, 1);
        let (mut store, acl) = sess_pair();
        let mut sess = AdminSession::local(&mut store, &acl, krb5_kdc::documented_admin_id());
        let rc = run_stdin_reader(&mut sess, std::io::Cursor::new(b"\xff\nnope\nq\n"));
        assert_eq!(rc, 1);
    }

    struct InjectedErr {
        kind: io::ErrorKind,
        n: u32,
    }
    impl io::Read for InjectedErr {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            self.n += 1;
            assert!(self.n < 8, "IO error must break the stdin loop");
            Err(io::Error::new(self.kind, "injected"))
        }
    }

    #[test]
    fn stdin_read_error_breaks() {
        let (mut store, acl) = sess_pair();
        let mut sess = AdminSession::local(&mut store, &acl, krb5_kdc::documented_admin_id());
        let rc = run_stdin_reader(
            &mut sess,
            io::BufReader::new(InjectedErr {
                kind: io::ErrorKind::Other,
                n: 0,
            }),
        );
        assert_eq!(rc, 1);
    }

    #[test]
    fn merge_write_refuses_unparseable() {
        let dir = std::env::temp_dir().join(format!(
            "kt-refuse-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("bad.keytab");
        std::fs::write(&path, b"not-a-keytab").unwrap();
        let added = Keytab::default();
        assert!(merge_write_keytab(&path, &added).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"not-a-keytab");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
