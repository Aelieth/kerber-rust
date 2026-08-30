//! Local kadm5 verbs against a dump/stash (MIT `kadmin.local`).
//!
//! Usage: krb5-kadmin.local [-q command]
//! DB: `KRB5_KDC_DB` + `KRB5_KDC_STASH`. Passwords from `KRB5_PASSWORD`.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{self, BufRead};
use std::path::PathBuf;

use krb5_admin::AdminSession;
use krb5_kdc::{Acl, load_store, save_store};
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
    let actor = std::env::var("KRB5_KADMIN_PRINCIPAL")
        .unwrap_or_else(|_| format!("admin@{}", store.realm()));
    let acl = acl_file(&actor);
    let mut sess = AdminSession::local(&mut store, &acl, actor);
    if queued.is_empty() {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            let Ok(line) = line else {
                break;
            };
            if let Err(e) = run(&mut sess, &line) {
                eprintln!("kadmin.local: {e}");
            }
        }
    } else {
        for c in queued {
            if let Err(e) = run(&mut sess, &c) {
                eprintln!("kadmin.local: {e}");
                std::process::exit(1);
            }
        }
    }
    drop(sess);
    save_store(&store, &db, &stash).unwrap_or_else(|e| {
        eprintln!("kadmin.local: save: {e}");
        std::process::exit(1);
    });
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

fn acl_file(actor: &str) -> Acl {
    if let Ok(p) = std::env::var("KRB5_ACL_FILE")
        && let Ok(t) = std::fs::read_to_string(p)
    {
        return Acl::parse(&t);
    }
    Acl::allow_admin(actor)
}

fn run(sess: &mut AdminSession<'_>, line: &str) -> Result<(), String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(());
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    match parts.first().copied() {
        Some("q" | "quit" | "exit") => std::process::exit(0),
        Some("listprincs" | "list_principals") => {
            for id in sess.list_ids() {
                println!("{id}");
            }
            Ok(())
        }
        Some("getprinc" | "get_principal") => {
            let spec = parts.get(1).ok_or("getprinc <name>")?;
            let name = parse_name(sess, spec)?;
            let p = sess.get_principal_id(&name).map_err(|e| e.to_string())?;
            println!("Principal: {p}");
            Ok(())
        }
        Some("addprinc" | "add_principal") => {
            let spec = parts.last().ok_or("addprinc <name>")?;
            let name = parse_name(sess, spec)?;
            let pw = password()?;
            sess.create_password(&name, pw.as_bytes())
                .map_err(|e| e.to_string())
        }
        Some("delprinc" | "delete_principal") => {
            let spec = parts.get(1).ok_or("delprinc <name>")?;
            let name = parse_name(sess, spec)?;
            sess.delete(&name).map_err(|e| e.to_string())
        }
        Some("cpw" | "change_password") => {
            let spec = parts.last().ok_or("cpw <name>")?;
            let name = parse_name(sess, spec)?;
            let pw = password()?;
            sess.change_password(&name, pw.as_bytes())
                .map_err(|e| e.to_string())
        }
        Some("ktadd") => {
            let spec = parts.last().ok_or("ktadd <name>")?;
            let ktpath = parts
                .windows(2)
                .find(|w| w[0] == "-k")
                .and_then(|w| w.get(1))
                .ok_or("ktadd -k <file> <name>")?;
            let name = parse_name(sess, spec)?;
            let kt: Keytab = sess.ktadd(&name).map_err(|e| e.to_string())?;
            kt.write_file(std::path::Path::new(*ktpath))
                .map_err(|e| e.to_string())
        }
        Some("modprinc" | "modify_principal") => {
            let spec = parts.last().ok_or("modprinc <name>")?;
            let name = parse_name(sess, spec)?;
            sess.modify_attributes(&name, None)
                .map_err(|e| e.to_string())
        }
        Some("addpol" | "add_policy") => {
            let n = parts.get(1).ok_or("addpol <name>")?;
            sess.add_policy(n);
            Ok(())
        }
        Some("getpol" | "get_policy") => {
            let n = parts.get(1).ok_or("getpol <name>")?;
            let p = sess.get_policy(n).map_err(|e| e.to_string())?;
            println!("Policy: {p}");
            Ok(())
        }
        Some("setstr") => {
            let princ = parts.get(1).ok_or("setstr <princ> <key> <val>")?;
            let key = parts.get(2).ok_or("setstr key")?;
            let val = parts.get(3).ok_or("setstr val")?;
            let name = parse_name(sess, princ)?;
            sess.set_string_attr(&name, key, val)
                .map_err(|e| e.to_string())
        }
        Some(other) => Err(format!("unknown {other}")),
        None => Ok(()),
    }
}

fn parse_name(_sess: &AdminSession<'_>, spec: &str) -> Result<PrincipalName, String> {
    if spec.contains('@') {
        parse_principal(spec).map(|(n, _)| n)
    } else {
        Ok(PrincipalName::new(PrincipalName::NT_PRINCIPAL, [spec]))
    }
}

fn password() -> Result<String, String> {
    std::env::var("KRB5_PASSWORD").map_err(|_| "set KRB5_PASSWORD".into())
}
