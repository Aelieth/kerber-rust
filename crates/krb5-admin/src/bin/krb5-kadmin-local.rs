//! Local kadm5 verbs against a dump/stash (MIT `kadmin.local`).
//!
//! Usage: krb5-kadmin.local [-q command]
//! DB: `KRB5_KDC_DB` + `KRB5_KDC_STASH`. Passwords from `KRB5_PASSWORD`.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::io::{self, BufRead};
use std::path::PathBuf;

use krb5_admin::{AdminSession, KadminArgs, load_acl_file, parse_kadmin_args};
use krb5_kdc::load_store;
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
    let acl = load_acl_file(
        &actor,
        std::env::var_os("KRB5_ACL_FILE")
            .as_deref()
            .map(std::path::Path::new),
    )
    .unwrap_or_else(|e| {
        eprintln!("kadmin.local: {e}");
        std::process::exit(1);
    });
    let mut sess = AdminSession::local(&mut store, &acl, actor);
    if queued.is_empty() {
        let stdin = io::stdin();
        let mut failed = false;
        for line in stdin.lock().lines() {
            let Ok(line) = line else {
                break;
            };
            if let Err(e) = run(&mut sess, &line) {
                eprintln!("kadmin.local: {e}");
                failed = true;
            }
        }
        if failed {
            std::process::exit(1);
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
            let a = parse_kadmin_args(&parts[1..])?;
            let name = parse_name(sess, &a.name)?;
            if a.randkey {
                sess.create_randkey(&name).map_err(|e| e.to_string())?;
            } else {
                let pw = a.pw.clone().map_or_else(password, Ok)?;
                sess.create_password(&name, pw.as_bytes())
                    .map_err(|e| e.to_string())?;
            }
            apply_optional_fields(sess, &name, &a)
        }
        Some("delprinc" | "delete_principal") => {
            let spec = parts.get(1).ok_or("delprinc <name>")?;
            let name = parse_name(sess, spec)?;
            sess.delete(&name).map_err(|e| e.to_string())
        }
        Some("cpw" | "change_password") => {
            let a = parse_kadmin_args(&parts[1..])?;
            let name = parse_name(sess, &a.name)?;
            if a.randkey {
                sess.chrand(&name).map_err(|e| e.to_string())
            } else {
                let pw = a.pw.clone().map_or_else(password, Ok)?;
                sess.change_password(&name, pw.as_bytes())
                    .map_err(|e| e.to_string())
            }
        }
        Some("ktadd") => {
            let a = parse_kadmin_args(&parts[1..])?;
            let ktpath = a.ktpath.as_deref().ok_or("ktadd -k <file> <name>")?;
            let name = parse_name(sess, &a.name)?;
            let path = std::path::Path::new(ktpath);
            sess.ktadd_local(&name, !a.norandkey, |added| merge_write_keytab(path, added))
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
        Some("modprinc" | "modify_principal") => {
            let a = parse_kadmin_args(&parts[1..])?;
            let name = parse_name(sess, &a.name)?;
            apply_optional_fields(sess, &name, &a)
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

fn merge_write_keytab(path: &std::path::Path, added: &Keytab) -> Result<(), String> {
    let mut kt = std::fs::read(path)
        .ok()
        .and_then(|b| Keytab::parse(&b).ok())
        .unwrap_or_default();
    for e in &added.entries {
        kt.entries.push(krb5_protocol::KeytabEntry {
            realm: e.realm.clone(),
            name: e.name.clone(),
            timestamp: e.timestamp,
            kvno: e.kvno,
            key: e.key.clone(),
        });
    }
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

    #[test]
    fn unknown_verb_is_error() {
        let (mut store, acl) = krb5_kdc::bootstrap_documented().unwrap();
        let mut sess = AdminSession::local(&mut store, &acl, krb5_kdc::documented_admin_id());
        assert!(run(&mut sess, "nope").is_err());
    }
}
