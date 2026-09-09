//! R12: `KRB5_TL_DB_ARGS` is rejected at put (`kdb5.c:893-945`, `kdb_db2.c:817-822`).

use krb5_kdc::{
    TEST_REALM, TEST_USER, TlData, UlogEntry, bootstrap_documented, dump_store, load_dump,
    save_store,
};
use krb5_types::PrincipalName;

fn db_arg(nul: bool) -> TlData {
    let mut contents = b"foo=bar".to_vec();
    if nul {
        contents.push(0);
    }
    TlData {
        ty: 0x7fff,
        contents,
    }
}

fn inject_tl_32767(text: &str, princ: &str, arg: &[u8]) -> String {
    let mut out = String::new();
    for line in text.lines() {
        if line.starts_with("princ\t") && line.contains(&format!("\t{princ}\t")) {
            let (body, end) = line.strip_suffix(';').map_or((line, ""), |b| (b, ";"));
            let mut f: Vec<String> = body.split('\t').map(str::to_owned).collect();
            let n_tl: usize = f[3].parse().expect("n_tl");
            f[3] = (n_tl + 1).to_string();
            let hex = arg.iter().fold(String::new(), |mut s, b| {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
                s
            });
            f.splice(15..15, ["32767".into(), arg.len().to_string(), hex]);
            out.push_str(&f.join("\t"));
            out.push_str(end);
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

#[test]
fn load_dump_with_tl_32767_names_princ_and_arg() {
    let (store, _) = bootstrap_documented().unwrap();
    let text = dump_store(&store, b"masterpassword").unwrap();
    let poisoned = inject_tl_32767(&text, "user@KERBER.TEST", b"foo=bar\0");
    let Err(err) = load_dump(&poisoned, b"masterpassword") else {
        panic!("load must reject TL 32767");
    };
    let msg = err.to_string();
    assert!(
        msg.contains("Unsupported argument \"foo=bar\" for db2"),
        "{msg}"
    );
    assert!(msg.contains("user@KERBER.TEST"), "{msg}");
}

#[test]
fn iprop_db_args_entry_is_absent_after_apply() {
    let (mut store, _) = bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let mut p = store.get_name(&user).unwrap().clone();
    p.name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["r12iprop"]);
    p.tl_data.push(db_arg(true));
    let id = p.id();
    store.apply_updates(&[UlogEntry {
        sno: store.serial().saturating_add(1),
        time: 1,
        name: id.clone(),
        deleted: false,
        princ: Some(p),
    }]);
    assert!(
        store.get(&id).is_none(),
        "iprop put with 0x7fff must not insert"
    );
}

#[test]
fn merge_tl_db_args_leaves_entry_and_file_unchanged() {
    let dir = std::env::temp_dir().join(format!(
        "krb5-r12-db-args-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (mut store, _) = bootstrap_documented().unwrap();
    save_store(&store, &db, &stash).unwrap();
    store.persist_paths = Some((db.clone(), stash.clone()));
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
    let before = store.get_name(&user).unwrap().clone();
    let file_before = std::fs::read(&db).unwrap();
    let err = store
        .merge_tl_data_in(&user, TEST_REALM, &[db_arg(true)])
        .unwrap_err();
    assert!(err.to_string().contains("foo=bar"), "{err}");
    let three = store
        .merge_tl_data_in(
            &user,
            TEST_REALM,
            &[db_arg(true), db_arg(true), db_arg(true)],
        )
        .unwrap_err();
    assert!(three.to_string().contains("foo=bar"), "{three}");
    let nul = store
        .merge_tl_data_in(&user, TEST_REALM, &[db_arg(false)])
        .unwrap_err();
    assert!(nul.to_string().contains("Invalid argument"), "{nul}");
    let after = store.get_name(&user).unwrap();
    assert_eq!(after.attributes, before.attributes);
    assert_eq!(after.max_life, before.max_life);
    assert_eq!(after.tl_data, before.tl_data);
    assert_eq!(std::fs::read(&db).unwrap(), file_before);
    let _ = std::fs::remove_dir_all(&dir);
}
