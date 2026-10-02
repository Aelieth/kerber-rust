//! MIT `kdb5_util` dump parser and KDB usage-0 crypto (the CLI is `kdb5_util.rs`).
//!
//! Drives the shipped codec on the committed 1.22.2 golden (not a
//! reimplementation, not hardcoded key bytes).
//! A put that carries `KRB5_TL_DB_ARGS` is refused.
//! MIT `extract_db_args_from_tl_data` (`kdb5.c:893-945`): the `KRB5_TL_DB_ARGS` records are
//! pulled out of the entry as the put's `db_args`, and one without a trailing NUL is `EINVAL`.
//! MIT `krb5_db2_put_principal` (`kdb_db2.c:817-822`): DB2 refuses any `db_args` with `EINVAL`.

use krb5_crypto::{EncryptionType, KeyUsage, kdb_decrypt_key, string_to_key};
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented};
use krb5_kdc::{
    KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_SVR, KDB_DUMP_VERSION, KDB_LOCKDOWN_KEYS,
    KDB_REQUIRES_HW_AUTH, KDB_REQUIRES_PRE_AUTH, TL_LAST_PWD_CHANGE, TL_MOD_PRINC, TlData,
    UlogEntry, dump_store, dump_store_iprop, load_dump, master_key_from_password, parse_dump,
    save_store,
};

use krb5_testkit::scratch_dir;
use krb5_types::PrincipalName;
use std::path::PathBuf;

fn traces() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/traces/kdb")
}

fn golden_v7() -> String {
    std::fs::read_to_string(traces().join("mit-dump-v7.txt")).expect("golden v7")
}

fn golden_v6() -> String {
    std::fs::read_to_string(traces().join("mit-dump-v6.txt")).expect("golden v6")
}

#[test]
fn bootstrap_locks_down_krbtgt_and_master_key() {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let tgt = store.krbtgt().expect("krbtgt");
    assert_eq!(
        tgt.attributes & KDB_LOCKDOWN_KEYS,
        KDB_LOCKDOWN_KEYS,
        "krbtgt LOCKDOWN_KEYS at bootstrap, got {:#x}",
        tgt.attributes
    );
    let text = dump_store(&store, b"masterpassword").expect("dump");
    let dump = parse_dump(&text).expect("parse");
    assert_eq!(
        dump.princ("krbtgt/KERBER.TEST@KERBER.TEST")
            .expect("krbtgt dump")
            .attributes,
        KDB_LOCKDOWN_KEYS,
        "MIT kdb5_create krbtgt attributes"
    );
    assert_eq!(
        dump.princ("K/M@KERBER.TEST").expect("K/M dump").attributes,
        KDB_DISALLOW_ALL_TIX | KDB_LOCKDOWN_KEYS,
        "MIT kdb5_create K/M attributes"
    );
}

#[test]
fn parse_golden_pins_header_field_order_and_requires_preauth() {
    let text = golden_v7();
    let first = text.lines().next().expect("header");
    assert_eq!(first, "kdb5_util load_dump version 7");
    let dump = parse_dump(&text).expect("parse v7");
    assert_eq!(dump.version, KDB_DUMP_VERSION);
    assert_eq!(dump.version, 7);
    for name in [
        "user@KERBER.TEST",
        "pauser@KERBER.TEST",
        "host/testhost.kerber.test@KERBER.TEST",
        "nosvr@KERBER.TEST",
        "hwuser@KERBER.TEST",
    ] {
        assert!(dump.princ(name).is_some(), "missing {name}");
    }
    let pauser = dump.princ("pauser@KERBER.TEST").unwrap();
    // Captured kadmin.local getprinc: Attributes: REQUIRES_PRE_AUTH → 128, not 0x8.
    assert_eq!(pauser.attributes, 128);
    assert_eq!(pauser.attributes, KDB_REQUIRES_PRE_AUTH);
    let getprinc = std::fs::read_to_string(traces().join("getprinc-pauser.txt")).unwrap();
    assert!(
        getprinc.contains("Attributes: REQUIRES_PRE_AUTH"),
        "getprinc capture must pin REQUIRES_PRE_AUTH: {getprinc}"
    );
    assert!(!getprinc.contains("DISALLOW_ALL_TIX"));
    let user = dump.princ("user@KERBER.TEST").unwrap();
    assert_eq!(user.attributes, 0);
    let host = dump.princ("host/testhost.kerber.test@KERBER.TEST").unwrap();
    assert_eq!(host.db_len, 38);
    assert_eq!(host.keys.len(), 4);
    let nosvr = dump.princ("nosvr@KERBER.TEST").unwrap();
    assert_eq!(nosvr.attributes, KDB_DISALLOW_SVR);
    let hwuser = dump.princ("hwuser@KERBER.TEST").unwrap();
    assert_eq!(hwuser.attributes, KDB_REQUIRES_HW_AUTH);
    let pwprau = dump.princ("pwprau@KERBER.TEST").unwrap();
    assert_ne!(
        nosvr.keys[0].slots[0].contents, user.keys[0].slots[0].contents,
        "nosvr keys must be MIT-derived, not a clone of user"
    );
    assert_ne!(
        hwuser.keys[0].slots[0].contents, pwprau.keys[0].slots[0].contents,
        "hwuser keys must be MIT-derived, not a clone of pwprau"
    );
}

#[test]
fn parse_r18_version_6_same_princ_grammar() {
    let text = golden_v6();
    assert_eq!(
        text.lines().next().unwrap(),
        "kdb5_util load_dump version 6"
    );
    let dump = parse_dump(&text).expect("parse v6");
    assert_eq!(dump.version, 6);
    assert_eq!(
        dump.princ("pauser@KERBER.TEST").unwrap().attributes,
        KDB_REQUIRES_PRE_AUTH
    );
}

#[test]
fn truncated_or_reordered_dump_fails() {
    let text = golden_v7();
    let cut = &text[..text.len().saturating_sub(40)];
    assert!(parse_dump(cut).is_err(), "truncated dump must fail");

    let mut lines: Vec<String> = text.lines().map(ToOwned::to_owned).collect();
    let pauser_i = lines
        .iter()
        .position(|l| l.contains("pauser@KERBER.TEST"))
        .unwrap();
    let mut fields: Vec<&str> = lines[pauser_i].split('\t').collect();
    // Swap namelen and n_tl_data so the name-length check fails (both 4 on
    // pauser would make an n_tl/n_key swap a no-op).
    fields.swap(2, 3);
    lines[pauser_i] = fields.join("\t");
    let reordered = lines.join("\n");
    assert!(
        parse_dump(&reordered).is_err(),
        "field-reordered princ must fail parse"
    );
}

#[test]
fn decrypt_pauser_key_data_equals_string_to_key() {
    assert_eq!(
        KeyUsage::new(0).unwrap_err(),
        krb5_crypto::Error::InvalidKeyUsage
    );
    let dump = parse_dump(&golden_v7()).unwrap();
    let mkey = master_key_from_password(
        "KERBER.TEST",
        b"masterpassword",
        EncryptionType::Aes256CtsHmacSha384192,
    )
    .unwrap();
    let pauser = dump.princ("pauser@KERBER.TEST").unwrap();
    let slot = pauser
        .keys
        .iter()
        .find(|k| k.slots.first().is_some_and(|s| s.ty == 20))
        .expect("etype 20 key_data")
        .slots
        .first()
        .unwrap();
    let raw = kdb_decrypt_key(&mkey, &slot.contents).expect("kdb decrypt");
    let salt =
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["pauser"]).default_salt("KERBER.TEST");
    let expect = string_to_key(
        EncryptionType::Aes256CtsHmacSha384192,
        b"preauthpw",
        &salt,
        None,
    )
    .unwrap();
    assert_eq!(
        raw,
        expect.as_bytes(),
        "KDB usage-0 decrypt must equal string_to_key(preauthpw)"
    );

    let user = dump.princ("user@KERBER.TEST").unwrap();
    let user_slot = user
        .keys
        .iter()
        .find(|k| k.slots.first().is_some_and(|s| s.ty == 20))
        .unwrap()
        .slots
        .first()
        .unwrap();
    let user_raw = kdb_decrypt_key(&mkey, &user_slot.contents).unwrap();
    let user_salt =
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]).default_salt("KERBER.TEST");
    let user_expect = string_to_key(
        EncryptionType::Aes256CtsHmacSha384192,
        b"userpassword",
        &user_salt,
        None,
    )
    .unwrap();
    assert_eq!(user_raw, user_expect.as_bytes());

    let km = dump.princ("K/M@KERBER.TEST").unwrap();
    let km_raw = kdb_decrypt_key(&mkey, &km.keys[0].slots[0].contents).unwrap();
    assert_eq!(km_raw, mkey.as_bytes());
}

#[test]
fn load_dump_store_keys_match_string_to_key() {
    let store = load_dump(&golden_v7(), b"masterpassword").expect("load");
    assert_eq!(store.realm(), "KERBER.TEST");
    let pauser = store.get("pauser@KERBER.TEST").expect("pauser loaded");
    assert!(pauser.requires_preauth);
    assert_eq!(pauser.attributes, KDB_REQUIRES_PRE_AUTH);
    let got = pauser
        .key_for(EncryptionType::Aes256CtsHmacSha384192)
        .expect("etype 20");
    let salt =
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["pauser"]).default_salt("KERBER.TEST");
    let expect = string_to_key(
        EncryptionType::Aes256CtsHmacSha384192,
        b"preauthpw",
        &salt,
        None,
    )
    .unwrap();
    assert_eq!(got.key.as_bytes(), expect.as_bytes());

    let user = store.get("user@KERBER.TEST").unwrap();
    assert!(!user.requires_preauth);
    let host = store
        .get("host/testhost.kerber.test@KERBER.TEST")
        .expect("host");
    assert!(!host.keys.is_empty());
}

#[test]
fn dump_write_header_grammar_and_tl_data() {
    let store = load_dump(&golden_v7(), b"masterpassword").unwrap();
    let text = dump_store(&store, b"masterpassword").expect("dump");
    assert!(
        text.starts_with("kdb5_util load_dump version 7\n"),
        "writer must emit version 7, got {:?}",
        text.lines().next()
    );
    let iprop = dump_store_iprop(&store, b"masterpassword").expect("iprop dump");
    assert!(
        iprop.starts_with("ipropx 1 "),
        "iprop dump must start ipropx 1 <sno> <sec> 0, got {:?}",
        iprop.lines().next()
    );
    parse_dump(&iprop).expect("parse ipropx dump");
    let reparsed = parse_dump(&text).expect("reparse rust dump");
    assert_eq!(reparsed.version, 7);
    let pauser = reparsed.princ("pauser@KERBER.TEST").unwrap();
    assert_eq!(pauser.attributes, KDB_REQUIRES_PRE_AUTH);
    assert!(
        pauser.tl_data.iter().any(|t| t.ty == TL_LAST_PWD_CHANGE),
        "must preserve KRB5_TL_LAST_PWD_CHANGE"
    );
    assert!(
        pauser.tl_data.iter().any(|t| t.ty == TL_MOD_PRINC),
        "must preserve KRB5_TL_MOD_PRINC"
    );
    assert!(
        pauser
            .tl_data
            .iter()
            .any(|t| t.ty == krb5_kdc::TL_KADM_DATA),
        "must preserve KRB5_TL_KADM_DATA from the MIT dump"
    );
    for name in [
        "user@KERBER.TEST",
        "pauser@KERBER.TEST",
        "host/testhost.kerber.test@KERBER.TEST",
        "K/M@KERBER.TEST",
    ] {
        assert!(reparsed.princ(name).is_some(), "dump missing {name}");
    }
    // Re-encrypted keys must still decrypt to the same long-term key.
    let again = load_dump(&text, b"masterpassword").unwrap();
    let a = store
        .get("pauser@KERBER.TEST")
        .unwrap()
        .key_for(EncryptionType::Aes256CtsHmacSha384192)
        .unwrap()
        .key
        .as_bytes();
    let b = again
        .get("pauser@KERBER.TEST")
        .unwrap()
        .key_for(EncryptionType::Aes256CtsHmacSha384192)
        .unwrap()
        .key
        .as_bytes();
    assert_eq!(a, b);
}

#[test]
fn dump_load_preserves_sid_rid_not_dummy() {
    let store = load_dump(&golden_v7(), b"masterpassword").unwrap();
    assert_ne!(
        store.domain_sid().to_sddl(),
        krb5_types::pac::RpcSid::dummy_domain().to_sddl()
    );
    let krbtgt = store.get("krbtgt/KERBER.TEST@KERBER.TEST").expect("krbtgt");
    assert_eq!(krbtgt.rid, krb5_kdc::RID_KRBTGT);
    let user = store.get("user@KERBER.TEST").unwrap();
    assert_ne!(user.rid, 0);
    let sid = store.domain_sid().clone();
    let user_rid = user.rid;
    let text = dump_store(&store, b"masterpassword").unwrap();
    let reparsed = parse_dump(&text).unwrap();
    assert!(
        reparsed
            .princ("user@KERBER.TEST")
            .unwrap()
            .tl_data
            .iter()
            .any(|t| t.ty == krb5_kdc::TL_KERBER_SID),
        "dump must carry SID/RID tl_data"
    );
    let again = load_dump(&text, b"masterpassword").unwrap();
    assert_eq!(again.domain_sid().to_sddl(), sid.to_sddl());
    assert_eq!(again.get("user@KERBER.TEST").unwrap().rid, user_rid);
    assert_eq!(
        again.get("krbtgt/KERBER.TEST@KERBER.TEST").unwrap().rid,
        krb5_kdc::RID_KRBTGT
    );
}

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
    let dir = scratch_dir("krb5-r12-db-args");
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

/// MIT `k5beta7_common` writes a principal's own lifetimes: a `max_life` of 0 (no limit of the
/// principal's own; the realm's applies when a ticket is issued) and a `max_renewable_life` of 0
/// stay 0 through a dump and a load, where the realm's `max_life` used to be written.
#[test]
fn dump_keeps_a_principals_own_zero_lifetimes() {
    let mut store = load_dump(&golden_v7(), b"masterpassword").unwrap();
    assert_ne!(
        store.policy().max_life,
        0,
        "the realm has a max_life to stand in"
    );
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
    let pauser = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["pauser"]);
    for (name, life, rlife) in [(&user, 0, 0), (&pauser, 3600, 7200)] {
        store
            .apply_admin_fields(
                name,
                krb5_kdc::AdminFields {
                    max_life: Some(life),
                    max_renewable_life: Some(rlife),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    let text = dump_store(&store, b"masterpassword").unwrap();
    let parsed = parse_dump(&text).unwrap();
    let written = |n: &str| {
        let p = parsed.princ(n).unwrap();
        (p.max_life, p.max_renewable_life)
    };
    assert_eq!(written("user@KERBER.TEST"), (0, 0));
    assert_eq!(written("pauser@KERBER.TEST"), (3600, 7200));
    let again = load_dump(&text, b"masterpassword").unwrap();
    let held = |n: &str| {
        let p = again.get(n).unwrap();
        (p.max_life, p.max_renewable_life)
    };
    assert_eq!(held("user@KERBER.TEST"), (0, 0));
    assert_eq!(held("pauser@KERBER.TEST"), (3600, 7200));
}
