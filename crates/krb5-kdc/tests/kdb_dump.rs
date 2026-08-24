//! MIT `kdb5_util` dump parser, KDB usage-0 crypto, and dump/load CLI.
//!
//! Drives the shipped codec on the committed 1.22.2 golden (not a
//! reimplementation, not hardcoded key bytes).

use std::path::PathBuf;
use std::process::Command;

use krb5_crypto::{kdb_decrypt_key, string_to_key, EncryptionType, KeyUsage};
use krb5_kdc::{
    dump_store, load_dump, master_key_from_password, parse_dump, KDB_DUMP_VERSION,
    KDB_REQUIRES_PRE_AUTH, TL_LAST_PWD_CHANGE, TL_MOD_PRINC,
};
use krb5_types::PrincipalName;

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
fn krb5_kdb_cli_load_and_dump_content() {
    let dir = std::env::temp_dir().join(format!(
        "krb5-kdb-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let dumped = dir.join("rust.dump");
    let golden = traces().join("mit-dump-v7.txt");
    let bin = env!("CARGO_BIN_EXE_krb5-kdb");

    let load = Command::new(bin)
        .args(["load", golden.to_str().unwrap()])
        .env("KRB5_MASTER_PASSWORD", "masterpassword")
        .env("KRB5_KDC_DB", &db)
        .env("KRB5_KDC_STASH", &stash)
        .output()
        .expect("run load");
    let load_out = String::from_utf8_lossy(&load.stdout);
    let load_err = String::from_utf8_lossy(&load.stderr);
    assert!(load.status.success(), "load failed: {load_out}{load_err}");
    assert!(
        load_out.contains("ok load version=7"),
        "load stdout must report version: {load_out}"
    );
    assert!(
        load_out.contains("principals=7"),
        "load stdout must report principal count: {load_out}"
    );
    assert!(load_out.contains("realm=KERBER.TEST"));

    let dump = Command::new(bin)
        .args([
            "dump",
            dumped.to_str().unwrap(),
            "--from-dump",
            golden.to_str().unwrap(),
        ])
        .env("KRB5_MASTER_PASSWORD", "masterpassword")
        .output()
        .expect("run dump");
    let dump_out = String::from_utf8_lossy(&dump.stdout);
    let dump_err = String::from_utf8_lossy(&dump.stderr);
    assert!(dump.status.success(), "dump failed: {dump_out}{dump_err}");
    assert!(
        dump_out.contains("ok dump version=7"),
        "dump stdout: {dump_out}"
    );
    let written = std::fs::read_to_string(&dumped).expect("read rust.dump");
    assert!(
        written.starts_with("kdb5_util load_dump version 7\n"),
        "dumped file header"
    );
    assert!(written.contains("princ\t"));
    assert!(written.contains("user@KERBER.TEST"));
    assert!(written.contains("pauser@KERBER.TEST"));
    assert!(written.contains("host/testhost.kerber.test@KERBER.TEST"));
    let _ = std::fs::remove_dir_all(&dir);
}
