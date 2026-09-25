//! MIT built-in password-quality modules (`dict`, `empty`, `princ`)
//! on create and on change. Compiles at `370461b` (parent-red).
//! MIT 1.22.2 password history as the oracle. The fixture
//! `tests/traces/kdb/mit-dump-v7-history.txt` is a `kdb5_util dump` after
//! `addpol -history 3 hp`, `addprinc -pw s3cret1 -policy hp hpuser`,
//! `cpw -pw s3cret2`, `cpw -pw s3cret3`: hpuser's `KRB5_TL_KADM_DATA` carries
//! the two old passwords' keys encrypted under the lazily created
//! `kadmin/history` key (kvno 2), which is itself under the master key.

use krb5_crypto::{EncryptionType, kdb_decrypt_key, string_to_key};
use krb5_kdc::testrealm::{TEST_REALM, TEST_USER, bootstrap_documented};
use krb5_kdc::{
    Error, KADM5_POLICY, NamedPolicy, OsaPrincEnt, PWQUAL_DICT, PWQUAL_EMPTY, PWQUAL_PRINC,
    PrincipalStore, decrypt_history_entry, load_dump, master_key_from_password, parse_dump,
};

use krb5_testkit::{scratch_dir, user};
use krb5_types::PrincipalName;
use std::path::PathBuf;

fn name(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

fn rejected(r: Result<(), Error>) -> String {
    match r {
        Err(Error::PasswordPolicy(s)) => s,
        other => panic!("expected PasswordPolicy, got {other:?}"),
    }
}

#[test]
fn empty_password_is_rejected_without_a_policy() {
    let (mut store, _acl) = bootstrap_documented().unwrap();
    assert_eq!(
        rejected(store.check_new_password(&name("nopol"), None, b"")),
        PWQUAL_EMPTY
    );
    assert!(store.get_name(&user()).unwrap().pw_policy.is_none());
    assert_eq!(rejected(store.set_password(&user(), b"")), PWQUAL_EMPTY);
    // Unchanged key: the same password still verifies.
    store
        .set_password(&user(), b"userpassword")
        .expect("a non-empty password is still accepted");
}

#[test]
fn principal_component_and_realm_match_are_rejected_only_with_a_policy() {
    let (mut store, _acl) = bootstrap_documented().unwrap();
    store.put_policy(NamedPolicy::new("pq"));
    let pqu = name("pqu");
    assert_eq!(
        rejected(store.check_new_password(&pqu, Some("pq"), b"PQU")),
        PWQUAL_PRINC
    );
    assert_eq!(
        rejected(store.check_new_password(
            &pqu,
            Some("pq"),
            TEST_REALM.to_ascii_lowercase().as_bytes()
        )),
        PWQUAL_DICT
    );
    // Without a policy the same passwords pass (dict/princ skip).
    store.check_new_password(&pqu, None, b"PQU").unwrap();
    store
        .check_new_password(&pqu, None, TEST_REALM.as_bytes())
        .unwrap();
    // An unknown policy name is "no policy" (get_policy → have_polent false).
    store
        .check_new_password(&pqu, Some("gone"), b"PQU")
        .unwrap();
    // Substrings are not matches.
    store.check_new_password(&pqu, Some("pq"), b"pqu1").unwrap();
    // Multi-component names: every component is compared.
    let host = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "kdc.kerber.test"]);
    assert_eq!(
        rejected(store.check_new_password(&host, Some("pq"), b"KDC.kerber.TEST")),
        PWQUAL_PRINC
    );
    // On change: the bound policy makes the modules run.
    store
        .set_principal_policy(&user(), Some("pq".into()))
        .unwrap();
    assert_eq!(
        rejected(store.set_password(&user(), TEST_USER.to_ascii_uppercase().as_bytes())),
        PWQUAL_PRINC
    );
}

#[test]
fn dict_file_words_are_rejected_case_insensitively_only_with_a_policy() {
    let dir = scratch_dir("c1-dict");
    let dict = dir.join("dict.txt");
    std::fs::write(&dict, "zebra\ncorrecthorse\napple\nunterminated").unwrap();
    let mut conf = krb5_config::KdcConf {
        dict_file: Some(dict.clone()),
        ..Default::default()
    };
    let (mut store, _acl) = bootstrap_documented().unwrap();
    store.apply_kdc_conf(&conf).unwrap();
    store.put_policy(NamedPolicy::new("pq"));
    let u = name("dictu");
    assert_eq!(
        rejected(store.check_new_password(&u, Some("pq"), b"correcthorse")),
        PWQUAL_DICT
    );
    assert_eq!(
        rejected(store.check_new_password(&u, Some("pq"), b"CorrectHorse")),
        PWQUAL_DICT
    );
    store.check_new_password(&u, None, b"correcthorse").unwrap();
    store
        .check_new_password(&u, Some("pq"), b"correcthorse1")
        .unwrap();
    // The last line has no '\n' so it is not a word (init_dict memchr loop).
    store
        .check_new_password(&u, Some("pq"), b"unterminated")
        .unwrap();
    // A policy floor comes first (check_against_policy before the modules).
    let mut floor = NamedPolicy::new("long");
    floor.min_length = 20;
    store.put_policy(floor);
    assert_eq!(
        rejected(store.check_new_password(&u, Some("long"), b"correcthorse")),
        "min_length 20"
    );
    // ENOENT: no dictionary, and apply_kdc_conf still succeeds.
    conf.dict_file = Some(dir.join("missing.txt"));
    let mut store2: PrincipalStore = bootstrap_documented().unwrap().0;
    store2.apply_kdc_conf(&conf).unwrap();
    store2.put_policy(NamedPolicy::new("pq"));
    store2
        .check_new_password(&u, Some("pq"), b"correcthorse")
        .unwrap();
    // On change with the bound policy the dictionary applies too.
    store
        .set_principal_policy(&user(), Some("pq".into()))
        .unwrap();
    assert_eq!(rejected(store.set_password(&user(), b"APPLE")), PWQUAL_DICT);
    let _ = std::fs::remove_dir_all(&dir);
}

const MASTER_PW: &[u8] = b"masterpassword";

fn fixture() -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/traces/kdb/mit-dump-v7-history.txt");
    std::fs::read_to_string(p).expect("history fixture")
}

fn hpuser_keys(password: &[u8]) -> Vec<(i32, Vec<u8>)> {
    let salt =
        PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["hpuser"]).default_salt("KERBER.TEST");
    [
        EncryptionType::Aes256CtsHmacSha384192,
        EncryptionType::Aes128CtsHmacSha256128,
        EncryptionType::Aes256CtsHmacSha196,
        EncryptionType::Aes128CtsHmacSha196,
    ]
    .into_iter()
    .map(|et| {
        (
            et.to_iana(),
            string_to_key(et, password, &salt, None)
                .unwrap()
                .as_bytes()
                .to_vec(),
        )
    })
    .collect()
}

#[test]
fn mit_kadm_data_decodes_and_its_history_decrypts_under_the_history_key() {
    let dump = parse_dump(&fixture()).unwrap();
    let mkey = master_key_from_password(
        "KERBER.TEST",
        MASTER_PW,
        EncryptionType::Aes256CtsHmacSha384192,
    )
    .unwrap();
    let hist = dump
        .princ("kadmin/history@KERBER.TEST")
        .expect("kadmin/history in the dump");
    let hist_kd = &hist.keys[0];
    assert_eq!(hist_kd.kvno, 2, "create_hist re-randomizes to kvno 2");
    assert_eq!(
        hist_kd.slots[0].ty, 20,
        "handle->params.enctype = the master enctype"
    );
    let hist_raw = kdb_decrypt_key(&mkey, &hist_kd.slots[0].contents).unwrap();
    let hist_key =
        krb5_crypto::ProtocolKey::from_bytes(EncryptionType::Aes256CtsHmacSha384192, &hist_raw)
            .unwrap();

    let hp = dump.princ("hpuser@KERBER.TEST").unwrap();
    let osa = OsaPrincEnt::from_tl(&hp.tl_data)
        .unwrap()
        .expect("KADM_DATA");
    assert_eq!(osa.bound_policy(), Some("hp"));
    assert_eq!(osa.aux_attributes & KADM5_POLICY, KADM5_POLICY);
    assert_eq!(osa.admin_history_kvno, 2);
    assert_eq!(osa.old_keys.len(), 2, "history 3 keeps two old passwords");
    assert_eq!(
        osa.old_key_next, 0,
        "two entries fill the ring; next wraps to 0"
    );

    let entries = osa.old_keys_oldest_first();
    let expect = [hpuser_keys(b"s3cret1"), hpuser_keys(b"s3cret2")];
    for (entry, want) in entries.iter().zip(expect.iter()) {
        let keys = decrypt_history_entry(entry, &hist_key);
        assert_eq!(keys.len(), 4, "four keysalts per password");
        for k in &keys {
            let (_, raw) = want
                .iter()
                .find(|(et, _)| *et == k.etype.to_iana())
                .expect("etype");
            assert_eq!(
                k.key.as_bytes(),
                raw.as_slice(),
                "etype {}",
                k.etype.to_iana()
            );
            assert!(k.salt_type.is_none(), "normal salt: key_data_ver 1");
        }
    }
    // Under the master key the same bytes are garbage: the history key is real.
    assert!(decrypt_history_entry(entries[0], &mkey).is_empty());
}

#[test]
fn loading_the_mit_history_dump_enforces_mit_reuse_and_keeps_the_record() {
    let store = load_dump(&fixture(), MASTER_PW).unwrap();
    let hp = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["hpuser"]);
    let p = store.get_name(&hp).unwrap();
    assert_eq!(
        p.pw_policy.as_deref(),
        Some("hp"),
        "policy read from KADM_DATA"
    );
    assert_eq!(
        p.key_history.len(),
        8,
        "two old passwords × four keys, decrypted"
    );
    assert_eq!(p.kadm.admin_history_kvno, 2);
    assert_eq!(p.kadm.old_keys.len(), 2);
    // MIT refused s3cret1 and s3cret2 live ("Cannot reuse password"); the current is s3cret3.
    for reused in [b"s3cret1".as_slice(), b"s3cret2", b"s3cret3"] {
        assert!(
            store.check_password_quality(&hp, reused).is_err(),
            "{} must be a reuse",
            String::from_utf8_lossy(reused)
        );
    }
    assert!(store.check_password_quality(&hp, b"s3cret4").is_ok());
    let history = PrincipalName::new(PrincipalName::NT_SRV_INST, ["kadmin", "history"]);
    let h = store.get_name(&history).expect("kadmin/history loaded");
    assert_eq!(h.max_life, 64);
    assert_eq!(h.attributes, 0);
    assert_eq!(h.keys.len(), 1);
    assert_eq!(h.keys[0].kvno, 2);
}
