//! W1-C C1: MIT built-in password-quality modules (`dict`, `empty`, `princ`)
//! on create and on change. Compiles at `370461b` (parent-red).

use krb5_kdc::{
    Error, NamedPolicy, PWQUAL_DICT, PWQUAL_EMPTY, PWQUAL_PRINC, PrincipalStore, TEST_REALM,
    TEST_USER, bootstrap_documented,
};
use krb5_types::PrincipalName;

fn user() -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER])
}

fn name(s: &str) -> PrincipalName {
    PrincipalName::new(PrincipalName::NT_PRINCIPAL, [s])
}

fn rejected(r: Result<(), Error>) -> String {
    match r {
        Err(Error::PasswordPolicy(s)) => s,
        other => panic!("expected PasswordPolicy, got {other:?}"),
    }
}

fn scratch_dir(name: &str) -> std::path::PathBuf {
    let scratch = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("CARGO_TARGET_DIR")
                .map(|p| std::path::PathBuf::from(p).join("test-krb5"))
        })
        .or_else(|| std::env::var_os("KERBER_SCRATCH").map(std::path::PathBuf::from))
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/test-krb5")
        });
    let dir = scratch.join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `pwqual_empty.c:38-44`: the only module that runs without a policy, on
/// create (`svr_principal.c:370`) and on change (`svr_principal.c:1282`).
/// Live MIT: `addprinc -pw "" e` → `Empty passwords are not allowed`.
#[test]
fn c1_empty_password_is_rejected_without_a_policy() {
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

/// `pwqual_princ.c:40-55`: only with a policy; the realm compares first with
/// the plain `KADM5_PASS_Q_DICT` text, then every component with the module
/// message, all `strcasecmp`. Live MIT: `-pw pqu -policy pq pqu` →
/// `Password may not match principal name`; `-pw kerber.test` → `Password
/// is in the password dictionary`.
#[test]
fn c1_principal_component_and_realm_match_are_rejected_only_with_a_policy() {
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

/// `pwqual_dict.c:136-150,215-230`: `[realms] dict_file` words, one per
/// `\n`-terminated line, `strcasecmp` exact match, only with a policy;
/// a missing file continues without a dictionary (`init_dict` ENOENT).
/// Live MIT: `correcthorse` / `CorrectHorse` rejected under a policy,
/// `correcthorse` accepted with none, `correcthorse1` accepted.
#[test]
fn c1_dict_file_words_are_rejected_case_insensitively_only_with_a_policy() {
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
