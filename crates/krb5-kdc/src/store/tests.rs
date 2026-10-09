//! In-memory store tests (private-bound; moved out of `store.rs`).

use super::rid::sid_from_random_bytes;
use super::transit::hierarchical_intermediates;
use super::*;
use crate::kdb_dump::{TL_LAST_ADMIN_UNLOCK, TL_LAST_PWD_CHANGE, TL_MOD_PRINC};
use krb5_crypto::EncryptionType;
use krb5_types::transited::hierarchical_walk_realms;
use std::collections::BTreeMap;

const TEST_REALM_STR: &str = "KERBER.TEST";

const A128: EncryptionType = EncryptionType::Aes128CtsHmacSha196;

const A256: EncryptionType = EncryptionType::Aes256CtsHmacSha196;

/// A principal with keys `(etype, kvno)` stored in the given order.
fn keyed(keys: &[(EncryptionType, u32)]) -> Principal {
    let (mut store, _) = crate::testrealm::bootstrap_documented().unwrap();
    let name = crate::testrealm::documented_host();
    let entries = keys
        .iter()
        .map(|&(e, v)| KeyEntry::new(e, random_key(e).unwrap(), v))
        .collect();
    {
        let id = store.canonical_id(&name, TEST_REALM_STR).unwrap();
        store.map.get_mut(&id).unwrap().keys = entries;
    }
    store.get_name(&name).unwrap().clone()
}

fn admin_tl_u32(p: &Principal, ty: i32) -> u32 {
    p.tl_data
        .iter()
        .find(|t| t.ty == ty)
        .and_then(|t| t.contents.get(..4))
        .map_or(0, |b| u32::from_le_bytes(b.try_into().unwrap()))
}

fn plant_stale_admin_tl(p: &mut Principal, ts: u32) {
    p.tl_data
        .retain(|t| t.ty != TL_LAST_PWD_CHANGE && t.ty != TL_MOD_PRINC);
    p.tl_data.push(TlData {
        ty: TL_LAST_PWD_CHANGE,
        contents: ts.to_le_bytes().to_vec(),
    });
    let mut modp = ts.to_le_bytes().to_vec();
    modp.extend_from_slice(b"kadmin/admin@KERBER.TEST\0");
    p.tl_data.push(TlData {
        ty: TL_MOD_PRINC,
        contents: modp,
    });
}

fn max_kvno(store: &PrincipalStore, name: &PrincipalName) -> u32 {
    store
        .get_name(name)
        .and_then(|p| p.keys.iter().map(|k| k.kvno).max())
        .unwrap_or(0)
}

fn as_req_sname_etype(
    cname: &PrincipalName,
    etype: i32,
) -> Result<krb5_types::AsReq, krb5_protocol::Error> {
    krb5_protocol::as_req_sname(
        cname.clone(),
        crate::testrealm::TEST_REALM,
        500,
        None,
        PrincipalName::krbtgt(crate::testrealm::TEST_REALM),
        vec![etype],
    )
}

/// MIT `krb5_dbe_def_search_enctype` (`kdb_default.c:60-61`): a requested etype outside the
/// permitted set is `NO_PERMITTED_KEY` before the key list is read, even when the
/// principal holds such a key.
#[test]
fn find_enctype_non_permitted_request_is_no_permitted_key_up_front() {
    let p = keyed(&[(A128, 1)]);
    let only256 = |e: EncryptionType| e == A256;
    assert_eq!(
        p.find_enctype(Some(A128), 0, only256).err(),
        Some(KeyLookup::NoPermittedKey)
    );
    // And an absent-but-permitted etype is NO_MATCHING_KEY.
    assert_eq!(
        p.find_enctype(Some(A256), 0, only256).err(),
        Some(KeyLookup::NoMatchingKey)
    );
}

/// `:65-67` kvno 0 is the highest kvno only; `:82-86` non-permitted keys
/// of that kvno are skipped; `:92-94` only-non-permitted matches →
/// `NO_PERMITTED_KEY`, no key at that kvno → `NO_MATCHING_KEY`.
#[test]
fn find_enctype_top_kvno_skips_non_permitted_and_names_the_miss() {
    let p = keyed(&[(A128, 2), (A256, 2), (A256, 1)]);
    let all = |_: EncryptionType| true;
    let only256 = |e: EncryptionType| e == A256;
    let only128 = |e: EncryptionType| e == A128;
    // Stored order wins between permitted keys of the top kvno.
    assert_eq!(p.find_enctype(None, 0, all).unwrap().etype, A128);
    // The aes128 stored first is skipped when not permitted.
    let k = p.find_enctype(None, 0, only256).unwrap();
    assert_eq!((k.etype, k.kvno), (A256, 2));
    // kvno 0 never reaches down to kvno 1: with aes128 the only permitted
    // etype and aes256 at kvno 1 irrelevant, the top kvno still answers.
    assert_eq!((p.find_enctype(None, 0, only128).unwrap().kvno), 2);
    // Explicit kvno 1 holds aes256 only.
    assert_eq!(
        p.find_enctype(None, 1, only128).err(),
        Some(KeyLookup::NoPermittedKey)
    );
    assert_eq!(
        p.find_enctype(None, 3, all).err(),
        Some(KeyLookup::NoMatchingKey)
    );
    assert_eq!(
        p.find_enctype(Some(A128), 1, all).err(),
        Some(KeyLookup::NoMatchingKey)
    );
    // An empty key set is NO_MATCHING_KEY (`:62-63`).
    let mut empty = p.clone();
    empty.keys.clear();
    assert_eq!(
        empty.find_enctype(None, 0, all).err(),
        Some(KeyLookup::NoMatchingKey)
    );
}

#[test]
fn chrand_stamps_last_pwd_and_mod() {
    let (mut store, _) = crate::testrealm::bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::testrealm::TEST_USER]);
    let mut p = store.get_name(&user).unwrap().clone();
    plant_stale_admin_tl(&mut p, 1_000);
    store.debug_insert(p);
    store.chrand(&user).unwrap();
    let after = store.get_name(&user).unwrap();
    assert_ne!(
        admin_tl_u32(after, TL_LAST_PWD_CHANGE),
        1_000,
        "chrand must stamp last-pwd"
    );
    assert_ne!(
        admin_tl_u32(after, TL_MOD_PRINC),
        1_000,
        "chrand must stamp mod"
    );
}

#[test]
fn set_keys_stamps_last_pwd_and_mod() {
    let (mut store, _) = crate::testrealm::bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::testrealm::TEST_USER]);
    let mut p = store.get_name(&user).unwrap().clone();
    let etype = p.best_key().unwrap().etype;
    plant_stale_admin_tl(&mut p, 1_000);
    store.debug_insert(p);
    let key = random_key(etype).unwrap();
    store
        .set_keys(&user, vec![KeyEntry::new(etype, key, 0)], 0)
        .unwrap();
    let after = store.get_name(&user).unwrap();
    assert_ne!(
        admin_tl_u32(after, TL_LAST_PWD_CHANGE),
        1_000,
        "setkey must stamp last-pwd"
    );
    assert_ne!(
        admin_tl_u32(after, TL_MOD_PRINC),
        1_000,
        "setkey must stamp mod"
    );
}

#[test]
fn set_keys_clears_requires_pwchange_and_fail_count() {
    let (mut store, _) = crate::testrealm::bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::testrealm::TEST_USER]);
    let mut p = store.get_name(&user).unwrap().clone();
    p.attributes |= KDB_REQUIRES_PWCHANGE;
    p.fail_auth_count = 4;
    let etype = p.best_key().unwrap().etype;
    let key = p.best_key().unwrap().key.clone();
    store.debug_insert(p);
    store
        .set_keys(&user, vec![KeyEntry::new(etype, key, 0)], 0)
        .unwrap();
    let after = store.get_name(&user).unwrap();
    assert_eq!(after.attributes & KDB_REQUIRES_PWCHANGE, 0);
    assert_eq!(after.fail_auth_count, 0);
}

#[test]
fn kdc_conf_wins_over_krb5_conf_for_enctype_knobs() {
    // MIT builds the KDC profile with kdc.conf before krb5.conf, so a knob
    // in both is the kdc.conf value. The bin applies krb5.conf first.
    let mut store = PrincipalStore::new("KERBER.TEST");
    let krb5 = krb5_config::Krb5Conf::parse(
        "[libdefaults]\n allow_rc4 = false\n allow_weak_crypto = true\n",
    )
    .unwrap();
    store.apply_libdefaults(&krb5);
    assert!(
        store.policy.allow_weak_crypto,
        "krb5.conf allow_weak_crypto must reach the KDC"
    );
    let kdc = krb5_config::KdcConf::parse("[libdefaults]\n allow_rc4 = true\n").unwrap();
    store.apply_kdc_conf(&kdc).unwrap();
    assert!(
        store.policy.allow_rc4,
        "kdc.conf allow_rc4 wins over krb5.conf"
    );
    assert!(
        store.policy.allow_weak_crypto,
        "kdc.conf did not set allow_weak_crypto, so krb5.conf's value survives"
    );
}

/// MIT's KDC profile is kdc.conf before krb5.conf: its `spake_preauth_groups` wins, and the words
/// split at commas too; `spake_preauth_kdc_challenge` comes from kdc.conf's `[kdcdefaults]`.
#[test]
fn spake_groups_and_challenge_reach_the_policy_like_mit() {
    use krb5_crypto::SpakeGroup;
    let mut store = PrincipalStore::new("KERBER.TEST");
    let krb5 =
        krb5_config::Krb5Conf::parse("[libdefaults]\n    spake_preauth_groups = P-256\n").unwrap();
    store.apply_libdefaults(&krb5);
    assert_eq!(store.policy.spake_preauth_groups, [SpakeGroup::P256]);
    assert_eq!(store.policy.spake_kdc().unwrap().challenge, None);
    let kdc = krb5_config::KdcConf::parse(
        "[libdefaults]\n    spake_preauth_groups = P-384, edwards25519,P-256 edwards25519\n\
         [kdcdefaults]\n    spake_preauth_kdc_challenge = edwards25519\n",
    )
    .unwrap();
    store.apply_kdc_conf(&kdc).unwrap();
    assert_eq!(
        store.policy.spake_preauth_groups,
        [SpakeGroup::Edwards25519, SpakeGroup::P256]
    );
    assert_eq!(
        store.policy.spake_kdc().unwrap().challenge,
        Some(SpakeGroup::Edwards25519)
    );
}

#[test]
fn apply_kdc_conf_sets_ticket_policy() {
    let mut store = PrincipalStore::new("KERBER.TEST");
    let conf = krb5_config::KdcConf::parse(
        r"
[libdefaults]
    allow_weak_crypto = yes
    spake_preauth_groups = P-256

[realms]
    KERBER.TEST = {
        max_life = 1h 30m
        max_renewable_life = 2d 0h 0m 0s
        requires_preauth = no
        restrict_anonymous_to_tgt = true
        pkinit_require_freshness = true
        encrypted_challenge_indicator = encrypted_challenge
        pkinit_indicator = pkinit
        spake_preauth_indicator = spake
        host_based_services = host
        no_host_referral = imap
    }
",
    )
    .unwrap();
    store.apply_kdc_conf(&conf).unwrap();
    assert_eq!(store.policy.host_based_services, "host");
    assert_eq!(store.policy.no_host_referral, "imap");
    assert_eq!(store.policy.max_life, 5400);
    assert_eq!(store.policy.max_renewable_life, 2 * 86400);
    assert_eq!(store.policy.realm_max_renewable_life, 2 * 86400);
    assert!(!store.policy.requires_preauth);
    assert!(store.policy.restrict_anon);
    assert!(store.policy.pkinit_require_freshness);
    assert_eq!(
        store.policy.encrypted_challenge_indicator.as_deref(),
        Some("encrypted_challenge")
    );
    assert_eq!(store.policy.pkinit_indicators, vec!["pkinit".to_string()]);
    assert_eq!(
        store.policy.spake_preauth_indicators,
        vec!["spake".to_string()]
    );
    assert!(store.policy.allow_weak_crypto);
    assert!(!store.policy.allow_rc4);
    assert!(store.policy.reject_bad_transit);
    assert_eq!(
        store.policy.spake_preauth_groups,
        vec![krb5_crypto::SpakeGroup::P256]
    );
    let rc4 = krb5_config::KdcConf::parse(
        r"
[libdefaults]
    allow_rc4 = true
    permitted_enctypes = aes256-cts arcfour-hmac
[realms]
    KERBER.TEST = {
        supported_enctypes = aes256-cts:normal rc4-hmac:normal
    }
",
    )
    .unwrap();
    store.apply_kdc_conf(&rc4).unwrap();
    assert!(store.policy.allow_rc4);
    assert!(
        store
            .policy
            .supported_enctypes
            .contains(&EncryptionType::Rc4Hmac)
    );
    assert!(store.policy.etype_permitted(EncryptionType::Rc4Hmac));
}

#[test]
fn transit_allowed_capaths_dot_and_hierarchical() {
    let mut p = Policy::default();
    assert!(p.transit_allowed("A.TEST", "A.TEST", &[]));
    assert!(
        p.transit_allowed("A.TEST", "C.TEST", &[String::from("C.TEST")]),
        "first hop: server realm is an endpoint"
    );
    assert!(
        !p.transit_allowed(
            "A.TEST",
            "C.TEST",
            &[String::from("B.TEST"), String::from("C.TEST")]
        ),
        "B.TEST is not hierarchical between A.TEST and C.TEST"
    );
    p.capaths
        .entry("A.TEST".into())
        .or_default()
        .insert("C.TEST".into(), vec!["B.TEST".into()]);
    assert!(p.transit_allowed(
        "A.TEST",
        "C.TEST",
        &[String::from("B.TEST"), String::from("C.TEST")]
    ));
    p.capaths
        .entry("A.TEST".into())
        .or_default()
        .insert("C.TEST".into(), vec![".".into()]);
    assert!(!p.transit_allowed("A.TEST", "C.TEST", &[String::from("B.TEST")]));
}

#[test]
fn compressed_transited_cannot_hide_hop() {
    let t = krb5_types::TransitedEncoding {
        tr_type: 1,
        contents: krb5_types::OctetString::from(b"EX.COM,B.".to_vec()),
    };
    let hops = t.realms_for("A.EX.COM", "C.EX.COM").unwrap();
    assert!(
        hops.iter().any(|h| h == "B.EX.COM"),
        "compressed B. must expand to B.EX.COM: {hops:?}"
    );
    let mut p = Policy::default();
    p.capaths
        .entry("A.EX.COM".into())
        .or_default()
        .insert("C.EX.COM".into(), vec!["EX.COM".into()]);
    assert!(
        !p.transit_allowed("A.EX.COM", "C.EX.COM", &hops),
        "B.EX.COM is not on the capaths list"
    );
    p.capaths
        .entry("A.EX.COM".into())
        .or_default()
        .insert("C.EX.COM".into(), vec!["EX.COM".into(), "B.EX.COM".into()]);
    assert!(p.transit_allowed("A.EX.COM", "C.EX.COM", &hops));
}

#[test]
fn hierarchical_intermediates_huge_realm_is_empty() {
    assert_eq!(
        hierarchical_intermediates("A.EX.COM", "C.EX.COM"),
        vec!["EX.COM".to_string(), "C.EX.COM".to_string()]
    );
    let big = format!("{}A.TEST", "A.".repeat(30_000));
    assert_eq!(
        hierarchical_intermediates("A.TEST", &big),
        [] as [String; 0]
    );
    assert_eq!(
        hierarchical_intermediates(&big, "C.TEST"),
        [] as [String; 0]
    );
}

#[test]
fn hierarchical_walk_realms_matches_mit_rtree_hier() {
    assert_eq!(
        hierarchical_walk_realms("A.EX.COM", "C.EX.COM"),
        vec![
            "A.EX.COM".to_string(),
            "EX.COM".to_string(),
            "C.EX.COM".to_string()
        ]
    );
    assert_eq!(
        hierarchical_walk_realms("KERBER.TEST", "X.SUB.KERBER.TEST"),
        vec![
            "KERBER.TEST".to_string(),
            "SUB.KERBER.TEST".to_string(),
            "X.SUB.KERBER.TEST".to_string()
        ]
    );
    assert_eq!(
        hierarchical_walk_realms("FOO.COM", "BAR.ORG"),
        vec![
            "FOO.COM".to_string(),
            "COM".to_string(),
            "ORG".to_string(),
            "BAR.ORG".to_string()
        ]
    );
    assert_eq!(
        hierarchical_walk_realms("ABC.EXAMPLE.COM", "BC.EXAMPLE.COM"),
        vec![
            "ABC.EXAMPLE.COM".to_string(),
            "EXAMPLE.COM".to_string(),
            "BC.EXAMPLE.COM".to_string()
        ]
    );
    let empty: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    assert_eq!(
        walk_realm_instances(&empty, "A.EX.COM", "C.EX.COM"),
        hierarchical_walk_realms("A.EX.COM", "C.EX.COM")
    );
    let big = format!("{}A.TEST", "A.".repeat(30_000));
    assert_eq!(hierarchical_walk_realms("A.TEST", &big), [] as [String; 0]);
    assert_eq!(hierarchical_walk_realms(&big, "C.TEST"), [] as [String; 0]);
}

#[test]
fn space_separated_capaths_accepts_each_hop() {
    let mut p = Policy::default();
    p.capaths
        .entry("A.TEST".into())
        .or_default()
        .insert("C.TEST".into(), vec!["B.TEST".into(), "D.TEST".into()]);
    assert!(p.transit_allowed(
        "A.TEST",
        "C.TEST",
        &[String::from("B.TEST"), String::from("D.TEST")]
    ));
    assert!(!p.transit_allowed("A.TEST", "C.TEST", &[String::from("E.TEST")]));
}

#[test]
fn anonymous_crealm_transit_check_passes() {
    let p = Policy::default();
    assert!(p.transit_allowed(
        "WELLKNOWN:ANONYMOUS",
        "C.TEST",
        &[String::from("EVIL.TEST")]
    ));
}

#[test]
fn apply_kdc_conf_domain_sid() {
    let mut store = PrincipalStore::new("KERBER.TEST");
    let conf = krb5_config::KdcConf::parse(
        r"
[realms]
    KERBER.TEST = {
        domain_sid = S-1-5-21-891046300-1937985867-1481223175
    }
",
    )
    .unwrap();
    store.apply_kdc_conf(&conf).unwrap();
    assert_eq!(
        store.domain_sid().to_sddl(),
        "S-1-5-21-891046300-1937985867-1481223175"
    );
}

#[test]
fn apply_kdc_conf_rejects_bad_domain_sid() {
    let mut store = PrincipalStore::new("KERBER.TEST");
    let conf = krb5_config::KdcConf::parse(
        r"
[realms]
    KERBER.TEST = {
        domain_sid = not-a-sid
    }
",
    )
    .unwrap();
    assert!(store.apply_kdc_conf(&conf).is_err());
}

fn dict_conf(dict_file: &std::path::Path) -> krb5_config::KdcConf {
    krb5_config::KdcConf {
        dict_file: Some(dict_file.to_path_buf()),
        ..Default::default()
    }
}

#[test]
fn the_kdc_config_never_reads_the_dictionary() {
    // A directory opens but does not read (EISDIR): a path that read dict_file would fail.
    let dir = krb5_testkit::scratch_dir("krb5-pwqual-kdc");
    let conf = dict_conf(&dir);
    let mut store = PrincipalStore::new(TEST_REALM_STR);
    store.apply_kdc_conf(&conf).unwrap();
    assert!(store.pwqual_dict.is_none());
    let boot = PrincipalStore::bootstrap_with_kdc_conf(
        TEST_REALM_STR,
        "u",
        b"u-secret",
        "a",
        b"a-secret",
        Some(&conf),
    )
    .unwrap();
    assert!(boot.pwqual_dict.is_none());
    // The admin side reads it, and fails as MIT's kadm5_init does.
    let e = store.init_pwqual(Some(&conf)).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::IsADirectory);
    // kdb5_util create starts the admin side too, and fails before writing anything.
    let master = random_key(A256).unwrap();
    let created = crate::create::create_realm(TEST_REALM_STR, Some(&conf), &master, 1);
    assert!(
        matches!(&created, Err(Error::InvalidArgument(t)) if t.starts_with("kdc.conf dict_file ")),
        "{created:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pwqual_dict_words_are_init_dict_lines_matched_as_strcasecmp() {
    let dict = pwqual_dict::PwqualDict::from_bytes(
        b"zebra\nApple\npear\r\nspace \n\ncaf\xc3\xa9\nlat\xe9n\napple\nunterminated".to_vec(),
    )
    .unwrap();
    // `Apple` and `apple` are one word; the unterminated last line is none.
    assert_eq!(dict.word_count(), 7);
    let hits: [&[u8]; 8] = [
        b"zebra",
        b"ZEBRA",
        b"aPPLE",
        b"pear\r",
        b"space ",
        b"",
        b"CAF\xc3\xa9",
        b"LAT\xe9N",
    ];
    for w in hits {
        assert!(dict.contains(w), "{w:?}");
    }
    // ASCII folding only, as glibc's strcasecmp in the C and UTF-8 locales (live: MIT accepts
    // `CAFÉ` against `café`); bytes as they are, no trimming, no prefixes.
    let misses: [&[u8]; 7] = [
        b"unterminated",
        b"pear",
        b"space",
        b"zebr",
        b"zebras",
        b"CAF\xc3\x89",
        b"lat\xe8n",
    ];
    for w in misses {
        assert!(!dict.contains(w), "{w:?}");
    }
    let dir = krb5_testkit::scratch_dir("krb5-pwqual-open");
    let quiet = &mut |_: krb5_log::klog::Severity, _: &str| {};
    assert!(
        pwqual_dict::PwqualDict::open(None, quiet)
            .unwrap()
            .is_none()
    );
    assert!(
        pwqual_dict::PwqualDict::open(Some(&dir.join("missing")), quiet)
            .unwrap()
            .is_none()
    );
    std::fs::write(dir.join("one"), "no newline").unwrap();
    let one = pwqual_dict::PwqualDict::open(Some(&dir.join("one")), quiet)
        .unwrap()
        .unwrap();
    assert_eq!(one.word_count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_nul_inside_a_line_ends_that_word_and_shifts_the_rest() {
    // MIT `init_dict` (`lib/kadm5/srv/pwqual_dict.c:136-151`): newlines are counted, then each
    // word is a C string, so a NUL ends it and the words after it shift.
    let dict = pwqual_dict::PwqualDict::from_bytes(b"abc\0def\nxyz\nqrs\n".to_vec()).unwrap();
    assert!(dict.contains(b"abc"), "abc");
    assert!(dict.contains(b"DEF"), "def, ASCII-folded");
    assert!(dict.contains(b"xyz"), "xyz");
    assert!(!dict.contains(b"qrs"), "qrs shifted off the list");
    assert!(!dict.contains(b"abcdef"));
    let lead = pwqual_dict::PwqualDict::from_bytes(b"\0lead\nlast\n".to_vec()).unwrap();
    assert!(lead.contains(b"lead"));
    assert!(!lead.contains(b"last"), "last shifted off the list");
    assert!(lead.contains(b""), "a leading NUL is the empty word");
}

#[test]
fn iso8859_1_strcasecmp_folds_latin1_letters() {
    // MIT `word_compare` (`lib/kadm5/srv/pwqual_dict.c:64-68`): `strcasecmp` in an ISO-8859-1
    // locale folds E-acute. The C and UTF-8 locales do not (settled live). The process locale
    // is not changed: the fold is the one `from_bytes_folded` is given.
    let dict = pwqual_dict::PwqualDict::from_bytes_folded(
        b"caf\xe9\n".to_vec(),
        pwqual_dict::CaseFold::Latin1,
    )
    .unwrap();
    assert!(dict.contains(b"CAF\xe9"), "ASCII fold");
    assert!(
        dict.contains(b"caf\xc9"),
        "Latin-1 E-acute folds onto e-acute"
    );
    assert!(dict.contains(b"CAF\xc9"));
    let ascii = pwqual_dict::PwqualDict::from_bytes_folded(
        b"caf\xe9\n".to_vec(),
        pwqual_dict::CaseFold::Ascii,
    )
    .unwrap();
    assert!(ascii.contains(b"CAF\xe9"));
    assert!(
        !ascii.contains(b"caf\xc9"),
        "C and UTF-8 leave byte C9 alone"
    );
}

#[test]
fn case_fold_follows_the_named_codeset_only() {
    use pwqual_dict::{CaseFold, case_fold_for_locale};
    let latin = [
        "en_US.ISO-8859-1",
        "en_US.iso88591",
        "en_US.ISO8859-1",
        "latin1",
        "iso_8859-1",
        "en_US.ISO-8859-1@euro",
    ];
    for spec in latin {
        assert_eq!(case_fold_for_locale(spec), CaseFold::Latin1, "{spec}");
    }
    for spec in [
        "C",
        "C.UTF-8",
        "",
        "en_US",
        "en_US.ISO-8859-15",
        "en_US.utf8",
        "POSIX",
    ] {
        assert_eq!(case_fold_for_locale(spec), CaseFold::Ascii, "{spec}");
    }
}

#[test]
fn a_fifo_dict_file_with_a_writer_is_empty() {
    // MIT `init_dict` (`lib/kadm5/srv/pwqual_dict.c:120-133`): `fstat` reports 0 for a FIFO, so
    // the read takes no bytes. A FIFO with no writer blocks in `open` on both sides.
    let dir = krb5_testkit::scratch_dir("krb5-pwqual-fifo");
    let path = dir.join("fifo");
    let st = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .unwrap();
    assert!(st.success(), "mkfifo");
    let path_w = path.clone();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let writer = std::thread::spawn(move || {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path_w)
            .unwrap();
        let _ = rx.recv();
        drop(file);
    });
    let quiet = &mut |_: krb5_log::klog::Severity, _: &str| {};
    let started = std::time::Instant::now();
    let dict = pwqual_dict::PwqualDict::open(Some(&path), quiet)
        .unwrap()
        .unwrap();
    let _ = tx.send(());
    writer.join().unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(dict.word_count(), 0);
    assert!(!dict.contains(b"zebra"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pwqual_dict_reads_the_fstat_size_so_dev_zero_is_empty() {
    // A character device says 0 bytes and never ends: read as MIT reads it, it is an empty
    // dictionary at once, with no notice, as MIT says nothing for a file it opened (live: MIT's
    // kadmind starts and accepts any word).
    use krb5_log::klog::Severity;
    let zero = std::path::Path::new("/dev/zero");
    let mut notes: Vec<(Severity, String)> = Vec::new();
    let mut note = |severity: Severity, text: &str| notes.push((severity, text.to_owned()));
    let started = std::time::Instant::now();
    let dict = pwqual_dict::PwqualDict::open(Some(zero), &mut note)
        .unwrap()
        .unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(dict.word_count(), 0);
    let mut store = PrincipalStore::new(TEST_REALM_STR);
    store
        .init_pwqual_noting(Some(&dict_conf(zero)), &mut note)
        .unwrap();
    assert!(notes.is_empty(), "{notes:?}");
    store.put_policy(NamedPolicy::new("pq"));
    let u = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["dictu"]);
    store.check_new_password(&u, Some("pq"), b"zebra").unwrap();
}

#[test]
fn passwd_check_logs_a_module_refusal_and_not_a_policy_floor() {
    // MIT `passwd_check` (`lib/kadm5/srv/server_misc.c:114-134`): policy floors return before
    // the modules, and only a module refusal is logged.
    use krb5_log::klog::Severity;
    let mut store = PrincipalStore::new(TEST_REALM_STR);
    store.pwqual_dict = Some(std::sync::Arc::new(
        pwqual_dict::PwqualDict::from_bytes(b"secret\n".to_vec()).unwrap(),
    ));
    let mut floors = NamedPolicy::new("floors");
    floors.min_length = 4;
    floors.min_classes = 2;
    store.put_policy(floors);
    store.put_policy(NamedPolicy::new("open"));
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["sam"]);
    let notes = std::cell::RefCell::new(Vec::<(Severity, String)>::new());
    let mut note = |severity: Severity, text: &str| {
        notes.borrow_mut().push((severity, text.to_owned()));
    };
    let line = |module: &str, text: &str| {
        format!(
            "password quality module {module} rejected password for sam@{TEST_REALM_STR}: {text}"
        )
    };
    let logged = |module: &str, text: &str| [(Severity::Err, line(module, text))];

    let err = store
        .check_new_password_in(&name, TEST_REALM_STR, Some("floors"), b"ab", &mut note)
        .unwrap_err();
    assert!(matches!(err, Error::PasswordPolicy(t) if t == "min_length 4"));
    assert!(notes.borrow().is_empty(), "{:?}", notes.borrow());

    notes.borrow_mut().clear();
    let err = store
        .check_new_password_in(&name, TEST_REALM_STR, Some("floors"), b"aaaa", &mut note)
        .unwrap_err();
    assert!(matches!(err, Error::PasswordPolicy(t) if t == "min_classes 2"));
    assert!(notes.borrow().is_empty(), "{:?}", notes.borrow());

    store
        .check_new_password_in(&name, TEST_REALM_STR, Some("floors"), b"caf\xe9", &mut note)
        .unwrap();
    assert!(notes.borrow().is_empty(), "four bytes, lower plus other");

    notes.borrow_mut().clear();
    let err = store
        .check_new_password_in(&name, TEST_REALM_STR, Some("open"), b"Secret", &mut note)
        .unwrap_err();
    assert!(matches!(err, Error::PasswordPolicy(t) if t == PWQUAL_DICT));
    assert_eq!(notes.borrow().as_slice(), logged("dict", PWQUAL_DICT));

    notes.borrow_mut().clear();
    let err = store
        .check_new_password_in(
            &name,
            TEST_REALM_STR,
            Some("open"),
            b"secret\0trailing",
            &mut note,
        )
        .unwrap_err();
    assert!(matches!(err, Error::PasswordPolicy(t) if t == PWQUAL_DICT));
    assert_eq!(notes.borrow().as_slice(), logged("dict", PWQUAL_DICT));

    notes.borrow_mut().clear();
    let err = store
        .check_new_password_in(&name, TEST_REALM_STR, None, b"", &mut note)
        .unwrap_err();
    assert!(matches!(err, Error::PasswordPolicy(t) if t == PWQUAL_EMPTY));
    assert_eq!(notes.borrow().as_slice(), logged("empty", PWQUAL_EMPTY));

    notes.borrow_mut().clear();
    let err = store
        .check_new_password_in(&name, TEST_REALM_STR, Some("floors"), b"", &mut note)
        .unwrap_err();
    assert!(
        matches!(err, Error::PasswordPolicy(ref t) if t == "min_length 4"),
        "{err:?}"
    );
    assert!(
        notes.borrow().is_empty(),
        "empty under a length floor is not the empty module"
    );

    notes.borrow_mut().clear();
    let err = store
        .check_new_password_in(
            &name,
            TEST_REALM_STR,
            Some("open"),
            TEST_REALM_STR.as_bytes(),
            &mut note,
        )
        .unwrap_err();
    assert!(matches!(err, Error::PasswordPolicy(t) if t == PWQUAL_DICT));
    assert_eq!(notes.borrow().as_slice(), logged("princ", PWQUAL_DICT));

    notes.borrow_mut().clear();
    let err = store
        .check_new_password_in(&name, TEST_REALM_STR, Some("open"), b"Sam", &mut note)
        .unwrap_err();
    assert!(matches!(err, Error::PasswordPolicy(t) if t == PWQUAL_PRINC));
    assert_eq!(notes.borrow().as_slice(), logged("princ", PWQUAL_PRINC));

    let (mut live, _) = crate::testrealm::bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::testrealm::TEST_USER]);
    let mut hist = NamedPolicy::new("hist");
    hist.history = 1;
    live.put_policy(hist);
    live.set_principal_policy(&user, Some("hist".into()))
        .unwrap();
    live.set_password(&user, b"Fresh-secret-1").unwrap();
    notes.borrow_mut().clear();
    let realm = live.realm().to_owned();
    let err = live
        .check_password_quality_in(&user, &realm, b"Fresh-secret-1", &mut note)
        .unwrap_err();
    assert!(
        matches!(err, Error::PasswordPolicy(ref t) if t == "history"),
        "{err:?}"
    );
    assert!(notes.borrow().is_empty(), "history is not a quality module");
}

#[test]
fn pwqual_dict_gives_mits_notices_when_there_is_no_dictionary() {
    // The notices go to a collector, not the process-wide log other tests write to.
    use krb5_log::klog::Severity;
    let dir = krb5_testkit::scratch_dir("krb5-pwqual-notices");
    let (missing, words) = (dir.join("nosuch"), dir.join("w"));
    std::fs::write(&words, "zebra\n").unwrap();
    let mut notes: Vec<(Severity, String)> = Vec::new();
    let mut note = |severity: Severity, text: &str| notes.push((severity, text.to_owned()));
    let mut store = PrincipalStore::new(TEST_REALM_STR);
    store.init_pwqual_noting(None, &mut note).unwrap();
    store
        .init_pwqual_noting(Some(&dict_conf(&missing)), &mut note)
        .unwrap();
    store
        .init_pwqual_noting(Some(&dict_conf(&words)), &mut note)
        .unwrap();
    let warning = format!(
        "WARNING!  Cannot find dictionary file {}, continuing without one.",
        missing.display()
    );
    assert_eq!(
        notes,
        [
            (
                Severity::Info,
                "No dictionary file specified, continuing without one.".to_owned()
            ),
            (Severity::Err, warning),
        ]
    );
    assert!(store.pwqual_dict.is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_reread_moves_the_dictionary_and_ticket_policy_never_copies_them() {
    let dir = krb5_testkit::scratch_dir("krb5-pwqual-reread");
    let (db, stash, words) = (dir.join("principal"), dir.join("stash"), dir.join("words"));
    std::fs::write(&words, "zebra\ncorrecthorse\n").unwrap();
    let (mut store, acl) = crate::testrealm::bootstrap_documented().unwrap();
    store.put_policy(NamedPolicy::new("pq"));
    crate::persist::save_store(&store, &db, &stash).unwrap();
    store.persist_paths = Some((db.clone(), stash.clone()));
    store.init_pwqual(Some(&dict_conf(&words))).unwrap();
    store.policy.host_based_services = "host-based-services ".repeat(4);
    let dict = Arc::as_ptr(store.pwqual_dict.as_ref().unwrap());
    let services = store.policy.host_based_services.as_ptr();
    let admin = crate::testrealm::documented_admin_id();
    let u = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["dictu"]);
    // Each change reads the database again first; a refused one reads it back after.
    store
        .change(|s| {
            s.create_password(&acl, &admin, &u, b"first-secret")?;
            s.set_principal_policy(&u, Some("pq".into()))
        })
        .unwrap()
        .unwrap();
    store.reload().unwrap();
    let refused = store
        .change(|s| s.set_password(&u, b"CorrectHorse"))
        .unwrap();
    assert!(
        matches!(&refused, Err(Error::PasswordPolicy(t)) if t == PWQUAL_DICT),
        "{refused:?}"
    );
    store
        .change(|s| s.set_password(&u, b"correcthorse-1"))
        .unwrap()
        .unwrap();
    let kept = store.pwqual_dict.as_ref().unwrap();
    assert_eq!(Arc::as_ptr(kept), dict, "the dictionary was rebuilt");
    assert_eq!(Arc::strong_count(kept), 1);
    assert_eq!(
        store.policy.host_based_services.as_ptr(),
        services,
        "the ticket policy was copied"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn random_sid_rejects_all_zero() {
    assert!(sid_from_random_bytes(&[0; 12]).is_err());
}

/// The serial is the update log's: a new process that maps the log sees the serial the change
/// left, and the dump carries none (kerber-rust 1.0 kept one on `K/M`).
#[test]
fn persist_round_trip_keeps_serial_not_mtime() {
    let dir = krb5_testkit::scratch_dir("krb5-iprop-serial");
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let ulog = dir.join("principal.ulog");
    let (mut store, acl) = crate::testrealm::bootstrap_documented().unwrap();
    crate::persist::save_store(&store, &db, &stash).unwrap();
    store.persist_paths = Some((db.clone(), stash.clone()));
    store.map_ulog(&ulog, 100, IpropRole::Primary).unwrap();
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["serialed"]);
    store
        .change(|s| {
            s.create_password(
                &acl,
                &crate::testrealm::documented_admin_id(),
                &extra,
                b"serial-secret",
            )
        })
        .unwrap()
        .unwrap();
    let sno = store.serial();
    assert_eq!(sno, 2, "the dummy entry, then the create");
    let mut loaded = crate::persist::load_store(&db, &stash).unwrap();
    assert_eq!(loaded.serial(), 0, "no log is mapped by a load");
    loaded.map_ulog(&ulog, 100, IpropRole::Primary).unwrap();
    assert_eq!(
        loaded.serial(),
        sno,
        "serial must survive in the update log, not db_stamp mtime"
    );
    assert!(loaded.get_name(&extra).is_some());
    let text = std::fs::read_to_string(&db).unwrap();
    assert!(
        !text.contains(&format!("\t{}\t", crate::kdb_dump::TL_KERBER_SERIAL)),
        "the dump keeps no serial"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn create_host_changepw_flag_survives_save() {
    let dir = krb5_testkit::scratch_dir("krb5-changepw");
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (mut store, acl) = crate::testrealm::bootstrap_documented().unwrap();
    let cpw = crate::principals::kadmin_changepw();
    store
        .delete(&acl, &crate::testrealm::documented_admin_id(), &cpw)
        .unwrap();
    crate::persist::save_store(&store, &db, &stash).unwrap();
    store.persist_paths = Some((db.clone(), stash.clone()));
    store
        .map_ulog(&dir.join("principal.ulog"), 100, IpropRole::Primary)
        .unwrap();
    store
        .change(|s| s.create_host(&acl, &crate::testrealm::documented_admin_id(), &cpw))
        .unwrap()
        .unwrap();
    let loaded = crate::persist::load_store(&db, &stash).unwrap();
    let p = loaded.get_name(&cpw).expect("changepw");
    assert_ne!(p.attributes & KDB_PWCHANGE_SERVICE, 0);
    let mkey = store.iprop_master_key().unwrap();
    let flagged = store
        .ulog()
        .unwrap()
        .entries()
        .unwrap()
        .into_iter()
        .rev()
        .find(|e| e.name.contains("kadmin/changepw") && !e.deleted)
        .expect("ulog kdbe for kadmin/changepw");
    let vals = crate::store::iprop_xdr::decode_incr_update(&flagged.update, Some(&mkey))
        .unwrap()
        .0
        .vals;
    assert!(
        vals.iter().any(
            |v| matches!(v, crate::store::KdbeVal::AttrFlags(f) if f & KDB_PWCHANGE_SERVICE != 0)
        ),
        "ulog update must carry PWCHANGE_SERVICE"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ktadd_chrand_save_fail_rolls_back_rotation() {
    let dir = krb5_testkit::scratch_dir("krb5-ktadd-chrand");
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (mut store, acl) = crate::testrealm::bootstrap_documented().unwrap();
    let extra = PrincipalName::new(
        PrincipalName::NT_SRV_HST,
        ["host", "chrandfail.kerber.test"],
    );
    store
        .create_host(&acl, &crate::testrealm::documented_admin_id(), &extra)
        .unwrap();
    crate::persist::save_store(&store, &db, &stash).unwrap();
    store.persist_paths = Some((db.clone(), stash.clone()));
    let before = max_kvno(&store, &extra);
    super::FAIL_NEXT_CHRAND_SAVE.with(|c| c.set(true));
    let err = store
        .ktadd_local_atomic(
            &extra,
            true,
            &crate::testrealm::documented_admin_id(),
            |_| Ok(()),
        )
        .unwrap_err();
    assert!(
        err.to_string().contains("injected chrand save fail"),
        "{err}"
    );
    assert_eq!(max_kvno(&store, &extra), before);
    let reloaded = crate::persist::load_store(&db, &stash).unwrap();
    assert_eq!(max_kvno(&reloaded, &extra), before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ktadd_export_fail_rolls_back_rotation() {
    let dir = krb5_testkit::scratch_dir("krb5-ktadd-export");
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (mut store, acl) = crate::testrealm::bootstrap_documented().unwrap();
    let extra = PrincipalName::new(
        PrincipalName::NT_SRV_HST,
        ["host", "exportfail.kerber.test"],
    );
    store
        .create_host(&acl, &crate::testrealm::documented_admin_id(), &extra)
        .unwrap();
    crate::persist::save_store(&store, &db, &stash).unwrap();
    store.persist_paths = Some((db.clone(), stash.clone()));
    let before = max_kvno(&store, &extra);
    super::FAIL_NEXT_KTADD_EXPORT.with(|c| c.set(true));
    let err = store
        .ktadd_local_atomic(
            &extra,
            true,
            &crate::testrealm::documented_admin_id(),
            |_| Ok(()),
        )
        .unwrap_err();
    assert!(err.to_string().contains("injected export fail"), "{err}");
    assert_eq!(max_kvno(&store, &extra), before);
    let reloaded = crate::persist::load_store(&db, &stash).unwrap();
    assert_eq!(max_kvno(&reloaded, &extra), before);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The rotation is written only once the keytab was: a keytab write that fails leaves the
/// database as it was, with nothing to roll back on disk, even when the database's directory has
/// meanwhile become read-only.
#[test]
fn ktadd_write_failure_leaves_the_database_unwritten() {
    let dir = krb5_testkit::scratch_dir("krb5-ktadd-rbsave");
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (mut store, acl) = crate::testrealm::bootstrap_documented().unwrap();
    let extra = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "rbsave.kerber.test"]);
    store
        .create_host(&acl, &crate::testrealm::documented_admin_id(), &extra)
        .unwrap();
    crate::persist::save_store(&store, &db, &stash).unwrap();
    store.persist_paths = Some((db.clone(), stash.clone()));
    let before = max_kvno(&store, &extra);
    let err = store
        .ktadd_local_atomic(
            &extra,
            true,
            &crate::testrealm::documented_admin_id(),
            |_| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
                }
                Err(Error::Crypto("disk full".into()))
            },
        )
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("disk full"), "{msg}");
    assert_eq!(max_kvno(&store, &extra), before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
    }
    let reloaded = crate::persist::load_store(&db, &stash).unwrap();
    assert_eq!(max_kvno(&reloaded, &extra), before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn as_cant_find_client_key_is_etype_nosupp() {
    use krb5_types::err;
    let (mut store, _) = crate::testrealm::bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::testrealm::TEST_USER]);
    let mut p = store.get_name(&user).unwrap().clone();
    p.keys
        .retain(|k| k.etype == EncryptionType::Aes256CtsHmacSha384192);
    p.requires_preauth = false;
    p.attributes &= !KDB_REQUIRES_PRE_AUTH;
    store.debug_insert(p);
    let req = as_req_sname_etype(&user, 18).unwrap();
    let err = crate::issue_as(&store, &req).unwrap_err();
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::ETYPE_NOSUPP);
            assert_eq!(text.as_deref(), Some("CANT_FIND_CLIENT_KEY"));
        }
        other => panic!("expected 14 CANT_FIND_CLIENT_KEY, got {other:?}"),
    }
}

#[test]
fn as_no_server_key_is_finding_server_key() {
    use krb5_protocol::{as_req, pa_enc_timestamp};
    use krb5_types::err;
    let (mut store, _) = crate::testrealm::bootstrap_documented().unwrap();
    let krbtgt = PrincipalName::krbtgt(crate::testrealm::TEST_REALM);
    let mut p = store.get_name(&krbtgt).unwrap().clone();
    p.keys.clear();
    store.debug_insert(p);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::testrealm::TEST_USER]);
    let key = {
        let u = store.get_name(&user).unwrap();
        u.key_for(EncryptionType::Aes256CtsHmacSha196)
            .unwrap()
            .key
            .clone()
    };
    let req = as_req(
        user,
        crate::testrealm::TEST_REALM,
        501,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    let err = crate::issue_as(&store, &req).unwrap_err();
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::GENERIC);
            assert_eq!(text.as_deref(), Some("FINDING_SERVER_KEY"));
        }
        other => panic!("expected 60 FINDING_SERVER_KEY, got {other:?}"),
    }
}

#[test]
fn last_admin_unlock_skips_failcount_lockout() {
    use krb5_protocol::{as_req, pa_enc_timestamp};
    let (mut store, _) = crate::testrealm::bootstrap_documented().unwrap();
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::testrealm::TEST_USER]);
    store.put_policy(NamedPolicy {
        name: "lock".into(),
        min_length: 1,
        min_classes: 1,
        history: 0,
        max_fail: 1,
        pw_failcnt_interval: 0,
        pw_lockout_duration: 0,
        pw_min_life: 0,
        pw_max_life: 0,
        allowed_keysalts: None,
    });
    store
        .set_principal_policy(&user, Some("lock".into()))
        .unwrap();
    let mut p = store.get_name(&user).unwrap().clone();
    p.fail_auth_count = 1;
    p.last_failed = 100;
    p.tl_data.retain(|t| t.ty != TL_LAST_ADMIN_UNLOCK);
    p.tl_data.push(TlData {
        ty: TL_LAST_ADMIN_UNLOCK,
        contents: 200u32.to_le_bytes().to_vec(),
    });
    store.debug_insert(p);
    let key = store
        .get_name(&user)
        .unwrap()
        .key_for(EncryptionType::Aes256CtsHmacSha196)
        .unwrap()
        .key
        .clone();
    let req = as_req(
        user,
        crate::testrealm::TEST_REALM,
        504,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
    )
    .unwrap();
    crate::issue_as(&store, &req).expect("TL 1792 after last_failed");
}

#[test]
fn as_missing_krbtgt_is_get_local_tgt() {
    use krb5_protocol::{as_req_sname, pa_enc_timestamp};
    use krb5_types::err;
    let (mut store, _) = crate::testrealm::bootstrap_documented().unwrap();
    let krbtgt = PrincipalName::krbtgt(crate::testrealm::TEST_REALM);
    let mut p = store.get_name(&krbtgt).unwrap().clone();
    p.keys.clear();
    store.debug_insert(p);
    let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::testrealm::TEST_USER]);
    let host = crate::testrealm::documented_host();
    let key = store
        .get_name(&user)
        .unwrap()
        .key_for(EncryptionType::Aes256CtsHmacSha196)
        .unwrap()
        .key
        .clone();
    let req = as_req_sname(
        user,
        crate::testrealm::TEST_REALM,
        503,
        Some(vec![pa_enc_timestamp(&key).unwrap()]),
        host,
        vec![EncryptionType::Aes256CtsHmacSha196.to_iana()],
    )
    .unwrap();
    let err = crate::issue_as(&store, &req).unwrap_err();
    match err {
        Error::Protocol { code, text, .. } => {
            assert_eq!(code, err::GENERIC);
            assert_eq!(text.as_deref(), Some("GET_LOCAL_TGT"));
        }
        other => panic!("expected 60 GET_LOCAL_TGT, got {other:?}"),
    }
}
