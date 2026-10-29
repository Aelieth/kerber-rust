//! In-memory store tests (private-bound; moved out of `store.rs`).

use super::rid::sid_from_random_bytes;
use super::*;
use crate::kdb_dump::TL_LAST_ADMIN_UNLOCK;
use krb5_crypto::EncryptionType;

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

// MIT: `krb5_dbe_def_search_enctype` (kdb_default.c:60-61)
/// A requested etype outside the
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
        !krb5_types::transited::transit_allowed(&p.capaths, "A.EX.COM", "C.EX.COM", &hops),
        "B.EX.COM is not on the capaths list"
    );
    p.capaths
        .entry("A.EX.COM".into())
        .or_default()
        .insert("C.EX.COM".into(), vec!["EX.COM".into(), "B.EX.COM".into()]);
    assert!(krb5_types::transited::transit_allowed(
        &p.capaths, "A.EX.COM", "C.EX.COM", &hops
    ));
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
fn a_reread_moves_the_dictionary_and_ticket_policy_never_copies_them() {
    let dir = krb5_testkit::scratch_dir("krb5-pwqual-reread");
    let (db, stash, words) = (dir.join("principal"), dir.join("stash"), dir.join("words"));
    std::fs::write(&words, "zebra\ncorrecthorse\n").unwrap();
    let (mut store, acl) = crate::testrealm::bootstrap_documented().unwrap();
    store.put_policy(NamedPolicy::new("pq")).unwrap();
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
    store
        .put_policy(NamedPolicy {
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
        })
        .unwrap();
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

const DES3: EncryptionType = EncryptionType::Des3CbcSha1;

/// A DES key octet has an odd number of one bits: its low bit is the parity.
fn odd_parity(octets: &[u8]) -> bool {
    octets.iter().all(|b| b.count_ones() % 2 == 1)
}

// MIT: `krb5_c_make_random_key` (lib/crypto/krb/make_random_key.c:31-76)
/// `keybytes` random octets through the
/// enctype's random-to-key, so a des3 key is 24 octets of odd parity (`k5_rand2key_des3`,
/// `k5_des_fixup_key_parity`) and every other enctype's key is its length. 24 raw random octets are all of odd
/// parity with probability 2^-24, so 64 keys decide it.
#[test]
fn random_key_of_des3_is_24_octets_of_odd_parity() {
    for _ in 0..64 {
        let key = random_key(DES3).unwrap();
        assert_eq!(key.etype(), DES3);
        assert_eq!(key.as_bytes().len(), 24);
        assert!(odd_parity(key.as_bytes()), "{:02x?}", key.as_bytes());
    }
    for etype in [
        A128,
        A256,
        EncryptionType::Aes128CtsHmacSha256128,
        EncryptionType::Aes256CtsHmacSha384192,
        EncryptionType::Rc4Hmac,
        EncryptionType::Camellia128CtsCmac,
        EncryptionType::Camellia256CtsCmac,
    ] {
        let key = random_key(etype).unwrap();
        assert_eq!(key.etype(), etype);
        assert_eq!(key.as_bytes().len(), etype.key_len());
    }
}

/// The keys `addprinc -randkey -e des3-cbc-sha1:normal` and `cpw -randkey -e des3-cbc-sha1:normal` give a
/// principal are drawn like MIT's `krb5_dbe_crk` / `krb5_dbe_cpw` draw them, with `krb5_c_make_random_key`: a des3
/// key of odd parity on every octet, which a MIT `kinit`, `kvno` or `kdb5_util load` takes. Before, they were 24 raw
/// random octets and MIT said "DES key has bad parity".
#[test]
fn randkey_principals_hold_des3_keys_of_odd_parity() {
    let (mut store, acl) = crate::testrealm::bootstrap_documented().unwrap();
    let admin = crate::testrealm::documented_admin_id();
    let name = PrincipalName::new(
        PrincipalName::NT_SRV_HST,
        ["host", "des3randkey.kerber.test"],
    );
    store
        .create_host_etypes(&acl, &admin, &name, &[DES3.into(), A256.into()])
        .unwrap();
    let created: Vec<KeyEntry> = store.get_name(&name).unwrap().keys.clone();
    assert_eq!(created.len(), 2);
    for k in &created {
        assert_eq!(k.key.as_bytes().len(), k.etype.key_len());
    }
    let des3 = created
        .iter()
        .find(|k| k.etype == DES3)
        .expect("a des3 key");
    assert!(odd_parity(des3.key.as_bytes()), "addprinc -randkey");
    let rekeyed = store
        .chrand_etypes_keepold_in(&name, TEST_REALM_STR, &[DES3.into()], 0, &admin)
        .unwrap();
    let des3 = rekeyed
        .iter()
        .find(|k| k.etype == DES3)
        .expect("a des3 key");
    assert!(odd_parity(des3.key.as_bytes()), "cpw -randkey");
    assert_eq!(rekeyed.len(), 1);
}
