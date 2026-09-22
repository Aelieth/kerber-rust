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

/// `kdb_default.c:60-61`: a requested etype outside the permitted set is
/// `NO_PERMITTED_KEY` before the key list is read, even when the
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
        vec![krb5_types::spake::GROUP_P256]
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
    assert!(hierarchical_intermediates("A.TEST", &big).is_empty());
    assert!(hierarchical_intermediates(&big, "C.TEST").is_empty());
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
    assert!(hierarchical_walk_realms("A.TEST", &big).is_empty());
    assert!(hierarchical_walk_realms(&big, "C.TEST").is_empty());
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

#[test]
fn random_sid_rejects_all_zero() {
    assert!(sid_from_random_bytes(&[0; 12]).is_err());
}

#[test]
fn persist_round_trip_keeps_serial_not_mtime() {
    let dir = std::env::temp_dir().join(format!(
        "krb5-iprop-serial-{}-{}",
        std::process::id(),
        unix_now_u32()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let db = dir.join("principal");
    let stash = dir.join("stash");
    let (mut store, acl) = crate::testrealm::bootstrap_documented().unwrap();
    crate::persist::save_store(&store, &db, &stash).unwrap();
    store.persist_paths = Some((db.clone(), stash.clone()));
    let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["serialed"]);
    store
        .create_password(
            &acl,
            &crate::testrealm::documented_admin_id(),
            &extra,
            b"serial-secret",
        )
        .unwrap();
    let sno = store.serial();
    assert!(sno > 0);
    let loaded = crate::persist::load_store(&db, &stash).unwrap();
    assert_eq!(
        loaded.serial(),
        sno,
        "serial must survive dump persist, not db_stamp mtime"
    );
    assert!(loaded.get_name(&extra).is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn create_host_changepw_flag_survives_save() {
    let dir = std::env::temp_dir().join(format!(
        "krb5-changepw-{}-{}",
        std::process::id(),
        unix_now_u32()
    ));
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
        .create_host(&acl, &crate::testrealm::documented_admin_id(), &cpw)
        .unwrap();
    let loaded = crate::persist::load_store(&db, &stash).unwrap();
    let p = loaded.get_name(&cpw).expect("changepw");
    assert_ne!(p.attributes & KDB_PWCHANGE_SERVICE, 0);
    let flagged = store
        .ulog()
        .into_iter()
        .rev()
        .find(|e| e.name.contains("kadmin/changepw") && e.princ.is_some())
        .expect("ulog kdbe for kadmin/changepw");
    assert_ne!(
        flagged.princ.as_ref().unwrap().attributes & KDB_PWCHANGE_SERVICE,
        0,
        "ulog snapshot must carry PWCHANGE_SERVICE"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ktadd_chrand_save_fail_rolls_back_rotation() {
    let dir = std::env::temp_dir().join(format!(
        "krb5-ktadd-chrand-{}-{}",
        std::process::id(),
        unix_now_u32()
    ));
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
    let dir = std::env::temp_dir().join(format!(
        "krb5-ktadd-export-{}-{}",
        std::process::id(),
        unix_now_u32()
    ));
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

#[test]
fn ktadd_rollback_save_fail_surfaces_both() {
    let dir = std::env::temp_dir().join(format!(
        "krb5-ktadd-rbsave-{}-{}",
        std::process::id(),
        unix_now_u32()
    ));
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
    assert!(msg.contains("rollback failed"), "{msg}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
    }
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
