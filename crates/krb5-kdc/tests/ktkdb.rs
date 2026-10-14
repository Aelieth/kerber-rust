//! The KDB keytab's lookup, `krb5_ktkdb_get_entry`, over `Principal`s the tests make out of a
//! bootstrapped realm's `kadmin/changepw`.

use krb5_crypto::EncryptionType as E;
use krb5_kdc::principals::kadmin_changepw;
use krb5_kdc::testrealm::{TEST_REALM, bootstrap_documented};
use krb5_kdc::{
    KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_SVR, KeyEntry, KtkdbError, Principal, ktkdb_get_entry,
    random_key,
};
use krb5_types::PrincipalName;

const ALL: [E; 3] = [
    E::Aes256CtsHmacSha196,
    E::Aes128CtsHmacSha196,
    E::Aes256CtsHmacSha384192,
];

/// `kadmin/changepw` with these keys, in this order: (enctype, kvno).
fn service(keys: &[(E, u32)]) -> Principal {
    let (store, _) = bootstrap_documented().expect("bootstrap");
    let mut p = store
        .get_name(&kadmin_changepw())
        .expect("changepw")
        .clone();
    p.keys = keys
        .iter()
        .map(|&(e, kvno)| KeyEntry::new(e, random_key(e).expect("key"), kvno))
        .collect();
    p
}

fn get(p: &Principal, kvno: u32, etype: i32, permitted: &[E]) -> Result<(E, u32), KtkdbError> {
    ktkdb_get_entry(Some(p), &kadmin_changepw(), TEST_REALM, kvno, etype, |e| {
        permitted.contains(&e)
    })
    .map(|k| (k.etype, k.kvno))
}

/// MIT `krb5_ktkdb_get_entry` (`lib/kdb/keytab.c:157-180`): a principal that is not a cross-realm TGT gives its FIRST key at the kvno, whatever the ticket's enctype, and a ticket of an enctype not similar to it finds `KRB5_KDB_NO_PERMITTED_KEY`.
#[test]
fn the_first_key_at_the_kvno_is_the_only_one_a_service_ticket_can_use() {
    let p = service(&[(E::Aes256CtsHmacSha196, 3), (E::Aes128CtsHmacSha196, 3)]);
    assert_eq!(get(&p, 3, 18, &ALL), Ok((E::Aes256CtsHmacSha196, 3)));
    assert_eq!(get(&p, 3, 17, &ALL), Err(KtkdbError::NoPermittedKey));
}

/// MIT `krb5_dbe_def_search_enctype` (`lib/kdb/kdb_default.c:47-94`): kvno 0 is the highest key version, and through the lookup a kvno the principal lacks is `KRB5_KT_KVNONOTFOUND`.
#[test]
fn kvno_zero_is_the_highest_and_a_missing_kvno_is_kvnonotfound() {
    let p = service(&[(E::Aes256CtsHmacSha196, 5), (E::Aes256CtsHmacSha196, 4)]);
    assert_eq!(get(&p, 0, 18, &ALL), Ok((E::Aes256CtsHmacSha196, 5)));
    assert_eq!(get(&p, 4, 18, &ALL), Ok((E::Aes256CtsHmacSha196, 4)));
    assert_eq!(get(&p, 9, 18, &ALL), Err(KtkdbError::KvnoNotFound));
}

/// A key of an enctype outside `permitted_enctypes` is passed over: the next one is the first, and
/// when all are outside it the answer is `KRB5_KDB_NO_PERMITTED_KEY`.
#[test]
fn a_key_outside_the_permitted_enctypes_is_passed_over() {
    let p = service(&[(E::Aes256CtsHmacSha196, 1), (E::Aes128CtsHmacSha196, 1)]);
    let only_128 = [E::Aes128CtsHmacSha196];
    assert_eq!(get(&p, 1, 17, &only_128), Ok((E::Aes128CtsHmacSha196, 1)));
    assert_eq!(get(&p, 1, 18, &only_128), Err(KtkdbError::NoPermittedKey));
    assert_eq!(get(&p, 1, 18, &[]), Err(KtkdbError::NoPermittedKey));
}

/// MIT `krb5_ktkdb_get_entry` (`lib/kdb/keytab.c:140-149`): no such principal, and one that may not be a service, are `KRB5_KT_NOTFOUND`.
#[test]
fn a_principal_that_is_not_a_service_is_not_found() {
    let mut p = service(&[(E::Aes256CtsHmacSha196, 1)]);
    let name = kadmin_changepw();
    assert_eq!(
        ktkdb_get_entry(None, &name, TEST_REALM, 1, 18, |_| true).err(),
        Some(KtkdbError::NotFound)
    );
    p.attributes |= KDB_DISALLOW_SVR;
    assert_eq!(get(&p, 1, 18, &ALL), Err(KtkdbError::NotFound));
    p.attributes = KDB_DISALLOW_ALL_TIX;
    assert_eq!(get(&p, 1, 18, &ALL), Err(KtkdbError::NotFound));
}

/// MIT `krb5_ktkdb_get_entry` (`lib/kdb/keytab.c:152-157`): for a cross-realm TGT the lookup takes the ticket's enctype, not the first key.
/// MIT `is_xrealm_tgt` (`lib/kdb/keytab.c:200-220`): matches any first component that is a prefix of `krbtgt` and a second that is not the realm.
#[test]
fn a_cross_realm_tgt_is_looked_up_by_the_tickets_enctype() {
    let p = service(&[(E::Aes256CtsHmacSha196, 1), (E::Aes128CtsHmacSha196, 1)]);
    let xtgt = PrincipalName::krbtgt("ELSEWHERE.TEST");
    let at = |name: &PrincipalName, etype| {
        ktkdb_get_entry(Some(&p), name, TEST_REALM, 1, etype, |_| true).map(|k| k.etype)
    };
    assert_eq!(at(&xtgt, 17), Ok(E::Aes128CtsHmacSha196));
    let prefix = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krb", "ELSEWHERE.TEST"]);
    assert_eq!(at(&prefix, 17), Ok(E::Aes128CtsHmacSha196));
    let local_tgt = PrincipalName::krbtgt(TEST_REALM);
    assert_eq!(at(&local_tgt, 17), Err(KtkdbError::NoPermittedKey));
    assert_eq!(at(&xtgt, 99), Err(KtkdbError::NoPermittedKey));
}

/// MIT `krb5_c_enctype_compare` (`lib/crypto/krb/enctype_util.c:73-86`): an enctype MIT does not implement is `KRB5_BAD_ENCTYPE`.
#[test]
fn an_enctype_mit_does_not_know_is_bad_enctype() {
    let p = service(&[(E::Aes256CtsHmacSha196, 1)]);
    assert_eq!(get(&p, 1, 99, &ALL), Err(KtkdbError::BadEnctype));
}
