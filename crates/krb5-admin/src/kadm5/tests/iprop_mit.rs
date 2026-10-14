//! Updates shaped as an MIT 1.22.2 primary sends them (the attribute lists `kproplog -v` showed
//! for `setstr`, `cpw -randkey` and `modprinc +allow_tix`), pulled onto this replica: only the
//! attributes an update carries change, an update that clears a flag clears it, and the lockout
//! attributes never change on a replica.

use super::*;
use krb5_kdc::{
    AdminFields, KDB_DISALLOW_ALL_TIX, KDB_REQUIRES_PRE_AUTH, NamedPolicy, Principal,
    PrincipalStore, PrincipalWrite, TL_KADM_DATA, TL_LAST_ADMIN_UNLOCK, TL_MOD_PRINC,
    TL_STRING_ATTRS, tl_mod_princ_name,
};

const REALM: &str = "KERBER.TEST";
const KV5M_DATA: u32 = 0x970e_a702;
const EXPIRE: u32 = 1_924_992_000;
const PW_EXPIRE: u32 = 1_906_502_400;
const MAX_LIFE: u64 = 5 * 3600;
const MAX_RLIFE: u64 = 3 * 86_400;

/// A replica holding `p11user` as the live settle's primary made it: `+requires_preauth
/// -allow_tix`, both expirations, its own lifetimes, a policy and a string attribute.
fn replica() -> (PrincipalStore, PrincipalName) {
    let (mut store, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let actor = krb5_kdc::testrealm::documented_admin_id();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["p11user"]);
    store.put_policy(NamedPolicy::new("p11pol"));
    store
        .create_password(&acl, &actor, &name, b"p11-Secret1")
        .unwrap();
    store
        .apply_admin_fields(
            &name,
            AdminFields {
                attributes: Some(KDB_REQUIRES_PRE_AUTH | KDB_DISALLOW_ALL_TIX),
                max_life: Some(MAX_LIFE),
                expiration: Some(EXPIRE),
                pw_expire: Some(PW_EXPIRE),
                policy: Some("p11pol".into()),
                clear_policy: false,
                max_renewable_life: Some(MAX_RLIFE),
            },
        )
        .unwrap();
    store.set_string(&name, "start", Some("s0")).unwrap();
    (store, name)
}

fn record(store: &PrincipalStore, name: &PrincipalName) -> Principal {
    store.get_name(name).unwrap().clone()
}

fn princ(w: &mut XdrW, comps: &[&str]) {
    w.opaque(REALM.as_bytes());
    w.u32(u32::try_from(comps.len()).unwrap());
    for c in comps {
        w.u32(KV5M_DATA);
        w.opaque(c.as_bytes());
    }
    w.u32(1);
}

fn tl(w: &mut XdrW, records: &[(i32, Vec<u8>)]) {
    w.u32(u32::try_from(records.len()).unwrap());
    for (ty, contents) in records {
        w.u32(ty.cast_unsigned());
        w.opaque(contents);
    }
}

/// The tail of every MIT update in the settle: `AT_PRINC`, `AT_PW_LAST_CHANGE`, `AT_MOD_PRINC`
/// (`admin`), `AT_MOD_TIME`, then `AT_TL_DATA` with the strings, the kadm5 record and the
/// master key version.
fn mit_tail(w: &mut XdrW, strings: &[u8], kadm: &[u8]) {
    w.u32(AT_PRINC);
    princ(w, &["p11user"]);
    w.u32(AT_PW_LAST_CHANGE);
    w.u32(1_790_000_000);
    w.u32(AT_MOD_PRINC);
    princ(w, &["admin"]);
    w.u32(AT_MOD_TIME);
    w.u32(1_790_000_100);
    w.u32(AT_TL_DATA);
    tl(
        w,
        &[
            (TL_STRING_ATTRS, strings.to_vec()),
            (TL_KADM_DATA, kadm.to_vec()),
            (8, vec![1, 0]),
        ],
    );
}

/// One `kdb_incr_result_t` carrying one update of `p11user` with `n` attributes.
fn mit_result(sno: u32, n: u32, vals: &[u8]) -> Vec<u8> {
    mit_result_for("p11user", sno, n, vals)
}

/// One `kdb_incr_result_t` carrying one update of `princ` with `n` attributes.
fn mit_result_for(princ: &str, sno: u32, n: u32, vals: &[u8]) -> Vec<u8> {
    let mut w = XdrW::default();
    w.u32(sno);
    w.u32(1_790_000_100);
    w.u32(0);
    w.u32(1);
    w.opaque(format!("{princ}@{REALM}").as_bytes());
    w.u32(sno);
    w.u32(1_790_000_100);
    w.u32(0);
    w.u32(n);
    w.b.extend_from_slice(vals);
    w.u32(0);
    w.u32(1);
    w.u32(0);
    w.opaque(&[]);
    w.u32(krb5_kdc::IPROP_OK);
    w.b
}

fn pull(store: &mut PrincipalStore, wire: &[u8]) {
    let (status, _, _, _, updates) = decode_incr_result(wire, None).unwrap();
    assert_eq!(status, krb5_kdc::IPROP_OK);
    let _ = store.apply_updates(&updates);
}

fn kadm_of(p: &Principal) -> Vec<u8> {
    p.tl_data
        .iter()
        .find(|t| t.ty == TL_KADM_DATA)
        .unwrap()
        .contents
        .clone()
}

fn assert_kept(after: &Principal) {
    assert_eq!(
        after.attributes & KDB_DISALLOW_ALL_TIX,
        KDB_DISALLOW_ALL_TIX
    );
    assert_eq!(
        after.attributes & KDB_REQUIRES_PRE_AUTH,
        KDB_REQUIRES_PRE_AUTH
    );
    assert!(after.locked, "a disabled account stays disabled");
    assert!(after.requires_preauth);
    assert_eq!(after.expiration, EXPIRE);
    assert_eq!(after.max_life, MAX_LIFE);
    assert_eq!(after.max_renewable_life, MAX_RLIFE);
    assert_eq!(after.pw_policy.as_deref(), Some("p11pol"));
}

#[test]
fn an_mit_setstr_update_keeps_every_attribute_it_does_not_carry() {
    let (mut store, name) = replica();
    let before = record(&store, &name);
    let mut vals = XdrW::default();
    mit_tail(&mut vals, b"start\0s0\0note\0n1\0", &kadm_of(&before));
    let wire = mit_result(store.serial() + 1, 5, &vals.b);
    pull(&mut store, &wire);
    let after = record(&store, &name);
    assert_kept(&after);
    assert_eq!(after.pw_expire, PW_EXPIRE);
    assert_eq!(
        after.string_attrs,
        vec![
            ("start".to_owned(), "s0".to_owned()),
            ("note".to_owned(), "n1".to_owned())
        ]
    );
    assert_eq!(after.keys.len(), before.keys.len());
    assert_eq!(
        tl_mod_princ_name(&after.tl_data).as_deref(),
        Some("admin@KERBER.TEST"),
        "AT_MOD_PRINC with AT_MOD_TIME is the modifier"
    );
}

#[test]
fn an_mit_cpw_randkey_update_keeps_every_attribute_it_does_not_carry() {
    let (mut store, name) = replica();
    let before = record(&store, &name);
    let mut vals = XdrW::default();
    vals.u32(AT_PW_EXP);
    vals.u32(PW_EXPIRE + 86_400);
    vals.u32(AT_KEYDATA);
    vals.u32(2);
    for (etype, len) in [(18u32, 32usize), (17, 16)] {
        vals.u32(1);
        vals.u32(2);
        vals.u32(1);
        vals.u32(etype);
        vals.u32(1);
        vals.opaque(&vec![0x5a; len]);
    }
    mit_tail(&mut vals, b"start\0s0\0", &kadm_of(&before));
    let wire = mit_result(store.serial() + 1, 7, &vals.b);
    pull(&mut store, &wire);
    let after = record(&store, &name);
    assert_kept(&after);
    assert_eq!(after.pw_expire, PW_EXPIRE + 86_400);
    assert_eq!(after.keys.len(), 2);
    assert!(after.keys.iter().all(|k| k.kvno == 2));
    assert_eq!(after.string_attrs, before.string_attrs);
}

#[test]
fn an_mit_update_that_clears_a_flag_clears_it_and_keeps_the_rest() {
    let (mut store, name) = replica();
    let before = record(&store, &name);
    let mut vals = XdrW::default();
    vals.u32(AT_ATTRFLAGS);
    vals.u32(KDB_REQUIRES_PRE_AUTH);
    mit_tail(&mut vals, b"start\0s0\0", &kadm_of(&before));
    let wire = mit_result(store.serial() + 1, 6, &vals.b);
    pull(&mut store, &wire);
    let after = record(&store, &name);
    assert_eq!(after.attributes, KDB_REQUIRES_PRE_AUTH);
    assert!(!after.locked, "+allow_tix enables the account");
    assert!(after.requires_preauth);
    assert_eq!(after.expiration, EXPIRE);
    assert_eq!(after.pw_expire, PW_EXPIRE);
    assert_eq!(after.max_life, MAX_LIFE);
    assert_eq!(after.max_renewable_life, MAX_RLIFE);
}

#[test]
fn a_replica_never_takes_the_lockout_attributes_from_an_update() {
    let (mut store, name) = replica();
    let mut p = record(&store, &name);
    p.last_success = 111;
    p.last_failed = 222;
    p.fail_auth_count = 3;
    PrincipalWrite::put_principal(&mut store, p).unwrap();
    let mut vals = XdrW::default();
    vals.u32(AT_MAX_LIFE);
    vals.u32(4 * 3600);
    vals.u32(AT_LAST_SUCCESS);
    vals.u32(0);
    vals.u32(AT_LAST_FAILED);
    vals.u32(0);
    vals.u32(AT_FAIL_AUTH_COUNT);
    vals.u32(0);
    vals.u32(AT_PRINC);
    princ(&mut vals, &["p11user"]);
    let wire = mit_result(store.serial() + 1, 5, &vals.b);
    pull(&mut store, &wire);
    let after = record(&store, &name);
    assert_eq!(after.max_life, 4 * 3600);
    assert_eq!(after.last_success, 111);
    assert_eq!(after.last_failed, 222);
    assert_eq!(after.fail_auth_count, 3);
}

#[test]
fn an_mit_tl_data_update_replaces_records_by_type_and_removes_none() {
    let (mut store, name) = replica();
    store.admin_unlock(&name).unwrap();
    let before = record(&store, &name);
    assert!(before.tl_data.iter().any(|t| t.ty == TL_LAST_ADMIN_UNLOCK));
    let mut vals = XdrW::default();
    vals.u32(AT_PRINC);
    princ(&mut vals, &["p11user"]);
    vals.u32(AT_TL_DATA);
    tl(&mut vals, &[(TL_STRING_ATTRS, b"note\0n2\0".to_vec())]);
    let wire = mit_result(store.serial() + 1, 2, &vals.b);
    pull(&mut store, &wire);
    let after = record(&store, &name);
    assert_eq!(
        after.string_attrs,
        vec![("note".to_owned(), "n2".to_owned())]
    );
    for ty in [TL_LAST_ADMIN_UNLOCK, TL_KADM_DATA, TL_MOD_PRINC] {
        assert_eq!(
            after.tl_data.iter().find(|t| t.ty == ty),
            before.tl_data.iter().find(|t| t.ty == ty),
            "tagged data {ty:#x} the update did not carry is kept"
        );
    }
    assert_kept(&after);
}

/// MIT `krb5_dbe_specialize_salt` on a rename keeps each key's salt explicitly; a replica loads
/// that record from a dump, then an MIT `cpw -pw` sends keys with the normal salt. The replica
/// offers the new keys' salt, so a client salting as offered derives the stored key.
#[test]
fn an_mit_cpw_after_a_rename_offers_the_new_keys_salt() {
    let (mut store, acl) = krb5_kdc::testrealm::bootstrap_documented().unwrap();
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["p11salt"]);
    store
        .create_password(
            &acl,
            &krb5_kdc::testrealm::documented_admin_id(),
            &name,
            b"old-Secret1",
        )
        .unwrap();
    let old_salt = format!("{REALM}p11old").into_bytes();
    let mut p = record(&store, &name);
    for k in &mut p.keys {
        k.salt_type = Some(4);
        k.kdb_salt = Some(old_salt.clone());
    }
    PrincipalWrite::put_principal(&mut store, p).unwrap();
    let dump = krb5_kdc::dump_store(&store, b"masterpassword").unwrap();
    let mut store = krb5_kdc::load_dump(&dump, b"masterpassword").unwrap();
    assert_eq!(record(&store, &name).salt, old_salt);
    let new_salt = name.default_salt(REALM);
    let etype = krb5_crypto::EncryptionType::Aes256CtsHmacSha196;
    let key = krb5_crypto::string_to_key(etype, b"new-Secret2", &new_salt, None).unwrap();
    let mut vals = XdrW::default();
    vals.u32(AT_KEYDATA);
    vals.u32(1);
    vals.u32(1);
    vals.u32(2);
    vals.u32(1);
    vals.u32(18);
    vals.u32(1);
    vals.opaque(key.as_bytes());
    vals.u32(AT_PRINC);
    princ(&mut vals, &["p11salt"]);
    let wire = mit_result_for("p11salt", store.serial() + 1, 2, &vals.b);
    pull(&mut store, &wire);
    let after = record(&store, &name);
    assert_eq!(after.salt, new_salt, "the salt offered is the new keys'");
    let derived = krb5_crypto::string_to_key(etype, b"new-Secret2", &after.salt, None).unwrap();
    assert_eq!(derived.as_bytes(), after.keys[0].key.as_bytes());
}
