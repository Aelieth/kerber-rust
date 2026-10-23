//! kdb5_util create.

use krb5_config::KdcConf;
use krb5_crypto::ProtocolKey;
use krb5_types::PrincipalName;

use crate::error::Error;
use crate::kdb_dump::{TL_ACTKVNO, TL_KADM_DATA, TL_LAST_PWD_CHANGE, TL_MKVNO, TL_MOD_PRINC};
use crate::mkey::MASTER_NAME;
use crate::store::{
    AdminEnt, KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_TGT_BASED, KDB_LOCKDOWN_KEYS,
    KDB_PWCHANGE_SERVICE, KDB_REQUIRES_PRE_AUTH, KeyEntry, Principal, PrincipalFields,
    PrincipalStore, TlData, kadm5_mask, random_key, refresh_kadm_tl,
};

// MIT: `ADMIN_LIFETIME` (kadm5_create.c:54-54)
const ADMIN_LIFETIME: u32 = 60 * 60 * 3;
// MIT: `CHANGEPW_LIFETIME` (kadm5_create.c:55-55)
const CHANGEPW_LIFETIME: u32 = 60 * 5;

// MIT: `kdb5_create` (kadmin/dbutil/kdb5_create.c:170-175)
// MIT: `add_principal` (kadmin/dbutil/kdb5_create.c:392-406)
// MIT: `add_principal` (kadmin/dbutil/kdb5_create.c:409-440)
// MIT: `add_principal` (kadmin/dbutil/kdb5_create.c:441-454)
// MIT: `add_principal` (kadmin/dbutil/kdb5_create.c:462-465)
// MIT: `add_admin_princs` (kadmin/dbutil/kadm5_create.c:139-154)
// MIT: `add_admin_princ` (kadmin/dbutil/kadm5_create.c:207-213)
/// A missing dictionary does not fail this.
pub fn create_realm(
    realm: &str,
    kdc: Option<&KdcConf>,
    master: &ProtocolKey,
    mkvno: u16,
) -> Result<PrincipalStore, Error> {
    let mut store = create_realm_db(realm, kdc, master, mkvno)?;
    if let Some(c) = kdc {
        // MIT: `kadm5_create_magic_princs` (kadmin/dbutil/kadm5_create.c:100-107)
        store.init_pwqual(Some(c)).map_err(|e| {
            let path = c.dict_file.as_deref().unwrap_or(std::path::Path::new(""));
            Error::InvalidArgument(format!("kdc.conf dict_file {}: {e}", path.display()))
        })?;
    }
    add_admin_principals(&mut store, mkvno)?;
    Ok(store)
}

// MIT: `kdb5_create` (kadmin/dbutil/kdb5_create.c:291-294)
/// K/M and krbtgt skip the update log.
pub fn create_realm_db(
    realm: &str,
    kdc: Option<&KdcConf>,
    master: &ProtocolKey,
    mkvno: u16,
) -> Result<PrincipalStore, Error> {
    let mut store = PrincipalStore::try_new(realm)?;
    if let Some(c) = kdc {
        store.apply_kdc_conf(c)?;
    }
    let now = crate::store::unix_now_u32();
    let flags = store.default_create_attributes(false);
    let creation = db_creation(realm, now);

    let km_name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, MASTER_NAME);
    let km_keys = vec![KeyEntry::new(
        master.etype(),
        master.clone(),
        u32::from(mkvno),
    )];
    let mut km = new_entry(&store, km_name, km_keys, flags | KDB_DISALLOW_ALL_TIX);
    let mut actkvno = Vec::with_capacity(8);
    actkvno.extend_from_slice(&1u16.to_le_bytes());
    actkvno.extend_from_slice(&mkvno.to_le_bytes());
    actkvno.extend_from_slice(&0u32.to_le_bytes());
    km.mkvno = mkvno;
    km.tl_data = vec![
        tl(TL_MKVNO, mkvno.to_le_bytes().to_vec()),
        tl(TL_ACTKVNO, actkvno),
        creation.clone(),
    ];
    store.debug_insert(km);

    let mut tgt_keys = Vec::new();
    for etype in store.policy.password_etypes() {
        tgt_keys.push(KeyEntry::new(etype, random_key(etype)?, 1));
    }
    let mut tgt = new_entry(&store, PrincipalName::krbtgt(realm), tgt_keys, flags);
    tgt.mkvno = mkvno;
    tgt.tl_data = vec![creation];
    store.debug_insert(tgt);
    Ok(store)
}

/// Admin is three hours; changepw is five minutes.
pub fn add_admin_principals(store: &mut PrincipalStore, mkvno: u16) -> Result<(), Error> {
    let realm = store.realm().to_owned();
    let caller = crate::kdb5_util_id_for_realm(&realm);
    for (name, attributes, max_life) in [
        (
            crate::principals::kadmin_admin(),
            KDB_DISALLOW_TGT_BASED | KDB_LOCKDOWN_KEYS,
            ADMIN_LIFETIME,
        ),
        (
            crate::principals::kadmin_changepw(),
            KDB_DISALLOW_TGT_BASED | KDB_PWCHANGE_SERVICE | KDB_LOCKDOWN_KEYS,
            CHANGEPW_LIFETIME,
        ),
    ] {
        let ent = AdminEnt {
            mask: kadm5_mask::ATTRIBUTES | kadm5_mask::MAX_LIFE,
            attributes,
            max_life,
            ..AdminEnt::default()
        };
        store.create_principal_3_in(&name, &realm, None, &[], &ent, &caller)?;
        stamp_kadm5_create_tl(store, &name, mkvno);
    }
    Ok(())
}

fn new_entry(
    store: &PrincipalStore,
    name: PrincipalName,
    keys: Vec<KeyEntry>,
    attributes: u32,
) -> Principal {
    let attributes = attributes | KDB_LOCKDOWN_KEYS;
    let realm = store.realm().to_owned();
    let salt = name.default_salt(&realm);
    let mut p = Principal::from_keys(
        name,
        realm,
        keys,
        salt,
        PrincipalFields {
            requires_preauth: attributes & KDB_REQUIRES_PRE_AUTH != 0,
            max_life: store.policy.max_life,
            locked: attributes & KDB_DISALLOW_ALL_TIX != 0,
            pw_expire: 0,
        },
    );
    p.attributes = attributes;
    p.max_renewable_life = store.policy.max_renewable_life;
    p.expiration = store.policy.default_principal_expiration;
    p
}

fn db_creation(realm: &str, now: u32) -> TlData {
    let mut contents = now.to_le_bytes().to_vec();
    contents.extend_from_slice(format!("db_creation@{realm}").as_bytes());
    contents.push(0);
    tl(TL_MOD_PRINC, contents)
}

fn tl(ty: i32, contents: Vec<u8>) -> TlData {
    TlData { ty, contents }
}

// MIT: `kadm5_create_principal_3` (lib/kadm5/srv/svr_principal.c:475-478)
// MIT: `kadm5_create_principal_3` (lib/kadm5/srv/svr_principal.c:490-501)
fn stamp_kadm5_create_tl(store: &mut PrincipalStore, name: &PrincipalName, mkvno: u16) {
    let Some(mut p) = store.get_name(name).cloned() else {
        return;
    };
    let mod_princ = p.tl_data.iter().find(|t| t.ty == TL_MOD_PRINC).cloned();
    let last_pwd = p
        .tl_data
        .iter()
        .find(|t| t.ty == TL_LAST_PWD_CHANGE)
        .cloned();
    p.tl_data.clear();
    refresh_kadm_tl(&mut p);
    p.tl_data.retain(|t| t.ty == TL_KADM_DATA);
    p.tl_data.extend(mod_princ);
    p.tl_data.push(tl(TL_MKVNO, mkvno.to_le_bytes().to_vec()));
    p.tl_data.extend(last_pwd);
    p.mkvno = mkvno;
    store.debug_insert(p);
}

pub fn kdc_conf_for_realm(text: &str, realm: &str) -> Result<KdcConf, krb5_config::Error> {
    KdcConf::parse_for_realm(text, realm)
}

#[cfg(feature = "test-hooks")]
pub fn seed_test_principals(
    store: &mut PrincipalStore,
    user_password: &[u8],
    admin_password: &[u8],
) -> Result<(), Error> {
    use crate::testrealm::{TEST_ADMIN, TEST_USER, documented_kiprop};
    let realm = store.realm().to_owned();
    let creator = format!("db_creation@{realm}");
    for (who, pw) in [(TEST_USER, user_password), (TEST_ADMIN, admin_password)] {
        let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [who]);
        store.insert_new_password(&name, &realm, pw, &[], &creator)?;
    }
    let actor = crate::admin_id_for_realm(&realm);
    let acl = crate::Acl::allow_admin(&actor)?;
    store.create_host(&acl, &actor, &crate::host_for_realm(&realm))?;
    store.create_host(&acl, &actor, &documented_kiprop())?;
    Ok(())
}
