//! kdb5_util create.

use std::path::Path;

use krb5_config::{KdcConf, KdcPaths, ProfileSet};
use krb5_crypto::{EncryptionType, ProtocolKey};
use krb5_protocol::{Keytab, KeytabEntry};
use krb5_types::PrincipalName;
use zeroize::Zeroizing;

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
    for row in realm_rows(&store, master, mkvno)? {
        store.debug_insert(row);
    }
    Ok(store)
}

// MIT: `add_principal` (kadmin/dbutil/kdb5_create.c:392-406)
// MIT: `add_principal` (kadmin/dbutil/kdb5_create.c:409-440)
// MIT: `add_principal` (kadmin/dbutil/kdb5_create.c:441-454)
// MIT: `add_principal` (kadmin/dbutil/kdb5_create.c:462-465)
/// K/M and krbtgt, as `kdb5_util create` inserts them.
pub fn realm_rows(
    store: &PrincipalStore,
    master: &ProtocolKey,
    mkvno: u16,
) -> Result<Vec<Principal>, Error> {
    let realm = store.realm();
    let now = crate::store::unix_now_u32();
    let flags = store.default_create_attributes(false);
    let creation = db_creation(realm, now);

    let km_name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, MASTER_NAME);
    let km_keys = vec![KeyEntry::new(
        master.etype(),
        master.clone(),
        u32::from(mkvno),
    )];
    let mut km = new_entry(store, km_name, km_keys, flags | KDB_DISALLOW_ALL_TIX);
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

    let mut tgt_keys = Vec::new();
    for ks in store.policy.password_keysalts() {
        if !tgt_keys.iter().any(|k: &KeyEntry| k.etype == ks.etype) {
            tgt_keys.push(KeyEntry::new(ks.etype, random_key(ks.etype)?, 1));
        }
    }
    let mut tgt = new_entry(store, PrincipalName::krbtgt(realm), tgt_keys, flags);
    tgt.mkvno = mkvno;
    tgt.tl_data = vec![creation];
    Ok(vec![km, tgt])
}

// MIT: `add_admin_princs` (kadmin/dbutil/kadm5_create.c:139-154)
// MIT: `add_admin_princ` (kadmin/dbutil/kadm5_create.c:207-213)
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
        if store.get_name(&name).is_some() {
            continue;
        }
        let ent = AdminEnt {
            mask: kadm5_mask::ATTRIBUTES | kadm5_mask::MAX_LIFE,
            attributes,
            max_life,
            ..AdminEnt::default()
        };
        store.create_principal_3_in(
            &name,
            &realm,
            crate::CreateKeys::Random,
            &[],
            &ent,
            &caller,
        )?;
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

pub enum MasterKey {
    Random { etype: Option<EncryptionType> },
    Password(Zeroizing<Vec<u8>>),
    Key(ProtocolKey),
}

pub struct AdminSpec {
    pub name: PrincipalName,
    pub requires_preauth: bool,
    pub etypes: Vec<EncryptionType>,
    pub max_life: Option<u32>,
}

impl AdminSpec {
    #[must_use]
    pub fn new(name: PrincipalName) -> Self {
        Self {
            name,
            requires_preauth: true,
            etypes: Vec::new(),
            max_life: None,
        }
    }
}

pub struct RealmSpec<'a> {
    pub realm: &'a str,
    pub profile: &'a ProfileSet,
    pub mkvno: u16,
    pub admin: Option<AdminSpec>,
}

pub struct Bootstrapped {
    pub master: ProtocolKey,
    pub kvno: u16,
    pub created: Vec<String>,
    pub admin_keytab: Option<Keytab>,
}

pub struct StashTarget<'a> {
    pub path: &'a Path,
}

pub fn bootstrap_realm_into(
    store: &mut PrincipalStore,
    master: MasterKey,
    spec: &RealmSpec<'_>,
) -> Result<Bootstrapped, Error> {
    if store.realm() != spec.realm {
        return Err(Error::InvalidArgument(format!(
            "realm {} does not match the store",
            spec.realm
        )));
    }
    store.change(|store| fill_realm(store, master, spec))?
}

fn fill_realm(
    store: &mut PrincipalStore,
    master: MasterKey,
    spec: &RealmSpec<'_>,
) -> Result<Bootstrapped, Error> {
    let mut created = Vec::new();
    let (master, kvno) = if let Some(found) = master_on_store(store)? {
        found
    } else {
        if let Some(kdc) = spec.profile.kdc.as_ref() {
            store.apply_kdc_conf(kdc)?;
        }
        (resolve_master(spec, master)?, spec.mkvno)
    };
    let mut wrote_rows = false;
    for row in realm_rows(store, &master, kvno)? {
        if store.get_name(&row.name).is_some() {
            continue;
        }
        created.push(row.id());
        store.debug_insert(row);
        wrote_rows = true;
    }
    if wrote_rows && store.db_path().is_some() {
        store.flush_unlogged()?;
    }
    for name in [
        crate::principals::kadmin_admin(),
        crate::principals::kadmin_changepw(),
    ] {
        if store.get_name(&name).is_none() {
            created.push(crate::kdb::lookup_principal_id(&name, spec.realm));
        }
    }
    add_admin_principals(store, kvno)?;
    let admin_keytab = match &spec.admin {
        None => None,
        Some(admin) => {
            if store.get_name(&admin.name).is_none() {
                create_bootstrap_admin(store, spec.realm, admin)?;
                created.push(crate::kdb::lookup_principal_id(&admin.name, spec.realm));
            }
            Some(admin_keytab(store, admin)?)
        }
    };
    Ok(Bootstrapped {
        master,
        kvno,
        created,
        admin_keytab,
    })
}

fn create_bootstrap_admin(
    store: &mut PrincipalStore,
    realm: &str,
    admin: &AdminSpec,
) -> Result<(), Error> {
    let mut attributes = store.default_create_attributes(false);
    if admin.requires_preauth {
        attributes |= KDB_REQUIRES_PRE_AUTH;
    }
    let mut mask = kadm5_mask::ATTRIBUTES;
    let max_life = match admin.max_life {
        Some(life) => {
            mask |= kadm5_mask::MAX_LIFE;
            life
        }
        None => 0,
    };
    let ent = AdminEnt {
        mask,
        attributes,
        max_life,
        ..AdminEnt::default()
    };
    let actor = format!("bootstrap@{realm}");
    let keysalts: Vec<krb5_crypto::KeySalt> = admin.etypes.iter().map(|e| (*e).into()).collect();
    store.create_principal_3_in(
        &admin.name,
        realm,
        crate::CreateKeys::Random,
        &keysalts,
        &ent,
        &actor,
    )
}

fn admin_keytab(store: &PrincipalStore, admin: &AdminSpec) -> Result<Keytab, Error> {
    let principal = store.get_name(&admin.name).ok_or(Error::NotFound)?;
    let want = if admin.etypes.is_empty() {
        vec![
            EncryptionType::Aes256CtsHmacSha196,
            EncryptionType::Aes128CtsHmacSha196,
        ]
    } else {
        admin.etypes.clone()
    };
    let realm = krb5_types::try_ascii(&principal.realm)
        .map_err(|e| Error::InvalidArgument(e.to_string()))?;
    let timestamp = krb5_types::KerberosTime::now().unix_seconds();
    let mut entries = Vec::new();
    for etype in want {
        let Some(key) = principal.key_for(etype) else {
            continue;
        };
        entries.push(KeytabEntry {
            realm: realm.clone(),
            name: principal.name.clone(),
            timestamp,
            kvno: key.kvno,
            key: key.key.clone(),
        });
    }
    if entries.is_empty() {
        return Err(Error::NotFound);
    }
    Ok(Keytab {
        version: 0x0502,
        skipped_unknown_etype: 0,
        unparsed: Vec::new(),
        entries,
    })
}

fn resolve_master(spec: &RealmSpec<'_>, master: MasterKey) -> Result<ProtocolKey, Error> {
    match master {
        MasterKey::Key(key) => Ok(key),
        MasterKey::Random { etype } => {
            let etype = match etype {
                Some(etype) => etype,
                None => profile_master_etype(spec)?,
            };
            random_key(etype)
        }
        MasterKey::Password(password) => {
            crate::mkey::master_key_from_password(spec.realm, password, profile_master_etype(spec)?)
        }
    }
}

fn profile_master_etype(spec: &RealmSpec<'_>) -> Result<EncryptionType, Error> {
    let name = spec
        .profile
        .kdc
        .as_ref()
        .and_then(|conf| conf.master_key_type.as_deref());
    crate::mkey::master_etype(name).map_err(Error::InvalidArgument)
}

fn master_on_store(store: &PrincipalStore) -> Result<Option<(ProtocolKey, u16)>, Error> {
    let name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, crate::mkey::MASTER_NAME);
    let Some(principal) = store.get_name(&name) else {
        return Ok(None);
    };
    if principal.keys.is_empty() {
        return Err(Error::NotFound);
    }
    let kvno = active_kvno(principal)
        .filter(|kvno| {
            principal
                .keys
                .iter()
                .any(|key| key.kvno == u32::from(*kvno))
        })
        .or_else(|| newest_kvno(principal))
        .ok_or_else(|| Error::InvalidArgument("master kvno does not fit".to_owned()))?;
    let key = principal
        .keys
        .iter()
        .find(|key| key.kvno == u32::from(kvno))
        .map(|key| key.key.clone())
        .ok_or(Error::NotFound)?;
    Ok(Some((key, kvno)))
}

// MIT: `find_actkvno` (lib/kdb/kdb5.c:1333-1344)
fn active_kvno(principal: &Principal) -> Option<u16> {
    let tl = principal.tl_data.iter().find(|tl| tl.ty == TL_ACTKVNO)?;
    let bytes = tl.contents.as_slice();
    if bytes.len() < 8 || u16::from_le_bytes([bytes[0], bytes[1]]) != 1 {
        return None;
    }
    let mut chosen = None;
    let mut at = 2;
    let now = crate::store::unix_now_u32();
    while at + 6 <= bytes.len() {
        let kvno = u16::from_le_bytes([bytes[at], bytes[at + 1]]);
        let time = u32::from_le_bytes([bytes[at + 2], bytes[at + 3], bytes[at + 4], bytes[at + 5]]);
        if chosen.is_none() || time <= now {
            chosen = Some(kvno);
        }
        if time > now {
            break;
        }
        at += 6;
    }
    chosen
}

fn newest_kvno(principal: &Principal) -> Option<u16> {
    principal
        .keys
        .iter()
        .map(|key| key.kvno)
        .max()
        .and_then(|kvno| u16::try_from(kvno).ok())
}

pub fn create_database(
    store: &PrincipalStore,
    db: &Path,
    stash: &StashTarget<'_>,
    boot: &Bootstrapped,
) -> Result<(), Error> {
    if stash.path.exists() {
        let (key, kvno) =
            crate::persist::read_stashed_master(stash.path).map_err(|err| db_err(&err))?;
        if kvno != u32::from(boot.kvno)
            || key.etype() != boot.master.etype()
            || key.as_bytes() != boot.master.as_bytes()
        {
            return Err(Error::InvalidArgument(
                "stashed master does not match".into(),
            ));
        }
    } else {
        crate::persist::write_stash(
            stash.path,
            store.realm(),
            &boot.master,
            u32::from(boot.kvno),
        )?;
    }
    ensure_lock_files(db)?;
    commit_store(store, db, &boot.master)
}

pub fn open_or_create(
    paths: &KdcPaths,
    profile: &ProfileSet,
    admin: Option<AdminSpec>,
) -> Result<(PrincipalStore, Bootstrapped), Error> {
    let Some(realm) = paths.realm.as_deref() else {
        return Err(Error::InvalidArgument("no default realm".to_owned()));
    };
    let db = &paths.database_name;
    let stash = &paths.key_stash_file;
    let resumed = if db.exists() || !stash.exists() {
        None
    } else {
        let (key, kvno) = crate::persist::read_stashed_master(stash).map_err(|e| db_err(&e))?;
        let mkvno = u16::try_from(kvno)
            .map_err(|_| Error::InvalidArgument("master kvno does not fit".to_owned()))?;
        Some((MasterKey::Key(key), mkvno))
    };
    let (master, mkvno) = resumed.unwrap_or((MasterKey::Random { etype: None }, 1));
    let mut store = if db.exists() {
        crate::daemon::open_database(paths, &[], "K/M").map_err(open_failure)?
    } else {
        PrincipalStore::try_new(realm)?
    };
    let boot = bootstrap_realm_into(
        &mut store,
        master,
        &RealmSpec {
            realm,
            profile,
            mkvno,
            admin,
        },
    )?;
    if !db.exists() {
        create_database(&store, db, &StashTarget { path: stash }, &boot)?;
        store = crate::daemon::open_database(paths, &[], "K/M").map_err(open_failure)?;
    }
    Ok((store, boot))
}

fn open_failure(f: crate::daemon::OpenFailure) -> Error {
    match f {
        crate::daemon::OpenFailure::Database(e) | crate::daemon::OpenFailure::MasterKey(e) => {
            Error::InvalidArgument(e)
        }
    }
}

fn db_err(err: &impl std::fmt::Display) -> Error {
    Error::Db {
        kind: std::io::ErrorKind::Other,
        text: err.to_string(),
    }
}

fn ensure_lock_files(db: &Path) -> Result<(), Error> {
    let lock = crate::dblock::DbLock::create(db).map_err(|err| db_err(&err))?;
    let policy = crate::dblock::suffixed(db, crate::dblock::SUFFIX_POLICY_LOCK);
    if !policy.exists()
        && let Err(err) = lock.create_policy_lock()
    {
        let _ = lock.unlock();
        return Err(db_err(&err));
    }
    lock.unlock().map_err(|err| db_err(&err))
}

fn commit_store(store: &PrincipalStore, db: &Path, master: &ProtocolKey) -> Result<(), Error> {
    let tmp = temp_database(db);
    clear_temp(&tmp);
    if let Err(err) = crate::persist::create_store(store, &tmp, master) {
        clear_temp(&tmp);
        return Err(db_err(&err));
    }
    if db.exists() {
        clear_temp(&tmp);
        return Err(Error::InvalidArgument("database already exists".into()));
    }
    if let Err(err) = std::fs::rename(&tmp, db) {
        clear_temp(&tmp);
        return Err(db_err(&err));
    }
    clear_temp_locks(&tmp);
    Ok(())
}

fn temp_database(db: &Path) -> std::path::PathBuf {
    let mut name = std::ffi::OsString::from(".");
    name.push(db.file_name().unwrap_or(std::ffi::OsStr::new("principal")));
    name.push(".tmp-create");
    db.with_file_name(name)
}

fn clear_temp(tmp: &Path) {
    let _ = std::fs::remove_file(tmp);
    clear_temp_locks(tmp);
}

fn clear_temp_locks(tmp: &Path) {
    let _ = std::fs::remove_file(crate::dblock::suffixed(tmp, crate::dblock::SUFFIX_LOCK));
    let _ = std::fs::remove_file(crate::dblock::suffixed(
        tmp,
        crate::dblock::SUFFIX_POLICY_LOCK,
    ));
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
