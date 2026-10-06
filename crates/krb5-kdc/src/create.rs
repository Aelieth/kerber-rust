//! The realm `kdb5_util create` writes: MIT `kdb5_create.c` (`K/M`, `krbtgt`) and
//! `kadm5_create.c` (`kadmin/admin`, `kadmin/changepw`). No other principal is made: no
//! `kadmin/history`, no `kiprop/*`, no host or user.

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

/// MIT `ADMIN_LIFETIME` (`kadm5_create.c:54-54`): `60*60*3`, three hours.
const ADMIN_LIFETIME: u32 = 60 * 60 * 3;
/// MIT `CHANGEPW_LIFETIME` (`kadm5_create.c:55-55`): `60*5`, five minutes.
const CHANGEPW_LIFETIME: u32 = 60 * 5;

/// The principals of a new realm, as MIT `kdb5_util create` writes them, under `master` at
/// master key version `mkvno`.
///
/// `K/M` holds `master`; `krbtgt/realm@realm` has a random key of each `supported_enctypes`
/// type; both are stamped `db_creation@realm` and take the realm's `default_principal_flags`,
/// `max_life`, `max_renewable_life` and `default_principal_expiration`. Then `kadmin/admin` and
/// `kadmin/changepw` are created the way `kadm5_create_principal` creates them for a caller
/// named `kdb5_util`, with MIT's attributes and lifetimes. None of them is logged: with iprop
/// enabled, `kdb5_util create` maps the update log afterwards and starts it over.
/// MIT `kdb5_create` (`kadmin/dbutil/kdb5_create.c:170-175`): `K/M` and `krbtgt` take the realm's flags, lifetimes, expiration and key/salt list.
/// MIT `add_principal` (`kadmin/dbutil/kdb5_create.c:392-406`): each entry is stamped `db_creation` with those defaults.
/// MIT `add_principal` (`kadmin/dbutil/kdb5_create.c:409-440`): `K/M` gets `DISALLOW_ALL_TIX`, the master key, and the active and master key versions.
/// MIT `add_principal` (`kadmin/dbutil/kdb5_create.c:441-454`): `krbtgt` gets one random key per key/salt type.
/// MIT `add_principal` (`kadmin/dbutil/kdb5_create.c:462-465`): both get `LOCKDOWN_KEYS`.
/// MIT `add_admin_princs` (`kadmin/dbutil/kadm5_create.c:139-154`): `kadmin/admin` and `kadmin/changepw`, their attributes and lifetimes.
/// MIT `add_admin_princ` (`kadmin/dbutil/kadm5_create.c:207-213`): a random-key create with only the attributes and the max life masked.
///
/// # Errors
///
/// [`Error::Crypto`] when `kdc` sets a `domain_sid` that is not valid SDDL;
/// [`Error::InvalidArgument`] when its `dict_file` cannot be read for any reason but being
/// missing; [`Error::Rng`] when the CSPRNG fails while generating a random key.
pub fn create_realm(
    realm: &str,
    kdc: Option<&KdcConf>,
    master: &ProtocolKey,
    mkvno: u16,
) -> Result<PrincipalStore, Error> {
    let mut store = PrincipalStore::new(realm);
    if let Some(c) = kdc {
        store.apply_kdc_conf(c)?;
        // MIT `kadm5_create_magic_princs` (`kadmin/dbutil/kadm5_create.c:100-107`): the create starts the admin side, which reads the dictionary or fails.
        store.init_pwqual(Some(c)).map_err(|e| {
            let path = c.dict_file.as_deref().unwrap_or(std::path::Path::new(""));
            Error::InvalidArgument(format!("kdc.conf dict_file {}: {e}", path.display()))
        })?;
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

    let caller = crate::kdb5_util_id_for_realm(realm);
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
        store.create_principal_3_in(&name, realm, None, &[], &ent, &caller)?;
        stamp_kadm5_create_tl(&mut store, &name, mkvno);
    }
    Ok(store)
}

/// `K/M` or `krbtgt` before its tagged data: the realm's lifetimes and expiration, and the
/// given attributes with `LOCKDOWN_KEYS`.
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

/// `KRB5_TL_MOD_PRINC` naming `db_creation@realm`, the modifier `kdb5_util create` stamps on
/// the entries it writes without a kadm5 handle.
fn db_creation(realm: &str, now: u32) -> TlData {
    let mut contents = now.to_le_bytes().to_vec();
    contents.extend_from_slice(format!("db_creation@{realm}").as_bytes());
    contents.push(0);
    tl(TL_MOD_PRINC, contents)
}

fn tl(ty: i32, contents: Vec<u8>) -> TlData {
    TlData { ty, contents }
}

/// The tagged data `kadm5_create_principal` leaves on a new entry, in MIT's order: the admin
/// record, the modifier, the master key version and the password change time.
/// MIT `kadm5_create_principal_3` (`lib/kadm5/srv/svr_principal.c:475-478`): the master key version that wrapped the keys is recorded.
/// MIT `kadm5_create_principal_3` (`lib/kadm5/srv/svr_principal.c:490-501`): the admin record is stored with the entry.
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

/// The settings of the KDC profile `text` that apply to `realm`: every section but
/// `[realms]`, and only `realm`'s own stanza there, so another realm's relations are never
/// lent to this one.
/// MIT `get_string_param` (`lib/kadm5/alt_prof.c:310-336`): a realm parameter is read from that realm's stanza, else it takes the default.
///
/// # Errors
///
/// As [`KdcConf::parse`].
pub fn kdc_conf_for_realm(text: &str, realm: &str) -> Result<KdcConf, krb5_config::Error> {
    let mut kept = String::with_capacity(text.len());
    let mut section = String::new();
    let mut depth = 0usize;
    let mut keep = true;
    for raw in text.lines() {
        let line = raw.trim();
        if depth == 0
            && let Some(s) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
        {
            section = s.trim().to_ascii_lowercase();
            keep = true;
        } else if section == "realms" {
            if line.ends_with('{') {
                if depth == 0 {
                    let name = line
                        .trim_end_matches('{')
                        .trim()
                        .trim_end_matches('=')
                        .trim();
                    keep = name == realm;
                }
                depth += 1;
            } else if line.starts_with('}') && depth > 0 {
                depth -= 1;
                if depth == 0 {
                    if keep {
                        kept.push_str(raw);
                        kept.push('\n');
                    }
                    keep = true;
                    continue;
                }
            }
        }
        if keep {
            kept.push_str(raw);
            kept.push('\n');
        }
    }
    KdcConf::parse(&kept)
}

/// The principals the gates seed beside a new realm: `user@` and `admin@` with the given
/// passwords, `host/testhost.<realm>` and `kiprop/testhost.kerber.test` with random keys.
///
/// # Errors
///
/// [`Error::AlreadyExists`] when one of them exists; [`Error::PasswordPolicy`] when a password
/// is empty; [`Error::Rng`] when the CSPRNG fails.
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
