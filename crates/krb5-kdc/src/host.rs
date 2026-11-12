use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use krb5_crypto::{KeyUsage, ProtocolKey};
use krb5_types::pac::RpcSid;

use crate::error::Error;
use crate::kdb_dump::DumpPrincipal;
use crate::store::{KDB_DISALLOW_ALL_TIX, NamedPolicy, Principal, PrincipalStore};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalRow {
    pub name: String,
    pub record: Vec<u8>,
    pub has_keys: bool,
    pub disabled: bool,
    pub kvno: u32,
    pub expiration: Option<u32>,
    pub password_expiration: Option<u32>,
    pub policy: Option<String>,
    pub modified_date: u32,
    pub attributes: u32,
    pub alias_target: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedPrincipal {
    pub name: String,
    pub record: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRow {
    pub name: String,
    pub record: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmState {
    pub realm: String,
    pub state: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoadedRealm {
    pub principals: Vec<LoadedPrincipal>,
    pub policies: Vec<PolicyRow>,
    pub realm: Option<RealmState>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RealmBatch {
    pub upsert_principals: Vec<PrincipalRow>,
    pub delete_principals: Vec<String>,
    pub put_policies: Vec<PolicyRow>,
    pub delete_policies: Vec<String>,
    pub realm: Option<RealmState>,
}

impl RealmBatch {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.upsert_principals.is_empty()
            && self.delete_principals.is_empty()
            && self.put_policies.is_empty()
            && self.delete_policies.is_empty()
            && self.realm.is_none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KerberosStoreError {
    NotReady(String),
    Failed(String),
    Refused(String),
}

impl std::fmt::Display for KerberosStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReady(why) => write!(f, "Kerberos store not ready: {why}"),
            Self::Failed(why) => write!(f, "Kerberos store failed: {why}"),
            Self::Refused(why) => write!(f, "Kerberos store refused the change: {why}"),
        }
    }
}

impl std::error::Error for KerberosStoreError {}

/// Blocking calls; `commit` may also run mid-change, before `change_committing`'s closure.
pub trait KerberosStore: Send + Sync {
    fn load(&self) -> Result<LoadedRealm, KerberosStoreError>;
    fn commit(&self, batch: RealmBatch) -> Result<(), KerberosStoreError>;
}

#[derive(Debug, Default)]
pub struct MemoryRealm(Mutex<Option<Held>>);

#[derive(Debug)]
struct Held {
    realm: RealmState,
    principals: BTreeMap<String, Vec<u8>>,
    policies: BTreeMap<String, Vec<u8>>,
}

impl KerberosStore for MemoryRealm {
    fn load(&self) -> Result<LoadedRealm, KerberosStoreError> {
        let held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(h) = held.as_ref() else {
            return Ok(LoadedRealm::default());
        };
        Ok(LoadedRealm {
            principals: h
                .principals
                .iter()
                .map(|(name, record)| LoadedPrincipal {
                    name: name.clone(),
                    record: record.clone(),
                })
                .collect(),
            policies: h
                .policies
                .iter()
                .map(|(name, record)| PolicyRow {
                    name: name.clone(),
                    record: record.clone(),
                })
                .collect(),
            realm: Some(h.realm.clone()),
        })
    }

    fn commit(&self, batch: RealmBatch) -> Result<(), KerberosStoreError> {
        let mut held = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let RealmBatch {
            upsert_principals,
            delete_principals,
            put_policies,
            delete_policies,
            realm,
        } = batch;
        let mut h = match (held.take(), realm) {
            (None, None) => {
                return Err(KerberosStoreError::Refused(
                    "a first commit needs the realm".to_owned(),
                ));
            }
            (Some(h), Some(r)) if r.realm != h.realm.realm => {
                let why = format!("realm name is {}, batch says {}", h.realm.realm, r.realm);
                *held = Some(h);
                return Err(KerberosStoreError::Refused(why));
            }
            (None, Some(r)) => Held {
                realm: r,
                principals: BTreeMap::new(),
                policies: BTreeMap::new(),
            },
            (Some(mut h), Some(r)) => {
                h.realm = r;
                h
            }
            (Some(h), None) => h,
        };
        for name in &delete_principals {
            h.principals.remove(name);
        }
        for name in &delete_policies {
            h.policies.remove(name);
        }
        for p in put_policies {
            h.policies.insert(p.name, p.record);
        }
        for p in upsert_principals {
            h.principals.insert(p.name, p.record);
        }
        *held = Some(h);
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordError {
    Magic { name: String },
    Version { name: String, version: u8 },
    Mkvno { name: String, mkvno: u32 },
    Seal { name: String },
    Name { row: String, sealed: String },
    Body { name: String, text: String },
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Magic { name } => write!(f, "{name}: not a sealed record"),
            Self::Version { name, version } => {
                write!(f, "{name}: record version {version} is not readable here")
            }
            Self::Mkvno { name, mkvno } => {
                write!(f, "{name}: sealed under master key version {mkvno}")
            }
            Self::Seal { name } => write!(f, "{name}: the record's seal does not verify"),
            Self::Name { row, sealed } => write!(f, "{row}: the record names {sealed}"),
            Self::Body { name, text } => write!(f, "{name}: {text}"),
        }
    }
}

impl std::error::Error for RecordError {}

#[derive(Clone, Debug)]
pub struct SealKey {
    pub kvno: u32,
    pub key: ProtocolKey,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Principal = 1,
    Policy = 2,
    Realm = 3,
}

const MAGIC: &[u8; 3] = b"KRH";
const VERSION: u8 = 1;
const SEAL_USAGE: u32 = 1100;
const HEAD: usize = 3 + 1 + 1 + 4 + 4 + 2;

fn seal_input(kind: Kind, realm: &str, name: &str, body: &[u8]) -> Vec<u8> {
    let mut m = b"KRB5-HOST-SEAL\0".to_vec();
    m.extend_from_slice(&[VERSION, kind as u8]);
    for part in [realm.as_bytes(), name.as_bytes()] {
        m.extend_from_slice(part);
        m.push(0);
    }
    m.extend_from_slice(body);
    m
}

fn sealed(k: &SealKey, kind: Kind, realm: &str, name: &str, body: &[u8]) -> Result<Vec<u8>, Error> {
    let usage = KeyUsage::new(SEAL_USAGE)?;
    let mac = krb5_crypto::checksum(&k.key, usage, &seal_input(kind, realm, name, body))?;
    let len = u16::try_from(mac.len()).map_err(|_| Error::Crypto("seal too long".to_owned()))?;
    let mut out = Vec::with_capacity(HEAD + mac.len() + body.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&[VERSION, kind as u8]);
    out.extend_from_slice(&k.kvno.to_be_bytes());
    out.extend_from_slice(&k.key.etype().checksum_type().to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&mac);
    out.extend_from_slice(body);
    Ok(out)
}

fn opened<'r>(
    k: &SealKey,
    kind: Kind,
    realm: &str,
    name: &str,
    record: &'r [u8],
) -> Result<&'r str, RecordError> {
    let body_err = |text: &str| RecordError::Body {
        name: name.to_owned(),
        text: text.to_owned(),
    };
    if record.get(..3) != Some(MAGIC.as_slice()) || record.len() < HEAD {
        return Err(RecordError::Magic {
            name: name.to_owned(),
        });
    }
    let version = record[3];
    if version == 0 || version > VERSION {
        return Err(RecordError::Version {
            name: name.to_owned(),
            version,
        });
    }
    if record[4] != kind as u8 {
        return Err(body_err("a record of another kind"));
    }
    let word = |at: usize| [record[at], record[at + 1], record[at + 2], record[at + 3]];
    let mkvno = u32::from_be_bytes(word(5));
    if mkvno != k.kvno {
        return Err(RecordError::Mkvno {
            name: name.to_owned(),
            mkvno,
        });
    }
    let cksumtype = i32::from_be_bytes(word(9));
    if cksumtype != k.key.etype().checksum_type() {
        return Err(RecordError::Seal {
            name: name.to_owned(),
        });
    }
    let len = usize::from(u16::from_be_bytes([record[13], record[14]]));
    let Some((mac, body)) = record[HEAD..].split_at_checked(len) else {
        return Err(body_err("a truncated seal"));
    };
    let usage = KeyUsage::new(SEAL_USAGE).map_err(|e| body_err(&e.to_string()))?;
    let input = seal_input(kind, realm, name, body);
    if krb5_crypto::verify_checksum_keyed(&k.key, usage, &input, cksumtype, mac).is_err() {
        return Err(RecordError::Seal {
            name: name.to_owned(),
        });
    }
    std::str::from_utf8(body).map_err(|_| body_err("a record that is not UTF-8"))
}

/// The local realm's names drop `@REALM`; a row name with an unescaped `@` keeps its realm.
pub(crate) fn row_name(id: &str, realm: &str) -> String {
    id.strip_suffix(&format!("@{realm}"))
        .map_or_else(|| id.to_owned(), str::to_owned)
}

fn full_name(row: &str, realm: &str) -> String {
    let mut escaped = false;
    for c in row.chars() {
        match c {
            '\\' if !escaped => escaped = true,
            '@' if !escaped => return row.to_owned(),
            _ => escaped = false,
        }
    }
    format!("{row}@{realm}")
}

fn dump_err(e: &crate::kdb_dump::DumpError) -> Error {
    Error::Crypto(e.to_string())
}

pub fn principal_row(
    store: &PrincipalStore,
    p: &Principal,
    k: &SealKey,
) -> Result<PrincipalRow, Error> {
    let realm = store.realm();
    let id = p.id();
    let body = crate::kdb_dump::princ_record(store, p, &k.key).map_err(|e| dump_err(&e))?;
    let attributes = crate::kdb_dump::dump_attributes(p);
    let modified_date = p
        .tl_data
        .iter()
        .find(|t| t.ty == crate::kdb_dump::TL_MOD_PRINC)
        .and_then(|t| crate::kdb_dump::tl_mod_princ(&t.contents))
        .map_or_else(krb5_types::unix_now, |(at, _)| at);
    Ok(PrincipalRow {
        name: row_name(&id, realm),
        record: sealed(k, Kind::Principal, realm, &id, body.as_bytes())?,
        has_keys: !p.keys.is_empty() || !p.opaque_keys.is_empty(),
        disabled: attributes & KDB_DISALLOW_ALL_TIX != 0,
        kvno: p.top_kvno().unwrap_or(0),
        expiration: (p.expiration != 0).then_some(p.expiration),
        password_expiration: (p.pw_expire != 0).then_some(p.pw_expire),
        policy: p.pw_policy.clone(),
        modified_date,
        attributes,
        alias_target: p.alias_target(),
    })
}

pub fn open_principal(
    row: &LoadedPrincipal,
    realm: &str,
    k: &SealKey,
) -> Result<DumpPrincipal, RecordError> {
    let name = full_name(&row.name, realm);
    let body = opened(k, Kind::Principal, realm, &name, &row.record)?;
    let dp = crate::kdb_dump::parse_princ_record(body).map_err(|e| RecordError::Body {
        name: name.clone(),
        text: e.to_string(),
    })?;
    if dp.name != name {
        return Err(RecordError::Name {
            row: row.name.clone(),
            sealed: dp.name,
        });
    }
    Ok(dp)
}

pub fn policy_row(pol: &NamedPolicy, realm: &str, k: &SealKey) -> Result<PolicyRow, Error> {
    let body = crate::kdb_dump::policy_record(pol);
    Ok(PolicyRow {
        name: pol.name.clone(),
        record: sealed(k, Kind::Policy, realm, &pol.name, body.as_bytes())?,
    })
}

pub fn open_policy(row: &PolicyRow, realm: &str, k: &SealKey) -> Result<NamedPolicy, RecordError> {
    let body = opened(k, Kind::Policy, realm, &row.name, &row.record)?;
    let pol = crate::kdb_dump::parse_policy_record(body).ok_or_else(|| RecordError::Body {
        name: row.name.clone(),
        text: "not one policy record".to_owned(),
    })?;
    if pol.name != row.name {
        return Err(RecordError::Name {
            row: row.name.clone(),
            sealed: pol.name,
        });
    }
    Ok(pol)
}

pub fn realm_state(
    realm: &str,
    domain_sid: &RpcSid,
    next_rid: u32,
    k: &SealKey,
) -> Result<RealmState, Error> {
    let body = format!("{}\t{next_rid}\n", domain_sid.to_sddl());
    Ok(RealmState {
        realm: realm.to_owned(),
        state: sealed(k, Kind::Realm, realm, realm, body.as_bytes())?,
    })
}

pub fn open_realm_state(
    state: &RealmState,
    realm: &str,
    k: &SealKey,
) -> Result<(RpcSid, u32), RecordError> {
    if state.realm != realm {
        return Err(RecordError::Name {
            row: state.realm.clone(),
            sealed: realm.to_owned(),
        });
    }
    let body = opened(k, Kind::Realm, realm, realm, &state.state)?;
    body.strip_suffix('\n')
        .and_then(|b| b.split_once('\t'))
        .and_then(|(sid, next)| Some((RpcSid::from_sddl(sid)?, next.parse().ok()?)))
        .ok_or_else(|| RecordError::Body {
            name: realm.to_owned(),
            text: "not one realm-state record".to_owned(),
        })
}
