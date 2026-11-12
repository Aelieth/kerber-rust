use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

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
