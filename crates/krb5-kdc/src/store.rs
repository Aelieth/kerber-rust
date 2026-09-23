//! In-memory principal database and ACL-gated mutations.
//!
//! One module per MIT source family: `flags` (`KRB5_KDB_*`), `principal`,
//! `policy`, `password` (quality, chpass, history compare), `keys`,
//! `alias`, `transit`, `iprop_ulog`, `history`, `rid`. In-src tests live
//! in `store/tests.rs`.

mod alias;
mod flags;
mod history;
mod iprop_ulog;
mod keys;
mod password;
mod policy;
mod principal;
mod rid;
mod transit;

#[cfg(test)]
mod tests;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use krb5_protocol::ReplayCache;
use krb5_types::PrincipalName;
use krb5_types::pac::RpcSid;
use krb5_types::pkinit::PkinitCa;

use crate::error::Error;
use principal::default_mod_actor;
use rid::generate_domain_sid;

fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u32::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
use std::cell::Cell;

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_KTADD_EXPORT: Cell<bool> = const { Cell::new(false) };
    static FAIL_NEXT_CHRAND_SAVE: Cell<bool> = const { Cell::new(false) };
}

/// kadm5 `KADM5_*` mask bits (`lib/kadm5/admin.h`) that a create or modify
/// request carries alongside its `kadm5_principal_ent_rec`.
pub mod kadm5_mask {
    /// `KADM5_PRINCIPAL`.
    pub const PRINCIPAL: u32 = 0x0000_0001;
    /// `KADM5_PRINC_EXPIRE_TIME`.
    pub(crate) const PRINC_EXPIRE_TIME: u32 = 0x0000_0002;
    /// `KADM5_PW_EXPIRATION`.
    pub(crate) const PW_EXPIRATION: u32 = 0x0000_0004;
    /// `KADM5_ATTRIBUTES`.
    pub const ATTRIBUTES: u32 = 0x0000_0010;
    /// `KADM5_MAX_LIFE`.
    pub const MAX_LIFE: u32 = 0x0000_0020;
    /// `KADM5_KVNO`.
    pub const KVNO: u32 = 0x0000_0100;
    /// `KADM5_POLICY`.
    pub const POLICY: u32 = 0x0000_0800;
    /// `KADM5_POLICY_CLR`.
    pub const POLICY_CLR: u32 = 0x0000_1000;
    /// `KADM5_MAX_RLIFE`.
    pub(crate) const MAX_RLIFE: u32 = 0x0000_2000;
    /// `KADM5_KEY_DATA`.
    pub const KEY_DATA: u32 = 0x0002_0000;
}

/// Realm principal store (dump-v7 / HashMap backend).
#[derive(Clone, Debug)]
pub struct PrincipalStore {
    realm: String,
    map: HashMap<String, Principal>,
    /// Ticket policy.
    pub policy: Policy,
    env: crate::kdb::KdcEnv,
    /// Optional `(db, stash)` paths; mutations write through when set.
    pub persist_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
    /// Last observed (mtime, len) of the db file; kadmind mutations bump it.
    pub(crate) db_stamp: Option<(Option<std::time::SystemTime>, u64)>,
    /// Per-realm NT domain SID (never the dummy `S-1-5-21-1-2-3`).
    domain_sid: RpcSid,
    /// Next RID to allocate (`RID_FIRST_USER` and up).
    next_rid: u32,
    policies: HashMap<String, NamedPolicy>,
    as_fail: Arc<Mutex<HashMap<String, AsFailState>>>,
    serial: Arc<AtomicU32>,
    ulog: Arc<Mutex<VecDeque<UlogEntry>>>,
    pending: Arc<Mutex<Vec<UlogEntry>>>,
}

pub(crate) fn unix_now_u32() -> u32 {
    u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(u32::MAX)
}

impl PrincipalStore {
    /// Empty store for `realm`.
    #[must_use]
    pub fn new(realm: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
            map: HashMap::new(),
            policy: Policy::default(),
            env: crate::kdb::KdcEnv::new(),
            persist_paths: None,
            db_stamp: None,
            domain_sid: generate_domain_sid().unwrap_or_else(|_| {
                eprintln!("krb5-kdc: getrandom failed generating domain SID");
                std::process::exit(1);
            }),
            next_rid: RID_FIRST_USER,
            policies: HashMap::new(),
            as_fail: Arc::new(Mutex::new(HashMap::new())),
            serial: Arc::new(AtomicU32::new(0)),
            ulog: Arc::new(Mutex::new(VecDeque::new())),
            pending: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Reload from stash/db when the file mtime or length changed.
    ///
    /// Kadmind and the KDC are separate processes sharing `KRB5_KDC_DB`.
    /// Length is part of the stamp because some filesystems have 1s mtime.
    /// There is no dump file lock: reload→mutate→save can still lose a
    /// concurrent writer's last save (dirty-flag/lock is with db2/LMDB).
    ///
    /// # Errors
    ///
    /// Persist load failures.
    pub fn reload_if_stale(&mut self) -> Result<(), Error> {
        let Some((db, stash)) = self.persist_paths.clone() else {
            return Ok(());
        };
        let Ok(meta) = std::fs::metadata(&db) else {
            return Ok(());
        };
        let stamp = (meta.modified().ok(), meta.len());
        if Some(stamp) == self.db_stamp {
            return Ok(());
        }
        tracing::info!(
            event = krb5_log::events::KDC_LISTEN,
            correlation_id = krb5_log::current_correlation_id(),
            component = "krb5-kdc",
            outcome = "ok",
            detail = "reload store",
            db_len = stamp.1,
        );
        let mut loaded =
            crate::persist::load_store(&db, &stash).map_err(|e| Error::Crypto(e.to_string()))?;
        loaded.db_stamp = Some(stamp);
        // Dump rows/named-policies/serial come from disk; kdc.conf ticket
        // policy, lockout overlay, replay caches, and PKINIT CA are process-local.
        loaded.policy.clone_from(&self.policy);
        loaded.domain_sid.clone_from(&self.domain_sid);
        loaded.as_fail = Arc::clone(&self.as_fail);
        loaded.env = std::mem::take(&mut self.env);
        *self = loaded;
        Ok(())
    }

    /// Ticket policy.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Process-local KDC env (replay / PKINIT CA).
    #[must_use]
    pub fn env(&self) -> &crate::kdb::KdcEnv {
        &self.env
    }

    /// TGS replay cache.
    #[must_use]
    pub fn tgs_replay(&self) -> &ReplayCache {
        &self.env.tgs_replay
    }

    /// PA-ENC-TIMESTAMP replay cache.
    #[must_use]
    pub fn pa_replay(&self) -> &ReplayCache {
        &self.env.pa_replay
    }

    /// PKINIT CA if provisioned.
    #[must_use]
    pub fn pkinit_ca(&self) -> Option<&PkinitCa> {
        self.env.pkinit_ca.as_ref()
    }

    pub(crate) fn save_configured(&self) -> Result<(), Error> {
        self.save_if_configured()
    }

    fn save_if_configured(&self) -> Result<(), Error> {
        self.commit_ulog();
        let Some((db, stash)) = &self.persist_paths else {
            return Ok(());
        };
        crate::persist::save_store(self, db, stash).map_err(|e| Error::Crypto(e.to_string()))?;
        tracing::info!(
            event = krb5_log::events::ADMIN,
            component = "krb5-kdc",
            outcome = "ok",
            detail = "saved store",
            db = %db.display(),
        );
        Ok(())
    }

    /// Provision a PKINIT test CA. Off by default so a KDC without an
    /// operator-supplied trust anchor does not mint untrusted CMS.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when P-256 key generation fails.
    pub fn enable_pkinit_ca(&mut self) -> Result<&PkinitCa, Error> {
        if self.env.pkinit_ca.is_none() {
            self.env.pkinit_ca = PkinitCa::generate();
        }
        self.env
            .pkinit_ca
            .as_ref()
            .ok_or_else(|| Error::Crypto("pkinit CA generate failed".into()))
    }

    /// Realm name.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Seed krbtgt, a password user, and an admin. Host principals are added
    /// through [`Self::create_host`].
    ///
    /// # Errors
    ///
    /// Returns crypto failures from string-to-key.
    pub fn bootstrap(
        realm: &str,
        user: &str,
        user_password: &[u8],
        admin: &str,
        admin_password: &[u8],
    ) -> Result<Self, Error> {
        Self::bootstrap_with_kdc_conf(realm, user, user_password, admin, admin_password, None)
    }

    /// [`Self::bootstrap`] after applying `kdc.conf` so `supported_enctypes`
    /// orders keys like MIT `kdb5_util create` / `addprinc` without `-e`.
    ///
    /// # Errors
    ///
    /// Returns crypto failures from string-to-key, or an unparseable
    /// `domain_sid`.
    pub fn bootstrap_with_kdc_conf(
        realm: &str,
        user: &str,
        user_password: &[u8],
        admin: &str,
        admin_password: &[u8],
        kdc: Option<&krb5_config::KdcConf>,
    ) -> Result<Self, Error> {
        let mut store = Self::new(realm);
        // No profile: keep the harness create default (7 d) so `--test-realm`
        // principals match stock `max_renewable_life = 7d`. A supplied
        // kdc.conf with the key omitted then sets create = 0 and the realm
        // cap = 7 d (`kdc/main.c` vs `alt_prof.c`).
        store.policy.max_renewable_life = 7 * 24 * 3600;
        store.policy.spake_preauth_groups = vec![krb5_types::spake::GROUP_P256];
        if let Some(c) = kdc {
            store.apply_kdc_conf(c)?;
        }
        // MIT `kdb5_util create` (`kdb5_create.c` `add_principal`): the TGS
        // key is random and the entry carries no default flags.
        let tgt = PrincipalName::krbtgt(realm);
        store.create_principal_3_in(
            &tgt,
            realm,
            None,
            &[],
            &AdminEnt {
                mask: kadm5_mask::ATTRIBUTES,
                ..AdminEnt::default()
            },
            &default_mod_actor(realm),
        )?;
        store.apply_admin_fields(
            &tgt,
            AdminFields {
                attributes: Some(KDB_LOCKDOWN_KEYS),
                max_life: None,
                expiration: None,
                pw_expire: None,
                policy: None,
                clear_policy: false,
                max_renewable_life: None,
            },
        )?;
        store.insert_password(
            &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [user]),
            user_password,
        )?;
        store.insert_password(
            &PrincipalName::new(PrincipalName::NT_PRINCIPAL, [admin]),
            admin_password,
        )?;
        Ok(store)
    }

    /// Lookup `name@realm`, following alias stubs like `krb5_db_get_principal`.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Principal> {
        self.map.get(&self.resolve_id(id)?)
    }

    /// The stored record itself, alias stubs included (`kdb5_util dump` view).
    #[must_use]
    pub fn get_raw(&self, id: &str) -> Option<&Principal> {
        self.map.get(id)
    }

    /// Lookup by name components in this realm.
    #[must_use]
    pub fn get_name(&self, name: &PrincipalName) -> Option<&Principal> {
        self.get_in_realm(name, &self.realm)
    }

    /// Lookup `name@princ_realm` (MIT `kdb_get_entry` uses the request realm).
    #[must_use]
    pub fn get_in_realm(&self, name: &PrincipalName, princ_realm: &str) -> Option<&Principal> {
        self.get(&crate::kdb::lookup_principal_id(name, princ_realm))
    }

    /// PEM of the PKINIT test CA for MIT `pkinit_anchors = FILE:`.
    #[must_use]
    pub fn pkinit_anchor_pem(&self) -> Option<String> {
        self.env.pkinit_ca.as_ref().map(PkinitCa::cert_pem)
    }

    /// User identity PEM (cert+key) for MIT `X509_user_identity=FILE:`.
    #[must_use]
    pub fn pkinit_user_pem(&self, cn: &str) -> Option<String> {
        self.env
            .pkinit_ca
            .as_ref()
            .and_then(|c| c.user_identity_pem(cn))
    }

    /// KDC identity PEM (cert+key) for MIT `pkinit_identity = FILE:`.
    #[must_use]
    pub fn pkinit_kdc_pem(&self) -> Option<String> {
        self.env
            .pkinit_ca
            .as_ref()
            .and_then(|c| c.kdc_identity_pem_for(&self.realm))
    }

    /// Principal ids (`name@REALM`), sorted.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.map.keys().cloned().collect();
        v.sort();
        v
    }

    /// Iterate principals (persistence).
    pub(crate) fn debug_principals(&self) -> impl Iterator<Item = &Principal> {
        self.map.values()
    }

    /// Insert a fully-formed principal (persistence / dump load; no ulog).
    pub(crate) fn debug_insert(&mut self, mut p: Principal) {
        self.settle_rid(&mut p);
        self.map.insert(p.id(), p);
    }
}

pub use alias::MAX_ALIAS_DEPTH;
pub use flags::{
    KDB_DISALLOW_ALL_TIX, KDB_DISALLOW_DUP_SKEY, KDB_DISALLOW_FORWARDABLE, KDB_DISALLOW_POSTDATED,
    KDB_DISALLOW_RENEWABLE, KDB_DISALLOW_SVR, KDB_DISALLOW_TGT_BASED, KDB_LOCKDOWN_KEYS,
    KDB_NO_AUTH_DATA_REQUIRED, KDB_OK_AS_DELEGATE, KDB_OK_TO_AUTH_AS_DELEGATE,
    KDB_PWCHANGE_SERVICE, KDB_REQUIRES_HW_AUTH, KDB_REQUIRES_PRE_AUTH, KDB_REQUIRES_PWCHANGE,
    KDB_V1_BASE_LENGTH,
};
pub(crate) use flags::{KDB_DISALLOW_PROXIABLE, KDB_NEW_PRINC, KDB_SUPPORT_DESMD5};
pub use iprop_ulog::{
    IPROP_ERROR, IPROP_FULL_RESYNC, IPROP_NIL, IPROP_OK, IPROP_PERM_DENIED, UlogEntry,
};
pub use keys::{KeyEntry, KeyLookup, random_key};
pub use password::{
    PWQUAL_DICT, PWQUAL_EMPTY, PWQUAL_PRINC, S2K_ITERS, apply_keysalt_policy, s2k_params,
};
pub use policy::{NamedPolicy, Policy, parse_dict_words};
pub use principal::{AdminEnt, AdminFields, KadmData, Principal, TlData, strip_db_args};
pub(crate) use principal::{AsFailState, db_args_put_error, refresh_kadm_tl};
pub use rid::{RID_FIRST_USER, RID_KRBTGT};
pub(crate) use transit::walk_realm_instances;
