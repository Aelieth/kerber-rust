//! In-memory principal database and ACL-gated mutations.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

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

use krb5_crypto::{EncryptionType, ProtocolKey, string_to_key};
use krb5_protocol::{Keytab, KeytabEntry, ReplayCache};
use krb5_types::pac::{PacIdentity, RpcSid};
use krb5_types::pkinit::PkinitCa;
use krb5_types::{MAX_TRANSIT_RAW, PrincipalName};
use subtle::ConstantTimeEq;

/// Well-known RID: Administrator.
pub const RID_ADMINISTRATOR: u32 = 500;
/// Well-known RID: krbtgt.
pub const RID_KRBTGT: u32 = 502;
/// First allocated RID for ordinary principals (AD-style).
pub const RID_FIRST_USER: u32 = 1000;

use crate::acl::{Acl, AdminOp, Restrictions};
use crate::error::Error;
use crate::kdb_dump::{TL_LAST_PWD_CHANGE, TL_MOD_PRINC};

/// Default PBKDF2 iteration count advertised in ETYPE-INFO2 (RFC 3962 default).
pub const S2K_ITERS: u32 = 4096;

/// MIT `KRB5_KDB_DISALLOW_POSTDATED`.
pub const KDB_DISALLOW_POSTDATED: u32 = 0x0000_0001;
/// MIT `KRB5_KDB_DISALLOW_FORWARDABLE`.
pub const KDB_DISALLOW_FORWARDABLE: u32 = 0x0000_0002;
/// MIT `KRB5_KDB_DISALLOW_TGT_BASED`.
pub const KDB_DISALLOW_TGT_BASED: u32 = 0x0000_0004;
/// MIT `KRB5_KDB_DISALLOW_RENEWABLE`.
pub const KDB_DISALLOW_RENEWABLE: u32 = 0x0000_0008;
/// MIT `KRB5_KDB_DISALLOW_PROXIABLE`.
pub const KDB_DISALLOW_PROXIABLE: u32 = 0x0000_0010;
/// MIT `KRB5_KDB_DISALLOW_DUP_SKEY`.
pub const KDB_DISALLOW_DUP_SKEY: u32 = 0x0000_0020;
/// MIT `KRB5_KDB_DISALLOW_ALL_TIX`.
pub const KDB_DISALLOW_ALL_TIX: u32 = 0x0000_0040;
/// MIT `KRB5_KDB_REQUIRES_PRE_AUTH`. Captured `getprinc` + dump field is **128**, not `0x8`.
pub const KDB_REQUIRES_PRE_AUTH: u32 = 0x0000_0080;
/// MIT `KRB5_KDB_REQUIRES_HW_AUTH`.
pub const KDB_REQUIRES_HW_AUTH: u32 = 0x0000_0100;
/// MIT `KRB5_KDB_REQUIRES_PWCHANGE` (`+needchange`).
pub const KDB_REQUIRES_PWCHANGE: u32 = 0x0000_0200;
/// MIT `KRB5_KDB_DISALLOW_SVR`.
pub const KDB_DISALLOW_SVR: u32 = 0x0000_1000;
/// MIT `KRB5_KDB_PWCHANGE_SERVICE` — expired keys may still AS to this server.
pub const KDB_PWCHANGE_SERVICE: u32 = 0x0000_2000;
/// MIT `KRB5_KDB_SUPPORT_DESMD5`.
pub const KDB_SUPPORT_DESMD5: u32 = 0x0000_4000;
/// MIT `KRB5_KDB_NEW_PRINC`.
pub const KDB_NEW_PRINC: u32 = 0x0000_8000;
/// MIT `KRB5_KDB_OK_AS_DELEGATE`.
pub const KDB_OK_AS_DELEGATE: u32 = 0x0010_0000;
/// MIT `KRB5_KDB_OK_TO_AUTH_AS_DELEGATE` (S4U2Self may stay forwardable).
pub const KDB_OK_TO_AUTH_AS_DELEGATE: u32 = 0x0020_0000;
/// MIT `KRB5_KDB_NO_AUTH_DATA_REQUIRED`.
pub const KDB_NO_AUTH_DATA_REQUIRED: u32 = 0x0040_0000;
/// MIT `KRB5_KDB_LOCKDOWN_KEYS`.
pub const KDB_LOCKDOWN_KEYS: u32 = 0x0080_0000;
/// MIT `KRB5_KDB_V1_BASE_LENGTH` (dump `len` field).
pub const KDB_V1_BASE_LENGTH: u32 = 38;

/// Long-term key for one etype.
#[derive(Clone, Debug)]
pub struct KeyEntry {
    /// Encryption type.
    pub etype: EncryptionType,
    /// Protocol key.
    pub key: ProtocolKey,
    /// Key version.
    pub kvno: u32,
    /// MIT `key_data_type[1]` when dump `ver` is 2.
    pub salt_type: Option<i32>,
    /// MIT `key_data_contents[1]` (salt) when dump `ver` is 2.
    pub kdb_salt: Option<Vec<u8>>,
}

impl KeyEntry {
    /// Key without dump salt metadata (`ver` 1 on write).
    #[must_use]
    pub fn new(etype: EncryptionType, key: ProtocolKey, kvno: u32) -> Self {
        Self {
            etype,
            key,
            kvno,
            salt_type: None,
            kdb_salt: None,
        }
    }
}

/// MIT dump `tl_data` triplet (type, length implied by contents).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlData {
    /// `tl_data_type` (`KRB5_TL_*`).
    pub ty: i32,
    /// Raw contents (length is `contents.len()`).
    pub contents: Vec<u8>,
}

/// One realm principal.
#[derive(Clone, Debug)]
pub struct Principal {
    /// Name (no realm).
    pub name: PrincipalName,
    /// Realm.
    pub realm: String,
    /// Active key_data (current kvno, plus `keepold` kvnos).
    pub keys: Vec<KeyEntry>,
    /// OSA password-history keys (dump `TL_KERBER_HIST`; not getprinc/EXTRACT).
    pub key_history: Vec<KeyEntry>,
    /// Salt used for password-derived keys.
    pub salt: Vec<u8>,
    /// Whether AS requires PA-ENC-TIMESTAMP.
    pub requires_preauth: bool,
    /// Max ticket life in seconds (0 = use realm policy).
    pub max_life: u64,
    /// Locked out.
    pub locked: bool,
    /// Password expiry unix seconds (0 = none).
    pub pw_expire: u32,
    /// MIT KDB attributes bitfield (passthrough for dump/load).
    pub attributes: u32,
    /// Max renewable life in seconds (0 = use realm policy).
    pub max_renewable_life: u64,
    /// Principal expiration unix seconds (0 = never).
    pub expiration: u32,
    /// Last successful authentication unix seconds.
    pub last_success: u32,
    /// Last failed authentication unix seconds.
    pub last_failed: u32,
    /// Failed password attempts.
    pub fail_auth_count: u32,
    /// Master-key kvno that encrypts `key_data`.
    pub mkvno: u16,
    /// Dump `len` field (`KRB5_KDB_V1_BASE_LENGTH` = 38).
    pub db_entry_len: u32,
    /// Opaque MIT `tl_data` for lossless dump round-trip.
    pub tl_data: Vec<TlData>,
    /// Opaque MIT extra data (`e_data`).
    pub e_data: Vec<u8>,
    /// Relative ID in the realm domain SID (0 = unassigned).
    pub rid: u32,
    /// Evidence-server names allowed to S4U2Proxy here (RBCD).
    pub s4u_allowed_from: Vec<String>,
    /// Target names this principal may S4U2Proxy to (classic constrained
    /// delegation / `msDS-AllowedToDelegateTo`).
    pub s4u_allowed_to: Vec<String>,
    /// Bound named password policy (`policy\t` / kadm5).
    pub pw_policy: Option<String>,
    /// MIT string attributes (`setstr` / `KRB5_TL_STRING_ATTRS`).
    pub string_attrs: Vec<(String, String)>,
}

impl Principal {
    /// Construct a principal with dump metadata zeroed (bootstrap / KDB3 load).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_keys(
        name: PrincipalName,
        realm: String,
        keys: Vec<KeyEntry>,
        salt: Vec<u8>,
        requires_preauth: bool,
        max_life: u64,
        locked: bool,
        pw_expire: u32,
    ) -> Self {
        let mut attributes = 0u32;
        if requires_preauth {
            attributes |= KDB_REQUIRES_PRE_AUTH;
        }
        if locked {
            attributes |= KDB_DISALLOW_ALL_TIX;
        }
        Self {
            name,
            realm,
            keys,
            key_history: Vec::new(),
            salt,
            requires_preauth,
            max_life,
            locked,
            pw_expire,
            attributes,
            max_renewable_life: 0,
            expiration: 0,
            last_success: 0,
            last_failed: 0,
            fail_auth_count: 0,
            mkvno: 1,
            db_entry_len: KDB_V1_BASE_LENGTH,
            tl_data: Vec::new(),
            e_data: Vec::new(),
            rid: 0,
            s4u_allowed_from: Vec::new(),
            s4u_allowed_to: Vec::new(),
            pw_policy: None,
            string_attrs: Vec::new(),
        }
    }
}

/// Circular iprop update-log entry (serial-numbered; MIT `kdb_incr_update`).
#[derive(Clone, Debug)]
pub struct UlogEntry {
    /// Monotonic serial (`kdb_sno_t`).
    pub sno: u32,
    /// Unix seconds.
    pub time: u32,
    /// Unparsed `name@REALM` (or `policy:<name>`).
    pub name: String,
    /// Deletion marker.
    pub deleted: bool,
    /// Snapshot for in-process apply (absent on dump-only markers).
    pub princ: Option<Principal>,
}

const ULOG_CAP: usize = 1024;
/// MIT `UPDATE_OK`.
pub const IPROP_OK: u32 = 0;
/// MIT `UPDATE_FULL_RESYNC_NEEDED`.
pub const IPROP_FULL_RESYNC: u32 = 2;
/// MIT `UPDATE_NIL`.
pub const IPROP_NIL: u32 = 4;
/// MIT `UPDATE_PERM_DENIED`.
pub const IPROP_PERM_DENIED: u32 = 5;

/// Process-local AS fail overlay (count + timestamps). Dump rows stay stale.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AsFailState {
    pub count: u32,
    pub last_failed: u32,
    pub last_success: u32,
}

/// Named dump/kadm5 password policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedPolicy {
    /// Policy name.
    pub name: String,
    /// Minimum password length.
    pub min_length: u32,
    /// Distinct character classes required (0 = none).
    pub min_classes: u32,
    /// History depth (0 = unused).
    pub history: u32,
    /// Failures before lockout (0 = no lockout).
    pub max_fail: u32,
    /// Seconds after `last_failed` after which the fail count resets (0 = never).
    pub pw_failcnt_interval: u32,
    /// Seconds the lock lasts after `last_failed` (0 = until a successful AS).
    pub pw_lockout_duration: u32,
}

impl NamedPolicy {
    /// Name-only policy with no quality/lockout rules.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            min_length: 0,
            min_classes: 0,
            history: 0,
            max_fail: 0,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
        }
    }
}

/// Realm-wide ticket policy.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Max ticket lifetime seconds.
    pub max_life: u64,
    /// Max renewable lifetime seconds.
    pub max_renewable_life: u64,
    /// Whether kdc.conf set `max_renewable_life` (unset ≠ 0).
    pub max_renewable_life_set: bool,
    /// Clock skew seconds.
    pub skew: i64,
    /// Allow weak etypes.
    pub allow_weak_crypto: bool,
    /// MIT `allow_rc4` (session keys).
    pub allow_rc4: bool,
    /// MIT `allow_des3` (session keys).
    pub allow_des3: bool,
    /// MIT `permitted_enctypes`. `None` = DEFAULT (every implemented type).
    pub permitted_enctypes: Option<Vec<EncryptionType>>,
    /// MIT `supported_enctypes`. Empty = AES 17–20.
    pub supported_enctypes: Vec<EncryptionType>,
    /// Default requires_preauth for new principals.
    pub requires_preauth: bool,
    /// `[capaths]` client → server → intermediates (`.` = direct).
    pub capaths: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    /// MIT `reject_bad_transit` (default true).
    pub reject_bad_transit: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_life: 10 * 3600,
            max_renewable_life: 7 * 24 * 3600,
            max_renewable_life_set: false,
            skew: 300,
            allow_weak_crypto: false,
            allow_rc4: false,
            allow_des3: false,
            permitted_enctypes: None,
            supported_enctypes: Vec::new(),
            requires_preauth: true,
            capaths: BTreeMap::new(),
            reject_bad_transit: true,
        }
    }
}

impl Policy {
    /// MIT `krb5_check_transited_list`: anonymous crealm passes; then capaths if present, else hierarchical.
    #[must_use]
    pub fn transit_allowed(&self, crealm: &str, srealm: &str, hops: &[String]) -> bool {
        if crealm == "WELLKNOWN:ANONYMOUS" {
            return true;
        }
        if hops.is_empty() {
            return true;
        }
        let permitted = permitted_transited(&self.capaths, crealm, srealm);
        hops.iter()
            .all(|h| h == crealm || h == srealm || permitted.iter().any(|p| p == h))
    }

    /// MIT `krb5_is_permitted_enctype`.
    #[must_use]
    pub fn etype_permitted(&self, e: EncryptionType) -> bool {
        self.permitted_enctypes
            .as_ref()
            .is_none_or(|v| v.contains(&e))
    }

    /// Long-term keys minted by addprinc/cpw when `-e` is omitted.
    #[must_use]
    pub fn password_etypes(&self) -> Vec<EncryptionType> {
        if self.supported_enctypes.is_empty() {
            randkey_etypes().to_vec()
        } else {
            self.supported_enctypes.clone()
        }
    }
}

fn permitted_transited(
    capaths: &BTreeMap<String, BTreeMap<String, Vec<String>>>,
    crealm: &str,
    srealm: &str,
) -> Vec<String> {
    if let Some(vals) = capaths.get(crealm).and_then(|m| m.get(srealm)) {
        if vals.iter().any(|v| v == ".") {
            return Vec::new();
        }
        return vals.clone();
    }
    hierarchical_intermediates(crealm, srealm)
}

fn hierarchical_intermediates(client: &str, server: &str) -> Vec<String> {
    if client.len() >= MAX_TRANSIT_RAW || server.len() >= MAX_TRANSIT_RAW {
        return Vec::new();
    }
    let c: Vec<&str> = client.split('.').collect();
    let s: Vec<&str> = server.split('.').collect();
    let mut common = 0usize;
    while common < c.len() && common < s.len() && c[c.len() - 1 - common] == s[s.len() - 1 - common]
    {
        common += 1;
    }
    if common == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for k in 1..=c.len() - common {
        out.push(c[k..].join("."));
    }
    for k in (0..s.len() - common).rev() {
        out.push(s[k..].join("."));
    }
    out
}

impl Principal {
    /// `name@REALM` lookup key (`krb5_unparse_name`).
    #[must_use]
    pub fn id(&self) -> String {
        crate::kdb::lookup_principal_id(&self.name, &self.realm)
    }

    /// First key of `etype`, if present (highest kvno preferred).
    #[must_use]
    pub fn key_for(&self, etype: EncryptionType) -> Option<&KeyEntry> {
        self.keys
            .iter()
            .filter(|k| k.etype == etype)
            .max_by_key(|k| k.kvno)
    }

    /// Key matching `etype` and `kvno`.
    #[must_use]
    pub fn key_for_kvno(&self, etype: EncryptionType, kvno: u32) -> Option<&KeyEntry> {
        self.keys
            .iter()
            .find(|k| k.etype == etype && k.kvno == kvno)
            .or_else(|| self.key_for(etype))
    }

    /// MS-KILE `PA-SUPPORTED-ENCTYPES` bits for keys actually present.
    ///
    /// AES-SHA1 17/18 are 0x08/0x10; RFC 8009 19/20 use 0x20/0x40 (the
    /// original MS-KILE table stopped at AES-SHA1; those bits are unused
    /// by FAST/claims which live at 0x00010000+).
    #[must_use]
    pub fn supported_enctypes_mask(&self) -> u32 {
        let mut m = 0u32;
        for k in &self.keys {
            m |= match k.etype {
                EncryptionType::Des3CbcSha1 => 0x0000_0002,
                EncryptionType::Rc4Hmac => 0x0000_0004,
                EncryptionType::Aes128CtsHmacSha196 => 0x0000_0008,
                EncryptionType::Aes256CtsHmacSha196 => 0x0000_0010,
                EncryptionType::Aes128CtsHmacSha256128 => 0x0000_0020,
                EncryptionType::Aes256CtsHmacSha384192 => 0x0000_0040,
                EncryptionType::Camellia128CtsCmac => 0x0000_0080,
                EncryptionType::Camellia256CtsCmac => 0x0000_0100,
            };
        }
        m
    }

    /// Preferred stored key (highest etype in [`EncryptionType::preferred`]).
    #[must_use]
    pub fn best_key(&self) -> Option<&KeyEntry> {
        EncryptionType::preferred()
            .into_iter()
            .find_map(|e| self.key_for(e))
            .or_else(|| self.keys.first())
    }
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

    pub(crate) fn remove_id_inner(&mut self, id: &str) -> Result<(), Error> {
        self.map.remove(id).ok_or(Error::NotFound)?;
        self.note_ulog(id.to_owned(), true, None);
        self.save_if_configured()
    }

    /// Master key for iprop `AT_KEYDATA` (stash, `K/M`, or `KRB5_MASTER_PASSWORD`).
    #[must_use]
    pub fn iprop_master_key(&self) -> Option<krb5_crypto::ProtocolKey> {
        if let Some((_, stash)) = &self.persist_paths
            && let Ok(bytes) = std::fs::read(stash)
        {
            for et in [
                krb5_crypto::EncryptionType::Aes256CtsHmacSha384192,
                krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            ] {
                if let Ok(k) = krb5_crypto::ProtocolKey::from_bytes(et, &bytes) {
                    return Some(k);
                }
            }
        }
        if let Ok(pw) = std::env::var("KRB5_MASTER_PASSWORD")
            && let Ok(k) = crate::master_key_from_password(
                &self.realm,
                pw.as_bytes(),
                crate::harness_master_etype(),
            )
        {
            return Some(k);
        }
        self.get(&format!("K/M@{}", self.realm))
            .and_then(|km| km.best_key())
            .map(|k| k.key.clone())
    }

    /// Monotonic iprop serial (0 = never mutated via save).
    #[must_use]
    pub fn serial(&self) -> u32 {
        self.serial.load(Ordering::SeqCst)
    }

    /// Set serial after dump load (`TL_KERBER_SERIAL`).
    pub(crate) fn set_serial(&self, sno: u32) {
        self.serial.store(sno, Ordering::SeqCst);
    }

    /// Reload ulog entries from persist (`{db}.ulog`).
    pub(crate) fn restore_ulog(&self, entries: Vec<UlogEntry>) {
        let mut log = self
            .ulog
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *log = entries.into();
    }

    /// Snapshot of the update log (oldest first).
    #[must_use]
    pub fn ulog(&self) -> Vec<UlogEntry> {
        self.ulog
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    /// Entries with `sno > last_sno`.
    #[must_use]
    pub fn updates_after(&self, last_sno: u32) -> Vec<UlogEntry> {
        self.ulog()
            .into_iter()
            .filter(|e| e.sno > last_sno)
            .collect()
    }

    /// MIT iprop GET_UPDATES: `(status, last_sno, entries)`.
    ///
    /// `last_sno == 0` is first contact → full resync. A gap in the
    /// circular log also returns full resync.
    #[must_use]
    pub fn iprop_get(&self, last_sno: u32) -> (u32, u32, Vec<UlogEntry>) {
        let cur = self.serial();
        if last_sno == 0 {
            return (IPROP_FULL_RESYNC, cur, Vec::new());
        }
        if last_sno >= cur {
            return (IPROP_NIL, cur, Vec::new());
        }
        let entries = self.updates_after(last_sno);
        if entries.is_empty() {
            return (IPROP_FULL_RESYNC, cur, Vec::new());
        }
        let first = entries.first().map_or(0, |e| e.sno);
        if last_sno.saturating_add(1) < first {
            return (IPROP_FULL_RESYNC, cur, Vec::new());
        }
        (IPROP_OK, cur, entries)
    }

    /// Apply serial-delta (does not re-log).
    ///
    /// MIT incremental kdbe is a field mask: a later `setstr` update may
    /// omit `AT_KEYDATA`. Empty incoming keys/history keep the existing
    /// principal's.
    pub fn apply_updates(&mut self, entries: &[UlogEntry]) {
        for e in entries {
            if e.deleted {
                self.map.remove(&e.name);
            } else if let Some(p) = &e.princ {
                let merged = if let Some(old) = self.map.get(&p.id()) {
                    Self::merge_iprop_princ(old, p)
                } else {
                    p.clone()
                };
                let merged = self.assign_iprop_rid(merged);
                self.map.insert(merged.id(), merged);
            }
            let cur = self.serial();
            if e.sno > cur {
                self.serial.store(e.sno, Ordering::SeqCst);
            }
        }
        let _ = self.save_if_configured();
    }

    fn merge_iprop_princ(old: &Principal, new: &Principal) -> Principal {
        let mut m = new.clone();
        if m.keys.is_empty() {
            m.keys.clone_from(&old.keys);
        }
        if m.key_history.is_empty() {
            m.key_history.clone_from(&old.key_history);
        }
        if m.string_attrs.is_empty() {
            m.string_attrs.clone_from(&old.string_attrs);
        }
        if m.tl_data.is_empty() {
            m.tl_data.clone_from(&old.tl_data);
        }
        if m.pw_policy.is_none() {
            m.pw_policy.clone_from(&old.pw_policy);
        }
        if m.salt.is_empty() {
            m.salt.clone_from(&old.salt);
        }
        if m.rid == 0 {
            m.rid = old.rid;
        }
        m
    }

    /// Incremental kdbe has no SID (vendor `0x4B0x` is stripped). A new
    /// replica row with `rid==0` must not PAC as `RID_FIRST_USER`.
    fn assign_iprop_rid(&mut self, mut p: Principal) -> Principal {
        if p.rid == 0 {
            p.rid = self.alloc_rid(&p.name);
        } else {
            self.bump_next_rid(p.rid);
        }
        p
    }

    fn note_ulog(&self, name: String, deleted: bool, princ: Option<Principal>) {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(UlogEntry {
                sno: 0,
                time: unix_now_u32(),
                name,
                deleted,
                princ,
            });
    }

    fn commit_ulog(&self) {
        let pending: Vec<UlogEntry> = {
            self.pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .drain(..)
                .collect()
        };
        if pending.is_empty() {
            return;
        }
        let mut log = self
            .ulog
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for mut e in pending {
            e.sno = self.serial.fetch_add(1, Ordering::SeqCst) + 1;
            log.push_back(e);
            while log.len() > ULOG_CAP {
                log.pop_front();
            }
        }
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

    /// Apply `kdc.conf` ticket policy.
    ///
    /// # Errors
    ///
    /// Unparseable `domain_sid` SDDL.
    pub fn apply_kdc_conf(&mut self, conf: &krb5_config::KdcConf) -> Result<(), Error> {
        self.policy.max_life = conf.max_life;
        self.policy.max_renewable_life = conf.max_renewable_life;
        self.policy.max_renewable_life_set = conf.max_renewable_life_set;
        self.policy.allow_weak_crypto = conf.allow_weak_crypto;
        if let Some(v) = conf.allow_rc4 {
            self.policy.allow_rc4 = v;
        }
        if let Some(v) = conf.allow_des3 {
            self.policy.allow_des3 = v;
        }
        if !conf.permitted_enctypes.is_empty() {
            self.policy.permitted_enctypes = krb5_crypto::parse_enctype_list(
                &conf.permitted_enctypes.join(" "),
                self.policy.allow_weak_crypto,
            );
        }
        if !conf.supported_enctypes.is_empty() {
            self.policy.supported_enctypes =
                krb5_crypto::parse_keysalt_list(&conf.supported_enctypes.join(" "));
        }
        self.policy.requires_preauth = conf.requires_preauth;
        self.policy.reject_bad_transit = conf.reject_bad_transit;
        if let Some(s) = conf.domain_sid.as_deref() {
            let Some(sid) = RpcSid::from_sddl(s) else {
                return Err(Error::Crypto(format!(
                    "kdc.conf domain_sid is not valid SDDL: {s}"
                )));
            };
            self.domain_sid = sid;
        }
        Ok(())
    }

    /// `[capaths]` from krb5.conf / kdc.conf.
    pub fn set_capaths(&mut self, capaths: BTreeMap<String, BTreeMap<String, Vec<String>>>) {
        self.policy.capaths = capaths;
    }

    /// Overlay `[libdefaults]` `allow_rc4` / `allow_des3` / `permitted_enctypes`.
    pub fn apply_libdefaults(&mut self, conf: &krb5_config::Krb5Conf) {
        if let Some(v) = conf.allow_rc4 {
            self.policy.allow_rc4 = v;
        }
        if let Some(v) = conf.allow_des3 {
            self.policy.allow_des3 = v;
        }
        if !conf.permitted_enctypes.is_empty() {
            self.policy.permitted_enctypes = krb5_crypto::parse_enctype_list(
                &conf.permitted_enctypes.join(" "),
                self.policy.allow_weak_crypto || conf.allow_weak_crypto,
            );
        }
    }

    /// Realm NT domain SID.
    #[must_use]
    pub fn domain_sid(&self) -> &RpcSid {
        &self.domain_sid
    }

    /// Next RID that would be allocated for an ordinary principal.
    #[must_use]
    pub fn next_rid(&self) -> u32 {
        self.next_rid
    }

    /// Override the realm domain SID (config / dump / persist).
    pub fn set_domain_sid(&mut self, sid: RpcSid) {
        self.domain_sid = sid;
    }

    pub(crate) fn set_principal_rid(&mut self, id: &str, rid: u32) {
        if let Some(p) = self.map.get_mut(id) {
            p.rid = rid;
        }
    }

    pub(crate) fn set_next_rid(&mut self, next: u32) {
        if next >= RID_FIRST_USER {
            self.next_rid = next;
        }
    }

    /// Permit `from` to S4U2Proxy to `name` (RBCD allow-list).
    pub fn allow_s4u_from(&mut self, name: &PrincipalName, from: &str) {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        if let Some(p) = self.map.get_mut(&id) {
            p.s4u_allowed_from.push(from.to_owned());
        }
    }

    /// Permit `name` to S4U2Proxy to `to` (classic constrained delegation).
    pub fn allow_s4u_to(&mut self, name: &PrincipalName, to: &str) {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        if let Some(p) = self.map.get_mut(&id) {
            p.s4u_allowed_to.push(to.to_owned());
        }
    }

    /// PAC identity for `name` in `crealm` (store RID, or `RID_FIRST_USER` if unknown).
    #[must_use]
    pub fn pac_identity(&self, name: &PrincipalName, crealm: &str) -> PacIdentity {
        let rid = self.get_name(name).map_or(RID_FIRST_USER, |p| {
            if p.rid == 0 { RID_FIRST_USER } else { p.rid }
        });
        PacIdentity {
            sam: name.components_joined(),
            realm: crealm.to_owned(),
            domain_sid: self.domain_sid.clone(),
            rid,
        }
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
        let mut store = Self::new(realm);
        store.insert_randkey(&PrincipalName::krbtgt(realm), &randkey_etypes())?;
        let tgt = PrincipalName::krbtgt(realm);
        store.apply_admin_fields(&tgt, Some(KDB_LOCKDOWN_KEYS), None, None, None, None, false)?;
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

    /// Lookup `name@realm`.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Principal> {
        self.map.get(id)
    }

    /// Lookup by name components in this realm.
    #[must_use]
    pub fn get_name(&self, name: &PrincipalName) -> Option<&Principal> {
        self.map
            .get(&crate::kdb::lookup_principal_id(name, &self.realm))
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

    /// `krbtgt/REALM@REALM`.
    #[must_use]
    pub fn krbtgt(&self) -> Option<&Principal> {
        self.get_name(&PrincipalName::krbtgt(&self.realm))
    }

    /// Local TGT keys plus inter-realm `krbtgt/FOREIGN` keys (incoming referrals).
    #[must_use]
    pub fn krbtgt_keys(&self) -> Vec<ProtocolKey> {
        self.krbtgt_key_vec()
    }

    pub(crate) fn krbtgt_key_vec(&self) -> Vec<ProtocolKey> {
        let mut out = Vec::new();
        if let Some(p) = self.krbtgt() {
            for k in &p.keys {
                out.push(k.key.clone());
            }
        }
        for p in self.map.values() {
            if p.name.is_krbtgt() && !p.name.is_krbtgt_for(&self.realm) {
                for k in &p.keys {
                    out.push(k.key.clone());
                }
            }
        }
        out
    }

    /// ACL-gated create of a password principal.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::AlreadyExists`].
    pub fn create_password(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
        password: &[u8],
    ) -> Result<(), Error> {
        self.create_password_etypes(acl, actor, name, password, &[])
    }

    /// ACL-gated create with an explicit keysalt list (`addprinc -e`).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::AlreadyExists`].
    pub fn create_password_etypes(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
        password: &[u8],
        etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        acl.check(actor, AdminOp::Create, Some(&id))?;
        if self.map.contains_key(&id) {
            return Err(Error::AlreadyExists);
        }
        self.insert_password_etypes(name, password, etypes)?;
        if let Some(rs) = acl.restrictions(actor, Some(&id)) {
            self.apply_acl_restrictions(&id, rs)?;
        }
        Ok(())
    }

    /// ACL-gated create of a random-key host (or other) principal.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::AlreadyExists`].
    pub fn create_host(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
    ) -> Result<(), Error> {
        self.create_host_etypes(acl, actor, name, &[])
    }

    /// `addprinc -randkey -e`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::AlreadyExists`].
    pub fn create_host_etypes(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
        etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        acl.check(actor, AdminOp::Create, Some(&id))?;
        if self.map.contains_key(&id) {
            return Err(Error::AlreadyExists);
        }
        let keys = if etypes.is_empty() {
            self.policy.password_etypes()
        } else {
            etypes.to_vec()
        };
        self.insert_randkey(name, &keys)?;
        let self_name = name.components_joined();
        if self_name == "kadmin/changepw"
            && let Some(p) = self.map.get_mut(&id)
        {
            p.attributes |= KDB_PWCHANGE_SERVICE;
        }
        self.allow_s4u_from(name, &self_name);
        self.allow_s4u_to(name, &self_name);
        if let Some(rs) = acl.restrictions(actor, Some(&id)) {
            self.apply_acl_restrictions(&id, rs)?;
        }
        if let Some(p) = self.map.get(&id) {
            self.note_ulog(id.clone(), false, Some(p.clone()));
        }
        self.save_if_configured()?;
        Ok(())
    }

    /// Replace password-derived keys (`keepold=false`): one active kvno;
    /// prior keys go to [`Principal::key_history`] pruned to policy depth N.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when the principal is missing.
    pub fn set_password(&mut self, name: &PrincipalName, password: &[u8]) -> Result<(), Error> {
        self.set_password_keepold(name, password, false)
    }

    /// Password change; `keepold` keeps prior key_data kvnos (MIT `cpw -keepold`).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when the principal is missing.
    pub fn set_password_keepold(
        &mut self,
        name: &PrincipalName,
        password: &[u8],
        keepold: bool,
    ) -> Result<(), Error> {
        self.check_password_quality(name, password)?;
        let id = format!("{}@{}", name.components_joined(), self.realm);
        let Some(existing) = self.map.get(&id) else {
            return Err(Error::NotFound);
        };
        let salt = existing.salt.clone();
        let next_kvno = existing
            .keys
            .iter()
            .chain(existing.key_history.iter())
            .map(|k| k.kvno)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        // MIT `pw_history_num` counts the current password inside N, so
        // history=1 keeps no old keys (A→B→A is allowed).
        let depth = existing
            .pw_policy
            .as_ref()
            .and_then(|n| self.policies.get(n))
            .map_or(0, |pol| pol.history.saturating_sub(1));
        let new_keys =
            keys_from_password(&self.policy.password_etypes(), password, &salt, next_kvno)?;
        self.replace_password_keys(&id, new_keys, depth, keepold)
    }

    fn replace_password_keys(
        &mut self,
        id: &str,
        new_keys: Vec<KeyEntry>,
        depth: u32,
        keepold: bool,
    ) -> Result<(), Error> {
        let p = self.map.get_mut(id).ok_or(Error::NotFound)?;
        let old = std::mem::replace(&mut p.keys, new_keys);
        p.key_history.extend(old.iter().cloned());
        p.key_history = prune_key_history(std::mem::take(&mut p.key_history), depth);
        if keepold {
            p.keys.extend(old);
        }
        stamp_admin_tl(p, true);
        let snap = p.clone();
        self.note_ulog(id.to_owned(), false, Some(snap));
        self.save_if_configured()
    }

    /// Set lockout and password-expiry, then persist when `persist_paths` is set.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when the principal is missing, or persist I/O.
    pub fn set_status(
        &mut self,
        name: &PrincipalName,
        locked: bool,
        pw_expire: u32,
    ) -> Result<(), Error> {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        p.locked = locked;
        p.pw_expire = pw_expire;
        if locked {
            p.attributes |= KDB_DISALLOW_ALL_TIX;
        } else {
            p.attributes &= !KDB_DISALLOW_ALL_TIX;
        }
        let snap = p.clone();
        self.note_ulog(id, false, Some(snap));
        self.save_if_configured()
    }

    /// ACL-gated inter-realm `krbtgt/FOREIGN` (shared key with the foreign KDC).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::AlreadyExists`].
    pub fn create_interrealm(
        &mut self,
        acl: &Acl,
        actor: &str,
        foreign_realm: &str,
        password: &[u8],
    ) -> Result<(), Error> {
        let name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", foreign_realm]);
        let id = format!("{}@{}", name.components_joined(), self.realm);
        acl.check(actor, AdminOp::Create, Some(&id))?;
        if self.map.contains_key(&id) {
            return Err(Error::AlreadyExists);
        }
        self.insert_password(&name, password)?;
        if let Some(p) = self.map.get_mut(&id) {
            p.requires_preauth = false;
        }
        if let Some(p) = self.map.get(&id) {
            self.note_ulog(id.clone(), false, Some(p.clone()));
        }
        self.save_if_configured()
    }

    /// Inter-realm `krbtgt/FOREIGN` with an explicit shared key (same bytes
    /// on both KDCs; default salts would diverge).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::AlreadyExists`].
    pub fn create_interrealm_key(
        &mut self,
        acl: &Acl,
        actor: &str,
        foreign_realm: &str,
        key: ProtocolKey,
    ) -> Result<(), Error> {
        let name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", foreign_realm]);
        let id = format!("{}@{}", name.components_joined(), self.realm);
        acl.check(actor, AdminOp::Create, Some(&id))?;
        if self.map.contains_key(&id) {
            return Err(Error::AlreadyExists);
        }
        let salt = name.default_salt(&self.realm);
        let p = Principal::from_keys(
            name,
            self.realm.clone(),
            vec![KeyEntry::new(key.etype(), key, 1)],
            salt,
            false,
            0,
            false,
            0,
        );
        self.put_principal(p);
        self.save_if_configured()
    }

    /// Extra inter-realm key used only to decrypt tickets the peer issued.
    ///
    /// Windows TDOs derive inbound and outbound AES keys from the same
    /// password with different salts. Insert at the front so [`Principal::best_key`]
    /// (highest kvno, last among ties) stays the issue key.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn add_interrealm_decrypt_key(
        &mut self,
        acl: &Acl,
        actor: &str,
        foreign_realm: &str,
        key: ProtocolKey,
    ) -> Result<(), Error> {
        let name = PrincipalName::new(PrincipalName::NT_SRV_INST, ["krbtgt", foreign_realm]);
        let id = format!("{}@{}", name.components_joined(), self.realm);
        acl.check(actor, AdminOp::Create, Some(&id))?;
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        let kvno = p.keys.iter().map(|k| k.kvno).min().unwrap_or(1);
        p.keys.insert(0, KeyEntry::new(key.etype(), key, kvno));
        let snap = p.clone();
        self.note_ulog(id, false, Some(snap));
        self.save_if_configured()
    }

    /// ACL-gated password change (admin `c` / `*`).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn change_password(
        &mut self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
        password: &[u8],
    ) -> Result<(), Error> {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        acl.check(actor, AdminOp::ChangePassword, Some(&id))?;
        self.set_password(name, password)
    }

    /// ACL-gated delete.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn delete(&mut self, acl: &Acl, actor: &str, name: &PrincipalName) -> Result<(), Error> {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        acl.check(actor, AdminOp::Delete, Some(&id))?;
        self.remove_id_inner(&id)
    }

    /// Rename a principal. Requires add and delete ACL privs (MIT).
    ///
    /// RID, keys, and attributes are kept. A non-zero RID is not
    /// re-allocated. Default-salt password keys stay verbatim (MIT);
    /// `kinit` after rename may need an explicit salt or `cpw`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`], [`Error::NotFound`], or [`Error::AlreadyExists`].
    pub fn rename(
        &mut self,
        acl: &Acl,
        actor: &str,
        old: &PrincipalName,
        new: &PrincipalName,
    ) -> Result<(), Error> {
        let old_id = format!("{}@{}", old.components_joined(), self.realm);
        let new_id = format!("{}@{}", new.components_joined(), self.realm);
        acl.check_rename(actor, &old_id, &new_id)?;
        if self.map.contains_key(&new_id) {
            return Err(Error::AlreadyExists);
        }
        let mut p = self.map.remove(&old_id).ok_or(Error::NotFound)?;
        p.name = new.clone();
        self.note_ulog(old_id, true, None);
        self.note_ulog(p.id(), false, Some(p.clone()));
        self.map.insert(p.id(), p);
        self.save_if_configured()
    }

    /// ACL-gated keytab export using the existing v2 writer.
    ///
    /// `LOCKDOWN_KEYS` is refused. Local CLI export uses
    /// [`Self::export_keytab_local`].
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn export_keytab(
        &self,
        acl: &Acl,
        actor: &str,
        name: &PrincipalName,
    ) -> Result<Keytab, Error> {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        acl.check(actor, AdminOp::Ktadd, Some(&id))?;
        let p = self.get_name(name).ok_or(Error::NotFound)?;
        if p.attributes & KDB_LOCKDOWN_KEYS != 0 {
            return Err(Error::AclDenied);
        }
        Self::keytab_from(p)
    }

    /// Local-operator keytab export for `--export-keytab` /
    /// `--export-krbtgt-keytab`.
    ///
    /// The operator already holds the DB and stash, so `LOCKDOWN_KEYS` is
    /// not applied. Remote kadm5 extract still uses [`Self::export_keytab`].
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn export_keytab_local(&self, name: &PrincipalName) -> Result<Keytab, Error> {
        #[cfg(test)]
        if FAIL_NEXT_KTADD_EXPORT.with(Cell::get) {
            FAIL_NEXT_KTADD_EXPORT.with(|c| c.set(false));
            return Err(Error::Crypto("injected export fail".into()));
        }
        let p = self.get_name(name).ok_or(Error::NotFound)?;
        Self::keytab_from(p)
    }

    /// Local `ktadd`: optional rotate, export ignoring lockdown, then `write`.
    ///
    /// On export, write, or chrand-save failure a rotation is rolled back
    /// so the dump kvno is unchanged. Standalone `chrand` does not roll
    /// back. A rollback save error is returned with the original failure
    /// (not swallowed).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`], RNG, persist, or `write`.
    pub fn ktadd_local_atomic(
        &mut self,
        name: &PrincipalName,
        rotate: bool,
        write: impl FnOnce(&Keytab) -> Result<(), Error>,
    ) -> Result<Keytab, Error> {
        let snap = self.get_name(name).cloned().ok_or(Error::NotFound)?;
        if rotate && let Err(e) = self.chrand(name) {
            return Err(self.rollback_rotate(true, snap, e));
        }
        let kt = match self.export_keytab_local(name) {
            Ok(kt) => kt,
            Err(e) => return Err(self.rollback_rotate(rotate, snap, e)),
        };
        match write(&kt) {
            Ok(()) => Ok(kt),
            Err(e) => Err(self.rollback_rotate(rotate, snap, e)),
        }
    }

    fn rollback_rotate(&mut self, rotate: bool, snap: Principal, e: Error) -> Error {
        if !rotate {
            return e;
        }
        let id = snap.id();
        self.note_ulog(id.clone(), false, Some(snap.clone()));
        self.map.insert(id, snap);
        match self.save_if_configured() {
            Ok(()) => e,
            Err(re) => Error::Crypto(format!("{e}; rollback failed: {re}")),
        }
    }

    fn keytab_from(p: &Principal) -> Result<Keytab, Error> {
        if p.keys.is_empty() {
            return Err(Error::NotFound);
        }
        let ts = krb5_types::KerberosTime::now().unix_seconds();
        let realm =
            krb5_types::try_ascii(&p.realm).map_err(|_| Error::Crypto("non-ascii realm".into()))?;
        let entries = p
            .keys
            .iter()
            .map(|key| KeytabEntry {
                realm: realm.clone(),
                name: p.name.clone(),
                timestamp: ts,
                kvno: key.kvno,
                key: key.key.clone(),
            })
            .collect();
        Ok(Keytab {
            version: 0x0502,
            skipped_unknown_etype: 0,
            unparsed: Vec::new(),
            entries,
        })
    }

    fn insert_password(&mut self, name: &PrincipalName, password: &[u8]) -> Result<(), Error> {
        self.insert_password_etypes(name, password, &[])
    }

    fn insert_password_etypes(
        &mut self,
        name: &PrincipalName,
        password: &[u8],
        etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        let salt = name.default_salt(&self.realm);
        let use_etypes = if etypes.is_empty() {
            self.policy.password_etypes()
        } else {
            etypes.to_vec()
        };
        let keys = keys_from_password(&use_etypes, password, &salt, 1)?;
        let mut p = Principal::from_keys(
            name.clone(),
            self.realm.clone(),
            keys,
            salt,
            self.policy.requires_preauth,
            0,
            false,
            0,
        );
        p.max_renewable_life = self.policy.max_renewable_life;
        stamp_admin_tl(&mut p, true);
        self.put_principal(p);
        self.save_if_configured()
    }

    fn insert_randkey(
        &mut self,
        name: &PrincipalName,
        etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        let mut keys = Vec::new();
        for etype in etypes {
            keys.push(KeyEntry::new(*etype, random_key(*etype)?, 1));
        }
        let salt = name.default_salt(&self.realm);
        let mut p = Principal::from_keys(
            name.clone(),
            self.realm.clone(),
            keys,
            salt,
            false,
            0,
            false,
            0,
        );
        p.max_renewable_life = self.policy.max_renewable_life;
        stamp_admin_tl(&mut p, true);
        self.put_principal(p);
        self.save_if_configured()
    }

    /// Key of `etype` at `kvno` for principal `name`.
    #[must_use]
    pub fn key_kvno(
        &self,
        name: &PrincipalName,
        etype: EncryptionType,
        kvno: Option<u32>,
    ) -> Option<&KeyEntry> {
        let p = self.get_name(name)?;
        match kvno {
            Some(v) => p.key_for_kvno(etype, v),
            None => p.key_for(etype),
        }
    }

    /// Principal ids (`name@REALM`), sorted.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.map.keys().cloned().collect();
        v.sort();
        v
    }

    /// Replace long-term keys with a new random kvno (kadm5 `chrand`).
    ///
    /// Default MIT `cpw -randkey` / `ktadd` does not keep old kvnos, so the
    /// previous password must fail `kinit`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] or RNG failure.
    pub fn chrand(&mut self, name: &PrincipalName) -> Result<Vec<KeyEntry>, Error> {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        let existing = self.map.get(&id).ok_or(Error::NotFound)?;
        let next_kvno = existing
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let mut new_keys = Vec::new();
        let etypes = self.policy.password_etypes();
        for etype in etypes {
            new_keys.push(KeyEntry::new(etype, random_key(etype)?, next_kvno));
        }
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        p.keys.clone_from(&new_keys);
        stamp_admin_tl(p, true);
        let snap = p.clone();
        self.note_ulog(id, false, Some(snap));
        #[cfg(test)]
        if FAIL_NEXT_CHRAND_SAVE.with(Cell::get) {
            FAIL_NEXT_CHRAND_SAVE.with(|c| c.set(false));
            return Err(Error::Crypto("injected chrand save fail".into()));
        }
        self.save_if_configured()?;
        Ok(new_keys)
    }

    /// Drop keys with kvno below `keepkvno`. `keepkvno <= 0` keeps only the
    /// newest kvno (MIT `purgekeys` without `-keepkvno`).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn purgekeys(&mut self, name: &PrincipalName, keepkvno: i32) -> Result<(), Error> {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        let keep = if keepkvno <= 0 {
            p.keys.iter().map(|k| k.kvno).max().unwrap_or(0)
        } else {
            u32::try_from(keepkvno).unwrap_or(u32::MAX)
        };
        p.keys.retain(|k| k.kvno >= keep);
        let snap = p.clone();
        self.note_ulog(id, false, Some(snap));
        self.save_if_configured()
    }

    /// Replace keys with caller-supplied material (`kadm5_setkey_principal`).
    ///
    /// `kvno == 0` on every entry picks the next version. `keepold` retains
    /// prior kvnos in [`Principal::keys`].
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`], or [`Error::Crypto`] when `keepold` collides with
    /// an existing kvno.
    pub fn set_keys(
        &mut self,
        name: &PrincipalName,
        mut keys: Vec<KeyEntry>,
        keepold: bool,
    ) -> Result<(), Error> {
        if keys.is_empty() {
            return Err(Error::Crypto("setkey empty".into()));
        }
        let id = format!("{}@{}", name.components_joined(), self.realm);
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        let want = keys[0].kvno;
        if keys.iter().any(|k| k.kvno != want) {
            return Err(Error::Crypto("setkey kvno".into()));
        }
        let kvno = if want == 0 {
            p.keys
                .iter()
                .chain(p.key_history.iter())
                .map(|k| k.kvno)
                .max()
                .unwrap_or(0)
                .saturating_add(1)
        } else {
            if keepold && p.keys.iter().any(|k| k.kvno == want) {
                return Err(Error::Crypto("setkey kvno".into()));
            }
            want
        };
        for k in &mut keys {
            k.kvno = kvno;
        }
        if keepold {
            let old = std::mem::replace(&mut p.keys, keys);
            p.keys.extend(old);
        } else {
            p.keys = keys;
        }
        stamp_admin_tl(p, true);
        let snap = p.clone();
        self.note_ulog(id, false, Some(snap));
        self.save_if_configured()
    }

    /// Apply kadm5 `modprinc` fields (mask already interpreted by the caller).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    #[allow(clippy::too_many_arguments)]
    pub fn apply_admin_fields(
        &mut self,
        name: &PrincipalName,
        attributes: Option<u32>,
        max_life: Option<u64>,
        expiration: Option<u32>,
        pw_expire: Option<u32>,
        policy: Option<String>,
        clear_policy: bool,
    ) -> Result<(), Error> {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        if let Some(a) = attributes {
            p.attributes = a;
            p.requires_preauth = a & KDB_REQUIRES_PRE_AUTH != 0;
            p.locked = a & KDB_DISALLOW_ALL_TIX != 0;
        }
        if let Some(m) = max_life {
            p.max_life = m;
        }
        if let Some(e) = expiration {
            p.expiration = e;
        }
        if let Some(e) = pw_expire {
            p.pw_expire = e;
        }
        if clear_policy {
            p.pw_policy = None;
        } else if let Some(pol) = policy {
            p.pw_policy = Some(pol);
        }
        stamp_admin_tl(p, false);
        let snap = p.clone();
        self.note_ulog(id, false, Some(snap));
        self.save_if_configured()
    }

    /// Impose kadm5.acl restrictions after create/modify (`auth.c` `impose_restrictions`).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn impose_acl_restrictions(
        &mut self,
        name: &PrincipalName,
        rs: &Restrictions,
    ) -> Result<(), Error> {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        self.apply_acl_restrictions(&id, rs)?;
        self.save_if_configured()
    }

    fn apply_acl_restrictions(&mut self, id: &str, rs: &Restrictions) -> Result<(), Error> {
        let p = self.map.get_mut(id).ok_or(Error::NotFound)?;
        rs.apply_to(p, unix_now());
        Ok(())
    }

    /// Iterate principals (persistence).
    pub(crate) fn debug_principals(&self) -> impl Iterator<Item = &Principal> {
        self.map.values()
    }

    /// Insert a fully-formed principal (persistence / dump load; no ulog).
    pub(crate) fn debug_insert(&mut self, mut p: Principal) {
        if p.rid == 0 {
            p.rid = self.alloc_rid(&p.name);
        }
        self.bump_next_rid(p.rid);
        self.map.insert(p.id(), p);
    }

    /// Named password policies.
    #[must_use]
    pub fn policies(&self) -> &HashMap<String, NamedPolicy> {
        &self.policies
    }

    /// Insert or replace a named policy.
    pub fn put_policy(&mut self, pol: NamedPolicy) {
        self.note_ulog(format!("policy:{}", pol.name), false, None);
        self.policies.insert(pol.name.clone(), pol);
        let _ = self.save_if_configured();
    }

    /// Load a dump policy without logging (dump/iprop apply).
    pub(crate) fn load_policy(&mut self, pol: NamedPolicy) {
        self.policies.insert(pol.name.clone(), pol);
    }

    /// Delete a named policy.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn delete_policy(&mut self, name: &str) -> Result<(), Error> {
        self.policies.remove(name).ok_or(Error::NotFound)?;
        self.note_ulog(format!("policy:{name}"), true, None);
        self.save_if_configured()
    }

    /// Bind `princ` to `policy` (None unbinds).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn set_principal_policy(
        &mut self,
        name: &PrincipalName,
        policy: Option<String>,
    ) -> Result<(), Error> {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        p.pw_policy = policy;
        let snap = p.clone();
        self.note_ulog(id, false, Some(snap));
        self.save_if_configured()
    }

    /// MIT `kadm5_get_strings`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn get_strings(&self, name: &PrincipalName) -> Result<Vec<(String, String)>, Error> {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        let p = self.map.get(&id).ok_or(Error::NotFound)?;
        Ok(p.string_attrs.clone())
    }

    /// MIT `kadm5_set_string`. `value == None` deletes `key`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn set_string(
        &mut self,
        name: &PrincipalName,
        key: &str,
        value: Option<&str>,
    ) -> Result<(), Error> {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
        p.string_attrs.retain(|(k, _)| k != key);
        if let Some(v) = value {
            p.string_attrs.push((key.to_owned(), v.to_owned()));
        }
        let snap = p.clone();
        self.note_ulog(id, false, Some(snap));
        self.save_if_configured()
    }

    /// Reject `password` against a named policy (create / kadm5 `-policy`).
    ///
    /// # Errors
    ///
    /// [`Error::PasswordPolicy`].
    pub fn check_named_policy(&self, policy: &str, password: &[u8]) -> Result<(), Error> {
        match self.policies.get(policy) {
            Some(pol) => check_pwqual(password, pol),
            None => Ok(()),
        }
    }

    /// Reject `password` against the principal's named policy.
    ///
    /// # Errors
    ///
    /// [`Error::PasswordPolicy`].
    pub fn check_password_quality(
        &self,
        name: &PrincipalName,
        password: &[u8],
    ) -> Result<(), Error> {
        let Some(p) = self.get_name(name) else {
            return Ok(());
        };
        let Some(ref n) = p.pw_policy else {
            return Ok(());
        };
        let Some(pol) = self.policies.get(n) else {
            return Ok(());
        };
        check_pwqual(password, pol)?;
        if pol.history == 0 {
            return Ok(());
        }
        let extra = pol.history.saturating_sub(1) as usize;
        let mut hist: Vec<&KeyEntry> = p.key_history.iter().collect();
        let mut kvnos: Vec<u32> = hist.iter().map(|k| k.kvno).collect();
        kvnos.sort_unstable();
        kvnos.dedup();
        let keep: Vec<u32> = kvnos.into_iter().rev().take(extra).collect();
        hist.retain(|k| keep.contains(&k.kvno));
        for k in p.keys.iter().chain(hist) {
            let params = s2k_params(k.etype);
            if let Ok(nk) = string_to_key(k.etype, password, &p.salt, Some(&params))
                && bool::from(nk.as_bytes().ct_eq(k.key.as_bytes()))
            {
                return Err(Error::PasswordPolicy("history".into()));
            }
        }
        Ok(())
    }

    /// Overlay AS-fail count for lockout (absolute; success stores 0).
    #[must_use]
    pub fn fail_auth_of(&self, p: &Principal) -> u32 {
        self.as_fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&p.id())
            .map_or(p.fail_auth_count, |s| s.count)
    }

    /// Overlay last-failed unix seconds (dump field if the overlay is empty).
    #[must_use]
    pub fn last_failed_of(&self, p: &Principal) -> u32 {
        self.as_fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&p.id())
            .map_or(p.last_failed, |s| s.last_failed)
    }

    /// Overlay last-success unix seconds.
    #[must_use]
    pub fn last_success_of(&self, p: &Principal) -> u32 {
        self.as_fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&p.id())
            .map_or(p.last_success, |s| s.last_success)
    }

    /// Max failures from the bound policy (0 = no lockout).
    #[must_use]
    pub fn max_fail_for(&self, p: &Principal) -> u32 {
        p.pw_policy
            .as_ref()
            .and_then(|n| self.policies.get(n))
            .map_or(0, |pol| pol.max_fail)
    }

    /// Bound named policy, if any.
    #[must_use]
    pub fn named_policy_for(&self, p: &Principal) -> Option<NamedPolicy> {
        p.pw_policy
            .as_ref()
            .and_then(|n| self.policies.get(n).cloned())
    }

    /// Zero the overlay fail count without stamping last_success (interval reset).
    pub fn clear_as_fail_count(&self, name: &PrincipalName) {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        let fallback = self
            .map
            .get(&id)
            .map_or(AsFailState::default(), |p| AsFailState {
                count: 0,
                last_failed: p.last_failed,
                last_success: p.last_success,
            });
        let mut g = self
            .as_fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match g.get_mut(&id) {
            Some(s) => s.count = 0,
            None => {
                g.insert(id, fallback);
            }
        }
    }

    /// Record AS password outcome (interior-mutable; dump writes the overlay).
    pub fn record_as_outcome(&self, name: &PrincipalName, ok: bool) {
        let id = format!("{}@{}", name.components_joined(), self.realm);
        let fallback = self
            .map
            .get(&id)
            .map_or(AsFailState::default(), |p| AsFailState {
                count: p.fail_auth_count,
                last_failed: p.last_failed,
                last_success: p.last_success,
            });
        let now = unix_now_u32();
        let mut g = self
            .as_fail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cur = g.get(&id).copied().unwrap_or(fallback);
        if ok {
            g.insert(
                id,
                AsFailState {
                    count: 0,
                    last_failed: cur.last_failed,
                    last_success: now,
                },
            );
        } else {
            g.insert(
                id,
                AsFailState {
                    count: cur.count.saturating_add(1),
                    last_failed: now,
                    last_success: cur.last_success,
                },
            );
        }
    }

    fn put_principal(&mut self, mut p: Principal) {
        if p.rid == 0 {
            p.rid = self.alloc_rid(&p.name);
        }
        self.bump_next_rid(p.rid);
        let id = p.id();
        self.note_ulog(id.clone(), false, Some(p.clone()));
        self.map.insert(id, p);
    }

    fn alloc_rid(&mut self, name: &PrincipalName) -> u32 {
        if name.is_krbtgt_for(&self.realm) {
            return RID_KRBTGT;
        }
        if name.name_type == PrincipalName::NT_PRINCIPAL
            && name
                .components_joined()
                .eq_ignore_ascii_case("Administrator")
        {
            return RID_ADMINISTRATOR;
        }
        let r = self.next_rid;
        self.next_rid = self.next_rid.saturating_add(1);
        r
    }

    fn bump_next_rid(&mut self, rid: u32) {
        if rid >= RID_FIRST_USER && rid >= self.next_rid {
            self.next_rid = rid.saturating_add(1);
        }
    }
}

pub(crate) fn prune_key_history(keys: Vec<KeyEntry>, depth: u32) -> Vec<KeyEntry> {
    if depth == 0 {
        return Vec::new();
    }
    let mut kvnos: Vec<u32> = keys.iter().map(|k| k.kvno).collect();
    kvnos.sort_unstable();
    kvnos.dedup();
    let keep: Vec<u32> = kvnos.into_iter().rev().take(depth as usize).collect();
    keys.into_iter()
        .filter(|k| keep.contains(&k.kvno))
        .collect()
}

fn stamp_admin_tl(p: &mut Principal, pwd_change: bool) {
    let now = unix_now_u32();
    p.tl_data
        .retain(|t| t.ty != TL_MOD_PRINC && !(pwd_change && t.ty == TL_LAST_PWD_CHANGE));
    let mut modp = now.to_le_bytes().to_vec();
    modp.extend_from_slice(format!("kadmin/admin@{}", p.realm).as_bytes());
    modp.push(0);
    p.tl_data.push(TlData {
        ty: TL_MOD_PRINC,
        contents: modp,
    });
    if pwd_change {
        p.tl_data.push(TlData {
            ty: TL_LAST_PWD_CHANGE,
            contents: now.to_le_bytes().to_vec(),
        });
    }
}

pub(crate) fn unix_now_u32() -> u32 {
    u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
    .unwrap_or(u32::MAX)
}

fn check_pwqual(password: &[u8], pol: &NamedPolicy) -> Result<(), Error> {
    let s = std::str::from_utf8(password).unwrap_or("");
    if pol.min_length > 0 && s.len() < pol.min_length as usize {
        return Err(Error::PasswordPolicy(format!(
            "min_length {}",
            pol.min_length
        )));
    }
    if pol.min_classes > 0 {
        let mut n = 0u32;
        if s.chars().any(|c| c.is_ascii_lowercase()) {
            n += 1;
        }
        if s.chars().any(|c| c.is_ascii_uppercase()) {
            n += 1;
        }
        if s.chars().any(|c| c.is_ascii_digit()) {
            n += 1;
        }
        if s.chars().any(|c| c.is_ascii_punctuation()) {
            n += 1;
        }
        if s.chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c.is_ascii_punctuation()))
        {
            n += 1;
        }
        if n < pol.min_classes {
            return Err(Error::PasswordPolicy(format!(
                "min_classes {}",
                pol.min_classes
            )));
        }
    }
    Ok(())
}

fn generate_domain_sid() -> Result<RpcSid, Error> {
    let mut b = [0u8; 12];
    getrandom::getrandom(&mut b).map_err(|_| Error::Rng)?;
    sid_from_random_bytes(&b)
}

fn sid_from_random_bytes(b: &[u8; 12]) -> Result<RpcSid, Error> {
    if b.iter().all(|x| *x == 0) {
        return Err(Error::Rng);
    }
    let a = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) | 1;
    let c = u32::from_le_bytes([b[4], b[5], b[6], b[7]]) | 1;
    let d = u32::from_le_bytes([b[8], b[9], b[10], b[11]]) | 1;
    let sid = RpcSid::nt_domain(a, c, d);
    if sid.to_sddl() == RpcSid::dummy_domain().to_sddl() {
        return Err(Error::Rng);
    }
    Ok(sid)
}

/// Fill a random protocol key of `etype`.
///
/// # Errors
///
/// [`Error::Rng`] when the CSPRNG fails.
pub fn random_key(etype: EncryptionType) -> Result<ProtocolKey, Error> {
    let mut buf = vec![0u8; etype.key_len()];
    getrandom::getrandom(&mut buf).map_err(|_| Error::Rng)?;
    ProtocolKey::from_bytes(etype, &buf).map_err(Error::from)
}

fn randkey_etypes() -> [EncryptionType; 4] {
    [
        EncryptionType::Aes256CtsHmacSha196,
        EncryptionType::Aes128CtsHmacSha196,
        EncryptionType::Aes256CtsHmacSha384192,
        EncryptionType::Aes128CtsHmacSha256128,
    ]
}

fn keys_from_password(
    etypes: &[EncryptionType],
    password: &[u8],
    salt: &[u8],
    kvno: u32,
) -> Result<Vec<KeyEntry>, Error> {
    let mut keys = Vec::new();
    for etype in etypes {
        let params = s2k_params(*etype);
        let key = string_to_key(*etype, password, salt, Some(&params))?;
        keys.push(KeyEntry::new(*etype, key, kvno));
    }
    Ok(keys)
}

/// s2kparams (4-byte big-endian iteration count) for `etype`.
///
/// RFC 3962 default 4096; RFC 8009 default 32768. MIT 1.22 rejects the
/// SHA-1 count on SHA-2 etypes (`KRB5_ERR_BAD_S2K_PARAMS`).
#[must_use]
pub fn s2k_params(etype: EncryptionType) -> Vec<u8> {
    etype.default_iterations().to_be_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn chrand_stamps_last_pwd_and_mod() {
        let (mut store, _) = crate::bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::TEST_USER]);
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
        let (mut store, _) = crate::bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::TEST_USER]);
        let mut p = store.get_name(&user).unwrap().clone();
        let etype = p.best_key().unwrap().etype;
        plant_stale_admin_tl(&mut p, 1_000);
        store.debug_insert(p);
        let key = random_key(etype).unwrap();
        store
            .set_keys(&user, vec![KeyEntry::new(etype, key, 0)], false)
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
    fn apply_kdc_conf_sets_ticket_policy() {
        let mut store = PrincipalStore::new("KERBER.TEST");
        let conf = krb5_config::KdcConf::parse(
            r"
[realms]
    KERBER.TEST = {
        max_life = 1h 30m
        max_renewable_life = 2d 0h 0m 0s
        requires_preauth = no
        allow_weak_crypto = yes
    }
",
        )
        .unwrap();
        store.apply_kdc_conf(&conf).unwrap();
        assert_eq!(store.policy.max_life, 5400);
        assert_eq!(store.policy.max_renewable_life, 2 * 86400);
        assert!(!store.policy.requires_preauth);
        assert!(store.policy.allow_weak_crypto);
        assert!(!store.policy.allow_rc4);
        assert!(store.policy.reject_bad_transit);
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
    fn bootstrap_sid_rid_are_real_not_dummy() {
        let (store, _) = crate::bootstrap_documented().unwrap();
        assert_ne!(
            store.domain_sid().to_sddl(),
            RpcSid::dummy_domain().to_sddl()
        );
        assert_eq!(store.krbtgt().unwrap().rid, RID_KRBTGT);
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::TEST_USER]);
        assert_eq!(store.get_name(&user).unwrap().rid, RID_FIRST_USER);
        let ident = store.pac_identity(&user, store.realm());
        assert_eq!(ident.rid, RID_FIRST_USER);
        assert_eq!(
            ident.client_sid().to_sddl(),
            store.domain_sid().with_rid(RID_FIRST_USER).to_sddl()
        );
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
    fn rename_keeps_rid_and_keys() {
        let (mut store, acl) = crate::bootstrap_documented().unwrap();
        let actor = crate::documented_admin_id();
        let old = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["renamefrom"]);
        let new = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["renameto"]);
        store
            .create_password(&acl, &actor, &old, b"rename-secret")
            .unwrap();
        let before = store.get_name(&old).unwrap();
        let rid = before.rid;
        let keys: Vec<(i32, u32, Vec<u8>)> = before
            .keys
            .iter()
            .map(|k| (k.etype.to_iana(), k.kvno, k.key.as_bytes().to_vec()))
            .collect();
        assert_ne!(rid, 0);
        store.rename(&acl, &actor, &old, &new).unwrap();
        assert!(store.get_name(&old).is_none());
        let after = store.get_name(&new).unwrap();
        assert_eq!(after.rid, rid);
        let after_keys: Vec<(i32, u32, Vec<u8>)> = after
            .keys
            .iter()
            .map(|k| (k.etype.to_iana(), k.kvno, k.key.as_bytes().to_vec()))
            .collect();
        assert_eq!(after_keys, keys);
        let add_only = Acl::parse("admin@KERBER.TEST a\n").expect("acl");
        store
            .create_password(&acl, &actor, &old, b"rename-secret")
            .unwrap();
        assert!(store.rename(&add_only, &actor, &old, &new).is_err());
    }

    #[test]
    fn named_policy_pwqual_and_lockout() {
        use krb5_protocol::{as_req, pa_enc_timestamp, pa_enc_timestamp_at};
        use krb5_types::KerberosTime;

        let (mut store, _) = crate::bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::TEST_USER]);
        store.put_policy(NamedPolicy {
            name: "strict".into(),
            min_length: 8,
            min_classes: 2,
            history: 1,
            max_fail: 3,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
        });
        store
            .set_principal_policy(&user, Some("strict".into()))
            .unwrap();
        assert!(store.check_password_quality(&user, b"short").is_err());
        assert!(store.set_password(&user, b"short").is_err());
        store.set_password(&user, b"Longer1x").unwrap();
        assert!(
            store.set_password(&user, b"Longer1x").is_err(),
            "history must reject reuse of the current password"
        );
        let n_kvno = {
            let p = store.get_name(&user).unwrap();
            let mut v: Vec<u32> = p.keys.iter().map(|k| k.kvno).collect();
            v.sort_unstable();
            v.dedup();
            v.len()
        };
        assert_eq!(n_kvno, 1, "keepold=false: one active kvno");

        let key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let good = as_req(
            user.clone(),
            crate::TEST_REALM,
            1,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        let zeros = krb5_crypto::ProtocolKey::from_bytes(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            &[0u8; 32],
        )
        .unwrap();
        let mut skew = 0i64;
        let mut bad_as = || {
            skew += 1;
            let ts = KerberosTime::now().add_seconds(skew).unwrap();
            as_req(
                user.clone(),
                crate::TEST_REALM,
                1,
                Some(vec![pa_enc_timestamp_at(&zeros, &ts).unwrap()]),
            )
            .unwrap()
        };
        let revoked = |e: &Error| matches!(e, Error::Protocol { code, .. } if *code == krb5_types::err::CLIENT_REVOKED);
        assert!(crate::issue_as(&store, &bad_as()).is_err());
        assert!(crate::issue_as(&store, &bad_as()).is_err());
        crate::issue_as(&store, &good).expect("success must reset fail count");
        assert!(crate::issue_as(&store, &bad_as()).is_err());
        let second = crate::issue_as(&store, &bad_as()).unwrap_err();
        assert!(
            !revoked(&second),
            "second fail after success must not lock (count was reset): {second:?}"
        );
        assert!(crate::issue_as(&store, &bad_as()).is_err());
        let locked = crate::issue_as(&store, &bad_as()).unwrap_err();
        assert!(revoked(&locked), "expected CLIENT_REVOKED, got {locked:?}");
    }

    #[test]
    fn pwqual_counts_five_mit_classes() {
        let (mut store, _) = crate::bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::TEST_USER]);
        store.put_policy(NamedPolicy {
            name: "five".into(),
            min_length: 8,
            min_classes: 5,
            history: 0,
            max_fail: 0,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
        });
        store
            .set_principal_policy(&user, Some("five".into()))
            .unwrap();
        assert!(
            store.check_password_quality(&user, b"Aa1!aaaa").is_err(),
            "lower+upper+digit+punct is 4 classes"
        );
        assert!(
            store.check_password_quality(&user, b"Aa1!aaa ").is_ok(),
            "space is MIT class other (5th)"
        );
    }

    #[test]
    fn password_history_matches_mit_window() {
        let (mut store, _) = crate::bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::TEST_USER]);
        store.put_policy(NamedPolicy {
            name: "h1".into(),
            min_length: 8,
            min_classes: 2,
            history: 1,
            max_fail: 0,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
        });
        store
            .set_principal_policy(&user, Some("h1".into()))
            .unwrap();
        store.set_password(&user, b"Hist-pw0").unwrap();
        assert!(
            store.set_password(&user, b"Hist-pw0").is_err(),
            "current password is inside history=1"
        );
        store.set_password(&user, b"Hist-pw1").unwrap();
        store
            .set_password(&user, b"Hist-pw0")
            .expect("history=1 must allow A→B→A like MIT");

        store.put_policy(NamedPolicy {
            name: "h2".into(),
            min_length: 8,
            min_classes: 2,
            history: 2,
            max_fail: 0,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
        });
        store
            .set_principal_policy(&user, Some("h2".into()))
            .unwrap();
        store.set_password(&user, b"Hist-seed1").unwrap();
        store.set_password(&user, b"Hist-seed2").unwrap();
        store.set_password(&user, b"Hist-pw0").unwrap();
        store.set_password(&user, b"Hist-pw1").unwrap();
        store.set_password(&user, b"Hist-pw2").unwrap();
        assert!(
            store.set_password(&user, b"Hist-pw1").is_err(),
            "history=2 must reject B after A→B→C (MIT)"
        );
        store
            .set_password(&user, b"Hist-pw0")
            .expect("history=2 must allow the N-boundary password A after A→B→C");
        let p = store.get_name(&user).unwrap();
        let mut kvnos: Vec<u32> = p.keys.iter().map(|k| k.kvno).collect();
        kvnos.sort_unstable();
        kvnos.dedup();
        assert_eq!(kvnos.len(), 1, "active keys are a single kvno");
        let mut hkv: Vec<u32> = p.key_history.iter().map(|k| k.kvno).collect();
        hkv.sort_unstable();
        hkv.dedup();
        assert!(
            hkv.len() <= 1,
            "history=2 stores N-1 old kvnos, got {hkv:?}"
        );
        let text = crate::dump_store(&store, b"masterpassword").unwrap();
        assert!(
            text.contains("\t19204\t"),
            "dump must emit TL_KERBER_HIST 0x4B04: {text}"
        );
        let again = crate::load_dump(&text, b"masterpassword").unwrap();
        let p2 = again.get_name(&user).unwrap();
        assert!(!p2.key_history.is_empty(), "hist tl_data must round-trip");
    }

    #[test]
    fn failed_as_stamps_last_failed() {
        use krb5_protocol::{as_req, pa_enc_timestamp, pa_enc_timestamp_at};
        use krb5_types::KerberosTime;

        let (store, _) = crate::bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::TEST_USER]);
        let p0 = store.get_name(&user).unwrap().clone();
        assert_eq!(store.last_failed_of(&p0), 0);
        assert_eq!(store.last_success_of(&p0), 0);
        let zeros = krb5_crypto::ProtocolKey::from_bytes(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            &[0u8; 32],
        )
        .unwrap();
        let ts = KerberosTime::now().add_seconds(1).unwrap();
        let bad = as_req(
            user.clone(),
            crate::TEST_REALM,
            1,
            Some(vec![pa_enc_timestamp_at(&zeros, &ts).unwrap()]),
        )
        .unwrap();
        assert!(crate::issue_as(&store, &bad).is_err());
        let p1 = store.get_name(&user).unwrap().clone();
        let failed = store.last_failed_of(&p1);
        assert!(
            failed > 0,
            "failed AS must stamp overlay last_failed, got {failed}"
        );
        let key = p1.best_key().unwrap().key.clone();
        let good = as_req(
            user.clone(),
            crate::TEST_REALM,
            1,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        crate::issue_as(&store, &good).unwrap();
        let p2 = store.get_name(&user).unwrap().clone();
        let ok_at = store.last_success_of(&p2);
        assert!(
            ok_at >= failed,
            "success must stamp last_success ({ok_at}) at/after last_failed ({failed})"
        );
        assert_eq!(store.fail_auth_of(&p2), 0);
    }

    #[test]
    fn lockout_duration_only_unlocks_after_sleep() {
        use krb5_protocol::{as_req, pa_enc_timestamp, pa_enc_timestamp_at};
        use krb5_types::KerberosTime;

        let (mut store, _) = crate::bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::TEST_USER]);
        store.put_policy(NamedPolicy {
            name: "dur".into(),
            min_length: 0,
            min_classes: 0,
            history: 0,
            max_fail: 1,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 1,
        });
        store
            .set_principal_policy(&user, Some("dur".into()))
            .unwrap();
        let key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let good = as_req(
            user.clone(),
            crate::TEST_REALM,
            1,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        let zeros = krb5_crypto::ProtocolKey::from_bytes(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            &[0u8; 32],
        )
        .unwrap();
        let mut skew = 0i64;
        let mut bad_as = || {
            skew += 1;
            let ts = KerberosTime::now().add_seconds(skew).unwrap();
            as_req(
                user.clone(),
                crate::TEST_REALM,
                1,
                Some(vec![pa_enc_timestamp_at(&zeros, &ts).unwrap()]),
            )
            .unwrap()
        };
        let revoked = |e: &Error| matches!(e, Error::Protocol { code, .. } if *code == krb5_types::err::CLIENT_REVOKED);
        assert!(crate::issue_as(&store, &bad_as()).is_err());
        let locked = crate::issue_as(&store, &bad_as()).unwrap_err();
        assert!(revoked(&locked), "max_fail 1 must lock on the next AS");
        std::thread::sleep(std::time::Duration::from_secs(2));
        crate::issue_as(&store, &good)
            .expect("elapsed lockout duration with interval=0 must unlock");
    }

    #[test]
    fn lockout_interval_only_resets_fail_count() {
        use krb5_protocol::{as_req, pa_enc_timestamp_at};
        use krb5_types::KerberosTime;

        let (mut store, _) = crate::bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::TEST_USER]);
        store.put_policy(NamedPolicy {
            name: "intv".into(),
            min_length: 0,
            min_classes: 0,
            history: 0,
            max_fail: 1,
            pw_failcnt_interval: 1,
            pw_lockout_duration: 0,
        });
        store
            .set_principal_policy(&user, Some("intv".into()))
            .unwrap();
        let zeros = krb5_crypto::ProtocolKey::from_bytes(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            &[0u8; 32],
        )
        .unwrap();
        let mut skew = 0i64;
        let mut bad_as = || {
            skew += 1;
            let ts = KerberosTime::now().add_seconds(skew).unwrap();
            as_req(
                user.clone(),
                crate::TEST_REALM,
                1,
                Some(vec![pa_enc_timestamp_at(&zeros, &ts).unwrap()]),
            )
            .unwrap()
        };
        let revoked = |e: &Error| matches!(e, Error::Protocol { code, .. } if *code == krb5_types::err::CLIENT_REVOKED);
        assert!(crate::issue_as(&store, &bad_as()).is_err());
        std::thread::sleep(std::time::Duration::from_secs(2));
        let second = crate::issue_as(&store, &bad_as()).unwrap_err();
        assert!(
            !revoked(&second),
            "elapsed failcnt interval with duration=0 must not lock: {second:?}"
        );
    }

    #[test]
    fn serial_ulog_delta_then_issue_as() {
        use krb5_protocol::{as_req, pa_enc_timestamp};

        let (mut master, acl) = crate::bootstrap_documented().unwrap();
        let (mut slave, _) = crate::bootstrap_documented().unwrap();
        let actor = crate::documented_admin_id();
        let sno0 = master.serial();
        assert!(
            sno0 > 0,
            "bootstrap mutations must advance serial (not mtime-only)"
        );
        assert_eq!(master.iprop_get(0).0, IPROP_FULL_RESYNC);
        assert_eq!(master.iprop_get(sno0).0, IPROP_NIL);

        let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["iproped"]);
        master
            .create_password(&acl, &actor, &extra, b"iprop-secret")
            .unwrap();
        let sno1 = master.serial();
        assert!(sno1 > sno0);
        let (st, last, entries) = master.iprop_get(sno0);
        assert_eq!(st, IPROP_OK);
        assert_eq!(last, sno1);
        assert!(
            entries
                .iter()
                .any(|e| e.name.contains("iproped") && !e.deleted),
            "ulog must record the create: {entries:?}"
        );

        slave.apply_updates(&entries);
        assert!(slave.get_name(&extra).is_some());
        assert_eq!(slave.serial(), sno1);
        let key = slave
            .get_name(&extra)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let req = as_req(
            extra,
            crate::TEST_REALM,
            11,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        crate::issue_as(&slave, &req).expect("slave must issue after serial-delta");
    }

    #[test]
    fn apply_updates_assigns_rid_so_replica_pac_is_not_first_user() {
        use crate::{decrypt_ticket_part, pa_enc_timestamp, pac_from_ticket_part};
        use krb5_protocol::as_req;
        use krb5_types::pac::{PAC_LOGON_INFO, Pac, parse_kerb_validation_info};

        let (mut master, acl) = crate::bootstrap_documented().unwrap();
        let (mut slave, _) = crate::bootstrap_documented().unwrap();
        let actor = crate::documented_admin_id();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::TEST_USER]);
        let user_rid = slave.get_name(&user).unwrap().rid;
        assert_eq!(user_rid, RID_FIRST_USER);

        let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["iproped"]);
        master
            .create_password(&acl, &actor, &extra, b"iprop-secret")
            .unwrap();
        let mut incr = master.get_name(&extra).unwrap().clone();
        incr.rid = 0;
        incr.tl_data.retain(|t| t.ty != crate::TL_KERBER_SID);
        slave.apply_updates(&[UlogEntry {
            sno: slave.serial().saturating_add(1),
            time: 1,
            name: incr.id(),
            deleted: false,
            princ: Some(incr),
        }]);

        let got = slave.get_name(&extra).unwrap().clone();
        assert_ne!(got.rid, 0, "incremental apply must allocate a RID");
        assert_ne!(got.rid, RID_FIRST_USER);
        assert_ne!(got.rid, user_rid);

        let key = got.best_key().unwrap().key.clone();
        let req = as_req(
            extra.clone(),
            crate::TEST_REALM,
            21,
            Some(vec![pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        let as_out = crate::issue_as(&slave, &req).expect("replica AS");
        let tgt = slave.krbtgt().unwrap().best_key().unwrap();
        let part = decrypt_ticket_part(&tgt.key, &as_out.rep.0.ticket).expect("enc");
        let pac = pac_from_ticket_part(&part).expect("PAC");
        let parsed = Pac::parse(&pac).expect("PAC");
        let logon =
            parse_kerb_validation_info(parsed.buffer(PAC_LOGON_INFO).expect("logon")).expect("NDR");
        assert_eq!(logon.user_id, got.rid);
        assert_ne!(logon.user_id, RID_FIRST_USER);
    }

    #[test]
    fn apply_updates_keeps_keys_on_keyless_incremental() {
        let (mut store, acl) = crate::bootstrap_documented().unwrap();
        let actor = crate::documented_admin_id();
        let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["keyless"]);
        store
            .create_password(&acl, &actor, &extra, b"keyless-secret")
            .unwrap();
        store.set_string(&extra, "note", Some("keep-me")).unwrap();
        let before = store.get_name(&extra).unwrap().clone();
        assert!(!before.keys.is_empty());
        let mut incr = before.clone();
        incr.keys.clear();
        incr.key_history.clear();
        incr.string_attrs.clear();
        incr.tl_data.clear();
        incr.pw_policy = None;
        let sno = store.serial().saturating_add(1);
        store.apply_updates(&[UlogEntry {
            sno,
            time: 1,
            name: before.id(),
            deleted: false,
            princ: Some(incr),
        }]);
        let after = store.get_name(&extra).unwrap();
        assert_eq!(after.keys.len(), before.keys.len());
        assert_eq!(after.keys[0].key.as_bytes(), before.keys[0].key.as_bytes());
        assert_eq!(after.string_attrs, before.string_attrs);
        assert_eq!(after.key_history.len(), before.key_history.len());
    }

    #[test]
    fn ulog_records_delete_rename_chrand() {
        let (mut store, acl) = crate::bootstrap_documented().unwrap();
        let actor = crate::documented_admin_id();
        let a = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["ulogdel"]);
        let b = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["ulogren"]);
        store
            .create_password(&acl, &actor, &a, b"ulog-secret")
            .unwrap();
        let after_create = store.serial();
        store.delete(&acl, &actor, &a).unwrap();
        let del = store.updates_after(after_create);
        assert!(
            del.iter().any(|e| e.name.contains("ulogdel") && e.deleted),
            "delete must be ulogged: {del:?}"
        );
        store
            .create_password(&acl, &actor, &a, b"ulog-secret")
            .unwrap();
        let after_recreate = store.serial();
        store.rename(&acl, &actor, &a, &b).unwrap();
        let ren = store.updates_after(after_recreate);
        assert!(
            ren.iter().any(|e| e.name.contains("ulogdel") && e.deleted)
                && ren
                    .iter()
                    .any(|e| e.name.contains("ulogren") && !e.deleted && e.princ.is_some()),
            "rename must ulog delete+add: {ren:?}"
        );
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [crate::TEST_USER]);
        let after_ren = store.serial();
        store.chrand(&user).unwrap();
        let ch = store.updates_after(after_ren);
        assert!(
            ch.iter()
                .any(|e| e.name.contains(crate::TEST_USER) && e.princ.is_some()),
            "chrand must be ulogged: {ch:?}"
        );
        store.set_status(&user, true, 0).unwrap();
        assert!(
            store
                .ulog()
                .iter()
                .any(|e| e.name.contains(crate::TEST_USER)
                    && e.princ.as_ref().is_some_and(|p| p.locked)),
            "set_status must be ulogged"
        );
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
        let (mut store, acl) = crate::bootstrap_documented().unwrap();
        crate::persist::save_store(&store, &db, &stash).unwrap();
        store.persist_paths = Some((db.clone(), stash.clone()));
        let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["serialed"]);
        store
            .create_password(
                &acl,
                &crate::documented_admin_id(),
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
        let (mut store, acl) = crate::bootstrap_documented().unwrap();
        let cpw = crate::documented_changepw();
        store
            .delete(&acl, &crate::documented_admin_id(), &cpw)
            .unwrap();
        crate::persist::save_store(&store, &db, &stash).unwrap();
        store.persist_paths = Some((db.clone(), stash.clone()));
        store
            .create_host(&acl, &crate::documented_admin_id(), &cpw)
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
        let (mut store, acl) = crate::bootstrap_documented().unwrap();
        let extra = PrincipalName::new(
            PrincipalName::NT_SRV_HST,
            ["host", "chrandfail.kerber.test"],
        );
        store
            .create_host(&acl, &crate::documented_admin_id(), &extra)
            .unwrap();
        crate::persist::save_store(&store, &db, &stash).unwrap();
        store.persist_paths = Some((db.clone(), stash.clone()));
        let before = max_kvno(&store, &extra);
        super::FAIL_NEXT_CHRAND_SAVE.with(|c| c.set(true));
        let err = store
            .ktadd_local_atomic(&extra, true, |_| Ok(()))
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

    fn max_kvno(store: &PrincipalStore, name: &PrincipalName) -> u32 {
        store
            .get_name(name)
            .and_then(|p| p.keys.iter().map(|k| k.kvno).max())
            .unwrap_or(0)
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
        let (mut store, acl) = crate::bootstrap_documented().unwrap();
        let extra = PrincipalName::new(
            PrincipalName::NT_SRV_HST,
            ["host", "exportfail.kerber.test"],
        );
        store
            .create_host(&acl, &crate::documented_admin_id(), &extra)
            .unwrap();
        crate::persist::save_store(&store, &db, &stash).unwrap();
        store.persist_paths = Some((db.clone(), stash.clone()));
        let before = max_kvno(&store, &extra);
        super::FAIL_NEXT_KTADD_EXPORT.with(|c| c.set(true));
        let err = store
            .ktadd_local_atomic(&extra, true, |_| Ok(()))
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
        let (mut store, acl) = crate::bootstrap_documented().unwrap();
        let extra = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "rbsave.kerber.test"]);
        store
            .create_host(&acl, &crate::documented_admin_id(), &extra)
            .unwrap();
        crate::persist::save_store(&store, &db, &stash).unwrap();
        store.persist_paths = Some((db.clone(), stash.clone()));
        let err = store
            .ktadd_local_atomic(&extra, true, |_| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
                }
                Err(Error::Crypto("disk full".into()))
            })
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
}
