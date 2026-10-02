//! Realm ticket policy (`alt_prof.c`, `kdc/main.c`) and named
//! kadm5 `osa_policy_ent` (`svr_policy.c`): defaults, kdc.conf /
//! krb5.conf overlay, and the policy CRUD on the store.
//! MIT `init_realm` (`kdc/main.c:316-319`): the realm's `max_renewable_life` is read into
//! `realm_maxrlife`, `KRB5_KDB_MAX_RLIFE` (7 d) when omitted.

use std::collections::{BTreeMap, HashMap};

use krb5_crypto::EncryptionType;
use krb5_types::PrincipalName;
use krb5_types::pac::RpcSid;

use super::PrincipalStore;
use super::keys::{KeyEntry, KeyLookup, default_supported_enctypes};
use super::principal::{Principal, refresh_kadm_tl};
use super::transit::permitted_transited;
use crate::error::Error;

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
    /// MIT `pw_min_life` seconds (`osa_policy_ent`).
    pub pw_min_life: u32,
    /// MIT `pw_max_life` seconds; 0 = no password expiration.
    pub pw_max_life: u32,
    /// MIT `osa_policy_ent.allowed_keysalts`; `None` is NULL (getpol omits the line).
    pub allowed_keysalts: Option<String>,
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
            pw_min_life: 0,
            pw_max_life: 0,
            allowed_keysalts: None,
        }
    }
}

/// Realm-wide ticket policy.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Max ticket lifetime seconds (MIT `alt_prof.c`: omitted = 24 h).
    pub max_life: u64,
    /// kadm5 create default.
    /// MIT `kadm5_get_config_params` (`alt_prof.c:577-578`): `max_rlife` omitted = 0.
    pub max_renewable_life: u64,
    /// KDC issue cap.
    /// MIT `init_realm` (`kdc/main.c:316-319`): `realm_maxrlife` omitted = 7 d.
    pub realm_max_renewable_life: u64,
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
    /// MIT `supported_enctypes`. Empty = MIT's default, aes256-cts-hmac-sha1-96 and
    /// aes128-cts-hmac-sha1-96.
    pub supported_enctypes: Vec<EncryptionType>,
    /// Default requires_preauth for new principals.
    pub requires_preauth: bool,
    /// MIT `[realms] default_principal_flags`: the `handle->params.flags` a
    /// kadm5 create takes when `KADM5_ATTRIBUTES` is not in the mask.
    /// MIT `kadm5_get_config_params` (`alt_prof.c:596-632`): the stanza is parsed
    /// into `params.flags`. `None` = the stanza is absent (MIT
    /// `KRB5_KDB_DEF_FLAGS` 0; here the `requires_preauth` knob's bit).
    pub default_principal_flags: Option<u32>,
    /// MIT `[realms] default_principal_expiration`: `handle->params.expiration`,
    /// the `expiration` of a create without `KADM5_PRINC_EXPIRE_TIME`.
    /// MIT `kadm5_get_config_params` (`alt_prof.c:580-594`): the stanza goes
    /// through `krb5_string_to_timestamp`. 0 when absent or unparsable (MIT
    /// leaves the zeroed field).
    pub default_principal_expiration: u32,
    /// `[capaths]` client → server → intermediates (`.` = direct).
    pub capaths: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    /// MIT `reject_bad_transit` (default true).
    pub reject_bad_transit: bool,
    /// MIT `disable_pac` (default false): issue no PAC.
    pub disable_pac: bool,
    /// MIT `restrict_anonymous_to_tgt` (default false).
    pub restrict_anon: bool,
    /// MIT `pkinit_require_freshness` (default false).
    pub pkinit_require_freshness: bool,
    /// MIT `host_based_services` (NT-UNKNOWN referral allow-list).
    pub host_based_services: String,
    /// MIT `no_host_referral` (service-type deny-list).
    pub no_host_referral: String,
    /// `[domain_realm]` for `krb5_get_host_realm`.
    pub domain_realm: BTreeMap<String, String>,
    /// `[realms] encrypted_challenge_indicator` (single).
    pub encrypted_challenge_indicator: Option<String>,
    /// `[realms] pkinit_indicator` (repeatable).
    pub pkinit_indicators: Vec<String>,
    /// `[realms] spake_preauth_indicator` (repeatable).
    pub spake_preauth_indicators: Vec<String>,
    /// `[libdefaults] spake_preauth_groups` as implemented group numbers.
    /// Empty = MIT KDC default — SPAKE is not advertised.
    /// MIT `DEFAULT_GROUPS_KDC` (`groups.c:60-60`): the KDC's default group list is empty.
    pub spake_preauth_groups: Vec<i32>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_life: 24 * 3600,
            max_renewable_life: 0,
            realm_max_renewable_life: 7 * 24 * 3600,
            skew: 300,
            allow_weak_crypto: false,
            allow_rc4: false,
            allow_des3: false,
            permitted_enctypes: None,
            supported_enctypes: Vec::new(),
            requires_preauth: true,
            default_principal_flags: None,
            default_principal_expiration: 0,
            capaths: BTreeMap::new(),
            reject_bad_transit: true,
            disable_pac: false,
            restrict_anon: false,
            pkinit_require_freshness: false,
            host_based_services: String::new(),
            no_host_referral: String::new(),
            domain_realm: BTreeMap::new(),
            encrypted_challenge_indicator: None,
            pkinit_indicators: Vec::new(),
            spake_preauth_indicators: Vec::new(),
            spake_preauth_groups: Vec::new(),
        }
    }
}

/// MIT `parse_groups` (`groups.c:175-210`): unknown names skipped.
/// Rust implements P-256 only; other IANA names are skipped.
#[must_use]
pub(crate) fn parse_spake_preauth_groups(names: &[String]) -> Vec<i32> {
    let mut out = Vec::new();
    for n in names {
        if n.eq_ignore_ascii_case("P-256") && !out.contains(&krb5_types::spake::GROUP_P256) {
            out.push(krb5_types::spake::GROUP_P256);
        }
    }
    out
}

impl Policy {
    /// MIT `krb5_check_transited_list`: anonymous crealm passes; then capaths if present, else hierarchical.
    #[must_use]
    pub(crate) fn transit_allowed(&self, crealm: &str, srealm: &str, hops: &[String]) -> bool {
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

    /// MIT `krb5_dbe_find_enctype` under this policy's `permitted_enctypes`
    /// ([`Principal::find_enctype`] with [`Policy::etype_permitted`]).
    ///
    /// # Errors
    ///
    /// [`KeyLookup::NoMatchingKey`] when no key of `p` matches `etype`/`kvno` at all;
    /// [`KeyLookup::NoPermittedKey`] when `etype` itself, or every matching key, is outside
    /// `permitted_enctypes`.
    pub fn find_enctype<'p>(
        &self,
        p: &'p Principal,
        etype: Option<EncryptionType>,
        kvno: u32,
    ) -> Result<&'p KeyEntry, KeyLookup> {
        p.find_enctype(etype, kvno, |e| self.etype_permitted(e))
    }

    /// MIT `get_first_current_key` (`kdc_util.c:462-473`): the first
    /// *permitted* key of the highest kvno, `krb5_dbe_find_enctype(-1, -1, 0)`.
    ///
    /// # Errors
    ///
    /// [`KeyLookup::NoMatchingKey`] when there are no keys,
    /// [`KeyLookup::NoPermittedKey`] when none at the top kvno is permitted.
    pub fn first_current_key<'p>(&self, p: &'p Principal) -> Result<&'p KeyEntry, KeyLookup> {
        self.find_enctype(p, None, 0)
    }

    /// MIT `krb5_get_host_realm` profile half (no DNS).
    #[must_use]
    pub fn realm_for_host(&self, host: &str) -> Option<&str> {
        krb5_config::host_to_realm(&self.domain_realm, host)
    }

    /// Long-term keys minted by addprinc/cpw when `-e` is omitted.
    /// MIT `kadm5_get_config_params` (`lib/kadm5/alt_prof.c:650-654`): the realm's `supported_enctypes`, else `KRB5_DEFAULT_SUPPORTED_ENCTYPES`.
    #[must_use]
    pub fn password_etypes(&self) -> Vec<EncryptionType> {
        if self.supported_enctypes.is_empty() {
            default_supported_enctypes().to_vec()
        } else {
            self.supported_enctypes.clone()
        }
    }
}

impl PrincipalStore {
    /// Apply `kdc.conf` ticket policy. `dict_file` is not read here: the password dictionary is
    /// the admin side's ([`Self::init_pwqual`]), and the KDC never reads it.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] when `domain_sid` is not valid SDDL.
    pub fn apply_kdc_conf(&mut self, conf: &krb5_config::KdcConf) -> Result<(), Error> {
        self.policy.max_life = conf.max_life;
        self.policy.max_renewable_life = conf.max_renewable_life;
        self.policy.realm_max_renewable_life = conf.realm_max_renewable_life;
        if let Some(v) = conf.allow_weak_crypto {
            self.policy.allow_weak_crypto = v;
        }
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
        self.policy.default_principal_flags = conf
            .default_principal_flags
            .as_deref()
            .map(crate::acl::default_principal_flags);
        self.policy.default_principal_expiration = conf
            .default_principal_expiration
            .as_deref()
            .and_then(krb5_types::timestamp::string_to_timestamp)
            .unwrap_or(0);
        self.policy.reject_bad_transit = conf.reject_bad_transit;
        self.policy.disable_pac = conf.disable_pac;
        self.policy.restrict_anon = conf.restrict_anon;
        self.policy.pkinit_require_freshness = conf.pkinit_require_freshness;
        self.policy
            .host_based_services
            .clone_from(&conf.host_based_services);
        self.policy
            .no_host_referral
            .clone_from(&conf.no_host_referral);
        self.policy
            .encrypted_challenge_indicator
            .clone_from(&conf.encrypted_challenge_indicator);
        self.policy
            .pkinit_indicators
            .clone_from(&conf.pkinit_indicators);
        self.policy
            .spake_preauth_indicators
            .clone_from(&conf.spake_preauth_indicators);
        if let Some(names) = &conf.spake_preauth_groups {
            self.policy.spake_preauth_groups = parse_spake_preauth_groups(names);
        }
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

    /// Overlay `[libdefaults]` `allow_rc4` / `allow_des3` / `permitted_enctypes`.
    pub fn apply_libdefaults(&mut self, conf: &krb5_config::Krb5Conf) {
        // krb5.conf [libdefaults] is the base; kdc.conf overrides it (applied
        // last in the KDC bin), so `allow_weak_crypto` here reaches the KDC.
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
                self.policy.allow_weak_crypto || conf.allow_weak_crypto,
            );
        }
        if let Some(names) = &conf.spake_preauth_groups {
            self.policy.spake_preauth_groups = parse_spake_preauth_groups(names);
        }
        self.policy.domain_realm.clone_from(&conf.domain_realm);
    }

    /// Named password policies.
    #[must_use]
    pub fn policies(&self) -> &HashMap<String, NamedPolicy> {
        &self.policies
    }

    /// Insert or replace a named policy; a failed save is not reported (see
    /// [`Self::put_policy_and_save`]).
    pub fn put_policy(&mut self, pol: NamedPolicy) {
        let _ = self.put_policy_and_save(pol);
    }

    /// Insert or replace a named policy and save the store when it persists.
    ///
    /// # Errors
    ///
    /// [`Error::Db`] when the store cannot be saved, a writer that may not write the database
    /// included; the policy stays in memory and nothing on disk changes.
    pub fn put_policy_and_save(&mut self, pol: NamedPolicy) -> Result<(), Error> {
        self.note_ulog(format!("policy:{}", pol.name), false, None);
        self.policies.insert(pol.name.clone(), pol);
        self.save_if_configured()
    }

    /// Load a dump policy without logging (dump/iprop apply).
    pub(crate) fn load_policy(&mut self, pol: NamedPolicy) {
        self.policies.insert(pol.name.clone(), pol);
    }

    /// Delete a named policy.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when no policy is named `name`; [`Error::Db`] when saving the
    /// store to `persist_paths` fails.
    pub fn delete_policy(&mut self, name: &str) -> Result<(), Error> {
        self.policies.remove(name).ok_or(Error::NotFound)?;
        self.note_ulog(format!("policy:{name}"), true, None);
        self.save_if_configured()
    }

    /// Bind `princ` to `policy` (None unbinds).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when the principal is missing; [`Error::Db`] when saving the
    /// store to `persist_paths` fails.
    pub fn set_principal_policy(
        &mut self,
        name: &PrincipalName,
        policy: Option<String>,
    ) -> Result<(), Error> {
        let realm = self.realm.clone();
        self.set_principal_policy_in(name, &realm, policy)
    }

    /// [`Self::set_principal_policy`] for `name@princ_realm`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when the principal is missing; [`Error::Db`] when saving the
    /// store to `persist_paths` fails.
    pub(crate) fn set_principal_policy_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        policy: Option<String>,
    ) -> Result<(), Error> {
        let id = self.canonical_id(name, princ_realm)?;
        {
            let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
            p.pw_policy = policy;
            refresh_kadm_tl(p);
        }
        self.apply_pw_max_life_in(name, princ_realm)?;
        let snap = self.map.get(&id).cloned();
        self.note_ulog(id, false, snap);
        self.save_if_configured()
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
    pub(crate) fn named_policy_for(&self, p: &Principal) -> Option<NamedPolicy> {
        p.pw_policy
            .as_ref()
            .and_then(|n| self.policies.get(n).cloned())
    }
}
