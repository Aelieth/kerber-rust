//! Named policies and the realm ticket policy.
// MIT: `init_realm` (kdc/main.c:316-319)

use std::collections::{BTreeMap, HashMap};

use krb5_crypto::{EncryptionType, SpakeGroup, spake_parse_groups};
use krb5_types::PrincipalName;
use krb5_types::pac::RpcSid;

use super::PrincipalStore;
use super::keys::{KeyEntry, KeyLookup, default_supported_enctypes};
use super::principal::{Principal, default_mod_actor, refresh_kadm_tl, stamp_admin_tl};
use super::transit::permitted_transited;
use crate::error::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedPolicy {
    pub name: String,
    pub min_length: u32,
    /// 0 requires no class.
    pub min_classes: u32,
    /// 0 keeps no history.
    pub history: u32,
    /// 0 means no lockout.
    pub max_fail: u32,
    /// 0 never resets the count.
    pub pw_failcnt_interval: u32,
    /// 0 lasts until a successful AS.
    pub pw_lockout_duration: u32,
    pub pw_min_life: u32,
    /// 0 sets no password expiration.
    pub pw_max_life: u32,
    pub allowed_keysalts: Option<String>,
}

impl NamedPolicy {
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

#[derive(Clone, Debug)]
pub struct Policy {
    /// Omitted is 24 hours; 0 sets no limit.
    pub max_life: u64,
    // MIT: `kadm5_get_config_params` (alt_prof.c:577-578)
    /// Omitted is 0, which means no renewal.
    pub max_renewable_life: u64,
    /// Omitted is 7 days.
    pub realm_max_renewable_life: u64,
    pub skew: i64,
    pub allow_weak_crypto: bool,
    pub allow_rc4: bool,
    pub allow_des3: bool,
    pub permitted_enctypes: Option<Vec<EncryptionType>>,
    pub supported_enctypes: Vec<EncryptionType>,
    pub requires_preauth: bool,
    // MIT: `kadm5_get_config_params` (alt_prof.c:596-632)
    pub default_principal_flags: Option<u32>,
    // MIT: `kadm5_get_config_params` (alt_prof.c:580-594)
    pub default_principal_expiration: u32,
    pub capaths: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    pub reject_bad_transit: bool,
    pub disable_pac: bool,
    pub ad_identity: bool,
    pub restrict_anon: bool,
    pub pkinit_require_freshness: bool,
    pub host_based_services: String,
    pub no_host_referral: String,
    pub domain_realm: BTreeMap<String, String>,
    pub encrypted_challenge_indicator: Option<String>,
    pub pkinit_indicators: Vec<String>,
    pub spake_preauth_indicators: Vec<String>,
    /// Empty leaves the SPAKE module unloaded.
    // MIT: `DEFAULT_GROUPS_KDC` (groups.c:60-60)
    pub spake_preauth_groups: Vec<SpakeGroup>,
    pub spake_preauth_kdc_challenge: Option<String>,
    pub disable_last_success: bool,
    pub disable_lockout: bool,
    // MIT: `k5_plugin_load_all` (lib/krb5/krb/plugin.c:421-455)
    pub kdcpreauth: krb5_config::PluginRelations,
    // MIT: `load_kdcpolicy_plugins` (kdc/policy.c:194-246)
    pub kdcpolicy: krb5_config::PluginRelations,
    // MIT: `load_audit_modules` (kdc/kdc_audit.c:71-84)
    pub audit: krb5_config::PluginRelations,
    // MIT: `k5_pwqual_load` (lib/kadm5/srv/pwqual.c:42-96)
    pub pwqual: krb5_config::PluginRelations,
    // MIT: `k5_kadm5_hook_load` (lib/kadm5/srv/kadm5_hook.c:40-94)
    pub kadm5_hook: krb5_config::PluginRelations,
    // MIT: `otp_state_new` (plugins/preauth/otp/otp_state.c:579-585)
    // MIT: `reset_for_hangup` (kdc/kdc_util.c:1916-1922)
    pub otp: Result<Vec<krb5_config::OtpType>, krb5_config::OtpInitError>,
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
            ad_identity: false,
            restrict_anon: false,
            pkinit_require_freshness: false,
            host_based_services: String::new(),
            no_host_referral: String::new(),
            domain_realm: BTreeMap::new(),
            encrypted_challenge_indicator: None,
            pkinit_indicators: Vec::new(),
            spake_preauth_indicators: Vec::new(),
            spake_preauth_groups: Vec::new(),
            spake_preauth_kdc_challenge: None,
            disable_last_success: false,
            disable_lockout: false,
            kdcpreauth: krb5_config::PluginRelations::default(),
            kdcpolicy: krb5_config::PluginRelations::default(),
            audit: krb5_config::PluginRelations::default(),
            pwqual: krb5_config::PluginRelations::default(),
            kadm5_hook: krb5_config::PluginRelations::default(),
            otp: Ok(vec![krb5_config::OtpType::builtin(
                krb5_config::DEFAULT_OTP_TYPE,
            )]),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpakeKdc<'a> {
    pub groups: &'a [SpakeGroup],
    pub challenge: Option<SpakeGroup>,
}

/// A list that names no enctype permits nothing.
// MIT: `krb5int_parse_enctype_list` (lib/krb5/krb/init_ctx.c:497-500)
fn parse_permitted(names: &[String], allow_weak: bool) -> Vec<EncryptionType> {
    krb5_crypto::parse_enctype_list(&names.join(" "), allow_weak).unwrap_or_default()
}

fn parse_spake_preauth_groups(words: &[String]) -> Vec<SpakeGroup> {
    spake_parse_groups(&words.join(" "))
}

impl Policy {
    // MIT: `group_init_state` (groups.c:213-281)
    pub fn spake_kdc(&self) -> Result<SpakeKdc<'_>, String> {
        if self.spake_preauth_groups.is_empty() {
            return Err("No SPAKE preauth groups configured".to_owned());
        }
        let challenge = match self.spake_preauth_kdc_challenge.as_deref() {
            None => None,
            Some(name) => match SpakeGroup::from_name(name) {
                Some(group) if self.spake_preauth_groups.contains(&group) => Some(group),
                _ => {
                    return Err(format!(
                        "SPAKE challenge group not a permitted group: {name}"
                    ));
                }
            },
        };
        Ok(SpakeKdc {
            groups: &self.spake_preauth_groups,
            challenge,
        })
    }

    // MIT: `otp_init` (plugins/preauth/otp/main.c:195-206)
    pub fn otp_kdc(&self) -> Result<&[krb5_config::OtpType], &krb5_config::OtpInitError> {
        self.otp.as_deref()
    }

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

    #[must_use]
    pub fn etype_permitted(&self, e: EncryptionType) -> bool {
        self.permitted_enctypes
            .as_ref()
            .is_none_or(|v| v.contains(&e))
    }

    // MIT: `krb5_get_permitted_enctypes` (lib/krb5/krb/init_ctx.c:573-595)
    #[must_use]
    pub fn permitted_list(&self) -> Vec<EncryptionType> {
        self.permitted_enctypes.clone().unwrap_or_else(|| {
            krb5_crypto::parse_enctype_list("DEFAULT", self.allow_weak_crypto).unwrap_or_default()
        })
    }

    pub fn find_enctype<'p>(
        &self,
        p: &'p Principal,
        etype: Option<EncryptionType>,
        kvno: u32,
    ) -> Result<&'p KeyEntry, KeyLookup> {
        p.find_enctype(etype, kvno, |e| self.etype_permitted(e))
    }

    // MIT: `get_first_current_key` (kdc_util.c:462-473)
    pub fn first_current_key<'p>(&self, p: &'p Principal) -> Result<&'p KeyEntry, KeyLookup> {
        self.find_enctype(p, None, 0)
    }

    #[must_use]
    pub fn realm_for_host(&self, host: &str) -> Option<&str> {
        krb5_config::host_to_realm(&self.domain_realm, host)
    }

    // MIT: `kadm5_get_config_params` (lib/kadm5/alt_prof.c:650-654)
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
        if let Some(names) = &conf.permitted_enctypes {
            self.policy.permitted_enctypes =
                Some(parse_permitted(names, self.policy.allow_weak_crypto));
        }
        if !conf.supported_enctypes.is_empty() {
            self.policy.supported_enctypes =
                krb5_crypto::parse_keysalt_list(&conf.supported_enctypes.join(" "));
        }
        if let Some(skew) = conf.clockskew {
            self.policy.skew = skew;
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
        self.policy.disable_last_success = conf.disable_last_success;
        self.policy.disable_lockout = conf.disable_lockout;
        self.policy.disable_pac = conf.disable_pac;
        self.policy.restrict_anon = conf.restrict_anon;
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
            .spake_preauth_indicators
            .clone_from(&conf.spake_preauth_indicators);
        if let Some(names) = &conf.spake_preauth_groups {
            self.policy.spake_preauth_groups = parse_spake_preauth_groups(names);
        }
        if let Some(group) = &conf.spake_preauth_kdc_challenge {
            self.policy.spake_preauth_kdc_challenge = Some(group.clone());
        }
        if let Some(s) = conf.domain_sid.as_deref() {
            let Some(sid) = RpcSid::from_sddl(s) else {
                return Err(Error::Crypto(format!(
                    "kdc.conf domain_sid is not valid SDDL: {s}"
                )));
            };
            self.domain_sid = sid;
        }
        self.policy.ad_identity = conf.domain_sid.is_some();
        self.policy.kdcpreauth = conf.plugin_relations("kdcpreauth");
        self.policy.kdcpolicy = conf.plugin_relations("kdcpolicy");
        self.policy.audit = conf.plugin_relations("audit");
        self.policy.pwqual = conf.plugin_relations("pwqual");
        self.policy.kadm5_hook = conf.plugin_relations("kadm5_hook");
        self.policy.otp = krb5_config::kdc_otp_types(conf, &krb5_config::Krb5Conf::default());
        Ok(())
    }

    // MIT: `add_kdc_config_file` (lib/krb5/os/init_os_ctx.c:339-366)
    pub fn apply_otp(
        &mut self,
        kdc: Option<&krb5_config::KdcConf>,
        krb5: Option<&krb5_config::Krb5Conf>,
    ) {
        let kdc_fallback = krb5_config::KdcConf::default();
        let krb5_fallback = krb5_config::Krb5Conf::default();
        self.policy.otp = krb5_config::kdc_otp_types(
            kdc.unwrap_or(&kdc_fallback),
            krb5.unwrap_or(&krb5_fallback),
        );
    }

    pub fn apply_kdcpreauth_plugins(
        &mut self,
        kdc: Option<&krb5_config::KdcConf>,
        krb5: Option<&krb5_config::Krb5Conf>,
    ) {
        let kdc_fallback = krb5_config::KdcConf::default();
        let krb5_fallback = krb5_config::Krb5Conf::default();
        self.policy.kdcpreauth = krb5_config::kdc_plugin_relations(
            kdc.unwrap_or(&kdc_fallback),
            krb5.unwrap_or(&krb5_fallback),
            "kdcpreauth",
        );
    }

    pub fn apply_kdcpolicy_plugins(
        &mut self,
        kdc: Option<&krb5_config::KdcConf>,
        krb5: Option<&krb5_config::Krb5Conf>,
    ) {
        let kdc_fallback = krb5_config::KdcConf::default();
        let krb5_fallback = krb5_config::Krb5Conf::default();
        self.policy.kdcpolicy = krb5_config::kdc_plugin_relations(
            kdc.unwrap_or(&kdc_fallback),
            krb5.unwrap_or(&krb5_fallback),
            "kdcpolicy",
        );
    }

    pub fn apply_audit_plugins(
        &mut self,
        kdc: Option<&krb5_config::KdcConf>,
        krb5: Option<&krb5_config::Krb5Conf>,
    ) {
        let kdc_fallback = krb5_config::KdcConf::default();
        let krb5_fallback = krb5_config::Krb5Conf::default();
        self.policy.audit = krb5_config::kdc_plugin_relations(
            kdc.unwrap_or(&kdc_fallback),
            krb5.unwrap_or(&krb5_fallback),
            "audit",
        );
    }

    pub fn apply_pwqual_plugins(
        &mut self,
        kdc: Option<&krb5_config::KdcConf>,
        krb5: Option<&krb5_config::Krb5Conf>,
    ) {
        let kdc_fallback = krb5_config::KdcConf::default();
        let krb5_fallback = krb5_config::Krb5Conf::default();
        self.policy.pwqual = krb5_config::kdc_plugin_relations(
            kdc.unwrap_or(&kdc_fallback),
            krb5.unwrap_or(&krb5_fallback),
            "pwqual",
        );
    }

    pub fn apply_kadm5_hook_plugins(
        &mut self,
        kdc: Option<&krb5_config::KdcConf>,
        krb5: Option<&krb5_config::Krb5Conf>,
    ) {
        let kdc_fallback = krb5_config::KdcConf::default();
        let krb5_fallback = krb5_config::Krb5Conf::default();
        self.policy.kadm5_hook = krb5_config::kdc_plugin_relations(
            kdc.unwrap_or(&kdc_fallback),
            krb5.unwrap_or(&krb5_fallback),
            "kadm5_hook",
        );
    }

    pub fn apply_profile(&mut self, profile: &krb5_config::ProfileSet) -> Result<(), Error> {
        self.set_capaths(profile.krb5.capaths.clone());
        self.apply_libdefaults(&profile.krb5);
        let (kdc, krb5) = (profile.kdc.as_ref(), Some(&profile.krb5));
        if let Some(conf) = kdc {
            self.apply_kdc_conf(conf)?;
        }
        let pkinit = krb5_config::PkinitParams::for_realm(&profile.kdc_context, &self.realm);
        self.policy.pkinit_require_freshness = pkinit.require_freshness;
        self.policy.pkinit_indicators = pkinit.indicators;
        self.apply_kdcpreauth_plugins(kdc, krb5);
        self.apply_otp(kdc, krb5);
        self.apply_kdcpolicy_plugins(kdc, krb5);
        self.apply_audit_plugins(kdc, krb5);
        self.apply_pwqual_plugins(kdc, krb5);
        self.apply_kadm5_hook_plugins(kdc, krb5);
        Ok(())
    }

    // MIT: `load_preauth_plugins` (kdc/kdc_preauth.c:207-219)
    pub fn init_pkinit(&mut self, profile: &krb5_config::ProfileSet) -> Option<String> {
        self.env.pkinit = None;
        if !crate::plugins::startup_module_loaded(&self.policy.kdcpreauth, "pkinit") {
            return None;
        }
        let params = krb5_config::PkinitParams::for_realm(&profile.kdc_context, &self.realm);
        match crate::pkinit::PkinitKdc::init(&params, &self.realm) {
            Ok(kdc) => {
                self.env.pkinit = Some(std::sync::Arc::new(kdc));
                None
            }
            Err(msg) => Some(msg),
        }
    }

    pub fn set_pkinit(&mut self, pkinit: Option<crate::pkinit::PkinitKdc>) {
        self.env.pkinit = pkinit.map(std::sync::Arc::new);
    }

    pub fn apply_libdefaults(&mut self, conf: &krb5_config::Krb5Conf) {
        self.policy.allow_weak_crypto = conf.allow_weak_crypto;
        if let Some(v) = conf.allow_rc4 {
            self.policy.allow_rc4 = v;
        }
        if let Some(v) = conf.allow_des3 {
            self.policy.allow_des3 = v;
        }
        if let Some(names) = &conf.permitted_enctypes {
            self.policy.permitted_enctypes = Some(parse_permitted(
                names,
                self.policy.allow_weak_crypto || conf.allow_weak_crypto,
            ));
        }
        if let Some(names) = &conf.spake_preauth_groups {
            self.policy.spake_preauth_groups = parse_spake_preauth_groups(names);
        }
        // MIT: `krb5_init_context_profile` (lib/krb5/krb/init_ctx.c:251-252)
        self.policy.skew = i64::from(conf.clockskew);
        self.policy.domain_realm.clone_from(&conf.domain_realm);
    }

    #[must_use]
    pub fn policies(&self) -> &HashMap<String, NamedPolicy> {
        &self.policies
    }

    pub fn put_policy(&mut self, pol: NamedPolicy) -> Result<(), Error> {
        self.change(|s| {
            s.note_ulog_reset();
            s.policies.insert(pol.name.clone(), pol);
            s.save_if_configured()
        })?
    }

    pub(crate) fn load_policy(&mut self, pol: NamedPolicy) {
        self.policies.insert(pol.name.clone(), pol);
    }

    pub fn delete_policy(&mut self, name: &str) -> Result<(), Error> {
        self.change(|s| {
            s.policies.remove(name).ok_or(Error::NotFound)?;
            s.note_ulog_reset();
            s.save_if_configured()
        })?
    }

    pub fn set_principal_policy(
        &mut self,
        name: &PrincipalName,
        policy: Option<String>,
    ) -> Result<(), Error> {
        let realm = self.realm.clone();
        self.set_principal_policy_in(name, &realm, policy, &default_mod_actor(&realm))
    }

    pub(crate) fn set_principal_policy_in(
        &mut self,
        name: &PrincipalName,
        princ_realm: &str,
        policy: Option<String>,
        actor: &str,
    ) -> Result<(), Error> {
        self.inside_change()?;
        let id = self.canonical_id(name, princ_realm)?;
        {
            let p = self.map.get_mut(&id).ok_or(Error::NotFound)?;
            p.pw_policy = policy;
            refresh_kadm_tl(p);
            stamp_admin_tl(p, false, actor);
        }
        self.apply_pw_max_life_in(name, princ_realm)?;
        let snap = self.map.get(&id).cloned();
        self.note_ulog(id, false, snap);
        self.save_if_configured()
    }

    #[must_use]
    pub fn max_fail_for(&self, p: &Principal) -> u32 {
        p.pw_policy
            .as_ref()
            .and_then(|n| self.policies.get(n))
            .map_or(0, |pol| pol.max_fail)
    }

    #[must_use]
    pub(crate) fn named_policy_for(&self, p: &Principal) -> Option<NamedPolicy> {
        p.pw_policy
            .as_ref()
            .and_then(|n| self.policies.get(n).cloned())
    }
}
