//! ```
//! use krb5_config::Krb5Conf;
//! let conf = Krb5Conf::parse("[libdefaults]\ndefault_realm = TESTLABBY.LOCAL\n")?;
//! assert_eq!(conf.default_realm.as_deref(), Some("TESTLABBY.LOCAL"));
//! Ok::<(), krb5_config::Error>(())
//! ```
//! ```
//! use krb5_config::Krb5Conf;
//! let conf = Krb5Conf::parse("[libdefaults]\nclockskew = 120\n")?;
//! assert_eq!(conf.clockskew, 120);
//! Ok::<(), krb5_config::Error>(())
//! ```

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![allow(
    clippy::disallowed_methods,
    reason = "the profile and environment readers the lint confines live here"
)]

use std::time::Duration;

mod ccname;
mod context;
mod files;
mod hostname;
mod iprop_params;
mod kdcconf;
pub mod listen;
mod logging;
mod otp_profile;
mod pkinit_params;
mod plugin_profile;
mod profile;
mod profile_set;
mod srv;
mod testenv;

#[cfg(test)]
mod tests;

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("config io: {0}")]
    Io(#[from] std::io::Error),
    #[error("config parse: {0}")]
    Parse(String),
    #[error("config parse: {1}")]
    Profile(ProfileError, String),
    #[error("dns srv: {0}")]
    Dns(String),
    // MIT: `k5_parse_host_string` (lib/krb5/krb/parse_host_string.c:107-108)
    #[error("Invalid argument")]
    InvalidArgument,
    // MIT KRB5_CC_UNKNOWN_TYPE; see docs/parity/b1-client.md
    #[error("{0}")]
    Ccache(String),
    // MIT: `KRB5_CONFIG_NODEFREALM` (krb5_err.et:310-310)
    // the text.
    #[error("Configuration file does not specify default realm")]
    NoDefaultRealm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileError {
    // MIT: `parse_include_file` (prof_parse.c:229-231)
    // a file that does not open fails with
    IncludeFile,
    // MIT: `parse_include_dir` (prof_parse.c:271-272)
    // a directory that does not list fails
    IncludeDir,
    // MIT: `os_init_paths` (init_os_ctx.c:403-408)
    // a syntax error is `KRB5_CONFIG_BADFORMAT`.
    Syntax,
    // MIT get_boolean; see docs/parity/a2-as.md
    BadBoolean,
    // MIT: `get_tristate` (lib/krb5/krb/init_ctx.c:115-118)
    // any other value is `EINVAL`.
    BadTristate,
    BadDeltat,
    BadPathToken,
}

impl Error {
    #[must_use]
    pub fn init_text(&self) -> String {
        match self {
            Self::Io(e) => {
                let text = e.to_string();
                text.rsplit_once(" (os error ")
                    .map_or(text.as_str(), |(t, _)| t)
                    .to_owned()
            }
            Self::Profile(p, _) => p.text().to_owned(),
            other => other.to_string(),
        }
    }
}

impl ProfileError {
    #[must_use]
    pub const fn context_rank(self) -> u8 {
        match self {
            Self::IncludeFile | Self::IncludeDir | Self::Syntax => 0,
            Self::BadBoolean => 1,
            Self::BadTristate => 2,
            Self::BadDeltat => 3,
            Self::BadPathToken => 4,
        }
    }

    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            // MIT: `PROF_FAIL_INCLUDE_FILE` (prof_err.et:67-67)
            // the code whose text this is.
            Self::IncludeFile => "Included profile file could not be read",
            // MIT: `PROF_FAIL_INCLUDE_DIR` (prof_err.et:69-69)
            // the code whose text this is.
            Self::IncludeDir => "Included profile directory could not be read",
            // MIT KRB5_CONFIG_BADFORMAT; see docs/parity/b1-client.md
            Self::Syntax => "Improper format of Kerberos configuration file",
            // MIT PROF_BAD_BOOLEAN; see docs/parity/b1-client.md
            Self::BadBoolean => "Invalid boolean value",
            Self::BadTristate | Self::BadPathToken => "Invalid argument",
            // MIT KRB5_DELTAT_BADFORMAT; see docs/parity/b1-client.md
            Self::BadDeltat => "Invalid format of Kerberos lifetime or clock skew string",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdcTransport {
    Udp,
    Tcp,
    Either,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub transport: KdcTransport,
}

impl Endpoint {
    #[must_use]
    pub fn kdc(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: 88,
            transport: KdcTransport::Either,
        }
    }
}

thread_local! {
    static HANDED_KDCS: Cell<Option<(String, Vec<Endpoint>)>> = const { Cell::new(None) };
}

pub fn hand_kdcs(realm: &str, list: Vec<Endpoint>) {
    HANDED_KDCS.with(|cell| cell.set(Some((realm.to_owned(), list))));
}

#[must_use]
pub fn handed_matches(realm: &str, host: &str, port: u16) -> bool {
    HANDED_KDCS.with(|cell| {
        let cur = cell.replace(None);
        let matches = cur.as_ref().is_some_and(|(got, list)| {
            got == realm
                && list
                    .first()
                    .is_some_and(|ep| ep.host == host && ep.port == port)
        });
        cell.set(cur);
        matches
    })
}

#[must_use]
pub fn take_handed_kdcs(realm: &str, host: &str, port: u16) -> Option<Vec<Endpoint>> {
    HANDED_KDCS.with(|cell| {
        let cur = cell.replace(None)?;
        let starts = cur
            .1
            .first()
            .is_some_and(|ep| cur.0 == realm && ep.host == host && ep.port == port);
        starts.then_some(cur.1)
    })
}

pub fn clear_handed() {
    HANDED_KDCS.with(|cell| cell.set(None));
}

// MIT krb5int_libdefault_string; see docs/parity/b1-client.md
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RealmLibdefaults {
    pub forwardable: Option<bool>,
    pub proxiable: Option<bool>,
    pub canonicalize: Option<bool>,
    pub ticket_lifetime: Option<u64>,
    pub renew_lifetime: Option<u64>,
    pub noaddresses: Option<bool>,
    pub preferred_preauth_types: Option<Vec<i32>>,
    pub verify_ap_req_nofail: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Krb5Conf {
    pub default_realm: Option<String>,
    pub allow_weak_crypto: bool,
    pub allow_rc4: Option<bool>,
    pub allow_des3: Option<bool>,
    pub clockskew: i32,
    pub dns_lookup_kdc: bool,
    pub dns_lookup_realm: bool,
    pub client_aware_channel_bindings: bool,
    pub client_aware_channel_bindings_invalid: bool,
    pub udp_preference_limit: Option<u32>,
    pub rdns: bool,
    pub kdc_timesync: bool,
    // MIT: `nofail` (vfy_increds.c:38-51)
    // `verify_ap_req_nofail` defaults to false.
    pub verify_ap_req_nofail: bool,
    pub permitted_enctypes: Option<Vec<String>>,
    pub default_tkt_enctypes: Vec<String>,
    pub default_tgs_enctypes: Vec<String>,
    pub forwardable: bool,
    pub proxiable: bool,
    // MIT: `krb5_init_creds_init` (get_in_tkt.c:921-930)
    // `canonicalize` defaults to false.
    pub canonicalize: bool,
    pub ticket_lifetime: Option<u64>,
    pub renew_lifetime: Option<u64>,
    pub noaddresses: Option<bool>,
    pub kdc_timeout: Option<String>,
    // MIT: `krb5_init_context_profile` (lib/krb5/krb/init_ctx.c:254-263)
    pub request_timeout: Option<Duration>,
    pub max_retries: Option<String>,
    pub kcm_socket: Option<String>,
    pub default_ccache_name: Option<String>,
    pub default_keytab_name: Option<String>,
    pub default_client_keytab_name: Option<String>,
    pub spake_preauth_groups: Option<Vec<String>>,
    pub preferred_preauth_types: Vec<i32>,
    // MIT krb5_sname_match; see docs/parity/b1-client.md
    pub ignore_acceptor_hostname: bool,
    pub qualify_shortname: Option<String>,
    pub realm_try_domains: Option<String>,
    pub dns_canonicalize_hostname: CanonHost,
    pub context_refusal: Option<ProfileError>,
    pub kdcs: BTreeMap<String, Vec<Endpoint>>,
    pub admin_servers: BTreeMap<String, Vec<Endpoint>>,
    pub kpasswd_servers: BTreeMap<String, Vec<Endpoint>>,
    pub kdc_host_invalid: BTreeSet<String>,
    pub admin_host_invalid: BTreeSet<String>,
    pub kpasswd_host_invalid: BTreeSet<String>,
    pub domain_realm: BTreeMap<String, String>,
    pub pkinit_identities: BTreeMap<String, Vec<String>>,
    pub pkinit_anchors: BTreeMap<String, Vec<String>>,
    pub capaths: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    pub logging: Vec<(String, String)>,
    pub kadm5: BTreeMap<String, Vec<(String, String)>>,
    pub pkinit: BTreeMap<String, Vec<(String, String)>>,
    pub kdcdefaults_pkinit: Vec<(String, String)>,
    pub libdefaults_pkinit: Vec<(String, String)>,
    pub realm_libdefaults_pkinit: BTreeMap<String, Vec<(String, String)>>,
    pub realm_libdefaults: BTreeMap<String, RealmLibdefaults>,
    // MIT encts_disabled; see docs/parity/b1-client-preauth.md
    pub disable_encrypted_timestamp: BTreeMap<String, bool>,
    // MIT configure_interface; see docs/parity/b1-client-preauth.md
    pub plugins: PluginProfile,
    // MIT token_types_decode; see docs/parity/a3-preauth.md
    pub otp: OtpTree,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CanonHost {
    #[default]
    True,
    False,
    Fallback,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdcConf {
    pub kdc_listen: String,
    pub kdc_listen_in_realm: bool,
    pub kdc_tcp_listen: Option<String>,
    pub realm: String,
    pub max_life: u64,
    pub max_renewable_life: u64,
    pub realm_max_renewable_life: u64,
    pub database_name: Option<PathBuf>,
    pub acl_file: Option<PathBuf>,
    pub key_stash_file: Option<PathBuf>,
    pub allow_weak_crypto: Option<bool>,
    pub allow_rc4: Option<bool>,
    pub allow_des3: Option<bool>,
    pub permitted_enctypes: Option<Vec<String>>,
    pub clockskew: Option<i64>,
    pub supported_enctypes: Vec<String>,
    pub requires_preauth: bool,
    pub default_principal_flags: Option<String>,
    pub default_principal_expiration: Option<String>,
    pub master_key_type: Option<String>,
    pub db_library: Option<String>,
    // MIT: `configure_context` (plugins/kdb/db2/kdb_db2.c:267-271)
    // `disable_last_success` from that `[dbmodules]` section, default false.
    pub disable_last_success: bool,
    pub disable_lockout: bool,
    pub domain_sid: Option<String>,
    pub reject_bad_transit: bool,
    pub disable_pac: bool,
    pub restrict_anon: bool,
    pub host_based_services: String,
    pub no_host_referral: String,
    pub encrypted_challenge_indicator: Option<String>,
    pub spake_preauth_indicators: Vec<String>,
    pub spake_preauth_groups: Option<Vec<String>>,
    pub spake_preauth_kdc_challenge: Option<String>,
    pub dict_file: Option<PathBuf>,
    pub logging: Vec<(String, String)>,
    pub kdc_max_dgram_reply_size: i32,
    pub kdc_tcp_listen_backlog: i32,
    pub unsupported: Vec<String>,
    // MIT: `get_profile_var` (lib/krb5/krb/plugin.c:188-203)
    // the relations sit under the interface name.
    pub plugins: PluginProfile,
    pub otp: OtpTree,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CcSpec {
    File(PathBuf),
    Memory(String),
    Dir(String),
    Kcm(String),
}

pub use ccname::{
    KRB5_CC_UNKNOWN_TYPE, default_ccache_name, default_ccspec, expand_ccache_params, parse_ccname,
    parse_ccspec, resolve_ccspec,
};
pub use context::ClientContext;
pub use files::ReadOnce;
pub use hostname::{
    CanonPrinc, HostPrinc, SnameError, expand_hostname, expand_hostname_no_dns,
    fallback_host_realm, local_host_name, sname_to_principal, this_host,
};
pub use iprop_params::{DEF_ULOGENTRIES, IpropParams, KadmindListen, MISSING_CONF_PARAMS};
pub use kdcconf::{
    KDC_DIR, KdcPaths, default_acl_file, default_kdb_file, default_kdc_profile, default_kprop_file,
    default_kpropd_acl, default_stash_file, env_kdc_config, kdc_conf_path,
};
pub use logging::LogSpecs;
pub use otp_profile::{
    DEFAULT_OTP_TYPE, OtpInitError, OtpProfile, OtpTree, OtpType, kdc_otp_types, token_types_decode,
};
pub use pkinit_params::PkinitParams;
pub use plugin_profile::{
    PluginProfile, PluginRelations, filter_plugin_modules, kdc_plugin_relations,
};
pub use profile::{
    client_realm_path, discover_kdc_in, env_ktname, env_new_password, env_password, host_to_realm,
    init_kdc_profile, init_profile, is_numeric_address, join_subsection_braces, krb5_conf_paths,
    load_krb5_conf, load_krb5_conf_paths, parse_deltat, split_krb5_config_paths,
};
pub use profile_set::ProfileSet;
pub use srv::lookup_srv_kdc;
pub use testenv::{isolate_test_krb5, isolated_profile, set_test_kdc_profile, set_test_krb5_paths};
