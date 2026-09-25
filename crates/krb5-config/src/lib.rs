//! krb5.conf / kdc.conf, process environment, and DNS SRV discovery.
//!
//! There is no C FFI. DNS SRV is a minimal RFC 2782 UDP client.
//!
//! One module per MIT source family: `profile` (krb5.conf), `kdcconf`,
//! `ccname`, `srv`, `testenv`. In-src tests stay under `tests`.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod ccname;
mod kdcconf;
mod profile;
mod srv;
mod testenv;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::path::PathBuf;

use thiserror::Error;

/// Config / discovery failure.
#[derive(Debug, Error)]
pub enum Error {
    /// I/O.
    #[error("config io: {0}")]
    Io(#[from] std::io::Error),
    /// Parse error with context.
    #[error("config parse: {0}")]
    Parse(String),
    /// DNS SRV lookup failed.
    #[error("dns srv: {0}")]
    Dns(String),
    /// Ccache name / `%{token}` expansion. `Unknown credential cache
    /// type` is KRB5_CC_UNKNOWN_TYPE (`krb5_err.et:190`); the two
    /// `%{token}` texts are this crate's (MIT `expand_path.c` says
    /// `Invalid token` / `variable missing }`).
    #[error("{0}")]
    Ccache(String),
}

/// One KDC (or kpasswd / admin) endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// Host name or dotted IP.
    pub host: String,
    /// UDP/TCP port.
    pub port: u16,
}

impl Endpoint {
    /// `host:88`.
    #[must_use]
    pub fn kdc(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port: 88,
        }
    }
}

/// Parsed `[libdefaults]` plus realm stanzas.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Krb5Conf {
    /// `default_realm`.
    pub default_realm: Option<String>,
    /// `allow_weak_crypto`.
    pub allow_weak_crypto: bool,
    /// `allow_rc4` (unset = false at the KDC unless kdc.conf set it).
    pub allow_rc4: Option<bool>,
    /// `allow_des3`.
    pub allow_des3: Option<bool>,
    /// Clock skew in seconds (default 300).
    pub clockskew: u32,
    /// `dns_lookup_kdc`.
    pub dns_lookup_kdc: bool,
    /// MIT `krb5_get_host_realm` (`hostrealm.c:361-398`): `dns_lookup_realm`.
    pub dns_lookup_realm: bool,
    /// `udp_preference_limit` (MIT default 1465). `None` = default.
    pub udp_preference_limit: Option<u32>,
    /// `rdns`. Parsed; we do not reverse-resolve addresses.
    pub rdns: bool,
    /// MIT `krb5_init_context_profile` (`init_ctx.c:268-270`): `kdc_timesync`. Default true. AS-REP
    /// `verify_as_reply` skips starttime vs the local clock when set.
    pub kdc_timesync: bool,
    /// MIT `nofail` (`vfy_increds.c:39-51`): `verify_ap_req_nofail`. Default false.
    pub verify_ap_req_nofail: bool,
    /// `permitted_enctypes`.
    pub permitted_enctypes: Vec<String>,
    /// `default_tkt_enctypes`.
    pub default_tkt_enctypes: Vec<String>,
    /// `default_tgs_enctypes`.
    pub default_tgs_enctypes: Vec<String>,
    /// `forwardable`.
    pub forwardable: bool,
    /// `proxiable`.
    pub proxiable: bool,
    /// MIT `krb5_init_creds_init` (`get_in_tkt.c:921-930`): `canonicalize`. Default false.
    pub canonicalize: bool,
    /// `ticket_lifetime` seconds.
    pub ticket_lifetime: Option<u64>,
    /// `renew_lifetime` seconds.
    pub renew_lifetime: Option<u64>,
    /// Heimdal `kdc_timeout` — no MIT parse site; stored and unused.
    pub kdc_timeout: Option<String>,
    /// Heimdal `max_retries` — no MIT parse site; stored and unused.
    pub max_retries: Option<String>,
    /// `[libdefaults] kcm_socket` (MIT; `KCM_SOCKET` env overrides).
    pub kcm_socket: Option<String>,
    /// `[libdefaults] default_ccache_name` (MIT parameter expansion).
    pub default_ccache_name: Option<String>,
    /// `[libdefaults] spake_preauth_groups`. `None` = omitted (KDC default none).
    pub spake_preauth_groups: Option<Vec<String>>,
    /// `[libdefaults] preferred_preauth_types`. Empty = MIT default `17, 16, 15, 14`.
    pub preferred_preauth_types: Vec<i32>,
    /// `[libdefaults] ignore_acceptor_hostname`. Default false
    /// MIT `krb5_sname_match` (`sname_match.c:51-53`): same check.
    pub ignore_acceptor_hostname: bool,
    /// Realm → KDC list.
    pub kdcs: BTreeMap<String, Vec<Endpoint>>,
    /// Realm → admin_server.
    pub admin_servers: BTreeMap<String, Vec<Endpoint>>,
    /// Realm → kpasswd_server.
    pub kpasswd_servers: BTreeMap<String, Vec<Endpoint>>,
    /// Domain → realm (`[domain_realm]`).
    pub domain_realm: BTreeMap<String, String>,
    /// Realm → `pkinit_identities` FILE values.
    pub pkinit_identities: BTreeMap<String, Vec<String>>,
    /// Realm → `pkinit_anchors` FILE values.
    pub pkinit_anchors: BTreeMap<String, Vec<String>>,
    /// `[capaths]` client-realm → server-realm → intermediates (`.` = direct).
    pub capaths: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

/// KDC policy from `kdc.conf`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdcConf {
    /// Bind addresses (host:port). Empty means `127.0.0.1:88`.
    pub kdc_listen: Vec<String>,
    /// TCP listen addresses.
    pub kdc_tcp_listen: Vec<String>,
    /// Realm name.
    pub realm: String,
    /// Maximum ticket lifetime in seconds (default 1 day, `alt_prof.c`).
    pub max_life: u64,
    /// MIT `kadm5_get_config_params` (`alt_prof.c:577-578`): kadm5 create default for `max_renewable_life`
    /// `GET_DELTAT_PARAM(max_rlife, …, 0)`). Omitted = 0.
    pub max_renewable_life: u64,
    /// MIT `gss_inquire_sec_context_by_oid` (`main.c:316-319`): KDC realm renewable cap (`kdc/ `realm_maxrlife`
    /// omitted = `KRB5_KDB_MAX_RLIFE` = 7 days). A written
    /// `max_renewable_life` sets this and [`Self::max_renewable_life`].
    pub realm_max_renewable_life: u64,
    /// Database path.
    pub database_name: Option<PathBuf>,
    /// ACL file.
    pub acl_file: Option<PathBuf>,
    /// Stash file for the master key.
    pub key_stash_file: Option<PathBuf>,
    /// User to drop to after binding a privileged port.
    pub kdc_user: Option<String>,
    /// `allow_weak_crypto`.
    pub allow_weak_crypto: Option<bool>,
    /// `allow_rc4` (`[libdefaults]` / `[kdcdefaults]`).
    pub allow_rc4: Option<bool>,
    /// `allow_des3`.
    pub allow_des3: Option<bool>,
    /// `permitted_enctypes` (empty = MIT DEFAULT).
    pub permitted_enctypes: Vec<String>,
    /// Realm `supported_enctypes` keysalt list.
    pub supported_enctypes: Vec<String>,
    /// Per-principal `requires_preauth` default.
    pub requires_preauth: bool,
    /// MIT `kadm5_get_config_params` (`alt_prof.c:596-632`): `[realms] default_principal_flags` as written (MIT
    /// `KADM5_CONFIG_FLAGS`; the flagspec list is parsed by the store). `None`
    /// = `KRB5_KDB_DEF_FLAGS` (0).
    pub default_principal_flags: Option<String>,
    /// `[realms] default_principal_expiration` as written (MIT
    /// MIT `kadm5_get_config_params` (`alt_prof.c:580-594`): `KADM5_CONFIG_EXPIRATION`, a
    /// `krb5_string_to_timestamp` form; the store converts it). `None` = 0.
    pub default_principal_expiration: Option<String>,
    /// `master_key_type` (MIT name, e.g. `aes256-cts-hmac-sha384-192`).
    pub master_key_type: Option<String>,
    /// `database_module` / `db_library`. Default dump-v7; unknown names error.
    pub db_library: Option<String>,
    /// Optional NT domain SID (`S-1-5-21-…`) for PAC issuance.
    pub domain_sid: Option<String>,
    /// `reject_bad_transit` (default true). When false, a failed transited
    /// check is accepted without `TRANSITED_POLICY_CHECKED`.
    pub reject_bad_transit: bool,
    /// disable_pac (default false).
    pub disable_pac: bool,
    /// restrict_anonymous_to_tgt (default false).
    pub restrict_anon: bool,
    /// pkinit_require_freshness (default false).
    pub pkinit_require_freshness: bool,
    /// host_based_services (space/comma-separated).
    pub host_based_services: String,
    /// no_host_referral (space/comma-separated).
    pub no_host_referral: String,
    /// `[realms] encrypted_challenge_indicator`.
    pub encrypted_challenge_indicator: Option<String>,
    /// `[realms] pkinit_indicator` (repeatable).
    pub pkinit_indicators: Vec<String>,
    /// `[realms] spake_preauth_indicator` (repeatable).
    pub spake_preauth_indicators: Vec<String>,
    /// `[libdefaults] spake_preauth_groups`. `None` = omitted.
    pub spake_preauth_groups: Option<Vec<String>>,
    /// `[realms] dict_file` for the `dict` password-quality module. MIT
    /// MIT `kadm5_get_config_params` (`alt_prof.c:486-513`): reads it from the realm stanza only, never from
    /// `[kdcdefaults]`.
    pub dict_file: Option<PathBuf>,
}

/// Resolved ccache name (`krb5_cc_resolve`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CcSpec {
    /// `FILE:path` or a residual with no type prefix.
    File(PathBuf),
    /// `MEMORY:name` (process-global).
    Memory(String),
    /// `DIR:dirname` or `DIR::filepath`.
    Dir(String),
    /// `KCM:` or `KCM:residual` (sssd-kcm / Heimdal daemon).
    Kcm(String),
}

pub use ccname::{
    KRB5_CC_UNKNOWN_TYPE, default_ccache_name, default_ccspec, expand_ccache_params, parse_ccname,
    parse_ccspec, resolve_ccspec,
};
pub use kdcconf::{env_kdc_config, kdc_conf_path};
pub use profile::{
    client_realm_path, discover_kdc, discover_kdc_in, env_ktname, env_new_password, env_password,
    host_to_realm, is_numeric_address, krb5_conf_paths, load_krb5_conf, load_krb5_conf_paths,
    parse_deltat, split_krb5_config_paths, udp_preference_limit,
};
pub use srv::lookup_srv_kdc;
pub use testenv::{isolate_test_krb5, set_test_krb5_paths};
