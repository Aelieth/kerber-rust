//! krb5.conf / kdc.conf, process environment, and DNS SRV discovery.
//!
//! There is no C FFI. DNS SRV is a minimal RFC 2782 UDP client.
//!
//! One module per MIT source family: `profile` (krb5.conf), `plugin_profile` (`[plugins]`),
//! `kdcconf`, `iprop_params`, `ccname`, `srv`, `testenv`. In-src tests stay under `tests`.
//!
//! # Examples
//!
//! `default_realm` is the `[libdefaults]` value:
//!
//! ```
//! use krb5_config::Krb5Conf;
//! let conf = Krb5Conf::parse("[libdefaults]\ndefault_realm = TESTLABBY.LOCAL\n")?;
//! assert_eq!(conf.default_realm.as_deref(), Some("TESTLABBY.LOCAL"));
//! Ok::<(), krb5_config::Error>(())
//! ```
//!
//! `clockskew` is a duration in seconds:
//!
//! ```
//! use krb5_config::Krb5Conf;
//! let conf = Krb5Conf::parse("[libdefaults]\nclockskew = 120\n")?;
//! assert_eq!(conf.clockskew, 120);
//! Ok::<(), krb5_config::Error>(())
//! ```

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod ccname;
mod hostname;
mod iprop_params;
mod kdcconf;
pub mod listen;
mod logging;
mod plugin_profile;
mod profile;
mod srv;
mod testenv;

#[cfg(test)]
mod tests;

use std::cell::Cell;
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
    /// A `krb5.conf` MIT's profile library refuses: the code it refuses it with, and what failed.
    #[error("config parse: {1}")]
    Profile(ProfileError, String),
    /// DNS SRV lookup failed.
    #[error("dns srv: {0}")]
    Dns(String),
    /// Ccache name / `%{token}` expansion. The two `%{token}` texts are this
    /// crate's (MIT `expand_path.c` says `Invalid token` / `variable missing }`).
    /// MIT `KRB5_CC_UNKNOWN_TYPE` (`krb5_err.et:190-190`): the error for
    /// `Unknown credential cache type`.
    #[error("{0}")]
    Ccache(String),
    /// No realm was given and krb5.conf names no `default_realm`.
    /// MIT `KRB5_CONFIG_NODEFREALM` (`krb5_err.et:310-310`): the text.
    #[error("Configuration file does not specify default realm")]
    NoDefaultRealm,
}

/// Why MIT's profile library refuses a `krb5.conf`, which `krb5_init_context` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileError {
    /// An `include` target that cannot be read. An include cycle or 32-deep nesting, which MIT
    /// does not look for, is this too: MIT recurses until a file does not open.
    /// MIT `parse_include_file` (`prof_parse.c:229-231`): a file that does not open fails with
    /// `PROF_FAIL_INCLUDE_FILE`.
    IncludeFile,
    /// An `includedir` that cannot be listed.
    /// MIT `parse_include_dir` (`prof_parse.c:271-272`): a directory that does not list fails
    /// with `PROF_FAIL_INCLUDE_DIR`.
    IncludeDir,
    /// A syntax error: an `include` indented inside a section is a relation with no `=`; a
    /// relation with no value is a subsection whose `{` must start the next line
    /// (`PROF_MISSING_OBRACE`).
    /// MIT `os_init_paths` (`init_os_ctx.c:403-408`): a syntax error is `KRB5_CONFIG_BADFORMAT`.
    Syntax,
    /// A boolean the library context reads that is none.
    /// MIT `get_boolean` (`lib/krb5/krb/init_ctx.c:92-94`): `profile_get_boolean`'s `PROF_BAD_BOOLEAN` is the context's error.
    BadBoolean,
    /// A `dns_canonicalize_hostname` that is neither a boolean nor `fallback`.
    /// MIT `get_tristate` (`lib/krb5/krb/init_ctx.c:115-118`): any other value is `EINVAL`.
    BadTristate,
    /// A `request_timeout` that is no time interval.
    /// MIT `krb5_init_context_profile` (`lib/krb5/krb/init_ctx.c:259-262`): `krb5_string_to_deltat`'s error is the context's.
    BadDeltat,
    /// A `plugin_base_dir` whose `%{...}` tokens do not expand.
    /// MIT `krb5_init_context_profile` (`lib/krb5/krb/init_ctx.c:275-281`): `k5_expand_path_tokens`'s error is the context's.
    BadPathToken,
}

impl Error {
    /// MIT `error_message` of the code a failed context init returns for this error, as a
    /// tool's `com_err` prints it: a system error's `strerror`, a profile code's text, else this
    /// error's own text.
    /// MIT `os_init_paths` (`init_os_ctx.c:403-408`): a profile syntax error is
    /// `KRB5_CONFIG_BADFORMAT`, any other failure its own code.
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
    /// Where `krb5_init_context` makes the check that refuses a profile with this error, the
    /// earlier first; a load error is before them all.
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

    /// The text `krb5_init_context`'s callers print for it.
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            // MIT `PROF_FAIL_INCLUDE_FILE` (`prof_err.et:67-67`): the code whose text this is.
            Self::IncludeFile => "Included profile file could not be read",
            // MIT `PROF_FAIL_INCLUDE_DIR` (`prof_err.et:69-69`): the code whose text this is.
            Self::IncludeDir => "Included profile directory could not be read",
            // MIT `KRB5_CONFIG_BADFORMAT` (`krb5_err.et:184-184`): the text.
            Self::Syntax => "Improper format of Kerberos configuration file",
            // MIT `PROF_BAD_BOOLEAN` (`prof_err.et:60-60`): the code whose text this is.
            Self::BadBoolean => "Invalid boolean value",
            // `EINVAL`'s `strerror`.
            Self::BadTristate | Self::BadPathToken => "Invalid argument",
            // MIT `KRB5_DELTAT_BADFORMAT` (`krb5_err.et:344-344`): the code whose text this is.
            Self::BadDeltat => "Invalid format of Kerberos lifetime or clock skew string",
        }
    }
}

/// Which transports a located KDC is contacted on.
///
/// A profile `kdc` host uses both. An SRV `_udp` target is UDP only, and an SRV `_tcp` target is TCP only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdcTransport {
    /// UDP only.
    Udp,
    /// TCP only.
    Tcp,
    /// UDP and TCP.
    Either,
}

/// One KDC (or kpasswd / admin) endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// Host name or dotted IP.
    pub host: String,
    /// UDP/TCP port.
    pub port: u16,
    /// Which transports to use. Profile hosts are [`KdcTransport::Either`].
    pub transport: KdcTransport,
}

impl Endpoint {
    /// `host:88` on UDP and TCP.
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

/// Keep `list` for the next [`take_handed_kdcs`] of `realm`.
///
/// MIT `k5_locate_server` runs once per `k5_sendto_kdc`. A caller that already located the realm
/// hands that list down so the send does not look it up again.
pub fn hand_kdcs(realm: &str, list: Vec<Endpoint>) {
    HANDED_KDCS.with(|cell| cell.set(Some((realm.to_owned(), list))));
}

/// Whether a handed list for `realm` starts with `host`:`port`.
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

/// The handed list when it is for `realm` and starts with `host`:`port`. Any other handed list is dropped.
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

#[cfg(test)]
mod handed_kdcs {
    use super::{Endpoint, clear_handed, hand_kdcs, handed_matches, take_handed_kdcs};

    #[test]
    fn a_handed_list_is_taken_once_for_its_first_address() {
        clear_handed();
        hand_kdcs(
            "KERBER.TEST",
            vec![Endpoint::kdc("192.0.2.1"), Endpoint::kdc("192.0.2.2")],
        );
        assert!(handed_matches("KERBER.TEST", "192.0.2.1", 88));
        assert!(!handed_matches("OTHER.TEST", "192.0.2.1", 88));
        let got = take_handed_kdcs("KERBER.TEST", "192.0.2.1", 88).unwrap();
        assert_eq!(got.len(), 2);
        assert!(take_handed_kdcs("KERBER.TEST", "192.0.2.1", 88).is_none());
    }
}

/// Drop a handed list that will not be sent.
pub fn clear_handed() {
    HANDED_KDCS.with(|cell| cell.set(None));
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
    /// `dns_lookup_realm` (MIT `krb5_get_host_realm`).
    pub dns_lookup_realm: bool,
    /// `udp_preference_limit` (MIT default 1465). `None` = default.
    pub udp_preference_limit: Option<u32>,
    /// `rdns`. Parsed; we do not reverse-resolve addresses.
    pub rdns: bool,
    /// `kdc_timesync`. AS-REP `verify_as_reply` skips starttime vs the local clock
    /// when set.
    /// MIT `krb5_init_context_profile` (`krb/init_ctx.c:268-270`): `kdc_timesync` defaults
    /// to true.
    pub kdc_timesync: bool,
    /// `verify_ap_req_nofail`.
    /// MIT `nofail` (`vfy_increds.c:38-51`): `verify_ap_req_nofail` defaults to false.
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
    /// `canonicalize`.
    /// MIT `krb5_init_creds_init` (`get_in_tkt.c:921-930`): `canonicalize` defaults to false.
    pub canonicalize: bool,
    /// `ticket_lifetime` seconds.
    pub ticket_lifetime: Option<u64>,
    /// `renew_lifetime` seconds.
    pub renew_lifetime: Option<u64>,
    /// Heimdal `kdc_timeout` — no MIT parse site; stored and unused.
    pub kdc_timeout: Option<String>,
    /// Heimdal `max_retries` — no MIT parse site; stored and unused.
    pub max_retries: Option<String>,
    /// `[libdefaults] kcm_socket`: the KCM daemon's socket, `-` for none (MIT).
    pub kcm_socket: Option<String>,
    /// `[libdefaults] default_ccache_name` (MIT parameter expansion).
    pub default_ccache_name: Option<String>,
    /// `[libdefaults] default_keytab_name`, as written (the caller expands its parameters).
    pub default_keytab_name: Option<String>,
    /// `[libdefaults] default_client_keytab_name`, as written (the caller expands its
    /// parameters).
    pub default_client_keytab_name: Option<String>,
    /// `[libdefaults] spake_preauth_groups`. `None` = omitted (KDC default none).
    pub spake_preauth_groups: Option<Vec<String>>,
    /// `[libdefaults] preferred_preauth_types`. Empty = MIT default `17, 16, 15, 14`.
    pub preferred_preauth_types: Vec<i32>,
    /// `[libdefaults] ignore_acceptor_hostname`. Default false.
    /// MIT `krb5_sname_match` (`sname_match.c:51-53`): a hostname in the matching principal is
    /// checked unless this is set.
    pub ignore_acceptor_hostname: bool,
    /// `[libdefaults] qualify_shortname`: the domain a hostname without a dot gains when it is
    /// not looked up in DNS; `Some("")` adds none, and unset (`None`) takes the resolver's first
    /// search domain ([`local_host_name`]).
    /// MIT `qualify_shortname` (`lib/krb5/os/sn2princ.c:66-80`): the profile's value when it is set, else the resolver's.
    pub qualify_shortname: Option<String>,
    /// `[libdefaults] dns_canonicalize_hostname`: when a host-based service name is
    /// canonicalized, and whether through DNS.
    pub dns_canonicalize_hostname: CanonHost,
    /// Why `krb5_init_context` refuses this profile, the first of its checks that fails: a
    /// boolean it reads that is none ([`ProfileError::BadBoolean`]), a `dns_canonicalize_hostname`
    /// that is neither a boolean nor `fallback` ([`ProfileError::BadTristate`]), a
    /// `request_timeout` that is no interval ([`ProfileError::BadDeltat`]), a `plugin_base_dir`
    /// whose tokens do not expand ([`ProfileError::BadPathToken`]). [`load_krb5_conf_paths`]
    /// fails with it.
    pub context_refusal: Option<ProfileError>,
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
    /// `[logging]` relations, name and value, in file order (includes followed); read by
    /// [`LogSpecs`].
    pub logging: Vec<(String, String)>,
    /// Realm → its stanza's `iprop_*` relations, name and value, in file order (includes
    /// followed); read by [`IpropParams`].
    pub iprop: BTreeMap<String, Vec<(String, String)>>,
    /// Realm → `[realms] disable_encrypted_timestamp`. Absent means false.
    /// MIT `encts_disabled` (`lib/krb5/krb/get_in_tkt.c:757-772`): a profile boolean, default false.
    pub disable_encrypted_timestamp: BTreeMap<String, bool>,
    /// `[plugins]` `disable` and `enable_only` for every interface in this profile.
    ///
    /// MIT `configure_interface` (`lib/krb5/krb/plugin.c:301-347`): a later stage reads one interface from here.
    pub plugins: PluginProfile,
}

/// `[libdefaults] dns_canonicalize_hostname`, MIT's tristate.
/// MIT `krb5_init_context_profile` (`lib/krb5/krb/init_ctx.c:244-248`): a boolean, else `fallback`, and `true` when unset.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CanonHost {
    /// `true`, MIT's default: the name is canonicalized through DNS when it is made.
    #[default]
    True,
    /// `false`: the name is expanded without DNS when it is made.
    False,
    /// `fallback`: the name is kept as given and canonicalized when it is used, first without
    /// DNS, then with it.
    Fallback,
}

/// KDC policy from `kdc.conf`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdcConf {
    /// The KDC's UDP listener list as written (MIT syntax, see [`listen`]): the realm
    /// stanza's `kdc_listen` / `kdc_ports`, else `[kdcdefaults]`'s, else
    /// [`listen::DEFAULT_KDC_PORTLIST`].
    /// MIT `init_realm` (`kdc/main.c:257-263`): `kdc_listen`, then `kdc_ports`, then the default.
    pub kdc_listen: String,
    /// Whether the realm stanza wrote `kdc_listen` / `kdc_ports`, so `krb5kdc -p` does not
    /// replace [`Self::kdc_listen`].
    pub kdc_listen_in_realm: bool,
    /// The KDC's TCP listener list (`kdc_tcp_listen` / `kdc_tcp_ports`, realm then
    /// `[kdcdefaults]`); `None` listens on [`Self::kdc_listen`].
    /// MIT `init_realm` (`kdc/main.c:267-282`): `kdc_tcp_listen`, then `kdc_tcp_ports`.
    pub kdc_tcp_listen: Option<String>,
    /// The realm stanza's `admin_server`, whose port (if written) is kadmind's port.
    pub admin_server: Option<String>,
    /// The realm stanza's `kadmind_listen` list.
    pub kadmind_listen: Option<String>,
    /// The realm stanza's `kadmind_port`.
    pub kadmind_port: Option<u16>,
    /// The realm stanza's `kpasswd_listen` list.
    pub kpasswd_listen: Option<String>,
    /// The realm stanza's `kpasswd_port`.
    pub kpasswd_port: Option<u16>,
    /// Realm name.
    pub realm: String,
    /// Maximum ticket lifetime in seconds (default 1 day, `alt_prof.c`).
    pub max_life: u64,
    /// kadm5 create default for `max_renewable_life`.
    /// MIT `kadm5_get_config_params` (`alt_prof.c:577-578`): an omitted value is 0
    /// (`GET_DELTAT_PARAM(max_rlife, …, 0)`).
    pub max_renewable_life: u64,
    /// KDC realm renewable cap. A written `max_renewable_life` sets this and
    /// [`Self::max_renewable_life`].
    /// MIT `init_realm` (`kdc/main.c:316-319`): `realm_maxrlife`; omitted, it is
    /// `KRB5_KDB_MAX_RLIFE` = 7 days.
    pub realm_max_renewable_life: u64,
    /// Database path.
    pub database_name: Option<PathBuf>,
    /// ACL file.
    pub acl_file: Option<PathBuf>,
    /// Stash file for the master key.
    pub key_stash_file: Option<PathBuf>,
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
    /// `[realms] default_principal_flags` as written (the flagspec list is parsed by the
    /// store). `None` = `KRB5_KDB_DEF_FLAGS` (0).
    /// MIT `kadm5_get_config_params` (`alt_prof.c:596-632`): `KADM5_CONFIG_FLAGS` from the
    /// flagspec list, else `KRB5_KDB_DEF_FLAGS`.
    pub default_principal_flags: Option<String>,
    /// `[realms] default_principal_expiration` as written (the store converts it). `None` = 0.
    /// MIT `kadm5_get_config_params` (`alt_prof.c:580-594`): `KADM5_CONFIG_EXPIRATION`, a
    /// `krb5_string_to_timestamp` form.
    pub default_principal_expiration: Option<String>,
    /// `master_key_type` (MIT name, e.g. `aes256-cts-hmac-sha384-192`).
    pub master_key_type: Option<String>,
    /// `database_module` / `db_library`. Default dump-v7; unknown names error.
    pub db_library: Option<String>,
    /// `disable_last_success` in the realm's `[dbmodules]` section: the KDC records no last
    /// successful authentication.
    /// MIT `get_conf_section` (`lib/kdb/kdb5.c:219-227`): the section is the realm stanza's `database_module`, else the realm name.
    /// MIT `configure_context` (`plugins/kdb/db2/kdb_db2.c:267-271`): `disable_last_success` from that `[dbmodules]` section, default false.
    pub disable_last_success: bool,
    /// `disable_lockout` in the realm's `[dbmodules]` section: the KDC neither counts failed
    /// authentications nor checks the lockout policy.
    /// MIT `configure_context` (`plugins/kdb/db2/kdb_db2.c:273-277`): `disable_lockout` from that `[dbmodules]` section, default false.
    pub disable_lockout: bool,
    /// Optional NT domain SID (`S-1-5-21-…`) for PAC issuance.
    pub domain_sid: Option<String>,
    /// `reject_bad_transit` (default true). When false, a failed transited
    /// check is accepted without `TRANSITED_POLICY_CHECKED`.
    pub reject_bad_transit: bool,
    /// MIT `disable_pac` (default false).
    pub disable_pac: bool,
    /// MIT `restrict_anonymous_to_tgt` (default false).
    pub restrict_anon: bool,
    /// MIT `pkinit_require_freshness` (default false).
    pub pkinit_require_freshness: bool,
    /// MIT `host_based_services` (space/comma-separated).
    pub host_based_services: String,
    /// MIT `no_host_referral` (space/comma-separated).
    pub no_host_referral: String,
    /// `[realms] encrypted_challenge_indicator`.
    pub encrypted_challenge_indicator: Option<String>,
    /// `[realms] pkinit_indicator` (repeatable).
    pub pkinit_indicators: Vec<String>,
    /// `[realms] spake_preauth_indicator` (repeatable).
    pub spake_preauth_indicators: Vec<String>,
    /// `[libdefaults] spake_preauth_groups`, the first one. `None` = omitted.
    pub spake_preauth_groups: Option<Vec<String>>,
    /// `[kdcdefaults] spake_preauth_kdc_challenge`, the first one: the group of an optimistic
    /// SPAKE challenge. `None` = omitted.
    /// MIT `group_init_state` (`groups.c:241-262`): read from `[kdcdefaults]` only, by the KDC.
    pub spake_preauth_kdc_challenge: Option<String>,
    /// `[realms] dict_file` for the `dict` password-quality module.
    /// MIT `kadm5_get_config_params` (`alt_prof.c:486-513`): reads it from the realm stanza
    /// only, never from `[kdcdefaults]`.
    pub dict_file: Option<PathBuf>,
    /// `[logging]` relations, name and value, in file order; read by [`LogSpecs`].
    pub logging: Vec<(String, String)>,
    /// `[kdcdefaults] kdc_max_dgram_reply_size`: a UDP reply longer than this, taken as an
    /// unsigned number, is replaced by `KRB_ERR_RESPONSE_TOO_BIG`.
    /// MIT `initialize_realms` (`kdc/main.c:636-638`): the last value read as `%d`, else `MAX_DGRAM_SIZE`.
    pub kdc_max_dgram_reply_size: i32,
    /// `[kdcdefaults] kdc_tcp_listen_backlog`: the KDC's TCP listeners' `listen` backlog.
    /// MIT `initialize_realms` (`kdc/main.c:639-644`): the last value read as `%d`, else this default.
    /// MIT `DEFAULT_TCP_LISTEN_BACKLOG` (`include/osconf.hin:100-100`): MIT's value is 5; this default is 128 (`docs/mit-deviations.md`).
    pub kdc_tcp_listen_backlog: i32,
    /// This file's `[plugins]` `disable` and `enable_only`.
    ///
    /// MIT `get_profile_var` (`lib/krb5/krb/plugin.c:188-203`): the relations sit under the interface name.
    pub plugins: PluginProfile,
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
pub use hostname::{expand_hostname, expand_hostname_no_dns, local_host_name, this_host};
pub use iprop_params::{DEF_ULOGENTRIES, IpropParams, MISSING_CONF_PARAMS};
pub use kdcconf::{
    KDC_DIR, KdcPaths, default_acl_file, default_kdb_file, default_kdc_profile, default_kpropd_acl,
    default_stash_file, env_kdc_config, kdc_conf_path,
};
pub use logging::LogSpecs;
pub use plugin_profile::{
    PluginProfile, PluginRelations, filter_plugin_modules, kdc_plugin_relations,
};
pub use profile::{
    client_realm_path, discover_kdc, discover_kdc_in, env_ktname, env_new_password, env_password,
    host_to_realm, init_kdc_profile, init_profile, is_numeric_address, krb5_conf_paths,
    load_krb5_conf, load_krb5_conf_paths, parse_deltat, split_krb5_config_paths,
    udp_preference_limit,
};
pub use srv::lookup_srv_kdc;
pub use testenv::{isolate_test_krb5, set_test_kdc_profile, set_test_krb5_paths};
