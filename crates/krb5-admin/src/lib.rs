//! Administration: kadmind (kadm5 over ONC RPC `AUTH_GSSAPI`), kadmin.local,
//! kpasswd (RFC 3244 on 464), kprop / kpropd (dump v7 on 754),
//! iprop (`IPROP_GET_UPDATES` / `FULL_RESYNC`, `krb5-iprop-pull`), and ktutil.
//!
//! The kadmind path enforces the KDC ACL. There is no C FFI.
//!
//! The public surface is the names this root re-exports. `kadm5`, `kprop`,
//! and `listen` stay private.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod kadm5;
mod kprop;
mod listen;

use krb5_crypto::EncryptionType;
use krb5_kdc::{Acl, AdminOp, PrincipalStore, kadmin_flagspec};
use krb5_protocol::{Keytab, ReplayCache, verify_ap_req};
use krb5_types::PrincipalName;
use thiserror::Error;

pub use kadm5::{
    IpropLast, IpropPull, Kadm5RpcSession, RpcCtx, changepw_acceptor, check_auth_gssapi_names,
    check_iprop_rpcsec_auth, check_rpcsec_auth, glob_pattern_ok, iprop_fullresync, iprop_pull,
    kadm5_handle_rpc, serve_kadm5_conn,
};
pub use kprop::{
    IpropPoll, KpropAuth, KpropdConfig, iprop_poll_once, kprop_dump_bytes, kprop_dump_iprop,
    kprop_expired_ap_req, kprop_load_bytes, kprop_send_dump, kprop_send_store,
    kprop_send_store_iprop, kprop_sendauth, kpropd_handle_conn, kpropd_recv_dump, kpropd_recvauth,
    kpropd_send_ack,
};
pub use listen::{
    KADMIND_PORT, KPASSWD_PORT, KPROP_PORT, dispatch_kadmind, encode_kadmind_req,
    encode_kpasswd_req, handle_kpasswd_rfc3244, kpasswd_udp_exchange_to, kprop_recv, kprop_send,
    parse_kpasswd_rep, serve_kpasswd_tcp, serve_kpasswd_udp,
};

/// MIT `kadmin.c:455-536` `princstr` for `kadm5_init`: `-p` / explicit name,
/// else `$USER/admin@REALM`, else the euid's passwd name `/admin@REALM`.
#[must_use]
pub fn kadmin_local_princstr(realm: &str, explicit: Option<&str>) -> String {
    if let Some(p) = explicit.filter(|s| !s.is_empty()) {
        return if p.contains('@') {
            p.to_owned()
        } else {
            format!("{p}@{realm}")
        };
    }
    let user = std::env::var("USER")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(euid_passwd_name)
        .unwrap_or_else(|| "root".into());
    format!("{user}/admin@{realm}")
}

fn euid_passwd_name() -> Option<String> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let uid = status
        .lines()
        .find(|l| l.starts_with("Uid:"))?
        .split_whitespace()
        .nth(1)?;
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let mut parts = line.split(':');
        let name = parts.next()?;
        let _pw = parts.next()?;
        if parts.next()? == uid {
            return Some(name.to_owned());
        }
    }
    None
}

/// Load a kadm5 ACL file. `None` is MIT `kadmin.local` full privs for `actor`.
///
/// The ACL is not a security boundary here: the actor is self-chosen via
/// `-p` / `KRB5_KADMIN_PRINCIPAL`. A set-but-unreadable path is a hard error.
///
/// # Errors
///
/// `path` is set and cannot be read.
pub fn load_acl_file(actor: &str, path: Option<&std::path::Path>) -> Result<Acl, String> {
    match path {
        Some(p) => {
            let t = std::fs::read_to_string(p).map_err(|e| format!("ACL {}: {e}", p.display()))?;
            let realm = actor.rsplit_once('@').map_or("", |(_, r)| r);
            Acl::parse_with_realm(&t, realm).map_err(|e| e.to_string())
        }
        None => Acl::allow_admin(actor).map_err(|e| e.to_string()),
    }
}

/// Parsed `kadmin.local` verb operands (`-randkey` / `-pw` / `+attr`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KadminArgs {
    /// Principal spec (no flags).
    pub name: String,
    /// `-randkey`.
    pub randkey: bool,
    /// `-norandkey` (ktadd).
    pub norandkey: bool,
    /// `-pw`.
    pub pw: Option<String>,
    /// `-policy`.
    pub policy: Option<String>,
    /// `ktadd -k`.
    pub ktpath: Option<String>,
    /// `+attr` bits.
    pub attr_set: u32,
    /// `-attr` bits.
    pub attr_clear: u32,
    /// `addprinc -e` keysalt list.
    pub etypes: Vec<EncryptionType>,
    /// `modprinc -unlock`.
    pub unlock: bool,
    /// `cpw -keepold`.
    pub keepold: bool,
    /// `modprinc -maxlife` seconds.
    pub max_life: Option<u64>,
    /// `modprinc -maxrenewlife` seconds.
    pub max_renewable_life: Option<u64>,
    /// `modprinc -expire` unix timestamp.
    pub expire: Option<u32>,
}

/// Parsed `kadmin.local addpol` operands (`kadmin.c:1600-1689`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyArgs {
    /// Policy name (last argument).
    pub name: String,
    /// `-maxlife`.
    pub pw_max_life: Option<u32>,
    /// `-minlife`.
    pub pw_min_life: Option<u32>,
    /// `-minlength`.
    pub min_length: Option<u32>,
    /// `-minclasses`.
    pub min_classes: Option<u32>,
    /// `-history`.
    pub history: Option<u32>,
    /// `-maxfailure`.
    pub max_fail: Option<u32>,
    /// `-failurecountinterval`.
    pub pw_failcnt_interval: Option<u32>,
    /// `-lockoutduration`.
    pub pw_lockout_duration: Option<u32>,
    /// `-allowedkeysalts` (`kadmin.c:1669`).
    pub allowed_keysalts: Option<String>,
}

/// MIT `kadmin.c:118-138` `strdur`.
#[must_use]
pub fn strdur(duration: i64) -> String {
    let (neg, mut rest) = if duration < 0 {
        (true, duration.saturating_neg())
    } else {
        (false, duration)
    };
    let days = rest / 86_400;
    rest %= 86_400;
    let hours = rest / 3600;
    rest %= 3600;
    let minutes = rest / 60;
    let seconds = rest % 60;
    format!(
        "{}{days} {} {hours:02}:{minutes:02}:{seconds:02}",
        if neg { "-" } else { "" },
        if days == 1 { "day" } else { "days" },
    )
}

/// Parse flags after the verb. Unknown `-foo` / `+foo` is an error.
///
/// # Errors
///
/// Missing principal, missing option value, or unknown flag.
pub fn parse_kadmin_args(parts: &[&str]) -> Result<KadminArgs, String> {
    let mut out = KadminArgs::default();
    let mut rest = Vec::new();
    let mut i = 0;
    while i < parts.len() {
        let p = parts[i];
        match p {
            "-randkey" => out.randkey = true,
            "-keepold" => out.keepold = true,
            "-norandkey" => out.norandkey = true,
            "-unlock" => out.unlock = true,
            "-pw" => {
                i += 1;
                out.pw = Some(
                    parts
                        .get(i)
                        .copied()
                        .ok_or("-pw needs a password")?
                        .to_owned(),
                );
            }
            "-policy" => {
                i += 1;
                out.policy = Some(
                    parts
                        .get(i)
                        .copied()
                        .ok_or("-policy needs a name")?
                        .to_owned(),
                );
            }
            "-k" => {
                i += 1;
                out.ktpath = Some(parts.get(i).copied().ok_or("-k needs a path")?.to_owned());
            }
            "-e" => {
                i += 1;
                let spec = parts.get(i).copied().ok_or("-e needs a keysalt list")?;
                out.etypes = krb5_crypto::parse_keysalt_list(spec);
                if out.etypes.is_empty() {
                    return Err(format!("-e unknown keysalt {spec}"));
                }
            }
            "-maxlife" => {
                i += 1;
                let spec = parts.get(i).copied().ok_or("-maxlife needs a duration")?;
                out.max_life = Some(u64::from(parse_pol_interval(spec)?));
            }
            "-maxrenewlife" => {
                i += 1;
                let spec = parts
                    .get(i)
                    .copied()
                    .ok_or("-maxrenewlife needs a duration")?;
                out.max_renewable_life = Some(u64::from(parse_pol_interval(spec)?));
            }
            "-expire" => {
                i += 1;
                let spec = parts.get(i).copied().ok_or("-expire needs a timestamp")?;
                out.expire = Some(
                    spec.parse()
                        .map_err(|_| format!("Invalid date specification \"{spec}\"."))?,
                );
            }
            s if let Some((set, clear)) = kadmin_flagspec(s) => {
                out.attr_set |= set;
                out.attr_clear |= clear;
            }
            s if s.starts_with('-') || s.starts_with('+') => {
                return Err(format!("unknown flag {s}"));
            }
            other => rest.push(other),
        }
        i += 1;
    }
    match rest.len() {
        0 => return Err("missing principal".into()),
        1 => rest[0].clone_into(&mut out.name),
        _ => return Err("extra argument".into()),
    }
    Ok(out)
}

/// Parse `addpol` flags. Last token is the policy name (`kadmin.c:1600-1695`).
///
/// # Errors
///
/// Missing name, missing option value, or unknown flag.
pub fn parse_policy_args(parts: &[&str]) -> Result<PolicyArgs, String> {
    if parts.is_empty() {
        return Err("addpol <name>".into());
    }
    let mut out = PolicyArgs::default();
    let mut i = 0;
    while i + 1 < parts.len() {
        let p = parts[i];
        let val = parts
            .get(i + 1)
            .copied()
            .ok_or_else(|| format!("{p} needs a value"))?;
        match p {
            "-maxlife" => out.pw_max_life = Some(parse_pol_interval(val)?),
            "-minlife" => out.pw_min_life = Some(parse_pol_interval(val)?),
            "-minlength" => {
                out.min_length = Some(val.parse().map_err(|_| format!("-minlength {val}"))?);
            }
            "-minclasses" => {
                out.min_classes = Some(val.parse().map_err(|_| format!("-minclasses {val}"))?);
            }
            "-history" => {
                out.history = Some(val.parse().map_err(|_| format!("-history {val}"))?);
            }
            "-maxfailure" => {
                out.max_fail = Some(val.parse().map_err(|_| format!("-maxfailure {val}"))?);
            }
            "-failurecountinterval" => {
                out.pw_failcnt_interval = Some(parse_pol_interval(val)?);
            }
            "-lockoutduration" => {
                out.pw_lockout_duration = Some(parse_pol_interval(val)?);
            }
            "-allowedkeysalts" => {
                if val == "-" {
                    out.allowed_keysalts = None;
                } else {
                    out.allowed_keysalts = Some(val.to_owned());
                }
            }
            _ => return Err(format!("unknown flag {p}")),
        }
        i += 2;
    }
    if i != parts.len() - 1 {
        return Err("addpol <name>".into());
    }
    parts[i].clone_into(&mut out.name);
    if out.name.is_empty() || out.name.starts_with('-') {
        return Err("addpol <name>".into());
    }
    Ok(out)
}

fn parse_pol_interval(s: &str) -> Result<u32, String> {
    // MIT parse_interval (kadmin.c:170-195): krb5_string_to_deltat, else getdate.y
    // (natural-language dates are the deferred getdate.y gap). The error text is
    // parse_date's `Invalid date specification "%s".`.
    krb5_types::deltat::parse(s)
        .ok()
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| format!("Invalid date specification \"{s}\"."))
}

/// Admin error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// ACL denied.
    #[error("acl denied")]
    AclDenied,
    /// kpropd `authorized_principal` refused the authenticated peer
    /// (`kpropd.c:540-543` syslog text).
    #[error("Rejected connection from unauthorized principal {0}")]
    KpropUnauthorized(String),
    /// Principal missing.
    #[error("not found")]
    NotFound,
    /// Password rejected by named policy.
    #[error("password policy: {0}")]
    PasswordPolicy(String),
    /// `KADM5_PASS_TOOSOON`.
    #[error("Current password's minimum life has not expired")]
    PassTooSoon {
        /// Unix time when a change is allowed.
        until: u32,
    },
    /// ONC RPC `GARBAGE_ARGS` (`kadm_rpc_svc.c` `svcerr_decode`).
    #[error("rpc garbage args")]
    GarbageArgs,
    /// ONC RPC `PROC_UNAVAIL` (`kadm_rpc_svc.c` `svcerr_noproc`).
    #[error("rpc proc unavail")]
    ProcUnavail,
    /// Wrapped KDC error.
    #[error("{0}")]
    Inner(String),
}

impl From<krb5_kdc::Error> for Error {
    fn from(e: krb5_kdc::Error) -> Self {
        match e {
            krb5_kdc::Error::AclDenied => Self::AclDenied,
            krb5_kdc::Error::NotFound => Self::NotFound,
            krb5_kdc::Error::PasswordPolicy(s) => Self::PasswordPolicy(s),
            krb5_kdc::Error::PassTooSoon { until } => Self::PassTooSoon { until },
            other => Self::Inner(other.to_string()),
        }
    }
}

/// Wire op codes for the kadmind-equivalent framing.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Create principal.
    Create = 1,
    /// Delete principal.
    Delete = 2,
    /// Export keytab (ktadd).
    Ktadd = 3,
    /// Change password (kpasswd / RFC 3244 style).
    Cpw = 4,
    /// Dump (kdb5_util / kprop).
    Dump = 5,
}

/// Authenticated admin session: AP-REQ must succeed and ACL is checked per op.
pub struct AdminSession<'a> {
    store: &'a mut PrincipalStore,
    acl: &'a Acl,
    actor: String,
}

impl<'a> AdminSession<'a> {
    /// Verify `ap_req` with `service_key` and bind `actor` from the authenticator.
    ///
    /// # Errors
    ///
    /// AP-REQ verify or missing cname.
    pub fn from_ap_req(
        store: &'a mut PrincipalStore,
        acl: &'a Acl,
        service_key: &krb5_crypto::ProtocolKey,
        ap_req: &[u8],
        replay: &ReplayCache,
    ) -> Result<Self, Error> {
        let ok =
            verify_ap_req(ap_req, service_key, replay).map_err(|e| Error::Inner(e.to_string()))?;
        let crealm = String::from_utf8_lossy(ok.authenticator.crealm.as_bytes());
        let actor = ok.authenticator.cname.unparse_with_realm(&crealm);
        Ok(Self { store, acl, actor })
    }

    /// Local (kadmin.local) session: actor is trusted as already authenticated.
    #[must_use]
    pub fn local(store: &'a mut PrincipalStore, acl: &'a Acl, actor: impl Into<String>) -> Self {
        Self {
            store,
            acl,
            actor: actor.into(),
        }
    }

    fn reload(&mut self) -> Result<(), Error> {
        self.store.reload_if_stale().map_err(Error::from)
    }

    fn target_id(&self, name: &PrincipalName) -> String {
        name.unparse_with_realm(self.store.realm())
    }

    /// Create a password principal (ACL `add`).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] when the actor is not permitted.
    pub fn create_password(&mut self, name: &PrincipalName, password: &[u8]) -> Result<(), Error> {
        self.create_password_etypes(name, password, &[])
    }

    /// MIT `kadm5_create_principal_3` `passwd_check` (`svr_principal.c:364-373`)
    /// for `addprinc [-policy P] -pw PW`: the named policy's floors (if the
    /// policy exists) and the built-in `dict` / `empty` / `princ` modules run
    /// before the principal is created.
    ///
    /// # Errors
    ///
    /// [`Error::PasswordPolicy`] with the MIT text.
    pub fn check_new_password(
        &mut self,
        name: &PrincipalName,
        policy: Option<&str>,
        password: &[u8],
    ) -> Result<(), Error> {
        self.reload()?;
        self.store
            .check_new_password(name, policy, password)
            .map_err(Error::from)
    }

    /// `addprinc -e`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] when the actor is not permitted.
    pub fn create_password_etypes(
        &mut self,
        name: &PrincipalName,
        password: &[u8],
        etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        self.reload()?;
        self.store
            .create_password_etypes(self.acl, &self.actor, name, password, etypes)
            .map_err(Error::from)
    }

    /// Create a random-key principal (`addprinc -randkey`).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or the name exists.
    pub fn create_randkey(&mut self, name: &PrincipalName) -> Result<(), Error> {
        self.create_randkey_etypes(name, &[])
    }

    /// `addprinc -randkey -e`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or the name exists.
    pub fn create_randkey_etypes(
        &mut self,
        name: &PrincipalName,
        etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        self.reload()?;
        self.store
            .create_host_etypes(self.acl, &self.actor, name, etypes)
            .map_err(Error::from)
    }

    /// `addprinc [-randkey] [-e] [-policy]`: bind the policy before
    /// `apply_keysalt_policy` (`svr_principal.c:444-447`).
    ///
    /// # Errors
    ///
    /// ACL, already exists, or [`krb5_kdc::Error::BadKeysalts`].
    pub fn create_etypes_pol(
        &mut self,
        name: &PrincipalName,
        password: Option<&[u8]>,
        etypes: &[EncryptionType],
        policy: Option<&str>,
    ) -> Result<(), Error> {
        self.reload()?;
        self.store
            .create_etypes_pol(self.acl, &self.actor, name, password, etypes, policy)
            .map_err(Error::from)
    }

    /// Rotate keys (`cpw -randkey` / default `ktadd`).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn chrand(&mut self, name: &PrincipalName) -> Result<(), Error> {
        self.chrand_etypes_keepold(name, &[], false)
    }

    /// `cpw -randkey [-e …] [-keepold]`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn chrand_etypes_keepold(
        &mut self,
        name: &PrincipalName,
        etypes: &[EncryptionType],
        keepold: bool,
    ) -> Result<(), Error> {
        self.reload()?;
        let tid = self.target_id(name);
        self.acl
            .check(&self.actor, AdminOp::ChangePassword, Some(&tid))
            .map_err(Error::from)?;
        self.store
            .chrand_etypes_keepold(name, etypes, u32::from(keepold), &self.actor)
            .map(|_| ())
            .map_err(Error::from)
    }

    /// Stored `attributes` word.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn principal_attributes(&self, name: &PrincipalName) -> Result<u32, Error> {
        Ok(self.store.get_name(name).ok_or(Error::NotFound)?.attributes)
    }

    /// Delete a principal (ACL `delete`).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn delete(&mut self, name: &PrincipalName) -> Result<(), Error> {
        self.reload()?;
        self.store
            .delete(self.acl, &self.actor, name)
            .map_err(Error::from)
    }

    /// Rename (ACL add + delete).
    ///
    /// # Errors
    ///
    /// Denied, missing, or the name exists.
    pub fn rename(&mut self, old: &PrincipalName, new: &PrincipalName) -> Result<(), Error> {
        self.reload()?;
        self.store
            .rename(self.acl, &self.actor, old, new)
            .map_err(Error::from)
    }

    /// `alias` (`kadmin_addalias`): create an alias stub for `target`.
    ///
    /// # Errors
    ///
    /// [`Error`](enum@Error) wrapping `KADM5_ALIAS_REALM` or `KADM5_DUP`.
    pub fn create_alias(
        &mut self,
        alias: &PrincipalName,
        alias_realm: &str,
        target: &PrincipalName,
        target_realm: &str,
    ) -> Result<(), Error> {
        self.reload()?;
        self.store
            .create_alias_in(alias, alias_realm, target, target_realm, &self.actor)
            .map_err(|e| match e {
                // MIT KADM5_DUP text (kadm5_create_alias / kdb_get_entry).
                krb5_kdc::Error::AlreadyExists => {
                    Error::Inner("Principal or policy already exists".into())
                }
                other => Error::from(other),
            })
    }

    /// Over-the-wire ktadd (ACL `e` / extract).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn ktadd(&mut self, name: &PrincipalName) -> Result<Keytab, Error> {
        self.reload()?;
        self.store
            .export_keytab(self.acl, &self.actor, name)
            .map_err(Error::from)
    }

    /// Local `ktadd` / `ktadd -norandkey`: ignore lockdown, rotate then
    /// extract, persist rotation only after `write` succeeds.
    ///
    /// # Errors
    ///
    /// Denied, missing, or the write failed.
    pub fn ktadd_local(
        &mut self,
        name: &PrincipalName,
        rotate: bool,
        write: impl FnOnce(&Keytab) -> Result<(), String>,
    ) -> Result<Keytab, Error> {
        self.reload()?;
        let tid = self.target_id(name);
        self.acl
            .check(&self.actor, AdminOp::Ktadd, Some(&tid))
            .map_err(Error::from)?;
        if rotate {
            self.acl
                .check(&self.actor, AdminOp::ChangePassword, Some(&tid))
                .map_err(Error::from)?;
        }
        self.store
            .ktadd_local_atomic(name, rotate, &self.actor, |kt| {
                write(kt).map_err(krb5_kdc::Error::Crypto)
            })
            .map_err(Error::from)
    }

    /// Change password (kpasswd / RFC 3244).
    ///
    /// The actor may always change their own password. Changing another
    /// principal requires ACL `c` / `*`.
    ///
    /// # Errors
    ///
    /// ACL denied or principal missing.
    pub fn change_password(&mut self, name: &PrincipalName, password: &[u8]) -> Result<(), Error> {
        self.change_password_etypes(name, password, &[])
    }

    /// `cpw -e` / `kadm5_chpass_principal_3` with a v3 `ks_tuple`.
    ///
    /// # Errors
    ///
    /// ACL denied, principal missing, or [`krb5_kdc::Error::BadKeysalts`].
    pub fn change_password_etypes(
        &mut self,
        name: &PrincipalName,
        password: &[u8],
        etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        self.reload()?;
        let store_realm = self.store.realm();
        let self_change =
            krb5_types::principal_from_unparsed(&self.actor, "").is_ok_and(|(actor, arealm)| {
                krb5_types::principal_compare(name, store_realm, &actor, &arealm)
            });
        if self_change {
            self.store.check_min_life(name).map_err(Error::from)?;
        }
        if !self_change {
            let tid = self.target_id(name);
            self.acl
                .check(&self.actor, AdminOp::ChangePassword, Some(&tid))
                .map_err(Error::from)?;
        }
        let realm = self.store.realm().to_owned();
        self.store
            .set_password_etypes_keepold_n_in(name, &realm, password, 0, &self.actor, etypes)
            .map_err(Error::from)
    }

    /// Realm of the bound store.
    #[must_use]
    pub fn realm(&self) -> &str {
        self.store.realm()
    }

    /// `listprincs`.
    #[must_use]
    pub fn list_ids(&self) -> Vec<String> {
        self.store.ids()
    }

    /// `listprincs [glob]` with MIT `glob_to_regexp` semantics (implicit `@*`).
    #[must_use]
    pub fn list_ids_glob(&self, glob: Option<&str>) -> Vec<String> {
        let ids = self.store.ids();
        match glob {
            Some(g) if g != "*" && !g.is_empty() => {
                let pat = crate::kadm5::glob_expand(g, true);
                ids.into_iter()
                    .filter(|id| crate::kadm5::glob_is_match(pat.as_bytes(), id.as_bytes()))
                    .collect()
            }
            _ => ids,
        }
    }

    /// `getprinc` display id.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn get_principal_id(&self, name: &PrincipalName) -> Result<String, Error> {
        let p = self.store.get_name(name).ok_or(Error::NotFound)?;
        Ok(p.id())
    }

    /// The record `getprinc` prints (`kadm5_get_principal`).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn get_principal_record(&self, name: &PrincipalName) -> Result<krb5_kdc::Principal, Error> {
        self.get_principal_record_in(name, self.store.realm())
    }

    /// [`Self::get_principal_record`] for `name@princ_realm`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn get_principal_record_in(
        &self,
        name: &PrincipalName,
        princ_realm: &str,
    ) -> Result<krb5_kdc::Principal, Error> {
        self.store
            .get_in_realm(name, princ_realm)
            .cloned()
            .ok_or(Error::NotFound)
    }

    /// `modprinc` attributes only.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn modify_attributes(
        &mut self,
        name: &PrincipalName,
        attributes: Option<u32>,
    ) -> Result<(), Error> {
        self.reload()?;
        let tid = self.target_id(name);
        self.acl
            .check(&self.actor, AdminOp::Modify, Some(&tid))
            .map_err(Error::from)?;
        let realm = self.store.realm().to_owned();
        self.store
            .apply_admin_fields_in(
                name,
                &realm,
                krb5_kdc::AdminFields {
                    attributes,
                    max_life: None,
                    expiration: None,
                    pw_expire: None,
                    policy: None,
                    clear_policy: false,
                    max_renewable_life: None,
                },
                &self.actor,
            )
            .map_err(Error::from)?;
        if let Some(rs) = self.acl.restrictions(&self.actor, Some(&tid)) {
            self.store
                .impose_acl_restrictions(name, rs)
                .map_err(Error::from)?;
        }
        Ok(())
    }

    /// `modprinc -expire`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn modify_expiration(
        &mut self,
        name: &PrincipalName,
        expiration: u32,
    ) -> Result<(), Error> {
        self.reload()?;
        let tid = self.target_id(name);
        self.acl
            .check(&self.actor, AdminOp::Modify, Some(&tid))
            .map_err(Error::from)?;
        let realm = self.store.realm().to_owned();
        self.store
            .apply_admin_fields_in(
                name,
                &realm,
                krb5_kdc::AdminFields {
                    attributes: None,
                    max_life: None,
                    expiration: Some(expiration),
                    pw_expire: None,
                    policy: None,
                    clear_policy: false,
                    max_renewable_life: None,
                },
                &self.actor,
            )
            .map_err(Error::from)
    }

    /// `modprinc -unlock`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn admin_unlock(&mut self, name: &PrincipalName) -> Result<(), Error> {
        self.reload()?;
        let tid = self.target_id(name);
        self.acl
            .check(&self.actor, AdminOp::Modify, Some(&tid))
            .map_err(Error::from)?;
        let realm = self.store.realm().to_owned();
        self.store
            .admin_unlock_in(name, &realm, &self.actor)
            .map_err(Error::from)
    }

    /// `modprinc -maxlife` / `-maxrenewlife`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn modify_ticket_lives(
        &mut self,
        name: &PrincipalName,
        max_life: Option<u64>,
        max_renewable_life: Option<u64>,
    ) -> Result<(), Error> {
        self.reload()?;
        let tid = self.target_id(name);
        self.acl
            .check(&self.actor, AdminOp::Modify, Some(&tid))
            .map_err(Error::from)?;
        let realm = self.store.realm().to_owned();
        self.store
            .apply_admin_fields_in(
                name,
                &realm,
                krb5_kdc::AdminFields {
                    attributes: None,
                    max_life,
                    expiration: None,
                    pw_expire: None,
                    policy: None,
                    clear_policy: false,
                    max_renewable_life,
                },
                &self.actor,
            )
            .map_err(Error::from)?;
        if let Some(rs) = self.acl.restrictions(&self.actor, Some(&tid)) {
            self.store
                .impose_acl_restrictions(name, rs)
                .map_err(Error::from)?;
        }
        Ok(())
    }

    /// `modprinc -policy`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] or [`Error::NotFound`].
    pub fn set_policy(&mut self, name: &PrincipalName, policy: &str) -> Result<(), Error> {
        self.reload()?;
        let tid = self.target_id(name);
        self.acl
            .check(&self.actor, AdminOp::Modify, Some(&tid))
            .map_err(Error::from)?;
        let realm = self.store.realm().to_owned();
        self.store
            .apply_admin_fields_in(
                name,
                &realm,
                krb5_kdc::AdminFields {
                    attributes: None,
                    max_life: None,
                    expiration: None,
                    pw_expire: None,
                    policy: Some(policy.to_owned()),
                    clear_policy: false,
                    max_renewable_life: None,
                },
                &self.actor,
            )
            .map_err(Error::from)?;
        if let Some(rs) = self.acl.restrictions(&self.actor, Some(&tid)) {
            self.store
                .impose_acl_restrictions(name, rs)
                .map_err(Error::from)?;
        }
        Ok(())
    }

    /// `addpol`.
    pub fn add_policy(&mut self, name: &str) {
        let _ = self.add_policy_ent(&PolicyArgs {
            name: name.to_owned(),
            ..PolicyArgs::default()
        });
    }

    /// `addpol` with MIT CLI flags (`svr_policy.c` floors).
    ///
    /// # Errors
    ///
    /// Explicit values below the MIT floors.
    pub fn add_policy_ent(&mut self, a: &PolicyArgs) -> Result<(), Error> {
        let _ = self.reload();
        let exists = self.store.policies().contains_key(&a.name);
        let pol =
            crate::kadm5::create_policy_local(exists, a).map_err(|t| Error::Inner(t.to_owned()))?;
        self.store.put_policy(pol);
        Ok(())
    }

    /// `modpol` (`svr_policy.c:292-322` on the merged record).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] or a floor/lifetime error.
    pub fn modify_policy_ent(&mut self, a: &PolicyArgs) -> Result<(), Error> {
        let _ = self.reload();
        let existing = self
            .store
            .policies()
            .get(&a.name)
            .cloned()
            .ok_or_else(|| Error::Inner("Policy does not exist".into()))?;
        let pol = crate::kadm5::modify_policy_local(&existing, a)
            .map_err(|t| Error::Inner(t.to_owned()))?;
        self.store.put_policy(pol);
        Ok(())
    }

    /// `delpol`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn delete_policy(&mut self, name: &str) -> Result<(), Error> {
        let _ = self.reload();
        self.store.delete_policy(name).map_err(Error::from)
    }

    /// `listpols`.
    #[must_use]
    pub fn list_policies(&self) -> Vec<String> {
        let mut n: Vec<String> = self.store.policies().keys().cloned().collect();
        n.sort();
        n
    }

    /// `listpols [glob]` with MIT `glob_to_regexp` semantics (no realm append).
    #[must_use]
    pub fn list_policies_glob(&self, glob: Option<&str>) -> Vec<String> {
        let mut n: Vec<String> = match glob {
            Some(g) if g != "*" && !g.is_empty() => {
                let pat = crate::kadm5::glob_expand(g, false);
                self.store
                    .policies()
                    .keys()
                    .filter(|k| crate::kadm5::glob_is_match(pat.as_bytes(), k.as_bytes()))
                    .cloned()
                    .collect()
            }
            _ => self.store.policies().keys().cloned().collect(),
        };
        n.sort();
        n
    }

    /// `getpol` (`kadmin.c:1794-1807` via `strdur`).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn get_policy(&self, name: &str) -> Result<String, Error> {
        let p = self.store.policies().get(name).ok_or(Error::NotFound)?;
        let mut text = format!(
            "Policy: {}\nMaximum password life: {}\nMinimum password life: {}\nMinimum password length: {}\nMinimum number of password character classes: {}\nNumber of old keys kept: {}\nMaximum password failures before lockout: {}\nPassword failure count reset interval: {}\nPassword lockout duration: {}",
            p.name,
            strdur(i64::from(p.pw_max_life)),
            strdur(i64::from(p.pw_min_life)),
            p.min_length,
            p.min_classes,
            p.history,
            p.max_fail,
            strdur(i64::from(p.pw_failcnt_interval)),
            strdur(i64::from(p.pw_lockout_duration)),
        );
        if let Some(ks) = p.allowed_keysalts.as_deref() {
            text.push_str("\nAllowed key/salt types: ");
            text.push_str(ks);
        }
        Ok(text)
    }

    /// `setstr`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn set_string_attr(
        &mut self,
        name: &PrincipalName,
        key: &str,
        val: &str,
    ) -> Result<(), Error> {
        self.reload()?;
        let realm = self.store.realm().to_owned();
        self.store
            .set_string_in(name, &realm, key, Some(val), &self.actor)
            .map_err(Error::from)
    }

    /// `getstrs`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn string_attrs(&self, name: &PrincipalName) -> Result<Vec<(String, String)>, Error> {
        self.store.get_strings(name).map_err(Error::from)
    }
}

/// kprop-equivalent: serialize the store (dump) and load on a replica.
///
/// # Errors
///
/// Write failed, or a key was refused.
pub fn propagate(
    store: &PrincipalStore,
    db_path: &std::path::Path,
    stash_path: &std::path::Path,
) -> Result<(), krb5_kdc::PersistError> {
    krb5_kdc::save_store(store, db_path, stash_path)
}

/// Load a propagated dump.
///
/// # Errors
///
/// Read failed, or the dump was refused.
pub fn receive_propagate(
    db_path: &std::path::Path,
    stash_path: &std::path::Path,
) -> Result<PrincipalStore, krb5_kdc::PersistError> {
    krb5_kdc::load_store(db_path, stash_path)
}

#[cfg(test)]
mod tests {

    use super::*;

    use krb5_kdc::testrealm::{bootstrap_documented, documented_admin_id};
    use krb5_kdc::{KDB_LOCKDOWN_KEYS, KDB_OK_TO_AUTH_AS_DELEGATE, KDB_REQUIRES_PRE_AUTH};

    #[test]
    fn parse_kadmin_args_flags() {
        let a = parse_kadmin_args(&["-randkey", "svc"]).unwrap();
        assert!(a.randkey);
        assert_eq!(a.name, "svc");
        let a = parse_kadmin_args(&["+requires_preauth", "user"]).unwrap();
        assert_eq!(a.attr_set, KDB_REQUIRES_PRE_AUTH);
        assert_eq!(a.name, "user");
        assert!(parse_kadmin_args(&["-bogus", "user"]).is_err());
        assert!(parse_kadmin_args(&["-randkey"]).is_err());
        let a = parse_kadmin_args(&["-k", "/tmp/x.keytab", "-norandkey", "host/x"]).unwrap();
        assert_eq!(a.ktpath.as_deref(), Some("/tmp/x.keytab"));
        assert!(a.norandkey);
        assert_eq!(a.name, "host/x");
        let a = parse_kadmin_args(&["+lockdown_keys", "lockee"]).unwrap();
        assert_eq!(a.attr_set, KDB_LOCKDOWN_KEYS);
        let a = parse_kadmin_args(&["+ok_to_auth_as_delegate", "host/x"]).unwrap();
        assert_eq!(a.attr_set, KDB_OK_TO_AUTH_AS_DELEGATE);
        let a = parse_kadmin_args(&["-e", "rc4-hmac:normal", "-pw", "x", "rc4user"]).unwrap();
        assert_eq!(a.etypes, vec![EncryptionType::Rc4Hmac]);
        assert_eq!(a.name, "rc4user");
        let a = parse_kadmin_args(&["-unlock", "locked"]).unwrap();
        assert!(a.unlock);
        let a = parse_kadmin_args(&["-maxrenewlife", "1d", "user"]).unwrap();
        assert_eq!(a.max_renewable_life, Some(86_400));
        let a = parse_kadmin_args(&["-maxlife", "2h", "user"]).unwrap();
        assert_eq!(a.max_life, Some(7_200));
        let a = parse_kadmin_args(&[
            "-randkey",
            "-keepold",
            "-e",
            "aes128-cts-hmac-sha1-96:normal",
            "krbtgt/KERBER.TEST",
        ])
        .unwrap();
        assert!(a.randkey && a.keepold);
        assert_eq!(a.etypes, vec![EncryptionType::Aes128CtsHmacSha196]);
        let a = parse_kadmin_args(&["+0x1ffffffff", "wide"]).unwrap();
        assert_eq!(a.attr_set, 0xffff_ffff);
        assert_eq!(a.name, "wide");
        let a = parse_kadmin_args(&["-allow_renewable", "user"]).unwrap();
        assert_eq!(a.attr_set, krb5_kdc::KDB_DISALLOW_RENEWABLE);
        let a = parse_kadmin_args(&["+allow_renewable", "user"]).unwrap();
        assert_eq!(a.attr_clear, krb5_kdc::KDB_DISALLOW_RENEWABLE);
        let a = parse_kadmin_args(&["-expire", "1", "expiredsvc"]).unwrap();
        assert_eq!(a.expire, Some(1));
    }

    #[test]
    fn parse_policy_args_and_strdur() {
        let a = parse_policy_args(&["-minlength", "8", "-minclasses", "2", "-history", "3", "p1"])
            .unwrap();
        assert_eq!(a.name, "p1");
        assert_eq!(a.min_length, Some(8));
        assert_eq!(a.min_classes, Some(2));
        assert_eq!(a.history, Some(3));
        let a = parse_policy_args(&["-maxlife", "1d", "-minlife", "1h", "life"]).unwrap();
        assert_eq!(a.pw_max_life, Some(86_400));
        assert_eq!(a.pw_min_life, Some(3600));
        assert_eq!(strdur(0), "0 days 00:00:00");
        assert_eq!(strdur(3600), "0 days 01:00:00");
        assert_eq!(strdur(86_400), "1 day 00:00:00");
        assert!(parse_policy_args(&["-bogus", "x", "p"]).is_err());
        assert!(parse_policy_args(&[]).is_err());
    }

    #[test]
    fn addpol_floors_and_getpol_layout() {
        let (mut store, acl) = bootstrap_documented().unwrap();
        let mut sess = AdminSession::local(&mut store, &acl, documented_admin_id());
        sess.add_policy("floors");
        let text = sess.get_policy("floors").unwrap();
        assert!(text.starts_with("Policy: floors\n"), "{text}");
        assert!(!text.contains("Policy: Policy:"), "{text}");
        assert!(text.contains("Minimum password length: 1"), "{text}");
        assert!(
            text.contains("Minimum number of password character classes: 1"),
            "{text}"
        );
        assert!(text.contains("Number of old keys kept: 1"), "{text}");
        assert!(
            text.contains("Maximum password life: 0 days 00:00:00"),
            "{text}"
        );
        assert!(
            sess.add_policy_ent(&parse_policy_args(&["-history", "0", "z"]).unwrap())
                .is_err()
        );
        assert!(
            !text.contains("Allowed key/salt types:"),
            "MIT omits the line when allowed_keysalts is NULL: {text}"
        );
        sess.add_policy_ent(
            &parse_policy_args(&["-allowedkeysalts", "aes256-cts:normal", "ksalt"]).unwrap(),
        )
        .unwrap();
        let ks = sess.get_policy("ksalt").unwrap();
        assert!(
            ks.contains("Allowed key/salt types: aes256-cts:normal"),
            "{ks}"
        );
    }

    #[test]
    fn kadmin_local_princstr_canonicalizes_explicit_like_parse_name() {
        assert_eq!(
            kadmin_local_princstr("KERBER.TEST", Some("admin/admin")),
            "admin/admin@KERBER.TEST"
        );
        assert_eq!(
            kadmin_local_princstr("KERBER.TEST", Some("joe/admin@OTHER.TEST")),
            "joe/admin@OTHER.TEST"
        );
    }
}
