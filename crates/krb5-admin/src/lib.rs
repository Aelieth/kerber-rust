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

mod getdate;
mod kadm5;
mod kadmin_cli;
mod kprop;
mod listen;

use krb5_crypto::EncryptionType;
use krb5_kdc::{Acl, AdminOp, PrincipalStore};
use krb5_protocol::{Keytab, ReplayCache, verify_ap_req};
use krb5_types::PrincipalName;
use thiserror::Error;

pub use getdate::{DateError, get_date_rel, parse_date, parse_interval};
pub use kadm5::{
    IpropLast, IpropPull, Kadm5RpcError, Kadm5RpcSession, RpcCtx, changepw_acceptor,
    check_auth_gssapi_names, check_iprop_rpcsec_auth, check_rpcsec_auth, glob_pattern_ok,
    iprop_fullresync, iprop_pull, kadm5_handle_rpc, serve_kadm5_conn,
};
pub use kadmin_cli::kadmin_local_main;
pub use kprop::{
    IpropPoll, KpropAuth, KpropdConfig, iprop_poll_once, is_iprop_dump, kprop_dump_bytes,
    kprop_dump_iprop, kprop_expired_ap_req, kprop_load_bytes, kprop_load_with_stash,
    kprop_send_dump, kprop_send_store, kprop_send_store_iprop, kprop_sendauth, kpropd_handle_conn,
    kpropd_recv_dump, kpropd_recvauth, kpropd_send_ack,
};
pub use listen::{
    KADMIND_PORT, KPASSWD_PORT, KPROP_PORT, dispatch_kadmind, encode_kadmind_req,
    encode_kpasswd_req, handle_kpasswd_rfc3244, kpasswd_udp_exchange_to, kprop_recv, kprop_send,
    parse_kpasswd_rep, serve_kpasswd_tcp, serve_kpasswd_udp,
};

/// Load a kadm5 ACL file. `None` is MIT `kadmin.local` full privs for `actor`.
///
/// The ACL is not a security boundary here: the actor is self-chosen via
/// `-p`. A set-but-unreadable path is a hard error.
///
/// # Errors
///
/// The message when `path` is set and cannot be read or does not parse as a kadm5.acl (a
/// syntax error, an unknown op letter, or a bad restriction); with no `path`, when `actor` is
/// not a principal name.
pub fn load_acl_file(actor: &str, path: Option<&std::path::Path>) -> Result<Acl, String> {
    match path {
        Some(p) => {
            let bytes = std::fs::read(p).map_err(|e| format!("ACL {}: {e}", p.display()))?;
            let realm = actor.rsplit_once('@').map_or("", |(_, r)| r);
            Acl::parse_bytes_with_realm(&bytes, realm).map_err(|e| e.to_string())
        }
        None => Acl::allow_admin(actor).map_err(|e| e.to_string()),
    }
}

/// Parsed `kadmin.local addpol` operands.
/// MIT `kadmin_parse_policy_args` (`kadmin.c:1600-1689`): the flags and the policy name MIT's
/// `addpol` parses.
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
    /// `-allowedkeysalts`.
    /// MIT `kadmin_parse_policy_args` (`kadmin.c:1669-1669`): `addpol` and `modpol` take the
    /// `-allowedkeysalts` flag.
    pub allowed_keysalts: Option<String>,
}

/// MIT `strdur` (`kadmin.c:118-138`): formats a duration as `kadmin` prints it.
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

/// Parse `addpol` flags. Last token is the policy name.
/// MIT `kadmin_parse_policy_args` (`kadmin.c:1600-1695`): the flags run up to the last
/// argument, which is the policy name.
///
/// # Errors
///
/// A message when no policy name is left after the flag/value pairs (`addpol <name>`: no
/// arguments, an even token count, or a last token that is empty or starts with `-`), a flag
/// is unknown, an interval does not parse (`Invalid date specification`), or a `-minlength`,
/// `-minclasses`, `-history`, or `-maxfailure` value is not an unsigned integer.
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
    getdate::parse_interval(s, getdate::now())
        .map(getdate::low32)
        .map_err(|e| e.to_string())
}

/// Admin error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// ACL denied.
    #[error("acl denied")]
    AclDenied,
    /// kpropd `authorized_principal` refused the authenticated peer (MIT's syslog text).
    /// MIT `doit` (`kpropd.c:540-543`): a refused peer is logged to syslog as
    /// `Rejected connection from unauthorized principal %s`.
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
    /// [`Error::Inner`] carrying the `verify_ap_req` text when `ap_req` does not verify under
    /// `service_key` (truncated, a bad checksum, a replay, clock skew, or an expired ticket).
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

    /// `f` as one change to the database under its exclusive lock, from a fresh read to one
    /// write ([`PrincipalStore::change`]), with the session's ACL and actor.
    fn change<T>(
        &mut self,
        f: impl FnOnce(&mut PrincipalStore, &Acl, &str) -> Result<T, krb5_kdc::Error>,
    ) -> Result<T, krb5_kdc::Error> {
        let (acl, actor) = (self.acl, self.actor.as_str());
        self.store
            .change(|s| f(s, acl, actor))
            .and_then(|done| done)
    }

    fn target_id(&self, name: &PrincipalName) -> String {
        name.unparse_with_realm(self.store.realm())
    }

    /// Create a password principal (ACL `add`).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] when the actor lacks ACL `a` on `name`; [`Error::PasswordPolicy`]
    /// when `password` is empty; [`Error::Inner`] when `name` exists or the store cannot be
    /// reloaded or saved.
    pub fn create_password(&mut self, name: &PrincipalName, password: &[u8]) -> Result<(), Error> {
        self.create_password_etypes(name, password, &[])
    }

    /// MIT `kadm5_create_principal_3` `passwd_check` for `addprinc [-policy P] -pw PW`: the
    /// named policy's floors (if the policy exists) and the built-in `dict` / `empty` /
    /// `princ` modules run before the principal is created.
    /// MIT `kadm5_create_principal_3` (`svr_principal.c:364-373`): the policy is loaded, then
    /// `passwd_check` runs, before the entry exists.
    ///
    /// # Errors
    ///
    /// [`Error::PasswordPolicy`] when `password` fails the policy's length or class floor or a
    /// quality module (`dict`, `empty`, `princ`); [`Error::Inner`] when the store cannot be
    /// reloaded.
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
    /// [`Error::AclDenied`] when the actor lacks ACL `a` on `name`; [`Error::PasswordPolicy`]
    /// when `password` is empty; [`Error::Inner`] when `name` exists or the store cannot be
    /// reloaded or saved.
    pub fn create_password_etypes(
        &mut self,
        name: &PrincipalName,
        password: &[u8],
        etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        self.reload()?;
        self.change(|s, acl, actor| s.create_password_etypes(acl, actor, name, password, etypes))
            .map_err(Error::from)
    }

    /// Create a random-key principal (`addprinc -randkey`).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] when the actor lacks ACL `a` on `name`; [`Error::Inner`] when `name`
    /// exists, a random key cannot be drawn, or the store cannot be reloaded or saved.
    pub fn create_randkey(&mut self, name: &PrincipalName) -> Result<(), Error> {
        self.create_randkey_etypes(name, &[])
    }

    /// `addprinc -randkey -e`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] when the actor lacks ACL `a` on `name`; [`Error::Inner`] when `name`
    /// exists, a random key cannot be drawn, or the store cannot be reloaded or saved.
    pub fn create_randkey_etypes(
        &mut self,
        name: &PrincipalName,
        etypes: &[EncryptionType],
    ) -> Result<(), Error> {
        self.reload()?;
        self.change(|s, acl, actor| s.create_host_etypes(acl, actor, name, etypes))
            .map_err(Error::from)
    }

    /// `addprinc [-randkey] [-e] [-policy]`: bind the policy before
    /// `apply_keysalt_policy`.
    /// MIT `kadm5_create_principal_3` (`svr_principal.c:444-447`): `apply_keysalt_policy` runs
    /// with the entry's policy.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] when the actor lacks ACL `a` on `name`; [`Error::PasswordPolicy`]
    /// when `password` fails the named policy's floors or a quality module; [`Error::Inner`]
    /// carrying [`krb5_kdc::Error::BadKeysalts`] when `etypes` is outside the policy's
    /// `allowed_keysalts`, or when `name` exists, a random key cannot be drawn, or the store
    /// cannot be reloaded or saved.
    pub fn create_etypes_pol(
        &mut self,
        name: &PrincipalName,
        password: Option<&[u8]>,
        etypes: &[EncryptionType],
        policy: Option<&str>,
    ) -> Result<(), Error> {
        self.reload()?;
        self.change(|s, acl, actor| s.create_etypes_pol(acl, actor, name, password, etypes, policy))
            .map_err(Error::from)
    }

    /// Rotate keys (`cpw -randkey` / default `ktadd`).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] when the actor lacks ACL `c` on `name`; [`Error::NotFound`] when
    /// `name` is not in the store; [`Error::Inner`] when a random key cannot be drawn or the
    /// store cannot be reloaded or saved.
    pub fn chrand(&mut self, name: &PrincipalName) -> Result<(), Error> {
        self.chrand_etypes_keepold(name, &[], false)
    }

    /// `cpw -randkey [-e …] [-keepold]`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] when the actor lacks ACL `c` on `name`; [`Error::NotFound`] when
    /// `name` is not in the store; [`Error::Inner`] carrying [`krb5_kdc::Error::BadKeysalts`]
    /// when `etypes` is outside the policy's `allowed_keysalts`, or when a random key cannot be
    /// drawn or the store cannot be reloaded or saved.
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
        self.change(|s, _, actor| s.chrand_etypes_keepold(name, etypes, u32::from(keepold), actor))
            .map(|_| ())
            .map_err(Error::from)
    }

    /// Stored `attributes` word.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when `name` is not in the store.
    pub fn principal_attributes(&self, name: &PrincipalName) -> Result<u32, Error> {
        Ok(self.store.get_name(name).ok_or(Error::NotFound)?.attributes)
    }

    /// Delete a principal (ACL `delete`).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] when the actor lacks ACL `d` on `name`; [`Error::NotFound`] when
    /// `name` is not in the store; [`Error::Inner`] when the store cannot be reloaded or saved.
    pub fn delete(&mut self, name: &PrincipalName) -> Result<(), Error> {
        self.reload()?;
        self.change(|s, acl, actor| s.delete(acl, actor, name))
            .map_err(Error::from)
    }

    /// Rename (ACL add + delete).
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] when the actor lacks ACL `d` on `old` or unrestricted `a` on `new`;
    /// [`Error::NotFound`] when `old` is not in the store; [`Error::Inner`] when `new` exists,
    /// `old` is an alias stub, or the store cannot be reloaded or saved.
    pub fn rename(&mut self, old: &PrincipalName, new: &PrincipalName) -> Result<(), Error> {
        self.reload()?;
        self.change(|s, acl, actor| s.rename(acl, actor, old, new))
            .map_err(Error::from)
    }

    /// `alias` (`kadmin_addalias`): create an alias stub for `target`.
    ///
    /// # Errors
    ///
    /// [`Error::Inner`] with the `KADM5_ALIAS_REALM` text when `alias_realm` is not
    /// `target_realm`, the `KADM5_DUP` text when `alias` already exists, or the failure's text
    /// when the store cannot be reloaded or saved.
    pub fn create_alias(
        &mut self,
        alias: &PrincipalName,
        alias_realm: &str,
        target: &PrincipalName,
        target_realm: &str,
    ) -> Result<(), Error> {
        self.reload()?;
        self.change(|s, _, actor| {
            s.create_alias_in(alias, alias_realm, target, target_realm, actor)
        })
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
    /// [`Error::AclDenied`] when the actor lacks ACL `e` on `name` or `name` has
    /// `LOCKDOWN_KEYS`; [`Error::NotFound`] when `name` is missing or keyless; [`Error::Inner`]
    /// when the store cannot be reloaded or the realm is not ASCII.
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
    /// [`Error::AclDenied`] when the actor lacks ACL `e` on `name`, or `c` when `rotate`;
    /// [`Error::NotFound`] when `name` is missing or keyless; [`Error::Inner`] carrying `write`'s
    /// message when it fails, or when the rotation cannot draw a key or save, the realm is not
    /// ASCII, or the store cannot be reloaded.
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
    /// [`Error::AclDenied`] when changing another principal without ACL `c` on `name`;
    /// [`Error::NotFound`] when `name` is missing; [`Error::PassTooSoon`] for a self-change inside
    /// `pw_min_life`; [`Error::PasswordPolicy`] when `password` fails the policy floors, a quality
    /// module, or the history; [`Error::Inner`] when the history key or entry cannot be made or
    /// the store cannot be reloaded or saved.
    pub fn change_password(&mut self, name: &PrincipalName, password: &[u8]) -> Result<(), Error> {
        self.change_password_etypes(name, password, &[])
    }

    /// `cpw -e` / `kadm5_chpass_principal_3` with a v3 `ks_tuple`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] when changing another principal without ACL `c` on `name`;
    /// [`Error::NotFound`] when `name` is missing; [`Error::PassTooSoon`] for a self-change inside
    /// `pw_min_life`; [`Error::PasswordPolicy`] when `password` fails the policy floors, a quality
    /// module, or the history; [`Error::Inner`] carrying [`krb5_kdc::Error::BadKeysalts`] when
    /// `etypes` is outside `allowed_keysalts`, or when the history key or entry cannot be made or
    /// the store cannot be reloaded or saved.
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
        self.change(|s, _, actor| {
            s.set_password_etypes_keepold_n_in(name, &realm, password, 0, actor, etypes)
        })
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

    /// `listprincs [glob]` with MIT `glob_to_regexp` semantics (implicit `@*`); an empty
    /// expression lists nothing, as `^@.*$` matches no principal name.
    #[must_use]
    pub fn list_ids_glob(&self, glob: Option<&str>) -> Vec<String> {
        crate::kadm5::principals_matching(self.store, glob)
    }

    /// `getprinc` display id.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when `name` is not in the store.
    pub fn get_principal_id(&self, name: &PrincipalName) -> Result<String, Error> {
        let p = self.store.get_name(name).ok_or(Error::NotFound)?;
        Ok(p.id())
    }

    /// The record `getprinc` prints (`kadm5_get_principal`).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when `name` is not in the store.
    pub fn get_principal_record(&self, name: &PrincipalName) -> Result<krb5_kdc::Principal, Error> {
        self.get_principal_record_in(name, self.store.realm())
    }

    /// [`Self::get_principal_record`] for `name@princ_realm`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when `name@princ_realm` is not in the store.
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
    /// [`Error::AclDenied`] when the actor lacks ACL `m` on `name`; [`Error::NotFound`] when
    /// `name` is not in the store; [`Error::Inner`] when the store cannot be reloaded or saved.
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
        let acl = self.acl;
        let restrictions = acl.restrictions(&self.actor, Some(&tid));
        // MIT `kadm5_modify_principal` (`lib/kadm5/srv/svr_principal.c:601-689`): the fields are set on the entry, then one put writes it.
        self.change(|s, _, actor| {
            s.apply_admin_fields_in(
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
                actor,
            )?;
            if let Some(rs) = restrictions {
                s.impose_acl_restrictions(name, rs)?;
            }
            Ok(())
        })
        .map_err(Error::from)
    }

    /// `modprinc -expire`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] when the actor lacks ACL `m` on `name`; [`Error::NotFound`] when
    /// `name` is not in the store; [`Error::Inner`] when the store cannot be reloaded or saved.
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
        self.change(|s, _, actor| {
            s.apply_admin_fields_in(
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
                actor,
            )
        })
        .map_err(Error::from)
    }

    /// `modprinc -unlock`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] when the actor lacks ACL `m` on `name`; [`Error::NotFound`] when
    /// `name` is not in the store; [`Error::Inner`] when the store cannot be reloaded or saved.
    pub fn admin_unlock(&mut self, name: &PrincipalName) -> Result<(), Error> {
        self.reload()?;
        let tid = self.target_id(name);
        self.acl
            .check(&self.actor, AdminOp::Modify, Some(&tid))
            .map_err(Error::from)?;
        let realm = self.store.realm().to_owned();
        self.change(|s, _, actor| s.admin_unlock_in(name, &realm, actor))
            .map_err(Error::from)
    }

    /// `modprinc -maxlife` / `-maxrenewlife`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] when the actor lacks ACL `m` on `name`; [`Error::NotFound`] when
    /// `name` is not in the store; [`Error::Inner`] when the store cannot be reloaded or saved.
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
        let acl = self.acl;
        let restrictions = acl.restrictions(&self.actor, Some(&tid));
        // MIT `kadm5_modify_principal` (`lib/kadm5/srv/svr_principal.c:601-689`): the fields are set on the entry, then one put writes it.
        self.change(|s, _, actor| {
            s.apply_admin_fields_in(
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
                actor,
            )?;
            if let Some(rs) = restrictions {
                s.impose_acl_restrictions(name, rs)?;
            }
            Ok(())
        })
        .map_err(Error::from)
    }

    /// `modprinc -policy`.
    ///
    /// # Errors
    ///
    /// [`Error::AclDenied`] when the actor lacks ACL `m` on `name`; [`Error::NotFound`] when
    /// `name` is not in the store; [`Error::Inner`] when the store cannot be reloaded or saved.
    pub fn set_policy(&mut self, name: &PrincipalName, policy: &str) -> Result<(), Error> {
        self.reload()?;
        let tid = self.target_id(name);
        self.acl
            .check(&self.actor, AdminOp::Modify, Some(&tid))
            .map_err(Error::from)?;
        let realm = self.store.realm().to_owned();
        let acl = self.acl;
        let restrictions = acl.restrictions(&self.actor, Some(&tid));
        // MIT `kadm5_modify_principal` (`lib/kadm5/srv/svr_principal.c:601-689`): the fields are set on the entry, then one put writes it.
        self.change(|s, _, actor| {
            s.apply_admin_fields_in(
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
                actor,
            )?;
            if let Some(rs) = restrictions {
                s.impose_acl_restrictions(name, rs)?;
            }
            Ok(())
        })
        .map_err(Error::from)
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
    /// [`Error::Inner`] with the MIT text of `KADM5_BAD_KEYSALTS` (a tab in `-allowedkeysalts`),
    /// `KADM5_DUP` (the policy exists), `KADM5_BAD_POLICY` (an empty or non-printable name), or
    /// `KADM5_BAD_MIN_PASS_LIFE`, `KADM5_BAD_LENGTH`, `KADM5_BAD_CLASS`, or `KADM5_BAD_HISTORY`
    /// (an explicit value outside MIT's bounds), or when the store cannot be saved.
    pub fn add_policy_ent(&mut self, a: &PolicyArgs) -> Result<(), Error> {
        let _ = self.reload();
        let exists = self.store.policies().contains_key(&a.name);
        let pol =
            crate::kadm5::create_policy_local(exists, a).map_err(|t| Error::Inner(t.to_owned()))?;
        self.change(|s, _, _| s.put_policy_and_save(pol))
            .map_err(Error::from)
    }

    /// `modpol` on the merged record.
    /// MIT `kadm5_modify_policy` (`svr_policy.c:292-322`): each masked field is merged into the
    /// stored record, and the min-life check reads the merged max life.
    ///
    /// # Errors
    ///
    /// [`Error::Inner`] `Policy does not exist` when no policy is named `a.name`, or with the MIT
    /// text of `KADM5_BAD_KEYSALTS` (a tab in `-allowedkeysalts`) or `KADM5_BAD_MIN_PASS_LIFE`,
    /// `KADM5_BAD_LENGTH`, `KADM5_BAD_CLASS`, or `KADM5_BAD_HISTORY` (a merged value outside
    /// MIT's bounds), or when the store cannot be saved.
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
        self.change(|s, _, _| s.put_policy_and_save(pol))
            .map_err(Error::from)
    }

    /// `delpol`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when no policy is named `name`; [`Error::Inner`] when the store cannot
    /// be saved.
    pub fn delete_policy(&mut self, name: &str) -> Result<(), Error> {
        let _ = self.reload();
        self.change(|s, _, _| s.delete_policy(name))
            .map_err(Error::from)
    }

    /// `listpols`.
    #[must_use]
    pub fn list_policies(&self) -> Vec<String> {
        let mut n: Vec<String> = self.store.policies().keys().cloned().collect();
        n.sort();
        n
    }

    /// `listpols [glob]` with MIT `glob_to_regexp` semantics (no realm append); an empty
    /// expression lists nothing, as `^$` matches no policy name.
    #[must_use]
    pub fn list_policies_glob(&self, glob: Option<&str>) -> Vec<String> {
        crate::kadm5::policies_matching(self.store, glob)
    }

    /// `getpol`, durations via `strdur`.
    /// MIT `kadmin_getpol` (`kadmin.c:1794-1807`): prints the policy fields, the lifetimes and
    /// intervals via `strdur`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when no policy is named `name`.
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
    /// [`Error::NotFound`] when `name` is not in the store; [`Error::Inner`] when the store
    /// cannot be reloaded or saved.
    pub fn set_string_attr(
        &mut self,
        name: &PrincipalName,
        key: &str,
        val: &str,
    ) -> Result<(), Error> {
        self.reload()?;
        let realm = self.store.realm().to_owned();
        self.change(|s, _, actor| s.set_string_in(name, &realm, key, Some(val), actor))
            .map_err(Error::from)
    }

    /// `getstrs`.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] when `name` is not in the store.
    pub fn string_attrs(&self, name: &PrincipalName) -> Result<Vec<(String, String)>, Error> {
        self.store.get_strings(name).map_err(Error::from)
    }
}

/// kprop-equivalent: serialize the store (dump) and load on a replica.
///
/// # Errors
///
/// [`krb5_kdc::PersistError::Io`] when the stash, dump, or `.ulog` file cannot be read or
/// written; [`krb5_kdc::PersistError::Crypto`] when an existing stash is not a usable master
/// key, a new master key cannot be derived or drawn, or a key cannot be wrapped;
/// [`krb5_kdc::PersistError::Format`] when a stash is written for a non-ASCII realm.
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
/// [`krb5_kdc::PersistError::Io`] when the stash or database cannot be read;
/// [`krb5_kdc::PersistError::Format`] when the database is neither UTF-8 dump text nor a sound
/// KDB1/KDB2/KDB3 blob, or its `.ulog` is malformed; [`krb5_kdc::PersistError::Crypto`] when
/// the stash key does not load the dump or the legacy blob.
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
}
