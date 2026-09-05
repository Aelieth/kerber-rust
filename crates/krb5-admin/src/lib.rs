//! Administration: kadmind, kadmin.local, kdb5_util, kpasswd, kprop.
//!
//! The kadmind path enforces the KDC ACL. There is no C FFI.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod kadm5;
mod kprop;
mod listen;

use krb5_crypto::EncryptionType;
use krb5_kdc::{
    Acl, AdminOp, KDB_LOCKDOWN_KEYS, KDB_OK_TO_AUTH_AS_DELEGATE, KDB_REQUIRES_PRE_AUTH,
    NamedPolicy, PrincipalStore,
};
use krb5_protocol::{Keytab, ReplayCache, verify_ap_req};
use krb5_types::PrincipalName;
use thiserror::Error;

pub use kadm5::{IpropPull, iprop_fullresync, iprop_pull, serve_kadm5_conn};
pub use kprop::{
    IpropPoll, KpropAuth, iprop_poll_once, kprop_dump_bytes, kprop_dump_iprop,
    kprop_expired_ap_req, kprop_load_bytes, kprop_send_dump, kprop_send_store,
    kprop_send_store_iprop, kprop_sendauth, kpropd_handle_conn, kpropd_recv_dump, kpropd_recvauth,
    kpropd_send_ack,
};
pub use listen::{
    KADMIND_PORT, KPASSWD_PORT, KPROP_PORT, dispatch_kadmind, encode_kadmind_req,
    encode_kpasswd_req, handle_kpasswd_rfc3244, kpasswd_udp_exchange_to, kprop_recv, kprop_send,
    parse_kpasswd_rep, serve_kpasswd_tcp, serve_kpasswd_udp,
};

/// Load a kadm5 ACL file. `None` is MIT `kadmin.local` full privs for `actor`.
///
/// The ACL is not a security boundary here: the actor is self-chosen via
/// `KRB5_KADMIN_PRINCIPAL`. A set-but-unreadable path is a hard error.
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

/// MIT `str_conv.c:147-152`: `strtoul(s, NULL, 16) & 0xffffffff`.
fn hex_flag32(hex: &str) -> u32 {
    let digits: String = hex.chars().take_while(char::is_ascii_hexdigit).collect();
    let v = u64::from_str_radix(&digits, 16).unwrap_or(0);
    u32::try_from(v & 0xffff_ffff).unwrap_or(0)
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

/// MIT `+requires_preauth` (and the matching `-requires_preauth` clear).
#[must_use]
pub fn kadmin_attr_bit(name: &str) -> Option<u32> {
    match name {
        "requires_preauth" => Some(KDB_REQUIRES_PRE_AUTH),
        "lockdown_keys" => Some(KDB_LOCKDOWN_KEYS),
        "ok_to_auth_as_delegate" => Some(KDB_OK_TO_AUTH_AS_DELEGATE),
        _ => None,
    }
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
            "-norandkey" => out.norandkey = true,
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
            s if s.starts_with('+') => {
                if let Some(hex) = s[1..].strip_prefix("0x") {
                    out.attr_set |= hex_flag32(hex);
                } else {
                    let bit =
                        kadmin_attr_bit(&s[1..]).ok_or_else(|| format!("unknown flag {s}"))?;
                    out.attr_set |= bit;
                }
            }
            s if let Some(hex) = s.strip_prefix("-0x") => {
                out.attr_clear |= hex_flag32(hex);
            }
            s if let Some(bit) = s.strip_prefix('-').and_then(kadmin_attr_bit) => {
                out.attr_clear |= bit;
            }
            s if s.starts_with('-') => return Err(format!("unknown flag {s}")),
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
                if val.contains('\t') || krb5_crypto::parse_keysalt_list(val).is_empty() {
                    return Err(format!("-allowedkeysalts {val}"));
                }
                out.allowed_keysalts = Some(val.to_owned());
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
    let v = krb5_types::deltat::parse(s).map_err(|_| format!("interval {s}"))?;
    u32::try_from(v).map_err(|_| format!("interval {s}"))
}

/// Admin error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// ACL denied.
    #[error("acl denied")]
    AclDenied,
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
    /// ACL or already exists.
    pub fn create_randkey(&mut self, name: &PrincipalName) -> Result<(), Error> {
        self.create_randkey_etypes(name, &[])
    }

    /// `addprinc -randkey -e`.
    ///
    /// # Errors
    ///
    /// ACL or already exists.
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

    /// Rotate keys (`cpw -randkey` / default `ktadd`).
    ///
    /// # Errors
    ///
    /// ACL or not found.
    pub fn chrand(&mut self, name: &PrincipalName) -> Result<(), Error> {
        self.reload()?;
        let tid = self.target_id(name);
        self.acl
            .check(&self.actor, AdminOp::ChangePassword, Some(&tid))
            .map_err(Error::from)?;
        self.store.chrand(name).map(|_| ()).map_err(Error::from)
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
    /// ACL or not found.
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
    /// ACL, not found, or already exists.
    pub fn rename(&mut self, old: &PrincipalName, new: &PrincipalName) -> Result<(), Error> {
        self.reload()?;
        self.store
            .rename(self.acl, &self.actor, old, new)
            .map_err(Error::from)
    }

    /// Over-the-wire ktadd (ACL `e` / extract).
    ///
    /// # Errors
    ///
    /// ACL or not found.
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
    /// ACL, not found, or `write`.
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
            .ktadd_local_atomic(name, rotate, |kt| {
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
        self.store.set_password(name, password).map_err(Error::from)
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

    /// `getprinc` display id.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`].
    pub fn get_principal_id(&self, name: &PrincipalName) -> Result<String, Error> {
        let p = self.store.get_name(name).ok_or(Error::NotFound)?;
        Ok(p.id())
    }

    /// `modprinc` attributes only.
    ///
    /// # Errors
    ///
    /// ACL or not found.
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
        self.store
            .apply_admin_fields(name, attributes, None, None, None, None, false)
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
    /// ACL or not found.
    pub fn set_policy(&mut self, name: &PrincipalName, policy: &str) -> Result<(), Error> {
        self.reload()?;
        let tid = self.target_id(name);
        self.acl
            .check(&self.actor, AdminOp::Modify, Some(&tid))
            .map_err(Error::from)?;
        self.store
            .apply_admin_fields(name, None, None, None, None, Some(policy.to_owned()), false)
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
        if self.store.policies().contains_key(&a.name) {
            return Err(Error::Inner("Principal or policy already exists".into()));
        }
        if let Some(0) = a.min_length {
            return Err(Error::Inner("Invalid password length".into()));
        }
        if let Some(c) = a.min_classes
            && !(1..=5).contains(&c)
        {
            return Err(Error::Inner("Invalid character class requirement".into()));
        }
        if let Some(0) = a.history {
            return Err(Error::Inner("Invalid history count".into()));
        }
        if let (Some(min), Some(max)) = (a.pw_min_life, a.pw_max_life)
            && min > max
            && max != 0
        {
            return Err(Error::Inner(
                "Password min life longer than max life".into(),
            ));
        }
        let mut p = NamedPolicy::new(&a.name);
        p.min_length = a.min_length.unwrap_or(1);
        p.min_classes = a.min_classes.unwrap_or(1);
        p.history = a.history.unwrap_or(1);
        p.pw_max_life = a.pw_max_life.unwrap_or(0);
        p.pw_min_life = a.pw_min_life.unwrap_or(0);
        p.max_fail = a.max_fail.unwrap_or(0);
        p.pw_failcnt_interval = a.pw_failcnt_interval.unwrap_or(0);
        p.pw_lockout_duration = a.pw_lockout_duration.unwrap_or(0);
        p.allowed_keysalts.clone_from(&a.allowed_keysalts);
        self.store.put_policy(p);
        Ok(())
    }

    /// `modpol` (`svr_policy.c:292-322` on the merged record).
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] or a floor/lifetime error.
    pub fn modify_policy_ent(&mut self, a: &PolicyArgs) -> Result<(), Error> {
        let _ = self.reload();
        let mut p = self
            .store
            .policies()
            .get(&a.name)
            .cloned()
            .ok_or(Error::NotFound)?;
        if let Some(0) = a.min_length {
            return Err(Error::Inner("Invalid password length".into()));
        }
        if let Some(c) = a.min_classes
            && !(1..=5).contains(&c)
        {
            return Err(Error::Inner("Invalid character class requirement".into()));
        }
        if let Some(0) = a.history {
            return Err(Error::Inner("Invalid history count".into()));
        }
        if let Some(v) = a.pw_max_life {
            p.pw_max_life = v;
        }
        if let Some(v) = a.pw_min_life {
            p.pw_min_life = v;
        }
        if p.pw_min_life > p.pw_max_life && p.pw_max_life != 0 && a.pw_min_life.is_some() {
            return Err(Error::Inner(
                "Password min life longer than max life".into(),
            ));
        }
        if let Some(v) = a.min_length {
            p.min_length = v;
        }
        if let Some(v) = a.min_classes {
            p.min_classes = v;
        }
        if let Some(v) = a.history {
            p.history = v;
        }
        if let Some(v) = a.max_fail {
            p.max_fail = v;
        }
        if let Some(v) = a.pw_failcnt_interval {
            p.pw_failcnt_interval = v;
        }
        if let Some(v) = a.pw_lockout_duration {
            p.pw_lockout_duration = v;
        }
        if a.allowed_keysalts.is_some() {
            p.allowed_keysalts.clone_from(&a.allowed_keysalts);
        }
        self.store.put_policy(p);
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
        self.store
            .set_string(name, key, Some(val))
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

/// RFC 3244 kpasswd request: AP-REQ + new password octets.
///
/// # Errors
///
/// AP-REQ verify or ACL.
pub fn kpasswd_set(
    store: &mut PrincipalStore,
    acl: &Acl,
    service_key: &krb5_crypto::ProtocolKey,
    ap_req: &[u8],
    replay: &ReplayCache,
    name: &PrincipalName,
    new_password: &[u8],
) -> Result<(), Error> {
    let mut sess = AdminSession::from_ap_req(store, acl, service_key, ap_req, replay)?;
    sess.change_password(name, new_password)
}

/// kprop-equivalent: serialize the store (dump) and load on a replica.
///
/// # Errors
///
/// Persist errors.
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
/// Persist errors.
pub fn receive_propagate(
    db_path: &std::path::Path,
    stash_path: &std::path::Path,
) -> Result<PrincipalStore, krb5_kdc::PersistError> {
    krb5_kdc::load_store(db_path, stash_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use krb5_kdc::{bootstrap_documented, documented_admin_id, documented_host};
    use krb5_protocol::ReplayCache;

    fn changepw_as_ticket(
        store: &krb5_kdc::PrincipalStore,
        user: &PrincipalName,
        user_key: &krb5_crypto::ProtocolKey,
        nonce: u32,
    ) -> krb5_kdc::IssuedAs {
        use krb5_kdc::{TEST_REALM, documented_changepw};
        use krb5_protocol::pa_enc_timestamp;
        krb5_kdc::issue_as(
            store,
            &krb5_protocol::as_req_sname(
                user.clone(),
                TEST_REALM,
                nonce,
                Some(vec![pa_enc_timestamp(user_key).unwrap()]),
                documented_changepw(),
                krb5_crypto::EncryptionType::preferred()
                    .iter()
                    .map(|e| e.to_iana())
                    .collect(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn allow_tgs_changepw(store: &mut krb5_kdc::PrincipalStore) {
        use krb5_kdc::{KDB_DISALLOW_TGT_BASED, documented_changepw};
        let changepw = documented_changepw();
        let a = store.get_name(&changepw).unwrap().attributes & !KDB_DISALLOW_TGT_BASED;
        store
            .apply_admin_fields(&changepw, Some(a), None, None, None, None, false)
            .unwrap();
    }

    fn reseal_ticket_crealm(
        key: &krb5_crypto::ProtocolKey,
        ticket: &mut krb5_types::Ticket,
        crealm: &str,
    ) {
        use krb5_asn1::encode;
        use krb5_crypto::{KeyUsage, encrypt};
        use krb5_kdc::decrypt_ticket_part;
        use krb5_types::{OctetString, ku};
        let mut part = decrypt_ticket_part(key, ticket).unwrap();
        part.crealm = krb5_types::ascii(crealm);
        let der = encode(&part).unwrap();
        let usage = KeyUsage::new(ku::TICKET).unwrap();
        ticket.enc_part.cipher = OctetString::from(encrypt(key, usage, &der).unwrap());
    }

    fn encode_setpw(ap_req: &[u8], krb_priv_der: &[u8]) -> Vec<u8> {
        let mut req = encode_kpasswd_req(ap_req, krb_priv_der);
        req[2..4].copy_from_slice(&0xff80u16.to_be_bytes());
        req
    }

    fn changepw_tgs_ticket(
        store: &krb5_kdc::PrincipalStore,
        user: &PrincipalName,
        user_key: &krb5_crypto::ProtocolKey,
        nonce: u32,
    ) -> krb5_kdc::IssuedTgs {
        use krb5_kdc::{TEST_REALM, documented_changepw};
        use krb5_protocol::{pa_enc_timestamp, tgs_req};
        let as_out = krb5_kdc::issue_as(
            store,
            &krb5_kdc::as_req(
                user.clone(),
                TEST_REALM,
                nonce,
                Some(vec![pa_enc_timestamp(user_key).unwrap()]),
            )
            .unwrap(),
        )
        .unwrap();
        krb5_kdc::issue_tgs(
            store,
            &tgs_req(
                as_out.rep.0.ticket.clone(),
                &as_out.session_key,
                TEST_REALM,
                user,
                documented_changepw(),
                TEST_REALM,
                nonce + 1,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn kpasswd_self_change_without_initial_is_initial_flag_needed() {
        use krb5_asn1::encode;
        use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
        use krb5_protocol::{build_ap_req, build_krb_priv, unwrap_krb_priv_ex};
        use krb5_types::ChangePasswdData;

        let (mut store, acl) = bootstrap_documented().unwrap();
        allow_tgs_changepw(&mut store);
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let user_key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let kvno_before = store
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        let tgs_out = changepw_tgs_ticket(&store, &user, &user_key, 901);
        let changepw = documented_changepw();
        let cpw_key = store
            .get_name(&changepw)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let ap = build_ap_req(
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
        )
        .unwrap();
        let cpw = ChangePasswdData {
            newpasswd: b"tgs-new-pass".to_vec().into(),
            targname: None,
            targrealm: None,
        };
        let priv_msg = build_krb_priv(&tgs_out.session_key, &encode(&cpw).unwrap()).unwrap();
        let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
        let shared = shared_store(store);
        let rep =
            handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
        let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
        let user_data = unwrap_krb_priv_ex(
            &tgs_out.session_key,
            &priv_rep,
            &ReplayCache::new(),
            false,
            false,
        )
        .unwrap();
        assert!(
            user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 7,
            "INITIAL_FLAG_NEEDED user-data [0,7]…, got {user_data:?}"
        );
        assert!(
            user_data[2..].starts_with(b"Ticket must be derived from a password"),
            "MIT text, got {:?}",
            String::from_utf8_lossy(&user_data[2..])
        );
        let after = shared.read().unwrap();
        let kvno_after = after
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        assert_eq!(
            kvno_after, kvno_before,
            "self-change without INITIAL must not set password"
        );
    }

    #[test]
    fn kpasswd_self_change_with_other_name_type_still_requires_initial() {
        use krb5_asn1::encode;
        use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
        use krb5_protocol::{build_ap_req, build_krb_priv, unwrap_krb_priv_ex};
        use krb5_types::ChangePasswdData;

        let (mut store, acl) = bootstrap_documented().unwrap();
        allow_tgs_changepw(&mut store);
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let user_key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let kvno_before = store
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        let tgs_out = changepw_tgs_ticket(&store, &user, &user_key, 931);
        let changepw = documented_changepw();
        let cpw_key = store
            .get_name(&changepw)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let ap = build_ap_req(
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
        )
        .unwrap();
        let cpw = ChangePasswdData {
            newpasswd: b"nt-unknown-pass".to_vec().into(),
            targname: Some(PrincipalName::new(PrincipalName::NT_UNKNOWN, [TEST_USER])),
            targrealm: Some(krb5_types::ascii(TEST_REALM)),
        };
        let priv_msg = build_krb_priv(&tgs_out.session_key, &encode(&cpw).unwrap()).unwrap();
        let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
        let shared = shared_store(store);
        let rep =
            handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
        let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
        let user_data = unwrap_krb_priv_ex(
            &tgs_out.session_key,
            &priv_rep,
            &ReplayCache::new(),
            false,
            false,
        )
        .unwrap();
        assert!(
            user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 7,
            "name-type-insensitive self-change is INITIAL_FLAG_NEEDED [0,7], got {user_data:?}"
        );
        assert!(
            user_data[2..].starts_with(b"Ticket must be derived from a password"),
            "MIT text, got {:?}",
            String::from_utf8_lossy(&user_data[2..])
        );
        let after = shared.read().unwrap();
        let kvno_after = after
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        assert_eq!(
            kvno_after, kvno_before,
            "NT-UNKNOWN targname must not bypass INITIAL"
        );
    }

    #[test]
    fn kpasswd_target_realm_mismatch_is_harderror() {
        use krb5_asn1::encode;
        use krb5_kdc::{
            TEST_ADMIN, TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store,
        };
        use krb5_protocol::{build_ap_req, build_krb_priv, unwrap_krb_priv_ex};
        use krb5_types::ChangePasswdData;

        let (store, acl) = bootstrap_documented().unwrap();
        let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
        let admin_key = store
            .get_name(&admin)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let kvno_before = store
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        let as_out = changepw_as_ticket(&store, &admin, &admin_key, 941);
        let changepw = documented_changepw();
        let cpw_key = store
            .get_name(&changepw)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let ap = build_ap_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &admin,
        )
        .unwrap();
        let cpw = ChangePasswdData {
            newpasswd: b"foreign-realm-pass".to_vec().into(),
            targname: Some(user.clone()),
            targrealm: Some(krb5_types::ascii("OTHER.TEST")),
        };
        let priv_msg = build_krb_priv(&as_out.session_key, &encode(&cpw).unwrap()).unwrap();
        let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
        let shared = shared_store(store);
        let rep =
            handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
        let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
        let user_data = unwrap_krb_priv_ex(
            &as_out.session_key,
            &priv_rep,
            &ReplayCache::new(),
            false,
            false,
        )
        .unwrap();
        assert!(
            user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 2,
            "privileged foreign targrealm is HARDERROR [0,2], got {user_data:?}"
        );
        assert_eq!(
            &user_data[2..],
            b"Password not changed.\nPrincipal does not exist while trying to change password.\n",
            "chpass_util.c:136-140, got {:?}",
            String::from_utf8_lossy(&user_data[2..])
        );
        let after = shared.read().unwrap();
        let kvno_after = after
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        assert_eq!(
            kvno_after, kvno_before,
            "foreign targrealm must not set password"
        );
    }

    #[test]
    fn kpasswd_foreign_self_change_needs_initial() {
        use krb5_asn1::encode;
        use krb5_kdc::{TEST_USER, documented_changepw, shared_dump as shared_store};
        use krb5_protocol::{build_ap_req, build_krb_priv, unwrap_krb_priv_ex};
        use krb5_types::ChangePasswdData;

        let (mut store, acl) = bootstrap_documented().unwrap();
        allow_tgs_changepw(&mut store);
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let user_key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let kvno_before = store
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        let tgs_out = changepw_tgs_ticket(&store, &user, &user_key, 951);
        let changepw = documented_changepw();
        let cpw_key = store
            .get_name(&changepw)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let mut ticket = tgs_out.rep.0.ticket.clone();
        reseal_ticket_crealm(&cpw_key, &mut ticket, "OTHER.TEST");
        let ap = build_ap_req(
            ticket,
            &tgs_out.session_key,
            &krb5_types::ascii("OTHER.TEST"),
            &user,
        )
        .unwrap();
        let cpw = ChangePasswdData {
            newpasswd: b"foreign-self-pass".to_vec().into(),
            targname: Some(user.clone()),
            targrealm: Some(krb5_types::ascii("OTHER.TEST")),
        };
        let priv_msg = build_krb_priv(&tgs_out.session_key, &encode(&cpw).unwrap()).unwrap();
        let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
        let shared = shared_store(store);
        let rep =
            handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
        let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
        let user_data = unwrap_krb_priv_ex(
            &tgs_out.session_key,
            &priv_rep,
            &ReplayCache::new(),
            false,
            false,
        )
        .unwrap();
        assert!(
            user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 7,
            "foreign-realm self without INITIAL is [0,7], got {user_data:?}"
        );
        assert!(
            user_data[2..].starts_with(b"Ticket must be derived from a password"),
            "MIT text, got {:?}",
            String::from_utf8_lossy(&user_data[2..])
        );
        let after = shared.read().unwrap();
        let kvno_after = after
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        assert_eq!(
            kvno_after, kvno_before,
            "foreign-realm self without INITIAL must not set password"
        );
    }

    #[test]
    fn kpasswd_unprivileged_other_principal_is_accessdenied() {
        use krb5_asn1::encode;
        use krb5_kdc::{
            TEST_ADMIN, TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store,
        };
        use krb5_protocol::{build_ap_req, build_krb_priv, unwrap_krb_priv_ex};
        use krb5_types::ChangePasswdData;

        let (mut store, acl) = bootstrap_documented().unwrap();
        allow_tgs_changepw(&mut store);
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
        let user_key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let kvno_before = store
            .get_name(&admin)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        let tgs_out = changepw_tgs_ticket(&store, &user, &user_key, 961);
        let changepw = documented_changepw();
        let cpw_key = store
            .get_name(&changepw)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let ap = build_ap_req(
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
        )
        .unwrap();
        let cpw = ChangePasswdData {
            newpasswd: b"other-should-fail".to_vec().into(),
            targname: Some(admin.clone()),
            targrealm: Some(krb5_types::ascii(TEST_REALM)),
        };
        let priv_msg = build_krb_priv(&tgs_out.session_key, &encode(&cpw).unwrap()).unwrap();
        let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
        let shared = shared_store(store);
        let rep =
            handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
        let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
        let user_data = unwrap_krb_priv_ex(
            &tgs_out.session_key,
            &priv_rep,
            &ReplayCache::new(),
            false,
            false,
        )
        .unwrap();
        assert!(
            user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 5,
            "unprivileged other principal is ACCESSDENIED [0,5], got {user_data:?}"
        );
        assert_eq!(
            &user_data[2..],
            b"Unauthorized request",
            "schpw.c:250-251, got {:?}",
            String::from_utf8_lossy(&user_data[2..])
        );
        let after = shared.read().unwrap();
        let kvno_after = after
            .get_name(&admin)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        assert_eq!(
            kvno_after, kvno_before,
            "unprivileged other principal must not set password"
        );
    }

    #[test]
    fn kpasswd_self_change_with_initial_succeeds() {
        use krb5_asn1::encode;
        use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
        use krb5_protocol::{build_ap_req, build_krb_priv, unwrap_krb_priv_ex};
        use krb5_types::ChangePasswdData;

        let (store, acl) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let user_key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let kvno_before = store
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        let as_out = changepw_as_ticket(&store, &user, &user_key, 911);
        let changepw = documented_changepw();
        let cpw_key = store
            .get_name(&changepw)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let ap = build_ap_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
        )
        .unwrap();
        let cpw = ChangePasswdData {
            newpasswd: b"as-new-pass".to_vec().into(),
            targname: None,
            targrealm: None,
        };
        let priv_msg = build_krb_priv(&as_out.session_key, &encode(&cpw).unwrap()).unwrap();
        let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
        let shared = shared_store(store);
        let rep =
            handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
        assert!(
            rep.len() > 6 && u16::from_be_bytes([rep[4], rep[5]]) > 0,
            "INITIAL self-change includes AP-REP"
        );
        let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
        let user_data = unwrap_krb_priv_ex(
            &as_out.session_key,
            &priv_rep,
            &ReplayCache::new(),
            false,
            false,
        )
        .unwrap();
        assert!(
            user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 0,
            "INITIAL self-change [0,0], got {user_data:?}"
        );
        let after = shared.read().unwrap();
        let kvno_after = after
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        assert!(
            kvno_after > kvno_before,
            "INITIAL self-change must bump kvno ({kvno_before} -> {kvno_after})"
        );
    }

    #[test]
    fn kpasswd_admin_change_ignores_initial() {
        use krb5_asn1::encode;
        use krb5_kdc::{
            TEST_ADMIN, TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store,
        };
        use krb5_protocol::{build_ap_req, build_krb_priv};
        use krb5_types::ChangePasswdData;

        let (mut store, acl) = bootstrap_documented().unwrap();
        allow_tgs_changepw(&mut store);
        let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
        let admin_key = store
            .get_name(&admin)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let tgs_out = changepw_tgs_ticket(&store, &admin, &admin_key, 921);
        let changepw = documented_changepw();
        let cpw_key = store
            .get_name(&changepw)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let ap = build_ap_req(
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &admin,
        )
        .unwrap();
        let cpw = ChangePasswdData {
            newpasswd: b"admin-set-user".to_vec().into(),
            targname: Some(user.clone()),
            targrealm: Some(krb5_types::ascii(TEST_REALM)),
        };
        let priv_msg = build_krb_priv(&tgs_out.session_key, &encode(&cpw).unwrap()).unwrap();
        let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
        let shared = shared_store(store);
        let rep =
            handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
        let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
        let user_data = krb5_protocol::unwrap_krb_priv_ex(
            &tgs_out.session_key,
            &priv_rep,
            &ReplayCache::new(),
            false,
            false,
        )
        .unwrap();
        assert!(
            user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 0,
            "admin-style change ignores INITIAL, got {user_data:?}"
        );
    }

    #[test]
    fn kadmind_enforces_acl() {
        let (mut store, acl) = bootstrap_documented().unwrap();
        let mut admin = AdminSession::local(&mut store, &acl, documented_admin_id());
        let extra = PrincipalName::new(
            PrincipalName::NT_SRV_HST,
            ["host", "admin-extra.kerber.test"],
        );
        admin.create_password(&extra, b"secret-pass").unwrap();
        let kt = admin.ktadd(&extra).unwrap();
        assert_eq!(&kt.to_bytes()[..2], &[0x05, 0x02]);
    }

    #[test]
    fn kadmind_denies_user() {
        let (mut store, acl) = bootstrap_documented().unwrap();
        let mut user = AdminSession::local(&mut store, &acl, "user@KERBER.TEST");
        let extra = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "nope.kerber.test"]);
        assert_eq!(
            user.create_password(&extra, b"x").unwrap_err(),
            Error::AclDenied
        );
        assert_eq!(
            user.ktadd(&documented_host()).unwrap_err(),
            Error::AclDenied
        );
    }

    #[test]
    fn kpasswd_self_service_and_admin_acl() {
        let (mut store, acl) = bootstrap_documented().unwrap();
        let user_name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        let admin_name = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
        {
            let mut user = AdminSession::local(&mut store, &acl, "user@KERBER.TEST");
            user.change_password(&user_name, b"new-user-pass").unwrap();
            assert_eq!(
                user.change_password(&admin_name, b"nope").unwrap_err(),
                Error::AclDenied
            );
        }
        let after = store.get_name(&user_name).unwrap();
        let old_max = after.keys.iter().map(|k| k.kvno).max().unwrap();
        assert!(old_max > 1, "self-service kpasswd must bump kvno");
        {
            let mut admin = AdminSession::local(&mut store, &acl, documented_admin_id());
            admin
                .change_password(&user_name, b"admin-set-pass")
                .unwrap();
        }
        let after = store.get_name(&user_name).unwrap();
        let new_max = after.keys.iter().map(|k| k.kvno).max().unwrap();
        assert!(new_max > old_max);
    }

    #[test]
    fn kprop_replica_issues_with_same_krbtgt() {
        let dir = std::env::temp_dir().join(format!("kprop-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("principal");
        let stash = dir.join("stash");
        let (store, _) = bootstrap_documented().unwrap();
        let before = store
            .krbtgt()
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .as_bytes()
            .to_vec();
        propagate(&store, &db, &stash).unwrap();
        let replica = receive_propagate(&db, &stash).unwrap();
        let after = replica
            .krbtgt()
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .as_bytes()
            .to_vec();
        assert_eq!(before, after);
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        let salt = cname.default_salt("KERBER.TEST");
        let key = krb5_crypto::string_to_key(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            b"userpassword",
            &salt,
            Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let req = krb5_kdc::as_req(
            cname,
            "KERBER.TEST",
            9,
            Some(vec![krb5_kdc::pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&replica, &req).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kadmind_wire_create_is_visible_after_reload() {
        use krb5_asn1::encode;
        use krb5_kdc::{
            TEST_REALM, documented_host, load_store, save_store, shared_dump as shared_store,
        };
        use krb5_protocol::{build_ap_req, pa_enc_timestamp, tgs_req};

        let dir = std::env::temp_dir().join(format!(
            "kadmind-wire-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("principal");
        let stash = dir.join("stash");
        let (store, acl) = bootstrap_documented().unwrap();
        save_store(&store, &db, &stash).unwrap();
        let store = load_store(&db, &stash).unwrap();
        assert!(store.persist_paths.is_some());

        let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
        let admin_key = store
            .get_name(&admin)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let as_req = krb5_kdc::as_req(
            admin.clone(),
            TEST_REALM,
            41,
            Some(vec![pa_enc_timestamp(&admin_key).unwrap()]),
        )
        .unwrap();
        let as_out = krb5_kdc::issue_as(&store, &as_req).unwrap();
        let tgs = tgs_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            TEST_REALM,
            &admin,
            documented_host(),
            TEST_REALM,
            42,
        )
        .unwrap();
        let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
        let host_key = store
            .get_name(&documented_host())
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let ap = build_ap_req(
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &admin,
        )
        .unwrap();
        let ap_der = encode(&ap).unwrap();

        let shared = shared_store(store);
        let replay = ReplayCache::new();
        let payload = b"wireuser@KERBER.TEST\0wire-secret";
        let body = encode_kadmind_req(Op::Create, &ap_der, payload);
        let reply = dispatch_kadmind(&shared, &acl, &host_key, &replay, &body).expect("create");
        assert_eq!(&reply[..4], &[0, 0, 0, 0]);

        let loaded = load_store(&db, &stash).unwrap();
        let created = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["wireuser"]);
        assert!(
            loaded.get_name(&created).is_some(),
            "kadmind create must persist to stash/db"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kpasswd_rfc3244_bumps_kvno() {
        use krb5_asn1::encode;
        use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
        use krb5_protocol::{build_ap_req, build_krb_priv, pa_enc_timestamp};
        use krb5_types::ChangePasswdData;

        let (store, acl) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let user_key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let kvno_before = store
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        let changepw = documented_changepw();
        let as_out = changepw_as_ticket(&store, &user, &user_key, 43);
        let cpw_key = store
            .get_name(&changepw)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let ap = build_ap_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
        )
        .unwrap();
        let ap_der = encode(&ap).unwrap();
        let cpw = ChangePasswdData {
            newpasswd: b"rfc3244-new".to_vec().into(),
            targname: Some(user.clone()),
            targrealm: Some(krb5_types::ascii(TEST_REALM)),
        };
        let cpw_der = encode(&cpw).unwrap();
        let priv_msg = build_krb_priv(&as_out.session_key, &cpw_der).unwrap();
        let priv_der = encode(&priv_msg).unwrap();
        let req = encode_setpw(&ap_der, &priv_der);
        let shared = shared_store(store);
        let replay = ReplayCache::new();
        let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &replay, &req).expect("kpasswd");
        assert!(
            rep.len() > 6 && u16::from_be_bytes([rep[4], rep[5]]) > 0,
            "success reply must include AP-REP"
        );
        let (ap_rep, priv_rep) = parse_kpasswd_rep(&rep).expect("parse kpasswd rep");
        assert!(!ap_rep.is_empty() && !priv_rep.is_empty());
        assert!(parse_kpasswd_rep(&[0, 6, 0, 1, 0, 0]).is_err());
        let after = shared.read().unwrap();
        let kvno_after = after
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        assert!(kvno_after > kvno_before, "RFC 3244 must bump kvno");

        let salt = user.default_salt(TEST_REALM);
        let new_key = krb5_crypto::string_to_key(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            b"rfc3244-new",
            &salt,
            Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let as_new = krb5_kdc::as_req(
            user.clone(),
            TEST_REALM,
            45,
            Some(vec![pa_enc_timestamp(&new_key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&*after, &as_new).expect("AS with RFC 3244 new password");

        let as_old = krb5_kdc::as_req(
            user,
            TEST_REALM,
            46,
            Some(vec![pa_enc_timestamp(&user_key).unwrap()]),
        )
        .unwrap();
        assert!(
            krb5_kdc::issue_as(&*after, &as_old).is_err(),
            "old password must fail after kpasswd"
        );
    }

    #[test]
    fn kpasswd_policy_rejection_is_softerror() {
        use krb5_asn1::encode;
        use krb5_kdc::{
            NamedPolicy, TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store,
        };
        use krb5_protocol::{ReplayCache, build_ap_req, build_krb_priv, unwrap_krb_priv_ex};
        use krb5_types::ChangePasswdData;

        let (mut store, acl) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        store.put_policy(NamedPolicy {
            name: "short8".into(),
            min_length: 8,
            min_classes: 0,
            history: 0,
            max_fail: 0,
            pw_failcnt_interval: 0,
            pw_lockout_duration: 0,
            pw_min_life: 0,
            pw_max_life: 0,
            allowed_keysalts: None,
        });
        store
            .set_principal_policy(&user, Some("short8".into()))
            .unwrap();
        let user_key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let changepw = documented_changepw();
        let as_out = changepw_as_ticket(&store, &user, &user_key, 47);
        let cpw_key = store
            .get_name(&changepw)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let ap = build_ap_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
        )
        .unwrap();
        let cpw = ChangePasswdData {
            newpasswd: b"abc".to_vec().into(),
            targname: Some(user),
            targrealm: Some(krb5_types::ascii(TEST_REALM)),
        };
        let priv_msg = build_krb_priv(&as_out.session_key, &encode(&cpw).unwrap()).unwrap();
        let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
        let shared = shared_store(store);
        let replay = ReplayCache::new();
        let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &replay, &req)
            .expect("policy rejection must reply");
        let (ap_rep, priv_rep) = parse_kpasswd_rep(&rep).expect("parse kpasswd rep");
        assert!(!ap_rep.is_empty(), "SOFTERROR reply includes AP-REP");
        let user_data = unwrap_krb_priv_ex(
            &as_out.session_key,
            &priv_rep,
            &ReplayCache::new(),
            false,
            false,
        )
        .expect("unwrap KRB-PRIV");
        assert!(
            user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 4,
            "SOFTERROR user-data [0,4]…, got {user_data:?}"
        );
    }

    #[test]
    fn kpasswd_udp_listener_then_issue_as() {
        use std::net::UdpSocket;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;
        use std::time::Duration;

        use krb5_asn1::encode;
        use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
        use krb5_protocol::{build_ap_req, build_krb_priv, pa_enc_timestamp};
        use krb5_types::ChangePasswdData;

        let (store, acl) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let user_key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let changepw = documented_changepw();
        let cpw_key = store
            .get_name(&changepw)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let as_out = changepw_as_ticket(&store, &user, &user_key, 47);
        let ap = build_ap_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
        )
        .unwrap();
        let cpw = ChangePasswdData {
            newpasswd: b"udp-new-pass".to_vec().into(),
            targname: Some(user.clone()),
            targrealm: Some(krb5_types::ascii(TEST_REALM)),
        };
        let priv_msg = build_krb_priv(&as_out.session_key, &encode(&cpw).unwrap()).unwrap();
        let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());

        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let shared = shared_store(store);
        let shared2 = shared.clone();
        let stop2 = Arc::clone(&stop);
        thread::spawn(move || {
            let _ = serve_kpasswd_udp(shared2, acl, cpw_key, sock, stop2);
        });
        thread::sleep(Duration::from_millis(30));
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        // Debug s2k in change_password can exceed 2s before the reply.
        client
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        client.send_to(&req, addr).unwrap();
        let mut buf = [0u8; 4096];
        let n = client.recv(&mut buf).expect("kpasswd reply");
        assert!(n > 6, "RFC 3244 reply");
        stop.store(true, Ordering::Relaxed);
        let after = shared.read().unwrap();
        let salt = user.default_salt(TEST_REALM);
        let new_key = krb5_crypto::string_to_key(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            b"udp-new-pass",
            &salt,
            Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let as_new = krb5_kdc::as_req(
            user,
            TEST_REALM,
            49,
            Some(vec![pa_enc_timestamp(&new_key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&*after, &as_new).expect("AS after UDP kpasswd");
    }

    #[test]
    fn kpasswd_mit_style_subkey_seq0_then_issue_as() {
        use krb5_asn1::encode;
        use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
        use krb5_protocol::{build_ap_req_with_cksum, build_krb_priv_with_seq, pa_enc_timestamp};
        use krb5_types::ApOptions;

        let (store, acl) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let user_key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let changepw = documented_changepw();
        let cpw_key = store
            .get_name(&changepw)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let as_out = changepw_as_ticket(&store, &user, &user_key, 50);
        let sub = krb5_crypto::ProtocolKey::from_bytes(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            &[0x5au8; 32],
        )
        .unwrap();
        let sub_ek = krb5_types::EncryptionKey {
            keytype: sub.etype().to_iana(),
            keyvalue: sub.as_bytes().to_vec().into(),
        };
        let ap = build_ap_req_with_cksum(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
            ApOptions::none(),
            None,
            Some(sub_ek),
        )
        .unwrap();
        // MIT kpasswd: version 1, raw password, subkey, seq 0.
        let priv_msg = build_krb_priv_with_seq(&sub, b"kpasswd-one", Some(0)).unwrap();
        let req = encode_kpasswd_req(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
        let shared = shared_store(store);
        let replay = ReplayCache::new();
        let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &replay, &req)
            .expect("MIT-style kpasswd");
        assert!(
            rep.len() > 6 && u16::from_be_bytes([rep[4], rep[5]]) > 0,
            "MIT kpasswd requires AP-REP on success"
        );
        let after = shared.read().unwrap();
        let salt = user.default_salt(TEST_REALM);
        let new_key = krb5_crypto::string_to_key(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            b"kpasswd-one",
            &salt,
            Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let as_new = krb5_kdc::as_req(
            user,
            TEST_REALM,
            52,
            Some(vec![pa_enc_timestamp(&new_key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&*after, &as_new).expect("AS after MIT-style kpasswd");
    }

    #[test]
    fn kpasswd_unknown_version_is_bad_version() {
        use krb5_kdc::{documented_changepw, shared_dump as shared_store};

        let (store, acl) = bootstrap_documented().unwrap();
        let cpw_key = store
            .get_name(&documented_changepw())
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let req = [0u8, 6, 0, 2, 0, 0];
        let shared = shared_store(store);
        let err = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
            .expect_err("MIT dispatch sends no reply");
        assert!(
            err.to_string()
                .contains("Requested protocol version not supported"),
            "{err}"
        );
    }

    #[test]
    fn kpasswd_inconsistent_length_is_malformed() {
        use krb5_kdc::{documented_changepw, shared_dump as shared_store};

        let (store, acl) = bootstrap_documented().unwrap();
        let cpw_key = store
            .get_name(&documented_changepw())
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let req = [0u8, 99, 0, 1, 0, 0];
        let shared = shared_store(store);
        let err = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
            .expect_err("MIT dispatch sends no reply");
        assert!(err.to_string().contains("Message stream modified"), "{err}");
    }

    #[test]
    fn kpasswd_bad_ap_req_is_chpwfail_autherror() {
        use krb5_asn1::decode;
        use krb5_kdc::{documented_changepw, shared_dump as shared_store};
        use krb5_types::KrbError;

        let (store, acl) = bootstrap_documented().unwrap();
        let cpw_key = store
            .get_name(&documented_changepw())
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let req = encode_kpasswd_req(&[0, 1, 2, 3], b"x");
        let shared = shared_store(store);
        let r1 = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
            .expect("chpwfail");
        let r2 = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
            .expect("retransmit");
        for rep in [&r1, &r2] {
            assert!(rep.len() > 6);
            assert_eq!(&rep[4..6], &[0, 0], "AP-REP length 0");
            let e: KrbError = decode(&rep[6..]).expect("framed KRB-ERROR");
            assert_eq!(e.error_code, krb5_types::err::GENERIC);
            assert!(e.e_text.is_none());
            assert_eq!(e.sname.name_type, PrincipalName::NT_PRINCIPAL);
            let data = e.e_data.as_ref().expect("e_data");
            assert!(data.len() >= 2 && data.as_ref()[0] == 0 && data.as_ref()[1] == 3);
            assert!(data.as_ref()[2..].starts_with(b"Failed reading application request"));
        }
    }

    #[test]
    fn kpasswd_ap_req_fills_datagram_is_bailout() {
        use krb5_kdc::{documented_changepw, shared_dump as shared_store};

        let (store, acl) = bootstrap_documented().unwrap();
        let cpw_key = store
            .get_name(&documented_changepw())
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let req = encode_kpasswd_req(&[0, 1, 2, 3], &[]);
        let shared = shared_store(store);
        let err = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
            .expect_err("schpw.c:89 >= is bailout");
        assert!(err.to_string().contains("Message stream modified"), "{err}");
    }

    #[test]
    fn kpasswd_bad_priv_after_ap_req_is_harderror() {
        use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
        use krb5_protocol::{build_ap_req, unwrap_krb_priv_ex};

        let (store, acl) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let user_key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let as_out = changepw_as_ticket(&store, &user, &user_key, 77);
        let cpw_key = store
            .get_name(&documented_changepw())
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let ap = build_ap_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
        )
        .unwrap();
        let req = encode_kpasswd_req(&krb5_asn1::encode(&ap).unwrap(), b"not-priv");
        let shared = shared_store(store);
        let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
            .expect("PRIV fail after AP-REQ");
        let (ap_rep, priv_rep) = parse_kpasswd_rep(&rep).expect("AP-REP + KRB-PRIV");
        assert!(!ap_rep.is_empty());
        let user_data = unwrap_krb_priv_ex(
            &as_out.session_key,
            &priv_rep,
            &ReplayCache::new(),
            false,
            false,
        )
        .unwrap();
        assert!(
            user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 2,
            "HARDERROR [0,2], got {user_data:?}"
        );
        assert_eq!(&user_data[2..], b"Failed decrypting request");
    }

    #[test]
    fn kpasswd_vno1_der_stays_password() {
        use krb5_asn1::encode;
        use krb5_kdc::{
            TEST_ADMIN, TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store,
        };
        use krb5_protocol::{build_ap_req, build_krb_priv};
        use krb5_types::ChangePasswdData;

        let (store, acl) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_ADMIN]);
        let user_kvno = store
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        let admin_kvno = store
            .get_name(&admin)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        let user_key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let as_out = changepw_as_ticket(&store, &user, &user_key, 61);
        let cpw_key = store
            .get_name(&documented_changepw())
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let ap = build_ap_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
        )
        .unwrap();
        let cpw = ChangePasswdData {
            newpasswd: b"der-as-pass".to_vec().into(),
            targname: Some(admin.clone()),
            targrealm: Some(krb5_types::ascii(TEST_REALM)),
        };
        let priv_msg = build_krb_priv(&as_out.session_key, &encode(&cpw).unwrap()).unwrap();
        let req = encode_kpasswd_req(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
        let shared = shared_store(store);
        let rep =
            handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req).unwrap();
        let (_, priv_rep) = parse_kpasswd_rep(&rep).unwrap();
        let user_data = krb5_protocol::unwrap_krb_priv_ex(
            &as_out.session_key,
            &priv_rep,
            &ReplayCache::new(),
            false,
            false,
        )
        .unwrap();
        assert!(
            user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 0,
            "vno-1 DER is a self-change password, got {user_data:?}"
        );
        let after = shared.read().unwrap();
        let user_kvno_after = after
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        let admin_kvno_after = after
            .get_name(&admin)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        assert!(user_kvno_after > user_kvno, "vno-1 DER must set self");
        assert_eq!(admin_kvno_after, admin_kvno, "vno-1 DER must not retarget");
    }

    #[test]
    fn kpasswd_setpw_decode_failure_is_malformed() {
        use krb5_asn1::encode;
        use krb5_kdc::{TEST_REALM, TEST_USER, documented_changepw, shared_dump as shared_store};
        use krb5_protocol::{build_ap_req, build_krb_priv, unwrap_krb_priv_ex};

        let (store, acl) = bootstrap_documented().unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let user_key = store
            .get_name(&user)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let kvno_before = store
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        let as_out = changepw_as_ticket(&store, &user, &user_key, 62);
        let cpw_key = store
            .get_name(&documented_changepw())
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let ap = build_ap_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &user,
        )
        .unwrap();
        let priv_msg = build_krb_priv(&as_out.session_key, b"not-der-setpw").unwrap();
        let req = encode_setpw(&encode(&ap).unwrap(), &encode(&priv_msg).unwrap());
        let shared = shared_store(store);
        let rep = handle_kpasswd_rfc3244(&shared, &acl, &cpw_key, &ReplayCache::new(), &req)
            .expect("decode failure replies");
        let (ap_rep, priv_rep) = parse_kpasswd_rep(&rep).expect("KRB-PRIV");
        assert!(!ap_rep.is_empty(), "decode failure after AP-REQ has AP-REP");
        let user_data = unwrap_krb_priv_ex(
            &as_out.session_key,
            &priv_rep,
            &ReplayCache::new(),
            false,
            false,
        )
        .unwrap();
        assert!(
            user_data.len() >= 2 && user_data[0] == 0 && user_data[1] == 1,
            "Failed decoding ChangePasswdData is MALFORMED [0,1], got {user_data:?}"
        );
        assert_eq!(&user_data[2..], b"Failed decoding ChangePasswdData");
        let after = shared.read().unwrap();
        let kvno_after = after
            .get_name(&user)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap();
        assert_eq!(
            kvno_after, kvno_before,
            "decode failure must not set password"
        );
    }

    #[test]
    fn kprop_tcp_replica_issues_as_with_shared_stash() {
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        use krb5_kdc::TEST_REALM;
        use krb5_kdc::TEST_USER;

        const MASTER: &[u8] = b"masterpassword";

        let (store, _) = bootstrap_documented().unwrap();
        let before = store
            .krbtgt()
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .as_bytes()
            .to_vec();

        let listener = TcpListener::bind("127.0.0.1:754")
            .or_else(|_| TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            kprop_recv(&mut stream, MASTER).expect("kprop_recv")
        });
        thread::sleep(Duration::from_millis(20));
        let mut client = TcpStream::connect(addr).unwrap();
        kprop_send(&store, MASTER, &mut client).expect("kprop_send");
        let replica = join.join().expect("thread");
        let after = replica
            .krbtgt()
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .as_bytes()
            .to_vec();
        assert_eq!(
            before, after,
            "replica krbtgt must match the primary (shared stash)"
        );
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let salt = cname.default_salt(TEST_REALM);
        let key = krb5_crypto::string_to_key(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            b"userpassword",
            &salt,
            Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let req = krb5_kdc::as_req(
            cname,
            TEST_REALM,
            91,
            Some(vec![krb5_kdc::pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&replica, &req).expect("replica issue_as");
    }

    #[test]
    fn kprop_dump_payload_is_version_7_not_kdb3() {
        const MASTER: &[u8] = b"masterpassword";
        let (store, _) = bootstrap_documented().unwrap();
        let bytes = kprop_dump_bytes(&store, MASTER).unwrap();
        assert!(
            bytes.starts_with(b"kdb5_util load_dump version 7\n"),
            "kprop body must be dump version 7, got {}",
            String::from_utf8_lossy(&bytes[..bytes.len().min(40)])
        );
        assert!(!bytes.starts_with(b"KDB3"));
        let replica = kprop_load_bytes(&bytes, MASTER).unwrap();
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [krb5_kdc::TEST_USER]);
        let salt = cname.default_salt(krb5_kdc::TEST_REALM);
        let key = krb5_crypto::string_to_key(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            b"userpassword",
            &salt,
            Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let req = krb5_kdc::as_req(
            cname,
            krb5_kdc::TEST_REALM,
            92,
            Some(vec![krb5_kdc::pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&replica, &req).expect("dump-codec replica issue_as");
    }

    #[test]
    fn kprop_truncated_or_kdb3_body_fails() {
        const MASTER: &[u8] = b"masterpassword";
        assert!(kprop_load_bytes(b"KDB3notadump", MASTER).is_err());
        assert!(kprop_load_bytes(b"kdb5_util load_dump version 7\nprinc\t", MASTER).is_err());
        assert!(kprop_load_bytes(b"not a dump", MASTER).is_err());
    }

    #[test]
    fn kprop_mit_wire_sendauth_replica_issues_as() {
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        use krb5_kdc::{TEST_REALM, TEST_USER, documented_host};
        use krb5_protocol::{pa_enc_timestamp, tgs_req};

        const MASTER: &[u8] = b"masterpassword";
        let (store, _) = bootstrap_documented().unwrap();
        let host = documented_host();
        let host_keys: Vec<_> = store
            .get_name(&host)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.key.clone())
            .collect();

        let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
        let admin_key = store
            .get_name(&admin)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let as_req = krb5_kdc::as_req(
            admin.clone(),
            TEST_REALM,
            71,
            Some(vec![pa_enc_timestamp(&admin_key).unwrap()]),
        )
        .unwrap();
        let as_out = krb5_kdc::issue_as(&store, &as_req).unwrap();
        let tgs = tgs_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            TEST_REALM,
            &admin,
            host.clone(),
            TEST_REALM,
            72,
        )
        .unwrap();
        let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let host_keys2 = host_keys.clone();
        let host_for_server = host.clone();
        let allowed = vec![format!("admin@{TEST_REALM}")];
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let dir = std::env::temp_dir().join(format!(
                "kprop-mit-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            let _ = std::fs::create_dir_all(&dir);
            let db = dir.join("replica");
            let stash = dir.join("stash");
            let store = kpropd_handle_conn(
                &mut stream,
                &host_keys2,
                Some(&host_for_server),
                Some(TEST_REALM),
                MASTER,
                &db,
                &stash,
                Some(allowed.as_slice()),
                ReplayCache::new(),
            )
            .expect("kpropd_handle_conn");
            let _ = std::fs::remove_dir_all(&dir);
            store
        });
        thread::sleep(Duration::from_millis(20));
        let mut client = TcpStream::connect(addr).unwrap();
        kprop_send_store(
            &mut client,
            &store,
            MASTER,
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &admin,
        )
        .expect("kprop_send_store");
        let replica = join.join().expect("thread");
        let cname = PrincipalName::new(PrincipalName::NT_PRINCIPAL, [TEST_USER]);
        let salt = cname.default_salt(TEST_REALM);
        let key = krb5_crypto::string_to_key(
            krb5_crypto::EncryptionType::Aes256CtsHmacSha196,
            b"userpassword",
            &salt,
            Some(&krb5_kdc::S2K_ITERS.to_be_bytes()),
        )
        .unwrap();
        let req = krb5_kdc::as_req(
            cname,
            TEST_REALM,
            93,
            Some(vec![krb5_kdc::pa_enc_timestamp(&key).unwrap()]),
        )
        .unwrap();
        krb5_kdc::issue_as(&replica, &req).expect("MIT-wire replica issue_as");
    }

    #[test]
    fn kpropd_rejects_client_not_on_allowlist() {
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        use krb5_kdc::{TEST_REALM, documented_host};
        use krb5_protocol::{pa_enc_timestamp, tgs_req};

        const MASTER: &[u8] = b"masterpassword";
        let (store, _) = bootstrap_documented().unwrap();
        let host = documented_host();
        let host_keys: Vec<_> = store
            .get_name(&host)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.key.clone())
            .collect();
        let admin = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["admin"]);
        let admin_key = store
            .get_name(&admin)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let as_req = krb5_kdc::as_req(
            admin.clone(),
            TEST_REALM,
            81,
            Some(vec![pa_enc_timestamp(&admin_key).unwrap()]),
        )
        .unwrap();
        let as_out = krb5_kdc::issue_as(&store, &as_req).unwrap();
        let tgs = tgs_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            TEST_REALM,
            &admin,
            host.clone(),
            TEST_REALM,
            82,
        )
        .unwrap();
        let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let host_keys2 = host_keys.clone();
        let host_for_server = host.clone();
        let allowed = vec![format!("host/testhost.kerber.test@{TEST_REALM}")];
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let dir = std::env::temp_dir().join(format!(
                "kprop-deny-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            let _ = std::fs::create_dir_all(&dir);
            let db = dir.join("replica");
            let stash = dir.join("stash");
            let err = kpropd_handle_conn(
                &mut stream,
                &host_keys2,
                Some(&host_for_server),
                Some(TEST_REALM),
                MASTER,
                &db,
                &stash,
                Some(allowed.as_slice()),
                ReplayCache::new(),
            )
            .unwrap_err();
            let _ = std::fs::remove_dir_all(&dir);
            err
        });
        thread::sleep(Duration::from_millis(20));
        let mut client = TcpStream::connect(addr).unwrap();
        let _ = kprop_send_store(
            &mut client,
            &store,
            MASTER,
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &admin,
        );
        let err = join.join().expect("thread");
        assert_eq!(err, Error::AclDenied);
    }

    #[test]
    fn kpropd_rejects_when_acl_unset() {
        use std::net::{TcpListener, TcpStream};
        use std::thread;
        use std::time::Duration;

        use krb5_kdc::{TEST_REALM, documented_host};
        use krb5_protocol::{pa_enc_timestamp, tgs_req};

        const MASTER: &[u8] = b"masterpassword";
        let (store, _) = bootstrap_documented().unwrap();
        let host = documented_host();
        let host_keys: Vec<_> = store
            .get_name(&host)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.key.clone())
            .collect();
        let host_key = store
            .get_name(&host)
            .unwrap()
            .best_key()
            .unwrap()
            .key
            .clone();
        let as_req = krb5_kdc::as_req(
            host.clone(),
            TEST_REALM,
            83,
            Some(vec![pa_enc_timestamp(&host_key).unwrap()]),
        )
        .unwrap();
        let as_out = krb5_kdc::issue_as(&store, &as_req).unwrap();
        let tgs = tgs_req(
            as_out.rep.0.ticket.clone(),
            &as_out.session_key,
            TEST_REALM,
            &host,
            host.clone(),
            TEST_REALM,
            84,
        )
        .unwrap();
        let tgs_out = krb5_kdc::issue_tgs(&store, &tgs).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let host_keys2 = host_keys.clone();
        let host_for_server = host.clone();
        let join = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let dir = std::env::temp_dir().join(format!(
                "kprop-unset-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            let _ = std::fs::create_dir_all(&dir);
            let db = dir.join("replica");
            let stash = dir.join("stash");
            let err = kpropd_handle_conn(
                &mut stream,
                &host_keys2,
                Some(&host_for_server),
                Some(TEST_REALM),
                MASTER,
                &db,
                &stash,
                None,
                ReplayCache::new(),
            )
            .unwrap_err();
            let _ = std::fs::remove_dir_all(&dir);
            err
        });
        thread::sleep(Duration::from_millis(20));
        let mut client = TcpStream::connect(addr).unwrap();
        let _ = kprop_send_store(
            &mut client,
            &store,
            MASTER,
            tgs_out.rep.0.ticket.clone(),
            &tgs_out.session_key,
            &krb5_types::ascii(TEST_REALM),
            &host,
        );
        let err = join.join().expect("thread");
        assert_eq!(err, Error::AclDenied);
    }

    #[test]
    fn load_acl_file_missing_is_error() {
        let path = std::env::temp_dir().join(format!("krb5-acl-missing-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(load_acl_file("admin@KERBER.TEST", Some(&path)).is_err());
        let acl = load_acl_file("admin@KERBER.TEST", None).unwrap();
        assert!(
            acl.check("admin@KERBER.TEST", AdminOp::Create, None)
                .is_ok()
        );
    }

    #[test]
    fn load_acl_file_parses_readable() {
        let path = std::env::temp_dir().join(format!("krb5-acl-ok-{}", std::process::id()));
        std::fs::write(&path, "admin@KERBER.TEST *\n").unwrap();
        let acl = load_acl_file("other@KERBER.TEST", Some(&path)).unwrap();
        assert!(
            acl.check("admin@KERBER.TEST", AdminOp::Create, None)
                .is_ok()
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn kpasswd_udp_exchange_ignores_off_path() {
        use std::net::UdpSocket;
        use std::thread;
        use std::time::Duration;

        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dest = server.local_addr().unwrap();
        thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (n, src) = server.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"req");
            let spoof = UdpSocket::bind("127.0.0.1:0").unwrap();
            let _ = spoof.send_to(b"spoof", src);
            thread::sleep(Duration::from_millis(30));
            let _ = server.send_to(b"kdc-ok", src);
        });
        let got = kpasswd_udp_exchange_to(dest, b"req").expect("kdc reply");
        assert_eq!(got, b"kdc-ok");
    }

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
        let a = parse_kadmin_args(&["+0x1ffffffff", "wide"]).unwrap();
        assert_eq!(a.attr_set, 0xffff_ffff);
        assert_eq!(a.name, "wide");
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

    fn max_kvno(store: &PrincipalStore, name: &PrincipalName) -> u32 {
        store
            .get_name(name)
            .unwrap()
            .keys
            .iter()
            .map(|k| k.kvno)
            .max()
            .unwrap_or(0)
    }

    #[test]
    fn ktadd_local_lockdown_rotates_and_extracts() {
        let (mut store, acl) = bootstrap_documented().unwrap();
        let extra = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "lockee.kerber.test"]);
        {
            let mut admin = AdminSession::local(&mut store, &acl, documented_admin_id());
            admin.create_randkey(&extra).unwrap();
            admin
                .modify_attributes(&extra, Some(KDB_LOCKDOWN_KEYS))
                .unwrap();
        }
        assert_eq!(
            store
                .export_keytab(&acl, &documented_admin_id(), &extra)
                .unwrap_err(),
            krb5_kdc::Error::AclDenied
        );
        let before = max_kvno(&store, &extra);
        let mut written = None;
        {
            let mut admin = AdminSession::local(&mut store, &acl, documented_admin_id());
            admin
                .ktadd_local(&extra, true, |kt| {
                    written = Some(kt.entries.len());
                    Ok(())
                })
                .unwrap();
        }
        assert!(written.unwrap() >= 1);
        assert!(max_kvno(&store, &extra) > before);
    }

    #[test]
    fn ktadd_local_write_fail_does_not_persist_rotation() {
        use krb5_kdc::{load_store, save_store};
        let dir = std::env::temp_dir().join(format!(
            "ktadd-atomic-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("principal");
        let stash = dir.join("stash");
        let (mut store, acl) = bootstrap_documented().unwrap();
        let extra = PrincipalName::new(PrincipalName::NT_SRV_HST, ["host", "atomic.kerber.test"]);
        {
            let mut admin = AdminSession::local(&mut store, &acl, documented_admin_id());
            admin.create_randkey(&extra).unwrap();
        }
        save_store(&store, &db, &stash).unwrap();
        store.persist_paths = Some((db.clone(), stash.clone()));
        let before = max_kvno(&store, &extra);
        {
            let mut admin = AdminSession::local(&mut store, &acl, documented_admin_id());
            let err = admin
                .ktadd_local(&extra, true, |_| Err("disk full".into()))
                .unwrap_err();
            assert!(matches!(err, Error::Inner(_)));
        }
        assert_eq!(max_kvno(&store, &extra), before);
        let reloaded = load_store(&db, &stash).unwrap();
        assert_eq!(max_kvno(&reloaded, &extra), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn setstr_reload_keeps_concurrent_create() {
        use krb5_kdc::{load_store, save_store};
        let dir = std::env::temp_dir().join(format!(
            "setstr-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("principal");
        let stash = dir.join("stash");
        let (store, acl) = bootstrap_documented().unwrap();
        save_store(&store, &db, &stash).unwrap();
        let mut local = load_store(&db, &stash).unwrap();
        let mut kadmind = load_store(&db, &stash).unwrap();
        kadmind.persist_paths = Some((db.clone(), stash.clone()));
        local.persist_paths = Some((db.clone(), stash.clone()));
        let extra = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["m5extra"]);
        kadmind
            .create_password(&acl, &documented_admin_id(), &extra, b"m5-secret")
            .unwrap();
        let user = PrincipalName::new(PrincipalName::NT_PRINCIPAL, ["user"]);
        {
            let mut sess = AdminSession::local(&mut local, &acl, documented_admin_id());
            sess.set_string_attr(&user, "m5k", "m5v").unwrap();
        }
        let loaded = load_store(&db, &stash).unwrap();
        assert!(loaded.get_name(&extra).is_some());
        assert!(loaded.get_name(&user).is_some());
        let attrs = loaded.get_strings(&user).unwrap();
        assert!(
            attrs.iter().any(|(k, v)| k == "m5k" && v == "m5v"),
            "setstr must persist m5k=m5v: {attrs:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ktadd_local_krbtgt_rotates_like_mit() {
        let (mut store, acl) = bootstrap_documented().unwrap();
        let tgt = PrincipalName::krbtgt(krb5_kdc::TEST_REALM);
        store
            .apply_admin_fields(&tgt, Some(KDB_LOCKDOWN_KEYS), None, None, None, None, false)
            .unwrap();
        let before = max_kvno(&store, &tgt);
        let mut n = 0;
        {
            let mut admin = AdminSession::local(&mut store, &acl, documented_admin_id());
            admin
                .ktadd_local(&tgt, true, |kt| {
                    n = kt.entries.len();
                    Ok(())
                })
                .unwrap();
        }
        assert!(n >= 1);
        assert!(max_kvno(&store, &tgt) > before);
    }
}
