//! kadm5.acl-style allow/deny for admin operations.

use crate::error::Error;

/// Mutating admin operations gated by the ACL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminOp {
    /// Add a principal.
    Create,
    /// Delete a principal.
    Delete,
    /// Export a keytab (`ktadd`).
    Ktadd,
    /// Change a password (`kpasswd` / kadm5 `c`).
    ChangePassword,
    /// Inquire (`getprinc` / `listprincs` / kadm5 `i`).
    Inquire,
    /// Extract keys (`ktadd -norandkey` / kadm5 `e`). Not implied by `*`/`x`.
    Extract,
    /// Modify attributes (`modprinc` / kadm5 `m`).
    Modify,
    /// List principals/policies (kadm5 `l`).
    List,
    /// Incremental/full dump propagation (kadm5 `p`).
    Propagate,
}

/// One ACL line: a principal pattern and permission flags.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AclEntry {
    /// Exact `name@REALM` (no glob in this increment except a trailing `*`).
    pub principal: String,
    /// `a` / `*`
    pub add: bool,
    /// `d` / `*`
    pub delete: bool,
    /// `i` (inquire) / `*`
    pub inquire: bool,
    /// `e` (extract keys). MIT does not include this in `*`/`x`.
    pub extract: bool,
    /// `c` (changepw) / `*`
    pub changepw: bool,
    /// `m` (modify) / `*`
    pub modify: bool,
    /// `l` (list) / `*`
    pub list: bool,
    /// `p` (propagate) / `*`
    pub propagate: bool,
}

/// Ordered ACL; first matching principal wins. Unlisted principals are denied.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Acl {
    entries: Vec<AclEntry>,
}

impl Acl {
    /// Empty deny-all ACL.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse kadm5.acl text (`principal  permissions`).
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut entries = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut bits = line.split_whitespace();
            let Some(principal) = bits.next() else {
                continue;
            };
            let perms = bits.next().unwrap_or("");
            let all = perms.contains('*') || perms.contains('x');
            entries.push(AclEntry {
                principal: principal.to_owned(),
                add: all || perms.contains('a'),
                delete: all || perms.contains('d'),
                inquire: all || perms.contains('i'),
                extract: perms.contains('e'),
                changepw: all || perms.contains('c'),
                modify: all || perms.contains('m'),
                list: all || perms.contains('l'),
                propagate: all || perms.contains('p'),
            });
        }
        Self { entries }
    }

    /// Allow `admin@REALM` every mutating op.
    #[must_use]
    pub fn allow_admin(admin: impl Into<String>) -> Self {
        Self {
            entries: vec![AclEntry {
                principal: admin.into(),
                add: true,
                delete: true,
                inquire: true,
                extract: true,
                changepw: true,
                modify: true,
                list: true,
                propagate: true,
            }],
        }
    }

    /// Check whether `actor` (`name@REALM`) may perform `op`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AclDenied`] when no matching line grants the op.
    pub fn check(&self, actor: &str, op: AdminOp) -> Result<(), Error> {
        for e in &self.entries {
            if !principal_matches(&e.principal, actor) {
                continue;
            }
            let ok = match op {
                AdminOp::Create => e.add,
                AdminOp::Delete => e.delete,
                AdminOp::Inquire => e.inquire,
                AdminOp::Ktadd | AdminOp::Extract => e.extract,
                AdminOp::ChangePassword => e.changepw,
                AdminOp::Modify => e.modify,
                AdminOp::List => e.list,
                AdminOp::Propagate => e.propagate,
            };
            if ok {
                tracing::info!(
                    event = krb5_log::events::KDC_ACL,
                    component = "krb5-kdc",
                    outcome = "ok",
                    actor,
                    op = op_name(op),
                );
                return Ok(());
            }
            break;
        }
        tracing::error!(
            event = krb5_log::events::KDC_ACL,
            component = "krb5-kdc",
            outcome = "error",
            actor,
            op = op_name(op),
            error = "ACL denied",
        );
        Err(Error::AclDenied)
    }

    /// MIT `kadm5_get_privs` mask for `actor` (`KADM5_PRIV_*`, 0 if none).
    #[must_use]
    pub fn privs(&self, actor: &str) -> u32 {
        for e in &self.entries {
            if !principal_matches(&e.principal, actor) {
                continue;
            }
            let mut bits = 0u32;
            if e.inquire {
                bits |= 0x01;
            }
            if e.add {
                bits |= 0x02;
            }
            if e.modify {
                bits |= 0x04;
            }
            if e.delete {
                bits |= 0x08;
            }
            if e.list {
                bits |= 0x10;
            }
            if e.changepw {
                bits |= 0x20;
            }
            if e.extract {
                bits |= 0x40;
            }
            return bits;
        }
        0
    }

    /// kadm5.acl principal glob (`*/admin@REALM`, `host/*@REALM`).
    #[must_use]
    pub fn name_matches(pattern: &str, actor: &str) -> bool {
        principal_matches(pattern, actor)
    }
}

fn op_name(op: AdminOp) -> &'static str {
    match op {
        AdminOp::Create => "create",
        AdminOp::Delete => "delete",
        AdminOp::Ktadd => "ktadd",
        AdminOp::ChangePassword => "cpw",
        AdminOp::Inquire => "inquire",
        AdminOp::Extract => "extract",
        AdminOp::Modify => "modify",
        AdminOp::List => "list",
        AdminOp::Propagate => "propagate",
    }
}

fn principal_matches(pattern: &str, actor: &str) -> bool {
    if pattern == actor {
        return true;
    }
    // `*/admin@REALM` style: wildcard only as a full name component.
    if let (Some((pp, prealm)), Some((ap, arealm))) =
        (pattern.rsplit_once('@'), actor.rsplit_once('@'))
    {
        if prealm != arealm {
            return false;
        }
        if pp == "*" {
            return true;
        }
        let pparts: Vec<&str> = pp.split('/').collect();
        let aparts: Vec<&str> = ap.split('/').collect();
        if pparts.len() != aparts.len() {
            return false;
        }
        pparts.iter().zip(aparts).all(|(p, a)| *p == "*" || *p == a)
    } else {
        false
    }
}
