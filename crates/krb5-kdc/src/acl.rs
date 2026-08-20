//! kadm5.acl-style allow/deny for mutating admin operations.

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
    /// `i` (inquire / extract) / `*`
    pub inquire: bool,
    /// `c` (changepw) / `*`
    pub changepw: bool,
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
                changepw: all || perms.contains('c'),
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
                changepw: true,
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
                AdminOp::Ktadd => e.inquire,
                AdminOp::ChangePassword => e.changepw,
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
}

fn op_name(op: AdminOp) -> &'static str {
    match op {
        AdminOp::Create => "create",
        AdminOp::Delete => "delete",
        AdminOp::Ktadd => "ktadd",
        AdminOp::ChangePassword => "cpw",
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
