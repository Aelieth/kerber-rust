//! kadm5_auth: MIT's kadmin authorization interface, with the built-in `acl` and `self`
//! modules. Every authorization site routes through one [`AuthStack`]; a request is
//! authorized when at least one module allows it and none deny it.

use krb5_kdc::{Acl, AdminOp, Restrictions};
use krb5_types::{principal_compare, principal_from_unparsed};

/// A module's answer for one request: MIT's `0` / `KRB5_PLUGIN_NO_HANDLE` / other code.
// MIT: `kadm5_auth_addprinc_fn` (include/krb5/kadm5_auth_plugin.h)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    Allow,
    Abstain,
    /// A built-in module only allows or abstains; an explicit denial stops the stack.
    #[allow(dead_code)]
    Deny,
}

/// One kadm5_auth module. Each method abstains by default, as an unset MIT vtable slot does.
/// `client` and the principal arguments are unparsed names (`name@REALM`); the target is the
/// canonical principal taken from the fetched record.
pub trait Kadm5Auth: Send + Sync {
    fn addprinc(&self, _client: &str, _target: &str) -> (Decision, Option<Restrictions>) {
        (Decision::Abstain, None)
    }
    fn modprinc(&self, _client: &str, _target: &str) -> (Decision, Option<Restrictions>) {
        (Decision::Abstain, None)
    }
    fn setstr(&self, _client: &str, _target: &str) -> Decision {
        Decision::Abstain
    }
    fn cpw(&self, _client: &str, _target: &str) -> Decision {
        Decision::Abstain
    }
    fn chrand(&self, _client: &str, _target: &str) -> Decision {
        Decision::Abstain
    }
    fn setkey(&self, _client: &str, _target: &str) -> Decision {
        Decision::Abstain
    }
    fn purgekeys(&self, _client: &str, _target: &str) -> Decision {
        Decision::Abstain
    }
    fn delprinc(&self, _client: &str, _target: &str) -> Decision {
        Decision::Abstain
    }
    fn renprinc(&self, _client: &str, _src: &str, _dest: &str) -> Decision {
        Decision::Abstain
    }
    fn getprinc(&self, _client: &str, _target: &str) -> Decision {
        Decision::Abstain
    }
    fn getstrs(&self, _client: &str, _target: &str) -> Decision {
        Decision::Abstain
    }
    fn extract(&self, _client: &str, _target: &str) -> Decision {
        Decision::Abstain
    }
    fn listprincs(&self, _client: &str) -> Decision {
        Decision::Abstain
    }
    fn addpol(&self, _client: &str, _policy: &str) -> Decision {
        Decision::Abstain
    }
    fn modpol(&self, _client: &str, _policy: &str) -> Decision {
        Decision::Abstain
    }
    fn delpol(&self, _client: &str, _policy: &str) -> Decision {
        Decision::Abstain
    }
    /// `client_policy` is the caller's own policy name, looked up in the caller's realm.
    fn getpol(&self, _client: &str, _policy: &str, _client_policy: Option<&str>) -> Decision {
        Decision::Abstain
    }
    fn listpols(&self, _client: &str) -> Decision {
        Decision::Abstain
    }
    fn iprop(&self, _client: &str) -> Decision {
        Decision::Abstain
    }
    fn addalias(&self, _client: &str, _alias: &str, _target: &str) -> Decision {
        Decision::Abstain
    }
}

fn allow_if(ok: bool) -> Decision {
    if ok {
        Decision::Allow
    } else {
        Decision::Abstain
    }
}

/// The built-in `acl` module: `kadm5.acl`, wrapping [`Acl`]. It allows or abstains, never denies.
// MIT: `kadm5_auth_acl_initvt` (kadmin/server/auth_acl.c)
pub struct AclModule<'a>(pub &'a Acl);

impl Kadm5Auth for AclModule<'_> {
    fn addprinc(&self, client: &str, target: &str) -> (Decision, Option<Restrictions>) {
        if self.0.allows(client, AdminOp::Create, Some(target)) {
            (
                Decision::Allow,
                self.0.restrictions(client, Some(target)).cloned(),
            )
        } else {
            (Decision::Abstain, None)
        }
    }
    fn modprinc(&self, client: &str, target: &str) -> (Decision, Option<Restrictions>) {
        if self.0.allows(client, AdminOp::Modify, Some(target)) {
            (
                Decision::Allow,
                self.0.restrictions(client, Some(target)).cloned(),
            )
        } else {
            (Decision::Abstain, None)
        }
    }
    fn setstr(&self, client: &str, target: &str) -> Decision {
        allow_if(self.0.allows(client, AdminOp::Modify, Some(target)))
    }
    fn cpw(&self, client: &str, target: &str) -> Decision {
        allow_if(self.0.allows(client, AdminOp::ChangePassword, Some(target)))
    }
    fn chrand(&self, client: &str, target: &str) -> Decision {
        allow_if(self.0.allows(client, AdminOp::ChangePassword, Some(target)))
    }
    fn setkey(&self, client: &str, target: &str) -> Decision {
        allow_if(self.0.allows(client, AdminOp::SetKey, Some(target)))
    }
    fn purgekeys(&self, client: &str, target: &str) -> Decision {
        allow_if(self.0.allows(client, AdminOp::Modify, Some(target)))
    }
    fn delprinc(&self, client: &str, target: &str) -> Decision {
        allow_if(self.0.allows(client, AdminOp::Delete, Some(target)))
    }
    // MIT: `acl_renprinc` (kadmin/server/auth_acl.c)
    fn renprinc(&self, client: &str, src: &str, dest: &str) -> Decision {
        allow_if(
            self.0.allows(client, AdminOp::Delete, Some(src))
                && self.0.allows(client, AdminOp::Create, Some(dest))
                && self.0.restrictions(client, Some(dest)).is_none(),
        )
    }
    fn getprinc(&self, client: &str, target: &str) -> Decision {
        allow_if(self.0.allows(client, AdminOp::Inquire, Some(target)))
    }
    fn getstrs(&self, client: &str, target: &str) -> Decision {
        allow_if(self.0.allows(client, AdminOp::Inquire, Some(target)))
    }
    fn extract(&self, client: &str, target: &str) -> Decision {
        allow_if(self.0.allows(client, AdminOp::Extract, Some(target)))
    }
    fn listprincs(&self, client: &str) -> Decision {
        allow_if(self.0.allows(client, AdminOp::List, None))
    }
    fn addpol(&self, client: &str, _policy: &str) -> Decision {
        allow_if(self.0.allows(client, AdminOp::Create, None))
    }
    fn modpol(&self, client: &str, _policy: &str) -> Decision {
        allow_if(self.0.allows(client, AdminOp::Modify, None))
    }
    fn delpol(&self, client: &str, _policy: &str) -> Decision {
        allow_if(self.0.allows(client, AdminOp::Delete, None))
    }
    fn getpol(&self, client: &str, _policy: &str, _client_policy: Option<&str>) -> Decision {
        allow_if(self.0.allows(client, AdminOp::Inquire, None))
    }
    fn listpols(&self, client: &str) -> Decision {
        allow_if(self.0.allows(client, AdminOp::List, None))
    }
    fn iprop(&self, client: &str) -> Decision {
        allow_if(self.0.allows(client, AdminOp::Propagate, None))
    }
    // MIT: `acl_addalias` (kadmin/server/auth_acl.c)
    fn addalias(&self, client: &str, alias: &str, target: &str) -> Decision {
        allow_if(
            self.0.allows(client, AdminOp::Create, Some(alias))
                && self.0.restrictions(client, Some(alias)).is_none()
                && self.0.allows(client, AdminOp::Modify, Some(target)),
        )
    }
}

fn is_same_principal(client: &str, target: &str) -> bool {
    match (
        principal_from_unparsed(client, ""),
        principal_from_unparsed(target, ""),
    ) {
        (Ok((cn, cr)), Ok((tn, tr))) => principal_compare(&cn, &cr, &tn, &tr),
        _ => false,
    }
}

/// The built-in `self` module: a principal may operate on itself.
// MIT: `kadm5_auth_self_initvt` (kadmin/server/auth_self.c)
pub struct SelfModule;

impl Kadm5Auth for SelfModule {
    // MIT: `self_compare` (kadmin/server/auth_self.c)
    fn cpw(&self, client: &str, target: &str) -> Decision {
        allow_if(is_same_principal(client, target))
    }
    fn chrand(&self, client: &str, target: &str) -> Decision {
        allow_if(is_same_principal(client, target))
    }
    fn purgekeys(&self, client: &str, target: &str) -> Decision {
        allow_if(is_same_principal(client, target))
    }
    fn getprinc(&self, client: &str, target: &str) -> Decision {
        allow_if(is_same_principal(client, target))
    }
    fn getstrs(&self, client: &str, target: &str) -> Decision {
        allow_if(is_same_principal(client, target))
    }
    // MIT: `self_getpol` (kadmin/server/auth_self.c)
    fn getpol(&self, _client: &str, policy: &str, client_policy: Option<&str>) -> Decision {
        allow_if(client_policy == Some(policy))
    }
}

/// The ordered stack of kadm5_auth modules for one request: `acl` first, then `self`.
pub struct AuthStack<'a> {
    modules: Vec<Box<dyn Kadm5Auth + 'a>>,
}

impl<'a> AuthStack<'a> {
    /// The built-in stack: `acl` first, then `self`, as MIT registers them.
    // MIT: `auth_init` (kadmin/server/auth.c:62-128)
    #[must_use]
    pub fn builtin(acl: &'a Acl) -> Self {
        Self {
            modules: vec![Box::new(AclModule(acl)), Box::new(SelfModule)],
        }
    }

    // MIT: `auth` (kadmin/server/auth.c:181-202)
    fn combine(&self, f: impl Fn(&dyn Kadm5Auth) -> Decision) -> bool {
        let mut authorized = false;
        for m in &self.modules {
            match f(m.as_ref()) {
                Decision::Allow => authorized = true,
                Decision::Deny => return false,
                Decision::Abstain => {}
            }
        }
        authorized
    }

    // MIT: `auth_restrict` (kadmin/server/auth.c:267-304)
    fn combine_restrict(
        &self,
        f: impl Fn(&dyn Kadm5Auth) -> (Decision, Option<Restrictions>),
    ) -> (bool, Vec<Restrictions>) {
        let mut authorized = false;
        let mut rss = Vec::new();
        for m in &self.modules {
            let (d, rs) = f(m.as_ref());
            if let Some(rs) = rs {
                rss.push(rs);
            }
            match d {
                Decision::Allow => authorized = true,
                Decision::Deny => return (false, rss),
                Decision::Abstain => {}
            }
        }
        (authorized, rss)
    }

    #[must_use]
    pub fn addprinc(&self, client: &str, target: &str) -> (bool, Vec<Restrictions>) {
        self.combine_restrict(|m| m.addprinc(client, target))
    }
    #[must_use]
    pub fn modprinc(&self, client: &str, target: &str) -> (bool, Vec<Restrictions>) {
        self.combine_restrict(|m| m.modprinc(client, target))
    }
    #[must_use]
    pub fn setstr(&self, client: &str, target: &str) -> bool {
        self.combine(|m| m.setstr(client, target))
    }
    #[must_use]
    pub fn cpw(&self, client: &str, target: &str) -> bool {
        self.combine(|m| m.cpw(client, target))
    }
    #[must_use]
    pub fn chrand(&self, client: &str, target: &str) -> bool {
        self.combine(|m| m.chrand(client, target))
    }
    #[must_use]
    pub fn setkey(&self, client: &str, target: &str) -> bool {
        self.combine(|m| m.setkey(client, target))
    }
    #[must_use]
    pub fn purgekeys(&self, client: &str, target: &str) -> bool {
        self.combine(|m| m.purgekeys(client, target))
    }
    #[must_use]
    pub fn delprinc(&self, client: &str, target: &str) -> bool {
        self.combine(|m| m.delprinc(client, target))
    }
    #[must_use]
    pub fn renprinc(&self, client: &str, src: &str, dest: &str) -> bool {
        self.combine(|m| m.renprinc(client, src, dest))
    }
    #[must_use]
    pub fn getprinc(&self, client: &str, target: &str) -> bool {
        self.combine(|m| m.getprinc(client, target))
    }
    #[must_use]
    pub fn getstrs(&self, client: &str, target: &str) -> bool {
        self.combine(|m| m.getstrs(client, target))
    }
    #[must_use]
    pub fn extract(&self, client: &str, target: &str) -> bool {
        self.combine(|m| m.extract(client, target))
    }
    #[must_use]
    pub fn listprincs(&self, client: &str) -> bool {
        self.combine(|m| m.listprincs(client))
    }
    #[must_use]
    pub fn addpol(&self, client: &str, policy: &str) -> bool {
        self.combine(|m| m.addpol(client, policy))
    }
    #[must_use]
    pub fn modpol(&self, client: &str, policy: &str) -> bool {
        self.combine(|m| m.modpol(client, policy))
    }
    #[must_use]
    pub fn delpol(&self, client: &str, policy: &str) -> bool {
        self.combine(|m| m.delpol(client, policy))
    }
    #[must_use]
    pub fn getpol(&self, client: &str, policy: &str, client_policy: Option<&str>) -> bool {
        self.combine(|m| m.getpol(client, policy, client_policy))
    }
    #[must_use]
    pub fn listpols(&self, client: &str) -> bool {
        self.combine(|m| m.listpols(client))
    }
    #[must_use]
    pub fn iprop(&self, client: &str) -> bool {
        self.combine(|m| m.iprop(client))
    }
    #[must_use]
    pub fn addalias(&self, client: &str, alias: &str, target: &str) -> bool {
        self.combine(|m| m.addalias(client, alias, target))
    }
}
