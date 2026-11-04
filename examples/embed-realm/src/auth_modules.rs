//! Example `kadm5_auth` modules (after MIT's `plugins/kadm5_auth/test/main.c`) that decide on
//! principal names, since this interface passes names, not the mask/policy/value. README has why.

use std::sync::Arc;

use krb5_admin::{Decision, Kadm5Auth};
use krb5_kdc::Restrictions;

/// Allows reading a `guest-*` principal; never denies.
pub struct Welcomer;

impl Kadm5Auth for Welcomer {
    fn name(&self) -> &'static str {
        "welcomer"
    }
    fn getprinc(&self, _client: &str, target: &str) -> Decision {
        if target.starts_with("guest-") {
            Decision::Allow
        } else {
            Decision::Abstain
        }
    }
}

/// Denies every write to a `deny-*` principal, over the ACL.
pub struct Bouncer;

impl Bouncer {
    fn blocked(target: &str) -> Decision {
        if target.starts_with("deny-") {
            Decision::Deny
        } else {
            Decision::Abstain
        }
    }
}

impl Kadm5Auth for Bouncer {
    fn name(&self) -> &'static str {
        "bouncer"
    }
    fn addprinc(&self, _client: &str, target: &str) -> (Decision, Option<Restrictions>) {
        (Self::blocked(target), None)
    }
    fn modprinc(&self, _client: &str, target: &str) -> (Decision, Option<Restrictions>) {
        (Self::blocked(target), None)
    }
    fn delprinc(&self, _client: &str, target: &str) -> Decision {
        Self::blocked(target)
    }
    fn setstr(&self, _client: &str, target: &str) -> Decision {
        Self::blocked(target)
    }
}

/// The modules this example registers, for `[plugins] kadm5_auth` to select.
#[must_use]
pub fn example_modules() -> Vec<Arc<dyn Kadm5Auth>> {
    vec![Arc::new(Welcomer), Arc::new(Bouncer)]
}
