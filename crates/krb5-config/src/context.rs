use std::sync::OnceLock;

use super::{Error, Krb5Conf, init_profile};

/// A client program's profile, read once when the program starts, and the cache name its
/// environment gave at the first lookup.
// MIT k5_os_init_context; see docs/parity/b1-client.md
#[derive(Clone, Debug)]
pub struct ClientContext {
    /// The profile; [`Krb5Conf::new`]'s defaults when no file is there.
    pub profile: Krb5Conf,
    /// `KRB5CCNAME`, read at the first default-cache lookup.
    ccname: OnceLock<Option<String>>,
}

impl Default for ClientContext {
    fn default() -> Self {
        Self::new(Krb5Conf::new())
    }
}

impl ClientContext {
    /// A context over a profile the caller holds; no file is read.
    #[must_use]
    pub fn new(profile: Krb5Conf) -> Self {
        Self {
            profile,
            ccname: OnceLock::new(),
        }
    }

    /// The context a program makes when it starts: [`init_profile`]'s profile.
    pub fn from_env() -> Result<Self, Error> {
        Ok(Self::new(init_profile()?))
    }

    /// `KRB5CCNAME` as the context's first lookup read it.
    // MIT krb5_cc_default_name; see docs/parity/b1-client.md
    pub fn ccname(&self) -> Option<&str> {
        self.ccname.get_or_init(|| env("KRB5CCNAME")).as_deref()
    }

    /// `KRB5_KTNAME`, read at each call.
    #[must_use]
    pub fn ktname(&self) -> Option<String> {
        env("KRB5_KTNAME")
    }

    /// `KRB5_CLIENT_KTNAME`, read at each call.
    #[must_use]
    pub fn client_ktname(&self) -> Option<String> {
        env("KRB5_CLIENT_KTNAME")
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var_os(name).map(|v| v.to_string_lossy().into_owned())
}
