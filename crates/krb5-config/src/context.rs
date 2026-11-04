use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use super::{Error, Krb5Conf, init_profile};

// MIT: `k5_os_init_context` (lib/krb5/os/init_os_ctx.c)
#[derive(Debug)]
pub struct ClientContext {
    pub profile: Krb5Conf,
    // MIT: `krb5_us_timeofday` (lib/krb5/os/ustime.c:67-78)
    kdc_offset_valid: AtomicBool,
    kdc_offset: AtomicI64,
    // KRB5CCNAME: read at the first lookup.
    ccname: OnceLock<Option<String>>,
}

impl Clone for ClientContext {
    fn clone(&self) -> Self {
        Self {
            profile: self.profile.clone(),
            kdc_offset_valid: AtomicBool::new(self.kdc_offset_valid.load(Ordering::Relaxed)),
            kdc_offset: AtomicI64::new(self.kdc_offset.load(Ordering::Relaxed)),
            ccname: self.ccname.clone(),
        }
    }
}

impl Default for ClientContext {
    fn default() -> Self {
        Self::new(Krb5Conf::new())
    }
}

impl ClientContext {
    #[must_use]
    pub fn new(profile: Krb5Conf) -> Self {
        Self {
            profile,
            kdc_offset_valid: AtomicBool::new(false),
            kdc_offset: AtomicI64::new(0),
            ccname: OnceLock::new(),
        }
    }

    pub fn from_env() -> Result<Self, Error> {
        Ok(Self::new(init_profile()?))
    }

    pub fn note_kdc_offset(&self, seconds: i64) {
        if self.kdc_offset_valid.load(Ordering::Relaxed) {
            return;
        }
        self.set_kdc_offset(seconds);
    }

    pub fn set_kdc_offset(&self, seconds: i64) {
        self.kdc_offset.store(seconds, Ordering::Relaxed);
        self.kdc_offset_valid.store(true, Ordering::Relaxed);
    }

    #[must_use]
    pub fn kdc_offset(&self) -> Option<i64> {
        self.kdc_offset_valid
            .load(Ordering::Relaxed)
            .then(|| self.kdc_offset.load(Ordering::Relaxed))
    }

    // MIT: `krb5_cc_default_name` (lib/krb5/os/ccdefname.c)
    pub fn ccname(&self) -> Option<&str> {
        self.ccname.get_or_init(|| env("KRB5CCNAME")).as_deref()
    }

    #[must_use]
    pub fn ktname(&self) -> Option<String> {
        env("KRB5_KTNAME")
    }

    #[must_use]
    pub fn client_ktname(&self) -> Option<String> {
        env("KRB5_CLIENT_KTNAME")
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var_os(name).map(|v| v.to_string_lossy().into_owned())
}
