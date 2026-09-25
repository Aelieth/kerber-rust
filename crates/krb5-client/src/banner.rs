//! Key-expiry banner. `krb5-kinit` prints the line; this module does not.

use std::sync::Mutex;

static HOOK: Mutex<Option<fn()>> = Mutex::new(None);

/// Install the function `krb5-kinit` uses to write the key-expiry banner.
///
/// The library calls it and does not write that line itself.
pub fn set_key_exp_banner_hook(hook: fn()) {
    *HOOK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(hook);
}

pub(crate) fn emit_key_exp_banner() {
    let hook = *HOOK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(hook) = hook {
        hook();
    }
}
