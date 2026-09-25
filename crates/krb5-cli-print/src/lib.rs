//! Slots for the two CLI stderr lines that used to be printed in libraries.
//!
//! `krb5-kinit` and `krb5-kadmind` install the printers. Until one is
//! installed, the library call writes nothing.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Mutex;

static KEY_EXP_BANNER: Mutex<Option<fn()>> = Mutex::new(None);
static KADM5_ERROR: Mutex<Option<fn(&str)>> = Mutex::new(None);

/// Install the key-expiry banner printer.
pub fn set_key_exp_banner_hook(hook: fn()) {
    *KEY_EXP_BANNER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(hook);
}

/// Write the key-expiry banner if `krb5-kinit` installed a printer.
pub fn emit_key_exp_banner() {
    let hook = *KEY_EXP_BANNER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(hook) = hook {
        hook();
    }
}

/// Install the `kadm5:` error printer.
pub fn set_kadm5_error_hook(hook: fn(&str)) {
    *KADM5_ERROR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(hook);
}

/// Write `kadm5: {error}` if `krb5-kadmind` installed a printer.
pub fn emit_kadm5_error(msg: &str) {
    let hook = *KADM5_ERROR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(hook) = hook {
        hook(msg);
    }
}
