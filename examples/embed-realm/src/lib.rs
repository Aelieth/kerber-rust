//! Shared modules for the `krb5-otp-kdc` binary: the TOTP verifier and the `require_mfa` policy.

#![forbid(unsafe_code)]

pub mod require_mfa;
pub mod totp;
