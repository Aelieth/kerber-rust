//! Harness-only tools for the gates.
//!
//! The binaries in this crate drive tests. They are not a product surface: each requires
//! `krb5-kdc/test-hooks`, so a release build has none of them.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
