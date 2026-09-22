//! Cargo emits `debug/krb5-forge-tgt` when this package's integration
//! test names that bin. `krb5-kdc`'s kdcpolicy test runs the binary.
//! There is no `#[test]` here, so the nextest id list does not grow.

const _: &str = env!("CARGO_BIN_EXE_krb5-forge-tgt");
