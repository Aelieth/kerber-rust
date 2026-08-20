# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses semantic versioning once a crate is published.

## [Unreleased]

### Added

- Phase 0–8 audit work: honest CI oracles (`client-gate`, `kdc-gate`,
  bidirectional Rust↔Rust), `cargo audit`/`deny`, MSRV 1.85, `--release`
  tests, `cargo doc`.
- RFC 4120 TicketFlags INITIAL=9 / PRE-AUTHENT=10; every KDC request
  yields a KRB-ERROR; AS-REP enc-part APPLICATION 25; TGS checksum,
  replay, TGT check, `KDC_ERR_ETYPE_NOSUPP` (14).
- Keytab/ccache atomic 0600 writes; AP-REQ skew/expiry/server-name;
  bounded shared replay caches; UDP `connect()`; configurable bind
  (no silent `0.0.0.0`); `--test-realm` vs persistent DB.
- `krb5-config` (`krb5.conf`/`kdc.conf`/env/SRV), ccache reader,
  keytab v1/merge, AP-REP / KRB-SAFE / PRIV / CRED, PRF/PRF+,
  `krb5-gss` wrap/unwrap/MIC, `krb5-admin` ACL-enforced kadmind
  equivalent, persist+stash, kpasswd (kvno bump + multi-kvno),
  FAST armor/cookie/strengthen, SPAKE2-P256, PKINIT ECDH P-256,
  PAC sign/verify on issued tickets, S4U2Self/S4U2Proxy/U2U,
  weak etypes behind `allow_weak_crypto`.

### Fixed

- Hostile/non-ASCII/`i32::MIN` keytab no longer panics.
- Wrong password answers `KDC_ERR_PREAUTH_FAILED` instead of dropping.
- Layering: KDC no longer depends on the client crate for keytabs.

## [0.1.0] - 2026-08-19

### Added

- Dual license Apache-2.0 OR MIT.
- Cargo workspace with `krb5-log`, `krb5-crypto`, `krb5-types`,
  `krb5-asn1`, and `examples/consumer`.
- Structured logging schema (correlation ID, crypto timing, error paths).
- RFC 3961/3962/8009 etypes 17–20: string-to-key, encrypt, decrypt,
  keyed checksum, key-usage derivation, secret zeroization.
- DER encode/decode for RFC 4120 `PrincipalName`, `Realm`,
  `EncryptedData`, `Ticket`, `KDC-REQ`, `KDC-REP`, `AP-REQ`, `KRB-ERROR`.
- Containerized MIT Kerberos 1.22.2 KDC harness and launch scripts.
- Stage 3: `krb5-protocol` AS/TGS over UDP/TCP and `krb5-client` kinit
  writing MIT FILE ccache v4 plus keytab v2. Live gate:
  `scripts/client-gate.sh` (Rust TGT + service ticket; MIT `klist`).
- Stage 5: `krb5-kdc` AS/TGS issue, kadm5.acl-style admin, MIT keytab
  v2 export, AP-REQ verify, UDP/TCP 88 listener. Gate:
  `scripts/kdc-gate.sh` (MIT `kinit` + `kvno` against the Rust KDC).
