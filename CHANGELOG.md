# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses semantic versioning once a crate is published.

## [Unreleased]

### Security

- PKINIT `cms_verify` is mandatory against a provisioned CA; forged CMS
  is `PREAUTH_FAILED` (no `cms_unwrap` fallback). The PKINIT CA is
  opt-in, not auto-generated.
- GSS OID length is bound-checked (hostile tokens return Truncated).
- GSS acceptor requires `expected_server` / `expected_realm`.
- TCP workers use an RAII slot plus `catch_unwind`.
- Request-path realms use `try_ascii` (non-ASCII → KRB-ERROR).
- `--test-realm` reads passwords from `KRB5_TEST_*_PASSWORD` (not
  compiled into the binary). Network crates deny `unwrap`/`expect`/`panic`.

### Added

- Phase 0–8 audit work: honest CI oracles (`client-gate`, `kdc-gate`,
  bidirectional Rust↔Rust), `cargo audit`/`deny`, MSRV 1.85, `--release`
  tests, `cargo doc`.
- RFC 4120 TicketFlags INITIAL=9 / PRE-AUTHENT=10; every KDC request
  yields a KRB-ERROR; AS-REP enc-part APPLICATION 25; TGS checksum,
  replay, TGT check, `KDC_ERR_ETYPE_NOSUPP` (14).
- Keytab/ccache atomic 0600 writes; AP-REQ skew/expiry/server-name;
  bounded shared replay caches; UDP `send_to`/`recv_from` with source
  filter; configurable bind (no silent `0.0.0.0`); `--test-realm` vs
  persistent DB.
- `krb5-config` (`krb5.conf`/`kdc.conf`/env/SRV), ccache reader,
  keytab v1/merge, AP-REP / KRB-SAFE / PRIV / CRED, PRF/PRF+,
  `krb5-gss` RFC 4121 wrap/unwrap/MIC with channel bindings,
  `krb5-admin` ACL-enforced kadmind
  equivalent, persist+stash, kpasswd (kvno bump + multi-kvno),
  FAST `PA-FX-FAST` CHOICE + armor/cookie/strengthen, SPAKE2-P256 (MIT `wbytes` / K'[n] / group 2),
  PKINIT Oakley MODP 2048/4096 + ECDH P-256 inside CMS SignedData with a
  test CA (`pkinit_anchors` FILE PEM) and ECDSA-SHA256, PAC with NDR logon-info,
  S4U2Self/S4U2Proxy/U2U, cross-realm referrals/transited, ktadd of
  all kvnos, kprop dump/load, weak etypes behind `allow_weak_crypto`.

### Fixed

- Hostile/non-ASCII/`i32::MIN` keytab no longer panics.
- Wrong password answers `KDC_ERR_PREAUTH_FAILED` instead of dropping.
- Layering: KDC no longer depends on the client crate for keytabs.
- Client UDP no longer uses `connect()` (MIT TGS replies were dropped);
  AS-REP enc-part is decoded as RFC APPLICATION 25, with MIT tag 26
  only when the plaintext starts with `0x7a`.
- KDC TCP worker cap, privilege drop after bind :88, and SIGTERM/SIGINT
  shutdown. GSS wrap tokens use the RFC 4121 16-byte header; SPNEGO
  uses long-form DER length. PKINIT CMS includes an X.509 test cert.

### Changed

- `clippy::pedantic` is a workspace deny; noisy lints (rasn bindings,
  rustdoc RFC vocabulary, long issue/TGS functions) stay allowed.
- PRF+ prepends the RFC 6113 counter; RFC 8009 PRF emits the full
  SHA-2 output; Camellia uses the `camellia`+`cmac` crates and Camellia
  ECB for PRF (not AES); RC4 uses the RFC 4757 usage map; PAC checksums
  use usage 17; SPAKE P-256 group id is 2.
- KRB-SAFE/PRIV/CRED unwrap consults `ReplayCache` and a 300s timestamp
  window; SAFE/PRIV builders increment `seq_number`.
- Docs: MIT `kinit` PKINIT, SPAKE (`pa_type` 151), FAST TGS `kvno`, and
  two-realm `kvno` are gated; PAC/Camellia remain unit-gated; kadmind
  RPC is not implemented. `KRB5_CONFIG` / `KRB5_KDC_PROFILE` /
  `/etc/krb5.conf` / `/etc/krb5kdc/kdc.conf` are consumed when present.
- `pkinit-gate.sh` fails when MIT PKINIT interop fails; `cargo-deny`
  is blocking in CI.
- `KERBER_CAPTURE_DIR` writes raw PDUs. Checked-in `tests/traces/mit-*.der`
  are decoded and **byte-diffed** (`encode(decode(raw)) == raw`) against
  the shipped encoder in unit CI (`golden_traces.rs`). Reply goldens are
  MIT-KDC bytes from `client-gate.sh`. AD lab coordinates: `docs/ad-lab.md`.
- RFC 6803 Camellia uses KDF-FEEDBACK-CMAC (not RFC 3961 n-fold DK).
  RFC 3961 3DES s2k uses 168-fold + random-to-key. Published KATs live
  in `krb5-crypto/tests/known_answer.rs`.
- `cargo fuzz` targets under `fuzz/` (CI smoke ~60s each).
- `krb5-config` / `krb5-types` / `krb5-crypto` deny `unwrap`/`expect`/`panic`.
- krbtgt and host principals carry RFC 8009 keys; `sha2-gate.sh` is a
  live MIT `kinit`/`kvno` forcing aes256-cts-hmac-sha384-192.
- Persistence is embed-only (the daemon cannot mutate `Arc<PrincipalStore>`
  at runtime). GSS first-seq matches the AP-REQ authenticator; wrap/MIC
  use a windowed replay cache. Send-side RRC≠0 / SSPI is AD-round pending.

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
