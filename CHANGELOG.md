# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project uses semantic versioning once a crate is published.

## [Unreleased]

### Added

- AD PAC: MS-RPCE NDR32 `KERB_VALIDATION_INFO` in field-encounter
  referent order. Golden `tests/traces/pac-kbruser.ndr` (kbruser /
  kbrgroup / ADKERBER SID) re-encodes byte-identically. Server checksum
  usage 17 verifies against the lab `svc.keytab` when present.
- PAC signatures 6, 7, 16 (`PAC_TICKET_CHECKSUM`), 19
  (`PAC_FULL_CHECKSUM`). `ulType` 12 is UPN/DNS; 16 is the ticket
  checksum. Issued tickets self-verify all four with the local krbtgt.
- `PA-SUPPORTED-ENCTYPES` bits follow keys on the principal (not a
  static `0x18`).
- GSS wrap send-side RRC=16 (RFC 4121).
- Runtime-mutable `SharedStore` (`RwLock`) so kadmind/kpasswd mutations
  reach stash/db. The KDC reloads the db when mtime/length changes.
  Privilege drop is skipped when a shared persist db is configured
  (kadmind writes 0600 files the dropped user could not re-read).
  `krb5-kadmind` ONC RPC program 2112 / AUTH_GSSAPI flavor 300001:
  MIT 1.22.2 `kadmin` `addprinc`/`cpw`/`getprinc`/`listprincs`/
  `modprinc`/`cpw -randkey`/`ktadd`/`delprinc` then `kinit` is gated
  by `scripts/kadmin-gate.sh`. `getprinc` encodes `mod_name` (MIT
  unparses it; a NULL modifier is `KRB5_PARSE_MALFORMED`).
  `listprincs` is MIT `xdr_gprincs_ret` (count, then `xdr_array` of
  `xdr_nullstring`). Version-1 AP-REQ framing remains for
  library tests. RFC 3244 kpasswd on UDP/TCP 464 (`kadmin/changepw`):
  MIT 1.22.2 `kpasswd` then `kinit` is gated by
  `scripts/kpasswd-gate.sh`. KRB-PRIV uses the authenticator subkey
  when present; success replies include AP-REP. kprop dump encrypts
  with the existing shared stash (never a throwaway master) and is
  proven over a real TCP socket (`kprop_tcp_replica_issues_as_with_shared_stash`).
  `krb5-kpropd` on TCP 754: MIT `sendauth` version `kprop5_01`, KRB-SAFE
  dump size (MIT checksums the full KRB-SAFE with a dummy checksum),
  `initivector` then KRB-PRIV 32768-byte dump-v7 chunks. MIT `kprop`
  then MIT `kinit user` is gated by `scripts/kprop-gate.sh`. Rust→MIT
  `kpropd` is not gated. A kadmind `addprinc` survives killing
  `krb5-kdc` by `/proc/PID/comm` and relaunching
  (`scripts/restart-gate.sh`).
- RFC 8636 SHA-256 PKINIT KDF on the KDC issue path when AuthPack
  `supportedKDFs` includes `id-pkinit-kdf-ah-sha256`: `kdf` is set in
  `DHRepInfo` and the reply key is `SHA-256(counter||Z||OtherInfo)`.
  MIT 1.22.2 `kinit` TRACE `PKINIT used KDF 2B06010502030602`. Without
  `supportedKDFs` the KDC still uses RFC 4556 `octetstring2key`.
- FILE ccache parser skips MIT `X-CACHECONF` etype 0 so AD `ad.ccache`
  tickets remain readable.
- In-tree TGS referral hop for `krbtgt/AD.KERBER.TEST`. Live
  bidirectional `AD.KERBER.TEST`↔`KERBER.TEST` host tickets
  (`scripts/ad-mit-trust-gate.sh`): Windows TDO inbound/outbound AES
  keys are both loaded. Referral TGTs carry a PAC signed with the
  inter-realm key (`scripts/samba-crossrealm-gate.sh` both directions).
  TGS verifies a presented TGT PAC with the key that opened the ticket
  and copies LOGON_INFO into the issued service PAC (foreign SID/RID
  survive; corrupt server or type-16 checksum is `KRB_AP_ERR_BAD_INTEGRITY`).
  Type-16 is over the original decrypted EncTicketPart bytes with PAC
  ad-data a single zero (not a rasn re-encode). Foreign TGTs check the
  server checksum plus type-16; KDC/19 use the issuing krbtgt. A TGT
  without a PAC still issues (MIT). `kvno` success is not that copy proof.
- `scripts/prod-gate.sh` drives shipped `krb5-kinit` against
  `127.0.0.1:18888`, requires `kdc.issue` JSON with `correlation_id`,
  and archives a PDU pcap. Heimdal and SSPI gates record unavailability.
- Live AD S4U2Self/S4U2Proxy: `scripts/ad-s4u-gate.sh` (`kvno -U` /
  `kvno -U -P`, client `kbruser@AD.KERBER.TEST`).
- MIT `kvno -U` / `-U -P` against the **Rust** KDC
  (`scripts/s4u-mit-gate.sh`, in CI); S4U2Proxy copies the evidence PAC,
  requires a forwardable evidence ticket, and denies classic constrained
  delegation unless `s4u_allowed_to` lists the target (and RBCD unless
  `s4u_allowed_from` lists the evidence server). PA-FOR-USER accepts
  HMAC-MD5-ARCFOUR (cksumtype -138) on AES session keys.
- `bounded_stress_handle_request` asserts 64 concurrent valid AS+TGS
  succeed. Harness CI runs `kadmin-gate`, `kpasswd-gate`, `kdb-dump-gate`,
  `kprop-gate`, `restart-gate`, `prod-gate`, `s4u-mit-gate`,
  `samba-ad-gate`, `samba-pac-verify-gate` (Samba IDL decode of a Rust PAC),
  `samba-pac-l2-gate` (Samba kcrypto validates PAC 6/7/16/19; a flipped MAC
  fails), `samba-crossrealm-gate` (MIT `kvno` both directions vs Samba), and
  `samba-realtrust-gate` (peer DC + `samba-tool domain trust create`; reverse
  PAC RID 1103).
  `samba-ad-gate.sh` exits 2 unless a live Samba/AD `kinit`/`kvno`
  succeeds (no fabricated pass from “image exists”).
- MIT `kdb5_util` dump/load (version 7; `-r18` is version 6):
  `krb5-kdb load`/`dump`, KDB usage-0 `key_data` with a cleartext
  `int16_LE` length prefix, master key string-to-key of
  `masterpassword` with salt `KERBER.TESTKM` and etype 20. Golden
  `tests/traces/kdb/mit-dump-v7.txt`. Gate `scripts/kdb-dump-gate.sh`
  (MIT `kinit` both directions). Protocol `KeyUsage::new(0)` still
  rejected. KDB3 persist remains the internal at-rest format.

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

### Previously added

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
  two-realm `kvno` are gated; AD PAC NDR is golden-gated; MIT `kadmin`
  AUTH_GSSAPI add/get/list/mod/chrand/del is gated
  (`scripts/kadmin-gate.sh`).
  `KRB5_CONFIG` / `KRB5_KDC_PROFILE` / `/etc/krb5.conf` /
  `/etc/krb5kdc/kdc.conf` are consumed when present.
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
- Persistence is stash/db with a runtime-mutable `RwLock` store. GSS
  first-seq matches the AP-REQ authenticator; wrap/MIC use a windowed
  replay cache. Production wrap emits RRC=16.

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
