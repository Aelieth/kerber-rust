# Stage progress

Promotion through a stage requires the multi-sided tests for that stage
and, once a live component exists, a production-gate run with structured
logs. Unit tests alone do not promote a stage.

| Stage | Content | Status |
| --- | --- | --- |
| 1 | Foundation, inventory, MIT 1.22.2 harness, logging schema | **In tree** |
| 2 | Crypto primitives + ASN.1/DER core, KATs, parser negative tests | **In tree** (etypes 17–20, RFC 4120 core PDUs) |
| 3 | Protocol library + minimal client (AS/TGS), ccache/keytab, first live MIT production gate | **In tree** (`krb5-protocol`, `krb5-client`; gate: `scripts/client-gate.sh`) |
| 4 | Higher-level client, GSS-API/SPNEGO (RFC 4121) | **In tree** (`krb5-gss` wrap/unwrap/MIC, SPNEGO framing; MIT GSS is out-of-process) |
| 5 | KDC core (AS+TGS) + database backend, bidirectional interop | **In tree** (in-memory + KDB3 persist/stash fallback; MIT `kdb5_util` dump/load textual codec; ACL; AP-REQ; gates: `kdc-gate.sh`, `bidirectional-gate.sh`, `kdb-dump-gate.sh`). MIT `kinit` both directions is the database oracle. |
| 6 | Admin tools, plugins, propagation, remaining parity | **In tree** (`krb5-admin` ACL-enforced session, ktadd of all kvnos, kpasswd with kvno rotation, kprop dump/load, inter-realm krbtgt + transited). Kadmind AUTH_GSSAPI 300001 gated by MIT `kadmin` add/get/list/mod/chrand/del. MIT `kpasswd` gated by `scripts/kpasswd-gate.sh`. |
| 7–8 | Hardening, stress, chaos, adversarial, observability, final gates | **Partial → Era II.** MIT-oracle gates exist for AS/TGS, FAST TGS `kvno`, GSS wrap, PKINIT `kinit`, SPAKE `kinit` (`pa_type` 151 / group 2), two-realm `kvno`, and SHA-2 `kinit`/`kvno`. Golden MIT DER is byte-diffed; published crypto KATs; 8 cargo-fuzz targets; panic-deny lints on input-facing crates. AD PAC NDR is golden-gated. Long soak and live Heimdal/AD/SSPI are the remaining Era II work. |

Stage 2 production-gate of a *Rust client* is Stage 3. This repository
currently gates crypto/ASN.1 on known-answer tests, malformed-input
tests, fmt/clippy, and harness `kinit` against MIT 1.22.2.

## Era II — Active Directory interop & production verification (in progress)

Stages 1–6 are substantially done at the MIT-1.22.2 level; the remaining road
to full 1.0 parity is tracked in `working/plan-roadmap-adprod-*.md`:

- **Track A — AD/Windows interop:** NDR32 `KERB_VALIDATION_INFO` decodes the
  captured `kbruser` PAC (`tests/traces/pac-kbruser.ndr`) byte-identically;
  issued PACs carry signatures 6, 7, 16, 19 and self-verify; server checksum
  usage 17 matches AD offline. Samba AD DC image is not in-tree (gate
  records unavailability). Production GSS wrap emits RRC≠0. S4U2Self/Proxy
  against the Rust KDC: `scripts/s4u-mit-gate.sh`. Live Windows `kinit`/`kvno`
  (`ad-windows-gate.sh`) and AD S4U (`ad-s4u-gate.sh`) use `~/adlab`. Bidirectional
  `AD.KERBER.TEST`↔`KERBER.TEST` host tickets are gated
  (`scripts/ad-mit-trust-gate.sh`).
- **Track B — Operational parity:** serving store is `RwLock` so kadmind
  mutations persist; KDC reloads the db on mtime/length change.
  `krb5-kadmind` AUTH_GSSAPI 300001: MIT `kadmin` add/cpw/get/list/mod/
  chrand/ktadd/del then `kinit extra@KERBER.TEST`
  (`scripts/kadmin-gate.sh`). RFC 3244
  kpasswd on UDP/TCP 464 (`scripts/kpasswd-gate.sh` MIT `kpasswd` then
  `kinit`); `krb5-kpropd` on 754 wrapping dump version 7 (`scripts/kprop-gate.sh`
  MIT `kprop` then MIT `kinit`); RFC 8636
  SHA-256 PKINIT KDF on the issue path when
  AuthPack advertises it (`scripts/pkinit-gate.sh`). Stage-5 database
  backend is MIT `kdb5_util` dump/load (`krb5-kdb`, version 7): MIT
  `kinit` against the Rust KDC on a loaded dump, and MIT `krb5kdc` +
  `kinit` on a Rust-written dump (`scripts/kdb-dump-gate.sh`).
- **Track C — Production verification:** `scripts/prod-gate.sh` twice:
  `krb5-kinit` AS+TGS, JSON log analysis, archived PDU pcap. Bounded
  stress + UDP chaos twice. `cargo deny`; `cargo geiger` is installed but a
  no-op on the virtual manifest (needs a per-package target); `cargo vet`
  absent. Samba/Heimdal/SSPI oracles captured unavailable. **1.0 is not
  tagged** (C4 matrix incomplete).

**Audit caveats (2026-08-24).** PAC **NDR codec** and **RFC 8636 KDF** are
done. Type-16/full PAC signatures remain self-round-trip until a Samba
oracle. Rust S4U2Self/Proxy is MIT-gated (`scripts/s4u-mit-gate.sh`
`kvno -U` / `-U -P`); S4U2Proxy rejects non-forwardable evidence and parses
PA-PAC-OPTIONS. `ad-*` gates are **one-shot** against a since-torn-down DC;
cross-realm referral TGTs **omit the PAC**. The **prod-gate is a
single-process Rust↔Rust loopback** (now in CI). `bounded_stress` asserts
concurrent AS+TGS; soak/differential absent. **kpropd** on 754 wraps dump
version 7; MIT `kprop`→Rust then MIT `kinit` is gated (`kprop-gate.sh`).
Rust→MIT `kpropd` is not gated. B1 restart (kill `krb5-kdc` by comm,
relaunch, MIT `kinit`) is gated. **kadmind** MIT-gates
add/get/list/mod/chrand/del (`renprinc` remaining). Harness CI runs
`pkinit-gate`, `kadmin-gate`, `kpasswd-gate`, `kdb-dump-gate`,
`kprop-gate`, `restart-gate`, `prod-gate`.
