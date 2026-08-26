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
| 5 | KDC core (AS+TGS) + database backend, bidirectional interop | **In tree** (in-memory + dump-v7 at-rest; one-release KDB3 load; MIT `kdb5_util` dump/load; ACL; AP-REQ; gates: `kdc-gate.sh`, `bidirectional-gate.sh`, `kdb-dump-gate.sh`). MIT `kinit` both directions is the database oracle. |
| 6 | Admin tools, plugins, propagation, remaining parity | **In tree** (`krb5-admin` ACL-enforced session, ktadd of all kvnos, kpasswd with kvno rotation, kprop dump/load, inter-realm krbtgt + transited). Kadmind AUTH_GSSAPI 300001 gated by MIT `kadmin` add/get/list/mod/chrand/del. MIT `kpasswd` gated by `scripts/kpasswd-gate.sh`. |
| 7–8 | Hardening, stress, chaos, adversarial, observability, final gates | **Partial → Era II.** MIT-oracle gates exist for AS/TGS, FAST TGS `kvno`, GSS wrap, PKINIT `kinit`, SPAKE `kinit` (`pa_type` 151 / group 2), two-realm `kvno`, and SHA-2 `kinit`/`kvno`. Golden MIT DER is byte-diffed; published crypto KATs; 8 cargo-fuzz targets; panic-deny lints on input-facing crates. AD PAC NDR is golden-gated. Wire **stress/chaos/soak** run over `harness/prod` (`stress-gate`, `chaos-gate`, `soak-gate`; scheduled soak in `soak.yml`). Differential-vs-MIT is `scripts/differential-gate.sh` (same AS/TGS bytes to Rust and MIT 1.22.2 on one dump). Live Heimdal/SSPI remain. |

Stage 2 production-gate of a *Rust client* is Stage 3. This repository
currently gates crypto/ASN.1 on known-answer tests, malformed-input
tests, fmt/clippy, and harness `kinit` against MIT 1.22.2.

## Era II — Active Directory interop & production verification (in progress)

Stages 1–6 are substantially done at the MIT-1.22.2 level; the remaining road
to full 1.0 parity is tracked in `working/plan-roadmap-adprod-*.md`:

- **Track A — AD/Windows interop:** NDR32 `KERB_VALIDATION_INFO` decodes the
  captured `kbruser` PAC (`tests/traces/pac-kbruser.ndr`) byte-identically.
  Issued PACs include buffers 12/17/18 and store SID/RID. Samba L1/L3
  gates: `samba-pac-verify-gate.sh`, `samba-pac-l2-gate.sh` (vendored kcrypto 6/7/16/19),
  `samba-crossrealm-gate.sh`. Production
  GSS wrap emits RRC≠0. S4U2Self/Proxy against the Rust KDC:
  `scripts/s4u-mit-gate.sh` (in CI; evidence PAC copy, classic
  constrained delegation, RBCD). Live Windows
  `kinit`/`kvno` (`ad-windows-gate.sh`) and AD S4U (`ad-s4u-gate.sh`)
  drive live Samba (`samba-ad-dc`), not the torn-down Windows DC.
- **Track B — Operational parity:** serving store is `RwLock` so kadmind
  mutations persist; KDC reloads the db on mtime/length change.
  `krb5-kadmind` AUTH_GSSAPI 300001: MIT `kadmin` add/cpw/get/list/mod/
  chrand/ktadd/`renprinc`/del then `kinit extra@KERBER.TEST`
  (`scripts/kadmin-gate.sh`). RFC 3244
  kpasswd on UDP/TCP 464 (`scripts/kpasswd-gate.sh` MIT `kpasswd` then
  `kinit`); kprop on 754 wrapping dump version 7 both directions
  (`scripts/kprop-gate.sh` MIT→Rust; `scripts/kprop-reverse-gate.sh`
  Rust→MIT `kpropd` then MIT `kinit`); RFC 8636
  SHA-256 PKINIT KDF on the issue path when
  AuthPack advertises it (`scripts/pkinit-gate.sh`). Stage-5 database
  backend is MIT `kdb5_util` dump/load (`krb5-kdb`, version 7): MIT
  `kinit` against the Rust KDC on a loaded dump, and MIT `krb5kdc` +
  `kinit` on a Rust-written dump (`scripts/kdb-dump-gate.sh`).
- **Track C — Production verification:** `scripts/prod-gate.sh` (loopback
  Rust↔Rust) plus **`scripts/prod-realm-gate.sh`** (MIT client vs Rust
  primary/replica on a docker network, realm `PROD.KERBER.TEST`, kprop
  failover, structured logs + NIC pcap). Wire **stress-gate** (p99 SLO),
  **chaos-gate** (netem + memory + failover-under-load), and **soak-gate**
  (RSS leak check; scheduled longer run). Differential-vs-MIT
  (`differential-gate`) is in CI. `cargo deny`; `cargo geiger` is installed but a
  no-op on the virtual manifest (needs a per-package target); `cargo vet`
  absent. Samba/Heimdal/SSPI oracles captured unavailable. **1.0 is not
  tagged** (C4 matrix incomplete).

**Audit caveats (2026-08-25).** PAC **NDR codec** and **RFC 8636 KDF** are
done. Samba L1 decodes the full buffer set of a Rust PAC
(`samba-pac-verify-gate.sh`); Samba `kcrypto` validates checksums 6/7/16/19
(`samba-pac-l2-gate.sh`); Samba's KDC accepts a Rust referral PAC
both directions (`samba-crossrealm-gate.sh`). TGS
verifies a presented PAC and copies LOGON_INFO (in-repo two-realm
tests; `kvno` is not that copy proof). Rust S4U2Self/Proxy is
MIT-gated in CI (`scripts/s4u-mit-gate.sh`); S4U2Proxy copies the evidence
PAC, denies classic constrained delegation unless `s4u_allowed_to` lists
the target, and denies RBCD unless allowed. `ad-windows-gate` / `ad-s4u-gate` are live Samba in CI.
`ad-mit-trust-gate.sh` aliases `samba-realtrust-gate.sh`. **C1** is
`prod-gate.sh` (loopback) plus **`prod-realm-gate.sh`** (multi-host MIT
client, named realm, kprop failover; in CI). Wire `stress-gate` /
`chaos-gate` / `soak-gate` are in CI; in-process `bounded_stress`
remains. Differential-vs-MIT is `differential-gate` (in CI). **kprop** on 754
is gated both directions (`kprop-gate` MIT→Rust; `kprop-reverse-gate`
Rust→MIT, additive to the in-process dump/send tests). **kadmind** MIT-gates add/get/list/mod/chrand/
`renprinc`/del. Harness CI runs `pkinit-gate`, `kadmin-gate`,
`kpasswd-gate`, `kdb-dump-gate`, `differential-gate`, `kprop-gate`, `kprop-reverse-gate`,
`restart-gate`, `prod-gate`, `prod-realm-gate`, `stress-gate`, `chaos-gate`, `soak-gate`, `s4u-mit-gate`, `samba-ad-gate`,
`ad-windows-gate`, `ad-s4u-gate`, `samba-pac-verify-gate`,
`samba-pac-l2-gate`, `samba-crossrealm-gate`, `samba-realtrust-gate`.
