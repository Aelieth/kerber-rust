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
| 5 | KDC core (AS+TGS) + database backend, bidirectional interop | **In tree** (in-memory + optional persist/stash; ACL; AP-REQ; gates: `kdc-gate.sh`, `bidirectional-gate.sh`). Not a full MIT KDB. |
| 6 | Admin tools, plugins, propagation, remaining parity | **In tree** (`krb5-admin` ACL-enforced session, ktadd of all kvnos, kpasswd with kvno rotation, kprop dump/load, inter-realm krbtgt + transited). Kadmind AUTH_GSSAPI 300001 gated by MIT `kadmin` `addprinc`/`cpw`. |
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
  remain in-tree. Live Windows `kinit` uses `~/adlab/env`
  (`AD_KBRUSER_PASSWORD`). `AD.KERBER.TEST`→`KERBER.TEST` live referral
  + `host/testhost.kerber.test` is gated (`scripts/ad-mit-trust-gate.sh`).
  Reverse host ticket: AD decrypt of the Rust-issued referral TGT fails.
- **Track B — Operational parity:** serving store is `RwLock` so kadmind
  mutations persist; KDC reloads the db on mtime/length change.
  `krb5-kadmind` AUTH_GSSAPI 300001: MIT `kadmin` `addprinc`/`cpw` then
  `kinit extra@KERBER.TEST` (`scripts/kadmin-gate.sh`). RFC 3244 kpasswd;
  kprop dump/load; RFC 8636 SHA-256 PKINIT KDF on the issue path when
  AuthPack advertises it (`scripts/pkinit-gate.sh`).
- **Track C — Production verification:** `scripts/prod-gate.sh` archives
  structured KDC logs; bounded concurrent `handle_request` stress; `cargo
  deny` + `cargo geiger` when present. 1.0 tag is not cut.
