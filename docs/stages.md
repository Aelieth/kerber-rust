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
| 6 | Admin tools, plugins, propagation, remaining parity | **In tree** (`krb5-admin` ACL-enforced session, ktadd, kprop-equivalent dump/load). Not MIT RPC ABI. |
| 7–8 | Hardening, stress, chaos, adversarial, observability, final gates | Partial (DER-strictness, listener negatives, bounded stress, `cargo audit`; long soak is not in this tree) |

Stage 2 production-gate of a *Rust client* is Stage 3. This repository
currently gates crypto/ASN.1 on known-answer tests, malformed-input
tests, fmt/clippy, and harness `kinit` against MIT 1.22.2.
