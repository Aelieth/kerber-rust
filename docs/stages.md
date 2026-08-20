# Stage progress

Promotion through a stage requires the multi-sided tests for that stage
and, once a live component exists, a production-gate run with structured
logs. Unit tests alone do not promote a stage.

| Stage | Content | Status |
| --- | --- | --- |
| 1 | Foundation, inventory, MIT 1.22.2 harness, logging schema | **In tree** |
| 2 | Crypto primitives + ASN.1/DER core, KATs, parser negative tests | **In tree** (etypes 17–20, RFC 4120 core PDUs) |
| 3 | Protocol library + minimal client (AS/TGS), ccache/keytab, first live MIT production gate | Not started |
| 4 | Higher-level client, GSS-API/SPNEGO (RFC 4121) | Not started |
| 5 | KDC core (AS+TGS) + database backend, bidirectional interop | Not started |
| 6 | Admin tools, plugins, propagation, remaining parity | Not started |
| 7–8 | Hardening, stress, chaos, adversarial, observability, final gates | Not started |

Stage 2 production-gate of a *Rust client* is Stage 3. This repository
currently gates crypto/ASN.1 on known-answer tests, malformed-input
tests, fmt/clippy, and harness `kinit` against MIT 1.22.2.
