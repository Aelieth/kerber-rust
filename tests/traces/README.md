# Golden DER / traces

In-crate tests (`crates/krb5-protocol/tests/golden_traces.rs`) decode each
`mit-*.der` with the shipped rasn codec and require `encode(decode(raw))`
to equal the captured bytes (plus named fields). A divergence fails the
unit `test` CI job. `mit-krb-error-preauth.der` is the KRB-ERROR we emit
(PREAUTH_REQUIRED), not a MIT-KDC reply.

Set `KERBER_CAPTURE_DIR` to this directory (or a temp dir) when running
the KDC or client: each raw PDU is written as `{kdc,client}-{req,rep}-<nonce>.der`
at the Rust socket boundary (no packet sniffer required). Those hash-named
files are gitignored.

## Provenance

| File | Tag | Origin |
| --- | --- | --- |
| `mit-as-req.der` | `0x6a` | MIT 1.22.2 client AS-REQ (`kdc-gate.sh` capture of MIT bytes) |
| `mit-as-req-preauth.der` | `0x6a` | MIT AS-REQ with PA-ENC-TIMESTAMP |
| `mit-krb-error-preauth.der` | `0x7e` | PREAUTH_REQUIRED (Rust KDC reply to MIT; KRB-ERROR we emit) |
| `mit-as-rep.der` | `0x6b` | MIT 1.22.2 KDC AS-REP (`client-gate.sh` `client-rep-*.der`) |
| `mit-tgs-req.der` | `0x6c` | MIT TGS-REQ (FAST) |
| `mit-tgs-rep.der` | `0x6d` | MIT 1.22.2 KDC TGS-REP (`client-gate.sh` `client-rep-*.der`) |

Reply goldens must be MIT-KDC bytes from the Rust client socket
(`client-rep-*.der`), not Rust-KDC socket dumps (`kdc-rep-*.der`).
`scripts/client-gate.sh` copies captures here (`KERBER_TRACE_DST` override).
`scripts/kdc-gate.sh` copies MIT *request* PDUs as `mit-*-req.der`.
