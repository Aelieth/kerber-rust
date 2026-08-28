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
| `mit-krb-error-preauth.der` | `0x7e` | PREAUTH_REQUIRED (Rust KDC reply to MIT; KRB-ERROR we emit). CA-enabled METHOD-DATA order `[16, 109, 151, 2, 19]` (PK_AS_REQ, TD-DH-PARAMETERS, SPAKE, ENC_TIMESTAMP, ETYPE-INFO2) is an **in-code pin** in `phase7_preauth.rs`, not a companion `.der`. MIT FAST 133/136 is not in this list. |
| `mit-as-rep.der` | `0x6b` | MIT 1.22.2 KDC AS-REP (`client-gate.sh` `client-rep-*.der`) |
| `mit-tgs-req.der` | `0x6c` | MIT TGS-REQ (FAST) |
| `mit-tgs-rep.der` | `0x6d` | MIT 1.22.2 KDC TGS-REP (`client-gate.sh` `client-rep-*.der`) |
| `pac-kbruser.ndr` | NDR | Windows Server 2022 `PAC_LOGON_INFO` for `kbruser` (identity bytes only; extracted from the captured `host/svc` ticket) |
| `kdb/mit-dump-v7.txt` | dump | MIT 1.22.2 `kdb5_util dump` (default **version 7**) of `KERBER.TEST` (`user`/`pauser`/`host/testhost.kerber.test`; master password `masterpassword`). Keys are master-key-encrypted; the test-realm password is already public. |
| `kdb/mit-dump-v6.txt` | dump | Same realm via `kdb5_util dump -r18` (**version 6**). Princ grammar matches v7. |
| `kdb/getprinc-pauser.txt` | text | `kadmin.local getprinc pauser` at dump time. `Attributes: REQUIRES_PRE_AUTH` is dump field **128**, not `0x8`. |

Reply goldens must be MIT-KDC bytes from the Rust client socket
(`client-rep-*.der`), not Rust-KDC socket dumps (`kdc-rep-*.der`).
`scripts/client-gate.sh` copies captures here (`KERBER_TRACE_DST` override).
`scripts/kdc-gate.sh` copies MIT *request* PDUs as `mit-*-req.der`.
