# Golden DER / traces

In-crate tests assert RFC 4120 APPLICATION tags against the shipped
encoder (`0x61` Ticket, `0x79` EncASRepPart, `0x7e` KRB-ERROR, `0x76`
KRB-CRED).

Set `KERBER_CAPTURE_DIR` to this directory (or a temp dir) when running
the KDC or client: each raw PDU is written as `{kdc,client}-{req,rep}-<nonce>.der`
at the Rust socket boundary (no packet sniffer required). Those hash-named
files are gitignored. `scripts/kdc-gate.sh` copies MIT 1.22.2 captures here
as `mit-*.der` (`KERBER_TRACE_DST` override).

Checked-in MIT 1.22.2 PDUs from `kdc-gate.sh` (APPLICATION tags):

| File | Tag | PDU |
| --- | --- | --- |
| `mit-as-req.der` | `0x6a` | AS-REQ |
| `mit-as-req-preauth.der` | `0x6a` | AS-REQ with PA-ENC-TIMESTAMP |
| `mit-krb-error-preauth.der` | `0x7e` | PREAUTH_REQUIRED |
| `mit-as-rep.der` | `0x6b` | AS-REP |
| `mit-tgs-req.der` | `0x6c` | TGS-REQ (FAST) |
| `mit-tgs-rep.der` | `0x6d` | TGS-REP |
