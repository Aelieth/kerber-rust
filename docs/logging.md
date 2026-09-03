# Structured logging schema

Library crates emit [`tracing`](https://docs.rs/tracing) events. They
never install a subscriber. Tests and the harness do.

## Fields

| Field | Required | Meaning |
| --- | --- | --- |
| `event` | yes | Stable name (`crypto.encrypt`, `asn1.decode`, `harness.kinit`, …) |
| `correlation_id` | yes | 32 hex chars; one ID per *exchange* (crypto/ASN.1 inherit the parent via `enter_correlation`; they do not mint a new ID per op) |
| `component` | yes | `krb5-crypto`, `krb5-asn1`, `krb5-kdc`, or `harness` |
| `outcome` | yes | `ok`, `error`, or `krb-error` |
| `duration_us` | crypto/asn1 | Wall time of the operation |
| `etype` | crypto | IANA encryption-type number |
| `key_usage` | crypto | RFC 3961 usage, when applicable |
| `pdu` | asn1 | Rust type name of the PDU |
| `byte_len` | asn1 | Encoded or input length |
| `error` | on failure | `Display` of the error (no key material) |
| `code` | krb-error | RFC 4120 error-code on `kdc.issue` |
| `e_text` | krb-error | MIT `log_tgs_req` status string (`PROCESS_TGS`, `GET_LOCAL_TGT`, `FIND_FAST`, …) |
| `detail` | krb-error | MIT `k5_setmsg` text for FAST unwrap failures (not on the wire) |

Canonical `event` strings live in `krb5_log::events`.

Every request logs one `event=kdc.issue` line from `handle_request`
at `info`, including `duration_us`. A **KRB-ERROR** PDU is
`outcome=krb-error` plus `code` (RFC 4120 error-code) and `e_text`
(MIT `log_tgs_req` status word, e.g. `BAD_TRANSIT`, `FIND_FAST`).
FAST unwrap failures also log `detail` (MIT's `k5_setmsg` text).
Code 25 logs `e_text=NEEDED_PREAUTH`. Store-programming failures
that cannot be encoded stay `outcome=error`.

## Logs as metrics

Every issue and crypto/ASN.1 event already carries `duration_us` and
`outcome`. An aggregator (log shipper, `analyze-kdc-slo.py`, the
stress/soak gates) derives counts, rates, and p99 from those fields.
**In-process counters, a metrics crate, and Prometheus are deferred**
past 1.0; they are not 1.0-blocking. Do not add them unless the
project later opts in.

## Example (JSON subscriber)

```json
{"event":"crypto.encrypt","correlation_id":"9f2c…","component":"krb5-crypto","etype":19,"key_usage":2,"duration_us":412,"outcome":"ok"}
```
