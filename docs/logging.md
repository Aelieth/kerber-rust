# Structured logging schema

Library crates emit [`tracing`](https://docs.rs/tracing) events. They
never install a subscriber. Tests and the harness do.

## Fields

| Field | Required | Meaning |
| --- | --- | --- |
| `event` | yes | Stable name. From Rust: a `krb5_log::events` constant (`crypto.encrypt`, `asn1.decode`, `kdc.issue`, `admin`, …; every constant there is emitted somewhere). From the harness containers: `harness.start`, `harness.kdc.ready`, `harness.kinit`, `heimdal.start`, `samba.start` (see below) |
| `correlation_id` | yes | 32 hex chars; one ID per *exchange* (crypto/ASN.1 inherit the parent via `enter_correlation`; they do not mint a new ID per op). The harness containers echo the `CORRELATION_ID` they were started with (`none` when unset) |
| `component` | yes | Rust: `krb5-crypto`, `krb5-asn1`, `krb5-protocol`, `krb5-kdc`, `krb5-admin`, or `krb5-client`. Harness: `harness` (the MIT KDC container), `heimdal-harness`, `samba-harness` |
| `outcome` | yes | `ok`, `error`, or `krb-error` |
| `duration_us` | crypto/asn1 | Wall time of the operation |
| `etype` | crypto | IANA encryption-type number |
| `key_usage` | crypto | RFC 3961 usage, when applicable |
| `pdu` | asn1 | Rust type name of the PDU |
| `byte_len` | asn1 | Encoded or input length |
| `error` | on failure | `Display` of the error (no key material) |
| `code` | krb-error | RFC 4120 error-code on `kdc.issue` |
| `e_text` | krb-error | MIT `log_tgs_req` status string (`PROCESS_TGS`, `GET_LOCAL_TGT`, `FIND_FAST`, …) |
| `detail` | krb-error | MIT `k5_setmsg` text when MIT has one; otherwise Rust's own. Omitted when empty. Not on the wire. |
| `kind` | kdc.issue | `AS_REQ` or `TGS_REQ` (`kdc_log.c`) |
| `req_etypes` | kdc.issue | MIT `ktypes2str`: `N etypes {name(num), …}` |
| `from` | kdc.issue | Client address (`k5_print_addr`) |
| `status` | kdc.issue | `ISSUE` on success; MIT status word on fail |
| `authtime` | kdc.issue | Ticket `authtime` as a Unix timestamp |
| `etypes` | kdc.issue | MIT `rep_etypes2str`: `etypes {rep=name(num), tkt=…, ses=…}` |
| `client` | kdc.issue | Unparsed client (`user@REALM`) |
| `server` | kdc.issue | Unparsed server (`krbtgt/REALM@REALM`) |
| `s4u` / `s4u_client` | kdc.issue | `PROTOCOL-TRANSITION` or `CONSTRAINED-DELEGATION` |
| `record` | kdc.audit | One JSON object using MIT `j_dict.h` keys |

Canonical Rust `event` strings live in `krb5_log::events`; the field
names above are written literally at each `tracing` call site (there
are no `FIELD_*` constants). `client.tgs`, `client.pkinit`,
`client.fast`, `kdc.lookaside.full`, and `kdc.pkinit` are those
constants. Their string values are the names above.

`target` is the Rust module path (`tracing`'s default). It is not part
of the log contract. Gates and tests match `event` and the fields in
the table. Moving a function into another module may change `target`
and must leave `event` unchanged.

## Harness log lines

The three container entrypoints under `harness/` are shell, not
`tracing`; each writes its lines with `printf` to stdout (`docker
logs`), one JSON object per line with the same `event` /
`correlation_id` / `component` / `outcome` core plus `realm`. Their
names are declared here and nowhere in Rust:

| `component` | `event` | Extra fields | Emitted |
| --- | --- | --- | --- |
| `harness` | `harness.start` | `kdc_port` | `harness/entrypoint.sh`, before the KDB is created |
| `harness` | `harness.kdc.ready` | `kdc_port`; `error` on `outcome=error` | once `krb5kdc` listens on 88, or after the wait times out |
| `harness` | `harness.kinit` | `principal` | after the in-container `kinit`; `outcome` `ok` or `error` |
| `heimdal-harness` | `heimdal.start` | `kdc` (the KDC binary path) | `harness/heimdal/entrypoint.sh`, before `exec` of the KDC |
| `samba-harness` | `samba.start` | — | `harness/samba/entrypoint.sh`, before `exec samba` (the domain is provisioned in the image) |

Gate scripts depend on two of these by exact string:
`scripts/lib/gate-common.sh`, `scripts/run-harness.sh` and
`scripts/kadmin-mit-gate.sh` wait for
`"event":"harness.kinit"` with `"outcome":"ok"` (and fail on
`"outcome":"error"`), and `scripts/heimdal-gate.sh` waits for
`"event":"heimdal.start"`. Renaming an event renames those greps.

Every request logs one `event=kdc.issue` line from `handle_request`
at `info`, including `duration_us`. A **KRB-ERROR** PDU is
`outcome=krb-error` plus `code` (RFC 4120 error-code) and `e_text`
(MIT `log_tgs_req` status word, e.g. `BAD_TRANSIT`, `FIND_FAST`).
FAST unwrap failures also log `detail` when non-empty (MIT's
`k5_setmsg` message where MIT has one; Rust's own otherwise). The
critical-FAST-option `detail` (`FAST option`) is Rust's text — MIT
has no `k5_setmsg` for `UNKNOWN_CRITICAL_FAST_OPTION`.
Code 25 logs `e_text=NEEDED_PREAUTH`. Store-programming failures
that cannot be encoded stay `outcome=error`.

A successful AS or TGS also emits the MIT ISSUE tuple on a second
`kdc.issue` line: `kind`, `req_etypes`, `from`, `status=ISSUE`,
`authtime`, `etypes` (`rep_etypes2str`), `client`, and `server`.
TGS S4U adds `s4u` + `s4u_client`. Unexpected transit-path errors
are `tracing` **error** (`kdc_log.c:201-206` `LOG_ERR`).

The `KdcAudit` registry (`kdc_audit.c`) writes `event=kdc.audit`
with MIT `j_dict.h` field names (`event_name`, `event_success`,
`stage`, `tkt_out_id`, `req_id`, `fromport`, `fromaddr`, …).
`tkt_out_id` is SHA-256 of `ticket.enc_part.ciphertext` as 64
uppercase hex digits. `req_id` is 31 alphanumeric characters
(MIT `REQID_LEN` including NUL). `KRB5_KDC_AUDIT=test` appends
the same JSON to `KRB5_KDC_AUDIT_LOG` (default `au.log`).

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
