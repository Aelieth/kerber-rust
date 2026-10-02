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
| `module` | kdc.authdata.module | Name of the kdcauthdata module that returned the error |
| `path` / `uid` / `gid` | protocol.secret_file | The file saved, and the owner and group of the file it replaced |

Canonical Rust `event` strings live in `krb5_log::events`; the field
names above are written literally at each `tracing` call site (there
are no `FIELD_*` constants). `client.tgs`, `client.pkinit`,
`client.fast`, `kdc.lookaside.full`, `kdc.pkinit`,
`kdc.authdata.module`, and `protocol.secret_file` are constants there
too, so no library call site writes an `event` string literal.

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

A request that reaches `handle_request` and gets a reply logs one
`event=kdc.issue` line at `info`, including `duration_us`:
`outcome=ok` for an AS-REP or TGS-REP, and for a **KRB-ERROR** PDU
`outcome=krb-error` plus `code` (RFC 4120 error-code) and `e_text`
(MIT `log_tgs_req` status word, e.g. `BAD_TRANSIT`, `FIND_FAST`).
FAST unwrap failures also log `detail` when non-empty (MIT's
`k5_setmsg` message where MIT has one; Rust's own otherwise). The
critical-FAST-option `detail` (`FAST option`) is Rust's text — MIT
has no `k5_setmsg` for `UNKNOWN_CRITICAL_FAST_OPTION`.
Code 25 logs `e_text=NEEDED_PREAUTH`. A handler error (an issued reply
that cannot be encoded) logs `outcome=error` at **error** instead. An
empty reply (MIT DISCARD) logs nothing from `handle_request`.

When the request decodes as an AS-REQ or TGS-REQ, a second `kdc.issue`
line carries MIT's tuple. On success it is the ISSUE tuple: `kind`,
`req_etypes`, `from`, `status=ISSUE`, `authtime`, `etypes`
(`rep_etypes2str`), `client`, and `server`; TGS S4U adds a third line
with `s4u` + `s4u_client`. After a KRB-ERROR it is the fail tuple, with
the status word and `outcome=krb-error`. Unexpected transit-path errors
are `tracing` **error** (`kdc_log.c:201-206` `LOG_ERR`).

The listener logs its own `kdc.issue` lines: an empty reply at
**debug**, a reply resent from the lookaside cache at `info` with
`outcome=retransmit`, a duplicate that arrives while the first copy is
being processed at `info` with `outcome=discard`, and a handler error
at **error** with `error_suffix` `while dispatching (udp)` or
`while dispatching (tcp)`, after the handler's own line.

A kdcauthdata module that returns an error logs
`event=kdc.authdata.module` at **error** with `correlation_id`,
`component`, `outcome=error`, `module`, and `error`, and the KDC runs
the next module (`kdc_authdata.c` `handle_authdata`). It is not a
`kdc.issue` line, so a request still logs only the `kdc.issue` lines
above.

A database, `.ulog`, stash or keytab save whose writer may not give
the new file the replaced file's owner or group (an unprivileged
writer) logs `event=protocol.secret_file` at **warn** with
`correlation_id`, `component`, `outcome=ok`, `path`, the old `uid` and
`gid`, `detail` (`owner not kept`, `group not kept`, or `owner and
group not kept`), and `error`; the save completes. With SELinux
permissive, a new file whose SELinux context cannot be set logs the same
event with `detail` `SELinux context not set` and is created without it
(enforcing, the save fails). The daemons' default filter includes
`krb5_protocol=warn`, so the line shows without `RUST_LOG`.

A KDC that cannot record a client's lockout attributes in
`principal.lockout` (the file is missing, as in a realm an earlier
release made, is no lockout file, or cannot be opened read-write or
written) logs `event=kdc.issue` at **warn**, once for each of the two
causes (no file it may open; one it may not write), with
`correlation_id`, `component`, `outcome=error` and the reason as
`detail`, writes the same text to its daemon log, and keeps the
attributes in memory until it can write the file; from then on the
file's are the only ones. A KDC that opened the file read-only keeps
them in memory until it is restarted, even once the file is writable.

The `KdcAudit` registry (`kdc_audit.c`) writes `event=kdc.audit`
with MIT `j_dict.h` field names (`event_name`, `event_success`,
`stage`, `tkt_out_id`, `req_id`, `fromport`, `fromaddr`, …).
`tkt_out_id` is SHA-256 of `ticket.enc_part.ciphertext` as 64
uppercase hex digits. `req_id` is 31 alphanumeric characters
(MIT `REQID_LEN` including NUL). `KRB5_KDC_AUDIT=test` appends
the same JSON to `KRB5_KDC_AUDIT_LOG` (default `au.log`).

## The daemon log (`[logging]`)

Besides the JSON stream on standard output, `krb5-kdc` and
`krb5-kadmind` write MIT's text log (`krb5_log::klog`, MIT
`lib/kadm5/logger.c`). The destinations are the `[logging]` relations
of the daemon's profile, kdc.conf first, then krb5.conf with its
includes: every `kdc` (KDC) or `admin_server` (kadmind) value, else
every `default` value, else syslog with facility AUTH. Fedora's
`/etc/krb5.conf` routes them to `/var/log/krb5kdc.log` and
`/var/log/kadmind.log` this way. `krb5-kadmin-local` opens the
`admin_server` destinations the same way, as MIT's `kadmin.local`
does, and writes only the dictionary notice to them.

| Destination | Meaning |
| --- | --- |
| `FILE:path` | append; a new file is created 0640 |
| `FILE=path` | write from the start without truncating, as MIT does |
| `STDERR` | standard error |
| `CONSOLE`, `DEVICE=path` | `/dev/console` or the path, lines ending CR LF |
| `SYSLOG[:severity[:facility]]` | `/dev/log`; the severity is ignored, the facility defaults to AUTH |

A spec that does not open is reported on standard error as MIT reports
it (`Couldn't open log file …`, `… cannot parse <…>`). Each line is
`Mmm dd hh:mm:ss host prog[pid](Severity): message`; debug lines go to
syslog only unless `[logging] debug = true`. SIGHUP reopens the files,
so logrotate's `systemctl reload` moves the daemon to a new one.

What is logged is what MIT logs: `setting up network...`, `set up N
sockets` and MIT's bind-failure lines; `commencing operation` /
`shutting down` (KDC) and `starting` / `finished, exiting` (kadmind);
at kadmind's and kadmin.local's start, `No dictionary file specified,
continuing without one.` without a `dict_file`, or `WARNING!  Cannot
find dictionary file …, continuing without one.` for a missing one;
one `AS_REQ` / `TGS_REQ` line per answered request (`ISSUE` with the
reply etypes, or the status word and the error's message) with the
`... PROTOCOL-TRANSITION` / `... CONSTRAINED-DELEGATION` line after an
S4U request; the transited-path lines; `closing down fd N` when a TCP
connection ends; and per kadm5 request one `Request:` or `Unauthorized
request:` line with client, service and address, plus the `chpw` /
`setpw` lines of kpasswd.

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
