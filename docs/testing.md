# Testing strategy

Testing is continuous. Categories grow with the stages.

## Normal / baseline

- Known-answer tests in `crates/krb5-crypto/tests/known_answer.rs`
  (RFC 3962, RFC 8009, MIT `t_derive.c` / `t_cksums.c`).
- DER round-trip in `crates/krb5-asn1/tests/round_trip.rs`.
- Downstream consumer tests in `examples/consumer`.

These tests call the shipped functions. They do not reimplement AES or
DER inside the test.

## Irregularity / adversarial

- Truncated and malformed DER must return `Error`, never panic.
- Decrypt of a truncated ciphertext or a flipped HMAC bit must fail.
- Key usage 0 is rejected.

Fuzzing of the DER parser is expected as the suite grows (`cargo fuzz`
harness not yet wired).

## Interop

Primary oracle: MIT Kerberos **1.22.2** in `harness/`. Heimdal and
Active Directory / SSPI are later stages.

## Production-gate

Stage 1: harness starts twice, port 88 reachable, MIT `kinit` obtains a
TGT, structured logs include `correlation_id`.

Stage 3: `scripts/client-gate.sh` copies the Rust `krb5-kinit` binary
into the MIT 1.22.2 container (same network namespace as the KDC),
obtains a TGT and a `host/testhost.kerber.test` service ticket, and
runs MIT `klist` on the FILE ccache. Host Docker UDP/TCP publish to
port 88 is unreliable; the gate therefore talks to `127.0.0.1:88`
*inside* the container.

Stage 5: `scripts/kdc-gate.sh` copies the Rust `krb5-kdc` binary into a
client-only MIT 1.22.2 container, binds 127.0.0.1:88 (fallback 8888),
and runs MIT `kinit user@KERBER.TEST` plus `kvno host/testhost.kerber.test`.
In-crate tests drive `issue_as` / `issue_tgs` / `Acl::check` /
`verify_ap_req` without a socket.

## MIT 1.22.2 harness

| Item | Value |
| --- | --- |
| Realm | `KERBER.TEST` |
| KDC ports | UDP/TCP 88 |
| Principal | `user@KERBER.TEST` / password `userpassword` |
| Service | `host/testhost.kerber.test` (randkey) |
| Image | `harness/Dockerfile`, `KRB5_VERSION=1.22.2` |

```bash
./scripts/run-harness.sh
# kinit inside the container; logs on stdout as JSON
./scripts/stop-harness.sh
```

Host-side `kinit` (if you have MIT clients installed):

```bash
KRB5_CONFIG="$PWD/harness/client-krb5.conf" kinit user@KERBER.TEST
```

Golden traces will live under `tests/traces/` once Stage 3 captures
them. Do not commit `/working`.
