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

DER-strictness negatives live in `crates/krb5-asn1/tests/der_strict.rs`.
`cargo fuzz` is optional; when it cannot run, those negatives are the
sub-bar.

## Interop

Primary oracle: MIT Kerberos **1.22.2** in `harness/`. Heimdal and
Active Directory / SSPI are later stages.

## Production-gate

Stage 1: harness starts twice, port 88 reachable, MIT `kinit` obtains a
TGT, structured logs include `correlation_id`.

Stage 3: `scripts/client-gate.sh` copies the Rust `krb5-kinit` binary
into the MIT 1.22.2 container (same network namespace as the KDC),
obtains a TGT and a `host/testhost.kerber.test` service ticket, and
runs MIT `klist` on the FILE ccache. The client uses unconnected UDP
(`send_to`/`recv_from`) and ignores off-path source addresses. Host
Docker UDP/TCP publish to port 88 is unreliable; the gate therefore
talks to `127.0.0.1:88` *inside* the container.

Stage 5: `scripts/kdc-gate.sh` copies the Rust `krb5-kdc` binary into a
client-only MIT 1.22.2 container, binds 127.0.0.1:88 (fallback 8888),
and runs MIT `kinit user@KERBER.TEST` plus `kvno host/testhost.kerber.test`.
In-crate tests drive `issue_as` / `issue_tgs` / `Acl::check` /
`verify_ap_req` without a socket.

Stage 4/5 GSS: `scripts/gss-gate.sh` copies `krb5-gss-accept` into the
MIT 1.22.2 container, exports `host/testhost.kerber.test` to a keytab,
and runs an out-of-process MIT `libgssapi_krb5` initiator (`scripts/gss-mit-client.c`)
that wraps `hello-from-mit-gss`. The Rust acceptor must unwrap that
plaintext.

PKINIT: `scripts/pkinit-gate.sh` **fails** unless MIT `pkinit.so` is
present and MIT `kinit -X X509_user_identity=FILE:` succeeds against
the Rust KDC. Set `KERBER_CAPTURE_DIR` to write raw PDUs under
`tests/traces/`.

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
