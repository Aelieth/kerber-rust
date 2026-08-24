# Testing strategy

Testing is continuous. Categories grow with the stages.

## Normal / baseline

- Known-answer tests in `crates/krb5-crypto/tests/known_answer.rs`
  (RFC 3961 3DES s2k, RFC 3962, RFC 6803 Camellia-CTS-CMAC, MIT
  `t_prf.c` PRF / RFC 6113 PRF+, RFC 4556 `octetstring2key`, RFC 4757
  RC4 s2k, SPAKE IANA M/N + fixed-scalar public, MIT `t_derive.c` /
  `t_cksums.c`).
- DER round-trip in `crates/krb5-asn1/tests/round_trip.rs`.
- Downstream consumer tests in `examples/consumer`.

These tests call the shipped functions. They do not reimplement AES or
DER inside the test.

## Irregularity / adversarial

- Truncated and malformed DER must return `Error`, never panic.
- Decrypt of a truncated ciphertext or a flipped HMAC bit must fail.
- Key usage 0 is rejected.

DER-strictness negatives live in `crates/krb5-asn1/tests/der_strict.rs`.
`fuzz/` has ≥6 cargo-fuzz targets (DER, AS/TGS/AP, keytab/ccache,
PKINIT CMS, PAC NDR, SPAKE points, Oakley DH, GSS tokens) seeded from
`tests/traces/`. CI smokes each target ~60s (`.github/workflows/fuzz.yml`).

## Interop

Primary oracle: MIT Kerberos **1.22.2** in `harness/`. A Windows
Server 2022 Evaluation DC (`AD.KERBER.TEST`) is captured for the AD
round; see [`ad-lab.md`](ad-lab.md). Live AD commands use `~/adlab`
only — never `/etc/krb5.conf` or SSSD. Heimdal and SSPI remain later.

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
the Rust KDC. The KDC log must contain `rfc8636 sha256 kdf` (MIT TRACE
`PKINIT used KDF 2B06010502030602`). Set `KERBER_CAPTURE_DIR` to write
raw PDUs under `tests/traces/`.

SPAKE: `scripts/spake-gate.sh` runs MIT `kinit` against the Rust KDC
with `preferred_preauth_types = 151` and `spake_preauth_groups = P-256`.
It fails unless TRACE contains `pa_type` 151 and group 2, and `klist`
shows `user@KERBER.TEST`.

SHA-2: `scripts/sha2-gate.sh` is a live MIT 1.22.2 gate. It copies the
Rust KDC into the MIT image, points `KRB5_CONFIG` at `/etc/krb5-sha2.conf`
(etype 20 only), and requires `kinit`/`kvno`/`klist -e` to name
`aes256-cts-hmac-sha384-192`. It hard-fails without Docker.

Cross-realm: `scripts/cross-realm-gate.sh` starts two Rust KDCs
(KERBER.TEST:88, OTHER.TEST:89) sharing `KRB5_TEST_INTERREALM_KEY`,
then MIT `kinit` + `kvno host/svc.other.test@OTHER.TEST`. It fails
unless `klist` contains `krbtgt/OTHER.TEST` and the host ticket.

AD PAC: `crates/krb5-kdc/tests/ad_pac.rs` decodes committed
`tests/traces/pac-kbruser.ndr` (byte-identical re-encode; `kbruser` /
`kbrgroup` / ADKERBER SID). With `~/adlab/svc.keytab` present, the
captured `host/svc` PAC server checksum is verified (usage 17). Skip
cleanly without the keytab.

Era II gates (honest unavailability, never a fabricated pass):

- `scripts/samba-ad-gate.sh` — Samba 4 AD DC (exit 2 + unavailability
  log when no image).
- `scripts/ad-windows-gate.sh` — isolated `kinit`/`kvno` against
  `10.10.38.38` (`~/adlab` only; needs `AD_KBRUSER_PASSWORD`).
- `scripts/kadmin-gate.sh` — MIT `kadmin` `addprinc`/`cpw` against
  `krb5-kadmind` on 749, then `kinit extra@KERBER.TEST`. AUTH_GSSAPI
  flavor 300001. Run twice.
- `scripts/prod-gate.sh` — Rust KDC on `127.0.0.1:18888`, structured
  logs archived under `$KERBER_SCRATCH/prod-gate/`.
- `scripts/ad-mit-trust-gate.sh` — both directions (aes256):
  `kbruser@AD.KERBER.TEST` → `host/testhost.kerber.test` and
  `user@KERBER.TEST` → `host/svc.ad.kerber.test`. Sources `~/adlab/env`.

Live AD work must set `KRB5_CONFIG` / `KRB5CCNAME` / `KRB5_KTNAME` to
`~/adlab`. Never edit host `/etc/krb5.conf` or SSSD.

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

Golden traces under `tests/traces/mit-*.der` are decoded and
field-diffed in `crates/krb5-protocol/tests/golden_traces.rs` (unit CI).
Reply goldens are MIT-KDC bytes from `client-gate.sh`. Do not commit
`/working`. `bidirectional-gate.sh` is a Rust-client↔Rust-KDC check,
not a live MIT oracle.
