# Architecture

kerber-rust is a Cargo workspace of small crates. Dependencies flow
downward only:

```
examples/consumer, examples/kdc-consumer
        │
        ├──────────────► krb5-asn1 ──► krb5-types
        │                     │
        ├──────────────► krb5-kdc / krb5-admin / krb5-gss
        │                      │
        ├──────────────► krb5-client ──► krb5-protocol ──► krb5-crypto
        │                      │                └──► krb5-config
        │                      │                │
        └──────────────► krb5-crypto            └──► krb5-asn1
```

## Crate responsibilities

**`krb5-log`** defines the structured event field names and allocates
correlation IDs. It does not install a `tracing` subscriber. Binaries,
tests, and the harness installer do.

**`krb5-crypto`** is pure functions over keys and byte slices. No
sockets, no ASN.1. Long-term keys (`ProtocolKey`) zeroize on drop.
HMAC comparison is constant-time (`subtle`). Random confounders come
from the OS CSPRNG (`getrandom`).

**`krb5-types`** holds RFC 4120 owned values with rasn derives. Tagging
is EXPLICIT, matching the RFC. This crate is the protocol vocabulary;
it does not catch codec errors.

**`krb5-asn1`** is the DER boundary: `encode` / `decode` return
`Result`, never panic, and emit log events for success and failure.

**`krb5-protocol`** runs AS and TGS over UDP with TCP fallback, plus
AP-REQ build/verify.

**`krb5-client`** is `kinit`, MIT FILE ccache v4, and keytab v2.

**`krb5-protocol`** runs AS/TGS/AP/SAFE/PRIV/CRED, plus MIT keytab and
FILE ccache (so the KDC does not depend on the client crate). UDP uses
`send_to`/`recv_from` and ignores off-path source addresses.

**`krb5-client`** is `kinit` (password from env/stdin, never argv).

**`krb5-kdc`** issues AS/TGS from an in-memory store. The at-rest file
is MIT dump version 7 (stash still holds the master key; SID/RID in
`TL_KERBER_SID`). Legacy KDB3 ciphertext still loads for one release.
`krb5-kdb` is the dump/load CLI. `key_data` uses KDB usage 0
with a cleartext `int16_LE` length prefix; protocol `KeyUsage::new(0)`
stays rejected. The serving store is `Arc<RwLock<PrincipalStore>>` so
kadmind/kpasswd mutations reach `save_store`. Default bind is
`127.0.0.1` (not `0.0.0.0`). After a privileged bind the daemon drops
to `KRB5_KDC_USER` (default `nobody`). TCP workers are capped
(`MAX_TCP_WORKERS`); SIGTERM/SIGINT stop `serve`. `--test-realm`
bootstraps documented principals (including `kadmin/admin` and
`kadmin/changepw`); with `KRB5_KDC_DB` + stash the test realm is saved
so a separate kadmind process can reload it. `--export-keytab` /
`KRB5_EXPORT_KEYTAB` writes the documented host principal. Issued PACs
include buffers 12/17/18 and store SID/RID. S4U2Proxy copies the
evidence PAC, requires a forwardable evidence ticket, and denies RBCD
unless allowed. Referral TGTs carry a PAC. TGS verifies a presented
TGT PAC with the ticket key and copies LOGON_INFO; a TGT without a PAC
still synthesizes identity from the store.

**`krb5-gss`** provides RFC 4121 wrap/MIC (MIT `libgssapi_krb5` is
out-of-process; `scripts/gss-gate.sh`). The acceptor binds
`expected_server` / `expected_realm` from the keytab. First wrap/MIC
seq is checked against the AP-REQ authenticator seq; wrap/MIC use a
windowed replay cache. Production `wrap` emits RRC=16 (AES confounder
size). SSPI peer proof remains environment-dependent.

**`krb5-admin`** is an ACL-enforced session plus listeners: version-1
AP-REQ framing (library tests) and `krb5-kadmind` ONC RPC program 2112
/ AUTH_GSSAPI flavor 300001 on TCP 749, RFC 3244 kpasswd on UDP/TCP
464 (`kadmin/changepw`, MIT `kpasswd` gated by
`scripts/kpasswd-gate.sh`), `krb5-kpropd` on 754 wrapping MIT dump
version 7 (`sendauth` `kprop5_01`, KRB-SAFE size, KRB-PRIV chunks).
MIT `kprop` then MIT `kinit` is gated by `scripts/kprop-gate.sh`.
Rust `krb5-kprop` → MIT `kpropd` then MIT `kinit` is
`scripts/kprop-reverse-gate.sh`.
MIT 1.22.2 `kadmin` add/get/list/mod/chrand/del is gated by
`scripts/kadmin-gate.sh`. A kadmind mutation survives KDC process
relaunch (`scripts/restart-gate.sh`).

**`krb5-config`** parses `krb5.conf` / `kdc.conf` and DNS SRV. The KDC
applies `kdc.conf` ticket policy from `KRB5_KDC_PROFILE` /
`KRB5_KDC_CONF` / `/etc/krb5kdc/kdc.conf`; without `--test-realm` it
also takes `database_name` / `key_stash_file` / `master_key_type` /
`db_library` / listen ports from that file. `kinit` and TGS referral chase call `discover_kdc` (`KRB5_CONFIG`
then `/etc/krb5.conf`); argv remains the fallback.

## Security invariants

- Key usage 0 is rejected (RFC 3961 §2).
- PBKDF2 iteration count 0 (RFC 3962 = 2^32) is rejected locally to
  avoid a cheap DoS; this is a documented limitation versus a strict
  reading of the RFC.
- Decrypt discards plaintext when the truncated HMAC does not match.
- No `unsafe` in this workspace (`forbid(unsafe_code)`).
- No C FFI.

## Observability

Every crypto and ASN.1 operation emits a `tracing` event with
`correlation_id`, `event`, `component`, `outcome`, and `duration_us`.
Crypto events include `etype` and `key_usage`. Failures include `error`.
See [logging.md](logging.md).
