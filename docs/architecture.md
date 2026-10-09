# Architecture

kerber-rust is a Cargo workspace of small crates. A crate depends only on
crates in the layers below it:

```
tools     krb5-tools (gate tools)       examples/consumer, examples/kdc-consumer
daemons   krb5-admin
roles     krb5-kdc     krb5-client     krb5-gss     (krb5-testkit: test helpers)
wire      krb5-protocol
codecs    krb5-asn1    krb5-crypto     krb5-config
base      krb5-types   krb5-log        krb5-cli
```

`krb5-admin` uses `krb5-kdc` and `krb5-gss`; `krb5-kdc`, `krb5-client` and
`krb5-gss` sit on `krb5-protocol`, which uses the three codec crates;
`krb5-asn1` uses `krb5-types` and `krb5-log`, `krb5-crypto` uses `krb5-log`,
and `krb5-config` uses `krb5-types`. The tools' command lines and password
prompts come from `krb5-cli`, which depends on no other crate here.

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

**`krb5-protocol`** runs AS/TGS/AP/SAFE/PRIV/CRED (AS and TGS over UDP with
TCP fallback), plus MIT keytab and FILE ccache, so the KDC does not depend
on the client crate. UDP uses
`send_to`/`recv_from` and ignores off-path source addresses. Reply
compare (`diff`) masks KRB-ERROR times/`e_text` and nulls AS/TGS
volatiles so `scripts/differential-gate.sh` can fail red on an
un-whitelisted MIT divergence.

**`krb5-client`** is `kinit` and the user CLIs over MIT FILE ccache v4 and
keytab v2 (the password comes from env or stdin, never argv).

**`krb5-kdc`** issues AS/TGS from an in-memory store. The at-rest file
is MIT dump version 7 (stash still holds the master key; SID/RID in
`TL_KERBER_SID`). Legacy KDB3 ciphertext still loads for one release.
`krb5-kdb` is MIT's `kdb5_util` (create, stash, dump, load, destroy). `key_data` uses KDB usage 0
with a cleartext `int16_LE` length prefix; protocol `KeyUsage::new(0)`
stays rejected. The serving store is `Arc<RwLock<PrincipalStore>>` so
kadmind/kpasswd mutations reach `save_store`. The `krb5-kdc` daemon
takes MIT `krb5kdc`'s options, listens where kdc.conf says (every local
address by default), detaches unless `-n`, and writes MIT's text log
where `[logging]` says ([logging.md](logging.md)). It always serves a
database file and, as MIT's, keeps its user; only a `test-hooks` build
serving the test realm without one drops to `KRB5_KDC_USER` (default
`nobody`) after a privileged bind. It serves every client from MIT's
net-server loop on its main thread, one thread: at most 45 TCP streams
(`MAX_TCP_WORKERS`), the one that started first evicted past that, and
no stream timeout, as MIT's. `krb5-kadmind` serves kpasswd and kadm5
from the same loop: one cap of 45 over its streams and RPC connections,
and each read of a kadm5 record waits at most 35 s, as MIT's.
As MIT's daemons, `krb5-kdc` and `krb5-kadmind` stop on SIGINT,
SIGTERM or SIGQUIT and reopen their log files on SIGHUP. In a
`test-hooks` build, `--test-realm`
bootstraps documented principals (including `kadmin/admin` and
`kadmin/changepw`); with `KRB5_KDC_DB` + stash the test realm is saved
so a separate kadmind process can reload it. `--export-keytab` /
`KRB5_EXPORT_KEYTAB` writes the documented host principal. Issued PACs
are MIT's (CLIENT_INFO, DELEGATION_INFO and the checksums) unless there
is AD data — kdc.conf `domain_sid`, or a subject PAC carrying
LOGON_INFO — which keeps the AD shape (buffers 1/12/17/18, store
SID/RID). S4U2Proxy requires a forwardable evidence ticket and denies
RBCD unless allowed. Referral TGTs carry a PAC. TGS verifies a presented
TGT PAC with the ticket key and carries its client info (and, with AD
data, its LOGON_INFO); a TGT without a PAC gets a ticket without one.

**`krb5-gss`** provides RFC 4121 wrap/MIC (MIT `libgssapi_krb5` is
out-of-process; `scripts/gss-gate.sh`). The acceptor binds
`expected_server` / `expected_realm` from the keytab. First wrap/MIC
seq is checked against the AP-REQ authenticator seq; wrap/MIC use a
windowed replay cache. Production `wrap` emits RRC=0 (MIT 1.22.2);
`wrap_iov` is AES/RFC 8009 only. SSPI peer proof remains
environment-dependent.

**`krb5-admin`** is an ACL-enforced session plus listeners: version-1
AP-REQ framing (library tests) and `krb5-kadmind` ONC RPC program 2112
/ AUTH_GSSAPI flavor 300001 on TCP 749, RFC 3244 kpasswd on UDP/TCP
464 (`kadmin/changepw`, MIT `kpasswd` gated by
`scripts/kpasswd-gate.sh`), `krb5-kpropd` on 754 wrapping MIT dump
version 7 (`sendauth` `kprop5_01`, KRB-SAFE size, KRB-PRIV chunks).
MIT `kprop` then MIT `kinit` is gated by `scripts/kprop-gate.sh`.
Rust `krb5-kprop` → MIT `kpropd` then MIT `kinit` is
`scripts/kprop-reverse-gate.sh` (additive to the in-process kprop tests).
A multi-host MIT client against a Rust primary and replica is
`scripts/prod-realm-gate.sh`. Wire stress, chaos and soak over that realm
are `scripts/stress-gate.sh`, `scripts/chaos-gate.sh`, and
`scripts/soak-gate.sh`.
MIT 1.22.2 `kadmin` add/get/list/mod/chrand/del is gated by
`scripts/kadmin-gate.sh`. Named policies and lockout:
`scripts/policy-gate.sh`. Iprop serial/ulog and `kpropd -A`:
`scripts/iprop-gate.sh`. Extension points: [`plugins.md`](plugins.md)
(traits, not dlopen). A kadmind mutation survives KDC process
relaunch (`scripts/restart-gate.sh`). The database is locked between
processes as MIT's db2 module locks it (`dblock.rs`): `principal.ok` and
`principal.kadm5.lock` beside it, whole-file OFD locks, shared for every read
(the KDC only while it sees whether the database changed and reads it again,
or reads a client's lockout record) and exclusive for every change from a
fresh read of the dump to its one write and the age bump
(`PrincipalStore::change`), so a concurrent local `addprinc` survives a remote
`cpw` and no writer saves over another. The KDC takes it exclusively only to
update a client's record in `principal.lockout` in place (`lockout/file.rs`), which
leaves the database and its age alone.

**`krb5-config`** parses `krb5.conf` / `kdc.conf` and DNS SRV. Every
KDC-side tool finds kdc.conf and the database through `KdcPaths`, as MIT's
`kadm5_get_config_params` does: the profile is `KRB5_KDC_PROFILE`, else
`KDC_DIR/kdc.conf`, and a missing one reads as empty;
`database_name` / `key_stash_file` / `acl_file` / `master_key_type` come from
the realm's own stanza (the named realm, else `default_realm`; with neither
the tool stops as MIT's does), else MIT's defaults under `KDC_DIR`
(`/var/kerberos/krb5kdc`, set at build time by `KERBER_KDC_DIR`); only a
`test-hooks` build puts the gates' `KRB5_KDC_CONF` / `KRB5_KDC_DB` /
`KRB5_KDC_STASH` / `KRB5_ACL_FILE` / `KRB5_MASTER_ETYPE` on top. The KDC also
takes ticket policy, `db_library` and listen ports from that file. `kinit` and
TGS referral chase call `discover_kdc` (`KRB5_CONFIG` then `/etc/krb5.conf`);
argv remains the fallback.

**`krb5-cli`** is MIT's command-line shapes and password prompts for the
tools: glibc `getopt` (with the leading `+` that stops at the first operand),
option tables matched by exact spelling for the tools MIT parses by hand
(`kdb5_util`'s globals anywhere on the line, `kadmind`'s `-nofork` / `-port`),
and `krb5_prompter_posix` / `krb5_read_password` (one line per prompt from a
pipe, echo off on a terminal, `Password mismatch`).

**`krb5-tools`** holds the harness-only gate tools (`diffsend`, `loadgen`,
`krb5-forge-tgt`, …; `publish = false`), built only beside `krb5-kdc/test-hooks`.
It is not a product surface.

**`krb5-testkit`** holds shared test helpers (`publish = false`, a
dev-dependency only).

## Security invariants

- Key usage 0 is rejected (RFC 3961 §2).
- PBKDF2 iteration count 0 (RFC 3962 = 2^32) is rejected locally to
  avoid a cheap DoS; this is a documented limitation versus a strict
  reading of the RFC.
- Decrypt discards plaintext when the truncated HMAC does not match.
- No `unsafe` in this workspace (`forbid(unsafe_code)`).
- No C FFI.

## Code conventions

- Errors are typed enums per crate (most derive `thiserror`). There is no
  `anyhow` and no crate-wide `Result<T>` alias, so every signature names
  its error type.
- Logs carry explicit fields (see [Observability](#observability)) rather
  than `#[instrument]` spans.
- The comment and rustdoc rules (R1 to R4) are in
  [CONTRIBUTING.md § Code comments](../CONTRIBUTING.md#code-comments);
  `check_mit_anchor_form`, `check_mit_anchor_truth` and
  `check_no_process_history` in `scripts/ci-policy.py` keep R1 and R3 true
  (see [testing.md](testing.md)).

## Observability

Every crypto and ASN.1 operation emits a `tracing` event with
`correlation_id`, `event`, `component`, `outcome`, and `duration_us`.
Crypto events include `etype` and `key_usage`. Failures include `error`.
See [logging.md](logging.md).
