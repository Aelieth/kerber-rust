# Testing strategy

Testing is continuous. Categories grow with the stages.

## Gate discipline

`scripts/ci-policy.py` enforces workflow YAML (fail-red jobs, nextest
`--profile ci` on every invocation, no per-push `cargo test
--workspace` or `cargo test --all`, `--no-run` + junit upload, no
echo-only `then`/`elif`/`else` arm in `scripts/*-gate.sh` or
`scripts/lib/*.sh`, `"ci.yml"` path-equality). A mixed `exit`+`echo`
chain is a hit. Multi-line `||` / `&&` / `\\` conditions are joined
before matching (including 2+ continuations). `echo | tee` / `echo >
file` is informational unless the arm also asserts. The ledger header
tally must match a recount of the verdict cells. It cannot check
red-at-HEAD artefacts: `working/` is gitignored. `__pycache__/` is
gitignored.

Red-at-HEAD artefact contract (captured under
`working/logs/…/<item>-red-at-head.log`): the file is captured tool
output of the failing unit or live cell, not a paraphrase. Write
"unit-red only; MIT by source" when MIT clients cannot emit the cell.
Retroactive red is `scripts/red-at-sha.sh <base-sha> <gate-script>
[args]`: a `git worktree` at the base SHA with `CARGO_TARGET_DIR`
under an absolute `KERBER_SCRATCH`, a provenance header (`base_sha=`,
`tree_sha=` from `git write-tree` after the overlay, `command=`,
worktree, probe sha256, `Compiling`/`Finished`, binary SHA-256s,
`gate_rc=`), HEAD `scripts/lib/*.{sh,py}`, `scripts/*.{c,py}`, and
the whole `harness/` tree copied into the worktree so probes and
docker builds are current, then the current gate script against
those binaries. The worktree is removed and `git worktree prune`d on
EXIT (the target dir stays).
Archive the captured output under `working/logs/…` and the scratch.
Both legs of a text-equality cell assert pinned literals (never
capture-from-MIT). Every branch asserts: no `if` whose body is only
`echo`.

Wire `e_text` is MIT's status word (`do_as_req.c:806`,
`do_tgs_req.c:205-206`). MIT `k5_setmsg` texts are KDC-log messages
and land in the `kdc.issue` `detail` field, not on the wire. A cell
that pins MIT text must say whether it is wire or log. The KDC MIT
1.22.2 parity ledger is [`mit-parity-ledger.md`](mit-parity-ledger.md);
a `proof` cell may name an existing gate script or `diffsend` case,
or mark that clause `proposed` / `propose`. `proposed` scopes only
the clause it is in (semicolon-separated).

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
`fuzz/` has 9 cargo-fuzz targets (DER, AS/TGS/AP, keytab/ccache,
PKINIT CMS, PAC NDR, SPAKE points, Oakley DH, GSS tokens, transited)
seeded from `tests/traces/` (transited also has `fuzz/corpus/transited/`).
CI smokes each target ~60s (`.github/workflows/fuzz.yml`; schedule,
dispatch, and PR on `fuzz/**` — no `push:` trigger). Transited seeds
are `crealm\\0srealm\\0contents` so `process_intermediates` is reached.

## Interop

The 1.0 external-oracle inventory is [`interop-matrix.md`](interop-matrix.md).

Primary oracle: MIT Kerberos **1.22.2** in `harness/`. Secondary:
Heimdal **7.8** in `harness/heimdal/` (`scripts/heimdal-gate.sh`). A
Windows Server 2022 Evaluation DC (`AD.KERBER.TEST`) is captured for
the AD round; see [`ad-lab.md`](ad-lab.md). Live AD commands use
`~/adlab` only — never `/etc/krb5.conf` or SSSD. SSPI remains later.

## Production-gate

Stage 1: harness starts twice, port 88 reachable, MIT `kinit` obtains a
TGT, structured logs include `correlation_id`.

Stage 3: `scripts/client-gate.sh` copies the Rust `krb5-kinit` binary
into the MIT 1.22.2 container (same network namespace as the KDC),
obtains a TGT and a `host/testhost.kerber.test` service ticket, and
runs MIT `klist` on the FILE ccache. Rust `krb5-klist -c -f -e` reads a
MIT-`kinit` FILE ccache and MIT `klist -f -e` reads the Rust-written
one (principal, service, flags, etype). `krb5-kvno` obtains
`host/testhost.kerber.test` via TGS (no `-U`/`-P`); MIT `klist` names
that ticket and a MIT `kvno` ticket is visible to Rust klist.
`krb5-kdestroy` zeros then
unlinks so MIT `klist` reports no cache. kdestroy refuses a symlink
(target intact) and the no-`-c` default is `/tmp/krb5cc_<uid>`. The client uses unconnected UDP
(`send_to`/`recv_from`) and ignores off-path source addresses. Host
Docker UDP/TCP publish to port 88 is unreliable; the gate therefore
talks to `127.0.0.1:88` *inside* the container.

G8a: `scripts/ccache-gate.sh` is a MIT 1.22.2 FILE/DIR/MEMORY oracle.
`ccache-mit-remove.c` calls MIT `krb5_cc_remove_cred` on a Rust-written
FILE; Rust `remove_cred` tombstones a MIT-written FILE (`endtime = 0`,
`authtime = -1`). Both `klist` implementations skip tombstones; MIT
`klist -C` still shows `config:` after a host-ticket remove. A MIT
`kinit` FILE round-trips through `FileCcache::parse` / `to_bytes`
byte-for-byte. DIR: two MIT `kinit` into `DIR:/tmp/dcc`, MIT
`kswitch -p` and Rust `krb5-kswitch -c DIR::` agree both ways.
MEMORY: a MIT FILE is stored and listed in-process. Unbuilt prefixes
(`KEYRING:`) are `Unknown credential cache type`. `KCM:` talks sssd-kcm
(`scripts/kcm-gate.sh`). DIR list of a missing
path does not create `primary`. Committed `tests/traces/ccache-mit-addr-u2u.bin`
(`kinit -a` + u2u) identity-checks addresses/authdata/`second_ticket`.
FILE write remains temp+rename (G8b gssproxy/SSSD oracles exit 2).
G8b: `kinit -kt` clustering, `klist -s` vs MIT `check_ccache`,
`scripts/knobs-gate.sh` (Heimdal `kdc_timeout` ignored; honored etype
list + `F`). `sssd-renew-gate` / `kit-conformance-gate` /
`gssproxy-gate` / `nfs-krb5p-gate` honest **exit 2** until vendored.
`scripts/kcm-gate.sh` is the G8c live sssd-kcm oracle (MIT `klist`
names `user@KERBER.TEST`); socket path is `KCM_SOCKET`, else
`[libdefaults] kcm_socket`, else `/var/run`→`/run`. The oracle
container runs `sssd_kcm` as in-container root (needs
`/var/lib/sss/secrets`); host isolation is the throwaway container,
not `useradd 4242`. Empty-residual
`kinit -c KCM:` re-INITIALIZEs the default (not MIT `krb5_cc_new_unique`).
`scripts/kcm-opcode-gate.sh` value-asserts F43/F42 opcodes on the
scheduled `kcm-opcode` workflow. Verdict [`kcm-nfs-verdict.md`](kcm-nfs-verdict.md)
(FILE stays until NFS cells run). R6 SSSD `krb5_child` renewal stays
exit 2 (image is socket-only).

Stage 5: `scripts/kdc-gate.sh` copies the Rust `krb5-kdc` binary into a
client-only MIT 1.22.2 container, binds 127.0.0.1:88 (fallback 8888),
and runs MIT `kinit user@KERBER.TEST` plus `kvno host/testhost.kerber.test`.
In-crate tests drive `issue_as` / `issue_tgs` / `Acl::check` /
`verify_ap_req` without a socket. The database oracle is MIT
`kdb5_util` dump/load (`scripts/kdb-dump-gate.sh`): MIT dump → Rust
load → Rust KDC → MIT `kinit`, and Rust dump → MIT `kdb5_util load` →
MIT `krb5kdc` → MIT `kinit`. Promotion is MIT `kinit` + `klist`, never
a Rust-vs-Rust round-trip. Golden dump: `tests/traces/kdb/mit-dump-v7.txt`
(MIT 1.22.2 default is version **7**; `-r18` is version 6).

Stage 4/5 GSS: `scripts/gss-gate.sh` copies `krb5-gss-accept` into the
MIT 1.22.2 container, exports `host/testhost.kerber.test` to a keytab,
and runs an out-of-process MIT `libgssapi_krb5` initiator (`scripts/gss-mit-client.c`)
that wraps `hello-from-mit-gss`. The Rust acceptor must unwrap that
plaintext. A second MIT initiator with `GSS_C_DELEG_FLAG` must make the
acceptor print `gss-accept delegated=user@KERBER.TEST`. A Rust initiator
with a KRB-CRED trailer must make MIT `gss-mit-server` print the same
name. A MIT SPNEGO initiator (`gss_mech_spnego`) must complete
`NegTokenResp` + `mechListMIC` and still unwrap `hello-from-mit-gss`.
A captured initiator AP-REQ resent on a new connection is 34
`REPEAT` (`authenticator replay`) on both the Rust acceptor and MIT
`gss-mit-server` (KRB-ERROR 34, `Request is a replay`). MIT `dfl`
file persistence across process restart is W1-C; Rust is in-memory.
MIT `gss_wrap_iov`
(HEADER|DATA|PADDING|TRAILER, and with `SIGN_ONLY`)
must unwrap on the Rust acceptor; Rust `wrap_iov` concatenates to a
token MIT `gss_unwrap_iov` STREAM accepts. The acceptor prints
`gss-accept import ok` and `inquire flags=` with lifetime > 0.

PKINIT: `scripts/pkinit-gate.sh` **fails** unless MIT `pkinit.so` is
present and MIT `kinit -X X509_user_identity=FILE:` succeeds against
the Rust KDC. The KDC log must contain `rfc8636 sha256 kdf` (MIT TRACE
`PKINIT used KDF 2B06010502030602`). Set `KERBER_CAPTURE_DIR` to write
raw PDUs under `tests/traces/`.

SPAKE: `scripts/spake-gate.sh` runs MIT `kinit` against the Rust KDC
with `preferred_preauth_types = 151` and `spake_preauth_groups = P-256`.
It fails unless TRACE contains `pa_type` 151 and group 2, and `klist`
shows `user@KERBER.TEST`. Reverse: `scripts/rust-kinit-spake-gate.sh`
is Rust `kinit --spake` against MIT KDC (`spake_preauth_groups = P-256`)
and MIT `klist` `user@KERBER.TEST`. FAST: `scripts/rust-kinit-fast-gate.sh`
is Rust `kinit --fast --armor-ccache` against MIT; the AS-REQ carries
PA-FX-FAST and MIT `klist` names `user@KERBER.TEST`. MIT 1.22.2 KDC TRACE
does **not** print `FX-FAST`; the gate asserts `Decrypted AP-REQ` (the
armor AP-REQ). Reverse FAST: `scripts/mit-fast-kdc-gate.sh` is MIT
`kinit -T` + `kvno` against the Rust KDC (TRACE upgrades on
`PA_FX_FAST`; KDC log ≥2 `KrbFastResponse`). Forged-realm armor
(`krb5-forge-tgt --keep-cipher --claim-realm`) is 35 `NOT_US` on
both MIT and Rust (`The ticket isn't for us`). Forged-realm FAST TGS
(`kvno` on a forged `kinit -T` ccache) is 7 `PROCESS_TGS` on both;
the MIT client line is required verbatim. Unit-red FAST negatives
(`phase7_preauth.rs`): bad `req_checksum` is 41, unkeyed is 12, unknown
armor type is 24, AS checksum ignores a dummy PA-TGS-REQ, TGS
authenticator cname mismatch is 36. MIT clients cannot emit these. Reverse PKINIT:
`scripts/rust-kinit-pkinit-gate.sh` is Rust `kinit --pkinit FILE:` against
MIT KDC (`pkinit.so` + KDC cert + `id-pkinit-san`); it **fails** if the
plugin is missing. MIT `klist` names `user@KERBER.TEST`. A follow-up
negative restarts MIT with `pkinit_identity` pointing at the *client*
cert; Rust `kinit` must fail with `pkinit kdc eku`. MIT not listening
on that identity is **red**. `scripts/pkinit-gate.sh` also
refuses MIT `kinit` with `other.pem` (SAN ≠ `user`) and greps the Rust
KDC log for `pkinit client san`. NT-ENTERPRISE:
`scripts/rust-kinit-enterprise-gate.sh` is MIT `kinit -E` against the
Rust KDC (klist default principal is the canonical `user@KERBER.TEST`)
**and** Rust `kinit -E` against MIT, which must match MIT `kinit -E`
(`CLIENT_NOT_FOUND` on MIT db2; no UPN alias). A foreign UPN suffix is
not a local alias. SPAKE: `scripts/rust-kinit-spake-gate.sh` sets
`+requires_preauth user` and asserts a SPAKE *completion* line
(`SPAKE response received` or `SPAKE derived K'`) from the MIT KDC TRACE,
not a PREAUTH_REQUIRED offer. FAST: `scripts/rust-kinit-fast-gate.sh`
asserts `Decrypted AP-REQ` from TRACE only.

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

MSRV is 1.95 (`package.rust-version`), edition 2024, matching KLLDAP
0.7.5. The `msrv` CI job is `cargo test --workspace --locked` on that
toolchain. `rasn` is unpinned (`0.28`); golden MIT DER is the protocol
net if encodings drift. There is no unlocked `--locked` fallback.
KLLDAP alignment: [`integration-klldap.md`](integration-klldap.md).

Era II gates. The harness CI job runs `kadmin-gate`, `kadmin-local-gate`, `policy-gate`, `history-mit-gate`, `kpasswd-gate`, `rust-kpasswd-mit-gate`, `ktutil-gate`, `mit-fast-kdc-gate`,
`kdb-dump-gate`, `differential-gate`, `kprop-gate`, `kprop-reverse-gate`, `iprop-gate`,
`expire-gate`, `flags-gate`, `renew-gate`, `postdate-gate`, `getprivs-gate`, `prop-acl-gate`, `restart-gate`,
`prod-gate`, `prod-realm-gate`, `stress-gate`, `chaos-gate`, `soak-gate`, `s4u-mit-gate`, `samba-ad-gate`, `ad-windows-gate`,
`ad-s4u-gate`, `samba-pac-verify-gate`, `samba-pac-l2-gate`,
`samba-crossrealm-gate`, `samba-realtrust-gate`, and `heimdal-gate` after `pkinit-gate`.
`ad-*` are live Samba (`samba-ad-dc`), not the torn-down Windows DC.
`heimdal-gate` is live Heimdal 7.8 both directions. `gss-sspi` exits 2
when that oracle is absent.

- `scripts/samba-ad-gate.sh` — Samba 4 AD DC. The only `exit 0` is after a
  live `kinit`/`kvno`/`klist`. Missing docker, image, or KDC is `exit 2`
  plus `samba-ad-gate-unavailable.log`.
- `scripts/samba-pac-verify-gate.sh` — co-located Rust KDC on `:8888`;
  Samba `PAC_DATA_RAW` + typed LOGON_INFO/REQUESTOR of a Rust-issued PAC
  (buffers 1,10,12,16,17,18,19,6,7). Dummy SID fails.
- `scripts/samba-pac-l2-gate.sh` — vendored Samba `kcrypto` (RFC 3961 AES
  checksums) recomputes PAC 6/7/16/19 of a Rust-issued ticket. Type-16 is
  hashed in the oracle over the raw EncTicketPart with PAC ad-data
  `0x00`. A type-6 MAC byte flip (`off+4`) must print `L2_MISMATCH` (not
  `L2_MISSING`). A second negative flips a pre-PAC EncTicketPart primitive
  byte (type-16 signed bytes) and must print `L2_MISMATCH` including `16`.
  Type-16 pre-image **transliteration**: Python `zero_pac_ad_data` is a
  port of the Rust rewriter, not Samba C; reverse `samba-realtrust-gate`
  is the live Samba type-16 oracle. Missing image/`kcrypto` is `exit 2`.
- `scripts/samba-realtrust-gate.sh` — two Samba AD DCs; real
  `samba-tool domain trust create` (fail with images present is `exit 1`);
  both-direction `kvno`; reverse Rust service PAC LOGON_INFO SID/RID
  equals live Samba-A `kbruser` `objectSid`. Missing images `exit 2`.
- `scripts/samba-crossrealm-gate.sh` — shared-trust-password TDO;
  MIT `kvno` `user@KERBER.TEST` → `host/svc.ad.kerber.test` and
  `kbruser@AD.KERBER.TEST` → `host/testhost.kerber.test`. Samba logs
  must not contain `PAC … failed`. `kvno` is not proof that the TGS
  copied LOGON_INFO; that copy is `tgs_copies_foreign_referral_pac_identity`
  / `tgs_rejects_corrupt_foreign_referral_pac` in
  `crates/krb5-kdc/tests/phase7_preauth.rs`. Type-16 is hashed over the
  original EncTicketPart bytes with PAC ad-data a single zero.
- `scripts/ad-windows-gate.sh` — live Samba `kinit kbruser@AD.KERBER.TEST`
  then `kvno host/svc.ad.kerber.test` (aes256-cts-hmac-sha1-96). Samba
  kvno is 2 (Windows lab was 3). Missing image is `exit 2`.
- `scripts/ad-s4u-gate.sh` — live Samba: `kinit -f -k kbrsvc` then
  MIT `kvno -U kbruser kbrsvc` (S4U2Self) and
  `kvno -U kbruser -P host/svc.ad.kerber.test` (S4U2Proxy). klist must
  name `host/svc.ad.kerber.test` `for client kbruser@AD.KERBER.TEST`.
  Windows used a computer account `host/svc`; Samba registers that SPN
  on `kbrsvc` (S4U2Self to `host/svc` is `client and server principal
  names must match`).
- `scripts/s4u-mit-gate.sh` — MIT `kvno -U user` and `kvno -U user -P`
  against the **Rust** KDC (`kinit -f -k host/testhost.kerber.test`).
  The user-TGT → host S4U2Self mismatch cell runs against both the MIT
  KDC (default entrypoint, :88) and the Rust KDC (:8888); both log
  `INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH`. klist must name
  `for client user@KERBER.TEST`. `kvno -U nosuch` is `Client not found`;
  `kvno -U locked` (`KRB5_TEST_LOCKED_USER`, `DISALLOW_ALL_TIX`) is
  `credentials have been revoked`. S4U2Proxy rejects a non-forwardable
  evidence ticket (`BADOPTION`), denies classic constrained delegation
  unless `s4u_allowed_to` lists the target, and parses PA-PAC-OPTIONS
  (167). In CI (`mit-extra`).
- `scripts/policy-gate.sh` — MIT `kadmin` addpol/modpol/getpol/listpols/`cpw`/delpol
  against `krb5-kadmind`; too-short and reuse; `-minclasses 5`; history-N
  (current counts inside N);
  `maxfailure 2` reset then `CLIENT_REVOKED`; lockout duration / failcnt
  interval. In CI.
- `scripts/store-gate.sh` — `db_library=memory` KDC seeded from `--test-realm`;
  MIT `kinit` + `kvno`. In CI after `kdc-gate`.
- `scripts/iprop-gate.sh` — MIT `kpropd -A` must not report IPROP
  program unregistered. After first-contact kprop `-i` (ipropx),
  mutate the master, restart the Rust kadmind, and require serial-delta
  with no extra FULL_RESYNC: MIT `kinit extra` on the MIT replica;
  `krb5-iprop-pull` vs MIT kadmind then MIT `kinit extra2` (replica dump
  keeps `setstr` TL 0x000b); extra2's replica PAC RID is not 1000
  (same RID as the master is deferred: MIT kdbe has no SID and
  incremental encode omits vendor `0x4B0x` TL);
  MIT `delprinc extra2` then the name is gone on the Rust replica. In CI.
- `scripts/expire-gate.sh` — MIT `kinit` NAME_EXP vs KEY_EXPIRED;
  `kinit -S kadmin/changepw` on a password-expired client; TGS `kvno`
  after client `-pwexpire`/`-expire` still succeeds; `modprinc +needchange`
  is `KEY_EXPIRED` unless the server is `PWCHANGE_SERVICE`. In CI.
- `scripts/flags-gate.sh` — MIT `modprinc` DISALLOW_*/OK_AS_DELEGATE/
  REQUIRES_HW_AUTH then `kinit`/`kvno`/`klist -f`. In CI.
- `scripts/renew-gate.sh` — four-term renew: `getprinc` krbtgt and user
  `Maximum renewable life` not `0 days`; `kinit -r 7d` `renew until` ≈
  start + 7d; then `kinit -R` (endtime moves, `renew until` unchanged);
  `-allow_renewable` strips `R`; `kinit -p` shows `P`. In CI.
- `scripts/knobs-gate.sh` — `kdc_timeout`/`max_retries` ignored; honored
  `forwardable` + `default_tkt_enctypes`; `default_ccache_name`
  env > conf (`%{uid}`) > builtin; `[domain_realm]` + conf
  `proxiable` (MIT and Rust `kvno` host tickets both `PT`). In CI
  (MIT harness).
- `scripts/capaths-transit-gate.sh` — MIT `kvno` A.TEST→B.TEST→C.TEST
  vs three live MIT 1.22.2 KDCs, then the same chase vs three Rust
  KDCs; EncTicketPart transited (`tr-type` 1, contents `B.TEST`) and
  `TRANSITED_POLICY_CHECKED` match; missing capaths is `KDC policy
  rejects request` (12). Skip cells grep **only the new lines** of
  **that cell’s KDC-under-test log** for `BAD_TRANSIT` (MIT `FILE:`
  kdc log for MIT cells; Rust JSON `kdc.issue`/`krb-error` for Rust
  cells) and C-skip `klist` shows `krbtgt/C.TEST@B.TEST`.
  `krb5-kvno --disable-transited-check` vs default MIT and Rust is
  POLICY; with `reject_bad_transit=false` the skip is accepted and T
  is off. Forged `ticket.realm` on a B-sealed `krbtgt/C.TEST` (empty
  transited) is rejected at both MIT C and Rust C (`PROCESS_TGS`).
  `host/svc.c.test@GARBAGE.EXAMPLE` aimed at C (`--body-realm`) is 60
  `GET_LOCAL_TGT` on both MIT and Rust. Dest RENEW at C with issuer
  `body.realm` is 60 both sides. A peer-minted TGT for a local user
  (`--claim-crealm`) is `INVALID LINEAGE` on both sides. A seeded C TGT
  plus `krb5-kvno -U victim@A.TEST user@C.TEST` is 36
  `INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH` on both MIT C and Rust C
  (name collision across realms; `-U` `body.realm` is the presented
  TGT realm, no S4U referral walk). `krb5-kvno --renew` requires
  `--body-realm` (exit 2). A seeded C TGT plus inbound
  `krbtgt` `DISALLOW_ALL_TIX` is 7 `PROCESS_TGS` on both MIT C
  (`modprinc -allow_tix`; client `Server <sname> not found in Kerberos
  database`) and Rust C. Bare A TGT plus Rust `krb5-kvno
  host/svc.c.test@C.TEST` chases MIT A→B→C (`body.realm` is the current
  TGT realm). In CI (`mit-extra`).
- `scripts/capaths-compress-gate.sh` — MIT 4-hop
  A.EX.COM→EX.COM→B.EX.COM→C.EX.COM; EncTicketPart contents
  `EX.COM,B.`, expanded `EX.COM,B.EX.COM`, T set; deny is `KDC
  policy rejects request`. In CI (`mit-extra`).
- `scripts/config-include-gate.sh` — MIT vs Rust on the same
  `include`/`includedir` + colon-split `KRB5_CONFIG` tree: dotted
  `10.conf` is read; two-file scalar first-wins; missing include
  fails (does not hang). In CI (MIT harness).
- `scripts/sssd-renew-gate.sh` / `kit-conformance-gate.sh` /
  `gssproxy-gate.sh` / `nfs-krb5p-gate.sh` — honest **exit 2** until the
  Fedora/kit/NFS oracles are vendored (CI treats 2 as skip). R6
  SSSD-side `krb5_child` renewal is still ungated.
- `scripts/kcm-opcode-gate.sh` — live F43/F42 `sssd_kcm`; asserts
  `GET_CRED_LIST=ok` and `RETRIEVE`/`REPLACE`=`KRB5_FCC_INTERNAL`.
  Scheduled/dispatch (`kcm-opcode.yml`), not per-push.
- `scripts/postdate-gate.sh` — MIT `kinit -s` is INVALID (`i`), `kvno`
  is TKT_NYV; `kinit -v` after starttime is usable; `-allow_postdated`
  is CANNOT_POSTDATE. In CI.
- `scripts/getprivs-gate.sh` — MIT `kadmin getprivs` as a limited `i`
  actor is INQUIRE only; `cpw -randkey` is AUTH_CHANGEPW
  (`change-password` privilege), not AUTH_GET. In CI.
- `scripts/prop-acl-gate.sh` — MIT `kprop` vs unset or empty
  `KRB5_KPROP_ACL` is refused (no replica dump); host allowlist still
  loads. In CI.
- `scripts/kadmin-gate.sh` — MIT `kadmin` against `krb5-kadmind` on 749
  (AUTH_GSSAPI 300001): `addprinc`, `cpw`, `getprinc` (`Principal:
  extra@KERBER.TEST`; last password change is not `[never]`; last
  modified is not Unix epoch), `listprincs` (names `extra` and `user`),
  `modprinc +requires_preauth` then `kinit`, `cpw -randkey` (old
  password must fail; last password change / last modified move) +
  `ktadd` + `kinit -k`, `ktadd -norandkey` +
  `kinit -k`, `+lockdown_keys` (cpw is `change-password` privilege;
  `ktadd -norandkey` of lockee/krbtgt/`kadmin/changepw` is `extract-keys`;
  `delprinc`/`renprinc` of a locked-down principal is `delete`;
  `modprinc -lockdown_keys` is `modify`; `getprinc krbtgt` shows
  `LOCKDOWN_KEYS`),
  `purgekeys` (old kvno gone), `cpw -keepold` (getprinc lists both kvnos),
  `setstr`/`getstrs`, `renprinc -force`
  `renamefrom`→`renameto` then `getprinc` new / old fails / `kinit -k`
  new, `delprinc` then `getprinc` error. Rename uses `-randkey` (MIT
  default-salt password keys may not `kinit` after rename). Run twice.
- `scripts/kadmin-local-gate.sh` — Rust `krb5-kadmin-local` `addprinc`
  extra2 and `host/slashhost` on dump/stash; MIT `kadmin` getprinc
  names `extra2@KERBER.TEST` and `host/slashhost@KERBER.TEST` (slash
  is two name-string components). Set-but-unreadable `KRB5_ACL_FILE`
  exits non-zero. `-randkey` then MIT `getprinc` `vno 1` and
  `kinit -k`; `+requires_preauth` on MIT `getprinc`; two `ktadd -k`
  leave both principals (`klist -k`); dump-based `getprinc` after a
  mutating local `setstr` must keep a concurrent `kadmind` `addprinc`
  (`m5k: m5v` via `getstrs`); local `addprinc n7local` then remote
  `cpw extra2` must keep both on a fresh dump. Run twice.
- `scripts/kpasswd-gate.sh` — MIT `kpasswd` against kadmind UDP/TCP
  464 (`kadmin/changepw`), then `kinit` with the new password; old
  password must fail; second `kpasswd` + `kinit`; then Rust
  `krb5-kpasswd` against the same Rust kadmind. A `-minlength 8`
  policy rejection is RFC 3244 `SOFTERROR` (`[0,4]`; MIT `kpasswd`
  rc 2, `Password change rejected`) on both Rust kadmind and MIT
  `kadmind`. A TGT-based `kvno kadmin/changepw` / `kadmin/admin` is
  refused (`KDC policy rejects request`; KDC `TGT BASED NOT ALLOWED`)
  on both KDCs; `getprinc` shows `DISALLOW_TGT_BASED`/`LOCKDOWN_KEYS`;
  remote `ktadd -norandkey` is `extract-keys`. After `+allow_tgs_req`,
  a TGS-obtained `kadmin/changepw` ticket self-change is result 7
  `Ticket must be derived from a password` on both kadminds
  (`scripts/kpasswd-tgs-client.c`), including
  `KPASSWD_TARGNAME_TYPE=0`. MIT vno-1 kadmind log is `chpw request from
  127.0.0.1 for user@KERBER.TEST: Operation requires initial ticket`;
  the type-0 (`krb5_set_password`) cell pins `setpw request from
  127.0.0.1 by user@KERBER.TEST for user@KERBER.TEST: Operation
  requires initial ticket` on both legs. An unprivileged other
  principal (`KPASSWD_TARGET=extra@KERBER.TEST`) is result 5
  `Unauthorized request` on both legs. Run twice.
  `scripts/rust-kpasswd-mit-gate.sh` is Rust `krb5-kpasswd` against
  MIT `kadmind` (AS-REQ sname `kadmin/changepw`; MIT
  `DISALLOW_TGT_BASED`).
- `scripts/kdb-dump-gate.sh` — MIT 1.22.2 dump/load both directions.
  Half A: `krb5-kdb load` of `tests/traces/kdb/mit-dump-v7.txt`, Rust
  KDC, MIT `kinit user` / `kinit pauser` (`REQUIRES_PRE_AUTH` = 128).
  Half B: MIT `kdb5_util load` of the **running KDC at-rest file**
  (`kdb5_util load_dump version 7`, not KDB3), MIT `krb5kdc`, MIT
  `kinit` with `renew until` in `klist`. Run twice.
- `scripts/differential-gate.sh` — one dump, two live KDCs (Rust `:8888`,
  MIT 1.22.2 `krb5kdc` `:88`). `examples/diffsend.rs` encodes each
  AS/TGS case **once** and TCP-exchanges the same bytes to both.
  KRB-ERROR compares `error_code`/`realm`/`sname`/`e_text` (mask
  `stime`/`susec`/`ctime`/`cusec`; PREAUTH `e_data` is
  structural; extra FAST/SPAKE PA types are mechanism ads; MIT
  ETYPE-INFO2 must be a subset of the Rust set — MIT lists the
  chosen etype, Rust lists every key). A foreign-realm AS-REQ is MIT `C_PRINCIPAL_UNKNOWN(6)`
  `CLIENT_NOT_FOUND`, not RFC `WRONG_REALM(68)`.
  A TGS with a non-krbtgt presented ticket is MIT `NOT_US(35)`
  `BAD TGS SERVER NAME`.
  AS-REP/TGS-REP decrypt, null volatiles, and compare the
  stable set. Ticket flags compare the full flag word; only named
  whitelist bits (renewable, canonicalize) are masked. Un-whitelisted
  divergence is fail-red. Honest `exit 2`
  only when docker/MIT image is absent. In CI (bare `run:`).
  Compare lives behind `krb5-protocol` feature `diff` (`examples/diffsend`
  and the unit fixture); it is not on the default public API.
  **TGS vehicle:** success TGS cases mint a PAC-less TGT with the
  exported krbtgt key (etype 20, empty `tr-type` 1). A live Rust PAC
  TGT is `PROCESS_TGS` at MIT; an MIT PAC TGT fails Rust type-16
  verify. PAC copy/re-sign is not exercised on this path.
  **Whitelist (with justification):**
  - `mit-renewable-flags` — MIT default policy issues renewable
    tickets (`kdb-dump-gate` `klist` `renew until`). Rust *does*
    issue renewable when the client requests it; the remaining gap
    is default-policy, not an inability to set the flag.
  - `mit-as-padata` — MIT adds `PA-ETYPE-INFO2` / `PA-SUPPORTED-ENCTYPES`
    on replies; those types are filtered before compare.
  - `mit-order-tgs-times` — MIT fails expired/NYV header tickets
    inside `PROCESS_TGS` (`rd_req`); Rust's `check_ticket_times`
    uses `TKT_EXPIRED` / `NOT_YET_VALID`. Same error_code.
  - `mit-as-enc-app-26` — MIT wraps AS enc-part as APPLICATION 26
    (RFC 4120 is 25); decode accepts 25/26/untagged.
  - `mit-as-enc-kvno` — MIT omits AS-REP enc-part kvno; Rust sets kvno 1.
  - `mit-extra-ticket-flags` — MIT sets canonicalize (bit 15) on issued
    tickets; that bit is masked. Any other un-whitelisted flag bit
    fails red. Same-realm TGS sets `TRANSITED_POLICY_CHECKED` (bit 12)
    when the transited check ran, matching MIT; it is not whitelisted.
    Default `reject_bad_transit` rejects `DISABLE_TRANSITED_CHECK` as
    POLICY (12); `reject_bad_transit=false` accepts with T off.
    AS-REP TGTs do not set bit 12.
- `scripts/kprop-gate.sh` — MIT `kprop` of a version-7 dump to
  `krb5-kpropd` on 754 (`kprop5_01` sendauth, KRB-SAFE size, KRB-PRIV
  32768-byte chunks), then MIT `kinit user` against the replica Rust
  KDC. `klist` names `user@KERBER.TEST`. Run twice.
- `scripts/kprop-reverse-gate.sh` — Rust `krb5-kprop` to MIT `kpropd`
  (`kpropd -S -P 754`), then MIT `krb5kdc` + MIT `kinit user@KERBER.TEST`.
  Additive to the in-process kprop dump/send tests in `krb5-admin`; it does
  not replace them. Missing MIT image is `exit 2`. Run twice.
- `scripts/restart-gate.sh` — MIT `kadmin addprinc extra`, MIT `kinit`,
  kill `krb5-kdc` by `/proc/PID/comm`, relaunch the same binary on the
  same db/stash, MIT `kinit extra` still works. Then MIT `kdb5_util load`
  of the daemon-persisted dump-v7 file. Run twice.
- `scripts/prod-gate.sh` — Rust KDC on `127.0.0.1:18888`, `krb5-kinit`
  AS+TGS, structured-log analysis (`kdc.issue` + `correlation_id`),
  PDU pcap under `$KERBER_SCRATCH/prod-gate/` (loopback CAP_NET_RAW
  is unavailable in rootless distrobox; pcap is reconstructed from
  `KERBER_CAPTURE_DIR`). Kept as the loopback gate.
- `scripts/prod-realm-gate.sh` — C1 multi-host: `PROD.KERBER.TEST` on a
  docker network (Rust primary + Rust replica + MIT client). MIT `kinit`/
  `kvno`/`kadmin addprinc+ktadd` against the primary; Rust `krb5-kprop`
  to the replica `:754`; kill primary; MIT `kinit`/`kvno` against the
  replica. Structured-log analysis + real NIC pcap when `NET_RAW` works
  (`pcap-source=reconstructed` otherwise; reconstructed still requires
  AS/TGS PDUs 10/11/12/13). CI sets `KERBER_REQUIRE_REAL_PCAP=1` so
  missing eth0 capture fails red. In CI after `prod-gate`.
- `scripts/stress-gate.sh` — C2a: concurrent wire AS+TGS via
  `examples/loadgen.rs` plus MIT `kinit`/`kvno` under load. Throughput
  uses `kdc.issue` timestamps or `duration_us`, not Docker wall clock.
  p99/throughput undershoot with `kdc_issue_err==0` and no panics is a
  warning; error-rate and panics stay hard-fail. `kdc_issue_krb_error`
  is counted and kept out of `min-issue-ok`. Own CI job (`slo`),
  `continue-on-error`; not on the required per-SHA path.
- `scripts/chaos-gate.sh` — C2b: `tc netem` delay/loss/reorder (MIT
  must complete), low `--memory` under load (no OOM-panic), `docker kill`
  of the primary mid-load then MIT `kinit`/`kvno` on the kprop replica
  (including a kadmin-created host). `KERBER_REQUIRE_NETEM=1` in CI
  dies unless netem applied; after kill, `State.Running=false`. Own CI
  job (`chaos`), `continue-on-error`.
- `scripts/soak-gate.sh` — C2c: sustained moderate load (~70 s in CI,
  300 s scheduled in `.github/workflows/soak.yml`). RSS last ≤ first×1.5
  + 8 MiB and slope ≤ 0.05 MiB/s; window-over-window `duration_us` p99
  must not degrade by more than 2.5×; error-rate 0; panics 0;
  `correlation_id` on issue-ok. `KERBER_REQUIRE_REAL_PCAP=1` fails
  unless the client tcpdump archive is present. Archives logs + pcap +
  RSS/latency series. Per-push `soak` is `continue-on-error`; the
  scheduled workflow is fail-red. Per-push `continue-on-error` is only
  `slo` / `chaos` / `soak`. `scripts/rust-kinit-fast-gate.sh` is fail-red
  on `mit-extra` (SHA-2-first FAST vs MIT).
- `scripts/heimdal-gate.sh` — Heimdal 7.8 secondary oracle
  (`harness/heimdal/`, Debian bookworm apt, no `krb5-user`). The only
  `exit 0` is after both directions content-assert AES-SHA1
  (`aes256-cts-hmac-sha1-96`): Heimdal `kinit` + `kgetcred` against the
  Rust KDC with `klist` naming `user@KERBER.TEST` and
  `host/testhost.kerber.test`, then Rust `krb5-kinit` against the
  Heimdal KDC with Heimdal `klist` naming the same principals. Bookworm
  Heimdal 7.8 has no RFC 8009 etypes 19/20; the image pins
  `default_etypes` and the HDB master key to etype 18. Missing
  docker/image is honest `exit 2` plus
  `heimdal-gate-unavailable.log`. Samba PAC L1/L2/L3, realtrust, and
  Heimdal run on the scheduled `peers` workflow (fail-red, no
  `continue-on-error`); not required per SHA.
  TGS-REP `name-type` is a hint (RFC 4120 §6.2); Heimdal canonicalize
  may return NT-SRV-HST for a host principal requested as NT-PRINCIPAL.
- `scripts/gss-sspi-gate.sh` — exit 2 + unavailability log when that
  oracle is absent.
- `scripts/ad-mit-trust-gate.sh` — alias of `samba-realtrust-gate.sh`
  (does not claim a Windows DC).

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
