# Gates

Every `scripts/*-gate.sh`, one row each: the oracle it content-asserts
against, where it runs (`workflow:job` in `.github/workflows`), its lane,
and what it asserts. `ci-policy.py` `check_gate_documented` holds this
table to the scripts and the workflows: a gate with no row, a row for no
gate, a workflow or lane cell that differs from the workflows, an unknown
oracle or an empty assertion is red. The jobs, their budgets and the tiers
are in [testing.md § CI lanes](testing.md#ci-lanes-which-job-runs-which-gates)
and its Tier contract; the gate rules are in
[testing.md § Gate discipline](testing.md#gate-discipline).

Lanes: **fail-red**, a red blocks the push; **skip2**, the step runs the
gate through `skip2`, so exit 2 (oracle unavailable) is green; **soft**, a
`continue-on-error` job; **nightly**, a scheduled workflow (a red is a red,
but a push does not wait for it). **stub** and **wrapper** (lane —) are in
no workflow: a stub needs an absent peer, a wrapper runs other gates
locally.

Oracles: **MIT** 1.22.2 (the equality bar; the SSSD, gssproxy and NFS
peers are Fedora builds on MIT krb5, spoken to over MIT's wire and error
table), **Samba** 4 AD, **Heimdal** 7.8 (secondary), a **Windows** SSPI
peer, or **none** (Rust against Rust: it proves behaviour, not parity).

| Gate | Oracle | Workflow | Lane | Asserts |
| --- | --- | --- | --- | --- |
| `scripts/ad-mit-trust-gate.sh` | Samba | stub | — | `exec`s `samba-realtrust-gate.sh`: that gate's checks and exit code |
| `scripts/ad-s4u-gate.sh` | Samba | `peers:peers` | nightly | Samba's own KDC, no Rust leg (a reference run): MIT `kinit -f -k` as `kbrsvc`, `kvno -U` `kbruser` and `kvno -U` `kbruser` `-P` `host/svc.ad.kerber.test` exit 0; `klist -f -e` names the `host/svc.ad.kerber.test` ticket, `for client` `kbruser`, and an AES `-cts-hmac-sha1-96` etype |
| `scripts/ad-windows-gate.sh` | Samba | `peers:peers` | nightly | Samba `kinit kbruser` + `kvno host/svc`: live Samba ticket (not the torn-down Windows DC) |
| `scripts/bidirectional-gate.sh` | none | `ci:harness` | fail-red | Rust client vs Rust KDC (not an oracle): `krb5-kinit` with `-S host/testhost.kerber.test` exits 0 (TGT + service ticket); FILE ccache magic `0504` |
| `scripts/capaths-compress-gate.sh` | MIT | `ci:mit-extra` | fail-red | MIT 4-hop A.EX.COM→EX.COM→B.EX.COM→C.EX.COM: contents `EX.COM,B.`, expanded `EX.COM,B.EX.COM`, T set; deny `KDC policy rejects request` |
| `scripts/capaths-transit-gate.sh` | MIT | `ci:mit-extra-2` | fail-red | MIT `kvno` A.TEST→B.TEST→C.TEST vs three MIT KDCs then three Rust KDCs: EncTicketPart `transited_tr_type` 1, `transited_contents` `B.TEST` and `T` (`transited_policy_checked=1`) match MIT KDC; deny (C without capaths): `KDC policy rejects request`; `krb5-kvno --disable-transited-check` vs both: default is `KDC policy rejects request` with `BAD_TRANSIT` in the new KDC-log lines, `reject_bad_transit=false` accepts with `transited_policy_checked=0`; inbound krbtgt `DISALLOW_ALL_TIX` fails with `PROCESS_TGS` in the new KDC-log lines on MIT C and Rust C; S4U colliding-name fails with `INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH` in the new KDC-log lines on MIT C and Rust C; bare-A-TGT `klist` keeps `krbtgt/C.TEST@B.TEST` not unasked `krbtgt/B.TEST@A.TEST` |
| `scripts/ccache-gate.sh` | MIT | `ci:harness` | fail-red | MIT FILE/DIR/MEMORY vs Rust marshal: MIT-written FILE identity (`ccache-probe identity`: `identity_ok bytes=`); committed `kinit -a`+u2u golden identity; Rust `klist -c DIR:` of a missing path fails and creates nothing; MIT `krb5_cc_remove_cred` on a Rust FILE and Rust `remove_cred` on a MIT FILE; both `klist` skip tombstones; `klist -C` `config:` kept; DIR `kinit` twice + MIT/`krb5-kswitch` both ways; MEMORY consumes a MIT FILE; `KEYRING:` is `Unknown credential cache type` |
| `scripts/chaos-gate.sh` | MIT | `ci:chaos` | soft | `netem` + memory cap + primary kill under load: MIT completes; no OOM-panic; replica `kinit`/`kvno` after kill |
| `scripts/client-gate.sh` | MIT | `ci:harness` | fail-red | Rust `krb5-kinit` vs MIT `krb5kdc`: MIT `klist` of the Rust ccache names `user@KERBER.TEST` + `host/testhost.kerber.test`; Rust `klist -f -e` matches MIT flags/etype; `krb5-kvno` service ticket; `kdestroy` then MIT `klist` has no cache; symlink kdestroy refused (target intact); default ccache `/tmp/krb5cc_<uid>`; Rust `kvno` rewrite keeps MIT `klist -C` `config:`; `kinit -kt`; MIT and Rust `klist -s` agree |
| `scripts/client-differential-gate.sh` | MIT | wrapper | — | local wrapper: `client-differential-flows-gate.sh` then `client-differential-cli-gate.sh` |
| `scripts/client-differential-cli-gate.sh` | MIT | `ci:mit-extra-2` | fail-red | MIT and Rust CLIs against the MIT KDC, on the flows gate's container: MIT `klist -C -f -e -a` over both FILE caches; seven CLI error paths non-zero both sides; +3d `LD_PRELOAD` skew: both `kdc_timesync = 0` are Clock skew, default timesync recovers (rc=0, `klist`) on both; `gss-mit-client` → Rust acceptor replay 34 (`accept_sec_context: KRB-ERROR 34: authenticator replay`); two-kvno keytab `kinit -k` gets a TGT on both CLIs; `KEY_EXP` changepw (`+needchange`) both CLIs get a TGT after the password change; `t_vfy_increds` / `krb5-vfy-increds` host, outdated (BADKEYVER keytab text on both), no-keytab, NFS, `verify_ap_req_nofail`; `kpasswd` `Password change rejected`; `krb5_set_password` `Access denied`; `kinit -C` `canonicalize`; `kinit -s` `postdated`; default etypes MIT 18/17/20/19/16/23/25/26 vs Rust AES-only; FAST AS outer `till` is `zero` on both; PKINIT / anon second AS `[133, 16, 150, 149]`; SPAKE first-shot `[150, 149]` / error 25; password preauth cascade `[150, 149]` then `[133, 151, 150, 149]` twice; `kvno -U` TGS padata `[1, 136, 130, 129]`; `kvno -U -P` S4U2Proxy TGS `[1, 136, 167]`; `kinit -v` TGS `kdc_options` hold `validate`, MIT = Rust |
| `scripts/client-differential-flows-gate.sh` | MIT | `ci:mit-extra-2` | fail-red | MIT + Rust `kinit`/`kvno` vs the MIT KDC through `kdc-req-proxy.py`: 11 seeded flows (plain/preauth/FAST/SPAKE/PKINIT/`-R`/`-k`/kvno/`-U`/`--u2u`/`-n`), both clients rc 0; CORE request fields match; every flow `SHAPE_MATCH kdc_options=` (MIT = Rust on at least one request of the flow) |
| `scripts/config-include-gate.sh` | MIT | `ci:harness` | fail-red | MIT vs Rust `kinit`/`kvno` on `include`/`includedir` + `KRB5_CONFIG`: dotted `10.conf` drop-in; A:B first-wins `default_realm`; missing include fails both sides |
| `scripts/cross-kdc-gate.sh` | MIT | `ci:harness-2` | fail-red | one identical dump; MIT `krb5kdc` :88 and Rust KDC :8888: a TGT issued by either KDC is accepted by the other's TGS (`kvno` both ways); the TGT enc-part etype (`klist -e`) is the same on both KDCs |
| `scripts/cross-realm-gate.sh` | MIT | `ci:mit-extra` | fail-red | MIT `kinit` + `kvno host/svc.other.test@OTHER.TEST`: `klist` has `krbtgt/OTHER.TEST` and the host ticket |
| `scripts/differential-gate.sh` | MIT | `ci:harness-2` | fail-red | same AS/TGS bytes to Rust and MIT on one dump (diffsend encodes each case once): stable-rep / error-code compare; diffsend rc 0 and all 111 cases `"outcome":"ok"` (`DIFFSEND_RATCHET=111`; any mismatch is red); a `"whitelist"` key is red |
| `scripts/expire-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kinit` vs Rust KDC after `modprinc -expire`/`-pwexpire`/`+needchange`: NAME_EXP vs KEY_EXPIRED; TGS `kvno` after client expiry; `kinit -S kadmin/changepw`; `+needchange` KEY_EXPIRED |
| `scripts/flags-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `modprinc` +flag then `kinit`/`kvno`/`klist -f`: ALL_TIX revoked; no `F` when DISALLOW_FORWARDABLE; `O` when OK_AS_DELEGATE; DISALLOW_SVR `kvno` error matches `user2user`, `MUST_USE_USER2USER`, `KDC policy` or `cannot accommodate`; TGT_BASED POLICY; REQUIRES_HW_AUTH `kinit` trace has `Received error from KDC:.*Additional pre-authentication required` |
| `scripts/getprivs-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kadmin getprivs` vs Rust kadmind ACL: the admin (`*`) and an actor whose ACL is `i` alone both print `INQUIRE` (or `GET`), `ADD` and `MODIFY`; the `i` actor's `cpw -randkey` is refused as AUTH_CHANGEPW (`change-password`), not AUTH_GET |
| `scripts/gss-gate.sh` | MIT | `ci:harness` | fail-red | MIT `libgssapi_krb5` initiator vs `krb5-gss-accept`: unwrap of `hello-from-mit-gss`; `GSS_C_DELEG_FLAG` both directions names `user@KERBER.TEST`; MIT SPNEGO handshake (`gss-accept spnego mic ok`, `gss-accept spnego peer mic ok`); MIT `gss_wrap_iov` unwraps on the Rust acceptor (with `SIGN_ONLY` through Rust `unwrap_iov`); Rust `wrap_iov` / MIT `gss_unwrap_iov`; MIT DCE `wrap_iov` → Rust and → MIT unwrap; inquire lifetime > 0; replayed AP-REQ is 34 on both (MIT KRB-ERROR 34 `Request is a replay`; Rust `accept_sec_context: KRB-ERROR 34: authenticator replay`); direction/filler/EC mutations rejected on both acceptors |
| `scripts/gss-sspi-gate.sh` | Windows | stub | — | no SSPI acceptor or Windows GSS server in the tree: unconditional exit 2 plus `gss-sspi-gate-unavailable.log` (not a green claim) |
| `scripts/gssproxy-gate.sh` | MIT | `ci:harness-2` | skip2 | `X-GSSPROXY` FILE entry: **exit 2** until a Fedora/gssproxy oracle is vendored |
| `scripts/heimdal-gate.sh` | Heimdal | `peers:peers` | nightly | Heimdal `kinit`/`kgetcred` vs Rust; Rust `krb5-kinit` vs Heimdal: `klist` names `user@KERBER.TEST` and `host/testhost.kerber.test` in both directions (the only content asserts; `aes256-cts-hmac-sha1-96` is the configured `default_etypes`, not asserted); missing image `exit 2` |
| `scripts/history-mit-gate.sh` | MIT | `ci:harness` | fail-red | MIT `kadmin.local` history-window on a MIT KDB: history=1 allows A→B→A; history=2 rejects B after A→B→C |
| `scripts/iprop-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kpropd -A` GET_UPDATES + `krb5-iprop-pull` vs MIT kadmind: MIT `kinit extra` after master restart + serial-delta (no extra FULL_RESYNC); MIT `kinit extra2` on Rust replica whose dump holds the `setstr` value; extra2 PAC RID ≠ 1000 |
| `scripts/kadmin-gate.sh` | MIT | wrapper | — | local wrapper: `kadmin-rust-gate.sh`, `kadmin-rust-acl-gate.sh`, `kadmin-mit-gate.sh`, `kadmin-both-gate.sh` |
| `scripts/kadmin-both-gate.sh` | MIT | `ci:harness` | fail-red | both kadminds side by side: `listprincs`/`listpols` glob lists and `getprinc` records (keys, lifetimes) equal between the Rust kadmind and MIT kadmind |
| `scripts/kadmin-local-gate.sh` | MIT | `ci:mit-extra` | fail-red | Rust `krb5-kadmin-local` then MIT `kadmin`: `addprinc extra2` and `addprinc host/slashhost`; MIT `getprinc` both names, `listprincs extra2*`; a `KRB5_ACL_FILE` naming a missing file is ignored (`listprincs` rc 0, lists `user@KERBER.TEST`); `-randkey` + MIT `getprinc` `vno 1` + `kinit -k`; `+requires_preauth`; two `ktadd -k` both names; dump `getprinc` after mutating `setstr` keeps a concurrent kadmind create (`m5k: m5v`); local `addprinc n7local` then remote `cpw -pw extra-n7 extra2` keeps both; MIT `kadmin.local` `ktadd -k` of `krbtgt/KERBER.TEST` rotates (`Key: vno` 2) and writes the keytab, Rust local `ktadd -k` of `krbtgt/KERBER.TEST` writes it (`klist -k`); `passwd_check` modules vs MIT `kadmin.local` (`dl` identical): `addprinc -pw ""` is `Empty passwords are not allowed`, a principal-name password under a policy is `Password may not match principal name`, a realm or `dict_file` word under a policy is `Password is in the password dictionary`, no policy accepts the name and the dict word, the rejected `pqname` create leaves nothing |
| `scripts/kadmin-mit-gate.sh` | MIT | `ci:harness` | fail-red | MIT kadmind 749 in its own `kerber-rust-kadmin-mit` container (the oracle leg; needs the Rust leg's container and its `load_rust_snap` snapshots): the MIT side of the RPC cells (`AUTH_TOOWEAK`, RPCSEC_GSS reject, integrity tamper, changepw `listprincs` `list_code=43787564`), the lockdown cells (`extract-keys`, `delete'' privilege`, `modify'' privilege`), the alias/glob, ACL and policy cells; `kadmin/history` shape, `getprivs`, `getpol` and expiry equal to the Rust snapshots; `modprinc -unlock` against both kadminds (TL `1792`) |
| `scripts/kadmin-rust-gate.sh` | MIT | `ci:harness` | fail-red | MIT `kadmin` vs `krb5-kadmind` 749 (the Rust leg): add/cpw/mod then `kinit extra`; get/list; chrand (dates move)/ktadd/`ktadd -norandkey` then `kinit -k`; `+lockdown_keys`/purgekeys/`cpw -keepold`/setstr/`renprinc`; del then `getprinc` fails |
| `scripts/kadmin-rust-acl-gate.sh` | MIT | `ci:harness` | fail-red | MIT `kadmin` vs `krb5-kadmind` 749: the `alias_cells` / `glob_cells`, ACL-restart and policy cells (attached to the Rust leg's container) |
| `scripts/kcm-gate.sh` | MIT | `ci:mit-extra-2` | fail-red | Rust `KCM:` vs Fedora `sssd-kcm` + Fedora's MIT `klist`: Rust `kinit -c KCM:` then MIT `klist` names `user@KERBER.TEST`; MIT `kinit -c KCM:` then Rust `klist` names the principal; `kswitch` two-principal (GEN_NEW residual); restart persist; re-prime; `kdestroy`; `KEYRING:` still unknown |
| `scripts/kcm-opcode-gate.sh` | MIT | `kcm-opcode:kcm-opcode` | nightly | F43 and F42 `sssd-kcm` (KCM socket up, `GET_DEFAULT_CACHE` code 0): `GET_CRED_LIST=ok`; `RETRIEVE`/`REPLACE`=`KRB5_FCC_INTERNAL` |
| `scripts/kdb-dump-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kdb5_util` dump/load both ways: MIT `kinit` vs Rust; MIT load of policy-bearing dump + `getpol lockme` |
| `scripts/kdc-gate.sh` | MIT | `ci:harness` | fail-red | MIT `kinit`/`kvno` vs Rust KDC: MIT TGT + host ticket; TGS audit seed stage 1 / no `tkt_out_id` / same `req_id` as `ENCR_REP`; `examples/configs` as written: `krb5-kdb create`, `krb5-kdc` + `krb5-kadmind` on `kdc.conf` alone, MIT `kadmin` `addprinc`, MIT `kinit` + `kvno` on `krb5.conf` |
| `scripts/kdcpolicy-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kdcpolicy_test.so` vs Rust `TestPolicy` (`KRB5_KDCPOLICY=test`): AS/TGS deny on a `fail` first component is `KDC policy rejects request` on both legs (Rust AS also `LOCAL_POLICY` in `/tmp/kdc.log`); SPAKE `spake_preauth_indicator = ONE_HOUR` rewrites AS life to 3600 s and TGS life to 1800 s on both; a foreign indicator (`OTHER`) is `KDC policy rejects request` on both |
| `scripts/kit-conformance-gate.sh` | MIT | `ci:harness-2` | skip2 | no check yet: **exit 2** whether `KIT_TWIN` is absent or present (the 2×2 is not vendored; a present twin prints `kit_twin_digest=`) |
| `scripts/knobs-gate.sh` | MIT | `ci:harness` | fail-red | kit-like `krb5.conf` vs MIT 1.22.2 and Rust `kinit`: `kdc_timeout`/`max_retries` do not change MIT (or Rust) kinit success; `forwardable` + `default_tkt_enctypes` show `F` and `aes256-cts-hmac-sha1-96` on `klist -f -e`; `default_ccache_name` env>conf>builtin path parity; conf `proxiable`: MIT and Rust `kvno` host tickets show `P` |
| `scripts/kpasswd-gate.sh` | MIT | wrapper | — | local wrapper: `kpasswd-rust-gate.sh` then `kpasswd-mit-gate.sh` |
| `scripts/kpasswd-mit-gate.sh` | MIT | `ci:harness-2` | fail-red | the oracle leg of `kpasswd-rust-gate.sh`, against MIT kadmind 464: `-minlength 8` is `SOFTERROR` (`kpasswd` rc 2, `Password change rejected`, `result_code=4`); TGT `kvno kadmin/changepw` / `kadmin/admin` refused (`KDC policy rejects request`), MIT KDC log `TGT BASED NOT ALLOWED` |
| `scripts/kpasswd-rust-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kpasswd` vs Rust kadmind 464, then Rust `krb5-kpasswd` vs Rust kadmind: new password `kinit`; old fails; second `kpasswd` + `kinit`; `-minlength 8` is RFC 3244 `SOFTERROR` (rc 2, `Password change rejected`, `result_code=4`); TGT `kvno kadmin/changepw` is 12 `TGT BASED NOT ALLOWED` (`KDC policy rejects request`) |
| `scripts/kprop-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kprop` dump v7 vs `krb5-kpropd` 754: MIT `kinit user` on replica; `klist` names `user@KERBER.TEST` |
| `scripts/kprop-reverse-gate.sh` | MIT | `ci:harness-2` | fail-red | Rust `krb5-kprop` vs MIT `kpropd`: MIT `krb5kdc` + MIT `kinit user@KERBER.TEST` |
| `scripts/ktutil-gate.sh` | MIT | `ci:mit-extra` | fail-red | MIT `ktadd` / Rust `ktutil` / MIT `kinit -k`: Rust list of MIT keytab; Rust-written keytab `kinit -k` |
| `scripts/mit-fast-kdc-gate.sh` | MIT | `ci:mit-extra` | fail-red | MIT `kinit -T` + `kvno` vs Rust KDC; forged-realm armor vs MIT + Rust; forged-realm FAST TGS: plain `kinit` TRACE `FAST negotiation: available` (RFC 6806 `enc-pa-rep`); `kinit -T` TRACE `Upgrading to FAST due to presence of PA_FX_FAST` or `Using FAST due to armor ccache negotiation result`; ≥2 `fast::KrbFastResponse` in the KDC log; forged `kinit -T` is 35 (NOT_US) / `The ticket isn't for us` both sides; forged FAST TGS is 7 `PROCESS_TGS` + MIT `UNKNOWN SERVER: server='krbtgt/KERBER.TEST@FORGED.EXAMPLE'`; client `Server host/testhost.kerber.test@KERBER.TEST not found in Kerberos database` verbatim; MIT default-client `edwards25519` SPAKE vs a P-256-only KDC is 24 on both |
| `scripts/nfs-krb5p-gate.sh` | MIT | `ci:harness-2` | skip2 | NFS `sec=krb5i`/`krb5p`: **exit 2** / manual until nfs-klldap-host is vendored |
| `scripts/pkinit-gate.sh` | MIT | `ci:harness` | fail-red | MIT `kinit -X X509_user_identity=FILE:` vs Rust KDC: `pkinit.so` present; log `rfc8636 sha256 kdf`; SAN≠cname log `pkinit client san`; anonymous `kinit -n` → `klist` `WELLKNOWN/ANONYMOUS` / `WELLKNOWN:ANONYMOUS`, `restrict_anon` `kvno` is 12; RFC 8070 `pkinit_require_freshness = true`: MIT `kinit -X` succeeds and the Rust KDC log has `freshness token received`, `disable_freshness=yes` is `Preauthentication failed` + `no freshness token, rejecting` |
| `scripts/policy-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kadmin` addpol/modpol/getpol/`cpw`/delpol + `kinit`: too-short + reuse; minclasses 5; history-N (current inside N); maxfailure-2; lockout duration/interval |
| `scripts/postdate-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kinit -s` / `kinit -v` vs Rust KDC: INVALID `i` then `kvno` fails (`not yet valid` or `NYV`); validate then `kvno`; `-allow_postdated` is CANNOT_POSTDATE |
| `scripts/prod-gate.sh` | none | `ci:harness-2` | fail-red | loopback Rust↔Rust on `127.0.0.1` (not an oracle): `krb5-kinit` AS+TGS against the Rust KDC; `kdc.issue` + `correlation_id` log analysis; a reconstructed PDU pcap |
| `scripts/prod-realm-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT client vs Rust primary/replica `PROD.KERBER.TEST`: MIT `kinit`/`kvno`/`kadmin`; kprop failover; NIC pcap when required |
| `scripts/prop-acl-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kprop` vs Rust kpropd `KRB5_KPROP_ACL`, and vs MIT `kpropd` `-a` as the oracle: unset or empty allowlist: `Rejected connection from unauthorized principal`, no replica; host allowlist: `SUCCEEDED`, replica, MIT `kinit user`; `acl-$name` cells: 17 `kpropd.acl` variants (exact, other principal, glob lines, leading/trailing whitespace, no realm, longer name, `#`, enctype match / alias case / mismatch / unknown / number / two / CRLF, name CRLF, no final newline) give the same kprop verdict and refusal count on MIT kpropd and Rust kpropd |
| `scripts/rc4-session-gate.sh` | MIT | `ci:mit-extra` | fail-red | MIT `kinit`/`kvno` vs Rust KDC and Rust `krb5-kinit`/`krb5-kvno` vs MIT, `session_enctypes rc4-hmac` on krbtgt + host: both legs: TGT and host session key `arcfour-hmac` in `klist -e`; Rust KDC log `"key_usage":9`; `DEPRECATED:arcfour-hmac` display parity on both `klist`; `allow_rc4` under `[kdcdefaults]` alone: both KDCs refuse the rc4-only client alike (`KDC has no support for encryption type`); KDC `permitted_enctypes` aes256: `z14mixed` sealed aes256 (control aes128) and `z14only` `FINDING_SERVER_KEY`, alike; stale keytab after `cpw -randkey -keepold` is `Password incorrect` on both; armor TGT resealed under the non-permitted aes128 key: `kinit -T` is `Generic error (see e-text)` on both, the genuine TGT still armors |
| `scripts/rd-safe-oracle-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT 1.22.2 `krb5_rd_safe` in an in-container C oracle (`scripts/oracle/rd-safe-oracle.c`) over a KRB-SAFE the oracle builds with MIT `krb5_mk_safe`, rewrites and re-signs (no Rust code runs): canonical body verifies (`SAFE_CANON_OK`); non-canonical KRB-SAFE-BODY (seq-number INTEGER with a leading zero octet) verifies (`SAFE_NONCANON_BODY_OK`); seq-number 2^31 verifies (`SAFE_SEQ_2_31_OK`) |
| `scripts/renew-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kinit -R` / `kinit -p` vs Rust KDC: `renew until` preserved; `-allow_renewable` strips `R`; `klist -f` shows `P` |
| `scripts/restart-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kadmin addprinc extra`; kill `krb5-kdc` by comm; relaunch: MIT `kinit extra` after relaunch; MIT load of persist dump v7 |
| `scripts/rust-kinit-enterprise-gate.sh` | MIT | `ci:mit-extra` | fail-red | MIT `kinit -E` vs Rust KDC; Rust `kinit -E` vs MIT (must match MIT client): MIT db2: MIT and Rust `kinit -E` of `user@KERBER.TEST` exit non-zero with `not found`; Rust KDC: klist `Default principal: user@KERBER.TEST` (not `user@KERBER.TEST@KERBER.TEST`) |
| `scripts/rust-kinit-fast-gate.sh` | MIT | `ci:mit-extra` | fail-red | Rust `kinit --fast` vs MIT KDC: MIT `klist` `user@KERBER.TEST`; TRACE `Decrypted AP-REQ`; no-`+requires_preauth` `nopreauth@KERBER.TEST` FAST: TRACE `Decrypted AP-REQ` `aes256-sha2`, `klist -e` `aes256-cts-hmac-sha384-192` |
| `scripts/rust-kinit-pkinit-gate.sh` | MIT | `ci:mit-extra` | fail-red | Rust `kinit --pkinit FILE:` vs MIT KDC: MIT `klist` `user@KERBER.TEST`; `pkinit.so`; PKINIT evidence in TRACE+OUT; rogue KDC is `pkinit kdc eku` (MIT not listening is red); anonymous `kinit -n` + `restrict_anon` (`WELLKNOWN/ANONYMOUS`, `WELLKNOWN:ANONYMOUS`); `require_freshness` leg: MIT KDC logs `freshness token received` for the Rust client |
| `scripts/rust-kinit-spake-gate.sh` | MIT | `ci:mit-extra` | fail-red | Rust `kinit --spake` vs MIT KDC P-256: MIT `klist` `user@KERBER.TEST`; TRACE `SPAKE response received` or `SPAKE derived K`; `klist -C` shows `config: fast_avail(krbtgt/KERBER.TEST@KERBER.TEST) = yes` and `config: pa_type(krbtgt/KERBER.TEST@KERBER.TEST) = 151`; proxy log `error_code=91` + `e_text=PREAUTH_FAILED` |
| `scripts/rust-kpasswd-mit-gate.sh` | MIT | `ci:mit-extra` | fail-red | Rust `krb5-kpasswd` vs MIT `kadmind` 464: new password `kinit`; old fails |
| `scripts/s4u-mit-gate.sh` | MIT | `ci:mit-extra-2` | fail-red | MIT `kvno -U` / `-U -P` vs Rust KDC: `klist` `for client user@KERBER.TEST`; user-TGT → host S4U2Self (Rust `krb5-kvno -U admin`) exits 1 and both KDCs (MIT :88, Rust :8888) log `INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH`; `kvno -U nosuch` not found; `kvno -U locked` revoked; S4U2Proxy without a delegation grant is `KDC can't fulfill requested option` on MIT db2 and the Rust KDC; RBCD: MIT `kvno -U user -P host/rbcd.kerber.test` gets a ticket whose PAC has delegation info (type 11) from MIT's KDC (test KDB) and from the Rust KDC |
| `scripts/samba-ad-gate.sh` | Samba | `peers:peers` | nightly | live Samba DC `kinit` and `kvno` of `krbtgt/${REALM}@${REALM}` exit 0; `klist` has `${USER}@${REALM}` and `krbtgt/${REALM}@${REALM}`; missing image `exit 2` |
| `scripts/samba-crossrealm-gate.sh` | Samba | `peers:peers` | nightly | MIT `kvno` both ways vs Samba (L3): Samba logs must not match `PAC.*` followed by fail / error / invalid |
| `scripts/samba-pac-l2-gate.sh` | Samba | `peers:peers` | nightly | vendored Samba `kcrypto` 6/7/16/19 (L2): recompute; a type-6 MAC byte flip, and a pre-PAC EncTicketPart byte flip (type 16's signed bytes), → `L2_MISMATCH` |
| `scripts/samba-pac-verify-gate.sh` | Samba | `peers:peers` | nightly | Samba decode of a Rust PAC (L1): all nine buffers of `pac_l1.py`'s `NEED` (`L1_OK`); a dummy requester SID fails |
| `scripts/samba-realtrust-gate.sh` | Samba | `peers:peers` | nightly | `samba-tool domain trust create` + reverse PAC: reverse LOGON_INFO SID/RID = live Samba-A `kbruser` `objectSid` |
| `scripts/sha2-gate.sh` | MIT | `ci:mit-extra` | fail-red | MIT `kinit`/`kvno` etype 20 vs Rust KDC: `klist -e` names `aes256-cts-hmac-sha384-192` |
| `scripts/soak-gate.sh` | none | `ci:soak`, `soak:soak` | soft, nightly | self RSS / latency on the prod realm under sustained load (MIT sampling is not the leak proof): fails on the RSS cap or the steady-window slope, an error rate above 0 or a panic; a window-over-window p99 rise over 2.5× is a warning |
| `scripts/spake-gate.sh` | MIT | `ci:mit-extra` | fail-red | MIT `kinit` `pa_type` 151 / group 2 vs Rust KDC: TRACE 151 + group 2; `klist` `user@KERBER.TEST` |
| `scripts/sssd-renew-gate.sh` | MIT | `ci:harness-2` | skip2 | SSSD `krb5_child` renew: **exit 2** (no `SSSD_FEDORA_IMAGE`, image pull failure, or `sssd-kcm oracle not wired`; SSSD-side renewal still ungated) |
| `scripts/store-gate.sh` | MIT | `ci:harness` | fail-red | MIT `kinit`/`kvno` vs MemoryStore KDC: `backend memory`; `user@KERBER.TEST` + host kvno |
| `scripts/stress-gate.sh` | MIT | `ci:slo` | soft | wire AS+TGS + MIT `kinit`/`kvno` under load: fails on an error rate above 0, a panic or fewer than 16 issue-ok; p99 `duration_us` over 50 ms or under 8 issue-ok/s is a warning |

## Notes by gate

The detail behind the rows. A row states only what its script greps or dies on; a note adds the
setup, the legs and the pointers behind it, and says so when it names something the script does
not check (a unit test, or "not asserted").

- `scripts/ad-mit-trust-gate.sh` — alias of `samba-realtrust-gate.sh` (does
  not claim a Windows DC).
- `scripts/ad-s4u-gate.sh` — live Samba, Samba's own KDC; no Rust leg (a
  reference run): `kinit -f -k kbrsvc` then MIT `kvno -U kbruser kbrsvc`
  (S4U2Self) and `kvno -U kbruser -P host/svc.ad.kerber.test` (S4U2Proxy).
  klist must name `host/svc.ad.kerber.test` and
  `for client kbruser@AD.KERBER.TEST`. `host/svc.ad.kerber.test` is an SPN
  that Samba registers on `kbrsvc` (image build), so S4U2Self targets
  `kbrsvc`.
- `scripts/ad-windows-gate.sh` — live Samba `kinit kbruser@AD.KERBER.TEST`
  then `kvno host/svc.ad.kerber.test`; `klist -e` must name both principals
  and show an `aes128-cts-hmac-sha1-96` or `aes256-cts-hmac-sha1-96` etype.
  Missing image is `exit 2`.
- `scripts/capaths-compress-gate.sh` — MIT 4-hop
  A.EX.COM→EX.COM→B.EX.COM→C.EX.COM; EncTicketPart contents `EX.COM,B.`,
  expanded `EX.COM,B.EX.COM`, T set; deny is `KDC policy rejects request`.
- `scripts/capaths-transit-gate.sh` — MIT `kvno` A.TEST→B.TEST→C.TEST vs
  three live MIT 1.22.2 KDCs, then the same chase vs three Rust KDCs;
  EncTicketPart transited (`tr-type` 1, contents `B.TEST`) and
  `TRANSITED_POLICY_CHECKED` match; missing capaths is
  `KDC policy rejects request`. The POLICY skip cells grep **only the
  new lines** of **that cell’s KDC-under-test log** for `BAD_TRANSIT` (MIT
  `FILE:` kdc log for MIT cells; Rust JSON `kdc.issue`/`krb-error` for Rust
  cells) and C-skip `klist` shows `krbtgt/C.TEST@B.TEST`.
  `krb5-kvno --disable-transited-check` vs default MIT and Rust is POLICY;
  with `reject_bad_transit=false` the skip is accepted and T is off. Forged
  `ticket.realm` on a B-sealed `krbtgt/C.TEST` (empty transited) is rejected
  at both MIT C and Rust C (`PROCESS_TGS`).
  `host/svc.c.test@GARBAGE.EXAMPLE` aimed at C (`--body-realm`) is refused
  with `GET_LOCAL_TGT` on both MIT and Rust. Dest RENEW at C with issuer
  `body.realm` is refused with `GET_LOCAL_TGT` both sides. A peer-minted TGT
  for a local user (`--claim-crealm`) is `INVALID LINEAGE` on both sides. A
  seeded C TGT plus `krb5-kvno -U victim@A.TEST user@C.TEST` is refused with
  `INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH` on both MIT C and Rust C (name
  collision across realms; `-U` `body.realm` is the presented TGT realm, no
  S4U referral walk). A seeded C TGT plus inbound `krbtgt`
  `DISALLOW_ALL_TIX` (MIT C `modprinc -allow_tix`) is refused on both MIT C
  and Rust C: `kvno` reports `not found in Kerberos database` or
  `PROCESS_TGS`, and the new KDC-log lines carry `PROCESS_TGS`. Bare A TGT
  plus Rust `krb5-kvno host/svc.c.test@C.TEST` chases MIT A→B→C
  (`body.realm` is the current TGT realm).
- `scripts/ccache-gate.sh` — a MIT 1.22.2 FILE/DIR/MEMORY oracle.
  `ccache-mit-remove.c` calls MIT `krb5_cc_remove_cred` on a Rust-written
  FILE; Rust `remove_cred` on a MIT-written FILE drops the host ticket (the
  `endtime = 0`, `authtime = -1` tombstone itself is the unit test
  `remove_cred_tombstones_ticket_and_config`). Both `klist` implementations
  skip tombstones; MIT `klist -C` still shows `config:` after a host-ticket
  remove. A MIT `kinit` FILE round-trips through `FileCcache::parse` /
  `to_bytes` byte-for-byte. DIR: two MIT `kinit` into `DIR:/tmp/dcc`, MIT
  `kswitch -p` and Rust `krb5-kswitch -c DIR::` agree both ways. MEMORY: a
  MIT FILE is stored and listed in-process. Unbuilt prefixes (`KEYRING:`)
  are `Unknown credential cache type`. `KCM:` talks sssd-kcm
  (`scripts/kcm-gate.sh`). Rust `klist -c DIR:` of a missing path fails and
  creates nothing. Committed `tests/traces/ccache-mit-addr-u2u.bin` (`kinit -a` +
  u2u) identity-checks addresses/authdata/`second_ticket`. FILE write
  (temp+rename) is not gated here: the gssproxy/SSSD oracles exit 2.
- `scripts/chaos-gate.sh` — `tc netem` delay/loss/reorder (MIT must
  complete), low `--memory` under load (no OOM-panic), `docker kill` of the
  primary mid-load then MIT `kinit`/`kvno` on the kprop replica (including a
  kadmin-created host). `KERBER_REQUIRE_NETEM=1` in CI dies unless netem
  applied; after kill, `State.Running=false`.
- `scripts/client-differential-flows-gate.sh` /
  `scripts/client-differential-cli-gate.sh` (local wrapper
  `client-differential-gate.sh`) — both clients against the live MIT KDC
  through `scripts/lib/kdc-req-proxy.py` (UDP+TCP). Eleven seeded flows
  compare AS-REQ/TGS-REQ CORE fields (`msg_type`, `sname`, nonce present,
  etype list non-empty); SHAPE diffs (padata, KDCOptions, etype list,
  addresses, rtime/till) are printed as a ranked list. Every seeded flow
  must `SHAPE_MATCH kdc_options` (MIT = Rust on at least one request of the
  flow; the option names are not checked). MIT `klist -C -f -e -a` reads
  both FILE caches; seven CLI error paths (wrong password, unknown
  principal, expired, revoked, no KDC, bad keytab, bad ccache) are non-zero
  on both CLIs. +3d `skew-preload.c`: MIT and Rust `kdc_timesync = 0` are
  Clock skew too great (proves the preload); default `kdc_timesync` recovers
  on both (rc=0, `klist` `user@KERBER.TEST`) (`get_in_tkt.c:260-270`).
  `gss-mit-client` → Rust acceptor replay is 34.
- `scripts/client-gate.sh` — copies the Rust `krb5-kinit` binary into the
  MIT 1.22.2 container (same network namespace as the KDC), obtains a TGT
  and a `host/testhost.kerber.test` service ticket, and runs MIT `klist` on
  the FILE ccache. Rust `krb5-klist -c -f -e` reads a MIT-`kinit` FILE
  ccache and MIT `klist -f -e` reads the Rust-written one (principal,
  service, flags, etype). `krb5-kvno` obtains `host/testhost.kerber.test`
  via TGS (no `-U`/`-P`); MIT `klist` names that ticket and a MIT `kvno`
  ticket is visible to Rust klist. After `krb5-kdestroy` MIT `klist`
  reports no cache. kdestroy refuses a symlink (target intact) and the
  no-`-c` default is `/tmp/krb5cc_<uid>`. Host Docker UDP/TCP publish to
  port 88 is unreliable; the gate therefore talks to `127.0.0.1:88`
  *inside* the container. It also covers `kinit -kt` clustering and
  `klist -s` against MIT `check_ccache`.
- `scripts/config-include-gate.sh` — MIT vs Rust on the same
  `include`/`includedir` + colon-split `KRB5_CONFIG` tree: dotted `10.conf`
  is read; two-file scalar first-wins; missing include fails (does not
  hang).
- `scripts/cross-realm-gate.sh` — starts two Rust KDCs (KERBER.TEST:88,
  OTHER.TEST:89) sharing `KRB5_TEST_INTERREALM_KEY`, then MIT `kinit` +
  `kvno host/svc.other.test@OTHER.TEST`. It fails unless `klist` contains
  `krbtgt/OTHER.TEST` and the host ticket.
- `scripts/differential-gate.sh` — one dump, two live KDCs (Rust `:8888`,
  MIT 1.22.2 `krb5kdc` `:88`). `crates/krb5-tools/src/bin/diffsend.rs`
  encodes each AS/TGS case **once** and TCP-exchanges the same bytes to
  both. KRB-ERROR compares `error_code`/`realm`/`sname`/`e_text` (mask
  `stime`/`susec`/`ctime`/`cusec`; PREAUTH `e_data` is structural: the
  padata type multisets must be equal, and the ETYPE-INFO2 etype sets must
  be equal). A foreign-realm AS-REQ is MIT `C_PRINCIPAL_UNKNOWN(6)`
  `CLIENT_NOT_FOUND`, not RFC `WRONG_REALM(68)`. A TGS with a non-krbtgt
  presented ticket is MIT `NOT_US(35)` `BAD TGS SERVER NAME`. `as-success`
  and `tgs-success` decrypt, null volatiles, and compare the stable set;
  ticket flags compare the full flag word with no masking; any divergence
  is fail-red. The other reply cases check the tags and named fields.
  There is no case-name whitelist: the gate fails if a diffsend line
  carries a `"whitelist"` key, and `ci-policy` bans the whitelist mechanism
  identifiers. The case ratchet is `DIFFSEND_RATCHET=N` in the gate,
  checked against the distinct `"case":…,"outcome":"ok"` lines diffsend
  emitted (not the literal its summary claims), and the gate greps a line
  for every case; `ci-policy` reconciles the four copies of the case list —
  the `expect_*` names in `diffsend.rs`, `DIFFSEND_CASES`, the ledger
  header, the gate greps — and the ratchet against the driver's summary
  literal. Honest `exit 2` when docker or the MIT image is absent
  (provenance no longer `exit 1` / `KERBER_NO_IMAGE` as a substitute).
  Compare lives behind `krb5-protocol` feature `diff`
  (`crates/krb5-tools/src/bin/diffsend.rs` and the unit fixture); `diff` is
  a default feature, so it is on the default public API. **TGS vehicle:**
  `tgs-success` mints a PAC-less TGT with the exported krbtgt key (etype
  20, empty `tr-type` 1). PAC-bearing cases mint a diffsend-signed PAC TGT
  (for example `tgs-pac-request-false`); no case verifies the re-signed
  PAC checksums of an issued ticket. **Transited flag:** the full
  flag-word compare holds `TRANSITED_POLICY_CHECKED` (bit 12) to MIT's in
  `as-success` and `tgs-success`.
- `scripts/expire-gate.sh` — MIT `kinit` NAME_EXP vs KEY_EXPIRED;
  `kinit -S kadmin/changepw` on a password-expired client; TGS `kvno` after
  client `-pwexpire`/`-expire` still succeeds; `modprinc +needchange` is
  `KEY_EXPIRED` unless the server is `PWCHANGE_SERVICE`.
- `scripts/flags-gate.sh` — MIT `modprinc` DISALLOW_*/OK_AS_DELEGATE/
  REQUIRES_HW_AUTH then `kinit`/`kvno`/`klist -f`.
- `scripts/getprivs-gate.sh` — MIT `kadmin getprivs` prints `INQUIRE` (or
  `GET`), `ADD` and `MODIFY` for the admin and for an actor whose ACL is `i`
  alone. MIT's `kadm5_get_privs` returns `~0` (`server_misc.c:147-158`); the
  gate does not see `~0` (the unit test `get_privs_is_all_ones` holds it).
  That actor's `cpw -randkey` is refused as AUTH_CHANGEPW
  (`change-password` privilege), not AUTH_GET.
- `scripts/gss-gate.sh` — copies `krb5-gss-accept` into the MIT 1.22.2
  container, exports `host/testhost.kerber.test` to a keytab, and runs an
  out-of-process MIT `libgssapi_krb5` initiator (`scripts/oracle/gss-mit-client.c`)
  that wraps `hello-from-mit-gss`. The Rust acceptor must unwrap that
  plaintext. A second MIT initiator with `GSS_C_DELEG_FLAG` must make the
  acceptor print `gss-accept delegated=user@KERBER.TEST`. A Rust initiator
  with a KRB-CRED trailer must make MIT `gss-mit-server` print the same
  name. A MIT SPNEGO initiator (`oid_spnego`, 1.3.6.1.5.5.2) must complete
  `NegTokenResp` + `mechListMIC` and still unwrap `hello-from-mit-gss`. A
  captured initiator AP-REQ resent on a new connection is 34 `REPEAT`
  (`authenticator replay`) on both the Rust acceptor and MIT
  `gss-mit-server` (KRB-ERROR 34, `Request is a replay`). No cell restarts
  an acceptor: MIT `dfl` file persistence across process restart is
  deferred (the ledger's `srv_rcache.c; rc_file2.c` row). MIT `gss_wrap_iov`
  (HEADER|DATA|PADDING|TRAILER, and with `SIGN_ONLY`) must unwrap on the
  Rust acceptor; Rust `wrap_iov` concatenates to a token MIT
  `gss_unwrap_iov` STREAM accepts. The acceptor prints
  `gss-accept import ok` and `inquire flags=` with lifetime > 0.
  `GSS_C_DCE_STYLE` wrap_iov must unwrap to the sent bytes on both legs;
  Rust-initiator direction/filler/EC mutations are rejected on both
  acceptors.
- `scripts/gss-sspi-gate.sh` — always exit 2 + `gss-sspi-gate-unavailable.log`:
  no SSPI acceptor or Windows GSS server is in the tree to drive.
- `scripts/heimdal-gate.sh` — Heimdal 7.8 secondary oracle
  (`harness/heimdal/`, Debian bookworm apt, no `krb5-user`). It exits 0 only
  after both directions pass `assert_klist`: Heimdal `kinit` + `kgetcred`
  against the Rust KDC with `klist` naming `user@KERBER.TEST` and
  `host/testhost.kerber.test`, then Rust `krb5-kinit` against the Heimdal
  KDC with Heimdal `klist` naming the same principals. No etype is asserted;
  the image pins `default_etypes` and the HDB master key to etype 18
  (`aes256-cts-hmac-sha1-96`). A missing Heimdal image is honest `exit 2`
  plus `heimdal-gate-unavailable.log`; missing docker is `exit 2`.
- `scripts/iprop-gate.sh` — MIT `kpropd -A` must not report IPROP program
  unregistered. After first-contact kprop `-i` (ipropx), mutate the master,
  restart the Rust kadmind, and require serial-delta with no extra
  FULL_RESYNC: MIT `kinit extra` on the MIT replica; `krb5-iprop-pull` vs
  MIT kadmind then MIT `kinit extra2` (the replica dump holds the `setstr`
  value); extra2's replica PAC RID is not 1000 (same RID as the master is
  deferred: MIT kdbe has no SID and incremental encode omits vendor `0x4B0x`
  TL); MIT `delprinc extra2` then the name is gone on the Rust replica.
- `scripts/kadmin-local-gate.sh` — Rust `krb5-kadmin-local` `addprinc`
  extra2 and `host/slashhost` on dump/stash; MIT `kadmin` getprinc names
  `extra2@KERBER.TEST` and `host/slashhost@KERBER.TEST` (slash is two
  name-string components). A `KRB5_ACL_FILE` naming a missing file is
  ignored: `listprincs` exits 0 and lists `user@KERBER.TEST`. `-randkey`
  then MIT `getprinc` `vno 1` and `kinit -k`; `+requires_preauth` on MIT
  `getprinc`; two `ktadd -k` leave both principals (`klist -k`);
  dump-based `getprinc` after a mutating local `setstr` must keep a
  concurrent `kadmind` `addprinc` (`m5k: m5v` via `getstrs`); local
  `addprinc n7local` then remote `cpw extra2` must keep both on a fresh
  dump.
- `scripts/kadmin-rust-acl-gate.sh` — attaches to the
  `kerber-rust-kadmin-gate` container that `kadmin-rust-gate.sh` keeps
  (`KERBER_KADMIN_KEEP=1`; local wrapper `scripts/kadmin-gate.sh`) and
  drives MIT `kadmin` against `krb5-kadmind` on 749: the alias and glob
  cells of `scripts/lib/kadmin-glob-cells.sh`; ACL restarts (an ACL without
  `admin@` refuses admin `getprinc` with the `get` privilege error; an
  unknown op letter, a CRLF continuation, a missing default ACL file and
  `-maxlife 3dd` each stop kadmind starting; the default ACL path and
  `-maxlife 12:34` load; `-maxlife 42x` gives a 42-second maximum ticket
  life; `*/admin` does not match `foo\/admin`); `getprinc`/`addprinc` of
  `user@OTHER.REALM`, with an unprivileged `addprinc` refused for `add`;
  unauthorised `modprinc`/`setstr`/`purgekeys`/`getprinc` of `nosuch` is
  `Principal does not exist`; policy cells (`getpol` lives and 1/1/1
  floors, `modpol -minlength 0` and minlife over maxlife refused, admin
  `cpw` reuse is `Cannot reuse password`, self `cpw` inside the minimum
  life refused, an unmasked `pw_max_life` ignored); `+0x1ffffffff` keeps
  `DISALLOW_ALL_TIX`; six `-keepold` changes (password, randkey, setkey)
  keep 5 kvnos; `purgekeys` of a locked-down principal draws no lockdown
  refusal.
- `scripts/kadmin-rust-gate.sh` / `kadmin-mit-gate.sh` / `kadmin-both-gate.sh` —
  MIT `kadmin` against `krb5-kadmind` on 749 in `kadmin-rust-gate.sh` (local
  wrapper `scripts/kadmin-gate.sh`): `addprinc`, `cpw`, `getprinc`
  (`Principal: extra@KERBER.TEST`; last password change is not `[never]`;
  last modified is not Unix epoch), `listprincs` (names `extra` and `user`),
  `modprinc +requires_preauth` then `kinit`, `cpw -randkey` (old password
  must fail; last password change / last modified move) + `ktadd` +
  `kinit -k`, `ktadd -norandkey` + `kinit -k`, `+lockdown_keys` (cpw is
  `change-password` privilege; `ktadd -norandkey` of krbtgt and
  `kadmin/changepw` is `extract-keys`, and of lockee adds no key;
  `delprinc`/`renprinc` of a locked-down principal is `delete`;
  `modprinc -lockdown_keys` is `modify`; `getprinc krbtgt` shows
  `LOCKDOWN_KEYS`), `purgekeys` (prints `purged`; kvno 2 stays),
  `cpw -keepold` (getprinc lists both kvnos), `setstr`/`getstrs`,
  `renprinc -force` `renamefrom`→`renameto` then `getprinc` new / old fails
  / `kinit -k` new, `delprinc` then `getprinc` error. Rename uses
  `-randkey`. Crafted `kadm5_init_with_password(..., KADM5_CHANGEPW_SERVICE)`
  listprincs is `KADM5_AUTH_LIST` (`Operation requires ``list'' privilege`)
  on both kadminds (`scripts/oracle/kadm5-changepw-rpc.c`); stock `kadmin` never
  selects `kadmin/changepw` (`kadmin.c:418-421`, `client_init.c:411`).
  `kadmin-mit-gate.sh` is the MIT-kadmind side of the RPC, lockdown,
  alias/glob, ACL and policy cells; `kadmin-both-gate.sh` diffs the two
  kadminds' `listprincs`/`listpols` glob lists and `getprinc` shapes
  (`z1u`, `Key:` lines, `Maximum ticket life`).
- `scripts/kcm-gate.sh` — the live sssd-kcm oracle (MIT `klist` names
  `user@KERBER.TEST`); MIT `kinit`/`klist` are Fedora `krb5-workstation`
  in the sssd-kcm container. The gate does not vary the socket source; the
  Rust order (`KCM_SOCKET`, else `[libdefaults] kcm_socket`, else the
  default) is the unit test `kcm_socket_env_overrides_conf_then_default`.
  The oracle container runs `sssd_kcm` as in-container root (needs
  `/var/lib/sss/secrets`); host isolation is the throwaway container, not
  `useradd 4242`. Empty-residual `kinit -c KCM:` re-INITIALIZEs the collection
  default, as MIT `kinit` does (not asserted; the module doc of
  `crates/krb5-protocol/src/kcm.rs`). Verdict
  [`kcm-nfs-verdict.md`](labs/kcm-nfs-verdict.md) (FILE stays until NFS
  cells run).
- `scripts/kcm-opcode-gate.sh` — live F43/F42 `sssd_kcm`; asserts
  `GET_CRED_LIST=ok` and `RETRIEVE`/`REPLACE`=`KRB5_FCC_INTERNAL`.
- `scripts/kdb-dump-gate.sh` — MIT 1.22.2 dump/load both directions. Half A:
  `krb5-kdb load` of MIT's `kdb5_util dump` of
  `tests/traces/kdb/mit-dump-v7.txt` (taken after an MIT `alias a1 user`
  and a password history), Rust KDC, MIT `kinit user` / `kinit pauser`.
  Half B: MIT `kdb5_util load` of the **running KDC at-rest file**
  (`kdb5_util load_dump version 7`, not KDB3), MIT `krb5kdc`, MIT `kinit`
  with `renew until` in `klist`. The database oracle is MIT `kdb5_util`
  dump/load: MIT dump → Rust load → Rust KDC → MIT `kinit`, and Rust dump →
  MIT `kdb5_util load` → MIT `krb5kdc` → MIT `kinit`. Promotion is MIT
  `kinit` + `klist`, never a Rust-vs-Rust round-trip. Golden dump:
  `tests/traces/kdb/mit-dump-v7.txt` (MIT 1.22.2 default is version **7**).
- `scripts/kdc-gate.sh` — copies the Rust `krb5-kdc` binary into a MIT
  1.22.2 container (`shell_container`; its audit cell later runs MIT
  `krb5kdc` there), binds 127.0.0.1:88 (fallback 8888), and runs MIT
  `kinit user@KERBER.TEST` plus `kvno host/testhost.kerber.test`. Its last
  cell runs `examples/configs` as written: `krb5-kdb create EXAMPLE.COM`,
  `krb5-kdc` and `krb5-kadmind` on `kdc.conf` alone, then MIT `kadmin`,
  `kinit` and `kvno` through `kadm5.acl` and `krb5.conf`.
- `scripts/knobs-gate.sh` — `kdc_timeout = 1`/`max_retries = 1` leave MIT
  and Rust kinit succeeding; `forwardable` + `default_tkt_enctypes` show `F`
  and `aes256-cts-hmac-sha1-96` on `klist -f -e`; `default_ccache_name`
  env > conf (`%{uid}`) > builtin; conf `proxiable` (MIT and Rust `kvno`
  host tickets both show `P`; the conf's `[domain_realm]` entries all map to
  the default realm, so the mapping itself is not tested).
- `scripts/kpasswd-rust-gate.sh` / `scripts/kpasswd-mit-gate.sh` — MIT
  `kpasswd` against kadmind 464 (`kadmin/changepw`; local wrapper
  `kpasswd-gate.sh`), then `kinit` with the new password; old password must
  fail; second `kpasswd` + `kinit`; then Rust `krb5-kpasswd` against the
  same Rust kadmind. A `-minlength 8` policy rejection is RFC 3244
  `SOFTERROR` (`[0,4]`; MIT `kpasswd` rc 2, `Password change rejected`) on
  both Rust kadmind and MIT `kadmind`. A TGT-based `kvno kadmin/changepw` /
  `kadmin/admin` is refused (`KDC policy rejects request`; KDC
  `TGT BASED NOT ALLOWED`) on both KDCs; `getprinc` shows
  `DISALLOW_TGT_BASED`/`LOCKDOWN_KEYS`; remote `ktadd -norandkey` is
  `extract-keys`. After `+allow_tgs_req`, a TGS-obtained `kadmin/changepw`
  ticket self-change is result 7 `Ticket must be derived from a password` on
  both kadminds (`scripts/oracle/kpasswd-tgs-client.c`), including
  `KPASSWD_TARGNAME_TYPE=0`. MIT vno-1 kadmind log is
  `chpw request from 127.0.0.1 for user@KERBER.TEST: Operation requires initial ticket`;
  the type-0 (`krb5_set_password`) cell pins
  `setpw request from 127.0.0.1 by user@KERBER.TEST for user@KERBER.TEST: Operation requires initial ticket`
  on both legs. An unprivileged other principal
  (`KPASSWD_TARGET=extra@KERBER.TEST`) is result 5 `Unauthorized request` on
  both legs.
- `scripts/kprop-gate.sh` — MIT `kprop` of a version-7 dump to `krb5-kpropd`
  on 754 (`kprop5_01` sendauth, KRB-SAFE size, KRB-PRIV data), then MIT
  `kinit user` against the replica Rust KDC. `klist` names
  `user@KERBER.TEST`.
- `scripts/kprop-reverse-gate.sh` — Rust `krb5-kprop` to MIT `kpropd`
  (`kpropd -S -P 754`), then MIT `krb5kdc` + MIT `kinit user@KERBER.TEST`.
  Additive to the in-process kprop dump/send tests in `krb5-admin`; it does
  not replace them. Missing MIT image is `exit 2` under
  `KERBER_SKIP_MIT_BUILD=1` (as in CI); otherwise `need_image` builds it.
- `scripts/mit-fast-kdc-gate.sh` — MIT `kinit -T` + `kvno` against the Rust
  KDC (TRACE `Upgrading to FAST due to presence of PA_FX_FAST` or `Using FAST
  due to armor ccache negotiation result`; KDC log ≥2 `KrbFastResponse`).
  Forged-realm armor (`krb5-forge-tgt --keep-cipher --claim-realm`) is 35
  `NOT_US` on both MIT and Rust (`The ticket isn't for us`). Forged-realm FAST
  TGS (`kvno` on a forged `kinit -T` ccache) is 7 `PROCESS_TGS` on both; the
  MIT client line is required verbatim. Not asserted by this gate: the
  unit-red negatives MIT clients cannot emit, FAST (`as_fast.rs`) bad
  `req_checksum` is 41, unkeyed is 12, unknown armor type is 24, AS checksum
  ignores a dummy PA-TGS-REQ; plain TGS (`ap_req.rs`) authenticator cname
  mismatch is 36.
- `scripts/pkinit-gate.sh` — **fails** unless MIT `pkinit.so` is present and
  MIT `kinit -X X509_user_identity=FILE:` succeeds against the Rust KDC. The
  KDC log must contain `rfc8636 sha256 kdf`. It also refuses MIT `kinit`
  with `other.pem` (SAN ≠ `user`) and greps the Rust KDC log for
  `pkinit client san`.
- `scripts/policy-gate.sh` — MIT `kadmin`
  addpol/modpol/getpol/listpols/`cpw`/delpol against `krb5-kadmind`;
  too-short and reuse; `-minclasses 5`; history-N (current counts inside N);
  `maxfailure 2` reset then `CLIENT_REVOKED`; lockout duration / failcnt
  interval.
- `scripts/postdate-gate.sh` — MIT `kinit -s` is INVALID (`i`), `kvno` fails
  (`not yet valid` or `NYV`); `kinit -v` after starttime is usable; `-allow_postdated`
  is CANNOT_POSTDATE.
- `scripts/prod-gate.sh` — Rust KDC on `127.0.0.1:18888`, `krb5-kinit`
  AS+TGS, structured-log analysis (`kdc.issue` + `correlation_id`), PDU pcap
  under `$KERBER_SCRATCH/prod-gate/` (pcap is reconstructed from
  `KERBER_CAPTURE_DIR`; the gate still needs `tcpdump` + `sudo -n` for a
  loopback capture it never reads, else it exits 2 `unavailable`). A
  loopback Rust↔Rust gate, not an oracle.
- `scripts/prod-realm-gate.sh` — multi-host: `PROD.KERBER.TEST` on a docker
  network (Rust primary + Rust replica + MIT client). MIT `kinit`/
  `kvno`/`kadmin addprinc+ktadd` against the primary; Rust `krb5-kprop` to
  the replica `:754`; kill primary; MIT `kinit`/`kvno` against the replica.
  Structured-log analysis + a real eth0 pcap from tcpdump on the primary,
  which must hold AS/TGS msg types 10/11/12/13; with no tcpdump on the
  primary the pcap is rebuilt from captured PDUs
  (`pcap_source=reconstructed`, still requiring 10/11/12/13), and a started
  capture that archives nothing fails. CI sets `KERBER_REQUIRE_REAL_PCAP=1`
  so missing eth0 capture fails red.
- `scripts/prop-acl-gate.sh` — MIT `kprop` vs unset or empty
  `KRB5_KPROP_ACL` is refused (no replica dump); host allowlist still loads.
  The `acl-*` cells run 17 `kpropd.acl` variants against MIT `kpropd -a` and
  the Rust kpropd (same file, re-read per connection) and die unless kprop's
  verdict and the `Rejected connection from unauthorized principal` count
  agree (`kpropd.c:1298-1348`).
- `scripts/renew-gate.sh` — four-term renew: `getprinc` krbtgt and a new
  `renewuser` `Maximum renewable life` not `0 days 00:00:00`; `kinit -r 7d`
  `renew until` ≈ start + 7d; then `kinit -R` (endtime moves, `renew until`
  unchanged); `-allow_renewable` strips `R`; `kinit -p` shows `P`.
- `scripts/restart-gate.sh` — MIT `kadmin addprinc extra`, MIT `kinit`, kill
  `krb5-kdc` by `/proc/PID/comm`, relaunch the same binary on the same
  db/stash, MIT `kinit extra` still works. Then MIT `kdb5_util load` of the
  daemon-persisted dump-v7 file.
- `scripts/rust-kinit-enterprise-gate.sh` — MIT `kinit -E` against the Rust
  KDC (klist default principal is the canonical `user@KERBER.TEST`) **and**
  Rust `kinit -E` against MIT, which must match MIT `kinit -E` (both exit
  non-zero with `not found` on MIT db2; no UPN alias). A mixed-case UPN
  suffix (`user@kerber.test`) is not a local alias: both directions refuse
  it.
- `scripts/rust-kinit-fast-gate.sh` — Rust `kinit --fast --armor-ccache`
  against MIT; the AS-REQ carries PA-FX-FAST and MIT `klist` names
  `user@KERBER.TEST`. The gate asserts `Decrypted AP-REQ` (the armor
  AP-REQ), from TRACE only; the no-preauth FAST AP-REQ is `aes256-sha2`.
- `scripts/rust-kinit-pkinit-gate.sh` — Rust `kinit --pkinit FILE:` against
  MIT KDC (`pkinit.so` + KDC cert + `id-pkinit-san`); it **fails** if the
  plugin is missing. MIT `klist` names `user@KERBER.TEST`. A follow-up
  negative restarts MIT with `pkinit_identity` pointing at the *client*
  cert; Rust `kinit` must fail with `pkinit kdc eku`. MIT not listening on
  that identity is **red**.
- `scripts/rust-kinit-spake-gate.sh` — Rust `kinit --spake` against MIT KDC
  (`spake_preauth_groups = P-256`) and MIT `klist` `user@KERBER.TEST`, with
  the same 91 `PREAUTH_FAILED` pin as `spake-gate.sh`. It sets
  `+requires_preauth user` and asserts a SPAKE *completion* line
  (`SPAKE response received` or `SPAKE derived K`) from the MIT KDC TRACE,
  not a PREAUTH_REQUIRED offer.
- `scripts/rust-kpasswd-mit-gate.sh` — Rust `krb5-kpasswd` against MIT
  `kadmind`.
- `scripts/s4u-mit-gate.sh` — MIT `kvno -U user` and `kvno -U user -P`
  against the **Rust** KDC (`kinit -f -k host/testhost.kerber.test`). The
  user-TGT → host S4U2Self mismatch cell (MIT `kinit` user TGT, then Rust
  `krb5-kvno -U admin`) runs against both the MIT KDC (the image's config,
  `krb5kdc -n` relaunched on :88) and the Rust KDC (:8888); both log
  `INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH`. klist must name
  `for client user@KERBER.TEST`. `kvno -U nosuch` is
  `not found in Kerberos database`; `kvno -U locked`
  (`KRB5_TEST_LOCKED_USER`, `DISALLOW_ALL_TIX`) is
  `credentials have been revoked`. S4U2Proxy denies classic constrained
  delegation unless `s4u_allowed_to` lists the target
  (`KDC can't fulfill requested option`, e_text `NOT_ALLOWED_TO_DELEGATE`).
  A non-forwardable evidence ticket (`BADOPTION`) and PA-PAC-OPTIONS (167)
  are Rust tests (`s4u2proxy_rejects_non_forwardable_evidence`,
  `s4u2proxy_rejects_malformed_pac_options`), not gate cells.
- `scripts/samba-ad-gate.sh` — Samba 4 AD DC. The only `exit 0` is after a
  live `kinit`/`kvno`/`klist`. Missing image or KDC is `exit 2` plus
  `samba-ad-gate-unavailable.log`; missing docker is `exit 2`.
- `scripts/samba-crossrealm-gate.sh` — shared-trust-password TDO; MIT `kvno`
  `user@KERBER.TEST` → `host/svc.ad.kerber.test` and
  `kbruser@AD.KERBER.TEST` → `host/testhost.kerber.test`. Samba logs must
  not contain `PAC … failed`. `kvno` is not proof that the TGS copied
  LOGON_INFO; that copy is `tgs_copies_foreign_referral_pac_identity` /
  `tgs_rejects_corrupt_foreign_referral_pac` in
  `crates/krb5-kdc/tests/tgs_crossrealm.rs`.
- `scripts/samba-pac-l2-gate.sh` — vendored Samba `kcrypto` (RFC 3961 AES
  checksums) recomputes PAC 6/7/16/19 of a Rust-issued ticket. Type-16 is
  hashed in the oracle over the raw EncTicketPart with PAC ad-data `0x00`. A
  type-6 MAC byte flip (`off+4`) must print `L2_MISMATCH` (not
  `L2_MISSING`). A second negative flips a pre-PAC EncTicketPart primitive
  byte (type-16 signed bytes) and must print `L2_MISMATCH` including `16`.
  Type-16 pre-image **transliteration**: Python `zero_pac_ad_data` is a port
  of the Rust rewriter, not Samba C. Missing image/`kcrypto` is `exit 2`.
- `scripts/samba-pac-verify-gate.sh` — co-located Rust KDC on `:8888`; Samba
  `PAC_DATA_RAW` + typed LOGON_INFO/REQUESTOR of a Rust-issued PAC (buffers
  1,10,12,16,17,18,19,6,7). Dummy SID fails.
- `scripts/samba-realtrust-gate.sh` — two Samba AD DCs; real
  `samba-tool domain trust create` (fail with images present is `exit 1`);
  both-direction `kvno`; reverse Rust service PAC LOGON_INFO SID/RID equals
  live Samba-A `kbruser` `objectSid`. Missing images `exit 2`.
- `scripts/sha2-gate.sh` — a live MIT 1.22.2 gate. It copies the Rust KDC
  into the MIT image, points `KRB5_CONFIG` at `/etc/krb5-sha2.conf` (etype
  20 only), and requires `kinit`/`kvno`/`klist -e` to name
  `aes256-cts-hmac-sha384-192`. Without Docker, `provenance.sh` exits 2
  (`docker not available`) before the gate's own `exit 1`.
- `scripts/soak-gate.sh` — sustained moderate load (~120 s in CI, 480 s
  scheduled in `.github/workflows/soak.yml`). RSS last ≤ first×1.5 + 33 MiB
  (the 33 MiB is sized, not asserted, as 8 MiB slack + the bounded working
  set: the 10 MiB lookaside of `kdc/replay.c`, ~17 MiB real with its map/FIFO
  overhead, plus the two replay caches over their 5-minute window, ~8 MiB at
  soak load — 25 MiB measured at 300 s) and slope ≤ 0.05 MiB/s over the steady window, which
  starts at the later of the KDC's `kdc.lookaside.full` event (when logged)
  and 300 s into the run (before that the working set is spread over the
  run: a run with fewer than 5 samples in a steady window is judged by the
  cap and by its whole-run slope ≤ 0.05 MiB/s + 33 MiB ÷ elapsed, and warns
  `rss_slope_unsettled`, so the 120 s per-push soak checks boundedness and
  the scheduled 480 s soak checks the steady slope); an error rate above 0,
  a panic or an issue-ok without `correlation_id` fails it; a
  window-over-window `duration_us` p99 rise over 2.5× is a warning.
  `KERBER_REQUIRE_REAL_PCAP=1` fails unless the client tcpdump archive is
  present. Archives logs + pcap + RSS/latency series.
- `scripts/spake-gate.sh` — runs MIT `kinit` against the Rust KDC with
  `preferred_preauth_types = 151` and `spake_preauth_groups = P-256`. It
  fails unless TRACE contains `151` and group 2, and `klist` shows
  `user@KERBER.TEST`. First-round KRB-ERROR **91** `e_text` is
  `PREAUTH_FAILED` (`do_as_req.c:439-442,809`) in the
  `scripts/lib/kdc-error-proxy.py` capture and the Rust KDC log.
- `scripts/sssd-renew-gate.sh` / `kit-conformance-gate.sh` /
  `gssproxy-gate.sh` / `nfs-krb5p-gate.sh` — honest **exit 2** until the
  Fedora/kit/NFS oracles are vendored (CI treats 2 as skip). SSSD-side
  `krb5_child` renewal is still ungated.
- `scripts/store-gate.sh` — `db_library=memory` KDC seeded from
  `--test-realm`; MIT `kinit` + `kvno`.
- `scripts/stress-gate.sh` — concurrent wire AS+TGS via
  `crates/krb5-tools/src/bin/loadgen.rs` plus MIT `kinit`/`kvno` under load.
  Throughput uses `kdc.issue` timestamps or `duration_us`, not Docker wall
  clock. p99/throughput undershoot with `kdc_issue_err==0` and no panics is
  a warning; error-rate and panics stay hard-fail. `kdc_issue_krb_error` is
  counted and kept out of `min-issue-ok`.
