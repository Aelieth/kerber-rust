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
| `scripts/ad-mit-trust-gate.sh` | Samba | stub | — | the retired Windows-DC one-shot: runs `samba-realtrust-gate.sh` and claims no Windows DC |
| `scripts/ad-s4u-gate.sh` | Samba | `peers:peers` | nightly | Samba `kvno -U` / `-U -P`: `klist` names `host/svc.ad.kerber.test` for `kbruser` |
| `scripts/ad-windows-gate.sh` | Samba | `peers:peers` | nightly | Samba `kinit kbruser` + `kvno host/svc`: live Samba ticket (not the torn-down Windows DC) |
| `scripts/bidirectional-gate.sh` | none | `ci:harness` | fail-red | Rust client vs Rust KDC (not an oracle): TGT + service ticket, FILE ccache `0x0504`, keytab `0x0502` |
| `scripts/capaths-compress-gate.sh` | MIT | `ci:mit-extra` | fail-red | MIT 4-hop A.EX.COM→EX.COM→B.EX.COM→C.EX.COM: contents `EX.COM,B.`, expanded `EX.COM,B.EX.COM`, T set; deny `KDC policy rejects request` |
| `scripts/capaths-transit-gate.sh` | MIT | `ci:mit-extra-2` | fail-red | MIT `kvno` A.TEST→B.TEST→C.TEST vs three MIT KDCs then three Rust KDCs; `krb5-kvno --disable-transited-check` vs both: EncTicketPart transited `tr-type=1` contents `B.TEST` and `T` match MIT KDC; deny: `KDC policy rejects request`; skip+default POLICY; skip+`reject_bad_transit=false` accept T=0; inbound krbtgt `DISALLOW_ALL_TIX` is 7 `PROCESS_TGS`; S4U colliding-name is 36 on MIT C and Rust C; bare-A-TGT `klist` keeps `krbtgt/C.TEST@B.TEST` not unasked `krbtgt/B.TEST@A.TEST` |
| `scripts/ccache-gate.sh` | MIT | `ci:harness` | fail-red | MIT FILE/DIR/MEMORY vs Rust marshal: MIT-written FILE `parse → to_bytes` identity; committed `kinit -a`+u2u golden identity; DIR list of a missing path does not create `primary`; MIT `krb5_cc_remove_cred` on a Rust FILE and Rust `remove_cred` on a MIT FILE; both `klist` skip tombstones; `klist -C` `config:` kept; DIR `kinit` twice + MIT/`krb5-kswitch` both ways; MEMORY consumes a MIT FILE; `KEYRING:` is `Unknown credential cache type` |
| `scripts/chaos-gate.sh` | MIT | `ci:chaos` | soft | `tc netem` + memory cap + primary kill under load: MIT completes; no OOM-panic; replica `kinit`/`kvno` after kill |
| `scripts/client-gate.sh` | MIT | `ci:harness` | fail-red | Rust `krb5-kinit` vs MIT `krb5kdc`: MIT `klist` names TGT + `host/testhost.kerber.test`; Rust `klist -f -e` matches MIT flags/etype; `krb5-kvno` service ticket; `kdestroy` then MIT `klist` has no cache; symlink kdestroy refused (target intact); default ccache `/tmp/krb5cc_<uid>`; Rust `kvno` rewrite keeps MIT `klist -C` `config:`; `kinit -kt`; MIT and Rust `klist -s` agree |
| `scripts/client-differential-gate.sh` | MIT | wrapper | — | local wrapper: `client-differential-flows-gate.sh` then `client-differential-cli-gate.sh` |
| `scripts/client-differential-cli-gate.sh` | MIT | `ci:mit-extra-2` | fail-red | MIT and Rust CLIs against the MIT KDC, on the flows gate's container: MIT `klist -C -f -e -a` over both FILE caches; seven CLI error paths non-zero both sides; +3d `LD_PRELOAD` skew: both `kdc_timesync=0` are Clock skew, default timesync recovers (rc=0, `klist`) on both; `gss-mit-client` → Rust acceptor replay 34; two-kvno `kinit -k` uses the highest kvno on both CLIs; `KEY_EXP` changepw (`+needchange`) both CLIs get a TGT after the password change; `t_vfy_increds` / `krb5-vfy-increds` host, outdated, no-keytab, NFS, `verify_ap_req_nofail`; `kpasswd` `Password change rejected`; `krb5_set_password` `Access denied`; `kinit -C` `canonicalize`; `kinit -s` `postdated`; default etypes MIT 18/17/20/19/16/23/25/26 vs Rust AES-only; FAST AS outer `till=zero`; PKINIT / anon second AS `[133, 16, 150, 149]`; SPAKE first-shot `[150, 149]` / error 25; password preauth cascade `[150, 149]` then `[133, 151, 150, 149]` twice; `kvno -U` TGS padata `[1, 136, 130, 129]`; `kvno -U -P` S4U2Proxy TGS `[1, 136, 167]`; `kinit -v` VALIDATE options `forwardable`+`allow_postdate`+`validate`; TGS-REP client vs TGT client (`gc_via_tkt.c`); acceptor `sname_match` / `ignore_acceptor_hostname`; TGS `try_fallback` specified-realm retry; `fwd_tgt` FORWARDED options; the skew/replay/referral/AP-REP grades; realm-over-kdcdefaults booleans; acceptor kvno+etype on kpasswd/`vfy_increds` (GSS iterates etype-only like MIT `decrypt_try_server`); acceptor transited re-check (`ILL_CR_TKT` when T is unset and a hop is off `walk_realm_tree`; live MIT tickets carry T) |
| `scripts/client-differential-flows-gate.sh` | MIT | `ci:mit-extra-2` | fail-red | MIT + Rust `kinit`/`kvno` vs the MIT KDC through `kdc-req-proxy.py`: 11 seeded flows (plain/preauth/FAST/SPAKE/PKINIT/`-R`/`-k`/kvno/`-U`/`--u2u`/`-n`); CORE request fields match; every flow `SHAPE_MATCH kdc_options` (AS `RENEWABLE_OK`; `kinit -R` `forwardable`+`renewable`+`renew`) |
| `scripts/config-include-gate.sh` | MIT | `ci:harness` | fail-red | MIT vs Rust `kinit`/`kvno` on `include`/`includedir` + `KRB5_CONFIG`: dotted `10.conf` drop-in; A:B first-wins `default_realm`; missing include fails both sides |
| `scripts/cross-kdc-gate.sh` | MIT | `ci:harness-2` | fail-red | one identical dump; MIT `krb5kdc` :88 and Rust KDC :8888: a TGT issued by either KDC is accepted by the other's TGS (`kvno` both ways); the TGT enc-part etype (`klist -e`) is the same on both KDCs |
| `scripts/cross-realm-gate.sh` | MIT | `ci:mit-extra` | fail-red | MIT `kinit` + `kvno host/svc.other.test@OTHER.TEST`: `klist` has `krbtgt/OTHER.TEST` and the host ticket |
| `scripts/differential-gate.sh` | MIT | `ci:harness-2` | fail-red | same AS/TGS bytes to Rust and MIT on one dump: stable-rep / error-code compare; all 111 cases must compare ok (any mismatch is red; there is no whitelist, and a `whitelist` key is red) |
| `scripts/expire-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kinit` vs Rust KDC after `modprinc -expire`/`-pwexpire`/`+needchange`: NAME_EXP vs KEY_EXPIRED; TGS `kvno` after client expiry; `kinit -S kadmin/changepw`; `+needchange` KEY_EXPIRED |
| `scripts/flags-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `modprinc` +flag then `kinit`/`kvno`/`klist -f`: ALL_TIX revoked; no `F` when DISALLOW_FORWARDABLE; `O` when OK_AS_DELEGATE; SVR user2user; TGT_BASED POLICY; HW_AUTH no ticket |
| `scripts/getprivs-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kadmin getprivs` vs Rust kadmind ACL: the admin and an actor whose ACL is `i` alone both report every privilege (INQUIRE, ADD, MODIFY), as MIT `kadm5_get_privs` returns `~0`; the `i` actor's `cpw -randkey` is refused as AUTH_CHANGEPW (`change-password`), not AUTH_GET |
| `scripts/gss-gate.sh` | MIT | `ci:harness` | fail-red | MIT `libgssapi_krb5` initiator vs `krb5-gss-accept`: unwrap of `hello-from-mit-gss`; `GSS_C_DELEG_FLAG` both directions names `user@KERBER.TEST`; MIT SPNEGO handshake + `mechListMIC`; MIT `gss_wrap_iov` / Rust `unwrap_iov` (incl. `SIGN_ONLY`); Rust `wrap_iov` / MIT `gss_unwrap_iov`; MIT DCE `wrap_iov` → Rust and → MIT unwrap (the IOV, DCE, SPNEGO and mutual AP-REP cells are the oracle for the `k5sealiov.c`, `spnego_mech.c` and `accept_sec_context.c:1021` ledger rows); inquire lifetime > 0; replayed AP-REQ is 34 on both (MIT KRB-ERROR 34 `Request is a replay`; Rust `accept_sec_context: KRB-ERROR 34: authenticator replay`); MIT `dfl` file persists across restart, Rust in-memory (ledger `srv_rcache.c; rc_file2.c` row, deferred) |
| `scripts/gss-sspi-gate.sh` | Windows | stub | — | needs a Windows SSPI peer: exit 2 plus an unavailability log without it (not a green claim) |
| `scripts/gssproxy-gate.sh` | MIT | `ci:harness-2` | skip2 | `X-GSSPROXY` FILE entry: **exit 2** until a Fedora/gssproxy oracle is vendored |
| `scripts/heimdal-gate.sh` | Heimdal | `peers:peers` | nightly | Heimdal `kinit`/`kgetcred` vs Rust; Rust `krb5-kinit` vs Heimdal: `klist` names `user@KERBER.TEST` and `host/testhost.kerber.test` in both directions (the only content asserts; `aes256-cts-hmac-sha1-96` is the configured `default_etypes`, not asserted); missing image `exit 2` |
| `scripts/history-mit-gate.sh` | MIT | `ci:harness` | fail-red | MIT `kadmin.local` history-window on a MIT KDB: history=1 allows A→B→A; history=2 rejects B after A→B→C |
| `scripts/iprop-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kpropd -A` GET_UPDATES + `krb5-iprop-pull` vs MIT kadmind: MIT `kinit extra` after master restart + serial-delta (no extra FULL_RESYNC); MIT `kinit extra2` on Rust replica with `setstr` TL 0x000b; extra2 PAC RID ≠ 1000 (same-RID-as-master deferred: MIT kdbe has no SID) |
| `scripts/kadmin-gate.sh` | MIT | wrapper | — | local wrapper: `kadmin-rust-gate.sh`, `kadmin-rust-acl-gate.sh`, `kadmin-mit-gate.sh`, `kadmin-both-gate.sh` |
| `scripts/kadmin-both-gate.sh` | MIT | `ci:harness` | fail-red | both kadminds side by side: `listprincs`/`listpols` glob lists and `getprinc` records (keys, lifetimes) equal between the Rust kadmind and MIT kadmind |
| `scripts/kadmin-local-gate.sh` | MIT | `ci:mit-extra` | fail-red | Rust `krb5-kadmin-local` then MIT `kadmin`: `addprinc extra2` and `addprinc host/slashhost`; MIT getprinc/listprincs those names; set-but-unreadable `KRB5_ACL_FILE` is non-zero; `-randkey` + `kinit -k`; `+requires_preauth`; two `ktadd -k` both names; dump `getprinc` after mutating `setstr` keeps a concurrent kadmind create (`m5k: m5v`); local `addprinc n7local` then remote `cpw extra2` keeps both; local `ktadd krbtgt/REALM` is the MIT footgun (rotates + writes); `passwd_check` modules vs MIT `kadmin.local` (`dl` identical): `addprinc -pw ""` is `Empty passwords are not allowed`, principal-name / realm / `dict_file` word under a policy is `KADM5_PASS_Q_DICT`, no policy accepts them, rejected creates leave nothing |
| `scripts/kadmin-mit-gate.sh` | MIT | `ci:harness` | fail-red | the same MIT `kadmin` cells against MIT kadmind 749 (the oracle leg, attached to the Rust leg's container) |
| `scripts/kadmin-rust-gate.sh` | MIT | `ci:harness` | fail-red | MIT `kadmin` vs `krb5-kadmind` 749 (the Rust leg): add/cpw/get/list/mod/chrand (dates move)/ktadd/`ktadd -norandkey`/`+lockdown_keys`/purgekeys/`cpw -keepold`/setstr/`renprinc`/del then `kinit extra` |
| `scripts/kadmin-rust-acl-gate.sh` | MIT | `ci:harness` | fail-red | MIT `kadmin` vs `krb5-kadmind` 749: the ACL-restart and policy cells (attached to the Rust leg's container) |
| `scripts/kcm-gate.sh` | MIT | `ci:mit-extra-2` | fail-red | Rust `KCM:` vs Fedora `sssd-kcm` + MIT 1.22.2 `klist`: Rust `kinit -c KCM:` then MIT `klist` names `user@KERBER.TEST`; MIT `kinit -c KCM:` then Rust `klist` names the principal; `kswitch` two-principal (GEN_NEW residual); restart persist; re-prime; `kdestroy`; `KEYRING:` still unknown |
| `scripts/kcm-opcode-gate.sh` | MIT | `kcm-opcode:kcm-opcode` | nightly | running F43/F42 `sssd_kcm` on digest-pinned base images (the `krb5-libs` / `sssd-kcm` NVRs recorded); `GET_CRED_LIST=ok`; `RETRIEVE`/`REPLACE`=`KRB5_FCC_INTERNAL` |
| `scripts/kdb-dump-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kdb5_util` dump/load both ways: MIT `kinit` vs Rust; MIT load of policy-bearing dump + `getpol lockme` |
| `scripts/kdc-gate.sh` | MIT | `ci:harness` | fail-red | MIT `kinit`/`kvno` vs Rust KDC: MIT TGT + host ticket (FAST TGS `kvno` included); TGS audit seed stage 1 / no `tkt_out_id` / same `req_id` as `ENCR_REP`; `examples/configs` as written: `krb5-kdb create`, `krb5-kdc` + `krb5-kadmind` on `kdc.conf` alone, MIT `kadmin` `addprinc`, MIT `kinit` + `kvno` on `krb5.conf` |
| `scripts/kdcpolicy-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kdcpolicy_test.so` vs Rust `TestPolicy` (`KRB5_KDCPOLICY=test`): AS/TGS deny on a `fail` first component is `KDC policy rejects request` (`LOCAL_POLICY`) on both legs; SPAKE `spake_preauth_indicator = ONE_HOUR` rewrites AS/TGS life on both; a foreign indicator is `LOCAL_POLICY` on both |
| `scripts/kit-conformance-gate.sh` | MIT | `ci:harness-2` | skip2 | kit twin 2×2: `KIT_TWIN` digest logged; **exit 2** if the twin is absent |
| `scripts/knobs-gate.sh` | MIT | `ci:harness` | fail-red | kit-like `krb5.conf` vs MIT 1.22.2 and Rust `kinit`: `kdc_timeout`/`max_retries` do not change MIT (or Rust) kinit success; `forwardable` + `default_tkt_enctypes` show `F` and `aes256-cts-hmac-sha1-96` on `klist -f -e`; `default_ccache_name` env>conf>builtin path parity; `[domain_realm]` + conf `proxiable` host tickets `PT` |
| `scripts/kpasswd-gate.sh` | MIT | wrapper | — | local wrapper: `kpasswd-rust-gate.sh` then `kpasswd-mit-gate.sh` |
| `scripts/kpasswd-mit-gate.sh` | MIT | `ci:harness-2` | fail-red | the same kpasswd cells against MIT kadmind 464 (the oracle leg): `SOFTERROR` and `TGT BASED NOT ALLOWED` as on the Rust kadmind |
| `scripts/kpasswd-rust-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kpasswd` vs Rust kadmind 464, then Rust `krb5-kpasswd` vs Rust kadmind: new password `kinit`; old fails; run twice; `-minlength 8` is RFC 3244 `SOFTERROR` (rc 2, `Password change rejected`); TGT `kvno kadmin/changepw` is 12 `TGT BASED NOT ALLOWED` (`KDC policy rejects request`) |
| `scripts/kprop-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kprop` dump v7 vs `krb5-kpropd` 754: MIT `kinit user` on replica; `klist` names `user@KERBER.TEST` |
| `scripts/kprop-reverse-gate.sh` | MIT | `ci:harness-2` | fail-red | Rust `krb5-kprop` vs MIT `kpropd`: MIT `krb5kdc` + MIT `kinit user@KERBER.TEST` |
| `scripts/ktutil-gate.sh` | MIT | `ci:mit-extra` | fail-red | MIT `ktadd` / Rust `ktutil` / MIT `kinit -k`: Rust list of MIT keytab; Rust-written keytab `kinit -k` |
| `scripts/mit-fast-kdc-gate.sh` | MIT | `ci:mit-extra` | fail-red | MIT `kinit -T` + `kvno` vs Rust KDC; forged-realm armor vs MIT + Rust; forged-realm FAST TGS: TRACE `Upgrading to FAST due to presence of PA_FX_FAST` or `Using FAST due to armor ccache negotiation result` (RFC 6806 `enc-pa-rep` / pa 149); ≥2 `fast::KrbFastResponse` (AS + TGS); forged `kinit -T` is 35 `NOT_US` / `The ticket isn't for us` both sides; forged FAST TGS is 7 `PROCESS_TGS` + MIT `UNKNOWN SERVER: server='krbtgt/KERBER.TEST@FORGED.EXAMPLE'`; client `Server host/testhost.kerber.test@KERBER.TEST not found in Kerberos database` verbatim; MIT default-client `edwards25519` SPAKE vs a P-256-only KDC is 24 on both |
| `scripts/nfs-krb5p-gate.sh` | MIT | `ci:harness-2` | skip2 | NFS `sec=krb5i`/`krb5p`: **exit 2** / manual until nfs-klldap-host is vendored |
| `scripts/pkinit-gate.sh` | MIT | `ci:harness` | fail-red | MIT `kinit -X X509_user_identity=FILE:` vs Rust KDC: `pkinit.so` present; log `rfc8636 sha256 kdf`; SAN≠cname log `pkinit client san`; anonymous `kinit -n` → `klist` `WELLKNOWN/ANONYMOUS` / `WELLKNOWN:ANONYMOUS`, `restrict_anon` `kvno` is 12; RFC 8070 `pkinit_require_freshness = true`: MIT `kinit -X` logs `freshness token received`, `disable_freshness=yes` is `Preauthentication failed` + `no freshness token, rejecting` |
| `scripts/policy-gate.sh` | MIT | `ci:harness` | fail-red | MIT `kadmin` addpol/modpol/getpol/`cpw`/delpol + `kinit`: too-short + reuse; minclasses 5; history-N (current inside N); maxfailure-2; lockout duration/interval |
| `scripts/postdate-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kinit -s` / `kinit -v` vs Rust KDC: INVALID `i` then TKT_NYV; validate then `kvno`; `-allow_postdated` is CANNOT_POSTDATE |
| `scripts/prod-gate.sh` | none | `ci:harness-2` | fail-red | loopback Rust↔Rust on `127.0.0.1` (not an oracle): `krb5-kinit` AS+TGS against the Rust KDC; `kdc.issue` + `correlation_id` log analysis; a reconstructed PDU pcap |
| `scripts/prod-realm-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT client vs Rust primary/replica `PROD.KERBER.TEST`: MIT `kinit`/`kvno`/`kadmin`; kprop failover; NIC pcap when required |
| `scripts/prop-acl-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kprop` vs Rust kpropd `KRB5_KPROP_ACL`, and vs MIT `kpropd -a` as the oracle: unset or empty allowlist: `Rejected connection from unauthorized principal`, no replica; host allowlist: MIT `kinit user`; `acl-*` cells: 17 `kpropd.acl` variants (exact, glob lines, leading/trailing whitespace, no realm, longer name, `#`, enctype match / alias case / mismatch / unknown / number / two / CRLF, no final newline) give the same kprop verdict and refusal count on MIT kpropd and Rust kpropd |
| `scripts/rc4-session-gate.sh` | MIT | `ci:mit-extra` | fail-red | MIT `kinit`/`kvno` vs Rust KDC and Rust `krb5-kinit`/`krb5-kvno` vs MIT, `session_enctypes = rc4-hmac` on krbtgt + host: both legs: TGT and host session key `arcfour-hmac` in `klist -e`; Rust TGS-REP log `key_usage 9`; `DEPRECATED:arcfour-hmac` display parity on both `klist` |
| `scripts/rd-safe-oracle-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT 1.22.2 `krb5_rd_safe` (in-container C oracle) over Rust-built KRB-SAFE: non-canonical KRB-SAFE-BODY verifies (`SAFE_NONCANON_BODY_OK`); canonical body verifies; `seq ≥ 2^31` verifies (`SAFE_SEQ_2_31_OK`) |
| `scripts/renew-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kinit -R` / `kinit -p` vs Rust KDC: `renew until` preserved; `-allow_renewable` strips `R`; `klist -f` shows `P` |
| `scripts/restart-gate.sh` | MIT | `ci:harness-2` | fail-red | MIT `kadmin addprinc extra`; kill `krb5-kdc` by comm; relaunch: MIT `kinit extra` after relaunch; MIT load of persist dump v7 |
| `scripts/rust-kinit-enterprise-gate.sh` | MIT | `ci:mit-extra` | fail-red | MIT `kinit -E` vs Rust KDC; Rust `kinit -E` vs MIT (must match MIT client): MIT db2: `CLIENT_NOT_FOUND` for `-E user@REALM`. Rust KDC: klist default principal `user@KERBER.TEST` |
| `scripts/rust-kinit-fast-gate.sh` | MIT | `ci:mit-extra` | fail-red | Rust `kinit --fast` vs MIT KDC: MIT `klist` `user@KERBER.TEST`; TRACE `Decrypted AP-REQ` (MIT 1.22.2 does not print `FX-FAST`); SHA-2-first `default_tkt_enctypes`; no-`+requires_preauth` `nopreauth@KERBER.TEST` AES-SHA2 FAST |
| `scripts/rust-kinit-pkinit-gate.sh` | MIT | `ci:mit-extra` | fail-red | Rust `kinit --pkinit FILE:` vs MIT KDC: MIT `klist` `user@KERBER.TEST`; `pkinit.so`; PA-PK-AS-REQ; rogue KDC is `pkinit kdc eku` (MIT not listening is red); anonymous `kinit -n` + `restrict_anon` (`WELLKNOWN/ANONYMOUS`, `WELLKNOWN:ANONYMOUS`); `require_freshness` leg: MIT KDC logs `freshness token received` for the Rust client |
| `scripts/rust-kinit-spake-gate.sh` | MIT | `ci:mit-extra` | fail-red | Rust `kinit --spake` vs MIT KDC P-256: MIT `klist` `user@KERBER.TEST`; TRACE `SPAKE response received` or `SPAKE derived K'`; `+requires_preauth` |
| `scripts/rust-kpasswd-mit-gate.sh` | MIT | `ci:mit-extra` | fail-red | Rust `krb5-kpasswd` vs MIT `kadmind` 464: new password `kinit`; old fails |
| `scripts/s4u-mit-gate.sh` | MIT | `ci:mit-extra-2` | fail-red | MIT `kvno -U` / `-U -P` vs Rust KDC; mismatch cell vs MIT + Rust: `klist` `for client user@KERBER.TEST`; user-TGT/host S4U is 36 on both KDCs (MIT KDC + client gated); `kvno -U nosuch` not found; `kvno -U locked` revoked; non-forwardable → `BADOPTION`; RBCD: MIT `kvno -U user -P host/rbcd…` gets a ticket whose PAC has delegation info (type 11) from MIT's KDC (test KDB) and from the Rust KDC |
| `scripts/samba-ad-gate.sh` | Samba | `peers:peers` | nightly | live Samba DC `kinit`/`kvno`: `klist` after live AS/TGS; missing image `exit 2` |
| `scripts/samba-crossrealm-gate.sh` | Samba | `peers:peers` | nightly | MIT `kvno` both ways vs Samba (L3): Samba logs must not contain `PAC … failed` |
| `scripts/samba-pac-l2-gate.sh` | Samba | `peers:peers` | nightly | vendored Samba `kcrypto` 6/7/16/19 (L2): recompute; a type-6 MAC byte flip, and a pre-PAC EncTicketPart byte flip (type 16's signed bytes), → `L2_MISMATCH` |
| `scripts/samba-pac-verify-gate.sh` | Samba | `peers:peers` | nightly | Samba decode of a Rust PAC (L1): buffers `{1,10,12,16,17,18,19,6,7}`; dummy SID fails |
| `scripts/samba-realtrust-gate.sh` | Samba | `peers:peers` | nightly | `samba-tool domain trust create` + reverse PAC: reverse LOGON_INFO SID/RID = live Samba-A `kbruser` `objectSid` |
| `scripts/sha2-gate.sh` | MIT | `ci:mit-extra` | fail-red | MIT `kinit`/`kvno` etype 20 vs Rust KDC: `klist -e` names `aes256-cts-hmac-sha384-192` |
| `scripts/soak-gate.sh` | none | `ci:soak`, `soak:soak` | soft, nightly | self RSS / latency on the prod realm under sustained load (MIT sampling is not the leak proof): fails on the RSS cap or the steady-window slope, an error rate above 0 or a panic; a window-over-window p99 rise over 2.5× is a warning |
| `scripts/spake-gate.sh` | MIT | `ci:mit-extra` | fail-red | MIT `kinit` `pa_type` 151 / group 2 vs Rust KDC: TRACE 151 + group 2; `klist` `user@KERBER.TEST` |
| `scripts/sssd-renew-gate.sh` | MIT | `ci:harness-2` | skip2 | SSSD `krb5_child` renew: **exit 2** (SSSD-side renewal still ungated; F43 KCM image is socket-only) |
| `scripts/store-gate.sh` | MIT | `ci:harness` | fail-red | MIT `kinit`/`kvno` vs MemoryStore KDC: `backend memory`; `user@KERBER.TEST` + host kvno |
| `scripts/stress-gate.sh` | MIT | `ci:slo` | soft | wire AS+TGS + MIT `kinit`/`kvno` under load: fails on an error rate above 0, a panic or fewer than 16 issue-ok; p99 `duration_us` over 50 ms or under 8 issue-ok/s is a warning |

## Notes by gate

The detail behind the rows. A gate with no note is fully described by its row.

- `scripts/ad-mit-trust-gate.sh` — alias of `samba-realtrust-gate.sh` (does
  not claim a Windows DC).
- `scripts/ad-s4u-gate.sh` — live Samba: `kinit -f -k kbrsvc` then MIT
  `kvno -U kbruser kbrsvc` (S4U2Self) and
  `kvno -U kbruser -P host/svc.ad.kerber.test` (S4U2Proxy). klist must name
  `host/svc.ad.kerber.test` `for client kbruser@AD.KERBER.TEST`. Windows
  used a computer account `host/svc`; Samba registers that SPN on `kbrsvc`
  (S4U2Self to `host/svc` is
  `client and server principal names must match`).
- `scripts/ad-windows-gate.sh` — live Samba `kinit kbruser@AD.KERBER.TEST`
  then `kvno host/svc.ad.kerber.test` (aes256-cts-hmac-sha1-96). Samba kvno
  is 2 (Windows lab was 3). Missing image is `exit 2`.
- `scripts/capaths-compress-gate.sh` — MIT 4-hop
  A.EX.COM→EX.COM→B.EX.COM→C.EX.COM; EncTicketPart contents `EX.COM,B.`,
  expanded `EX.COM,B.EX.COM`, T set; deny is `KDC policy rejects request`.
- `scripts/capaths-transit-gate.sh` — MIT `kvno` A.TEST→B.TEST→C.TEST vs
  three live MIT 1.22.2 KDCs, then the same chase vs three Rust KDCs;
  EncTicketPart transited (`tr-type` 1, contents `B.TEST`) and
  `TRANSITED_POLICY_CHECKED` match; missing capaths is
  `KDC policy rejects request` (12). Skip cells grep **only the new lines**
  of **that cell’s KDC-under-test log** for `BAD_TRANSIT` (MIT `FILE:` kdc
  log for MIT cells; Rust JSON `kdc.issue`/`krb-error` for Rust cells) and
  C-skip `klist` shows `krbtgt/C.TEST@B.TEST`.
  `krb5-kvno --disable-transited-check` vs default MIT and Rust is POLICY;
  with `reject_bad_transit=false` the skip is accepted and T is off. Forged
  `ticket.realm` on a B-sealed `krbtgt/C.TEST` (empty transited) is rejected
  at both MIT C and Rust C (`PROCESS_TGS`).
  `host/svc.c.test@GARBAGE.EXAMPLE` aimed at C (`--body-realm`) is 60
  `GET_LOCAL_TGT` on both MIT and Rust. Dest RENEW at C with issuer
  `body.realm` is 60 both sides. A peer-minted TGT for a local user
  (`--claim-crealm`) is `INVALID LINEAGE` on both sides. A seeded C TGT plus
  `krb5-kvno -U victim@A.TEST user@C.TEST` is 36
  `INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH` on both MIT C and Rust C (name
  collision across realms; `-U` `body.realm` is the presented TGT realm, no
  S4U referral walk). `krb5-kvno --renew` requires `--body-realm` (exit 2).
  A seeded C TGT plus inbound `krbtgt` `DISALLOW_ALL_TIX` is 7 `PROCESS_TGS`
  on both MIT C (`modprinc -allow_tix`; client
  `Server <sname> not found in Kerberos database`) and Rust C. Bare A TGT
  plus Rust `krb5-kvno host/svc.c.test@C.TEST` chases MIT A→B→C
  (`body.realm` is the current TGT realm).
- `scripts/ccache-gate.sh` — a MIT 1.22.2 FILE/DIR/MEMORY oracle.
  `ccache-mit-remove.c` calls MIT `krb5_cc_remove_cred` on a Rust-written
  FILE; Rust `remove_cred` tombstones a MIT-written FILE (`endtime = 0`,
  `authtime = -1`). Both `klist` implementations skip tombstones; MIT
  `klist -C` still shows `config:` after a host-ticket remove. A MIT `kinit`
  FILE round-trips through `FileCcache::parse` / `to_bytes` byte-for-byte.
  DIR: two MIT `kinit` into `DIR:/tmp/dcc`, MIT `kswitch -p` and Rust
  `krb5-kswitch -c DIR::` agree both ways. MEMORY: a MIT FILE is stored and
  listed in-process. Unbuilt prefixes (`KEYRING:`) are
  `Unknown credential cache type`. `KCM:` talks sssd-kcm
  (`scripts/kcm-gate.sh`). DIR list of a missing path does not create
  `primary`. Committed `tests/traces/ccache-mit-addr-u2u.bin` (`kinit -a` +
  u2u) identity-checks addresses/authdata/`second_ticket`. FILE write
  remains temp+rename (the gssproxy/SSSD oracles exit 2).
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
  must `SHAPE_MATCH kdc_options` (AS `RENEWABLE_OK`; `kinit -R` is
  `forwardable`+`renewable`+`renew` per `val_renew.c:62-67`). MIT
  `klist -C -f -e -a` reads both FILE caches; seven CLI error paths (wrong
  password, unknown principal, expired, revoked, no KDC, bad keytab, bad
  ccache) are non-zero on both CLIs. +3d `skew-preload.c`: MIT and Rust
  `kdc_timesync = 0` are Clock skew too great (proves the preload); default
  `kdc_timesync` recovers on both (rc=0, `klist` `user@KERBER.TEST`)
  (`get_in_tkt.c:260-270`). `gss-mit-client` → Rust acceptor replay is 34.
- `scripts/client-gate.sh` — copies the Rust `krb5-kinit` binary into the
  MIT 1.22.2 container (same network namespace as the KDC), obtains a TGT
  and a `host/testhost.kerber.test` service ticket, and runs MIT `klist` on
  the FILE ccache. Rust `krb5-klist -c -f -e` reads a MIT-`kinit` FILE
  ccache and MIT `klist -f -e` reads the Rust-written one (principal,
  service, flags, etype). `krb5-kvno` obtains `host/testhost.kerber.test`
  via TGS (no `-U`/`-P`); MIT `klist` names that ticket and a MIT `kvno`
  ticket is visible to Rust klist. `krb5-kdestroy` zeros then unlinks so MIT
  `klist` reports no cache. kdestroy refuses a symlink (target intact) and
  the no-`-c` default is `/tmp/krb5cc_<uid>`. The client uses unconnected
  UDP (`send_to`/`recv_from`) and ignores off-path source addresses. Host
  Docker UDP/TCP publish to port 88 is unreliable; the gate therefore talks
  to `127.0.0.1:88` *inside* the container. It also covers `kinit -kt`
  clustering and `klist -s` against MIT `check_ccache`.
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
  `stime`/`susec`/`ctime`/`cusec`; PREAUTH `e_data` is structural; extra
  FAST/SPAKE PA types are mechanism ads; the ETYPE-INFO2 etype sets must be
  equal — MIT and Rust both list the chosen client key). A foreign-realm
  AS-REQ is MIT `C_PRINCIPAL_UNKNOWN(6)` `CLIENT_NOT_FOUND`, not RFC
  `WRONG_REALM(68)`. A TGS with a non-krbtgt presented ticket is MIT
  `NOT_US(35)` `BAD TGS SERVER NAME`. AS-REP/TGS-REP decrypt, null
  volatiles, and compare the stable set. Ticket flags compare the full flag
  word with no masking; any divergence is fail-red. There is no case-name
  whitelist: the gate fails if a diffsend line carries a `"whitelist"` key,
  and `ci-policy` bans the whitelist mechanism identifiers. The case ratchet
  is `DIFFSEND_RATCHET=N` in the gate, checked against the distinct
  `"case":…,"outcome":"ok"` lines diffsend emitted (not the literal its
  summary claims), and the gate greps a line for every case; `ci-policy`
  reconciles the four copies of the case list — the `expect_*` names in
  `diffsend.rs`, `DIFFSEND_CASES`, the ledger header, the gate greps — and
  the ratchet against the driver's summary literal. Honest `exit 2` when
  docker or the MIT image is absent (provenance no longer `exit 1` /
  `KERBER_NO_IMAGE` as a substitute). Compare lives behind `krb5-protocol`
  feature `diff` (`crates/krb5-tools/src/bin/diffsend.rs` and the unit
  fixture); it is not on the default public API. **TGS vehicle:** success
  TGS cases mint a PAC-less TGT with the exported krbtgt key (etype 20,
  empty `tr-type` 1). A live Rust PAC TGT is `PROCESS_TGS` at MIT; an MIT
  PAC TGT fails Rust type-16 verify. PAC copy/re-sign is not exercised on
  this path. **Transited flag:** a same-realm TGS sets
  `TRANSITED_POLICY_CHECKED` (bit 12) when the transited check ran, matching
  MIT; the full flag-word compare covers it. Default `reject_bad_transit`
  rejects `DISABLE_TRANSITED_CHECK` as POLICY (12);
  `reject_bad_transit=false` accepts with the check off. AS-REP TGTs do not
  set bit 12.
- `scripts/expire-gate.sh` — MIT `kinit` NAME_EXP vs KEY_EXPIRED;
  `kinit -S kadmin/changepw` on a password-expired client; TGS `kvno` after
  client `-pwexpire`/`-expire` still succeeds; `modprinc +needchange` is
  `KEY_EXPIRED` unless the server is `PWCHANGE_SERVICE`.
- `scripts/flags-gate.sh` — MIT `modprinc` DISALLOW_*/OK_AS_DELEGATE/
  REQUIRES_HW_AUTH then `kinit`/`kvno`/`klist -f`.
- `scripts/getprivs-gate.sh` — MIT `kadmin getprivs` reports every privilege
  for the admin and for an actor whose ACL is `i` alone, as MIT's
  `kadm5_get_privs` returns `~0` (`server_misc.c:147-158`); that actor's
  `cpw -randkey` is refused as AUTH_CHANGEPW (`change-password` privilege),
  not AUTH_GET.
- `scripts/gss-gate.sh` — copies `krb5-gss-accept` into the MIT 1.22.2
  container, exports `host/testhost.kerber.test` to a keytab, and runs an
  out-of-process MIT `libgssapi_krb5` initiator (`scripts/gss-mit-client.c`)
  that wraps `hello-from-mit-gss`. The Rust acceptor must unwrap that
  plaintext. A second MIT initiator with `GSS_C_DELEG_FLAG` must make the
  acceptor print `gss-accept delegated=user@KERBER.TEST`. A Rust initiator
  with a KRB-CRED trailer must make MIT `gss-mit-server` print the same
  name. A MIT SPNEGO initiator (`gss_mech_spnego`) must complete
  `NegTokenResp` + `mechListMIC` and still unwrap `hello-from-mit-gss`. A
  captured initiator AP-REQ resent on a new connection is 34 `REPEAT`
  (`authenticator replay`) on both the Rust acceptor and MIT
  `gss-mit-server` (KRB-ERROR 34, `Request is a replay`). MIT `dfl` file
  persistence across process restart is deferred (the ledger's
  `srv_rcache.c; rc_file2.c` row); Rust is in-memory. MIT `gss_wrap_iov`
  (HEADER|DATA|PADDING|TRAILER, and with `SIGN_ONLY`) must unwrap on the
  Rust acceptor; Rust `wrap_iov` concatenates to a token MIT
  `gss_unwrap_iov` STREAM accepts. The acceptor prints
  `gss-accept import ok` and `inquire flags=` with lifetime > 0.
  `GSS_C_DCE_STYLE` wrap_iov (real EC padding) must unwrap to the sent bytes
  on both legs; Rust-initiator direction/filler/EC mutations are rejected on
  both acceptors.
- `scripts/gss-sspi-gate.sh` — exit 2 + unavailability log when that oracle
  is absent.
- `scripts/heimdal-gate.sh` — Heimdal 7.8 secondary oracle
  (`harness/heimdal/`, Debian bookworm apt, no `krb5-user`). The only
  `exit 0` is after both directions content-assert AES-SHA1
  (`aes256-cts-hmac-sha1-96`): Heimdal `kinit` + `kgetcred` against the Rust
  KDC with `klist` naming `user@KERBER.TEST` and
  `host/testhost.kerber.test`, then Rust `krb5-kinit` against the Heimdal
  KDC with Heimdal `klist` naming the same principals. Bookworm Heimdal 7.8
  has no RFC 8009 etypes 19/20; the image pins `default_etypes` and the HDB
  master key to etype 18. Missing docker/image is honest `exit 2` plus
  `heimdal-gate-unavailable.log`. TGS-REP `name-type` is a hint (RFC 4120
  §6.2); Heimdal canonicalize may return NT-SRV-HST for a host principal
  requested as NT-PRINCIPAL.
- `scripts/iprop-gate.sh` — MIT `kpropd -A` must not report IPROP program
  unregistered. After first-contact kprop `-i` (ipropx), mutate the master,
  restart the Rust kadmind, and require serial-delta with no extra
  FULL_RESYNC: MIT `kinit extra` on the MIT replica; `krb5-iprop-pull` vs
  MIT kadmind then MIT `kinit extra2` (replica dump keeps `setstr` TL
  0x000b); extra2's replica PAC RID is not 1000 (same RID as the master is
  deferred: MIT kdbe has no SID and incremental encode omits vendor `0x4B0x`
  TL); MIT `delprinc extra2` then the name is gone on the Rust replica.
- `scripts/kadmin-local-gate.sh` — Rust `krb5-kadmin-local` `addprinc`
  extra2 and `host/slashhost` on dump/stash; MIT `kadmin` getprinc names
  `extra2@KERBER.TEST` and `host/slashhost@KERBER.TEST` (slash is two
  name-string components). Set-but-unreadable `KRB5_ACL_FILE` exits
  non-zero. `-randkey` then MIT `getprinc` `vno 1` and `kinit -k`;
  `+requires_preauth` on MIT `getprinc`; two `ktadd -k` leave both
  principals (`klist -k`); dump-based `getprinc` after a mutating local
  `setstr` must keep a concurrent `kadmind` `addprinc` (`m5k: m5v` via
  `getstrs`); local `addprinc n7local` then remote `cpw extra2` must keep
  both on a fresh dump. Run twice.
- `scripts/kadmin-rust-gate.sh` / `kadmin-rust-acl-gate.sh` /
  `kadmin-mit-gate.sh` / `kadmin-both-gate.sh` — MIT `kadmin` against
  `krb5-kadmind` on 749 (local wrapper `scripts/kadmin-gate.sh`)
  (AUTH_GSSAPI 300001): `addprinc`, `cpw`, `getprinc`
  (`Principal: extra@KERBER.TEST`; last password change is not `[never]`;
  last modified is not Unix epoch), `listprincs` (names `extra` and `user`),
  `modprinc +requires_preauth` then `kinit`, `cpw -randkey` (old password
  must fail; last password change / last modified move) + `ktadd` +
  `kinit -k`, `ktadd -norandkey` + `kinit -k`, `+lockdown_keys` (cpw is
  `change-password` privilege; `ktadd -norandkey` of
  lockee/krbtgt/`kadmin/changepw` is `extract-keys`; `delprinc`/`renprinc`
  of a locked-down principal is `delete`; `modprinc -lockdown_keys` is
  `modify`; `getprinc krbtgt` shows `LOCKDOWN_KEYS`), `purgekeys` (old kvno
  gone), `cpw -keepold` (getprinc lists both kvnos), `setstr`/`getstrs`,
  `renprinc -force` `renamefrom`→`renameto` then `getprinc` new / old fails
  / `kinit -k` new, `delprinc` then `getprinc` error. Rename uses `-randkey`
  (MIT default-salt password keys may not `kinit` after rename). Crafted
  `kadm5_init_with_password(..., KADM5_CHANGEPW_SERVICE)` listprincs is
  `KADM5_AUTH_LIST` (`Operation requires ``list'' privilege`) on both
  kadminds (`scripts/kadm5-changepw-rpc.c`); stock `kadmin` never selects
  `kadmin/changepw` (`kadmin.c:418-421`, `client_init.c:411`). Run twice.
- `scripts/kcm-gate.sh` — the live sssd-kcm oracle (MIT `klist` names
  `user@KERBER.TEST`); socket path is `KCM_SOCKET`, else
  `[libdefaults] kcm_socket`, else `/var/run`→`/run`. The oracle container
  runs `sssd_kcm` as in-container root (needs `/var/lib/sss/secrets`); host
  isolation is the throwaway container, not `useradd 4242`. Empty-residual
  `kinit -c KCM:` re-INITIALIZEs the default (not MIT `krb5_cc_new_unique`).
  Verdict [`kcm-nfs-verdict.md`](labs/kcm-nfs-verdict.md) (FILE stays until NFS
  cells run).
- `scripts/kcm-opcode-gate.sh` — live F43/F42 `sssd_kcm`; asserts
  `GET_CRED_LIST=ok` and `RETRIEVE`/`REPLACE`=`KRB5_FCC_INTERNAL`.
- `scripts/kdb-dump-gate.sh` — MIT 1.22.2 dump/load both directions. Half A:
  `krb5-kdb load` of `tests/traces/kdb/mit-dump-v7.txt`, Rust KDC, MIT
  `kinit user` / `kinit pauser` (`REQUIRES_PRE_AUTH` = 128). Half B: MIT
  `kdb5_util load` of the **running KDC at-rest file**
  (`kdb5_util load_dump version 7`, not KDB3), MIT `krb5kdc`, MIT `kinit`
  with `renew until` in `klist`. Run twice. The database oracle is MIT
  `kdb5_util` dump/load: MIT dump → Rust load → Rust KDC → MIT `kinit`, and
  Rust dump → MIT `kdb5_util load` → MIT `krb5kdc` → MIT `kinit`. Promotion
  is MIT `kinit` + `klist`, never a Rust-vs-Rust round-trip. Golden dump:
  `tests/traces/kdb/mit-dump-v7.txt` (MIT 1.22.2 default is version **7**;
  `-r18` is version 6).
- `scripts/kdc-gate.sh` — copies the Rust `krb5-kdc` binary into a
  client-only MIT 1.22.2 container, binds 127.0.0.1:88 (fallback 8888), and
  runs MIT `kinit user@KERBER.TEST` plus `kvno host/testhost.kerber.test`.
  In-crate tests drive `issue_as` / `issue_tgs` / `Acl::check` /
  `verify_ap_req` without a socket. Its last cell runs `examples/configs` as
  written: `krb5-kdb create EXAMPLE.COM`, `krb5-kdc` and `krb5-kadmind` on
  `kdc.conf` alone, then MIT `kadmin`, `kinit` and `kvno` through `kadm5.acl`
  and `krb5.conf`.
- `scripts/knobs-gate.sh` — `kdc_timeout`/`max_retries` ignored; honored
  `forwardable` + `default_tkt_enctypes`; `default_ccache_name` env > conf
  (`%{uid}`) > builtin; `[domain_realm]` + conf `proxiable` (MIT and Rust
  `kvno` host tickets both `PT`).
- `scripts/kpasswd-rust-gate.sh` / `scripts/kpasswd-mit-gate.sh` — MIT
  `kpasswd` against kadmind UDP/TCP (local wrapper `kpasswd-gate.sh`) 464
  (`kadmin/changepw`), then `kinit` with the new password; old password must
  fail; second `kpasswd` + `kinit`; then Rust `krb5-kpasswd` against the
  same Rust kadmind. A `-minlength 8` policy rejection is RFC 3244
  `SOFTERROR` (`[0,4]`; MIT `kpasswd` rc 2, `Password change rejected`) on
  both Rust kadmind and MIT `kadmind`. A TGT-based `kvno kadmin/changepw` /
  `kadmin/admin` is refused (`KDC policy rejects request`; KDC
  `TGT BASED NOT ALLOWED`) on both KDCs; `getprinc` shows
  `DISALLOW_TGT_BASED`/`LOCKDOWN_KEYS`; remote `ktadd -norandkey` is
  `extract-keys`. After `+allow_tgs_req`, a TGS-obtained `kadmin/changepw`
  ticket self-change is result 7 `Ticket must be derived from a password` on
  both kadminds (`scripts/kpasswd-tgs-client.c`), including
  `KPASSWD_TARGNAME_TYPE=0`. MIT vno-1 kadmind log is
  `chpw request from 127.0.0.1 for user@KERBER.TEST: Operation requires initial ticket`;
  the type-0 (`krb5_set_password`) cell pins
  `setpw request from 127.0.0.1 by user@KERBER.TEST for user@KERBER.TEST: Operation requires initial ticket`
  on both legs. An unprivileged other principal
  (`KPASSWD_TARGET=extra@KERBER.TEST`) is result 5 `Unauthorized request` on
  both legs. Run twice.
- `scripts/kprop-gate.sh` — MIT `kprop` of a version-7 dump to `krb5-kpropd`
  on 754 (`kprop5_01` sendauth, KRB-SAFE size, KRB-PRIV 32768-byte chunks),
  then MIT `kinit user` against the replica Rust KDC. `klist` names
  `user@KERBER.TEST`. Run twice.
- `scripts/kprop-reverse-gate.sh` — Rust `krb5-kprop` to MIT `kpropd`
  (`kpropd -S -P 754`), then MIT `krb5kdc` + MIT `kinit user@KERBER.TEST`.
  Additive to the in-process kprop dump/send tests in `krb5-admin`; it does
  not replace them. Missing MIT image is `exit 2`. Run twice.
- `scripts/mit-fast-kdc-gate.sh` — MIT `kinit -T` + `kvno` against the Rust
  KDC (TRACE upgrades on `PA_FX_FAST`; KDC log ≥2 `KrbFastResponse`).
  Forged-realm armor (`krb5-forge-tgt --keep-cipher --claim-realm`) is 35
  `NOT_US` on both MIT and Rust (`The ticket isn't for us`). Forged-realm
  FAST TGS (`kvno` on a forged `kinit -T` ccache) is 7 `PROCESS_TGS` on
  both; the MIT client line is required verbatim. Unit-red FAST negatives
  (`as_fast.rs`): bad `req_checksum` is 41, unkeyed is 12, unknown armor
  type is 24, AS checksum ignores a dummy PA-TGS-REQ, TGS authenticator
  cname mismatch is 36. MIT clients cannot emit these.
- `scripts/pkinit-gate.sh` — **fails** unless MIT `pkinit.so` is present and
  MIT `kinit -X X509_user_identity=FILE:` succeeds against the Rust KDC. The
  KDC log must contain `rfc8636 sha256 kdf` (MIT TRACE
  `PKINIT used KDF 2B06010502030602`). Product capture writes only when
  `KERBER_CAPTURE_DIR` is set and non-empty (unset or empty writes nothing).
  Gates choose the directory; `scripts/lib/gate-common.sh`
  `refuse_golden_capture_dir` refuses a path under `tests/traces/`. Promote
  one file with `scripts/promote-trace.sh`. It also refuses MIT `kinit` with
  `other.pem` (SAN ≠ `user`) and greps the Rust KDC log for
  `pkinit client san`.
- `scripts/policy-gate.sh` — MIT `kadmin`
  addpol/modpol/getpol/listpols/`cpw`/delpol against `krb5-kadmind`;
  too-short and reuse; `-minclasses 5`; history-N (current counts inside N);
  `maxfailure 2` reset then `CLIENT_REVOKED`; lockout duration / failcnt
  interval.
- `scripts/postdate-gate.sh` — MIT `kinit -s` is INVALID (`i`), `kvno` is
  TKT_NYV; `kinit -v` after starttime is usable; `-allow_postdated` is
  CANNOT_POSTDATE.
- `scripts/prod-gate.sh` — Rust KDC on `127.0.0.1:18888`, `krb5-kinit`
  AS+TGS, structured-log analysis (`kdc.issue` + `correlation_id`), PDU pcap
  under `$KERBER_SCRATCH/prod-gate/` (loopback CAP_NET_RAW is unavailable in
  rootless distrobox; pcap is reconstructed from `KERBER_CAPTURE_DIR`). Kept
  as the loopback gate.
- `scripts/prod-realm-gate.sh` — multi-host: `PROD.KERBER.TEST` on a docker
  network (Rust primary + Rust replica + MIT client). MIT `kinit`/
  `kvno`/`kadmin addprinc+ktadd` against the primary; Rust `krb5-kprop` to
  the replica `:754`; kill primary; MIT `kinit`/`kvno` against the replica.
  Structured-log analysis + real NIC pcap when `NET_RAW` works
  (`pcap-source=reconstructed` otherwise; reconstructed still requires
  AS/TGS PDUs 10/11/12/13). CI sets `KERBER_REQUIRE_REAL_PCAP=1` so missing
  eth0 capture fails red.
- `scripts/prop-acl-gate.sh` — MIT `kprop` vs unset or empty
  `KRB5_KPROP_ACL` is refused (no replica dump); host allowlist still loads.
  The `acl-*` cells run 17 `kpropd.acl` variants against MIT `kpropd -a` and
  the Rust kpropd (same file, re-read per connection) and die unless kprop's
  verdict and the `Rejected connection from unauthorized principal` count
  agree (`kpropd.c:1298-1348`).
- `scripts/renew-gate.sh` — four-term renew: `getprinc` krbtgt and user
  `Maximum renewable life` not `0 days`; `kinit -r 7d` `renew until` ≈ start
  + 7d; then `kinit -R` (endtime moves, `renew until` unchanged);
  `-allow_renewable` strips `R`; `kinit -p` shows `P`.
- `scripts/restart-gate.sh` — MIT `kadmin addprinc extra`, MIT `kinit`, kill
  `krb5-kdc` by `/proc/PID/comm`, relaunch the same binary on the same
  db/stash, MIT `kinit extra` still works. Then MIT `kdb5_util load` of the
  daemon-persisted dump-v7 file. Run twice.
- `scripts/rust-kinit-enterprise-gate.sh` — MIT `kinit -E` against the Rust
  KDC (klist default principal is the canonical `user@KERBER.TEST`) **and**
  Rust `kinit -E` against MIT, which must match MIT `kinit -E`
  (`CLIENT_NOT_FOUND` on MIT db2; no UPN alias). A foreign UPN suffix is not
  a local alias.
- `scripts/rust-kinit-fast-gate.sh` — Rust `kinit --fast --armor-ccache`
  against MIT (SHA-2-first FAST); the AS-REQ carries PA-FX-FAST and MIT
  `klist` names `user@KERBER.TEST`. MIT 1.22.2 KDC TRACE does **not** print
  `FX-FAST`; the gate asserts `Decrypted AP-REQ` (the armor AP-REQ), from
  TRACE only.
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
  (`SPAKE response received` or `SPAKE derived K'`) from the MIT KDC TRACE,
  not a PREAUTH_REQUIRED offer.
- `scripts/rust-kpasswd-mit-gate.sh` — Rust `krb5-kpasswd` against MIT
  `kadmind` (AS-REQ sname `kadmin/changepw`; MIT `DISALLOW_TGT_BASED`).
- `scripts/s4u-mit-gate.sh` — MIT `kvno -U user` and `kvno -U user -P`
  against the **Rust** KDC (`kinit -f -k host/testhost.kerber.test`). The
  user-TGT → host S4U2Self mismatch cell runs against both the MIT KDC
  (default entrypoint, :88) and the Rust KDC (:8888); both log
  `INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH`. klist must name
  `for client user@KERBER.TEST`. `kvno -U nosuch` is `Client not found`;
  `kvno -U locked` (`KRB5_TEST_LOCKED_USER`, `DISALLOW_ALL_TIX`) is
  `credentials have been revoked`. S4U2Proxy rejects a non-forwardable
  evidence ticket (`BADOPTION`), denies classic constrained delegation
  unless `s4u_allowed_to` lists the target, and parses PA-PAC-OPTIONS (167).
- `scripts/samba-ad-gate.sh` — Samba 4 AD DC. The only `exit 0` is after a
  live `kinit`/`kvno`/`klist`. Missing docker, image, or KDC is `exit 2`
  plus `samba-ad-gate-unavailable.log`.
- `scripts/samba-crossrealm-gate.sh` — shared-trust-password TDO; MIT `kvno`
  `user@KERBER.TEST` → `host/svc.ad.kerber.test` and
  `kbruser@AD.KERBER.TEST` → `host/testhost.kerber.test`. Samba logs must
  not contain `PAC … failed`. `kvno` is not proof that the TGS copied
  LOGON_INFO; that copy is `tgs_copies_foreign_referral_pac_identity` /
  `tgs_rejects_corrupt_foreign_referral_pac` in
  `crates/krb5-kdc/tests/tgs_crossrealm.rs`. Type-16 is hashed over the
  original EncTicketPart bytes with PAC ad-data a single zero.
- `scripts/samba-pac-l2-gate.sh` — vendored Samba `kcrypto` (RFC 3961 AES
  checksums) recomputes PAC 6/7/16/19 of a Rust-issued ticket. Type-16 is
  hashed in the oracle over the raw EncTicketPart with PAC ad-data `0x00`. A
  type-6 MAC byte flip (`off+4`) must print `L2_MISMATCH` (not
  `L2_MISSING`). A second negative flips a pre-PAC EncTicketPart primitive
  byte (type-16 signed bytes) and must print `L2_MISMATCH` including `16`.
  Type-16 pre-image **transliteration**: Python `zero_pac_ad_data` is a port
  of the Rust rewriter, not Samba C; reverse `samba-realtrust-gate` is the
  live Samba type-16 oracle. Missing image/`kcrypto` is `exit 2`.
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
  `aes256-cts-hmac-sha384-192`. It hard-fails without Docker.
- `scripts/soak-gate.sh` — sustained moderate load (~120 s in CI, 480 s
  scheduled in `.github/workflows/soak.yml`). RSS last ≤ first×1.5 + 33 MiB
  (8 MiB slack + the bounded working set: the 10 MiB lookaside of
  `kdc/replay.c`, ~17 MiB real with its map/FIFO overhead, plus the two
  replay caches over their 5-minute window, ~8 MiB at soak load — 25 MiB
  measured at 300 s) and slope ≤ 0.05 MiB/s over the steady window, which
  starts once the KDC has logged `kdc.lookaside.full` and 300 s have elapsed
  (before that the working set is spread over the run; a run too short for a
  steady window is judged by the cap and warns `rss_slope_unsettled`, so the
  120 s per-push soak checks boundedness and the scheduled 480 s soak checks
  the steady slope); an error rate above 0, a panic or an issue-ok without
  `correlation_id` fails it; a window-over-window `duration_us` p99 rise over
  2.5× is a warning.
  `KERBER_REQUIRE_REAL_PCAP=1` fails unless the client tcpdump archive is
  present. Archives logs + pcap + RSS/latency series.
- `scripts/spake-gate.sh` — runs MIT `kinit` against the Rust KDC with
  `preferred_preauth_types = 151` and `spake_preauth_groups = P-256`. It
  fails unless TRACE contains `pa_type` 151 and group 2, and `klist` shows
  `user@KERBER.TEST`. First-round KRB-ERROR **91** `e_text` is
  `PREAUTH_FAILED` (`do_as_req.c:439-442,809`) both legs
  (`scripts/lib/kdc-error-proxy.py`).
- `scripts/sssd-renew-gate.sh` / `kit-conformance-gate.sh` /
  `gssproxy-gate.sh` / `nfs-krb5p-gate.sh` — honest **exit 2** until the
  Fedora/kit/NFS oracles are vendored (CI treats 2 as skip). SSSD-side
  `krb5_child` renewal is still ungated (the image is socket-only).
- `scripts/store-gate.sh` — `db_library=memory` KDC seeded from
  `--test-realm`; MIT `kinit` + `kvno`.
- `scripts/stress-gate.sh` — concurrent wire AS+TGS via
  `crates/krb5-tools/src/bin/loadgen.rs` plus MIT `kinit`/`kvno` under load.
  Throughput uses `kdc.issue` timestamps or `duration_us`, not Docker wall
  clock. p99/throughput undershoot with `kdc_issue_err==0` and no panics is
  a warning; error-rate and panics stay hard-fail. `kdc_issue_krb_error` is
  counted and kept out of `min-issue-ok`.
