# Interop matrix

External-oracle gates that content-assert against a real implementation
(MIT 1.22.2, Samba 4 AD, Heimdal 7.8) plus the fail-red supply-chain
job. Per-gate assertions: [`testing.md`](testing.md). Timing/replay:
[`security.md`](security.md). Isolation: never edit host
`/etc/krb5.conf` (`TESTLABBY.LOCAL`).

A row is **in CI** when the named job runs it without
`continue-on-error` (per-push `ci`, or scheduled `peers` /
`soak`). Missing docker/image is honest `exit 2` unless the script
documents otherwise. Per-push `continue-on-error` is only `slo` /
`chaos` / `soak`.

## MIT 1.22.2 (primary)

| Gate | Drives | Asserts | CI |
| --- | --- | --- | --- |
| `client-gate.sh` | Rust `krb5-kinit` vs MIT `krb5kdc` | MIT `klist` names TGT + `host/testhost.kerber.test`; Rust `klist -f -e` matches MIT flags/etype; `krb5-kvno` service ticket; `kdestroy` then MIT `klist` has no cache; symlink kdestroy refused (target intact); default ccache `/tmp/krb5cc_<uid>`; Rust `kvno` rewrite keeps MIT `klist -C` `config:`; `kinit -kt`; MIT and Rust `klist -s` agree | harness |
| `ccache-gate.sh` | MIT FILE/DIR/MEMORY vs Rust marshal | MIT-written FILE `parse → to_bytes` identity; committed `kinit -a`+u2u golden identity; DIR list of a missing path does not create `primary`; MIT `krb5_cc_remove_cred` on a Rust FILE and Rust `remove_cred` on a MIT FILE; both `klist` skip tombstones; `klist -C` `config:` kept; DIR `kinit` twice + MIT/`krb5-kswitch` both ways; MEMORY consumes a MIT FILE; `KEYRING:` is `Unknown credential cache type` | harness |
| `kcm-gate.sh` | Rust `KCM:` vs Fedora `sssd-kcm` + MIT 1.22.2 `klist` | Rust `kinit -c KCM:` then MIT `klist` names `user@KERBER.TEST`; MIT `kinit -c KCM:` then Rust `klist` names the principal; `kswitch` two-principal (GEN_NEW residual); restart persist; re-prime; `kdestroy`; `KEYRING:` still unknown | mit-extra |
| `kcm-opcode-gate.sh` | running F43/F42 `sssd_kcm` | NVR pin; `GET_CRED_LIST=ok`; `RETRIEVE`/`REPLACE`=`KRB5_FCC_INTERNAL` | kcm-opcode (scheduled/dispatch) |
| `knobs-gate.sh` | kit-like `krb5.conf` vs MIT 1.22.2 and Rust `kinit` | `kdc_timeout`/`max_retries` do not change MIT (or Rust) kinit success; `forwardable` + `default_tkt_enctypes` show `F` and `aes256-cts-hmac-sha1-96` on `klist -f -e`; `default_ccache_name` env>conf>builtin path parity; `[domain_realm]` + conf `proxiable` host tickets `PT` | harness |
| `config-include-gate.sh` | MIT vs Rust `kinit`/`kvno` on `include`/`includedir` + `KRB5_CONFIG` | dotted `10.conf` drop-in; A:B first-wins `default_realm`; missing include fails both sides | harness |
| `kit-conformance-gate.sh` | kit twin 2×2 | `KIT_TWIN` digest logged; **exit 2** if the twin is absent | harness (skip 2) |
| `gssproxy-gate.sh` | `X-GSSPROXY` FILE entry | **exit 2** until a Fedora/gssproxy oracle is vendored | harness (skip 2) |
| `nfs-krb5p-gate.sh` | NFS `sec=krb5i`/`krb5p` | **exit 2** / manual until nfs-klldap-host is vendored | harness (skip 2) |
| `sssd-renew-gate.sh` | SSSD `krb5_child` renew | **exit 2** (R6 SSSD-side renewal still ungated; F43 KCM image is socket-only) | harness (skip 2) |
| `ktutil-gate.sh` | MIT `ktadd` / Rust `ktutil` / MIT `kinit -k` | Rust list of MIT keytab; Rust-written keytab `kinit -k` | mit-extra |
| `kadmin-local-gate.sh` | Rust `krb5-kadmin-local` then MIT `kadmin` | `addprinc extra2` and `addprinc host/slashhost`; MIT getprinc/listprincs those names; set-but-unreadable `KRB5_ACL_FILE` is non-zero; `-randkey` + `kinit -k`; `+requires_preauth`; two `ktadd -k` both names; dump `getprinc` after mutating `setstr` keeps a concurrent kadmind create (`m5k: m5v`); local `addprinc n7local` then remote `cpw extra2` keeps both; local `ktadd krbtgt/REALM` is the MIT footgun (rotates + writes) | mit-extra |
| `rust-kpasswd-mit-gate.sh` | Rust `krb5-kpasswd` vs MIT `kadmind` 464 | new password `kinit`; old fails | mit-extra |
| `kdc-gate.sh` | MIT `kinit`/`kvno` vs Rust KDC | MIT TGT + host ticket (FAST TGS `kvno` included) | harness |
| `gss-gate.sh` | MIT `libgssapi_krb5` initiator vs `krb5-gss-accept` | unwrap of `hello-from-mit-gss`; `GSS_C_DELEG_FLAG` both directions names `user@KERBER.TEST`; MIT SPNEGO handshake + `mechListMIC`; MIT `gss_wrap_iov` / Rust `unwrap_iov` (incl. `SIGN_ONLY`); Rust `wrap_iov` / MIT `gss_unwrap_iov`; inquire lifetime > 0 | harness |
| `pkinit-gate.sh` | MIT `kinit -X X509_user_identity=FILE:` vs Rust KDC | `pkinit.so` present; log `rfc8636 sha256 kdf`; SAN≠cname log `pkinit client san` | harness |
| `spake-gate.sh` | MIT `kinit` `pa_type` 151 / group 2 vs Rust KDC | TRACE 151 + group 2; `klist` `user@KERBER.TEST` | mit-extra |
| `rust-kinit-spake-gate.sh` | Rust `kinit --spake` vs MIT KDC P-256 | MIT `klist` `user@KERBER.TEST`; TRACE `SPAKE response received` or `SPAKE derived K'`; `+requires_preauth` | mit-extra |
| `rust-kinit-fast-gate.sh` | Rust `kinit --fast` vs MIT KDC | MIT `klist` `user@KERBER.TEST`; TRACE `Decrypted AP-REQ` (MIT 1.22.2 does not print `FX-FAST`); SHA-2-first `default_tkt_enctypes`; no-`+requires_preauth` `nopreauth@KERBER.TEST` AES-SHA2 FAST | mit-extra |
| `mit-fast-kdc-gate.sh` | MIT `kinit -T` + `kvno` vs Rust KDC | TRACE `Upgrading to FAST due to presence of PA_FX_FAST`; ≥2 `fast::KrbFastResponse` (AS + TGS) | mit-extra |
| `rust-kinit-pkinit-gate.sh` | Rust `kinit --pkinit FILE:` vs MIT KDC | MIT `klist` `user@KERBER.TEST`; `pkinit.so`; PA-PK-AS-REQ; rogue KDC is `pkinit kdc eku` (MIT not listening is red) | mit-extra |
| `rust-kinit-enterprise-gate.sh` | MIT `kinit -E` vs Rust KDC; Rust `kinit -E` vs MIT (must match MIT client) | MIT db2: `CLIENT_NOT_FOUND` for `-E user@REALM`. Rust KDC: klist default principal `user@KERBER.TEST` | mit-extra |
| `sha2-gate.sh` | MIT `kinit`/`kvno` etype 20 vs Rust KDC | `klist -e` names `aes256-cts-hmac-sha384-192` | mit-extra |
| `cross-realm-gate.sh` | MIT `kinit` + `kvno host/svc.other.test@OTHER.TEST` | `klist` has `krbtgt/OTHER.TEST` and the host ticket | mit-extra |
| `capaths-transit-gate.sh` | MIT `kvno` A.TEST→B.TEST→C.TEST vs three MIT KDCs then three Rust KDCs | EncTicketPart transited `tr-type=1` contents `B.TEST` and `T` match MIT KDC; deny: MIT `KDC policy rejects transited path` | mit-extra |
| `kadmin-gate.sh` | MIT `kadmin` vs `krb5-kadmind` 749 | add/cpw/get/list/mod/chrand (dates move)/ktadd/`ktadd -norandkey`/`+lockdown_keys`/purgekeys/`cpw -keepold`/setstr/`renprinc`/del then `kinit extra` | harness |
| `policy-gate.sh` | MIT `kadmin` addpol/modpol/getpol/`cpw`/delpol + `kinit` | too-short + reuse; minclasses 5; history-N (current inside N); maxfailure-2; lockout duration/interval | harness |
| `history-mit-gate.sh` | MIT `kadmin.local` history-window on a MIT KDB | history=1 allows A→B→A; history=2 rejects B after A→B→C | harness |
| `store-gate.sh` | MIT `kinit`/`kvno` vs MemoryStore KDC | `backend memory`; `user@KERBER.TEST` + host kvno | harness |
| `iprop-gate.sh` | MIT `kpropd -A` GET_UPDATES + `krb5-iprop-pull` vs MIT kadmind | MIT `kinit extra` after master restart + serial-delta (no extra FULL_RESYNC); MIT `kinit extra2` on Rust replica with `setstr` TL 0x000b; extra2 PAC RID ≠ 1000 (same-RID-as-master deferred: MIT kdbe has no SID) | harness |
| `expire-gate.sh` | MIT `kinit` vs Rust KDC after `modprinc -expire`/`-pwexpire`/`+needchange` | NAME_EXP vs KEY_EXPIRED; TGS `kvno` after client expiry; `kinit -S kadmin/changepw`; `+needchange` KEY_EXPIRED | harness |
| `flags-gate.sh` | MIT `modprinc` +flag then `kinit`/`kvno`/`klist -f` | ALL_TIX revoked; no `F` when DISALLOW_FORWARDABLE; `O` when OK_AS_DELEGATE; SVR user2user; TGT_BASED POLICY; HW_AUTH no ticket | harness |
| `renew-gate.sh` | MIT `kinit -R` / `kinit -p` vs Rust KDC | `renew until` preserved; `-allow_renewable` strips `R`; `klist -f` shows `P` | harness |
| `postdate-gate.sh` | MIT `kinit -s` / `kinit -v` vs Rust KDC | INVALID `i` then TKT_NYV; validate then `kvno`; `-allow_postdated` is CANNOT_POSTDATE | harness |
| `getprivs-gate.sh` | MIT `kadmin getprivs` vs Rust kadmind ACL | admin INQUIRE/ADD/MODIFY; limited `i` is INQUIRE only; `cpw -randkey` is AUTH_CHANGEPW | harness |
| `prop-acl-gate.sh` | MIT `kprop` vs Rust kpropd `KRB5_KPROP_ACL` | unset or empty allowlist: `acl denied`, no replica; host allowlist: MIT `kinit user` | harness |
| `kpasswd-gate.sh` | MIT `kpasswd` vs Rust kadmind 464; Rust `krb5-kpasswd` vs Rust kadmind | new password `kinit`; old fails; run twice; Rust client after MIT | harness |
| `kdb-dump-gate.sh` | MIT `kdb5_util` dump/load both ways | MIT `kinit` vs Rust; MIT load of policy-bearing dump + `getpol lockme` | harness |
| `differential-gate.sh` | same AS/TGS bytes to Rust and MIT on one dump | stable-rep / error-code compare; un-whitelisted mismatch fails red | harness |
| `kprop-gate.sh` | MIT `kprop` dump v7 vs `krb5-kpropd` 754 | MIT `kinit user` on replica; `klist` names `user@KERBER.TEST` | harness |
| `kprop-reverse-gate.sh` | Rust `krb5-kprop` vs MIT `kpropd` | MIT `krb5kdc` + MIT `kinit user@KERBER.TEST` | harness |
| `restart-gate.sh` | MIT `kadmin addprinc extra`; kill `krb5-kdc` by comm; relaunch | MIT `kinit extra` after relaunch; MIT load of persist dump v7 | harness |
| `s4u-mit-gate.sh` | MIT `kvno -U` / `-U -P` vs Rust KDC | `klist` `for client user@KERBER.TEST`; `kvno -U nosuch` not found; `kvno -U locked` revoked; non-forwardable → `BADOPTION` | mit-extra |
| `prod-realm-gate.sh` | MIT client vs Rust primary/replica `PROD.KERBER.TEST` | MIT `kinit`/`kvno`/`kadmin`; kprop failover; NIC pcap when required | harness |
| `stress-gate.sh` | wire AS+TGS + MIT `kinit`/`kvno` under load | p99 `duration_us` ≤ 50 ms; ≥ 8 issue-ok/s; error-rate 0 | slo (continue-on-error) |
| `chaos-gate.sh` | `tc netem` + memory cap + primary kill under load | MIT completes; no OOM-panic; replica `kinit`/`kvno` after kill | chaos (continue-on-error) |

## Samba 4 AD (AD.KERBER.TEST)

| Gate | Drives | Asserts | CI |
| --- | --- | --- | --- |
| `samba-ad-gate.sh` | live Samba DC `kinit`/`kvno` | `klist` after live AS/TGS; missing image `exit 2` | peers (nightly) |
| `ad-windows-gate.sh` | Samba `kinit kbruser` + `kvno host/svc` | live Samba ticket (not the torn-down Windows DC) | peers (nightly) |
| `ad-s4u-gate.sh` | Samba `kvno -U` / `-U -P` | `klist` names `host/svc.ad.kerber.test` for `kbruser` | peers (nightly) |
| `samba-pac-verify-gate.sh` | Samba decode of a Rust PAC (L1) | buffers `{1,10,12,16,17,18,19,6,7}`; dummy SID fails | peers (nightly) |
| `samba-pac-l2-gate.sh` | vendored Samba `kcrypto` 6/7/16/19 (L2) | recompute; type-6/16 MAC flip → `L2_MISMATCH` | peers (nightly) |
| `samba-crossrealm-gate.sh` | MIT `kvno` both ways vs Samba (L3) | Samba logs must not contain `PAC … failed` | peers (nightly) |
| `samba-realtrust-gate.sh` | `samba-tool domain trust create` + reverse PAC | reverse LOGON_INFO SID/RID = live Samba-A `kbruser` `objectSid` | peers (nightly) |

`ad-mit-trust-gate.sh` is an alias of `samba-realtrust-gate.sh`. It does
not claim a Windows DC.

## Heimdal 7.8 (secondary)

| Gate | Drives | Asserts | CI |
| --- | --- | --- | --- |
| `heimdal-gate.sh` | Heimdal `kinit`/`kgetcred` vs Rust; Rust `krb5-kinit` vs Heimdal | AES-SHA1 both ways; `klist` names `user@KERBER.TEST` and `host/testhost.kerber.test`; missing image `exit 2` | peers (nightly) |

## Supply-chain (not an interop oracle)

| Check | Drives | Asserts | CI |
| --- | --- | --- | --- |
| cargo-audit | `rustsec/audit-check` | known advisories fail red | audit |
| cargo-deny | `deny.toml` licenses/advisories/sources | allowlist only; crates.io sources | audit |
| `scripts/geiger.sh` | per-crate `cargo geiger --forbid-only` | product 0-unsafe / `forbid(unsafe)`; dep surface archived, not a count gate | audit |
| `cargo vet --locked` | `supply-chain/` (Google / Mozilla / Bytecode Alliance) | every third-party crate imported, locally audited, or exempt; cargo-vet **0.10.0** | audit |

## Deviation ledger (MIT behaviours kept)

FILE `delete_cred` is a same-length tombstone (`endtime = 0`,
`authtime = -1`, config realm `X-CACHECONF:` → `X-RMED-CONF:`);
deletion is not guaranteed if marshal length would change. FILE
stores still append/rewrite via temp+rename (MIT opens `O_APPEND`
in place); G8b gssproxy/SSSD oracles were unavailable (honest exit 2),
so the in-place vs temp+rename decision stays **open**. Unknown ccache
prefixes are `KRB5_CC_UNKNOWN_TYPE` with no FILE fallback. `KCM:` is a
real type (sssd-kcm); `KEYRING:` stays unknown. Fleet default stays FILE
until NFS `sec=krb5i` cells run — [`kcm-nfs-verdict.md`](kcm-nfs-verdict.md). FILE
principal and realm octets must be ASCII GeneralString; non-ASCII MIT
caches fail parse (no silent corruption). DIR resolve does not create
`primary`.

**Knobs honored by ignoring:** `kdc_timeout` and `max_retries` have no
MIT 1.22.2 parse site (Heimdal spellings; `sendto_kdc.c` `MAX_PASS 3`).
Rust stores the strings and does not change pacing. `udp_preference_limit`
(MIT default 1465), `rdns`, `kdc_timesync`, `permitted_enctypes` /
`default_tkt_enctypes` / `default_tgs_enctypes`, `forwardable`,
`ticket_lifetime`, `renew_lifetime`, `dns_lookup_kdc` /
`dns_lookup_realm` are parsed at MIT's sites.

**Renewable default, admin-overridable:** ticket renew time is the min of
the request (`-r`, else RENEWABLE-OK till), the **krbtgt** entry, the
**client** entry, and kdc.conf realm `max_renewable_life` when that key
is **explicitly set** (unset ≠ 0). New principals copy the realm policy
value (7d) onto `max_renewable_life` so `getprinc` is not 0.

## Not external oracles

These run in CI (or scheduled) but **do not** count as an external
implementation oracle.

| Item | Why not an oracle | CI |
| --- | --- | --- |
| `bidirectional-gate.sh` | Rust client vs Rust KDC | harness |
| `prod-gate.sh` | loopback Rust↔Rust on `127.0.0.1` | harness |
| `soak-gate.sh` | self RSS / latency on the prod realm (MIT sampling is not the leak proof) | harness + `soak.yml` |
| golden MIT DER + crypto KATs | in-repo fixtures, not a live peer | test |
| 8 cargo-fuzz targets | `fuzz.yml` smoke, not an interop peer | fuzz |
| `gss-sspi-gate.sh` | honest `exit 2` when the SSPI oracle is absent | not a green claim |
| in-process `bounded_stress` | not the wire stress-gate | unit |
| cargo-vet exemptions | shrinking list; not a full local audit of every crate | documented |
| in-process metrics counters | deferred; logs-as-metrics only (`logging.md`) | n/a |

MSRV 1.95 `cargo test --workspace --locked` is the `msrv` job (edition
2024; `rasn` 0.28, goldens are the DER net). `publish = false` stays;
this matrix is the 1.0 claim, not crates.io. KLLDAP alignment:
[`integration-klldap.md`](integration-klldap.md).
