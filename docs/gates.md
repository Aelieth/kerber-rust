# Gates

Every `scripts/*-gate.sh`, one row each: the oracle it content-asserts
against, where it runs (`workflow:job` in `.github/workflows`), its lane,
and what it asserts. This table is that record. A later commit deletes a
row in the same commit that deletes its gate. The jobs, their budgets and the tiers
are in [testing.md § CI lanes](testing.md#ci-lanes-which-job-runs-which-gates)
and its Tier contract; the gate rules are in
[testing.md § Gate discipline](testing.md#gate-discipline).

Lanes: **fail-red**, a red blocks the push; **soft**, a `continue-on-error`
job; **nightly**, a scheduled workflow (a red is a red, but a push does not
wait for it). **stub** and **wrapper** (lane —) are in no workflow: a stub
needs an absent peer, a wrapper runs other gates locally.

Oracles: **MIT** 1.22.2 (the equality bar), **Samba** 4 AD, **Heimdal** 7.8
(secondary), or **none** (Rust against Rust: it proves behaviour, not
parity). An MIT program a gate compiles in the MIT image is linked by `krb5-config`
(`mit_oracle_cc`) and prints the `libkrb5` it loads, `krb5-1.22.2-final`, before
its first use; any other brand is red.

No gate drives SSSD's `krb5_child`, gssproxy, NFS, the satomlin kit or
Windows SSPI. They ran in the KVM field lab
([`harness/field/README.md`](../harness/field/README.md)), against MIT's
KDC first and then against ours: `krb5_child` logged in, renewed a TGT
and changed a password; NFS 4.2 `krb5i` and `krb5p` (AES-SHA1) mounted
from NFS-Ganesha through rpc.gssd (the kit's gssproxy, in the path, served no
credential under either KDC); the kit joined Fedora
clients with MIT's client tools; over the AD trust, Windows SSPI accepted a
user of the realm (SMB, LDAP) and, as a SPNEGO client, reached Apache
`mod_auth_gssapi`. Not run: the Rust tools on a cache gssproxy writes,
`krb5-gss` against SSPI, the kit with the Rust client tools against MIT's
KDC, and SHA-2 enctypes over NFS. Against our KDC the Rust client tools ran beside MIT's and
fail the kit's keytab check (no `klist -k`; [install.md](install.md) lists what is missing).


Rows: [OTP](gates-otp.md).
| Gate | Oracle | Workflow | Lane | Asserts |
| --- | --- | --- | --- | --- |
| `scripts/ad-s4u-gate.sh` | Samba | `peers:peers` | nightly | Samba's own KDC, no Rust leg (a reference run): MIT `kinit -f -k` as `kbrsvc`, `kvno -U` `kbruser` and `kvno -U` `kbruser` `-P` `host/svc.ad.kerber.test` exit 0; `klist -f -e` names the `host/svc.ad.kerber.test` ticket, `for client` `kbruser`, and an AES `-cts-hmac-sha1-96` etype |
| `scripts/ad-windows-gate.sh` | Samba | `peers:peers` | nightly | Samba `kinit kbruser` + `kvno host/svc`: live Samba ticket (not the torn-down Windows DC) |
| `scripts/asn1-decode-oracle-gate.sh` | MIT | `nightly:oracles` | nightly | MIT 1.22.2's own `decode_krb5_<type>` in an in-container C oracle (`scripts/oracle/asn1-decode-oracle.c`, no Rust code) over the decode sweep (`asn1-sweep corpus`: every explicit `[n]` field and SEQUENCE OF element of 41 message types broken each of nine ways, and each 32-bit counter at MIT's int32 edges), then over the Rust decoder's re-encoding of each case it decodes: red when the Rust decoder refuses a case MIT decodes, decodes one MIT refuses, or decodes one to a value MIT re-encodes otherwise, and when the committed golden (`crates/krb5-tools/tests/data/asn1-mit-golden.tsv`, which the unit test reads) is not MIT's answer |
| scripts/capaths-compress-gate.sh | MIT | `nightly:moving` | nightly | MIT 4-hop A.EX.COM→EX.COM→B.EX.COM→C.EX.COM: contents `EX.COM,B.`, expanded `EX.COM,B.EX.COM`, T set; deny `KDC policy rejects request` |
| `scripts/capaths-transit-gate.sh` | MIT | `nightly:moving` | nightly | MIT `kvno` A.TEST→B.TEST→C.TEST vs three MIT KDCs then three Rust KDCs: EncTicketPart `transited_tr_type` 1, `transited_contents` `B.TEST` and `T` (`transited_policy_checked=1`) match MIT KDC; deny (C without capaths): `KDC policy rejects request`; `krb5-kvno --disable-transited-check` vs both: default is `KDC policy rejects request` with `BAD_TRANSIT` in the new KDC-log lines, `reject_bad_transit=false` accepts with `transited_policy_checked=0`; inbound krbtgt `DISALLOW_ALL_TIX` fails with `PROCESS_TGS` in the new KDC-log lines on MIT C and Rust C; S4U colliding-name fails with `INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH` in the new KDC-log lines on MIT C and Rust C; bare-A-TGT `klist` keeps `krbtgt/C.TEST@B.TEST` not unasked `krbtgt/B.TEST@A.TEST` |
| `scripts/client-gate.sh` | MIT | `ci:mit-smoke` | fail-red | Rust `krb5-kinit` vs MIT `krb5kdc`: MIT `klist` of the Rust ccache names `user@KERBER.TEST` + `host/testhost.kerber.test`; Rust `klist -f -e` matches MIT flags/etype; `krb5-kvno` service ticket; `kdestroy` then MIT `klist` has no cache; symlink kdestroy refused (target intact); default ccache `/tmp/krb5cc_<uid>`; Rust `kvno` rewrite keeps MIT `klist -C` `config:`; `kinit -kt`; MIT and Rust `klist -s` agree |
| scripts/config-include-gate.sh | MIT | `nightly:moving` | nightly | MIT vs Rust `kinit`/`kvno` on `include`/`includedir` + `KRB5_CONFIG`: dotted `10.conf` drop-in; A:B first-wins `default_realm`; missing include fails both sides |
| scripts/cross-kdc-gate.sh | MIT | `nightly:moving` | nightly | one identical dump; MIT `krb5kdc` :88 and Rust KDC :8888: a TGT issued by either KDC is accepted by the other's TGS (`kvno` both ways); the TGT enc-part etype (`klist -e`) is the same on both KDCs; with no AD data (no `domain_sid`) the AS TGT's, the TGS and AS service tickets' and S4U2Self's PAC is MIT's buffer for buffer (`pac_layout`), the AS tickets are MIT's size, and one MIT TGT renewed by each KDC keeps the same PAC bytes; a cross-realm S4U2Self (`kvno -I`) both ways with OTHER.TEST, an MIT db2 realm: for its user either KDC's last hop gives MIT's PAC, and for a KERBER.TEST user MIT's last hop takes either KDC's referral |
| `scripts/differential-gate.sh` | MIT | `ci:mit-smoke` | fail-red | same AS/TGS bytes to Rust and MIT on one dump (diffsend encodes each case once): stable-rep / error-code compare; diffsend rc 0 and all 123 cases `"outcome":"ok"` (`DIFFSEND_RATCHET=123`; any mismatch is red); a `"whitelist"` key is red |
| `scripts/getprivs-gate.sh` | MIT | `nightly:moving` | nightly | MIT `kadmin getprivs` vs Rust kadmind ACL: the admin (`*`) and an actor whose ACL is `i` alone both print `INQUIRE` (or `GET`), `ADD` and `MODIFY`; the `i` actor's `cpw -randkey` is refused as AUTH_CHANGEPW (`change-password`), not AUTH_GET |
| scripts/gss-gate.sh | MIT | `nightly:moving` | nightly | MIT `libgssapi_krb5` initiator vs `krb5-gss-accept`: unwrap of `hello-from-mit-gss`; `GSS_C_DELEG_FLAG` both directions names `user@KERBER.TEST`; MIT SPNEGO handshake (`gss-accept spnego mic ok`, `gss-accept spnego peer mic ok`); MIT `gss_wrap_iov` unwraps on the Rust acceptor (with `SIGN_ONLY` through Rust `unwrap_iov`); Rust `wrap_iov` / MIT `gss_unwrap_iov`; MIT DCE `wrap_iov` → Rust and → MIT unwrap; inquire lifetime > 0; replayed AP-REQ is 34 on both (MIT KRB-ERROR 34 `Request is a replay`; Rust `accept_sec_context: KRB-ERROR 34: Request is a replay`); a ticket from `OTHER.TEST` listing `KERBER.TEST`, the server's realm, as transited is refused on both, MIT first (`Illegal cross-realm ticket`); a replayed AP-REQ's error token, with and without mutual, bare and in SPNEGO, is MIT's on both (`gss-reply.py`), eight crafted AP-REQs (`rd-sweep gss-errtok`) get MIT's reply on both, and the one claiming CHANNEL_BOUND without bindings MIT's context flags, and the Rust initiator reads MIT's error token as MIT's initiator does; direction/filler/EC mutations rejected on both acceptors |
| scripts/history-mit-gate.sh | MIT | `nightly:moving` | nightly | MIT `kadmin.local` history-window on a MIT KDB: history=1 allows A→B→A; history=2 rejects B after A→B→C |
| `scripts/iprop-gate.sh` | MIT | `nightly:moving` | nightly | MIT's kadmind, then ours, on a full resync: a legacy request's `iprop` dump, and after an outside `kadmin.local` write a replica's `ipropx 1` dump that MIT `kpropd -A` loads with the write, with `.dump_ok`, `.last_prop` and `kprop -f` of it; MIT `kpropd -A` GET_UPDATES + `krb5-iprop-pull` vs MIT kadmind: MIT `kinit extra` after master restart + serial-delta (no extra FULL_RESYNC); MIT `kinit extra2` on Rust replica whose dump holds the `setstr` value and whose `extra2` keeps the flags, lifetimes and expirations the setstr update did not carry; extra2 PAC RID ≠ 1000 (the replica's `domain_sid` makes the RID AD data) |
| scripts/kadmin-both-gate.sh | MIT | `nightly:moving` | nightly | both kadminds side by side: `listprincs`/`listpols` glob lists and `getprinc` records (keys, lifetimes) equal between the Rust kadmind and MIT kadmind |
| scripts/kadmin-local-gate.sh | MIT | `nightly:moving` | nightly | Rust `krb5-kadmin-local` then MIT `kadmin`: `addprinc -pw extra-local extra2` and `addprinc host/slashhost`; MIT `getprinc` both names, `listprincs extra2*`; a `KRB5_ACL_FILE` naming a missing file is ignored (`listprincs` rc 0, lists `user@KERBER.TEST`); `-randkey` + MIT `getprinc` `vno 1` + `kinit -k`; `+requires_preauth`; two `ktadd -k` both names; dump `getprinc` after mutating `setstr` keeps a concurrent kadmind create (`m5k: m5v`); local `addprinc -pw n7-pw n7local` then remote `cpw -pw extra-n7 extra2` keeps both; MIT `kadmin.local` `ktadd -k` of `krbtgt/KERBER.TEST` rotates (`Key: vno` 2) and writes the keytab, Rust local `ktadd -k` of `krbtgt/KERBER.TEST` writes it (`klist -k`); `passwd_check` modules vs MIT `kadmin.local` (`pwq_lines` identical): `addprinc -pw ""` is `Empty passwords are not allowed`, a principal-name password under a policy is `Password may not match principal name`, a realm or `dict_file` word under a policy is `Password is in the password dictionary`, no policy accepts the name and the dict word, the rejected `pqname` create leaves nothing |
| scripts/kadmin-mit-gate.sh | MIT | `nightly:moving` | nightly | MIT kadmind 749 in its own `kerber-rust-kadmin-mit` container (the oracle leg; needs the Rust leg's container and the `load_rust_snap` snapshots that `kadmin-rust-gate.sh` and `kadmin-rust-acl-gate.sh` save): the MIT side of the RPC cells (`AUTH_TOOWEAK`, service names, a later key, RPCSEC_GSS reject, integrity tamper, changepw `listprincs` `list_code=43787564`), the lockdown cells (`extract-keys`, `delete'' privilege`, `modify'' privilege`), the alias/glob, ACL and policy cells; `kadmin/history` shape, `getprivs`, `getpol` and expiry equal to the Rust snapshots; `modprinc -unlock` against both kadminds (TL `1792`) |
| scripts/kadmin-rust-gate.sh | MIT | `nightly:moving` | nightly | MIT `kadmin` vs `krb5-kadmind` 749 (the Rust leg): add/cpw/mod then `kinit extra`; get/list; chrand (dates move)/ktadd/`ktadd -norandkey` then `kinit -k`; `+lockdown_keys`/purgekeys/`cpw -keepold`/setstr/`renprinc`; del then `getprinc` fails |
| `scripts/kadmin-rust-acl-gate.sh` | MIT | `nightly:moving` | nightly | MIT `kadmin` vs `krb5-kadmind` 749: the `alias_cells` / `glob_cells`, ACL-restart and policy cells (attached to the Rust leg's container) |
| `scripts/kdb-dump-gate.sh` | MIT | `nightly:moving` | nightly | MIT `kdb5_util` dump/load both ways: MIT `kinit` vs Rust; MIT load of policy-bearing dump + `getpol lockme` |
| `scripts/kdc-gate.sh` | MIT | `ci:mit-smoke` | fail-red | MIT `kinit`/`kvno` vs Rust KDC: MIT TGT + host ticket; TGS audit seed stage 1 / no `tkt_out_id` / same `req_id` as `ENCR_REP`; `examples/configs` as written: `krb5-kdb create`, `krb5-kdc` + `krb5-kadmind` on `kdc.conf` alone, MIT `kadmin` `addprinc`, MIT `kinit` + `kvno` on `krb5.conf`; the same realm on KLLDAP's `kdc_ports = 750,88` with no listener pins: MIT `kinit` over TCP 88 and UDP 750 to the container's non-loopback address, MIT `kadmin` `addprinc -randkey` + `ktadd` on 749, `kinit -k` |
| scripts/kdcpolicy-gate.sh | MIT | `nightly:moving` | nightly | MIT `kdcpolicy_test.so` vs Rust `TestPolicy` (`KRB5_KDCPOLICY=test`): AS/TGS deny on a `fail` first component is `KDC policy rejects request` on both legs (Rust AS also `LOCAL_POLICY` in `/tmp/kdc.log`); SPAKE `spake_preauth_indicator = ONE_HOUR` rewrites AS life to 3600 s and TGS life to 1800 s on both; a foreign indicator (`OTHER`) is `KDC policy rejects request` on both |
| scripts/knobs-gate.sh | MIT | `nightly:moving` | nightly | kit-like `krb5.conf` vs MIT 1.22.2 and Rust `kinit`: `kdc_timeout`/`max_retries` do not change MIT (or Rust) kinit success; `forwardable` + `default_tkt_enctypes` show `F` and `aes256-cts-hmac-sha1-96` on `klist -f -e`; `default_ccache_name` env>conf>builtin path parity; conf `proxiable`: MIT and Rust `kvno` host tickets show `P` |
| scripts/kpasswd-mit-gate.sh | MIT | `nightly:moving` | nightly | the oracle leg of `kpasswd-rust-gate.sh`, against MIT kadmind 464: `-minlength 8` is `SOFTERROR` (`kpasswd` rc 2, `Password change rejected`, `result_code=4`); TGT `kvno kadmin/changepw` / `kadmin/admin` refused (`KDC policy rejects request`), MIT KDC log `TGT BASED NOT ALLOWED` |
| scripts/kpasswd-rust-gate.sh | MIT | `nightly:moving` | nightly | MIT `kpasswd` vs Rust kadmind 464: new password `kinit`; old fails; second `kpasswd` + `kinit`; `-minlength 8` is RFC 3244 `SOFTERROR` (rc 2, `Password change rejected`, `result_code=4`); TGT `kvno kadmin/changepw` is 12 `TGT BASED NOT ALLOWED` (`KDC policy rejects request`) |
| `scripts/kprop-gate.sh` | MIT | `nightly:moving` | nightly | MIT `kprop` dump v7 (+250 principals) vs `krb5-kpropd` 754: MIT `kinit user` on replica; `klist` names `user@KERBER.TEST` |
| `scripts/kprop-reverse-gate.sh` | MIT | `nightly:moving` | nightly | `krb5-kdb dump` (+250 principals) + Rust `krb5-kprop -f` vs MIT `kpropd`: byte-equal, `.last_prop`; MIT `kinit user` |
| `scripts/mit-fast-kdc-gate.sh` | MIT | `nightly:moving` | nightly | MIT `kinit -T` + `kvno` vs Rust KDC; forged-realm armor vs MIT + Rust; forged-realm FAST TGS: plain `kinit` TRACE `FAST negotiation: available` (RFC 6806 `enc-pa-rep`); `kinit -T` TRACE `Upgrading to FAST due to presence of PA_FX_FAST` or `Using FAST due to armor ccache negotiation result`; ≥2 `fast::KrbFastResponse` in the KDC log; forged `kinit -T` is 35 / `The ticket isn't for us` both sides (both KDC logs `FIND_FAST`); forged FAST TGS is 7 `PROCESS_TGS` + MIT `UNKNOWN SERVER: server='krbtgt/KERBER.TEST@FORGED.EXAMPLE'`; client `Server host/testhost.kerber.test@KERBER.TEST not found in Kerberos database` verbatim; MIT default-client `edwards25519` SPAKE vs a P-256-only KDC is 24 on both |
| `scripts/pkinit-gate.sh` | MIT | `nightly:moving` | nightly | MIT `kinit -X X509_user_identity=FILE:` vs Rust KDC: `pkinit.so` present; log `rfc8636 sha256 kdf`; SAN≠cname log `pkinit client san`; anonymous `kinit -n` → `klist` `WELLKNOWN/ANONYMOUS` / `WELLKNOWN:ANONYMOUS`, `restrict_anon` `kvno` prints `KDC policy rejects request` and the Rust KDC log has `ANONYMOUS NOT ALLOWED`; RFC 8070 `pkinit_require_freshness = true`: MIT `kinit -X` succeeds and the Rust KDC log has `freshness token received`, `disable_freshness=yes` is `Preauthentication failed` + `no freshness token, rejecting` |
| `scripts/prop-acl-gate.sh` | MIT | `nightly:moving` | nightly | MIT `kprop` vs Rust kpropd `-a`, and vs MIT `kpropd` `-a` as the oracle: no `-a` and no default `kpropd.acl`, or an empty one: `Rejected connection from unauthorized principal`, no replica; host allowlist by `-a` or as the default file: `SUCCEEDED`, replica, MIT `kinit user`; a ticket for `host/localhost` (its key in the keytab): `The ticket isn't for us` from both; a replica named `kdc2` searching `kerber.test`: both take a ticket for `host/kdc2.kerber.test` (`SUCCEEDED`, MIT's `krb5_recvauth(4, kprop5_01, host/kdc2.kerber.test@KERBER.TEST`) and refuse it under `qualify_shortname = ""` (`Service key not available`); kdc.conf's `dns_canonicalize_hostname = sometimes`, `allow_weak_crypto = maybe`, `request_timeout = bogus` or `plugin_base_dir = %{bogus}/x` stops both (`while initializing krb5`, `rc=1`), the boolean inside `KERBER.TEST = {` or as `Allow_Weak_Crypto` does not (`rc=124`); `acl-$name` cells: 17 `kpropd.acl` variants (exact, other principal, glob lines, leading/trailing whitespace, no realm, longer name, `#`, enctype match / alias case / mismatch / unknown / number / two / CRLF, name CRLF, no final newline) give the same kprop verdict and refusal count on MIT kpropd and Rust kpropd |
| scripts/rc4-session-gate.sh | MIT | `nightly:moving` | nightly | MIT `kinit`/`kvno` vs Rust KDC and Rust `krb5-kinit`/`krb5-kvno` vs MIT, `session_enctypes rc4-hmac` on krbtgt + host: both legs: TGT and host session key `arcfour-hmac` in `klist -e`; Rust KDC log `"key_usage":9`; `DEPRECATED:arcfour-hmac` display parity on both `klist`; `allow_rc4` under `[kdcdefaults]` alone: both KDCs refuse the rc4-only client alike (`KDC has no support for encryption type`); KDC `permitted_enctypes` aes256: `z14mixed` sealed aes256 (control aes128) and `z14only` `FINDING_SERVER_KEY`, alike; stale keytab after `cpw -randkey -keepold` is `Password incorrect` on both; armor TGT resealed under the non-permitted aes128 key: `kinit -T` is `Generic error (see e-text)` on both, the genuine TGT still armors |
| `scripts/rd-priv-oracle-gate.sh` | MIT | `nightly:oracles` | nightly | MIT 1.22.2 `krb5_rd_req`, `krb5_rd_priv` and `krb5_rd_safe` in an in-container C oracle (`scripts/oracle/rd-priv-oracle.c`) over `rd-sweep cases`: an AP-REQ whose authenticator, a KRB-PRIV whose `EncKrbPrivPart` and a KRB-SAFE whose body is broken as the decode sweep breaks a message, then re-encrypted or re-signed, and the three messages themselves broken the same way; MIT accepts the pristine three; red on any case the Rust acceptor answers otherwise than MIT (accepted, an ASN.1 error, or the krb5 code). Its order leg sends `rd-sweep order`'s faults, alone, in pairs and some twice, some naming the server, through the oracle's `text` mode with a replay cache and only aes256 permitted, and through `rd-sweep judge-order` with one of its own; red on any code or message otherwise than MIT's. Its second leg builds a realm in the container (`kdb5_util create`, `ktadd -norandkey` of `kadmin/changepw`, `kdb5_util dump`) and runs `rd-sweep kpasswd`'s requests, the cases as RFC 3244 frames, through the oracle's `kpasswd` mode (`-DKPASSWD_KDB`: `krb5_rd_req` naming `kadmin/changepw` against the `KDB:` keytab with sequence numbers only, `krb5_mk_rep`, `krb5_rd_priv` with no address) and through `rd-sweep judge-explicit` (the kpasswd request handler over the dump), both in the container: the KRB-PRIV names the container, none, 127.0.0.1 or an address no machine has as its receiver, and a ticket is sealed in each key of `kadmin/changepw` but its first; MIT reads the first two and refuses the rest; red on any request answered otherwise than MIT (`0` read, `req` AP-REQ refused, `priv` KRB-PRIV refused). Its third leg adds `kadmin/history` and a host service to that realm, writes each service's keys with `ktadd -norandkey` and runs `rd-sweep kadmind`'s AP-REQs (a ticket in each key, at kvno 0 and 99, in an enctype the keytab lacks, under another cleartext server or realm) through the oracle's `kadmind` mode (`krb5_rd_req` against the `KDB:` keytab with no server, as RPCSEC_GSS accepts, then naming `kadmin/admin` and `kadmin/changepw`, AUTH_GSSAPI's two) and through `rd-sweep judge-kdb`; red on any case answered otherwise than MIT (`0` or the krb5 code, for each of the three) |
| scripts/rust-kinit-enterprise-gate.sh | MIT | `nightly:moving` | nightly | MIT `kinit -E` vs Rust KDC; Rust `kinit -E` vs MIT (must match MIT client): MIT db2: MIT and Rust `kinit -E` of `user@KERBER.TEST` exit non-zero with `not found`; Rust KDC: klist `Default principal: user@KERBER.TEST` (not `user@KERBER.TEST@KERBER.TEST`) |
| `scripts/rust-kinit-fast-gate.sh` | MIT | `nightly:moving` | nightly | Rust `kinit --fast` vs MIT KDC: MIT `klist` `user@KERBER.TEST`; TRACE `Decrypted AP-REQ`; no-`+requires_preauth` `nopreauth@KERBER.TEST` FAST: TRACE `Decrypted AP-REQ` `aes256-sha2`, `klist -e` `aes256-cts-hmac-sha384-192`; `kdc_timesync = 0` + `kinit -s 1h`: MIT and Rust both exit 0; `kvno` with `clockskew = 60` and a ccache header offset of 120, -120, 0: MIT and Rust both `Clock skew too great in KDC reply` for the first two, exit 0 for 0; no preauth with a `norealm`, `onlyrealm` or `special` salt: MIT and Rust both exit 0; `kvno` with an expired `krbtgt/OTHER.TEST@KERBER.TEST` cached (5 s `maxlife`): MIT and Rust both start from the local TGT and use no cached TGT; `request_timeout = 3` with a TCP server that sends one byte a second (`scripts/lib/trickle-kdc.py`), `kinit` and `kpasswd`: MIT and Rust both exit 1 `Cannot contact any KDC` within 6 s; a TGS-REP with a modified ticket through `kdc-rewrite-proxy.py tgs-rep-ticket`: `kvno` prints `Ticket modified in KDC reply` and sends two TGS requests, MIT and Rust; a kpasswd reply with a short length field: both print `Message stream modified`; a realm relation `KDC =` (upper case): both find no KDC |
| `scripts/rust-kinit-pkinit-gate.sh` | MIT | `nightly:moving` | nightly | Rust `kinit --pkinit FILE:` vs MIT KDC: MIT `klist` `user@KERBER.TEST`; `pkinit.so`; Rust `kinit --pkinit` exits 0 with an empty `KRB5_PASSWORD`, and the MIT KDC trace plus the Rust `kinit` output match a five-arm case-insensitive regex led by `PKINIT`; rogue KDC is 76, `KDC name mismatch` from pkinit module 17 in the Rust trace (MIT not listening is red); anonymous `kinit -n` + `restrict_anon` (`WELLKNOWN/ANONYMOUS`, `WELLKNOWN:ANONYMOUS`); `require_freshness` leg: MIT KDC logs `freshness token received` for the Rust client; 40 same-named certs, MIT first: both log `(depth 0): self-signed certificate`, Rust under 3s; no-SKID CA with an AKID key id: MIT `kinit` and Rust `kinit` both exit 0 |
| `scripts/rust-kinit-spake-gate.sh` | MIT | `nightly:moving` | nightly | Rust `kinit --spake` vs MIT KDC P-256: MIT `klist` `user@KERBER.TEST`; TRACE `SPAKE response received` or `SPAKE derived K`; `klist -C` shows `config: fast_avail(krbtgt/KERBER.TEST@KERBER.TEST) = yes` and `config: pa_type(krbtgt/KERBER.TEST@KERBER.TEST) = 151`; proxy log `error_code=91` + `e_text=PREAUTH_FAILED`; then Rust `kinit` with its default group vs MIT KDC with Fedora's SPAKE settings: TRACE `Sending SPAKE challenge with group 1` + `SPAKE response received`, wire `[150, 149]` then `[133, 151, 150, 149]`, `pa_type` 151 |
| scripts/rust-kpasswd-mit-gate.sh | MIT | `nightly:moving` | nightly | Rust `krb5-kpasswd` vs MIT `kadmind` 464: new password `kinit`; old fails |
| `scripts/s4u-mit-gate.sh` | MIT | `nightly:moving` | nightly | MIT `kvno -U` / `-U -P` vs Rust KDC: `klist` `for client user@KERBER.TEST`; user-TGT → host S4U2Self (Rust `krb5-kvno -U admin`) exits 1 and both KDCs (MIT :88, Rust :8888) log `INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH`; `kvno -U nosuch` not found; `kvno -U locked` revoked; S4U2Proxy without a delegation grant is `KDC can't fulfill requested option` on MIT db2 and the Rust KDC; RBCD: MIT `kvno -U user -P host/rbcd.kerber.test` gets a ticket whose PAC has delegation info (type 11) from MIT's KDC (test KDB) and from the Rust KDC; the krbtgt/OTHER.TEST tickets realm A issues for it, kept by `kdc-padata-proxy.py` and read with `krb5-pac-extract --ticket`, have the same clients and PAC clients on both legs |
| `scripts/samba-ad-gate.sh` | Samba | `peers:peers` | nightly | live Samba DC `kinit` and `kvno` of `krbtgt/${REALM}@${REALM}` exit 0; `klist` has `${USER}@${REALM}` and `krbtgt/${REALM}@${REALM}`; missing image `exit 2` |
| `scripts/samba-crossrealm-gate.sh` | Samba | `peers:peers` | nightly | MIT `kvno` both ways vs Samba (L3): each exits 0 and `klist` names the service; after the forward `kvno` only, the Samba log tail must not match `PAC.*` followed by fail / error / invalid (case-insensitive) |
| `scripts/samba-pac-l2-gate.sh` | Samba | `peers:peers` | nightly | a realm with an AD identity (`domain_sid`); vendored Samba `kcrypto` 6/7/16/19 (L2): recompute; a type-6 MAC byte flip, and a pre-PAC EncTicketPart byte flip (type 16's signed bytes), → `L2_MISMATCH` |
| `scripts/samba-pac-verify-gate.sh` | Samba | `peers:peers` | nightly | a realm with an AD identity (`domain_sid`); Samba decode of a Rust PAC (L1): all nine buffers of `pac_l1.py`'s `NEED` (`L1_OK`); a dummy requester SID fails |
| `scripts/samba-realtrust-gate.sh` | Samba | `peers:peers` | nightly | `samba-tool domain trust create` + reverse PAC: reverse LOGON_INFO SID/RID = live Samba-A `kbruser` `objectSid` |
| `scripts/spake-gate.sh` | MIT | `nightly:moving` | nightly | MIT `kinit` `pa_type` 151 / group 2 vs Rust KDC: TRACE `Preauth module spake (151) (real) returned: 0/Success` + group 2; `klist` `user@KERBER.TEST`; then MIT `kinit` with its default group vs Rust KDC with Fedora's SPAKE settings: challenge group 1 in the 25, e-data `[136, 19, 151, 2, 133]` with the cookie `MIT1`, kvno 1, 138 bytes, `[133, 151, 150, 149]`, AS-REP `[19]` |

## Notes by gate

The detail behind the rows. A row states only what its script greps or dies on; a note adds the
setup, the legs and the pointers behind it, and says so when it names something the script does
not check (a unit test, or "not asserted").

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
- scripts/capaths-compress-gate.sh — MIT 4-hop
  A.EX.COM→EX.COM→B.EX.COM→C.EX.COM; EncTicketPart contents `EX.COM,B.`,
  expanded `EX.COM,B.EX.COM`, T set; deny is `KDC policy rejects request`.
- `scripts/capaths-transit-gate.sh` — MIT `kvno` A.TEST→B.TEST→C.TEST vs
  three live MIT 1.22.2 KDCs, then the same chase vs three Rust KDCs;
  EncTicketPart transited (`tr-type` 1, contents `B.TEST`) and
  `TRANSITED_POLICY_CHECKED` match; missing capaths is
  `KDC policy rejects request`. The POLICY skip cells grep **only the
  new lines** of **that cell’s KDC-under-test log** for `BAD_TRANSIT` (MIT
  `FILE:` kdc log for MIT cells; the Rust KDC's redirected output log for Rust
  cells) and C-skip `klist` shows `krbtgt/C.TEST@B.TEST`.
  `krb5-kvno --disable-transited-check` vs default MIT and Rust is POLICY;
  with `reject_bad_transit=false` the skip is accepted and T is off. Forged
  `ticket.realm` on a B-sealed `krbtgt/C.TEST` (empty transited) is rejected
  at both MIT C and Rust C (`PROCESS_TGS`).
  `host/svc.c.test@GARBAGE.EXAMPLE` aimed at C (`--body-realm`) is refused
  with `GET_LOCAL_TGT` on both MIT and Rust. Dest RENEW at C with issuer
  `body.realm` is refused with `GET_LOCAL_TGT` both sides. A peer-minted TGT
  for a local user (`--claim-crealm`) is `INVALID LINEAGE` on both sides. A
  seeded C TGT plus `krb5-kvno -I victim@A.TEST user@C.TEST` is refused with
  `INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH` on both MIT C and Rust C (name
  collision across realms; `krb5-kvno` prints MIT's line for 36, `Ticket/authenticator don't
  match`, and the new KDC log lines carry the status). A seeded C TGT plus inbound `krbtgt`
  `DISALLOW_ALL_TIX` (MIT C `modprinc -allow_tix`) is refused on both MIT C
  and Rust C: `kvno` reports
  `kvno: Server host/svc.c.test@C.TEST not found in Kerberos database`, and the
  new KDC-log lines carry `PROCESS_TGS`. Bare A TGT
  plus Rust `krb5-kvno host/svc.c.test@C.TEST` chases MIT A→B→C
  (`body.realm` is the current TGT realm).
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
- scripts/config-include-gate.sh — MIT vs Rust on the same
  `include`/`includedir` + colon-split `KRB5_CONFIG` tree: dotted `10.conf`
  is read; two-file scalar first-wins; missing include fails (does not
  hang); a missing include, an indented one and an unexpandable default cache name print MIT's
  exact line from both `kinit`s.
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
  literal. Honest `exit 2` when docker or the MIT image is absent.
  The `preauth (…) verify failure:` lines of the two KDC logs are equal.
  Compare lives behind `krb5-protocol` feature `diff`
  (`diffsend.rs` and the unit fixture); `diff` is
  a default feature, so it is on the default public API. **TGS vehicle:**
  `tgs-success` mints a PAC-less TGT with the exported krbtgt key (etype
  20, empty `tr-type` 1). PAC-bearing cases mint a diffsend-signed PAC TGT
  (for example `tgs-pac-request-false`); no case verifies the re-signed
  PAC checksums of an issued ticket. **Transited flag:** the full
  flag-word compare holds `TRANSITED_POLICY_CHECKED` (bit 12) to MIT's in
  `as-success` and `tgs-success`.
- `ticket-flags.sh` `TF.expire.kinit`, `TF.pw.kinit`, `TF.pw.changepw`,
  `TF.tgs.pw.kvno`, `TF.tgs.acct.kvno`, `TF.need.kinit`, `TF.need.changepw` —
  MIT `kinit` NAME_EXP vs KEY_EXPIRED; `kinit -S kadmin/changepw` on a
  password-expired client; TGS `kvno` after client `-pwexpire`/`-expire`
  still succeeds; `modprinc +needchange` is `KEY_EXPIRED` unless the server
  is `PWCHANGE_SERVICE`.
- `ticket-flags.sh` `TF.flags.revoke`, `TF.flags.fwd.bits`,
  `TF.flags.deleg.bits`, `TF.flags.svr.kvno`, `TF.flags.tgt.kvno`,
  `TF.flags.hw.kinit` — MIT `modprinc` DISALLOW_*/OK_AS_DELEGATE/
  REQUIRES_HW_AUTH then `kinit`/`kvno`/`klist -f`.
- `scripts/getprivs-gate.sh` — MIT `kadmin getprivs` prints `INQUIRE` (or
  `GET`), `ADD` and `MODIFY` for the admin and for an actor whose ACL is `i`
  alone. MIT's `kadm5_get_privs` returns `~0` (`server_misc.c:147-158`); the
  gate does not see `~0`. Field `kdb-writes` KA.privs shows all four names
  for an actor with no ACL line.
  That actor's `cpw -randkey` is refused as AUTH_CHANGEPW
  (`change-password` privilege), not AUTH_GET.
- scripts/gss-gate.sh — copies `krb5-gss-accept` into the MIT 1.22.2
  container, exports `host/testhost.kerber.test` to a keytab, and runs an
  out-of-process MIT `libgssapi_krb5` initiator (scripts/oracle/gss-mit-client.c)
  that wraps `hello-from-mit-gss`. The Rust acceptor must unwrap that
  plaintext. A second MIT initiator with `GSS_C_DELEG_FLAG` must make the
  acceptor print `gss-accept delegated=user@KERBER.TEST`. A Rust initiator
  with a KRB-CRED trailer must make MIT `gss-mit-server` print the same
  name. A MIT SPNEGO initiator (`oid_spnego`, 1.3.6.1.5.5.2) must complete
  `NegTokenResp` + `mechListMIC` and still unwrap `hello-from-mit-gss`. A
  captured initiator AP-REQ resent on a new connection is 34 `REPEAT`
  (`Request is a replay`) on both the Rust acceptor and MIT
  `gss-mit-server`. A ticket from `OTHER.TEST` that lists `KERBER.TEST`,
  the server's own realm, as transited (`rd-sweep gss-transit`) is refused
  by MIT's acceptor, then by ours (`Illegal cross-realm ticket`). A replayed
  AP-REQ gets MIT's KRB-ERROR token (0x0300) from both acceptors when it asked for
  mutual, none when it did not, and a SPNEGO reject carrying it; the Rust initiator
  reads MIT's error token as MIT's initiator does. Eight crafted AP-REQs
  (`rd-sweep gss-errtok`) get the same reply from both acceptors: six refused
  after the checksum's flags (a bad delegation id with and without the mutual
  flag, FINISHED, a second AD-AP-OPTIONS, a raw AP-REQ without DCE and a framed
  one with it), a bad non-0x8003 checksum, and a checksum claiming
  CHANNEL_BOUND without bindings, whose context reports MIT's flags. No cell replays a
  token across an acceptor restart: MIT `dfl` file persistence across process restart is
  deferred (the ledger's `srv_rcache.c; rc_file2.c` row). MIT `gss_wrap_iov`
  (HEADER|DATA|PADDING|TRAILER, and with `SIGN_ONLY`) must unwrap on the
  Rust acceptor; Rust `wrap_iov` concatenates to a token MIT
  `gss_unwrap_iov` STREAM accepts. The acceptor prints
  `gss-accept import ok` and `inquire flags=` with lifetime > 0.
  `GSS_C_DCE_STYLE` wrap_iov must unwrap to the sent bytes on both legs;
  Rust-initiator direction/filler/EC mutations are rejected on both
  acceptors.
- `scripts/iprop-gate.sh` — MIT's kadmind (leg 0), then ours (leg 0R), on a
  full resync: `krb5-iprop-pull --full-resync-v0` gets the legacy `iprop`
  dump; after an outside `kadmin.local addprinc outsider`, MIT `kpropd -A` on
  its own database asks for a resync, gets an `ipropx 1` dump from disk and
  loads it (`listprincs` has `outsider` and `user`), with `.dump_ok`,
  `.<host>.last_prop` and a `krb5-kprop -f` of the dump that succeeds. MIT
  `kpropd -A` must not report IPROP program unregistered. After a first ipropx `kprop -f`, mutate the master,
  restart the Rust master (`krb5-kdc` and `krb5-kadmind`), and require serial-delta with no extra
  FULL_RESYNC: MIT `kinit extra` on the MIT replica; `krb5-iprop-pull` vs
  MIT kadmind then MIT `kinit extra2` (the replica dump holds the `setstr`
  value, and Rust `krb5-kadmin-local` on the replica shows the flags, lifetimes
  and expirations `extra2` had before that setstr, whose update carries none of
  them); extra2's replica PAC RID is not 1000 (same RID as the master is
  deferred: MIT kdbe has no SID and incremental encode omits vendor `0x4B0x`
  TL); MIT `delprinc extra2` then the name is gone on the Rust replica.
- scripts/kadmin-local-gate.sh — Rust `krb5-kadmin-local` `addprinc`
  extra2 and `host/slashhost` on dump/stash; MIT `kadmin` getprinc names
  `extra2@KERBER.TEST` and `host/slashhost@KERBER.TEST` (slash is two
  name-string components). A `KRB5_ACL_FILE` naming a missing file is
  ignored: `listprincs` exits 0 and lists `user@KERBER.TEST`. `-randkey`
  then MIT `getprinc` `vno 1` and `kinit -k`; `+requires_preauth` on MIT
  `getprinc`; two `ktadd -k` leave both principals (`klist -k`);
  dump-based `getprinc` after a mutating local `setstr` must keep a
  concurrent `kadmind` `addprinc` (`m5k: m5v` via `getstrs`); local
  `addprinc n7local` then remote `cpw -pw extra-n7 extra2`, then `getprinc` names both on the same
  dump.
- `scripts/kadmin-rust-acl-gate.sh` — attaches to the
  `kerber-rust-kadmin-gate` container that `kadmin-rust-gate.sh` keeps
  (`KERBER_KADMIN_KEEP=1`) and
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
- scripts/kadmin-rust-gate.sh / `kadmin-mit-gate.sh` / `kadmin-both-gate.sh` —
  MIT `kadmin` against `krb5-kadmind` on 749 in `kadmin-rust-gate.sh`: `addprinc`, `cpw`, `getprinc`
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
- `scripts/kdb-dump-gate.sh` — MIT 1.22.2 dump/load both directions. Half A:
  `krb5-kdb load` of MIT's `kdb5_util dump` of
  `tests/traces/kdb/mit-dump-v7.txt` (taken after an MIT `alias a1 user`
  and a password history), Rust KDC, MIT `kinit user` / `kinit pauser`.
  Half B: MIT `kdb5_util load` of `krb5-kdb dump`'s dump of the running
  KDC's database (`kdb5_util load_dump version 7`, not KDB3; the database
  appends each change, so it is dumped first, as MIT's DB2 file is), MIT
  `krb5kdc`, MIT `kinit` with `renew until` in `klist`. The database oracle is MIT `kdb5_util`
  dump/load: MIT dump → Rust load → Rust KDC → MIT `kinit`, and Rust dump →
  MIT `kdb5_util load` → MIT `krb5kdc` → MIT `kinit`. Promotion is MIT
  `kinit` + `klist`, never a Rust-vs-Rust round-trip. Golden dump:
  `tests/traces/kdb/mit-dump-v7.txt` (MIT 1.22.2 default is version **7**).
- `scripts/kdc-gate.sh` — copies the Rust `krb5-kdc` binary into a MIT
  1.22.2 container (`shell_container`; its audit cell later runs MIT
  `krb5kdc` there), binds 127.0.0.1:88 (fallback 8888), and runs MIT
  `kinit user@KERBER.TEST` plus `kvno host/testhost.kerber.test`. Its last
  cell runs `examples/configs` as written: `krb5-kdb -r EXAMPLE.COM create -s`,
  `krb5-kdc` and `krb5-kadmind` on `kdc.conf` alone, then MIT `kadmin`,
  `kinit` and `kvno` through `kadm5.acl` and `krb5.conf`. The same realm then
  restarts on KLLDAP's listener shape (`kdc_ports = 750,88`, no `kdc_listen`,
  no kadmind or kpasswd relation) and MIT `kinit`, `kadmin` and `kinit -k`
  reach it on the container's non-loopback address: TCP 88, UDP 750, 749.
- scripts/knobs-gate.sh — `kdc_timeout = 1`/`max_retries = 1` leave MIT
  and Rust kinit succeeding; `forwardable` + `default_tkt_enctypes` show `F`
  and `aes256-cts-hmac-sha1-96` on `klist -f -e`; `default_ccache_name`
  env > conf (`%{uid}`) > builtin; conf `proxiable` (MIT and Rust `kvno`
  host tickets both show `P`; the conf's `[domain_realm]` entries all map to
  the default realm, so the mapping itself is not tested).
- scripts/kpasswd-rust-gate.sh / scripts/kpasswd-mit-gate.sh — MIT
  `kpasswd` against kadmind 464 (`kadmin/changepw`), then `kinit` with the new password; old password must
  fail; second `kpasswd` + `kinit`. A `-minlength 8` policy rejection is RFC 3244
  `SOFTERROR` (`[0,4]`; MIT `kpasswd` rc 2, `Password change rejected`) on
  both Rust kadmind and MIT `kadmind`. A TGT-based `kvno kadmin/changepw` /
  `kadmin/admin` is refused (`KDC policy rejects request`; KDC
  `TGT BASED NOT ALLOWED`) on both KDCs; `getprinc` shows
  `DISALLOW_TGT_BASED`/`LOCKDOWN_KEYS`; remote `ktadd -norandkey` is
  `extract-keys`. After `+allow_tgs_req`, a TGS-obtained `kadmin/changepw`
  ticket self-change is result 7 `Ticket must be derived from a password` on
  both kadminds (scripts/oracle/kpasswd-tgs-client.c), including
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
- `scripts/kprop-reverse-gate.sh` — `krb5-kdb dump`, then Rust `krb5-kprop -f`
  of it and of +250 principals to MIT `kpropd -S -P 754` (`SUCCEEDED`,
  `.last_prop`, byte-equal dumps), then MIT `krb5kdc` + `kinit
  user`. No MIT image is `exit 2` under `KERBER_SKIP_MIT_BUILD=1`, else
  `need_image`.
- `scripts/mit-fast-kdc-gate.sh` — MIT `kinit -T` + `kvno` against the Rust
  KDC (TRACE `Upgrading to FAST due to presence of PA_FX_FAST` or `Using FAST
  due to armor ccache negotiation result`; KDC log ≥2 `KrbFastResponse`).
  Forged-realm armor (`krb5-forge-tgt --keep-cipher --claim-realm`) is 35
  on both MIT and Rust (`The ticket isn't for us`; both KDC logs `FIND_FAST`). Forged-realm FAST
  TGS (`kvno` on a forged `kinit -T` ccache) is 7 `PROCESS_TGS` on both; the
  MIT client line is required verbatim. A wrong password under FAST has
  equal `preauth (…) verify failure:` lines in both KDC logs. Not asserted
  here: the unit-red negatives MIT clients cannot emit (`as_fast.rs`,
  `ap_req.rs`).
- `scripts/pkinit-gate.sh` — **fails** unless MIT `pkinit.so` is present and
  MIT `kinit -X X509_user_identity=FILE:` succeeds against the Rust KDC. The
  KDC log must contain `rfc8636 sha256 kdf`. It also refuses MIT `kinit`
  with `other.pem` (SAN ≠ `user`) and greps the Rust KDC log for
  `pkinit client san`.
- `ticket-flags.sh` `TF.pol.short`, `TF.pol.list`, `TF.class.five`,
  `TF.hist.allow`, `TF.pol.locked`, `TF.dur.open`, `TF.int.open` —
  MIT `kadmin` addpol/modpol/getpol/listpols/`cpw`/delpol; too-short and
  reuse; `-minclasses 5`; history-N; `maxfailure 2` then revoked;
  lockout duration and the failure-count interval.
- `ticket-flags.sh` `TF.post.kinit`, `TF.post.nyv`, `TF.post.validate`,
  `TF.post.life.delta`, `TF.post.deny` — MIT `kinit -s` is INVALID (`i`);
  `kvno` is not yet valid; `kinit -v` then works; a five-minute life ends
  300 s after the start; `-allow_postdated` is ineligible for postdating.
- `scripts/prop-acl-gate.sh` — MIT `kprop` vs Rust kpropd with no `-a` and
  no `kpropd.acl` in the KDC directory, or an empty `-a` file, is refused (no
  replica dump); the host allowlist loads, by `-a` or as the default file;
  both kpropds refuse a ticket for another principal of the keytab.
  A second container named `kdc2` (`--dns-search kerber.test`, no DNS canonicalization) runs
  both kpropds and MIT `kprop` as `host/kdc2.kerber.test`: each kpropd qualifies its name with
  the search domain, and under kdc.conf's `qualify_shortname = ""` is `host/kdc2`
  (`sn2princ.c:121-144`); a context relation MIT refuses at the top of kdc.conf's
  `[libdefaults]` stops both at their start (`init_ctx.c:219-281`), one in a realm's
  subsection or spelled otherwise does not.
  The `acl-*` cells run 17 `kpropd.acl` variants against MIT `kpropd -a` and
  the Rust kpropd (same file, re-read per connection) and die unless kprop's
  verdict and the `Rejected connection from unauthorized principal` count
  agree (`kpropd.c:1298-1348`).
- `ticket-flags.sh` `TF.renew.delta`, `TF.renew.until`, `TF.renew.moved`,
  `TF.renew.strip.bits`, `TF.flags.prox.allow`, `TF.renew.zero.delta`,
  `TF.renew.day.delta`, `TF.renew.none.log`, `TF.z71.delta` — four-term
  renew; `kinit -R` keeps renew-until and moves the end; `-allow_renewable`
  strips `R`; `kinit -p` shows `P`; maxrenewlife 0 and 1 day; a renewable
  TGT against DISALLOW_RENEWABLE logs `NON-RENEWABLE TICKET`; an omitted
  realm cap clips an 8-day request to 7 days.
- scripts/rust-kinit-enterprise-gate.sh — MIT `kinit -E` against the Rust
  KDC (klist default principal is the canonical `user@KERBER.TEST`) **and**
  Rust `kinit -E` against MIT, which must match MIT `kinit -E` (both exit
  non-zero with `not found` on MIT db2; no UPN alias). A mixed-case UPN
  suffix (`user@kerber.test`) is not a local alias: both directions refuse
  it.
- `scripts/rust-kinit-fast-gate.sh` — Rust `kinit --fast --armor-ccache`
  against MIT; the AS-REQ carries PA-FX-FAST and MIT `klist` names
  `user@KERBER.TEST`. The gate asserts `Decrypted AP-REQ` (the armor
  AP-REQ), from TRACE only; the no-preauth FAST AP-REQ is `aes256-sha2`.
  `kinit -T` over an armor cache with a stale header offset (120) writes
  the AS reply's offset (0), MIT first (`scripts/lib/ccache-offset.py`).
  `request_timeout = 3` over a TCP server that sends a reply one byte a
  second (`scripts/lib/trickle-kdc.py`): MIT and Rust `kinit` and `kpasswd`
  stop within 6 s with `Cannot contact any KDC`. A TGS-REP with a modified
  ticket (`kdc-rewrite-proxy.py tgs-rep-ticket`) and a kpasswd reply with a
  short length field: MIT and Rust print the same text, `kvno` after the same
  two TGS requests. A realm relation `KDC =` is ignored by both: no KDC found.
- `scripts/rust-kinit-pkinit-gate.sh` — Rust `kinit --pkinit FILE:` against
  MIT KDC (`pkinit.so` + KDC cert + `id-pkinit-san`); it **fails** if the
  plugin is missing. MIT `klist` names `user@KERBER.TEST`. A follow-up
  negative restarts MIT with `pkinit_identity` pointing at the *client*
  cert; Rust `kinit` must fail, its trace showing pkinit module 17's 76 (`KDC
  name mismatch`), as MIT's `verify_kdc_san`. MIT not listening on
  that identity is **red**.
- `scripts/rust-kinit-spake-gate.sh` — Rust `kinit --spake` against MIT KDC
  (`spake_preauth_groups = P-256`) and MIT `klist` `user@KERBER.TEST`, with
  the same 91 `PREAUTH_FAILED` pin as `spake-gate.sh`. It sets
  `+requires_preauth user` and asserts a SPAKE *completion* line
  (`SPAKE response received` or `SPAKE derived K`) from the MIT KDC TRACE,
  not a PREAUTH_REQUIRED offer. A second leg gives MIT's KDC Fedora's settings
  (`spake_preauth_groups = edwards25519`, `spake_preauth_kdc_challenge = edwards25519`):
  the Rust `kinit` with its default group answers the optimistic challenge in its
  second request.
- scripts/rust-kpasswd-mit-gate.sh — Rust `krb5-kpasswd` against MIT
  `kadmind`.
- `scripts/s4u-mit-gate.sh` — MIT `kvno -U user` and `kvno -U user -P`
  against the **Rust** KDC (`kinit -f -k host/testhost.kerber.test`). The
  user-TGT → host S4U2Self mismatch cell (MIT `kinit` user TGT, then Rust
  `krb5-kvno -U admin`) runs against both the MIT KDC (the image's config,
  `krb5kdc -n` relaunched on :88) and the Rust KDC (:8888); both log
  `INVALID_S4U2SELF_REQUEST_SERVER_MISMATCH`. klist must name
  `for client user@KERBER.TEST`. `kvno -U nosuch` is
  `not found in Kerberos database` (or `C_PRINCIPAL_UNKNOWN`); `kvno -U locked`
  (`KRB5_TEST_LOCKED_USER`, `DISALLOW_ALL_TIX`) is
  `credentials have been revoked` (or `CLIENT_REVOKED`). S4U2Proxy without a delegation grant
  (`KRB5_TEST_S4U_TO` unset on the Rust KDC) is `KDC can't fulfill requested option`
  on MIT db2 and the Rust KDC; the Rust KDC logs e_text `NOT_ALLOWED_TO_DELEGATE`,
  MIT db2 `UNSUPPORTED_S4U2PROXY_REQUEST`.
  In the two-realm RBCD cells, a proxy in front of realm A's KDC keeps the
  `krbtgt/OTHER.TEST` tickets A issues for `kvno -U user -P` (kvno keeps none);
  `krb5-pac-extract --ticket` decrypts each with the cross-realm key, and the
  Rust leg's client and PAC-client lines must equal MIT's (the S4U2Proxy
  referral: the host, with PAC client `user@KERBER.TEST`).
  A non-forwardable evidence ticket (`BADOPTION`) is diffsend
  `s4u2proxy-not-forwardable`. PA-PAC-OPTIONS (167) is a Rust test
  (`s4u2proxy_rejects_malformed_pac_options`), not a gate cell.
- `scripts/samba-ad-gate.sh` — Samba 4 AD DC. The only `exit 0` is after a
  live `kinit`/`kvno`/`klist`. Missing image or KDC is `exit 2` plus
  `samba-ad-gate-unavailable.log`; missing docker is `exit 2`.
- `scripts/samba-crossrealm-gate.sh` — shared-trust-password TDO; MIT `kvno`
  `user@KERBER.TEST` → `host/svc.ad.kerber.test` and
  `kbruser@AD.KERBER.TEST` → `host/testhost.kerber.test`. After the forward `kvno` only, the Samba log tail must
  not match `PAC.*(fail|error|invalid)` (case-insensitive). `kvno` is not proof that the TGS copied
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
- `scripts/samba-pac-verify-gate.sh` — co-located Rust KDC on `:8888` whose
  kdc.conf sets `domain_sid` (AD data); Samba `PAC_DATA_RAW` + typed
  LOGON_INFO/REQUESTOR of a Rust-issued PAC (buffers 1,10,12,16,17,18,19,6,7).
  Dummy SID fails.
- `scripts/samba-realtrust-gate.sh` — two Samba AD DCs; real
  `samba-tool domain trust create` (fail with images present is `exit 1`);
  both-direction `kvno`; reverse Rust service PAC LOGON_INFO SID/RID equals
  live Samba-A `kbruser` `objectSid`. Missing images `exit 2`.
- `ticket-flags.sh` `TF.sha2.krbtgt`, `TF.sha2.host` — MIT `kinit`/`kvno`
  with only etype 20. The krbtgt session key and the host ticket key are
  `aes256-cts-hmac-sha384-192`. The TGT ticket key stays the long-term
  sha1 key.
- `scripts/spake-gate.sh` — runs MIT `kinit` against the Rust KDC with
  `preferred_preauth_types = 151` and `spake_preauth_groups = P-256`. It
  fails unless TRACE contains `Preauth module spake (151) (real) returned: 0/Success`
  and group 2, and `klist` shows
  `user@KERBER.TEST`. First-round KRB-ERROR **91** `e_text` is
  `PREAUTH_FAILED` (`do_as_req.c:439-442,809`) in the
  `scripts/lib/kdc-error-proxy.py` capture and the Rust KDC log, which also
  has `preauth (spake) verify failure: More preauthentication data is required`. A second leg
  gives the Rust KDC Fedora's settings and runs MIT `kinit` with its default
  group: the `kdc-padata-proxy.py` wire must be MIT's (25 with
  `[136, 19, 151, 2, 133]` and its PA-FX-COOKIE `MIT1`, kvno 1, 138 bytes (`KDC_PROXY_COOKIE=1`), then `[133, 151, 150, 149]`, then an AS-REP with
  `[19]`), with a group-1 challenge and `pa_type` 151.
