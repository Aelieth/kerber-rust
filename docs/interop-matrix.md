# Interop matrix

The implementations this port is checked against and what is kept from
them. The gates that content-assert against each one, where they run and
what they assert are in [gates.md](gates.md) (its Oracle column).
Timing/replay: [`security.md`](security.md). Isolation: never edit host
`/etc/krb5.conf`.

- **MIT 1.22.2** is the primary oracle and the equality bar: live MIT
  clients, KDCs, kadmind, kpropd and libraries against the Rust side, in
  both directions where a direction exists. On Debian 13 and Rocky Linux 10 the server scenarios run against
  the distribution's own MIT, 1.21.3, and are graded as 1.21 behaves: its kadmind starts beside a taken
  port, a self password change keeps every old key, and Rocky's build offers PKINIT's elliptic-curve groups.
- **Samba 4 AD** (`AD.KERBER.TEST`) checks the PAC, S4U and trusts, in seven gates that `peers.yml` runs and
  fails unless all seven ran.
  - `samba-ad`, `ad-windows` and `ad-s4u` use only Samba's own tools: they show the oracle works, not our code.
  - `samba-pac-verify`, `samba-pac-l2`, `samba-crossrealm` and `samba-realtrust` use our KDC's debug, test-hooks
    build: Samba decodes its PAC, checks its checksums and rejects corrupted ones, takes its referral PACs both
    ways over a shared trust password, and returns the right reverse SID over a real `samba-tool` trust.
  - Our client tools are in none of the seven.
- **Heimdal 7.8**'s client tools on Debian 13 ran against MIT's KDC and then ours (below). Heimdal's KDC,
  cross-realm with it and its `kcm` have not been run since v1.1.0.

## Field consumers

Production use is the proof. Each consumer below ran against a kerber-rust realm brought up by
[install.md](install.md), beside the same scenario against a stock Fedora MIT 1.22.2 realm in the same lab
(libvirt VMs on one host), MIT first. The scenarios in the last column repeat through `make field`
([harness/field](../harness/field/README.md)), or by the hand drivers ([harness/hand](../harness/hand/README.md)).
The release pass of 1.2.1 ran on tree RP-FILL, with RP-FILL product failures in any leg.
A row that names a commit gives the run that proved it while 1.2.1 was built.

| Consumer | What ran against both realms | Repeats as |
| --- | --- | --- |
| SSSD on Fedora (`krb5_child`; the reference client kit) | password login into a FILE cache, renewal at an sssd restart, `passwd` through kpasswd, `-allow_tix` refused, the kit's own validation | `sssd-login` |
| NFS 4.2 to NFS-Ganesha through rpc.gssd | `sec=krb5i` and `krb5p` mounts by the machine credential, a user's writes and reads, root squashed, a ticketless user refused (the kit's gssproxy, in the path, served no credential under either KDC) | `services`, `nfs-client` |
| Keycloak (Java JGSS) SPNEGO | `401 Negotiate`, then `302` with `code=` and a mutual token | `services`, `nfs-client` |
| OpenSSH `gssapi-with-mic` | sshd GSSAPI from one client to another, short name and FQDN | by hand |
| Active Directory two-way trust (Windows Server) | an AD user into this realm over ssh, this realm's user to AD's SMB and LDAP acceptors, Windows as the SPNEGO client | `ad-trust` (`run.sh ad-trust`, in no profile; it changes the DC and undoes it) |
| KLLDAP (`079a564`) with `krb5-server` swapped for kerber-rust | its own gate, all phases, with the same lines as on MIT; its live-KDC FFI lane on two MIT client libraries; phase 80 on a realm migrated by install.md's container steps | `klldap-swap`; the VM legs by hand |
| An in-place upgrade of kerber-rust | install.md's upgrade blocks as written: listeners, MIT's log lines, principals unchanged, MIT clients over UDP and TCP | `upgrade` |
| Our client programs (`kinit`, `klist`, `kvno`, `kdestroy`, `ktutil`, `kswitch`) beside MIT's | called as a managed client calls them: FILE and DIR caches, keytabs, crossed caches and the refusals; FAST, SPAKE, S4U2Proxy, lifetimes and enctypes | `client-tools` |
| MIT's `kinit` with PKINIT | anonymous and certificate requests, P-256 and RSA KDC identities from kdc.conf | `pkinit` |
| MIT's `libkrb5` at kpasswd | set-password cells and raw datagrams at 464 | `kpasswd` |
| MIT's `kinit` and `kadmin` | ticket expiry, flags, renewal, postdating, policy and aes-sha2; what the KDC takes from kdc.conf; kadmind's writes against the KDC's lockout writes | `ticket-flags`, `kdc-profile`, `kdb-writes` |
| An iprop replica of an MIT primary | this port's `kpropd` and `krb5kdc` on the replica, beside MIT's | `replica` |
| Going back to MIT | install.md's section as written, the principals as kerber-rust kept them | `rollback` |
| A fresh install | install.md's blocks on a pristine VM, then a realm from scratch | `install` |
| MIT's client tools and SSSD on Fedora 44, Rocky Linux 10, Debian 13 and Ubuntu 26.04 | `FILE:` and `KCM:` caches: `kinit` by password and keytab, `kvno`, renewal, `kpasswd`, expiry and password expiry, lockout and unlock, an SSSD login with renewal, remote `kadmin`; the realm moved from MIT's KDC to ours on the same VM, its principals the same. At `4b01721d`, 68 rows equal and 16 SSSD renewals | `rp-cm.sh` (by hand) |
| Heimdal 7.8's client tools on Debian 13 | `kinit`, `klist`, `kgetcred` and `kpasswd` on a `FILE:` cache, and the texts for a wrong password and an unknown principal. At `2bdcedc3`, 5 rows equal | `rp-cm.sh <sha> hm` (by hand) |
| Windows 11's own Kerberos and SSPI, a workgroup machine joined with `ksetup` | realm mapping; AS and TGS and `klist`'s fields; SSPI sign and seal against MIT's GSS acceptor and ours; a password change; the wrong-password and expired-password texts; RC4 refused; SPNEGO to Keycloak; an interactive logon as a realm user. The machine's principal needs `+no_auth_data_required` ([install.md](install.md#windows-clients)). At `0f633715`, 10 rows equal | `rp-ws.sh` (by hand) |
| Our KDC, kadmind and replica on Debian 13 and Rocky Linux 10, beside the distribution's MIT | install, upgrade, kadmind's start, the KDC's settings, database writes, PKINIT, `kpasswd` and a replica. Every scenario passed on both legs: Debian 13 at `514f7b96`, Rocky Linux 10 at `0f633715` | `ds` (`harness/field/ds/<vm>.env`) |
| Load | requests and writes on each KDC for 600 s and for 3,600 s: no request failed (467,184 on ours in the hour). Ours' memory follows the realm's size, about 1.25 KiB per principal, and is flat with the size held (`9947d735`, `cbf91e16`) | `load`, `load-long` |
| Restarts, hostile input, the OTP default, `rd_safe` | a write, a kill and a relaunch keep the write and its dump; the KDC's replies to hostile input equal MIT's, its memory stays flat, and `kinit` works after each cell; `rd_safe` answers as MIT's; the OTP default's refusal and log lines equal MIT's but for the documented info text (`cbf91e16`) | `lt` |
| `sssd-kcm` 2.13.1 on Fedora 44, against MIT's KDC | our `kinit`, `klist`, `kvno`, `kdestroy` and `kswitch` beside MIT's on `KCM:` collections, each reading the other's caches; identical but for the program's name in one error | by hand |
| `krb5-embed-realm`, the KDC and kadmind over one store | a realm beside MIT's: the same 40 principal fields but `admin/admin`'s `REQUIRES_PRE_AUTH`, `kinit`, `addprinc`, restarts that keep the keys, 50 crash cells | by hand |

### Write cost

Measured beside MIT 1.22.2, MIT first, at 10, 1,000 and 5,000 principals, on 1.2's full-pass tree `637ea964`. At 5,000 a
password create is 0.84 times MIT's median, a random-key create 1.00 times and a password change 0.95 times; no
operation at any size is above 1.08 times MIT. With the update log on, none is above 1.004 times MIT. Ours at 5,000
over ours at 10 is 1.145, 1.035 and 1.159 for those three. That spread is the lab VM's CPU, which moved the
string-to-key time before the lock from session to session on both KDCs: the sync in the lock stays at 13.2 to
14.2 ms on both, and with fsync off ours is flat to 0.1 ms. Each write is one flush and no rename, at most 411 bytes
written; at 10 principals two deletes in a session compact, with three flushes and one rename. With fsync off, a
random-key create is 0.3 ms. While kadmind changes passwords, a kinit is 0.99 to 1.00 times MIT, with no failure.
A burst after idle at 10 principals read 1.51 times MIT (1.01 on the tree before); no bar covers it. On an earlier 1.2
tree the accept stall after a write was 0.271, 0.265 and 0.319 ms. A run of 218 kills, 50 of them during a rewrite,
left no torn change, and MIT loaded all 220 dumps (`kill-loop`). Twenty forced power-offs during writes left the
update log consistent 19 times and stable but behind once, where MIT's baseline was 12 consistent, 4 behind and
4 reset, and none of the 38 acknowledged writes was missing on the primary or the replica. In 1.2.1 the kill loop
ran on Debian 13 and Rocky Linux 10 too, at `0f633715`: 228 and 220 kills, no unexpected result, and MIT's
`kdb5_util` matched and loaded all 230 and 222 dumps.

### Not yet matched in 1.2.1

- **Client messages and logs.** None changes an outcome.
  - The KDC's AS_REQ line for a wrong encrypted-challenge password ends `Preauthentication failed`, where MIT's ends
    `Incorrect password in encrypted challenge`.
  - The KDC answers a SPAKE support message from a client whose only key is des3 with PREAUTH_FAILED even when the
    key is good, and the client falls back to encrypted challenge or timestamp. MIT's answer with SPAKE configured
    is not settled.
  - MIT's tools end a `com_err` line with `\r\n` (`default_com_err_proc`, `com_err.c:91-92`), and ours with `\n`.
- **Caches.** Each has a row in [mit-deviations.md](mit-deviations.md): kpasswd and kadmin with a `DIR:` default cache,
  `krb5_cc_cache_match` with a `DIR::` default naming a file whose name does not begin with `tkt`, and listing a FILE
  cache entry whose principal or realm is not ASCII.
- **Not supported:** what [install.md](install.md) lists under "Not supported", and the client tools' remaining
  differences it lists.
- **Corrupt records.** MIT's `getprinc` refuses a principal whose `LAST_PWD_CHANGE`, `MOD_PRINC` or `MKVNO` data is
  corrupt (`Database record is incomplete or corrupted`); ours prints the entry. Only a damaged database reaches it.
- **Not run:**
  - Heimdal's KDC, cross-realm with it and its `kcm`;
  - Windows: a domain-joined logon, SSPI as a server, and Windows OpenSSH;
  - a server on Ubuntu (its layout is Debian's);
  - the GSS initiator's exact `+1` after a wrap. Its repeats and stale numbers are, against MIT, in the `replica` leg;
  - cells dropped by decision: one GSS clock-skew cell, a "+1 h" cell and a 330-second delay pair (behind a switch,
    off);
  - a global IPv6 on the KDC;
  - hand legs: a desktop-login case that needs SDDM driven directly, `-UseDefaultCredentials` toward the Windows DC
    (it needs a change to the AD), and a remote journal read that needs a sudo password;
  - in the release pass: RP-FILL.

## Supply-chain (not an interop oracle)

| Check | Drives | Asserts | CI |
| --- | --- | --- | --- |
| cargo-audit | `cargo audit --deny warnings` (cargo-audit 0.22.2) | known advisories fail red | audit |
| cargo-deny | `deny.toml` licenses/advisories/sources | allowlist only; crates.io sources | audit |
| `cargo vet --locked` | `supply-chain/` (Google / Mozilla / Bytecode Alliance) | every third-party crate imported, locally audited, or exempt; cargo-vet **0.10.0** | audit |

## Deviation ledger (MIT behaviours kept)

FILE `delete_cred` is a same-length tombstone (`endtime = 0`,
`authtime = -1`, config realm `X-CACHECONF:` → `X-RMED-CONF:`);
deletion is not guaranteed if marshal length would change. FILE
stores still append/rewrite via temp+rename (MIT opens `O_APPEND`
in place); no run has driven the Rust tools on a cache gssproxy writes,
so the in-place vs temp+rename decision stays **open**. Unknown ccache
prefixes are `KRB5_CC_UNKNOWN_TYPE` with no FILE fallback. `KCM:` is a
real type (sssd-kcm); `KEYRING:` stays unknown. Fleet default stays FILE
until NFS `sec=krb5i` cells run — [`kcm-nfs-verdict.md`](labs/kcm-nfs-verdict.md). FILE
principal and realm octets must be ASCII GeneralString; non-ASCII MIT
caches fail parse (no silent corruption). A DIR resolve makes a missing
directory (0700) and its `primary`, as MIT's does.

**Knobs honored by ignoring:** `kdc_timeout` and `max_retries` have no
MIT 1.22.2 parse site (Heimdal spellings; `sendto_kdc.c` `MAX_PASS 3`).
Rust stores the strings and does not change pacing. `udp_preference_limit`
(MIT default 1465), `rdns`, `kdc_timesync`, `permitted_enctypes` /
`default_tkt_enctypes` / `default_tgs_enctypes`, `forwardable`,
`ticket_lifetime`, `renew_lifetime`, `kdc_default_options`,
`dns_lookup_kdc` / `dns_lookup_realm` are parsed at MIT's sites.

**Renewable default, admin-overridable:** ticket renew time is the min of
the request (`-r`, else RENEWABLE-OK till), the **krbtgt** entry, the
**client** entry, and the kdc.conf realm cap. An omitted
`max_renewable_life` leaves the realm cap at 7 d (`KRB5_KDB_MAX_RLIFE`,
`kdc/main.c:312-319`) and gives new principals 0 (the kadm5 create
default, `alt_prof.c:573-578`); a written value sets both (ledger rows
`kdc/main.c:312-319` in [A2](parity/a2-as.md) and `alt_prof.c:573-574` in
[A4](parity/a4-kadmin.md)). `modprinc -maxrenewlife` writes `KADM5_MAX_RLIFE`.

## Not external oracles

These run in CI (or scheduled) but **do not** count as an external
implementation oracle. The Rust-only gates (Oracle `none`) are in
[gates.md](gates.md).

| Item | Why not an oracle | CI |
| --- | --- | --- |
| golden MIT DER + crypto KATs | in-repo fixtures, not a live peer | test |
| 9 cargo-fuzz targets | `nightly.yml` smoke, not an interop peer | fuzz |
| cargo-vet exemptions | RP-FILL exempt (134 at 1.2.0, 121 at 1.1, 114 at 1.0), RP-FILL fully audited; not a full local audit of every crate | documented |
| in-process metrics counters | deferred; logs-as-metrics only (`logging.md`) | n/a |

MSRV 1.95 `cargo build --workspace --all-targets --locked` is the `msrv`
job; `cargo test --workspace --locked` on 1.95 is `nightly.yml`'s
`msrv-test`. Edition 2024; `rasn` 0.28.14 vendored with MIT's decode rules, goldens
and the decode sweep are the DER net. `publish = false` stays;
this matrix is the 1.2.1 claim, not crates.io. KLLDAP alignment:
[`embed/klldap.md`](embed/klldap.md).
