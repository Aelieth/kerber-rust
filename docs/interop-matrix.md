# Interop matrix

The implementations this port is checked against and what is kept from
them. The gates that content-assert against each one, where they run and
what they assert are in [gates.md](gates.md) (its Oracle column).
Timing/replay: [`security.md`](security.md). Isolation: never edit host
`/etc/krb5.conf` (`TESTLABBY.LOCAL`).

- **MIT 1.22.2** is the primary oracle and the equality bar: live MIT
  clients, KDCs, kadmind, kpropd and libraries against the Rust side, in
  both directions where a direction exists.
- **Samba 4 AD** (`AD.KERBER.TEST`) checks the PAC, S4U and trusts, on
  the nightly `peers` workflow.
- **Heimdal 7.8** is a secondary oracle, both directions, also nightly.

## Field consumers

Production use is the proof. Each consumer below ran against a kerber-rust realm brought up by
[install.md](install.md), beside the same scenario against a stock Fedora MIT 1.22.2 realm in the same lab
(libvirt VMs on one host), MIT first. The scenarios in the last column repeat through `make field`
([harness/field](../harness/field/README.md)). The full pass of the 1.1 tree
(`working/logs/f-FULL-r2/README.md`, tree `5f0ee306`) had no product failure in any leg; the cut's source differs
from that tree by one test-only change, the version, the docs and the CHANGELOG.

| Consumer | What ran against both realms | Repeats as |
| --- | --- | --- |
| SSSD on Fedora (`krb5_child`; the satomlin kit) | password login into a FILE cache, renewal at an sssd restart, `passwd` through kpasswd, `-allow_tix` refused, the kit's own validation | `sssd-login` |
| NFS 4.2 to NFS-Ganesha through rpc.gssd | `sec=krb5i` and `krb5p` mounts by the machine credential, a user's writes and reads, root squashed, a ticketless user refused (the kit's gssproxy, in the path, served no credential under either KDC) | `services`, `nfs-client` |
| Keycloak (Java JGSS) SPNEGO | `401 Negotiate`, then `302` with `code=` and a mutual token | `services`, `nfs-client` |
| OpenSSH `gssapi-with-mic` | sshd GSSAPI from one client to another, short name and FQDN | by hand |
| Active Directory two-way trust (Windows Server) | an AD user into this realm over ssh, this realm's user to AD's SMB and LDAP acceptors, Windows as the SPNEGO client | by hand (the harness never touches the DC) |
| KLLDAP (`079a564`) with `krb5-server` swapped for kerber-rust | its own gate, all phases, with the same lines as on MIT; its live-KDC FFI lane on two MIT client libraries; phase 80 on a realm migrated by install.md's container steps | `klldap-swap`; the VM legs by hand |
| An in-place upgrade of kerber-rust | install.md's upgrade blocks as written: listeners, MIT's log lines, principals unchanged, MIT clients over UDP and TCP | `upgrade` |

### Not yet matched in 1.1

- **Write cost.** A kadm5 write takes 4.1 times MIT's median at 10 principals and 11.2 times at 5,000 (101 and 299 ms
  against 25 and 27 ms with fsync on): the store rereads and rewrites the whole realm. While kadmind writes, a
  kinit takes a median of 60, 156 and 473 ms at 10, 1,000 and 5,000 principals, where MIT's is 15 to 18 ms. Reads
  match. The store redesign is after 1.1 (`working/logs/f-P18/`).
- **The GSS initiator's sequence number.** The authenticator's sequence number and the per-message start are 0; MIT
  draws a random one. MIT accepts ours, and a cross-context replay still fails the MIC.
- **Client messages and logs.** None changes an outcome.
  - The KDC's AS_REQ line for a wrong encrypted-challenge password ends `Preauthentication failed`, where MIT's ends
    `Incorrect password in encrypted challenge`.
  - The KDC answers a SPAKE support message from a client whose only key is des3 with PREAUTH_FAILED even when the
    key is good, and the client falls back to encrypted challenge or timestamp. MIT's answer with SPAKE configured
    is not settled.
- **Not supported:** what [install.md](install.md) lists under "Not supported", and the client tools' remaining
  differences it lists.
- **Did not run in the 1.1 pass** (the pass's own list, `working/logs/f-FULL-r2/README.md`, "What did not run"):
  - cells dropped by decision: one GSS clock-skew cell, a "+1 h" cell and a 330-second delay pair (behind a switch,
    off);
  - a global IPv6 on the KDC;
  - hand legs: a desktop-login case that needs SDDM driven directly, `-UseDefaultCredentials` toward the Windows DC
    (it needs a change to the AD, and the `-Credential` leg did run), and a remote journal read that needs a
    sudo password;
  - the timing of a 50-connection burst after a write (its generator is lost).

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
in place); no run has driven the Rust tools on a cache gssproxy writes,
so the in-place vs temp+rename decision stays **open**. Unknown ccache
prefixes are `KRB5_CC_UNKNOWN_TYPE` with no FILE fallback. `KCM:` is a
real type (sssd-kcm); `KEYRING:` stays unknown. Fleet default stays FILE
until NFS `sec=krb5i` cells run — [`kcm-nfs-verdict.md`](labs/kcm-nfs-verdict.md). FILE
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
| 9 cargo-fuzz targets | `fuzz.yml` smoke, not an interop peer | fuzz |
| in-process `bounded_stress` | not the wire stress-gate | unit |
| cargo-vet exemptions | 121 crates exempt (114 at 1.0), 20 fully audited; not a full local audit of every crate | documented |
| in-process metrics counters | deferred; logs-as-metrics only (`logging.md`) | n/a |

MSRV 1.95 `cargo build --workspace --all-targets --locked` is the `msrv`
job; `cargo test --workspace --locked` on 1.95 is `full-test.yml`'s
`msrv-test` (nightly + tags). Edition 2024; `rasn` 0.28.14 vendored with MIT's decode rules, goldens
and the decode sweep are the DER net. `publish = false` stays;
this matrix is the 1.1 claim, not crates.io. KLLDAP alignment:
[`embed/klldap.md`](embed/klldap.md).
