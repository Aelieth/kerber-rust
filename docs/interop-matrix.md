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
implementation oracle. The Rust-only gates (Oracle `none`) and the SSPI stub
are in [gates.md](gates.md).

| Item | Why not an oracle | CI |
| --- | --- | --- |
| golden MIT DER + crypto KATs | in-repo fixtures, not a live peer | test |
| 9 cargo-fuzz targets | `fuzz.yml` smoke, not an interop peer | fuzz |
| in-process `bounded_stress` | not the wire stress-gate | unit |
| cargo-vet exemptions | shrinking list; not a full local audit of every crate | documented |
| in-process metrics counters | deferred; logs-as-metrics only (`logging.md`) | n/a |

MSRV 1.95 `cargo build --workspace --all-targets --locked` is the `msrv`
job; `cargo test --workspace --locked` on 1.95 is `full-test.yml`'s
`msrv-test` (nightly + tags). Edition 2024; `rasn` 0.28, goldens are the
DER net. `publish = false` stays;
this matrix is the 1.0 claim, not crates.io. KLLDAP alignment:
[`embed/klldap.md`](embed/klldap.md).
