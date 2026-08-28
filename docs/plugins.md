# Extension points (traits, not dlopen)

MIT Kerberos loads C `.so` plugins (`kdb5`, `kdcpreauth`, `kdcpolicy`,
pwqual). This workspace forbids C FFI in the product, so the same
capabilities are **Rust traits and process-local registries**. There
is no `dlopen`.

| Surface | MIT analogue | In tree |
| --- | --- | --- |
| KDB | `kdb5` plugin / `db_library` | [`PrincipalRead`](../crates/krb5-kdc/src/kdb.rs) / `PrincipalWrite` / `StoreLifecycle`. Dump-v7 is the default. `db_library=memory` serves [`MemoryStore`](../crates/krb5-kdc/src/kdb.rs) from a dump seed (`scripts/store-gate.sh`). Kadmind still mutates `PrincipalStore` only. Replay caches, PKINIT CA, and the AS-fail overlay live on `KdcEnv` / process state and survive dump reload, not a full KDC restart. |
| kdcpreauth | `kdcpreauth` | [`KdcPreauth`](../crates/krb5-kdc/src/plugins.rs) registry. PKINIT, SPAKE, and enc-timestamp process AS (`EncTsOk`; caller must not re-verify). |
| kdcpolicy | `kdcpolicy` | [`KdcPolicy`](../crates/krb5-kdc/src/plugins.rs) `check_as` / `check_tgs` return `Result` and can deny. AS lockout stays inline, not in the swappable slot. |
| pwqual | `pwqual` | Named [`NamedPolicy`](../crates/krb5-kdc/src/store.rs): five classes; history depth N; `pw_failcnt_interval` / `pw_lockout_duration`. kadm5 addpol/modpol/getpol/delpol/listpols. |

LDAP, db2, and LMDB are not required implementations. None is
privileged: each backend implements the same KDB traits.

Iprop is not a plugin. The store keeps a monotonic serial and a
circular update log. kadmind serves MIT program **100423**
(`IPROP_GET_UPDATES`, `IPROP_FULL_RESYNC`). First contact
(`last_sno == 0`) returns full-resync; a slave then takes an
`ipropx` dump (`kprop -i` / `kdb5_util dump -i1`). Serial-delta is
MIT `kdb_incr_update_t` over RPCSEC_GSS (`krb5-iprop-pull` or
`iprop_poll_once`). `kdb_last_t` must echo the dump-header
timestamp or MIT returns `UPDATE_FULL_RESYNC_NEEDED`.

Gates: `scripts/policy-gate.sh` (MIT `kadmin` policies + `kinit`
`CLIENT_REVOKED`, minclasses 5, lockout time, history-N);
`scripts/store-gate.sh` (MemoryStore serve); `scripts/iprop-gate.sh`
(`kpropd -A` serial-delta then MIT `kinit extra`; MIT kadmind → Rust
slave then MIT `kinit extra2`).
