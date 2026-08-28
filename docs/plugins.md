# Extension points (traits, not dlopen)

MIT Kerberos loads C `.so` plugins (`kdb5`, `kdcpreauth`, `kdcpolicy`,
pwqual). This workspace forbids C FFI in the product, so the same
capabilities are **Rust traits and process-local registries**. There
is no `dlopen`.

| Surface | MIT analogue | In tree |
| --- | --- | --- |
| KDB | `kdb5` plugin / `db_library` | [`PrincipalRead`](../crates/krb5-kdc/src/kdb.rs) / `PrincipalWrite` / `StoreLifecycle`. Dump-v7 is the **servable** backend. `db_library` selects the factory; unknown names error. `MemoryStore` is a second in-tree backend for tests, not a production KDC. Replay caches, PKINIT CA, and the AS-fail overlay live on `KdcEnv` / process state and survive dump reload, not a full KDC restart. |
| kdcpreauth | `kdcpreauth` | [`KdcPreauth`](../crates/krb5-kdc/src/plugins.rs) registry. PKINIT and SPAKE process AS. Enc-timestamp is registered so METHOD-DATA advertises it; `EncTsMod::process_as` is a no-op (timestamp verify stays inline). |
| kdcpolicy | `kdcpolicy` | [`KdcPolicy`](../crates/krb5-kdc/src/plugins.rs) is observe-only (`check_as` / `check_tgs` do not decide tickets). |
| pwqual | `pwqual` | Named [`NamedPolicy`](../crates/krb5-kdc/src/store.rs) min-length / classes at `set_password`. History rejects any currently retained key (boolean), not a depth-N ring. No time-based auto-unlock. kadm5 addpol/modpol/getpol/delpol/listpols. |

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
`CLIENT_REVOKED`); `scripts/iprop-gate.sh` (`kpropd -A` serial-delta
then MIT `kinit extra`; MIT kadmind → Rust slave then MIT
`kinit extra2`).
