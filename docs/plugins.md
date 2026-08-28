# Extension points (traits, not dlopen)

MIT Kerberos loads C `.so` plugins (`kdb5`, `kdcpreauth`, `kdcpolicy`,
pwqual). This workspace forbids C FFI in the product, so the same
capabilities are **Rust traits and process-local registries**. There
is no `dlopen`.

| Surface | MIT analogue | In tree |
| --- | --- | --- |
| KDB | `kdb5` plugin / `db_library` | [`PrincipalRead`](../crates/krb5-kdc/src/kdb.rs) / `PrincipalWrite` / `StoreLifecycle`. Dump-v7 is the default backend. `db_library` selects the factory; unknown names error. `MemoryStore` is a second in-tree backend. Replay caches and the PKINIT CA live on `KdcEnv`, not dump rows. |
| kdcpreauth | `kdcpreauth` | [`KdcPreauth`](../crates/krb5-kdc/src/plugins.rs) registry. PKINIT, SPAKE, and enc-timestamp are registered built-ins. `preauth_required` enumerates the registry. |
| kdcpolicy | `kdcpolicy` | [`KdcPolicy`](../crates/krb5-kdc/src/plugins.rs). AS/TGS checks run through `current_policy()`. |
| pwqual | `pwqual` | Named [`NamedPolicy`](../crates/krb5-kdc/src/store.rs) min-length / classes / history at `set_password`. kadm5 addpol/modpol/getpol/delpol/listpols. |

LDAP, db2, and LMDB are not required implementations. None is
privileged: each backend implements the same KDB traits.

Iprop is not a plugin. The store keeps a monotonic serial and a
circular update log. kadmind serves MIT program **100423**
(`IPROP_GET_UPDATES`, `IPROP_FULL_RESYNC`). First contact
(`last_sno == 0`) returns full-resync; a slave then takes dump-v7
kprop. Serial-delta apply is in-process (`iprop_poll_once`).

Gates: `scripts/policy-gate.sh` (MIT `kadmin` policies + `kinit`
`CLIENT_REVOKED`); `scripts/iprop-gate.sh` (`kpropd -A` probe +
kprop both ways then MIT `kinit`).
