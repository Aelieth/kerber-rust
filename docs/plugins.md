# Extension points (traits, not dlopen)

MIT Kerberos loads C `.so` plugins (`kdb5`, `kdcpreauth`, `kdcpolicy`,
pwqual). This workspace forbids C FFI in the product, so the same
capabilities are **Rust traits and process-local registries**. There
is no `dlopen`.

| Surface | MIT analogue | In tree |
| --- | --- | --- |
| KDB | `kdb5` plugin / `db_library` | [`PrincipalRead`](../crates/krb5-kdc/src/kdb.rs) / `PrincipalWrite` / `StoreLifecycle`. Dump-v7 is the default. `db_library=memory` serves [`MemoryStore`](../crates/krb5-kdc/src/kdb.rs) from a dump seed (`scripts/store-gate.sh`). Kadmind still mutates `PrincipalStore` only. Replay caches, PKINIT CA, and the AS-fail overlay live on `KdcEnv` / process state and survive dump reload, not a full KDC restart. |
| kdcpreauth | `kdcpreauth` | [`KdcPreauth`](../crates/krb5-kdc/src/plugins.rs) registry. PKINIT, SPAKE, and enc-timestamp process AS (`EncTsOk`; caller must not re-verify). First `process_as` that returns an action wins; EXTRA is not consulted after EncTsOk on a normal login. Observe-every-AS is a future kadm5_hook. |
| kdcpolicy | `kdcpolicy` | [`KdcPolicy`](../crates/krb5-kdc/src/plugins.rs) `check_as` / `check_tgs` return `Result` and can deny. [`set_policy`](../crates/krb5-kdc/src/plugins.rs) is process-wide (KDC serve/worker threads see it); tests isolate with `set_thread_policy`. AS lockout stays inline, not in the swappable slot. |
| pwqual | `pwqual` | Named [`NamedPolicy`](../crates/krb5-kdc/src/store.rs): five classes; history depth N (current password counts inside N; store N-1 old kvnos); `pw_failcnt_interval` / `pw_lockout_duration`. kadm5 addpol/modpol/getpol/delpol/listpols. |

Preauth modules run in registry order (built-ins, then EXTRA). The
first `process_as` that returns `Some(PreauthAction)` issues or
challenges; later modules on that AS are skipped. Enc-timestamp
success is `EncTsOk`, so an EXTRA demo module is reached on
PREAUTH_REQUIRED (no action yet) and skipped on a normal password
login. Counting every AS (kadm5_hook) is not this cascade.

LDAP, db2, and LMDB are not required implementations. None is
privileged: each backend implements the same KDB traits.

Iprop is not a plugin. The store keeps a monotonic serial and a
circular update log. kadmind serves MIT program **100423**
(`IPROP_GET_UPDATES`, `IPROP_FULL_RESYNC`). First contact
(`last_sno == 0`) returns full-resync; a slave then takes an
`ipropx` dump (`kprop -i` / `kdb5_util dump -i1`). Serial-delta is
MIT `kdb_incr_update_t` over RPCSEC_GSS (`krb5-iprop-pull` or
`iprop_poll_once`). `kdb_last_t` must echo the dump-header
timestamp or MIT returns `UPDATE_FULL_RESYNC_NEEDED`. Incremental
kdbe decode leaves `key_history` empty (private `TL_KERBER_HIST`
`0x4B04` over MIT kdbe is interop-sensitive). History depth
propagates via full-resync dump, not serial-delta iprop.

Gates: `scripts/policy-gate.sh` (MIT `kadmin` policies + `kinit`
`CLIENT_REVOKED`, minclasses 5, lockout time, history-N);
`scripts/store-gate.sh` (MemoryStore serve); `scripts/iprop-gate.sh`
(`kpropd -A` serial-delta then MIT `kinit extra`; MIT kadmind → Rust
slave then MIT `kinit extra2`).
