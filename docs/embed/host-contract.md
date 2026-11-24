# Host contract

What an embedder that keeps the realm in its own database (a host store) must do, and
what kerber-rust does for it. As of v1.2.3. The contract covers only principals the host
owns (carrying the mark). Every other principal behaves as MIT's. Stricter-than-MIT rows
are in [mit-deviations.md](../mit-deviations.md). The rest of the embed surface is in
[api.md](api.md).

## 1. Ownership: the mark

- A TL-data type below 256, `TL_KERBER_HOST_OWNED` = 0x004B, in the principal's own record.
- Set and cleared only by `PrincipalStore::set_host_owned_in(name, realm, owned)`, inside any
  change on a host store. In your `change_committing` it reaches your closure as `Embedded`;
  in any other change it reaches `commit_change` as `Unspecified`, which rule 1 refuses on your
  rows. kadmind refuses TL types below 256 on create
  and modify, and `getprinc` returns only types above 255, so kadmin can neither set nor read it.
- Read with `Principal::host_owned()`. It rides the sealed record and dump/load.
- An alias is its own keyless record. Reads and writes resolve to the target, so the mark is
  read on the target.
- A name with no record yet (create, a rename destination, an alias, a case twin) reaches you
  as rows in the commit, with the names as requested. Decide there.

## 2. Writes

### 2.1 Your trait

```rust
pub trait KerberosStore: Send + Sync {
    fn load(&self) -> Result<LoadedRealm, KerberosStoreError>;
    fn commit_change(&self, change: HostChange) -> Result<(), KerberosStoreError>;
    fn prepare(&self, intent: &WriteIntent, target: Option<&TargetPeek>)
        -> Result<Option<HostPrepared>, KerberosStoreError> { Ok(None) }
}
```

- `commit_change` replaces the 1.2.2 `commit(RealmBatch)`. It gets every change you did not
  start, and the realm bootstrap.
- A first commit whose outcome you can't tell may answer `Failed`: kerber-rust keeps the stash
  and reads your rows at the next start to see whether it landed.
- Your own changes go through `PrincipalStore::change_committing(closure, f)`. The closure
  gets the same `HostChange`, with operation `Embedded`, and is always called. kerber-rust
  builds `Embedded` only there, so it never sends one to `commit_change`; only a `change_as`
  of your own with `Embedded` could.
- `change_password_shared_committing_then` and `create_password_shared_committing_then` run your
  `edit` once in that change, after the keys or the create. What `edit` writes wins: to keep the
  policy's `pw_expire`, read it inside `edit` and pass it to `set_status`. Your `checks` run again
  under the lock, the create's right before the create, so a rule of yours holds there.
- `change_as(intent, prepared, f)` is how a caller declares a write; kadmind and kpasswd use it.
- kadmind, kpasswd and the `*_shared` helpers call `prepare` before each write, outside every
  lock. A `change_as` of your own does not.
- `TargetPeek { id, host_owned }` is `Some` when the target record exists (`id` is canonical,
  resolved through an alias) and `None` when it does not. `intent.requested` then has the name as
  sent, so answer from your directory, case-insensitively.

| Operation | `TargetPeek` | The other name, in `intent.requested` |
|---|---|---|
| Create | normally `None`; `Some` for an existing name on a randkey or keyless create, or after a stale read; DUP still comes under the lock, so answer `Ok(None)` | the new name as sent |
| Rename | `Some` for the source | the destination |
| CreateAlias | `Some` for the alias target (`None` if missing, as MIT allows) | the alias name |
| Any other | `Some` for the resolved target, or `None` | the name as sent |

`prepare` is a fast path, not the authority. The mark or the row may change before the
commit; `rows[..].host_owned` in the commit is the authority.

### 2.2 What `commit_change` receives (`HostChange`)

- `intent: WriteIntent`:
  - `operation`: Create, Delete, Rename, Modify, ChangePassword, Randkey, SetKey, PurgeKeys,
    SetString, CreateAlias, CreatePolicy, ModifyPolicy, DeletePolicy, Bootstrap, Embedded or
    Unspecified.
  - `caller`: `Kadmind { client, initial, changepw_service, self_service }`,
    `Kpasswd { client, initial, self_service }`, `Local { principal }` (kadmin.local `-p`,
    kdb5_util) or `Embedder`.
  - `requested`: the names as sent, with the realm; a rename or alias gives two.
  - A name sent without a realm takes the profile's `[libdefaults] default_realm`, as MIT, else
    the served realm. A host that builds its profile in memory sets `default_realm` itself, or a
    bare name resolves to the process krb5.conf's realm.
  - `client_mask`: kadmind's request mask, after ACL restrictions.
  - `keepold`, and `password` (a `Zeroizing` copy) for create-with-password, chpass and
    kpasswd.
- `rows: Vec<RowChange>`, one per touched row, built from the change's own undo journal:
  - `id` is canonical, with the realm. A rename gives the old id deleted and the new id created.
  - `before`, `after`: `Option<Principal>`.
  - `mask`: the kadm5 bits whose values differ (KVNO, KEY_DATA, TL_DATA, POLICY and so on).
  - `host_owned`: the mark on before or after.
- `prepared`: what your `prepare` returned for this write.
- `batch`: the sealed `RealmBatch` rows, as in 1.2.2.

Rules for the rows:

- `mask` leaves out FAIL_AUTH_COUNT, LAST_SUCCESS and LAST_FAILED. The map's copy can lag the
  lockout file. An unlock arrives as Modify with FAIL_AUTH_COUNT in `intent.client_mask`; MIT's
  kadmin client also sets TL_DATA, with one TL_LAST_ADMIN_UNLOCK (0x0700) entry, the unlock time.
  A key change zeroes the count by definition. For marked rows the counter is yours.
- A declared change that touched no row does not reach `commit_change`, whatever its intent.
  The exception is your own `change_committing`, whose closure is always called (as `Embedded`).
  A touched row is present even when its mask is 0 (a same-second restamp).
- A write that declares no intent (a raw `put_principal` or a wrapper) arrives as `Unspecified`,
  with its rows. Refuse it on any row you own.
- Bootstrap arrives once per realm, at first start, with every row. Accept it, or the realm
  never opens.
- The `TL_MOD_PRINC` stamp stays MIT's: a kpasswd change is stamped `kadmind@REALM`. The real
  client is in `caller`.

### 2.3 Your answers, and what the client sees

| You return | The store does | kadmin client gets | kpasswd client gets |
|---|---|---|---|
| `Ok(())` | keeps the change; kadm5 postcommit hooks run | 0 | SUCCESS |
| `Denied(Denial { kadm5_code, text })` | restores the image, no reload | your `kadm5_code` (the client prints its own text for it: kadm5 replies carry none) | MIT's result switch, with your `text` as the result string |
| `Refused(why)` | restores, no reload | KRB5_KDB_CONSTRAINT_VIOLATION | HARDERROR (2) |
| `Failed` / `NotReady` | restores, then reloads (calls `load`) | KRB5_KDB_ACCESS_ERROR / KRB5_KDB_DBNOTINITED | HARDERROR (2) |
| a panic | caught: restores, marks a reload due, treated as `Failed` | KRB5_KDB_ACCESS_ERROR | HARDERROR (2) |

kpasswd's switch on a `Denied` code (`kpasswd_result`): AUTH_CHANGEPW gives 5, AUTH_INITIAL
gives 7, PASS_Q_* / PASS_REUSE / PASS_TOOSOON give 4, anything else gives 2.

Codes a host should use: KADM5_AUTH_ADD, AUTH_DELETE, AUTH_MODIFY, AUTH_CHANGEPW, AUTH_SETKEY,
AUTH_INSUFFICIENT, PROTECT_PRINCIPAL; PASS_Q_TOOSHORT or PASS_Q_GENERIC for a quality refusal.
Never UNK_PRINC. A `Denied` from `prepare` carries the same codes; no lock was taken.

### 2.4 Rules

1. Refuse `Unspecified` on rows you own; accept `Bootstrap` (above).
2. Inside `commit_change` and the closure: open your transaction there, never before calling the
   store; write your rows and the batch on that one connection; commit or roll back before you
   return; never call a store method (the lock is not reentrant); never wait on anything that
   waits for the store lock; keep slow work in `prepare`.
3. Key read-outs of a marked principal are refused by the KDC whatever you answer. The mark
   implies lockdown for read-outs only: EXTRACT_KEYS answers KADM5_AUTH_EXTRACT, CHRAND
   withholds the new keys, and `export_keytab` refuses. Writes stay your verdict.
4. Bulk ingest is refused on a host store: iprop replay (`apply_updates`) and the `load -update`
   merge (`update_store`), and the iprop service answers PERM_DENIED. The empty-store import
   path still works: `parse_dump`, `load_dump_with_stash_path`, `load_dump_with_key` or
   `load_dump_with_stash`, then commit
   `host_full_change()` to an empty host.
5. `kadmin/history`: in host mode a change you refuse also rolls back the history principal it
   created. MIT commits it at once (`lib/kadm5/srv/server_kdb.c:141-164`), so this is a deviation.

### 2.5 Threads and locks

| Callback | Thread | Lock held | Note |
|---|---|---|---|
| `prepare` | the entry's thread: kadmind's serve loop (RPC and kpasswd), or the caller's thread for embed helpers | none | Slow work (a password hash) delays every kadmin and kpasswd request on that loop. |
| `commit_change`, closure | the same thread | the store's write lock | No KDC request and no other change moves until you return. |
| `load` | the same thread, at open or when a reload is due | the write lock inside a change | Read only. |

## 3. Logins: `HostAdmission`

```rust
pub trait HostAdmission: Send + Sync {
    fn check_as(&self, q: &AsQuestion<'_>) -> Result<(), KdcRefusal>;
    fn as_notice(&self, n: AsNotice);
    fn check_tgs(&self, q: &TgsQuestion<'_>) -> Result<(), KdcRefusal>;
}
pub struct KdcRefusal { pub code: i32, pub e_text: Option<String> } // 18 CLIENT_REVOKED
```

Register with `store.policy.plugins.set_host_admission(Arc<dyn HostAdmission>)` (the
`PluginSet`, per store, kept across reloads). It applies only to marked principals. **A marked
principal with no module installed is refused with KDC error 18** and e-text `LOCKED_OUT` (as
MIT's lockout refusal), and the KDC logs it once per process. There is no fallback to MIT's
lockout. Install the module before any listener starts.

### 3.1 `check_as`: the verdict, before preauthentication

- Asked where MIT asks `check_policy_as` (`validate_as_request`), on every round trip including
  the first, before any padata is read. A refusal says nothing about the password.
- It replaces the KDC's own lockout check and count for that principal.
- MIT's entry checks still run first: expiry, password expiry, REQUIRES_PWCHANGE,
  DISALLOW_ALL_TIX.
- `AsQuestion`: `client` (the resolved record), `requested`, `server`, `peer`, `now`, `request`,
  `s4u2self`.
- S4U2Self: the impersonated local user gets MIT's entry checks, then `check_as` with
  `s4u2self: true`, before `check_tgs` is asked. A user refused there never reaches `check_tgs`.
  These are not logins: a host that counts login attempts should skip them.

### 3.2 `as_notice`: one notice per AS outcome for a marked client

- `AsNotice`: `client` (canonical), `requested`, `peer`, `time`, `code` (sent, or 0), `reason`,
  `mechanism`.
- `AsReason`: `Issued`; `PreauthFailed` (wrong secret, OTP reject); `PreauthNotCompleted` (skew,
  OTP timeout or no verifier); `PolicyRefused` (preauth passed or was not required, then
  refused); `EntryRefused` (MIT's entry checks); `HostRefused` (your `check_as`).
- `Mechanism`: `EncTimestamp`, `EncChallenge`, `Spake`, `Pkinit`, `Otp`.
- No notice for: a preauth-required (25) or more-data (91) round trip; an unknown client (MIT
  reports none either); a FAST unwrap failure; a parked OTP (the resumed request reports once);
  a lookaside resend; a discarded request; an S4U2Self (not an AS exchange).
- Delivered after the request's read guard is released, on the KDC serving thread (one thread
  per serve loop), with no lock held. A slow notice delays the next request on that loop. Write
  inline if the next `check_as` must see the count; queue the write if throughput matters.

### 3.3 `check_tgs`: stricter than MIT

- Asked for every TGS-REQ (normal, renew, validate, U2U, S4U2Self, S4U2Proxy; `TgsKind`) whose
  local subject carries the mark. The subject is the evidence ticket's client for S4U2Proxy, the
  S4U2Self user, and otherwise the header ticket's client.
- Also asked when the subject's local entry is missing, with `client: None`, so a deleted user
  stops renewing. Cross-realm clients are never asked.
- `TgsQuestion`: `client: Option<&Principal>`, `subject`, `server`, `ticket`, `request`, `peer`,
  `now`, `kind`.
- A refusal of 18 shows as "Clients credentials have been revoked" on `kinit -R`. MIT's TGS
  never checks the client (`do_tgs_req.c:771-779`). There is no TGS notice (MIT has no TGS audit).

### 3.4 Threads and locks

| Callback | Thread | Lock held | You may | You must not |
|---|---|---|---|---|
| `check_as`, `check_tgs` | KDC serving thread | the store's read guard | answer from memory or a bounded read; refuse | write to the store (deadlock); block |
| `as_notice` | the same thread | none | a bounded write to your own table | unbounded work |
