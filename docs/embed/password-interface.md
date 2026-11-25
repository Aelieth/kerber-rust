# The password interface

Every password write between kerber-rust and a host store takes one of the two paths below. The
keys are always MIT's `string_to_key(enctype, password, salt)`, so stock `kinit`, `kpasswd` and
`kadmin` keep working. kerber-rust keeps no password verifier. The host's own record of the
password, such as an OPAQUE record, lives in the host's tables, next to the principal's row, and
is written in the same transaction. [host-contract.md](host-contract.md) has the types.

## The two shapes

| Shape | Doors | What happens |
|---|---|---|
| **P**: prepare, then commit | kadmin `ank` with a password and `cpw` (CREATE_PRINCIPAL, CHPASS_PRINCIPAL and their v3 forms), kpasswd, `change_password_shared`, `create_password_shared` | 1. Under a read guard: run the checks and plan. 2. With no lock held: derive the keys, then the host's `prepare(intent, peek)` returns a token. 3. Under the write lock: apply the plan if the record, its name, its policy and `kadmin/history` are as read; otherwise run the checks again and derive under the lock. Then `commit_change(HostChange { intent, rows, prepared, batch })`. |
| **C**: one committing change | `change_password_shared_committing_then`, `create_password_shared_committing_then` (and `change_committing`) | 1. Under a read guard: plan. 2. With no lock held: derive the keys. 3. Under the write lock: apply, or redo under the lock. The host's own `commit` closure runs once, inside the change. The intent is `Embedded`. There is no `prepare` and no token. |

Use P for a door the host doesn't run itself (kadmin, kpasswd). Use C for the host's own doors.

## Rules

- **The token (P).** It reaches the one commit that writes, including a rerun under the lock,
  together with that commit's rows. It is dropped only when no commit writes. A rerun means the
  record changed after `prepare` saw it. If your token depends on what `prepare` saw, check it
  against `rows[..].before`.
- **Slow work.** In P, do it in `prepare`. In C, do it before you call the helper: your closure
  runs under the store's lock, so keep it to writes. This is contract rule 2.
- **The key/salt list.** `intent.keysalts` is the list a kadmin client sent with `-e` on create,
  chpass or chrand, exactly as sent. It is empty everywhere else. To refuse it, answer `Denied`
  with `KADM5_BAD_KEYSALTS`; stock kadmin prints "Invalid key/salt tuples".
- **Refusals.** A `Denied { kadm5_code, text }` from `prepare` or the commit reaches the client
  as that code. A refusal from `prepare` takes no lock. A refused first commit uses the token, and
  nothing reruns.
- **Key read-outs and key writes on a marked principal** follow the contract's rule 3.

## Where this differs from MIT

This table is shared with KLLDAP, which links to it. The kerber-rust rows are also in
[mit-deviations.md](../mit-deviations.md).

| Point | MIT 1.22 | kerber-rust | Kind |
|---|---|---|---|
| Who derives the keys | kadmind, from the password | kerber-rust, from the password | parity |
| Deriving and the lock | derived with no lock held; a change made in between is overwritten | derived with no lock held; the write is taken only if nothing changed, else redone under the lock | stricter |
| A second record beside the keys | none | the host's own, in the host's tables, in the same transaction | host only |
| The host learns the password | `kadm5_hook` `chpass`, before and after the commit | `prepare` and the commit | MIT-shaped |
| A raced change's prepared work | MIT has no `prepare`; a raced `cpw` succeeds | the token reaches the rerun (P), so a raced `cpw` succeeds | parity since 1.2.4 |
| `-e` key/salt lists | honoured; `KADM5_BAD_KEYSALTS` only when the policy's `allowed_keysalts` lacks one | the host sees `keysalts` and may refuse | stricter, host only |
| `randkey`, `setkey`, `ktadd` on a marked principal | the ACL decides | the host's verdict | stricter |
| Key read-outs of a marked principal | only `LOCKDOWN_KEYS` refuses | refused whatever the host answers | stricter |
| `kadmin/history` and a refused change | put on its own first | joins the caller's change, so a refusal rolls it back | stricter |
| A stored row's integrity | the database only | a MAC under the master key, in host mode | positive |
| Master key, stash, key wrapping | stash file; keys wrapped | the same | parity |

The host's own choices aren't kerber-rust rows. KLLDAP's are clearing Kerberos policy on a
directory user, not serving kpasswd, and its password envelope; see KLLDAP's docs.
