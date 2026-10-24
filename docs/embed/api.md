# Embed API

## Bootstrap

`bootstrap_realm_into` fills a store the caller owns. It creates only the
K/M, krbtgt, `kadmin/admin`, `kadmin/changepw`, and optional admin rows that
are missing, and it does not rotate a key that is already there. An existing
realm stamps each new row with the active K/M kvno (`TL_ACTKVNO`, else the
newest key). A new realm uses `RealmSpec.mkvno`; `kdb5_util create` uses 1,
and so does `embed-realm`. `Bootstrapped.kvno` is that kvno. The admin
requires pre-auth unless `AdminSpec` says otherwise. The keytab comes back
on `Bootstrapped` for the caller to write.

`create_database` writes the stash (a temp file renamed into place, mode 0600),
then both lock files, then the database by renaming a finished temp file into
place. That rename is the commit. A re-run that finds the stash and no database
reuses that master and kvno. A database with no lock file is refused, as an
open is.

`examples/embed-realm --bootstrap-only` does that open-or-create and writes
`admin.keytab` beside the database. A store takes the realm's lifetimes, flags,
and enctypes only after `apply_profile`, and `embed-realm` applies it before
`--create-trust` and `--allow-to-delegate`.
