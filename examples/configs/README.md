# Example configuration

A working single-realm setup, `EXAMPLE.COM`, for the Rust KDC, kadmind and
client tools. `scripts/kdc-gate.sh` runs these three files as written: it starts
`krb5-kdc` and `krb5-kadmind` on them, adds principals with MIT `kadmin`, and
gets tickets with MIT `kinit` and `kvno`.

| File | Read by | Install at |
| --- | --- | --- |
| `kdc.conf` | `krb5-kdc`, `krb5-kadmind`, `krb5-kdb`, `krb5-kadmin-local`, `krb5-kprop`, `krb5-kpropd`, `krb5-iprop-pull` | `KRB5_KDC_PROFILE` (or `KRB5_KDC_CONF`), else `/var/kerberos/krb5kdc/kdc.conf`; a missing file reads as empty, as MIT's does |
| `krb5.conf` | the Rust client tools; the KDC-side tools for `default_realm`, their realm unless one is named; MIT clients | `KRB5_CONFIG`, else `/etc/krb5.conf` |
| `kadm5.acl` | `krb5-kadmind` | the `acl_file` path in `kdc.conf` |

## Bringing the realm up

```bash
export KRB5_KDC_PROFILE=/etc/kerber-rust/kdc.conf
export KRB5_CONFIG=/etc/kerber-rust/krb5.conf   # default_realm EXAMPLE.COM: the daemons' realm
# krb5-kdb writes the EXAMPLE.COM stanza's database_name / key_stash_file:
KRB5_MASTER_PASSWORD=… KRB5_TEST_USER_PASSWORD=… KRB5_TEST_ADMIN_PASSWORD=… \
    krb5-kdb create EXAMPLE.COM      # the realm, plus user@ and admin@EXAMPLE.COM
krb5-kdc                             # UDP and TCP on every kdc_listen address
krb5-kadmind                         # kadm5 on 749 and kpasswd on 464, all local addresses
```

## Each key and its reader

`kdc.conf`, parsed by `crates/krb5-config/src/kdcconf.rs`
(`parse_kdcdefaults`, `parse_kdc_realm_line`):

| Key | Used by |
| --- | --- |
| `kdc_listen` | `crates/krb5-kdc/src/bin/krb5-kdc.rs` (`bind_sockets`), parsed by `crates/krb5-config/src/listen.rs`: as in MIT, the KDC binds UDP and TCP on every listed address, and a bare port (`kdc_ports = 88`, or KLLDAP's `750,88`) on every local address. The realm stanza's `kdc_listen` / `kdc_ports` win over `[kdcdefaults]`, and `kdc_tcp_listen` / `kdc_tcp_ports` give TCP its own list. This file keeps the KDC on `127.0.0.1`; drop the line to listen on port 88 everywhere. |
| `database_name`, `key_stash_file` | every KDC-side tool, through `KdcPaths` in `crates/krb5-config/src/kdcconf.rs`: the realm's own stanza (the realm is krb5.conf's `default_realm` unless the tool names one; with neither, the tool stops as MIT's does), else MIT's `/var/kerberos/krb5kdc/principal` and `/var/kerberos/krb5kdc/.k5.<REALM>`; `KRB5_KDC_DB` / `KRB5_KDC_STASH` override them |
| `acl_file` | `krb5-kadmind.rs` (`load_acl`) through `KdcPaths`, when `KRB5_ACL_FILE` is unset; unset in both, `/var/kerberos/krb5kdc/kadm5.acl` (beside the stash when `KRB5_KDC_STASH` moves it); a missing file refuses to start |
| `master_key_type` | `crates/krb5-kdc/src/mkey.rs` (`master_etype`) through `KdcPaths`, for `krb5-kdb` and every new stash (`crates/krb5-kdc/src/persist.rs`); `KRB5_MASTER_ETYPE` overrides it, and a name that is no enctype refuses. Unset, this port uses aes256-cts-hmac-sha384-192 where MIT uses aes256-cts-hmac-sha1-96, so the example sets MIT's |
| `supported_enctypes`, `max_life`, `max_renewable_life` | `crates/krb5-kdc/src/store/policy.rs` (`Policy::apply_kdc_conf`): the key types and salts new principals get, and the realm ticket caps |
| `default_principal_flags` | `crates/krb5-kdc/src/store/policy.rs` (`Policy::apply_kdc_conf`, parsed by `default_principal_flags` in `crates/krb5-kdc/src/acl.rs`): the attributes a kadm5 create without an attribute mask gets |

`krb5.conf`, parsed by `crates/krb5-config/src/profile.rs`: every
`[libdefaults]` key here (`parse_libdefaults`), the realm's `kdc`
(`parse_realm_line`, then `discover_kdc`), and `[domain_realm]`
(`host_to_realm`). Three keys are parsed but no Rust tool uses them yet; they
stay for MIT clients: `dns_lookup_realm` and `rdns` (MIT `krb5_get_host_realm`,
`krb5_sname_to_principal`), and `admin_server` (there is no remote `kadmin`
client; MIT `kadmin` uses it).

`kadm5.acl` lines are `<principal> <operations> [<target> [<restrictions>]]`,
read by `crates/krb5-kdc/src/acl.rs` as MIT's `auth_acl.c` reads them; `*` and
`x` grant every operation except extract (`e`).

## Set through the environment

- `KRB5_KDC_DB`, `KRB5_KDC_STASH`: override `database_name` / `key_stash_file`
  for every KDC-side tool.
- `KRB5_MASTER_PASSWORD`: `krb5-kdb` refuses to run `create`, `load`, `dump`
  or `addpol` without it; `load` and `dump` derive the master key from it.
- `KRB5_MASTER_ETYPE`: overrides `master_key_type`.
- `KRB5_ACL_FILE`: overrides `acl_file`.
- `KRB5_KPROP_ACL`: `krb5-kpropd`'s allowlist (`kpropd.acl` form); unset or empty
  refuses every propagation (`crates/krb5-admin/src/bin/krb5-kpropd.rs`).
- `KRB5_KDC_BIND`: the one address the KDC binds, instead of `kdc_listen`.
- `KRB5_KPASSWD_BIND`: the one address `krb5-kadmind` serves kpasswd on, instead
  of `kpasswd_listen` / `kpasswd_port`.
- `KRB5_KDC_USER`: the user the KDC drops to after binding as root (default
  `nobody`, `crates/krb5-kdc/src/listen.rs`). A KDC that serves a database
  file, as with this `kdc.conf`, keeps its user so it can re-read what
  `krb5-kadmind` writes. MIT's `krb5kdc` and `kadmind` never change user
  either; to run without root, start both daemons as one unprivileged user
  that owns the database directory, with `CAP_NET_BIND_SERVICE` for ports
  88, 464 and 749.

## What MIT reads that this port ignores

- `/path` entries in a listen list: MIT binds a UNIX-domain socket there; this
  port binds none.
- `kdc_tcp_listen_backlog`: the TCP listen queue is the Rust runtime's default.
- `[logging]`: no reader; `docs/logging.md` says what the daemons log.
- `iprop_enable` and `iprop_port`: iprop (program 100423) always answers on the
  kadmind port; there is no separate listener.
- `kdc_timeout` and `max_retries` in `krb5.conf`: parsed, but they do not change
  the client's pacing.
