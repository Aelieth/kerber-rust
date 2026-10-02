# Installing kerber-rust

kerber-rust installs and runs the way Fedora's MIT `krb5-server` package does: the same
command names (`krb5kdc`, `kadmind`, `kadmin.local`, `kdb5_util`, `kprop`, `kpropd`), the same
systemd units, sysconfig, tmpfiles.d and logrotate files, and the same `/var/kerberos/krb5kdc`
directory. This page takes a Fedora 43 host with SELinux enforcing from nothing to a realm that
clients use with MIT's own tools. Run each command as written, as an ordinary user with `sudo`.
The realm's names are set once, at the start of [A realm](#a-realm).

## What `make install` installs

| Path (with `PREFIX=/usr`) | Mode | What |
| --- | --- | --- |
| `/usr/sbin/krb5kdc`, `kadmind`, `kadmin.local`, `kdb5_util`, `kprop`, `kpropd` | 0755 | The KDC-side programs under MIT's names, as real files, so a daemon's `/proc/<pid>/comm` is `krb5kdc` or `kadmind` |
| `/usr/lib/systemd/system/krb5kdc.service`, `kadmin.service` | 0644 | Fedora's units, with `ExecStart` naming the installed programs |
| `/usr/lib/tmpfiles.d/krb5-krb5kdc.conf` | 0644 | `/run/krb5kdc`, made at boot |
| `/usr/share/kerber-rust/install-manifest` | 0644 | The files above and the `make install-clients` tools, each with its SHA-256: what `make uninstall` may remove |
| `/etc/sysconfig/krb5kdc`, `kadmin` | 0644 | `KRB5KDC_ARGS=`, `KADMIND_ARGS=` (config) |
| `/etc/logrotate.d/krb5kdc`, `kadmind` | 0644 | `/var/log/krb5kdc.log` and `/var/log/kadmind.log`: rotated monthly, twelve kept, then `systemctl reload` (config) |
| `/var/kerberos/krb5kdc/` | 0755 | The KDC directory, made only when it is missing |
| `/var/kerberos/krb5kdc/kdc.conf`, `kadm5.acl` | 0600 | Fedora's shipped files, for the realm `EXAMPLE.COM` (config) |

The files come from `dist/` in the source tree; the units and `kdc.conf` are Fedora's with the
paths filled in. Fedora's third unit, `kprop.service`, is not installed (see
[Not supported](#not-supported)). The rules are the package's:

- A config file is installed only when nothing is at its path, as dnf's `noreplace` does. An
  edited file survives every reinstall, and `make uninstall` never removes one.
- A path that belongs to an installed package (`rpm -qf`) is never replaced: `make install`
  stops before it writes anything and names the package.
- Every other file it writes, it lists with its SHA-256 in a manifest,
  `$(PREFIX)/share/kerber-rust/install-manifest`, renamed into place whole. `make uninstall`
  removes only the manifest's files that are still as install wrote them.
- `make install` never writes `/etc/krb5.conf` (krb5-libs owns it), the database or the stash,
  and never installs the test tools (`krb5-tools`, the `krb5-gss` programs, `krb5-iprop-pull`).
- On the live system it then does what the package's scriptlets do: `systemd-tmpfiles --create`,
  `restorecon` on each file it wrote when SELinux is enabled, and `systemctl daemon-reload`. It
  does not restart a running daemon; it says when one still runs the old programs. With
  `DESTDIR` set to a staging tree it does none of these and checks no package; a `DESTDIR` that
  resolves to `/` is the live system.

`make install-clients` installs the client tools `kinit`, `klist`, `kdestroy`, `kswitch`,
`kvno`, `kpasswd` and `ktutil` into `BINDIR`, for hosts without MIT's `krb5-workstation`. It is
never part of `make install`; on Fedora keep the package's tools.

## Prerequisites

```sh
sudo dnf install -y git gcc make lld rustup krb5-workstation logrotate words
rustup-init -y --default-toolchain none --profile minimal
. "$HOME/.cargo/env"
```

`lld` is the linker the build uses (`.cargo/config.toml`), and `gcc` drives it. The Rust release
is the one `rust-toolchain.toml` pins; rustup installs it in the next step. `krb5-workstation` is
MIT's client side (`kinit`, `kadmin`, the `libkadm5clnt` library). The checks below use it, and
it stays installed. `logrotate` rotates the daemons' logs and `words` is `kdc.conf`'s
`dict_file`: Fedora's krb5-server requires both, and a fresh Fedora has neither.

## Build

```sh
git clone https://github.com/Aelieth/kerber-rust.git
cd kerber-rust
rustup toolchain install
make build
```

`make build` is `cargo build --release --locked` of the KDC, admin and client crates with no
cargo features, so none of the test hooks the gates use is compiled in: the programs read no
password, and no database or stash path, from the environment. Run it as yourself.
`sudo make install` installs that build and never compiles (sudo would not find your toolchain),
and no install goal compiles as root: it stops if the build is missing or the sources are newer.
Build on the distribution you install on: the programs link against its C library.

## Install

Replace krb5-server (the usual case), or install beside it.

### Replacing krb5-server

```sh
sudo dnf remove -y --no-autoremove krb5-server
sudo make install PREFIX=/usr
```

When krb5-server is not installed, dnf says so and nothing changes. `--no-autoremove` keeps the
packages krb5-server pulled in; `krb5-workstation` and `krb5-libs` stay, and with them `kadmin`
and `libkadm5clnt`. If this host already runs an MIT realm, follow
[Upgrading an MIT realm](#upgrading-an-mit-realm) instead.

### Beside krb5-server

```sh
sudo make install PREFIX=/usr/local
```

- systemd reads `/usr/local/lib/systemd/system` before `/usr/lib/systemd/system`, so
  `krb5kdc.service` and `kadmin.service` start kerber-rust's programs from now on
  (`systemctl cat krb5kdc` names the unit file in use), until `make uninstall PREFIX=/usr/local`.
- `/usr/local/sbin` comes before `/usr/sbin` in root's `PATH` and in sudo's `secure_path`, so
  `sudo kdb5_util` and `sudo kadmin.local` run kerber-rust's too. MIT's stay in `/usr/sbin`.
- Both read the same `/etc/sysconfig` files, `kdc.conf` and `kadm5.acl`, and listen on the same
  ports, so one KDC runs at a time. Both also call the database `/var/kerberos/krb5kdc/principal`,
  in different formats (MIT's db2 file, kerber-rust's dump file): move a realm from one to the
  other with dump and load, as in [Upgrading an MIT realm](#upgrading-an-mit-realm).
- Under SELinux, programs in `/usr/local` are labelled `bin_t`, so the daemons run unconfined
  (`unconfined_service_t`), not in MIT's `krb5kdc_t` and `kadmind_t`.

### SELinux

`make install` labels what it wrote. With `PREFIX=/usr` the daemons get MIT's types:

```sh
ls -Z /usr/sbin/krb5kdc /usr/sbin/kadmind
```

The types are `krb5kdc_exec_t` and `kadmind_exec_t`, so systemd starts the daemons in
`krb5kdc_t` and `kadmind_t`, Fedora's policy for MIT's daemons. The KDC only reads the database
(it keeps lockout counts in memory); kadmind replaces the database file inside the directory,
which that policy allows `kadmind_t`.

### Firewall

Fedora Server and Workstation run firewalld; Fedora Cloud images do not.

```sh
if systemctl is-active --quiet firewalld; then
    sudo firewall-cmd --permanent --add-service=kerberos --add-service=kpasswd --add-service=kadmin
    sudo firewall-cmd --reload
fi
```

firewalld's services are `kerberos` (88 UDP and TCP), `kpasswd` (464 UDP and TCP) and `kadmin`
(749 TCP).

## A realm

Set the realm's names for this shell. The rest of this section uses them as written.

```sh
REALM=EXAMPLE.COM          # the realm, in capitals
DOMAIN=example.com         # the DNS domain of its hosts
KDC_HOST=kdc.example.com   # this host's DNS name, as clients reach it
```

### krb5.conf

`/etc/krb5.conf` belongs to krb5-libs, and Fedora's starts with `includedir /etc/krb5.conf.d/`.
Add the realm there. Every client host gets the same file.

```sh
sudo tee /etc/krb5.conf.d/realm.conf >/dev/null <<EOF
[libdefaults]
    default_realm = $REALM

[realms]
    $REALM = {
        kdc = $KDC_HOST
        admin_server = $KDC_HOST
    }

[domain_realm]
    .$DOMAIN = $REALM
    $DOMAIN = $REALM
EOF
```

Fedora's `[logging]` stays in `/etc/krb5.conf`. It sends the daemons' logs to
`/var/log/krb5kdc.log` and `/var/log/kadmind.log`.

### kdc.conf and kadm5.acl

```sh
sudo sed -i "s/EXAMPLE\.COM/$REALM/" /var/kerberos/krb5kdc/kdc.conf /var/kerberos/krb5kdc/kadm5.acl
sudo sed -i '/default_principal_flags = +preauth/a max_renewable_life = 7d' /var/kerberos/krb5kdc/kdc.conf
sudo cat /var/kerberos/krb5kdc/kadm5.acl
```

The ACL is now `*/admin@EXAMPLE.COM *` with your realm: every principal with the instance
`admin` (`admin/admin`, `alice/admin`) may do everything (kadm5.acl(5)). The realm's stanza in
`kdc.conf` is Fedora's: an `aes256-cts-hmac-sha384-192` master key, the keys every principal
gets (`supported_enctypes`), and `+preauth` on new principals. It sets no `max_renewable_life`,
so, as with MIT, principals get none and a ticket's `renew until` is its start time. SSSD and
other clients renew their tickets, so the second line gives the realm seven days. It must come
before `kdb5_util create`, which gives `krbtgt` the realm's values; new principals get them too.

### The database

```sh
sudo kdb5_util create -s
```

```text
Initializing database '/var/kerberos/krb5kdc/principal' for realm 'EXAMPLE.COM',
master key name 'K/M@EXAMPLE.COM'
You will be prompted for the database Master Password.
It is important that you NOT FORGET this password.
Enter KDC database master key:
Re-enter KDC database master key to verify:
```

As MIT's does, it makes `K/M`, `krbtgt/EXAMPLE.COM`, `kadmin/admin` and `kadmin/changepw`, and
with `-s` it stashes the master key in `/var/kerberos/krb5kdc/.k5.EXAMPLE.COM`, so the daemons
start without asking for it. Every password is read from the terminal, or one line per prompt
from standard input when that is not a terminal; none comes from the environment. A script can
pipe the password twice: `printf '%s\n%s\n' "$PW" "$PW" | sudo kdb5_util create -s`.

```sh
sudo restorecon -Rv /var/kerberos/krb5kdc
sudo ls -la /var/kerberos/krb5kdc
```

The directory holds the database `principal` (MIT's dump format, not db2) and its update log
`principal.ulog`, MIT's lock files `principal.ok` and `principal.kadm5.lock` (empty, 0600: the
tools and daemons lock the database through them, as MIT's do), the stash, `kdc.conf` and
`kadm5.acl`. Fedora builds MIT's tools with a patch that sets each new file's SELinux label from
the policy. kerber-rust's tools do that for the two lock files; `restorecon` gives the database
and the stash theirs (MIT's `krb5kdc_principal_t` for the database). Run it again after every
`kdb5_util create` or `load`.

### Start

```sh
sudo systemctl enable --now krb5kdc kadmin
systemctl status krb5kdc kadmin --no-pager
sudo ss -lntup | grep -E 'krb5kdc|kadmind'
```

As MIT's do, `krb5kdc` listens on 88 (UDP and TCP), and `kadmind` on 464 (kpasswd, UDP and
TCP) and 749 (kadmin, TCP), on every address: `ss` shows each port twice, on `0.0.0.0` and on
`[::]`, and a UDP reply leaves from the address its request was sent to.

### The first administrator and a user

```sh
sudo kadmin.local -q "addprinc admin/admin"
sudo kadmin.local -q "addprinc alice"
```

```text
Authenticating as principal root/admin@EXAMPLE.COM with password.
No policy specified for admin/admin@EXAMPLE.COM; defaulting to no policy
Enter password for principal "admin/admin@EXAMPLE.COM":
Re-enter password for principal "admin/admin@EXAMPLE.COM":
Principal "admin/admin@EXAMPLE.COM" created.
```

As MIT's does, `kadmin.local -q` exits 0 even when the query fails, so read what it prints.

### A remote check

MIT's `kadmin` talks to kadmind over the network, from this host or any client:

```sh
kadmin -p admin/admin -q listprincs
```

It asks for `admin/admin`'s password and lists `K/M`, `admin/admin`, `alice`, `kadmin/admin`,
`kadmin/changepw` and `krbtgt/EXAMPLE.COM`, each with `@EXAMPLE.COM`. Run as a user other than
root, it also prints `Couldn't open log file /var/log/kadmind.log: Permission denied`, because of
Fedora's `[logging]`. That line is harmless, and MIT's kadmin prints it too.

### A client host

On each client, with `krb5-workstation` and the same `/etc/krb5.conf.d/realm.conf`:

```sh
sudo kadmin -p admin/admin -q "addprinc -randkey host/$(hostname -f)"
sudo kadmin -p admin/admin -q "ktadd host/$(hostname -f)"
sudo klist -k
kinit alice
klist
```

`ktadd` without `-k` writes `/etc/krb5.keytab`, the keytab that sshd, SSSD and gssproxy read.

## Upgrading an MIT realm

On the host where `krb5-server` runs the realm, in the kerber-rust checkout built as in
[Build](#build). First, while MIT's tools are still installed, stop the daemons and dump the
realm:

```sh
sudo systemctl stop krb5kdc kadmin
sudo kdb5_util dump /var/kerberos/krb5kdc/mit-realm.dump
sudo dnf remove -y --no-autoremove krb5-server
```

The dump is MIT's version 7 text: every principal and policy, with the keys still encrypted in
the master key. `dnf remove` keeps the database, the stash and the dump. It saves each config
file you had edited as `<file>.rpmsave` (`kdc.conf` and `kadm5.acl` at least) and removes the
rest. Put the saved ones back before installing:

```sh
for f in /var/kerberos/krb5kdc/kdc.conf /var/kerberos/krb5kdc/kadm5.acl /etc/sysconfig/krb5kdc \
         /etc/sysconfig/kadmin /etc/logrotate.d/krb5kdc /etc/logrotate.d/kadmind; do
    if [ -e $f.rpmsave ]; then sudo mv $f.rpmsave $f; fi
done
sudo make install PREFIX=/usr
```

MIT's db2 database has the same name, `principal`, beside its policy database
`principal.kadm5`. Move those two aside (and `principal.ulog` too, if iprop was enabled), then
load the dump. MIT's lock files `principal.ok` and `principal.kadm5.lock` stay where they are:
kerber-rust locks the database through the same files.

```sh
sudo mkdir /var/kerberos/krb5kdc/mit-db2
sudo mv /var/kerberos/krb5kdc/principal /var/kerberos/krb5kdc/principal.kadm5 /var/kerberos/krb5kdc/mit-db2/
sudo kdb5_util load /var/kerberos/krb5kdc/mit-realm.dump
sudo restorecon -Rv /var/kerberos/krb5kdc
sudo kadmin.local -q listprincs
sudo systemctl enable --now krb5kdc kadmin
```

kerber-rust's `kdb5_util load` opens the dump's keys with the master key from the realm's stash,
which stays where MIT left it (`-P`, or `-m` and the typed password, if there is no stash;
MIT's `load` copies the keys unread). Keys, key versions, policies and passwords carry over, so
the clients' keytabs and the users' passwords keep working.

### Going back to MIT

kerber-rust's dump is MIT's format, so the same steps run the other way, in the checkout:

```sh
sudo systemctl stop krb5kdc kadmin
sudo kdb5_util dump /var/kerberos/krb5kdc/kerber-realm.dump
sudo make uninstall PREFIX=/usr
sudo dnf install -y krb5-server
sudo mkdir /var/kerberos/krb5kdc/kerber-db
sudo mv /var/kerberos/krb5kdc/principal /var/kerberos/krb5kdc/principal.ulog /var/kerberos/krb5kdc/kerber-db/
sudo kdb5_util load /var/kerberos/krb5kdc/kerber-realm.dump
sudo restorecon -Rv /var/kerberos/krb5kdc
sudo systemctl enable --now krb5kdc kadmin
```

## Upgrading kerber-rust

In the checkout, with the new release built as in [Build](#build). `make install` replaces the
programs and units an earlier install wrote and keeps every config file. For a realm an earlier
release made, two things changed:

- Release builds find the database, the stash and the ACL only where `kdc.conf` names them
  (`database_name`, `key_stash_file` and `acl_file` in the realm's stanza), else in
  `/var/kerberos/krb5kdc`; `KRB5_KDC_DB` and `KRB5_KDC_STASH` no longer count. Move a realm kept
  elsewhere into the KDC directory, as below for the 1.0 example's `/var/lib/kerber-rust` (a 1.0
  stash still loads), or name its files in the stanza; under SELinux only the KDC directory
  gives them a type the confined daemons may use. Carry the realm's `kdc.conf` stanza and
  `kadm5.acl` over as in [A realm](#a-realm).
- A database needs MIT's two lock files beside it, `<database_name>.ok` and
  `<database_name>.kadm5.lock`, and the tools and daemons refuse one without them with MIT's
  texts (`kadmin.local: No such file or directory while initializing kadmin.local interface`).
  Make them once, owned as the database is and labelled, while the daemons are stopped.

```sh
REALM=EXAMPLE.COM
OLD=/var/lib/kerber-rust            # where the realm was kept, if not in /var/kerberos/krb5kdc
DB=/var/kerberos/krb5kdc/principal  # kdc.conf's database_name, if the stanza names one
sudo systemctl stop krb5kdc kadmin
sudo make install PREFIX=/usr
for f in principal principal.ulog .k5.$REALM; do
    if sudo test -e "$OLD/$f"; then sudo mv "$OLD/$f" /var/kerberos/krb5kdc/; fi
done
sudo restorecon -Rv /var/kerberos/krb5kdc
for f in "$DB.ok" "$DB.kadm5.lock"; do
    if sudo test ! -e "$f"; then
        sudo install -m 0600 -o "$(sudo stat -c %u "$DB")" -g "$(sudo stat -c %g "$DB")" /dev/null "$f"
        sudo restorecon "$f"
    fi
done
sudo systemctl start krb5kdc kadmin
```

## Logs

- The daemons log to `/var/log/krb5kdc.log` and `/var/log/kadmind.log`, in MIT's line format.
  That comes from Fedora's `[logging]` (`kdc =`, `admin_server =`) in `/etc/krb5.conf`. A
  `[logging]` section in `kdc.conf` adds destinations, in MIT's forms (`FILE:`, `STDERR`,
  `SYSLOG`); with none anywhere, the daemons log to syslog.
- logrotate (one of the [prerequisites](#prerequisites)) rotates both monthly. Its
  `systemctl reload` sends SIGHUP, and the daemon reopens its log.
- `journalctl -u krb5kdc -u kadmin` holds only the start and stop lines, as it does for MIT.
- In the foreground (`sudo krb5kdc -n`, `sudo kadmind -nofork`) the daemons also write the
  structured JSON log on standard output ([logging.md](logging.md)).
- `sudo ausearch -m AVC -ts recent` shows any SELinux denial.

## Uninstall

```sh
sudo make uninstall PREFIX=/usr
```

Run it in the checkout, with the `PREFIX` you installed with. It reads the manifest that
`make install` and `make install-clients` wrote, `$(PREFIX)/share/kerber-rust/install-manifest`:
it stops and disables `krb5kdc` and `kadmin` when their unit files are still the ones install
wrote, removes each listed file whose SHA-256 is unchanged, keeps one that changed since or that
a package owns, then removes the manifest and reloads systemd. Without a manifest it removes
nothing. It keeps every config file and all of `/var/kerberos/krb5kdc`: the database with its
update log and lock files, the stash, `kdc.conf` and `kadm5.acl`.

## Not supported

- MIT's database files (db2, LMDB) and the LDAP backend. The database is MIT's dump format, so an
  MIT realm moves over with dump and load.
- Replica KDCs: Fedora's `kprop.service` and MIT's `kpropd` daemon. `kprop` and `kpropd` are
  installed and open the dump with the stash, but `kpropd` takes only `-r` and an address, not
  MIT's other options (`-s`, `-a`, `-f`, `-P`, `--pid-file`, `-D`): its keytab and ACL come from
  `KRB5_KPROP_KEYTAB` and `KRB5_KPROP_ACL`, and it does not detach. So `make install` installs
  no `kprop.service`.
- SPAKE with `edwards25519`, the group Fedora's `krb5.conf` names. The KDC implements P-256
  only, so with Fedora's settings it offers no SPAKE and clients use encrypted timestamps.
- OTP and RADIUS preauthentication, PKINIT configured in `kdc.conf`, master key rollover
  (`kdb5_util add_mkey` and the other `*_mkey` commands), `kproplog`, `sclient` / `sserver`, and
  plugin modules (plugins are Rust traits: [plugins.md](plugins.md)).
- `KEYRING:` credential caches in the tools `make install-clients` installs. `KCM:` (Fedora's
  default) and `FILE:` work.

## Make variables

| Variable | Default | Use |
| --- | --- | --- |
| `PREFIX` | `/usr/local` | `/usr` to replace krb5-server |
| `DESTDIR` | empty | A staging root: no package check, labels, tmpfiles or systemd steps (one that resolves to `/` is the live system) |
| `SBINDIR` | `$(PREFIX)/sbin` | The KDC-side programs; the units' `ExecStart` |
| `BINDIR` | `$(PREFIX)/bin` | `make install-clients` |
| `DATADIR` | `$(PREFIX)/share` | `kerber-rust/install-manifest`, what `make uninstall` may remove |
| `UNITDIR` | `$(PREFIX)/lib/systemd/system` | The units |
| `TMPFILESDIR` | `$(PREFIX)/lib/tmpfiles.d` | `krb5-krb5kdc.conf` |
| `SYSCONFDIR` | `/etc` | The base of the next two |
| `SYSCONFIGDIR` | `$(SYSCONFDIR)/sysconfig` | The units' `EnvironmentFile` |
| `LOGROTATEDIR` | `$(SYSCONFDIR)/logrotate.d` | The logrotate files |
| `KERBER_KDC_DIR` | `/var/kerberos/krb5kdc` | The programs' compiled-in KDC directory; it does not follow `PREFIX`. Give it to `make build` and `make install` alike |
| `CARGO`, `CARGO_TARGET_DIR` | `cargo`, `target/` | The build. sudo drops an exported `CARGO_TARGET_DIR`: give it to `make build` and `sudo make install` alike |
