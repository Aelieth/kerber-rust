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
  and never installs the test tools (`krb5-tools`, the `krb5-gss` programs, `krb5-iprop-pull`),
  which only a build with the test-hooks features builds.
- On the live system it then does what the package's scriptlets do: `systemd-tmpfiles --create`,
  `restorecon` on each file it wrote when SELinux is enabled, and `systemctl daemon-reload`. It
  does not restart a running daemon; it says when one still runs the old programs. With
  `DESTDIR` set to a staging tree it does none of these and checks no package; a `DESTDIR` that
  resolves to `/` is the live system.

`make install-clients` installs the client tools `kinit`, `klist`, `kdestroy`, `kswitch`,
`kvno`, `kpasswd` and `ktutil` into `BINDIR`, for hosts without MIT's `krb5-workstation`. It is
never part of `make install`; on Fedora keep the package's tools. `kinit`, `klist`, `kvno`,
`kdestroy` and `kswitch` take MIT 1.22.2's options, print its texts and exit codes, and pick
caches as MIT's do in `FILE:`, `DIR:` and `KCM:` collections (`klist -k`, `-l` and `-A`,
`kdestroy -A`, `kswitch -p`, a new cache for a second principal); the satomlin kit's keytab
checks run on them as on MIT's. They are **not yet a drop-in** for MIT's in these:
- `kinit -I`, `--request-pac` and `--no-request-pac`, `klist -V` and `kvno -F` are missing, and
  `kvno -U` does not first ask the KDC for the user's realm.
- `klist` prints dates as the C locale does, where MIT's follow the locale, and an error not yet
  compared with MIT's tools may read differently from MIT's text.
- `[libdefaults] request_timeout` is only checked (a malformed one stops a program, as MIT's
  context does); its value is ignored.
- `ktutil` has no `?` request, does not echo requests, and lists entries in its own format.
- `kinit -k` with no principal asks for `host/<host name>` in the default realm, where MIT's asks
  for the host's canonical name.
- `kinit` sends an expired password's change to the KDC's host on port 464, where MIT's sends it
  to `kpasswd_server`, else `admin_server`; `kpasswd` ignores a port given in `kpasswd_server`.
- With no enctypes in `krb5.conf` the default list is the four AES types; MIT's also has DES3, RC4
  and Camellia, so the two agree only where `krb5.conf` or Fedora's crypto-policies sets the list.
- Of `kinit -X`'s attributes only `X509_user_identity` and `X509_anchors` act (one anchors file);
  the rest, `disable_freshness` among them, are accepted and ignored.

Scripts that need one of these need MIT's `krb5-workstation`. With the default `PREFIX`,
`BINDIR` is `/usr/local/bin`, which comes before `/usr/bin` in `PATH` and in sudo's
`secure_path`, so these tools shadow MIT's for every user.

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
cargo features: the programs read no password, and no database or stash path, from the
environment. The release `kvno` still accepts four options the gates use and MIT's does not
(`--disable-transited-check`, `--body-realm`, `--renew`, `--renew-ticket`). Run it as yourself.
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
`krb5kdc_t` and `kadmind_t`, Fedora's policy for MIT's daemons. The KDC reads the database and
writes only the lockout counts beside it, in place in the existing `principal.lockout`, which
that policy allows `krb5kdc_t`; kadmind replaces the database file (and `principal.lockout` when
it rewrites it whole) inside the directory, which it allows `kadmind_t`.

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
sudo sed -i "s/^EXAMPLE\.COM = {/$REALM = {/" /var/kerberos/krb5kdc/kdc.conf
sudo sed -i "s/@EXAMPLE\.COM/@$REALM/" /var/kerberos/krb5kdc/kadm5.acl
sudo sed -i '/default_principal_flags = +preauth/a\     max_renewable_life = 7d' /var/kerberos/krb5kdc/kdc.conf
sudo cat /var/kerberos/krb5kdc/kadm5.acl
```

The first line renames the realm's stanza in `kdc.conf` (the file's opening comment still names
`EXAMPLE.COM`, the placeholder it tells you to replace). The ACL is now `*/admin@EXAMPLE.COM *`
with your realm: every principal with the instance `admin` (`admin/admin`, `alice/admin`) may do
everything (kadm5.acl(5)). The realm's stanza in `kdc.conf` is Fedora's: an
`aes256-cts-hmac-sha384-192` master key, the keys every principal gets (`supported_enctypes`),
and `+preauth` on new principals. It sets no `max_renewable_life`, so, as with MIT, principals
get none and a ticket's `renew until` is its start time. SSSD and other clients renew their
tickets, so the third line gives the realm seven days. It must come before `kdb5_util create`,
which gives `krbtgt` the realm's values; new principals get them too.

Tickets carry MIT's PAC: the client's name and the KDC's checksums, the bytes MIT's KDC issues.
A realm whose principals must carry an AD identity (a Samba or AD peer reads the PAC) adds
`domain_sid = S-1-5-21-…` to its stanza in the kdc.conf of every KDC of the realm, replicas
included, since each KDC reads its own. That is AD data, and the KDC then issues the AD-shaped
PAC (LOGON_INFO with the domain SID and each principal's RID, UPN_DNS_INFO, ATTRIBUTES_INFO,
REQUESTER_SID). A presented PAC that carries LOGON_INFO, such as an AD user's over a trust, keeps
that shape in any realm.

A KDC whose clients open many TCP connections at once right after a write (a password change, a
new principal) adds `kdc_tcp_listen_backlog = 128` under `[kdcdefaults]`, as
`examples/configs/kdc.conf` does. The KDC keeps MIT's default of 5, and it accepts no connection
while it rereads the database after a write, so in a burst of 50 a kinit can wait about a second
for its connection to be retried: at 5,000 principals, 428 of 500 did. Idle bursts wait too, as
on MIT's KDC: 19, 46 and 67 of 500 at 10, 1,000 and 5,000 principals. With 128, none waited a
second, on MIT's KDC or on kerber-rust.

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

The directory holds the database `principal` (MIT's dump format, not db2), with `iprop_enable`
its update log `principal.ulog` (MIT's), MIT's lock files `principal.ok` and `principal.kadm5.lock` (empty, 0600: the
tools and daemons lock the database through them, as MIT's do), `principal.lockout` (0600: each
principal's failed password attempts and last successful and failed authentication, which the
KDC records there in place, as MIT's KDC records them in its database), the stash, `kdc.conf`
and `kadm5.acl`. Fedora builds MIT's tools with a patch that sets each new file's SELinux label from
the policy, and kerber-rust's tools do the same (MIT's `krb5kdc_principal_t` for the database);
a save keeps the label of the file it replaces. `restorecon` changes nothing the tools made: it
is there for the directory, for files made by hand, and for a realm an earlier release saved
([Upgrading kerber-rust](#upgrading-kerber-rust)).

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

kerber-rust does not read MIT's db2 database. A realm moves over the way MIT moves one between
its own database types: MIT's `kdb5_util dump`, then kerber-rust's `kdb5_util load`. Until then
every kerber-rust program that opens MIT's database refuses it, leaves it as it is, and points
here (`krb5kdc` writes the line to its log and prints `cannot initialize realm … - see log file
for details`, as MIT's does):

```text
kdb5_util: Cannot open DB2 database '/var/kerberos/krb5kdc/principal': This is an MIT db2 database; dump it with the old installation's kdb5_util, then kdb5_util load here (docs/install.md, Upgrading an MIT realm) while initializing database
```

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

A loaded principal also keeps its attributes. Each principal kerber-rust creates gets
`REQUIRES_PRE_AUTH`, but neither `load` nor a later password change adds it, and MIT gives it
only when kdc.conf sets `default_principal_flags = +preauth` (Fedora's shipped kdc.conf does;
KLLDAP's does not). For a principal without it, the KDC answers a request that proves nothing
with a ticket, in a reply encrypted in the principal's key, which whoever asked can then try to
guess offline. Add it once to each principal that logs in with a password: the users and their
`/admin` principals (a principal with a random key, such as `host/` or `HTTP/`, gains nothing
from it):

```sh
sudo kadmin.local -q listprincs | grep -e '^[^/ ]*@' -e '^[^/ ]*/admin@' | grep -v '^kadmin/' |
    while read -r p; do sudo kadmin.local -q "modprinc +requires_preauth $p" </dev/null; done
```

Once the realm has served from kerber-rust, remove the dump and MIT's database. The dump holds
every key, encrypted in the master key that the stash beside it opens:

```sh
sudo rm -r /var/kerberos/krb5kdc/mit-realm.dump /var/kerberos/krb5kdc/mit-realm.dump.dump_ok \
    /var/kerberos/krb5kdc/mit-db2
```

### In a container

An image that runs the realm with its KDC directory on a volume, as KLLDAP's does, is upgraded
the same way by one-off containers on that volume: the old image dumps, the new one loads. Set
the names first:

```sh
REALM=EXAMPLE.COM
VOLUME=/srv/kdc/krb5kdc          # the host directory or volume mounted at /var/kerberos/krb5kdc
OLD_IMAGE=example/kdc:mit        # the image with MIT's krb5-server
NEW_IMAGE=example/kdc:kerber     # the same image with kerber-rust in its place
CONTAINER=kdc                    # the container that runs the realm
```

Stop the container (its daemons stop with it), note who owns MIT's database, dump the realm
with the old image's `kdb5_util`, and once the dump is written, move MIT's db2 files aside with
the new image (and `principal.ulog` too, if iprop was enabled):

```sh
docker stop "$CONTAINER"
OWNER=$(docker run --rm --network none --entrypoint stat -v "$VOLUME:/var/kerberos/krb5kdc" \
    "$OLD_IMAGE" -c %u:%g /var/kerberos/krb5kdc/principal)
docker run --rm --network none --entrypoint /usr/sbin/kdb5_util -v "$VOLUME:/var/kerberos/krb5kdc" \
    "$OLD_IMAGE" -r "$REALM" dump /var/kerberos/krb5kdc/mit-realm.dump &&
docker run --rm --network none --entrypoint sh -v "$VOLUME:/var/kerberos/krb5kdc" "$NEW_IMAGE" \
    -c 'cd /var/kerberos/krb5kdc && mkdir mit-db2 && mv principal principal.kadm5 mit-db2/'
```

Each command names the realm with `-r`: a one-off container has its image's own
`/etc/krb5.conf`, and an image that writes the realm's when it boots, as KLLDAP's does, has none
yet. `kdc.conf` and the stash are on the volume, where both images' `kdb5_util` find them. Then
load the dump with the new image, add `REQUIRES_PRE_AUTH` to the principals that log in with a
password (as in [Upgrading an MIT realm](#upgrading-an-mit-realm)), give the KDC directory back
to `OWNER`, and check:

```sh
docker run --rm --network none --entrypoint /usr/sbin/kdb5_util -v "$VOLUME:/var/kerberos/krb5kdc" \
    "$NEW_IMAGE" -r "$REALM" load /var/kerberos/krb5kdc/mit-realm.dump
docker run --rm --network none --entrypoint sh -v "$VOLUME:/var/kerberos/krb5kdc" "$NEW_IMAGE" -c '
    /usr/sbin/kadmin.local -r "$1" -q listprincs | grep -e "^[^/ ]*@" -e "^[^/ ]*/admin@" | grep -v "^kadmin/" |
        while read -r p; do /usr/sbin/kadmin.local -r "$1" -q "modprinc +requires_preauth $p" </dev/null; done' \
    sh "$REALM"
docker run --rm --network none --entrypoint chown -v "$VOLUME:/var/kerberos/krb5kdc" \
    "$NEW_IMAGE" -R "$OWNER" /var/kerberos/krb5kdc
docker run --rm --network none --entrypoint /usr/sbin/kadmin.local -v "$VOLUME:/var/kerberos/krb5kdc" \
    "$NEW_IMAGE" -r "$REALM" -q listprincs
```

- The one-off containers run as root, so the load leaves root's 0600 files. An image whose
  programs run as another user needs them back: KLLDAP runs `kadmin.local` as `LLDAP_UID`, and
  its manager sets the owner only when it creates a database, so there `OWNER` is
  `LLDAP_UID:LLDAP_GID`, as MIT's files were.
- `listprincs` lists the old realm's principals. Then run the container again from the new
  image with the options it ran with: `docker rm "$CONTAINER"` and the same `docker run` with
  `$NEW_IMAGE` (with Compose, change the image and run `docker compose up -d`).
- Give the one-off containers the volume options the container uses (`:Z` under SELinux with
  podman, for one). podman takes the same commands.
- To go back, run the same steps the other way, as in [Going back to MIT](#going-back-to-mit):
  dump with the new image, move `principal`, `principal.ulog` and `principal.lockout` aside,
  load with the old one, and give the directory back to `OWNER`.

Once the realm has served from the new image, remove the dump and MIT's database from the
volume, as on a host:

```sh
docker run --rm --network none --entrypoint sh -v "$VOLUME:/var/kerberos/krb5kdc" "$NEW_IMAGE" \
    -c 'cd /var/kerberos/krb5kdc && rm -r mit-realm.dump mit-realm.dump.dump_ok mit-db2'
```

### Going back to MIT

kerber-rust's dump is MIT's format, so the same steps run the other way, in the checkout:

```sh
sudo systemctl stop krb5kdc kadmin
sudo kdb5_util dump /var/kerberos/krb5kdc/kerber-realm.dump
sudo make uninstall PREFIX=/usr
sudo dnf install -y krb5-server
sudo mkdir /var/kerberos/krb5kdc/kerber-db
sudo mv /var/kerberos/krb5kdc/principal /var/kerberos/krb5kdc/principal.ulog /var/kerberos/krb5kdc/principal.lockout /var/kerberos/krb5kdc/kerber-db/
sudo kdb5_util load /var/kerberos/krb5kdc/kerber-realm.dump
sudo restorecon -Rv /var/kerberos/krb5kdc
sudo systemctl enable --now krb5kdc kadmin
```

## Upgrading kerber-rust

In the checkout: fetch the new release (`git pull`, or `git checkout <tag>` for a release tag)
and run `make build` as in [Build](#build). `make install` replaces the programs and units an
earlier install wrote and keeps every config file; give it the `PREFIX` you installed with
(`/usr` when kerber-rust replaced krb5-server, `/usr/local` beside it). For a realm an earlier
release made, five things changed:

- Release builds find the database, the stash and the ACL only where `kdc.conf` names them
  (`database_name`, `key_stash_file` and `acl_file` in the realm's stanza), else in
  `/var/kerberos/krb5kdc`; `KRB5_KDC_DB` and `KRB5_KDC_STASH` no longer count. Move a realm kept
  elsewhere into the KDC directory, as below for the 1.0 example's `/var/lib/kerber-rust` (a 1.0
  stash still loads), or name its files in the stanza; under SELinux only the KDC directory
  gives them a type the confined daemons may use. Carry the realm's `kdc.conf` stanza and
  `kadm5.acl` over as in [A realm](#a-realm).
- Each listen entry is a socket of its own, as in MIT: an explicit IPv6 address in `kdc_listen`,
  `kdc_tcp_listen`, `kadmind_listen` or `kpasswd_listen` (such as `[::]:88`) no longer takes IPv4
  clients too. A stanza that lists only `[::]` addresses must drop them, which leaves MIT's
  wildcards (`0.0.0.0` and `[::]`), or list `0.0.0.0:<port>` beside each, in the same step as
  `make install`.
- A database needs MIT's two lock files beside it, `<database_name>.ok` and
  `<database_name>.kadm5.lock`, and the tools and daemons refuse one without them with MIT's
  texts (`kadmin.local: No such file or directory while initializing kadmin.local interface`).
  Make them once, owned as the database is and labelled, while the daemons are stopped.
- The KDC records lockout counts and last logins in `<database_name>.lockout`, which
  `kdb5_util create` and `load` make; the KDC may not create files in its directory. Without it
  the KDC keeps them in memory, loses them on a restart and says so once in its log. Make it
  once, empty, owned as the database is and labelled, as the lock files below: the KDC fills it,
  and nothing else changes.
- The update log is MIT's: kept only with `iprop_enable` (which, as MIT's, needs `iprop_port`),
  one entry appended per change. Without iprop an earlier release's `principal.ulog` is no
  longer read or written and may be removed; with iprop the first program that maps it starts
  it over, so each replica takes one full dump (`krb5-kprop -i`). kadmind serves iprop on its
  own port and nothing listens on `iprop_port`, so an MIT replica's `iprop_port` names kadmind's
  port. kadmind grants a full resync but sends no dump: each one (after a policy change, or a
  replica the log has run past) needs `krb5-kprop -i` run by hand.

Stop the daemons and install, and move the realm into the KDC directory only if it was kept
elsewhere (leave `OLD` empty when it is already in `/var/kerberos/krb5kdc`):

```sh
REALM=EXAMPLE.COM
PREFIX=/usr                         # the PREFIX you installed with
OLD=                                # where the realm was kept, if not /var/kerberos/krb5kdc (1.0: /var/lib/kerber-rust)
sudo systemctl stop krb5kdc kadmin
sudo make install PREFIX="$PREFIX"
if [ -n "$OLD" ]; then
    for f in principal principal.ulog .k5.$REALM; do
        if sudo test -e "$OLD/$f"; then sudo mv "$OLD/$f" /var/kerberos/krb5kdc/; fi
    done
fi
sudo grep -nE '^[[:space:]]*(kdc_listen|kdc_tcp_listen|kadmind_listen|kpasswd_listen)[[:space:]]*=' \
    /var/kerberos/krb5kdc/kdc.conf
```

If that prints an entry whose addresses are all IPv6 (such as `[::]:88`), edit it now, before
the daemons start (the second item above): delete it, which leaves MIT's wildcards, or add
`0.0.0.0:<port>` beside it. Then label the directory, make the lock files and `principal.lockout`
where they are missing, and start:

```sh
DB=/var/kerberos/krb5kdc/principal  # kdc.conf's database_name, if the stanza names one
sudo restorecon -Rv /var/kerberos/krb5kdc
for f in "$DB.ok" "$DB.kadm5.lock" "$DB.lockout"; do
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
- In the foreground (`sudo krb5kdc -n`, `sudo kadmind -nofork`) the daemons print what MIT
  prints. `json = STDOUT` (or `STDERR`, `FILE:path`) in kdc.conf's `[logging]`, a relation MIT
  does not read, adds the structured JSON log ([logging.md](logging.md)).
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
  installed and open the dump with the stash. `kpropd` takes MIT's `-r`, `-s` (else the default
  keytab) and `-a` (else `kpropd.acl` in the KDC directory) and an address (without one it
  listens on port 754 of every address, as MIT's does), not MIT's other options (`-f`, `-P`,
  `--pid-file`, `-D`), and it does not detach. As MIT's, it accepts a ticket for its own
  `host/<this host>` only, its name as MIT makes it without DNS: a hostname without a dot gains
  `qualify_shortname`, else the resolver's first search domain, and is lowercased. MIT's DNS
  canonicalization (`dns_canonicalize_hostname = true`, its default, and the second step of
  `fallback`) is not ported, so the replica's keytab entry and `kprop`'s target must be that name.
  `kprop` takes `-s`, else the default keytab. So `make install` installs no `kprop.service`.
- SPAKE groups P-384 and P-521 (MIT's OpenSSL groups). `edwards25519`, the group Fedora's
  `krb5.conf` names and its `kdc.conf` challenges with, and P-256 work as MIT's.
- OTP and RADIUS preauthentication, PKINIT configured in `kdc.conf`, master key rollover
  (`kdb5_util add_mkey` and the other `*_mkey` commands), `kproplog`, `sclient` / `sserver`, and
  plugin modules (plugins are Rust traits: [plugins.md](plugins.md)).
- `KEYRING:` credential caches in the tools `make install-clients` installs. `KCM:` (Fedora's
  default), `DIR:` and `FILE:` work, with their collections; the tools' other gaps are listed
  above.

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
