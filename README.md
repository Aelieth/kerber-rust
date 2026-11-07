# kerber-rust

**A Kerberos server written in safe Rust that you can run in place of MIT's `krb5-server`.** Your MIT
clients, keytabs and passwords keep working. It installs the same commands, services and files in the
same places, and it is tested side by side with MIT Kerberos 1.22.2 on lab machines, with real clients
and services.

[![License: Apache-2.0 OR MIT](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](LICENSE-APACHE)
[![Edition 2024](https://img.shields.io/badge/edition-2024-informational.svg)](Cargo.toml)
[![MSRV 1.95](https://img.shields.io/badge/MSRV-1.95-informational.svg)](Cargo.toml)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](Cargo.toml)
[![interop MIT 1.22.2 · AD](https://img.shields.io/badge/interop-MIT%201.22.2%20%C2%B7%20AD-brightgreen.svg)](docs/interop-matrix.md)

**It is for you if** you run a Kerberos realm on Fedora and want the KDC in a memory-safe language
without changing your clients, or you are building a product that needs a KDC as a library. **It is not
for you if** you need a C library, an LDAP database backend, RADIUS one-time codes or several realms in
one KDC process: see [Limitations](#limitations).

This is version **1.2.0**. You build it from source; it is not on crates.io and there is no package.

[Why it exists](#why-it-exists) · [What it can do](#what-it-can-do) · [Limitations](#limitations) ·
[How it was tested](#how-it-was-tested) · [Download, install and use](#download-install-and-use) ·
[Move an MIT realm over](#move-an-mit-realm-over) · [Configuration](#configuration) · [More](#more)

## Why it exists

A Kerberos KDC holds the keys to every account in a realm, and it reads packets from anyone on the
network. MIT's KDC, the reference implementation, is written in C. kerber-rust does the same job in
Rust, with `unsafe` code forbidden in its own crates and no Kerberos C library underneath, so memory
bugs of the kind C allows cannot come from its own code.

Two things shaped it:

- **It has to be a real replacement.** A new KDC is no use if every client and script has to change,
  so MIT 1.22.2 is the bar: the same commands, files and network behaviour, down to the log lines and
  error texts wherever they have been compared.
- **It has to fit inside other software.** The goal is to become the KDC inside
  [KLLDAP](https://github.com/Aelieth/klldap), replacing a wrapper around system MIT Kerberos. So the
  KDC and `kadmind` also run as Rust libraries ([docs/embed](docs/embed/README.md)). That embedding
  is the next step: today KLLDAP runs with `krb5-server` swapped for these programs.

## What it can do

| You want to | What you get |
| --- | --- |
| **Run a realm** | `krb5kdc` over UDP and TCP, with Fedora's systemd units, SELinux types and `/var/kerberos/krb5kdc` layout |
| **Manage it** | `kadmind` for MIT's `kadmin`, plus `kadmin.local`, `kdb5_util`, password changes on port 464, policies and lockout |
| **Log people in** | passwords (encrypted timestamp, encrypted challenge, SPAKE), FAST, certificates (PKINIT with RSA or elliptic-curve keys), and one-time codes through a verifier you supply |
| **Keep replicas** | `kprop` and `kpropd`, full dumps in both directions with MIT, and incremental propagation (iprop) |
| **Cross boundaries** | cross-realm tickets and referrals, a two-way trust with Active Directory, S4U2Self, S4U2Proxy and RBCD, and MIT's PAC, or AD's shape with `domain_sid` |
| **Serve applications** | tickets for SSSD, NFS 4.2, Keycloak and OpenSSH, and a GSS-API library for Rust programs |
| **Skip MIT's client tools** | its own `kinit`, `klist`, `kvno`, `kdestroy`, `kswitch`, `kpasswd` and `ktutil`, if you want them |
| **Build it into a product** | the KDC and `kadmind` as libraries over one store, with plugin points as Rust traits |

It keeps its database in MIT's dump format, so a realm can move to it and back.

## Limitations

- **It is the server side, not a C library.** There is no C API. Programs linked against MIT's
  `libkrb5` and `libgssapi`, such as sshd and SSSD, keep using those libraries.
- **Not tested against Heimdal in 1.2.** Heimdal was tested in both directions through v1.1.0, and that
  test was retired during 1.2.
- **`KCM:` caches have one test,** on one setup: Fedora 44 with `sssd-kcm` 2.13.1, against MIT's KDC. It is
  not in the field suite, and it says nothing about other distributions.
- **Fedora, as far as the tests go,** but for one scenario that builds these programs in KLLDAP's
  AlmaLinux 10 image. The install steps and the lab are Fedora.
- **One realm per KDC process.**
- **Not supported:** MIT's db2, LMDB and LDAP database backends; RADIUS-backed OTP; SPAKE groups P-384
  and P-521; `PKCS11:` and `PKCS12:` PKINIT identities and revocation lists; master key rollover;
  `kproplog`, `sclient` and `sserver`; loadable plugin modules. [The full list](docs/install.md#not-supported).
- **Not planned:** SAM-2, IAKERB, kdcproxy (MS-KKDCP), FIPS mode, `KEYRING:` and MSLSA caches, `ksu` and
  `.k5login`, `kpropd` under inetd, and `gss_wrap_size_limit`.
- **Its own client tools are not yet a drop-in** for MIT's: [what differs](docs/install.md#what-make-install-installs).
  Keep `krb5-workstation` if a script depends on one of those differences.
- **Some behaviour differs from MIT on purpose.** Most of those differences refuse something MIT
  accepts. [Not yet matched](docs/interop-matrix.md#not-yet-matched-in-12) lists what an operator
  could see, and [the deviations file](docs/mit-deviations.md) has every deliberate one.
- **Its dependencies are not all audited or free of `unsafe`.** RustCrypto, curve25519-dalek, getrandom
  and nix contain `unsafe`, and `cargo vet` reports 16 crates fully audited and 134 exempted.
- **Windows SSPI has no test of its own.** Over the AD trust, on an earlier 1.2 build, Windows accepted
  this realm's users and acted as a SPNEGO client in the lab.

## How it was tested

The rule is simple: a feature counts as done only when it works against real MIT 1.22.2 on lab machines.
A Rust program talking to itself never counts.

**MIT goes first.** Each scenario in the field suite runs on lab virtual machines against a stock
Fedora MIT 1.22.2 realm, then runs the same way against kerber-rust, and the two results are compared
check by check. A *check* is one thing the harness looks at after a step, such as a command's exit code
or output, a log line or a file's contents. It passes or fails, or it is only recorded (informational).

The weekly suite, the burn-in, the `KCM:` and Samba tests, CI and the secret scan ran on commit `bac2ce01`.
The rest ran on its parent `04be5862`, which builds the same program bytes: `bac2ce01` changed only two
test-harness files.

| Test | What it does | Result |
| --- | --- | --- |
| Weekly field suite | 16 scenarios, on MIT and on kerber-rust: real clients and services, install, upgrade, going back to MIT, replicas | 3,044 checks passed, 0 failed (172 informational) |
| Burn-in | the nightly field profile, 6 scenarios on both, 7 times in a row with the code frozen | every run 563 passed, 0 failed (38 informational), and the results of every run matched |
| The 1.1 regression set | the checks that proved the 1.1 release, run again | 8,198 passed, 0 failed |
| OpenSSH by hand | sshd GSSAPI login from one client to another | 52 passed, 0 failed |
| `KCM:` caches by hand | MIT's tools, then ours: `kinit`, `klist`, `kvno`, `kswitch`, `kinit -R`, `kdestroy`, each reading the other's caches | 20 of 22 steps identical; the other 2 differ only in the program's name, because ours ran as `krb5-klist` |
| Samba AD by hand | 7 tests with live Samba 4 domain controllers. 4 use our KDC, in a debug build: Samba decodes its PAC, checks its checksums and rejects corrupted ones, takes its referrals both ways, and returns the right SID over a real `samba-tool` trust. The other 3 exercise only Samba's own tools, and our client tools are in none of them | 7 of 7 passed |
| Crashes | 218 kills during writes, 50 of them during a database rewrite, each result loaded by MIT's `kdb5_util` | no damaged change; MIT loaded all 220 dumps |
| Power loss | 20 forced power-offs during writes, with a replica | none of the 38 acknowledged writes was lost |
| Write speed | beside MIT at 5,000 principals | 0.79 to 1.00 times MIT's median time per write |
| CI | every push | 8 of 8 jobs |
| Secret scan | the source, the test harness and 72,629 test record files | 0 findings (168 known-safe hits reviewed and allowlisted) |

Real software that ran against both MIT and kerber-rust, in those scenarios:

- **SSSD** on Fedora: login, renewal at a restart and `passwd`.
- **NFS 4.2** to NFS-Ganesha with `sec=krb5i` and `krb5p`, through `rpc.gssd`.
- **Keycloak** SPNEGO, from Java.
- **KLLDAP** with `krb5-server` swapped for kerber-rust.
- **MIT's own** `kinit`, `klist`, `kvno`, `kadmin`, `kpasswd` and `kprop`.

Four things to know when you read those numbers:

- **The burn-in ran back to back,** not a night apart. It shows seven clean runs in a row, not a week of
  uptime.
- **The tagged binaries are not the exact bytes those runs used.** The version number feeds into the
  compiled symbol names, so setting it to 1.2.0 changed the bytes. The tagged source differs from the
  tested source by the version, the docs and the test scripts. No program code changed.
- **The real Active Directory trust was not part of the final run.** It last ran on an earlier 1.2 build
  (83 checks on MIT and 97 on kerber-rust, 0 failed).
- **Two scheduled CI workflows did not prove this code on their own.** `peers.yml` skipped its seven Samba
  tests, because its job had no MIT image, and stayed green. They were run by hand instead, and the job's
  fix is planned for 1.2.1. `nightly.yml` had one red job, because two test scripts left test KDCs running
  and the tests after them failed. Those scripts are fixed in the tag.

The details are in the [interop matrix](docs/interop-matrix.md), the [parity
ledger](docs/parity/README.md), which grades MIT's functions one row per check, and the [field
harness](harness/field/README.md), which you can run yourself.

## Download, install and use

These steps are for Fedora 44, as an ordinary user with `sudo`. They replace `krb5-server`, so if this host
already runs an MIT realm, go to [Move an MIT realm over](#move-an-mit-realm-over) instead.

**1. Get the tools and the code, and build it:**

```sh
sudo dnf install -y git gcc make lld rustup krb5-workstation logrotate words
rustup-init -y --default-toolchain none --profile minimal
. "$HOME/.cargo/env"
git clone --branch v1.2.0 https://github.com/Aelieth/kerber-rust.git
cd kerber-rust
rustup toolchain install
make build
```

**2. Install it:**

```sh
sudo dnf remove -y --setopt=clean_requirements_on_remove=False krb5-server
sudo make install PREFIX=/usr
```

If `krb5-server` is not installed, `dnf` says so and nothing changes.

**3. Make a realm.** Change the first two lines for yours. `kdb5_util create` asks you to choose a master
password.

```sh
REALM=EXAMPLE.COM
DOMAIN=example.com
KDC_HOST=$(hostname -f)
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
sudo sed -i "s/^EXAMPLE\.COM = {/$REALM = {/" /var/kerberos/krb5kdc/kdc.conf
sudo sed -i "s/@EXAMPLE\.COM/@$REALM/" /var/kerberos/krb5kdc/kadm5.acl
sudo sed -i '/default_principal_flags = +preauth/a\     max_renewable_life = 7d' /var/kerberos/krb5kdc/kdc.conf
sudo kdb5_util create -s
sudo restorecon -Rv /var/kerberos/krb5kdc
sudo systemctl enable --now krb5kdc kadmin
```

**4. Use it.** Add an administrator and a user, then log in with MIT's tools:

```sh
sudo kadmin.local -q "addprinc admin/admin"
sudo kadmin.local -q "addprinc alice"
kinit alice
klist
```

You should see a `krbtgt` ticket for your realm. From here,
[docs/install.md](docs/install.md) is the whole guide: the firewall, keying client hosts, certificates,
one-time codes, replicas, installing beside `krb5-server`, containers and uninstalling.

## Move an MIT realm over

kerber-rust does not read MIT's db2 database, so a realm moves the way MIT moves one between its own
database types: dump it with MIT's `kdb5_util`, load it with this one. Keys, policies and passwords carry
over, so clients' keytabs and users' passwords keep working.

On the host that runs the realm, in a checkout built as in step 1 above, while MIT's tools are still
installed:

```sh
sudo systemctl stop krb5kdc kadmin
sudo kdb5_util dump /var/kerberos/krb5kdc/mit-realm.dump
sudo dnf remove -y --setopt=clean_requirements_on_remove=False krb5-server
for f in /var/kerberos/krb5kdc/kdc.conf /var/kerberos/krb5kdc/kadm5.acl /etc/sysconfig/krb5kdc \
         /etc/sysconfig/kadmin /etc/sysconfig/kprop /etc/logrotate.d/krb5kdc /etc/logrotate.d/kadmind; do
    if [ -e $f.rpmsave ]; then sudo mv $f.rpmsave $f; fi
done
sudo make install PREFIX=/usr
sudo mkdir /var/kerberos/krb5kdc/mit-db2
sudo mv /var/kerberos/krb5kdc/principal /var/kerberos/krb5kdc/principal.kadm5 /var/kerberos/krb5kdc/mit-db2/
sudo kdb5_util load /var/kerberos/krb5kdc/mit-realm.dump
sudo restorecon -Rv /var/kerberos/krb5kdc
sudo kadmin.local -q listprincs
sudo systemctl enable --now krb5kdc kadmin
```

[The full section](docs/install.md#upgrading-an-mit-realm) covers iprop, requiring preauthentication on
loaded principals, and removing the old files. [Going back to MIT](docs/install.md#going-back-to-mit) runs
the same steps the other way.

**Already on kerber-rust 1.1?** Stop both daemons before you install: a 1.1 program cannot read a database
this release has changed. See [Upgrading kerber-rust](docs/install.md#upgrading-kerber-rust).

## Configuration

The files are MIT's, in MIT's places. [examples/configs](examples/configs/README.md) is a working
one-realm set.

| File | Read by | Where |
| --- | --- | --- |
| `kdc.conf` | `krb5kdc`, `kadmind`, `kadmin.local`, `kdb5_util`, `kpropd` | `KRB5_KDC_PROFILE`, else `/var/kerberos/krb5kdc/kdc.conf` |
| `krb5.conf` | the client tools and `kprop`; the KDC-side tools for `default_realm` | `KRB5_CONFIG`, else `/etc/krb5.conf` |
| `kadm5.acl` | `kadmind` | the `acl_file` path in `kdc.conf` |
| `kpropd.acl` | `kpropd` | `-a`, else `/var/kerberos/krb5kdc/kpropd.acl`; a missing file refuses every propagation |

Four things are worth knowing:

- **Restart after an edit.** Each daemon reads its config once, as it starts. SIGHUP only reopens the logs.
- **Check the log for ignored settings.** The daemons log each setting MIT reads that this does not support.
- **Renewable tickets need `max_renewable_life`.** As with MIT, a realm without it gives none, which is
  why step 3 adds it.
- **Some defaults differ on purpose.** The KDC's TCP listen backlog is 128 (`kdc_tcp_listen_backlog`),
  where MIT's is 5, and the client tools ask for DES3, RC4 or Camellia only if the profile names them.
  [The deviations file](docs/mit-deviations.md) has the rest.

## More

| To read about | Go to |
| --- | --- |
| Every document | [docs/README.md](docs/README.md) |
| The code's structure | [docs/architecture.md](docs/architecture.md) |
| Embedding it | [docs/embed](docs/embed/README.md), [docs/plugins.md](docs/plugins.md) |
| Logs | [docs/logging.md](docs/logging.md) |
| Timing, replay and secret handling | [docs/security.md](docs/security.md) |
| The tests and how to run them | [docs/testing.md](docs/testing.md), [docs/gates.md](docs/gates.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |

**License:** [Apache-2.0](LICENSE-APACHE) OR [MIT](LICENSE-MIT), at your option. See [NOTICE](NOTICE) and
[docs/export-control.md](docs/export-control.md), since this is cryptographic software.
