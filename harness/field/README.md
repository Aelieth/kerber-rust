# `harness/field/`: the KVM field lab (section F0)

Section F proves kerber-rust against real systems: Fedora clients (SSSD,
gssproxy, NFS, sshd, Firefox), Keycloak, Windows/AD and KLLDAP. Every scenario
runs first against a stock Fedora MIT `krb5-server` realm (the oracle), then
against kerber-rust. This directory builds the lab those scenarios run in:
five libvirt VMs on this host, on a private NAT network with its own DNS.

`lab.sh` is a harness. It drives libvirt, cloud-init and Anaconda, and it
asserts nothing about Kerberos. The VMs carry no Kerberos server software and
no realm. The field scenarios install those: by hand first (the hand records
`f-<scenario>`), then repeatably through `run.sh`
([Field runs](#field-runs-runsh)).

## Address plan

Network `kerber-lab`: NAT on `192.168.177.0/24`, bridge `virbr-kerber`.
Gateway, DHCP and DNS are on `192.168.177.1` (libvirt's dnsmasq).

| Name | Address | libvirt domain | OS | vCPU / RAM / disk | Role |
| --- | --- | --- | --- | --- | --- |
| `kdc.kerber.test` | `.10` + a LAN NIC | `kerber-kdc` | Fedora 43 Cloud | 2 / 2 GiB / 20 GB | MIT `krb5-server` (oracle), then kerber-rust |
| `services.kerber.test` | `.11` | `kerber-services` | Fedora 43 Cloud | 4 / 6 GiB / 40 GB | rootful podman: Ganesha NFS, Keycloak, lldap |
| `client1.kerber.test` | `.21` | `kerber-client1` | Fedora Kinoite 43 | 4 / 6 GiB / 40 GB | the fleet's client type (satomlin-kit twin), SPICE desktop |
| `client2.kerber.test` | `.22` | `kerber-client2` | Fedora 43 Cloud | 2 / 3 GiB / 20 GB | sshd target, second NFS client, headless checks |
| `klldap.kerber.test` | `.30` | `kerber-klldap` | Fedora 43 Cloud | 2 / 3 GiB / 30 GB | rootful Docker (`moby-engine`): KLLDAP with its own KDC (F3) |

- **DHCP:** static leases by MAC (`network-kerber-lab.xml`, the table in
  `lab.sh`). Other machines get `.100`–`.199`.
- **DNS:** forward and reverse records for every name above. `kerber.test` is
  local only, so unknown names get NXDOMAIN and nothing leaks upstream.
  Everything else is forwarded upstream.
- **AD:** `ad.kerber.test` is forwarded to the AD test DC `10.10.38.38`, so the
  VMs resolve `test-server.ad.kerber.test` (F2-AD). The realm is `KERBER.TEST`.
- **Own name:** a VM's own name resolves locally (systemd-resolved /
  nss-myhostname), not through DNS. In `getaddrinfo` order the answer is the
  IPv6 link-local address, then the lab address, and on kdc then the LAN
  address (on klldap, Docker's `172.17.0.1`). This is stock Fedora. A client
  running on kdc itself tries `fe80::…%2` first.

### kdc's LAN NIC (macvtap)

`kdc` has a second NIC: macvtap in bridge mode on the host's wired NIC (the
lowest-metric wired default route; override with `KERBER_LAB_LAN_IF`). It
takes a DHCP address from the user's real LAN. Its only job is to let the AD
DC (`10.10.38.38`) reach the KDC, and RA3's SPNEGO target, which runs on kdc.

`/usr/local/sbin/kerber-lab-lan-nic` confines the NIC. The kdc user-data's
`bootcmd` writes the script and runs it once. That stage runs before sshd
starts, so nothing listens on the LAN unfiltered.

- **Inbound filter:** nftables table `inet kerber_lab_lan`, on that NIC only.
  - It accepts established/related traffic, DHCP replies (`udp sport 67 dport
    68`, so the lease renews), and `10.10.38.38` to tcp/udp 88 and tcp 80.
  - It drops everything else from the LAN, including 22, 464, 749 and ICMP.
  - The lab NIC and loopback are not filtered.
  - `kerber-lab-lan-filter.service` loads `/etc/nftables/kerber-lab-lan.nft`
    before `network-pre.target` on every boot, including after a `reset`.
- **Routes and DNS:** the NIC carries no default route, no DHCP routes, no
  DNS and no IPv6 (`never-default`, `ignore-auto-routes`, `ignore-auto-dns`,
  `ipv6.method disabled`). Traffic to `10.10.0.0/16` leaves through it
  on-link. Everything else, internet included, goes through the lab NAT.
- **Check it:**
  - `lab.sh check kdc` asserts the table and its unit.
  - `lab.sh ssh kdc sudo nft list table inet kerber_lab_lan` shows the rules
    with their counters.
  - To open the NIC for a moment: `sudo nft delete table inet kerber_lab_lan`.
    `sudo systemctl restart kerber-lab-lan-filter` closes it again.
  - A firewall added to kdc later must leave this table in place.
- **Verified from the DC:** `working/logs/f-F0/lan-filter.txt` holds the
  WinRM `Test-NetConnection` record (2026-10-01).

- **Host to kdc:** by design, macvtap does not carry traffic between the host
  and its own guest. Reach kdc from the host at `192.168.177.10`.
- **LAN address:** `lab.sh ip kdc lan` reads it from the guest agent.
- **Lab subnet:** the other VMs are not reachable from the LAN. kdc is the only
  VM exposed to it, which is why RA3's SPNEGO target runs on kdc (tcp 80).

## Usage

Run from the repo root, on the host or inside the `rust-dev` distrobox. In the
distrobox, `lab.sh` sends host commands through `distrobox-host-exec`. It
needs membership in the `libvirt` group and no sudo.

```sh
harness/field/lab.sh up                 # build or start everything; idempotent
harness/field/lab.sh status             # VMs, addresses, snapshots, kdc's LAN address
harness/field/lab.sh check              # ssh, DNS + reverse, time sync, internet; kdc LAN + filter + AD DC :88; client1 SDDM
harness/field/lab.sh check --lab-only kdc   # the same without what reaches past the lab: internet, LAN address, AD DC
harness/field/lab.sh ssh kdc            # shell as 'lab' (passwordless sudo)
harness/field/lab.sh ssh client2 -- sudo dnf -y install krb5-workstation
harness/field/lab.sh ip kdc             # 192.168.177.10   (ip kdc lan: the LAN address)
harness/field/lab.sh snapshot kdc mit-oracle   # offline snapshot (shut down, snapshot, start)
harness/field/lab.sh reset all          # revert every VM to 'base' and boot it
harness/field/lab.sh reset kdc mit-oracle
harness/field/lab.sh collect kdc working/logs/f-r1 /var/log/krb5kdc.log /etc/krb5.conf
harness/field/lab.sh down               # shut the VMs down (the network stays up)
harness/field/lab.sh rebuild kdc --yes  # one VM from scratch (after a template change)
harness/field/lab.sh destroy --yes      # remove the VMs, volumes, pool and network
```

- **`up`:** builds each missing VM, waits for provisioning and takes snapshot
  `base`.
  - Timing: about 20 minutes from nothing with the images already downloaded
    (measured 2026-10-01). Most of it is the Kinoite install and upgrade and
    the cloud VMs' package upgrade. Downloading the 4.5 GB of Fedora media
    first took 6 minutes more.
  - `reset all` brings every VM back at `base` in about 30 seconds.
  - Interruptions: a VM without `base` is finished from whatever state it is
    in. An install that ended is never booted again.
  - Later runs only start stopped VMs.
- **`collect <vm> <dir> [file...]`:** writes `<dir>/<vm>/journal.txt` (the last
  `COLLECT_MINUTES`, default 60), `collect.txt`, and the listed files under
  `<dir>/<vm>/files/`.
- **Snapshots:** taken offline (internal qcow2), so a revert is a cold boot.
  chrony then steps the clock at start. A memory snapshot would resume with a
  stale clock, and Kerberos needs synced time.
- **`destroy`:** touches only lab objects: the `kerber-*` domains, every volume
  in pool `kerber-lab`, the pool and the network. It keeps the downloaded
  images, the SSH key and the console password.

## Field runs: `run.sh`

`run.sh` makes the hand-run field records repeatable. It drives the real
products on the lab (the doc's own blocks on kdc, the installed daemons, MIT's
clients on client2) and keeps their logs, one line per check. It is a harness,
not a gate: no ci-policy judge, ledger row or CI job runs it.

```sh
make field PROFILE=nightly REF=f-functional               # every scenario of the profile
make field PROFILE=nightly REF=f-functional ONLY=upgrade  # one of them
harness/field/run.sh --profile nightly --ref f-functional --only upgrade   # the same, without make
```

- **Options:**
  - `--profile nightly|weekly` picks the scenarios, in the order of the table
    under [Scenarios](#scenarios);
  - `--only a,b` runs some of them;
  - `--leg mit|rust|both` picks the realm (default `rust`). `both` runs one
    leg at a time, MIT's first (the oracle): every selected scenario on the
    MIT baseline, then every one on the ref under test. Each scenario of a leg
    uses the kdc that leg's `upgrade` left, so a leg without `upgrade` runs
    against whatever kdc holds, and its `kdc.leg` check fails when that is not
    the leg's KDC.
- **The tree under test** is `git archive <ref>` of this repository, read-only
  (`GIT_OPTIONAL_LOCKS=0`; `FIELD_REPO` in `field.env` names another). A dirty
  checkout runs the harness, never the product.
- **Preflight:**
  - it takes `~/kerber-lab/state/lab.lock` (flock). When that is held, the run
    exits 1 before it makes a run directory; it only makes `~/kerber-lab/runs`
    and the lock file when they are missing.
  - every snapshot `baseline.env` names must exist;
  - `lab.sh check --lab-only` of the VMs the selected scenarios use: ssh, DNS
    and reverse DNS, time sync, kdc's LAN filter. It never fetches from the
    internet, needs no LAN address and never probes the AD DC, so an outage
    there does not fail a run.
  - the sha256 of `/etc/krb5.conf`, and in the `rust-dev` distrobox also of the
    host's own, `/run/host/etc/krb5.conf`.
- **Postflight**, after a stop or an error too:
  - those sha256s unchanged;
  - nothing new in the host's `/tmp` owned by the user;
  - `lib/scan-secrets.py` over the whole run, its planted control first.
  - A run driven from a Claude Code session (`CLAUDECODE=1`) leaves that
    session's own `/tmp/claude-<uid>` out of the `/tmp` check, because the
    session writes there on every tool call. The `post.host.tmp` line says how
    many entries it left out.
- **Limits:** a scenario has `FIELD_SCENARIO_TIMEOUT` seconds (default 1800),
  and each of its commands `FIELD_CMD_TIMEOUT` (default 900), cut to what is
  left of the scenario's time. A command over its limit is stopped and fails
  its check, so a hung command cannot hold the lab lock.
- **A stop** (SIGINT, SIGTERM or SIGHUP) ends the running scenario once its
  current command returns; the scenario's cleanup runs and the rest are NOT-RUN.
- **The result:**
  - any failed check or guard fails the run;
  - a scenario or leg that could not run is NOT-RUN, which is never a pass;
  - the exit status is 0 only when every selected scenario passed;
  - when `upgrade` fails, the scenarios after it in that leg are NOT-RUN (kdc
    does not run that leg's KDC).
- **Records:** `~/kerber-lab/runs/<UTC>-<sha12>-<profile>/` holds:
  - `summary.txt` and `run.log`;
  - `guards/`: the preflight and postflight checks, the krb5.conf sums and the
    `/tmp` list;
  - one `<scenario>/<leg>/` per leg:
    - `record.txt`: every command, its output through `lib/redact.py`, its exit
      status;
    - `checks.tsv`: one line per check (name, PASS / FAIL / INFO, expectation,
      exit status, what was seen, its line in `record.txt`);
    - `result`, `collect/` (journald and the non-secret files) and `pcap/` (a
      capture without the AS exchanges).
  - `runs/index.tsv` has one line per run. The last 30 runs and every failed one
    are kept.
  - The run's `TMPDIR` is its own `tmp/`, with the ref's archive and any raw
    capture copied from a VM. It is removed when the run ends, after a stop or
    an error too (not after a SIGKILL). A raw capture on a VM is deleted as soon
    as it is copied, and by the scenario's cleanup.
- **Secrets** come from `~/kerber-lab/secrets` (`baseline.env` names the files)
  and reach a VM only on ssh stdin.
- **Inputs not in git** go in `~/kerber-lab/field.env` (0600, the shape of
  `field.env.example`).
- **A hand runner** takes the same lock, so no field run starts under it:
  `flock -n ~/kerber-lab/state/lab.lock bash` (held while that shell runs).
- **Never:** a snapshot created or deleted, a git ref written, the AD DC touched.

`lib/`, shared by `run.sh` and the scenarios:

| File | What |
| --- | --- |
| `rec.sh` | The recorder: `run` / `runin` (a VM command, stdin for secrets), `host` / `hostin`, `limited` (any other command, under the same time limit), `once` / `twice` / `chpw` (secrets for stdin), `check` / `checklast` (graded lines of `checks.tsv`), `observe` / `observelast` (INFO lines), `kdcmark` / `kdcsince` (kdc's daemon logs; the mark is a check, and no line is read without one), `capstart` / `capstop` (captures), `waitsync`, `finish` |
| `redact.py` | The record filter: every value under `~/kerber-lab/secrets` and in `~/adlab/env`, trace key prefixes, `encrypted <hex>`, the encrypted-timestamp and SPAKE trace values, OIDC codes, SPNEGO tokens, cookies, PEM keys |
| `scan-secrets.py` | Every one of those values in every file of a run, in UTF-8 and UTF-16-LE (keytab keys raw and as hex); a planted control first; a hit fails the run |
| `pcap-keep.sh` | A capture's copy without any AS exchange (IP fragments of other messages kept), checked to hold no AS message |
| `strings-check.sh` | R1's strings check of the test-only names on a VM, by file or by install manifest (every program it lists, none skipped); `--control` must go red |
| `install-check.sh` | On a VM after `make install`: every program the install manifest lists is byte-identical to the checkout's build (`cmp`, the names paired by its `dist/install.sh`) |
| `docblocks.py` | A doc section's shell blocks, by heading, run one top-level command at a time in one session, each with its exit status (a here-document stays whole, and so does a command a trailing `\`, `&&`, `\|\|` or `\|` carries on to the next line) |
| `ktrace.sh` | An MIT client command with its `KRB5_TRACE`, and an `answers:` line naming the transports the replies came over |
| `leg.sh` | A scenario's leg from `baseline.env`'s `MIT_*` or `RUST_*` set: `legset` (secret file names), `resetvm`, `kdcis` (kdc runs the leg's KDC: MIT's packaged binaries, or the install manifest and the ref's build), `servicesready`, `ktcheck` (a keytab against the KDC's keys), `tgtline` / `tktcheck` (a ticket's life, renewable span and flags from `klist -f`), `countlast` |
| `kt-vs-kdc.py` | A keytab's newest kvno and enctypes (`klist -k -e`) against the KDC's `getprinc` |
| `nfs-probe.sh`, `spnego-probe.sh`, `check_spnego.lab.sh` | S2's probes, run in throwaway containers on services (image `localhost/s2-nfs-probe:f43`, own network namespace): the kit's NFS client set-up and alice's, root's and bob's NFS access; the kit's `check_spnego` (its helper block and function verbatim from kit commit `e9f3325`, only the four SSO constants set to the lab's) and the two requests by hand |
| `kc-events.sh` | Keycloak's events since a time, read-only through the admin API from the host (the admin password on stdin, the token through a pipe) |
| `lldap-membership.sh` | S1's: one lldap group membership added or removed on services (lldap's admin password on stdin) |
| `ptydrive.py` | R2's pty driver: `su`, `passwd` and `pamtester` on a pseudo-terminal, their prompts answered from stdin |

## Scenarios

| Scenario | Profiles | Legs | VMs: baseline snapshot (MIT / rust) | Reference hand records (MIT; rust) | Duration (MIT / rust) |
| --- | --- | --- | --- | --- | --- |
| `upgrade` | nightly, weekly | mit, rust | kdc: `f4-mit` / `rust-field-p12` (reset; the rust leg leaves it on the ref's install); client2: `rust-ssh` (rust leg, reset) | f-UP1 | under 1 / about 3.5 min (the build about 2) |
| `services` | nightly, weekly | mit, rust | services: `f4-mit` / `services-rust` (reset); kdc as `upgrade` left it | f-S2-services; f-S2-rust | about 2 / 2 min |
| `nfs-client` | nightly, weekly | mit, rust | client2: `f4-mit` / `rust-ssh`, services: `f4-mit` / `services-rust` (both reset); kdc as `upgrade` left it | f-R4-mit + f-R5-mit; f-R4 + f-R5 (client2's legs) | about 1.5 / 1.5 min |
| `sssd-login` | nightly, weekly | mit, rust | client1: `f4-mit` / `rust-nfs-sso`, services: `f4-mit` / `services-rust` (both reset); kdc as `upgrade` left it | f-R2-mit; f-R2 (headless) | about 2 / 2 min |
| `klldap-swap` | nightly, weekly | mit, rust | none: this host's docker | f-F3-mit (mit leg), f-F3 (rust leg) | about 4 min (mit) and 8 min (rust) with BuildKit's cache warm; much longer cold (see below) |

With `--leg both`, the four take 15 to 16 minutes (2026-10-02, every VM reset by the run).

**The MIT baseline `f4-mit`** (kdc, client1, client2, services) was set up once by
hand on 2026-10-02 (record `~/kerber-lab/runs/hand-f4-mit-20261002T143502Z/`):
kdc's `mit-trust-ra` and client2's `mit-nfs` disagreed on `host/client2`'s
keys, so R4-MIT's join step was re-run on client2; every keytab on the four VMs
then equalled the KDC's (kvno and enctypes), and NFS, SPNEGO and ssh from
client2 worked before the snapshots. Every scenario's `kdc.leg` check makes sure
its leg ran against the right KDC.

`scenarios/upgrade.sh --leg mit` is minimal: kdc back to `f4-mit`, Fedora's
`krb5-server` binaries as packaged, `krb5kdc` and `kadmin` active, the same
`listen.sockets` and `listen.backlog` checks as the rust leg (MIT's own sockets
are where those expectations come from), the package versions recorded.

`scenarios/upgrade.sh --leg rust` puts the ref under test on kdc, so it runs first:

- It resets kdc and client2 to their baselines and waits for chrony. Then it
  records the realm as the baseline serves it (`listprincs`, `getprinc alice`).
- It copies the ref's archive to kdc as `~/kerber-rust-<sha12>`; the archive
  stands in for the doc's `git pull`.
- It runs docs/install.md as written. The blocks come from the archive's own
  copy, by heading, so a doc change is what runs:
  - Build's block, without `git clone` and `cd kerber-rust`;
  - "Upgrading kerber-rust" block 1, with `REALM` set to the realm, `PREFIX=/usr`
    and `OLD` empty;
  - the listen-entry edit the doc asks for, when its listing prints an all-IPv6
    entry;
  - block 2.
  - Every command must exit 0. The listing may exit 1, when there is no entry.
- Then it checks, as the hand record did:
  - kdc runs the ref's build: each program the install manifest lists is
    byte-identical to `target/release/<its build name>` (`lib/install-check.sh`),
    and `sha256sum -c` of the manifest passes;
  - `ss` shows exactly `0.0.0.0` and `[::]` on 88 udp/tcp, 464 udp/tcp and 749
    tcp, with listen queues 5 / 5 / 2;
  - MIT's `set up 4 sockets` / `set up 6 sockets` lines;
  - no AVC since the window start, with a `USER_CMD` control in the same window,
    once after the start and once at the end (`selinux.avc.end`, after
    kadmind's writes for bob's kpasswd); the daemons in `krb5kdc_t` /
    `kadmind_t`. `ausearch -ts` reads local time, so the window start is read
    from kdc's own clock in its local time (kdc runs UTC);
  - `listprincs` and `getprinc alice` identical before and after;
  - the strings check `none` on the manifest's programs, and red on a planted
    file;
  - from client2, MIT `kinit`, `kvno` and remote `kadmin` over UDP and over TCP,
    with the KDC's and kadmind's log lines;
  - bob's kpasswd there over UDP 464 (kdc refuses client2's TCP 464 for that one
    exchange) and back over TCP, with kadmind's two `chpw request from
    192.168.177.22 for bob@KERBER.TEST: success` lines;
  - `kinit` on kdc against `::1` over UDP and TCP, and against `127.0.0.2` (a
    UDP reply leaves from the address its request was sent to).
- It records, not grades: the AS and TGS sizes, the preauth types offered, the
  AP-REP subkeys and the daemons' RSS. `scenarios/upgrade.expect` lists where
  they are known to differ from MIT's, with the record that shows each.
- It leaves client2 as it found it, and kdc on the ref's install with its
  checkout.

The scenarios after `upgrade` never reset kdc. Each resets its own client and
services, then checks that kdc runs the leg's KDC (`kdc.leg`; on the rust leg
also `kdc.ref`: the installed programs are the ref's build). Every check is a
"reproduced" row of its hand records with no clock window, no GUI and no
Windows. What differs between the legs and is already known is recorded as an
INFO line and listed in `scenarios/<name>.expect`, with its record and what
would remove it.

- **`services.sh`** (S2): from throwaway probe containers on services, (A) NFS:
  alice mounts `/users` `sec=krb5p`, `/media` and `/data` `sec=krb5i`, writes and
  reads, her files 10001:10001 on the client and on the server's disk; root (the
  `host/services` machine credential) reads `/data/fleet` and is squashed;
  ticketless bob is refused. (B) Keycloak: the kit's `check_spnego` gives `401`
  with `Negotiate`, then `302` with `code=` and a mutual token; Keycloak logs the
  `LOGIN` events. Also: services' three keytabs equal the KDC's keys, and the
  KDC's `ISSUE` lines for `nfs/` and `HTTP/`. Recorded: the probes' TGS
  transport and the `PREAUTH_REQUIRED` padata (from the kept capture). Not here:
  S2's decode of the RPCSEC_GSS replies and call counts.
- **`nfs-client.sh`** (R4 + R5, client2's legs): root's first touch mounts the
  three shares by the machine credential, and root is squashed with R4's error
  texts; alice's `kinit` into the kit's `FILE:/tmp/krb5cc_10001` (owner, label,
  FRIA, 24 h, renewable 7 d), her krb5p home and krb5i shares, 10001 on both
  sides; bob refused with R4's texts; R5's `check_spnego` without and with a
  ticket, the two requests by hand, Keycloak's `LOGIN` events from client2; the
  KDC's lines for client2; no SELinux denial on client2 but the kit's known
  `nfsidmap-client` one. Recorded: alice's AS preauth types and AS-REP size. Not
  here: R4's PROOF 3 (ticket expiry, a clock window) and client1's legs (GUI).
- **`sssd-login.sh`** (R2, headless on client1; never SDDM, never the kit's
  join): `pamtester` login through SSSD (`FILE:/tmp/krb5cc_10001` alice's,
  `user_tmp_t`, FRIA, 24 h, renewable 7 d); the renewal's shape at an sssd
  restart with alice's maxlife lowered to 15 min (renewed at once: FRIAT, 24 h
  again, renew-until and authtime kept); `passwd` through SSSD and kpasswd (the
  new password logs in, the old one is refused, then restored); `-allow_tix`
  (`CLIENT LOCKED OUT`, kinit's "credentials have been revoked"); `lldap_disabled`
  (the TGT is issued, the account is denied); the kit's own `--validate`. Every
  realm and directory change is undone, also when the scenario stops early.
  Recorded: the cache's size.

`scenarios/klldap-swap.sh` runs KLLDAP on this host's docker, never on a lab VM
(run.sh still holds the lab lock while it runs). It needs, from `field.env`:
the KLLDAP checkout and its pin (`FIELD_KLLDAP_REPO`, `FIELD_KLLDAP_PIN`), the
phase-80 fixture (`FIELD_KLLDAP_FIXTURE`) and Zepmann/lldap-cli
(`FIELD_LLDAP_CLI`). All three are only read; the source is `git archive` of the
pin (`--no-optional-locks`), never a copy of the checkout's working tree.

- **`--leg mit`** (f-F3-mit): KLLDAP's image as its `make test` recipe builds
  it, with MIT `krb5-server` inside.
- **`--leg rust`** (f-F3), first:
  - the ref built in AlmaLinux 10, KLLDAP's base: the doc's Prerequisites
    mapped to AlmaLinux (gcc, make, lld; rustup from its installer), Build's
    block from the archive's docs/install.md without `git clone` and
    `cd kerber-rust`, then `make install DESTDIR=<staging> PREFIX=/usr`;
  - the strings check `none` on the staged programs and red on a planted file;
    their glibc floor no higher than the image's glibc;
  - KLLDAP's image built again (the MIT one, for the dump), and F3's one
    Dockerfile hunk: `krb5-server` out, `krb5-workstation` and `libkadm5`
    kept, the staging copied in, `/usr/sbin` and `/usr/lib` back to 0555. The
    swapped image is checked: no `krb5-server`, the modes and owners of its
    directories as in the MIT image, `sha256sum -c` of the install manifest;
  - the fixture's KDC migrated as docs/install.md "In a container" says, its
    three blocks taken from the archive by heading and run in one session
    (block 2's `docker stop` is not run: no container runs the copy). Every
    command must exit 0, and the loaded realm lists the dump's principals.
- **Both legs:**
  - KLLDAP's live-KDC FFI lane, `gate/kdc-sandbox.sh` with
    `cargo test -p lldap-kerberos -- --ignored`, as uid 1000 on the two MIT
    client libraries F3-MIT used: AlmaLinux 10's 1.21.3 (the image's) and
    Fedora 43's 1.22.2. The rust leg's environments have `krb5-server` removed
    and the staging in its place; the lane must run our `kdb5_util`,
    `kadmin.local`, `krb5kdc` and `kadmind`, `/usr/sbin/kadmin.local` too.
  - the image booted once with fresh volumes, for the observations;
  - `gate/run-gate.sh`, all phases, unchanged. Phase 80 takes the fixture's
    data as it is, so its pinned `key_seed` fails the same two lines on both
    legs; the check is that those two are the only lines not PASS. Its KDC is
    the fixture's (mit) or the migrated copy (rust);
  - phase 80 again on a copy of the data with a fresh `key_seed`: 4 of 4.
- **Against the MIT leg** (rust leg): this run's MIT leg, else
  `runs/mit-latest/klldap-swap/mit/`. The gate table line by line, the lanes'
  pass counts, and `/app/lldap` and `kerberos_manager` byte for byte. The table
  comparison masks the docker bridge address and LLDAP's two audit-log row
  counts, which the gate reads from a copy of the live database (one rerun on
  the same image gave 4 `policy_change` rows where F3-MIT's had 3). With no MIT
  leg to compare with, each comparison is NOT-RUN, and fails: a run is
  `--leg rust` unless told otherwise, so until a weekly MIT leg writes
  `runs/mit-latest/`, give `--leg both`.
- **Records**, besides `record.txt` and `checks.tsv`: `logs/` (each build, lane
  and gate run, redacted), `gate-table.txt`, `ffi.counts` and `app.sha256`, the
  files the comparison reads.
- **Observations**, not graded: the image's MIT packages, its listening
  sockets, its log files' modes, its KDC directory, the JSON lines in
  `docker logs`, and the lane sandbox's admin/admin attributes.
  `scenarios/klldap-swap.expect` lists the known differences, each with its
  record and the package or decision that owns it.
- **Where things run:** docker from wherever run.sh runs. The gate runs where
  `jq` is (lldap-cli needs it): here, or on the host through
  `distrobox-host-exec` from the `rust-dev` distrobox, which has none. Every
  path a container or the host writes is under the run's directory, and the
  fixture is read in place, so it must be on a path the host sees too
  (anything under `$HOME` is).
- **Resources:** images, containers, volumes and networks are named
  `kerber-field-<run id>-<leg>…` and removed at the end; BuildKit's cache stays,
  and makes a run after the first one fast. The ref's build and the lanes run
  under `nice` and `--cpus 8`; BuildKit's image builds take no CPU cap. Each leg
  downloads rustup, the toolchains and the crates again into its tmp, and
  deletes its scratch when it ends (several GB, with a container for what root
  wrote), so run.sh's secret scan reads the records, not the scratch.
  With a cold cache, or after `quay.io/almalinuxorg/10-minimal` moves (KLLDAP's
  Dockerfile does not pin it), KLLDAP's image build compiles everything again:
  F3-MIT's took 9 min with its first stage cached, so set `FIELD_CMD_TIMEOUT`
  and `FIELD_SCENARIO_TIMEOUT` higher for that run.
- **Secrets:** each leg makes its own (the fixture's admin password, the fresh
  `key_seed`, the boot's LLDAP secrets) in its tmp, never printed. KLLDAP's
  gate passes the fixture admin password on `docker run`'s command line, as
  it is written. A last check scans the leg's record for those values, the
  fixture's `key_seed` and its admin keytab's keys, with its planted control.

## What `up` builds

- **Cloud VMs (`kdc`, `services`, `client2`, `klldap`):**
  - Disk: a qcow2 overlay on the Fedora 43 Cloud Base image (`43-1.6`).
  - Seed: a NoCloud ISO (`cidata`) rendered from `cloud-init/<vm>.user-data`
    and `cloud-init/network-config.*`.
  - cloud-init sets the FQDN hostname and timezone UTC. It creates user `lab`
    (wheel, NOPASSWD sudo, the lab key, a console password; no SSH password
    login), upgrades all packages, and installs `chrony qemu-guest-agent
    tcpdump jq bind-utils tar rsync`. `services` also gets `podman`,
    `klldap` gets `moby-engine` (KLLDAP is Docker-only), and `kdc` gets
    `nftables` plus its LAN NIC confinement.
  - chronyd and the guest agent are enabled, and on `klldap` also
    `docker.service`.
- **`client1`:**
  - Installed unattended from the Fedora Kinoite 43 ISO with
    `kickstart/client1-kinoite.ks`. Its payload is the ISO's embedded ostree
    repo, the same `ostreesetup` line as the ISO's own
    `interactive-defaults.ks`.
  - The installer kernel boots directly with `inst.ks=hd:LABEL=OEMDRV:/ks.cfg`,
    and the kickstart rides on a small ISO labelled `OEMDRV`. The kickstart
    powers off at the end. `lab.sh` then drops the direct kernel boot, ejects
    the media and boots from disk.
  - Same `lab` user and key; `sshd` and `chronyd` enabled.
  - `xconfig --startxonboot` makes it boot to SDDM like a graphical install.
    Kinoite is KDE, so the plan's "GDM" is SDDM here.
  - After the first boot, `lab.sh` runs `rpm-ostree upgrade` and reboots,
    because the fleet runs updated deployments. The ISO's deployment stays as
    the rollback. Set `KERBER_LAB_KINOITE_UPGRADE=0` to skip this.
  - No packages are layered, so client1 is the stock Kinoite deployment until
    the kit layers its own. That means no guest agent, tcpdump or jq.
- **Media:** checked against Fedora's CHECKSUM files. `lab.sh` verifies the
  signature with the Fedora 43 key (`C6E7F081CF80E13146676E88829B606631645531`)
  and then the SHA-256, before it uploads anything into the pool.
- **Firmware:** every VM boots with SeaBIOS (BIOS), so internal snapshots work.
  libvirt does not take internal snapshots of UEFI/pflash guests.

### The VMs at snapshot `base` (built 2026-10-01)

| | kdc / services / client2 | client1 |
| --- | --- | --- |
| OS | Fedora 43 Cloud (`VARIANT_ID=cloud`), `dnf upgrade`d | Fedora Kinoite `43.20261001.0` (ostree `fedora:fedora/43/x86_64/kinoite`), rollback `43.1.6` |
| Kernel | 7.2.8-100.fc43 | 7.2.8-100.fc43 |
| MIT krb5 | `krb5-libs-1.22.2-4.fc43` only (no server, no workstation) | `krb5-libs-1.22.2-4.fc43`; `/etc/krb5.conf` has `includedir`, default ccache `KCM:` |
| Related packages | `sssd-client`, `openssh-server`, `podman` (Fedora Cloud ships podman) | `gssproxy-0.9.2`, `nfs-utils-2.8.7`, `sssd-client` (no `sssd`/`sssd-krb5`), Firefox 156, SDDM |
| Firewall | none (Fedora Cloud has no firewalld) | firewalld, zone `FedoraWorkstation` |
| SELinux | enforcing | enforcing |
| Time | UTC, chronyd on `2.fedora.pool.ntp.org` (through the NAT) | same |

`klldap` (built 2026-10-02, about 6 minutes) is the cloud column plus
`moby-engine` 29.6.2 (containerd 2.2.8, runc 1.5.2) with `docker.service`
enabled. Fedora's unit starts dockerd with `--selinux-enabled`, so containers
run as `container_t`. The image's `podman` stays installed.

## Where things live

| What | Where | In git |
| --- | --- | --- |
| Network XML, cloud-init and kickstart templates, `lab.sh` | `harness/field/` | yes |
| The field runs: `run.sh`, `lib/`, `scenarios/`, `baseline.env`, `field.env.example` | `harness/field/` | yes |
| Verified Fedora images, signed CHECKSUM files | `~/kerber-lab/images/` | no |
| Lab SSH key (`lab_ed25519`, 0600) and `known_hosts` | `~/kerber-lab/ssh/` | no |
| Console password and its SHA-512 crypt; the realms' passwords and keytabs | `~/kerber-lab/secrets/` | no |
| The field runs' records and `index.tsv` | `~/kerber-lab/runs/` | no |
| The field runs' inputs (`field.env`, 0600) and the lab lock (`state/lab.lock`) | `~/kerber-lab/` | no |
| Rendered seeds and kickstart (they hold the key and the hash) | `~/kerber-lab/seeds/` | no |
| VM disks, seed ISOs, the base image, the Kinoite ISO | pool `kerber-lab`, `/var/lib/libvirt/images/kerber-lab/` (root) | no |

- **`~/kerber-lab`:** mode 0700. Set `KERBER_LAB_HOME` to move it; it must be a
  path the host sees too (anything under `$HOME` is).
- **Templates:** they hold only placeholders (`@SSH_PUBKEY@`,
  `@LAB_PASSWD_HASH@`, `@LAB_MAC@`, `@LAN_MAC@`).
- **Console password:** for `virsh console` or the SPICE desktop when ssh is
  not an option. SSH accepts only the key.

## Isolation

- **Host:** the lab never touches the host's `/etc/krb5.conf` (realm
  `TESTLABBY.LOCAL`), the libvirt `default` network, other VMs, or host
  networking. libvirt's own firewall rules for `virbr-kerber` are the only
  host-side network change.
- **Secrets:** none enter git or field records.
- **Libvirt objects:** every one is named `kerber-lab` or `kerber-*`.
  `pool-build` created the standard libvirt directory `/var/lib/libvirt/images`
  as the pool's parent. `destroy` leaves it, empty.
