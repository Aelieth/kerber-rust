# Hand legs

The release proof's hand legs: drivers the tester runs by hand on the lab VMs (they drive `harness/field/lab.sh`; never run in CI, only shellchecked).

Environment (each driver takes the 40-hex sha of the build under test as `$1`):
- `HAND_WT`: the kerber-rust checkout the leg runs against (`$HAND_WT/harness/field/lab.sh` is the lab, `$HAND_WT/target-rp/release` the ship; `HAND_SHIP` overrides it).
- `HAND_REC`: the record dir; each leg writes under `$HAND_REC/<sha>/`; `lib/ship-guard.sh` reads `$HAND_REC/<sha>/step1/ship.sha256`.
- `$KERBER_LAB_HOME/field.env` (default `~/kerber-lab`, mode 0600) is sourced by `lib/env.sh`; `require_env NAME...` stops on an empty name.
- `FIELD_LAB_NET` (field.env): the lab network, for the legs that start the embed example on klldap (`rp-az.sh` too).
- `HAND_REPO` (`rp-step1-equal.sh`): the main checkout the driver adds `HAND_WT` from as a detached worktree when `HAND_WT` has no `.git`.
- `HAND_STEP1_BASE` (`rp-step1-equal.sh`): the 40-hex sha whose `step1/ship.sha256` (and `extra.sha256`, if any) under `HAND_REC` the build must equal.
- `HAND_RELEASE_TAG`, `HAND_RELEASE_TREE` (`rp-final-clone.sh`; the tag also `rp-cm.sh` and `rp-ws.sh`): the release under test, e.g. `v1.2.1` and its tree.
- `HAND_BASELINE_DIR` (`rp-b2.sh`): the last graded B2 record's `b2/results.tsv` and `combined/results.tsv`; the grade compares against them.
- `HAND_FIXTURE_DIR` (`rp-b2.sh`): the throwaway D3.TEST realm's dumps, stashes, keytabs and passwords, from the FULL-r2 record's `helpers/`; mode 0700, checked against `b2/shared/d3-fixtures.sha256`. Never the lab realm's keys, and never in git.
- `FIELD_KIT_DIR` (`rp-r3.sh`): the lab copy of the reference client kit (one `*-remote-setup.sh` plus `lib/`), its files at 0644 as the kit ships them (R3 hashes them as the ssh user); it stays out of the tree.
- `krb5-embed-realm`, built from `examples/embed-realm` into the ship dir, for `rp-ss.sh`, `rp-al-a45.sh`, `rp-ba.sh`, `rp-az.sh`, `rp-tr.sh`, `rp-tr-cell2.sh` and `rp-sc.sh`.
- Passwords a leg generates go to a private `mktemp -d` under `TMPDIR`, never the record, and are removed on exit.

Drivers:
- `rp-plw-mit.sh`: power-loss, MIT replica: a kill control, then 20 virsh-destroy cycles with iprop.
- `rp-plw-rust.sh`: the same power-loss cell with our kdb/kpropd/kadmin.local streamed onto the replica.
- The p18 legs run in order: `rp-p18-go.sh` first, then `rp-p18-diag.sh` or `rp-p18-matrix.sh`. Each calls `lib/p18-stage.sh`, which stages on klldap only what is absent: MIT 1.22.2's packages, `strace` and `libeatmydata`; `harness/field/p18/`'s layout (`vm-setup.sh`), seeds (`seed.sh`) and session scripts; and, for go, `docs/install.md`'s prerequisites. It prints `P18_STAGED` and the hash of each script it sent. A new seed is a new P18.TEST realm. Diag and the matrix print `P18_QUIET` (klldap's running containers and `dnf-makecache.timer`), which they leave as they are.
- `rp-p18-diag.sh`: write speed, one cell (N=10, iprop on, 5 rounds, MIT first).
- `rp-p18-matrix.sh`: write speed, the untraced MIT-vs-ours grade (N=10/1000/5000, 3 reps).
- `rp-p18-go.sh`: installs the build under /opt on the klldap VM, then runs `p18-trace.sh`.
- `p18-trace.sh`: guest script; strace of kadmind's fsync/write path, MIT then ours.
- `rp-ss.sh`: embed realm cells 1, 2, 3, 6, 4, 7, MIT first, then the example.
- `rp-a2.sh`, `rp-a3-mit.sh`, `rp-trickle-mit.sh`: cell A2, cell A3 and the KDC trickler, MIT legs.
- `rp-al-a45.sh`: A4 (SS cells 1-4) and A5 (the embed trickle) on klldap.
- `rp-al-rerun.sh`: A2, A3 and the trickler on one build.
- `rp-wr-mit.sh`, `rp-wr-ours.sh`: WR, the MIT and our legs, each on a fresh snapshot.
- `rp-wr-chain.sh`: WR, MIT first; ours only after a clean MIT end.
- `rp-ba.sh`: BA on klldap, MIT first.
- `rp-az.sh`: AZ: kadmin ACL cells, MIT first, then the doc upgrade, then embed cells 2-4 on klldap.
- `rp-tr.sh`, `rp-tr-cell2.sh`: TR: trust cells (MIT kadmin.local, embed realm, kinit/kvno legs); cell 2 reads the profiles `rp-tr.sh` saved.
- `rp-sc.sh`: SC: MIT first on the kdc, then the upgrade, then ours (tl-data, S4U, RID cells).
- `rp-fz.sh`: FZ: a raw TGS-REQ with a non-ASCII service name, MIT first, then the upgrade.
- `rp-bg.sh`: BG: GSS sequence-number rig and the channel-binding cells in a private namespace, no VM.
- `rp-bd.sh`: BD: des3 SPAKE legs on the mitd3 VM, MIT KDC first, then ours.
- `rp-kill.sh`: upgrade then the kill-loop profile, rust leg.
- `rp-final-clone.sh`: the README's `git clone` block run on a reset kdc VM at the tag commit, with the guest HEAD, tree and tag checked.
- `rp-step1-equal.sh`: step 1, a fresh `make build` of the commit; the 13 ship binaries must equal `HAND_STEP1_BASE`'s `step1/ship.sha256`; writes `step1/ship.sha256` for `lib/ship-guard.sh`.
- `rp-cm.sh`: CM, the client matrix: stock MIT clients and SSSD on client2, rocky10, deb13 and ub26, under `FILE:` and `KCM:`, against MIT's KDC, then ours moved onto the same VM from the same setup; `lib/cm-cells.sh` runs the cells on the VMs, `lib/cm-grade.py` grades ours against MIT, and `lib/cm-host.sh` is its host side (resets, MIT's setup, the move, the scans, the gates), shared with `rp-ws.sh`. `rp-cm.sh <sha> hm` is HM by the same route: Debian 13's Heimdal client tools on deb13 (`kinit`, `kgetcred`, `kpasswd`, error texts).
- `rp-ws.sh`: WS/WA, Windows 11's own client on `kerber-win` (SSPI, `klist`, the LSA) by CM's route: per leg, kdc and services reset, `kerber-win` reverted to `win-pre-ksetup`, joined with `ksetup` and a power cycle, then W1-W4, S1/S2 against MIT's and our acceptor, P1, P2, R1c, K1 (Keycloak) and L1 last; `lib/win-agent.py` is the guest agent (the secrets go in guest files, deleted on read), `lib/ws-cells.ps1` the guest side, `lib/ws-grade.py` the grade. It builds `krb5-gss-accept` (test hooks) from the sha with the host's `cargo`.
- `ds-baselines.sh`: DS's baselines on `deb13` or `rocky10` (`$2`; phases `base,mit,rust` as `$3`): `ds-base-<vm>`; `mit-oracle-<vm>`, the distro's MIT holding `f4-mit-f44`'s realm (MIT's dump piped into its load); `rust-base-<vm>`, kerber-rust at `a3a9e051` by that sha's family blocks of `docs/install.md`, holding `rust-field-p12-f44`'s realm (ours' dump and load); with phase `rep` (and `$4`, default `<vm>r`), on the same-family replica: `mit-replica-<vm>` (hostname kdc2, Debian's `krb5-kpropd`, MIT's units off, no realm) and `rust-replica-<vm>` (MIT's server packages removed, kerber-rust at `a3a9e051` installed by the same blocks, its units off, no realm). Each is proved before its snapshot (listprincs, getprinc, the stash's enctype, both units after a reboot, MIT `kinit alice` through `lab.sh takeover`), and no snapshot is taken over an existing name.
- `rp-weekly.sh`, `rp-weekly-services.sh`, `rp-tf.sh`, `rp-nightly.sh`, `rp-rep.sh`: the profile launchers (weekly; upgrade then services; ticket-flags then klldap-swap; nightly N; upgrade then replica).
- `rp-sr.sh`: SR: password counts in a gcore of kadmind after kpasswd and remote cpw, MIT first, then the upgrade, then ours.
- `t7/`: T-7, the constant-time measurement; `t7/run.sh` builds it from the checkout and runs it on the host (`t7/README.md`).
- `rp-b2.sh`: B2, the combined driver then the full B2 hold; `B2_LAUNCH=1` runs the lab, `B2_HOLD_ONLY=1` skips the combined driver.
  Optional for `rp-b2.sh`: `KP_RPM` (a local MIT krb5-server rpm; unset = install from the repository) and `D3_BASESHIP` (an unfixed build's programs; unset = the wire cell is NOT-RUN).
- `rp-r3.sh`: R3, sshd GSSAPI client1 to client2; `R3_LAUNCH=1` runs the lab.
- `b2/`: `shared/` (the hold's driver, modules and VM helpers; `helpers/SHA256SUMS` is checked before the lock), `combined/` (the combined driver and its OTP, RA, KA cells), `fix-p8/` (the P8 field check).
- `r3/`: the R3 driver `hc.sh`, `cells/r3.sh`, `vmctl.sh`, `install-ours.sh`, `parity.py`, `pcapdecode.sh`.
- `lib/`: `env.sh`, `ship-guard.sh` (re-hashes the 13 ship binaries), `compare-legs.py` and `expected-diff.txt` (the B2 grade), `p16a-leg.sh` (the combined driver's dictionary leg).
- `lib/`: also the guest and client helpers the legs copy onto the VMs (`*.py`, `*.c`) and the `bg-ns.sh`/`bg-seq.sh` namespace scripts.
