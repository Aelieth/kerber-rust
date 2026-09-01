# KCM NFS verdict (G8c / R7)

Date: 2026-09-01. Oracle: Fedora 43 `sssd-kcm` 2.12.0-3.fc43 (digest
`sha256:96b2a05f8ce3111e10c236abe8055b01500880d95ee7c2f92fa30847fdbb667b`,
krb5-libs 1.22.2-4.fc43) plus Fedora 42 compat `sssd-kcm` 2.11.1-2.fc42
(digest `sha256:e78cd1a688cd079c23864f289a89a49a3f4ad66d817864e325e1d058310ee95c`).
KDC: MIT Kerberos 1.22.2 harness (`KERBER.TEST`). Isolation: host
`/etc/krb5.conf` stayed `TESTLABBY.LOCAL`.

## Opcode pin (running daemon, not rpm)

Both F43 and F42 `sssd_kcm` listened on
`/run/.heim_org.h5l.kcm-socket`. After `GEN_NEW` + `INITIALIZE`:

| Opcode | Number | F43 2.12.0 | F42 2.11.1 |
| --- | --- | --- | --- |
| `RETRIEVE` | 7 | no (`KRB5_FCC_INTERNAL`) | no |
| `GET_CRED_LIST` | 13001 | **yes** (count 0 on empty) | **yes** |
| `REPLACE` | 13002 | no (`KRB5_FCC_INTERNAL`) | no |

The Rust client therefore iterates with `GET_CRED_LIST` and stores with
`INITIALIZE` + `STORE` (MIT's own fallback when REPLACE/RETRIEVE are
unsupported).

## R7 matrix

| Cell | How it was driven | Result |
| --- | --- | --- |
| Steady-state KCM TGT | Rust `kinit -c KCM:` vs MIT KDC; MIT `klist -c KCM:` names `user@KERBER.TEST` | **green** |
| Reverse | MIT `kinit -c KCM:`; Rust `klist` names `extra@KERBER.TEST` | **green** |
| sssd-kcm restart | `docker restart` of the kcm container (secrets DB on the writable layer) | **green** — MIT `klist` still names the TGT |
| Client reboot | same as restart in this environment (container stop/start, not hardware) | **green** (same cell) |
| Resume / re-prime | `kdestroy` then Rust `kinit -c KCM:` again | **green** |
| Two-principal + `kswitch` | `GEN_NEW` second cache (`uid:random`); `kswitch -c KCM:0` then `kswitch -p extra@KERBER.TEST` | **green**. Arbitrary residuals (`KCM:user`) are `FCC_INTERNAL` on sssd-kcm — MIT `kinit -c KCM:user` fails the same way |
| Quota + gssproxy `X-GSSPROXY` + PAC-fat tickets | gssproxy oracle and nfs-klldap-host **not vendored** | **not driven** (`gssproxy-gate` / `nfs-krb5p-gate` exit 2) |
| NFS `sec=krb5i` from KCM (requesting uid and root) | nfs-klldap-host absent | **exit 2** |

## Verdict

**FILE stays the fleet default.** KCM is a working client type against
live sssd-kcm (store/list/switch/destroy, restart persist, re-prime),
but R7's NFS mount cells and the gssproxy/PAC-fat quota row were not
run. R7 forbids a kit `KCM:` flip without those cells green.

Kit license: **none**. Do not drop the `/tmp`↔gssproxy sync loop.

## Rollback lever

No kit change was licensed, so there is nothing to roll back. Product
`default_ccache_name` is still FILE (`/tmp/krb5cc_<uid>`) unless
`KRB5CCNAME` / `-c` selects `KCM:`. `KEYRING:` remains
`Unknown credential cache type`.

To abandon KCM later: leave kit on FILE; Rust `KCM:` resolve can stay
(it is opt-in).

## Logs

`scripts/kcm-opcode-gate.sh` (F43/F42 NVRs + opcode yes/no).
`scripts/kcm-gate.sh` (MIT `klist` principal names, kswitch, restart,
re-prime, kdestroy). `scripts/nfs-krb5p-gate.sh` /
`gssproxy-gate.sh` / `kit-conformance-gate.sh` exit 2.
