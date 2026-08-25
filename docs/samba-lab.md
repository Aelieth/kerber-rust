# Samba AD DC lab (live `AD.KERBER.TEST` oracle)

Coordinates for the **Samba 4 Active Directory Domain Controller** used as the
live AD interop oracle (Track A / phase A3). **This file contains no secrets.**
Throwaway container test passwords live in the gitignored
`working/samba-lab-accounts.md`; the provisioning admin password is injected at
build/run time via env, never committed.

This Samba DC is the **live successor** to the captured Windows Server 2022 DC in
[`ad-lab.md`](ad-lab.md): it serves the **same realm** `AD.KERBER.TEST` with the
**same account names**, so the existing `ad-*` gates and the committed
`tests/traces/pac-kbruser.ndr` fixture line up **by name**. Unlike the Windows
DC (a real external machine that was torn down), Samba is a **synthetic,
ephemeral container we provision ourselves** — like the MIT harness. Its keys and
passwords are test fixtures, not real secrets.

> **Domain SID caveat.** A fresh `samba-tool domain provision` generates its own
> domain SID, so `kbruser`'s SID will **not** match the captured Windows
> `pac-kbruser.ndr` (which carries the real Windows domain SID). This is expected
> and is reconciled in A2/A5 — either pin Samba's domain SID at provision time or
> regenerate a Samba-sourced PAC fixture. The A3 gate does not depend on SID
> equality; it depends on Samba **verifying a Rust-issued PAC's signatures**.
>
> *(Verified 2026-08-25: Samba domain SID
> `S-1-5-21-891046300-1937985867-1481223175`, `kbruser` RID 1103, `kbrsvc` RID
> 1104 — recorded in `working/samba-lab-accounts.md`.)*

## Topology

| Item | Value |
| --- | --- |
| DC host | `dc1` (container hostname) |
| DC FQDN | `dc1.ad.kerber.test` |
| DC address | container-internal `127.0.0.1` (the gate runs inside the container via `docker exec`; no host port publish needed) |
| DNS domain | `ad.kerber.test` (Samba internal DNS) |
| Kerberos realm | `AD.KERBER.TEST` |
| NetBIOS domain | `ADKERBER` |
| Server role | `dc` (`--server-role=dc`, `--dns-backend=SAMBA_INTERNAL`) |
| Functional level | Windows Server 2016 (`--function-level=2016`; requires Samba ≥ 4.19, else fall back to `2008_R2`) |
| Samba version | **4.19.5-Ubuntu** (base `ubuntu:24.04`), verified. **≥ 4.19** is needed for FL 2016 and for issuing the type-16 ticket signature + type-19 extended-KDC signature (CVE-2022-37967) |
| Enctypes | AES-SHA1 (18/17) to match the captured lab. Set `msDS-SupportedEncryptionTypes = 0x18` (AES-only) on the test accounts to suppress RC4. **No** RFC 8009 SHA-2 — AD does not issue it. |
| PAC | type-1 LOGON_INFO, type-6 server checksum, type-7 KDC checksum, **type-16 ticket signature**, **type-19 extended-KDC signature** |
| Image | `samba-ad-dc:latest` (built from `harness/samba/`), overridable via `SAMBA_AD_IMAGE` |

## Accounts (names only — passwords in `working/samba-lab-accounts.md`)

| Principal | Role |
| --- | --- |
| `ADKERBER\Administrator` | Domain admin (Samba built-in; provisioning `--adminpass`) |
| `kbruser@AD.KERBER.TEST` | Test user (AS-REQ; PAC in TGT) |
| `kbrsvc@AD.KERBER.TEST` | Service account holding the SPN below |
| `host/svc.ad.kerber.test@AD.KERBER.TEST` | SPN on `kbrsvc`; AES keys (etype 18/17) |
| `krbtgt/AD.KERBER.TEST@AD.KERBER.TEST` | Realm TGS (auto-created by provision) |

`kbrsvc` is configured trusted-for-delegation (`msDS-AllowedToDelegateTo =
host/svc.ad.kerber.test`) for the S4U work (A4). Names mirror
[`ad-lab.md`](ad-lab.md) so the same gates apply.

## Provisioning recipe (target — finalized in `harness/samba/`)

Run once inside the image build/entrypoint (throwaway `<...>` passwords come from
the gitignored accounts doc / build env):

```bash
samba-tool domain provision \
  --realm=AD.KERBER.TEST --domain=ADKERBER \
  --server-role=dc --dns-backend=SAMBA_INTERNAL --host-name=dc1 \
  --function-level=2016 \
  --option="ad dc functional level = 2016" \
  --option="posix:eadb = /var/lib/samba/private/eadb.tdb" \
  --adminpass="$SAMBA_ADMIN_PASSWORD"

samba-tool user create kbruser "$SAMBA_KBRUSER_PASSWORD"
samba-tool user create kbrsvc  "$SAMBA_KBRSVC_PASSWORD"
samba-tool spn add host/svc.ad.kerber.test kbrsvc

# AES-only (0x18=24) via LDIF; constrained delegation + protocol transition for S4U (A4)
ldbmodify -H /var/lib/samba/private/sam.ldb   # msDS-SupportedEncryptionTypes=24 on kbruser,kbrsvc
samba-tool delegation for-any-protocol kbrsvc on
samba-tool delegation add-service kbrsvc host/svc.ad.kerber.test
```

*(Implemented in `harness/samba/Dockerfile` + `harness/samba/provision.sh`, verified
on Samba 4.19.5. Beyond `samba` the build needs the `samba-ad-provision`,
`samba-dsdb-modules`, and `samba-vfs-modules` packages. The two `--option` flags are
the build-in-Docker workarounds — tdb-backed NT ACLs (no CAP_SYS_ADMIN) and the DC
FL match; operational details in `working/samba-lab-accounts.md`.)*

## Ports (container-internal; the gate does not publish to the host)

| Port | Service |
| --- | --- |
| 88 UDP/TCP | Kerberos KDC |
| 464 UDP/TCP | kpasswd / set-password |
| 389 / 636 | LDAP / LDAPS (samba-tool, account setup) |
| 53 | Samba internal DNS |
| 3268 / 3269 | Global Catalog |
| 135 / 445 | RPC endpoint mapper / SMB |

## Gate

`scripts/samba-ad-gate.sh` — the **only `exit 0`** is a live Samba `kinit` +
`kvno` + `klist` content match; missing docker/image/KDC is `exit 2` +
`samba-ad-gate-unavailable.log` (Heimdal/SSPI-style honesty). It reads:

```bash
SAMBA_AD_IMAGE=samba-ad-dc:latest \
SAMBA_AD_REALM=AD.KERBER.TEST \
SAMBA_AD_USER=Administrator \
SAMBA_AD_PASSWORD=<admin pw> \
  ./scripts/samba-ad-gate.sh
```

**A2/A5 payoff (in CI):** `scripts/samba-pac-verify-gate.sh` (L1: Samba
IDL decode of a Rust PAC), `scripts/samba-pac-l2-gate.sh` (L2: Samba
`kcrypto` recomputes 6/7/16/19; a flipped MAC fails), and
`scripts/samba-crossrealm-gate.sh` (L3: MIT `kvno` both directions).
The Rust TGS verifies a presented PAC and copies LOGON_INFO (in-repo
two-realm tests). `kvno` is not that copy proof. Ubuntu
`samba-testsuite` does not ship `samba.tests.krb5.kcrypto`; L2 vendors
Samba 4.19.5's `kcrypto.py` (AES checksums) plus `python3-cryptography`.
Missing image is still `exit 2`.

## Isolation (never touch host krb5/sssd)

The gate runs **entirely inside the container** (`docker exec`, container-local
`/tmp/samba-krb5.conf`, `FILE:` ccache), so it never reads or writes host
`/etc/krb5.conf` (which stays `TESTLABBY.LOCAL`), host SSSD, or the host default
ccache. Do not publish Samba's ports to the host, do not `realm join` / `adcli
join`, and do not point host tools at this DC. Any *host-side* interaction (rare)
must use a `~/adlab`-style isolated `KRB5_CONFIG` / `KRB5CCNAME` / `KRB5_KTNAME`.

## Relationship to the captured Windows DC

- **Same realm/accounts by name** → existing `ad-s4u-gate.sh`,
  `ad-windows-gate.sh`, `ad-mit-trust-gate.sh` can be repointed at Samba (live,
  reproducible) instead of the torn-down Windows DC (one-shot).
- **Different domain SID** → the committed `pac-kbruser.ndr` (Windows-sourced)
  stays the NDR-codec golden; SID-dependent checks are reconciled in A2/A5.
- **Cross-realm trust (A5)** with `KERBER.TEST` is re-established against Samba
  via `samba-tool domain trust create` (replacing the Windows `netdom /twoway`);
  see [`ad-lab.md`](ad-lab.md) for the trust-key handling this must reproduce.
