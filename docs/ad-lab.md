# AD interop lab

Coordinates for the Windows Server 2022 Evaluation DC used as the
Active Directory oracle. **This file contains no secrets.** Service
keys, pcaps, FILE ccaches, and passwords stay in operator-held
`~/adlab/` and the gitignored `tests/traces/ad/` tree.

> **Live successor:** this Windows DC was the *capture* source and has been
> torn down. The **live** AD oracle going forward is a containerized Samba 4 AD
> DC serving the **same realm** `AD.KERBER.TEST` with the same account names —
> see [`samba-lab.md`](samba-lab.md). Its domain SID differs from the captured
> `tests/traces/pac-kbruser.ndr` by design (reconciled in A2/A5).

## Topology

| Item | Value |
| --- | --- |
| DC host | `TEST-SERVER` |
| DC FQDN | `test-server.ad.kerber.test` |
| DC IP | `10.10.38.38/24` |
| DNS domain | `ad.kerber.test` |
| Kerberos realm | `AD.KERBER.TEST` |
| NetBIOS | `ADKERBER` |
| Functional level | Windows Server 2016 (`WinThreshold`) |
| PAC | Fully patched DC: type-16 ticket signature and 2022 extended KDC signature (CVE-2022-37967) |
| Client | `alien` at `10.10.44.154` (Fedora). SSSD-joined to a **separate** home realm that must not be disturbed. |
| Reachability | By IP. No DNS delegation on the client. |
| Enctypes | AES-SHA1 (18/17). AD does not issue RFC 8009 SHA-2 etypes. |

## Accounts (names only)

| Principal | Role |
| --- | --- |
| `ADKERBER\Administrator` | Domain admin |
| `kbruser@AD.KERBER.TEST` | Test user (AS-REQ / PAC in TGT) |
| `kbrsvc@AD.KERBER.TEST` | Service account |
| `host/svc.ad.kerber.test@AD.KERBER.TEST` | SPN, **kvno 3**, `aes256-cts-hmac-sha1-96` (etype 18) |

Passwords and `svc.keytab` are operator-held. Never commit them.

## Fixtures

| Path | What |
| --- | --- |
| `~/adlab/ad-krb5.conf` | Standalone client profile (`default_realm=AD.KERBER.TEST`, `kdc=10.10.38.38`, DNS lookups off) |
| `~/adlab/ad.ccache` | FILE cache for `kbruser` |
| `~/adlab/svc.keytab` | Service key (secret) |
| `~/adlab/ad-krb.pcap` | Wire capture of AS+TGS including the PAC-bearing service ticket |
| `tests/traces/ad/` | Gitignored copies for local tests. Refresh **from** `~/adlab`. |
| `tests/traces/pac-kbruser.ndr` | Committed non-secret `PAC_LOGON_INFO` NDR of `kbruser` (no keys). |

## Safe re-test (never touch host krb5/sssd)

The client box uses `/etc/krb5.conf` for a different realm. AD work
must set all three:

```bash
export KRB5_CONFIG="$HOME/adlab/ad-krb5.conf"
export KRB5CCNAME="FILE:$HOME/adlab/ad.ccache"
export KRB5_KTNAME="FILE:$HOME/adlab/svc.keytab"
kinit kbruser@AD.KERBER.TEST
kvno host/svc.ad.kerber.test
```

Never `realm join`, `adcli join`, or edit `/etc/krb5.conf` /
`/etc/sssd/sssd.conf`. Never write tickets to the default KCM/KEYRING
cache. Rust `discover_kdc` appends `/etc/krb5.conf` after `KRB5_CONFIG`;
omit the env var and you will hit the home realm.

`kbrsvc` is trusted-to-authenticate-for-delegation with
`msDS-AllowedToDelegateTo` = `host/svc.ad.kerber.test`. Gate:
`scripts/ad-s4u-gate.sh` (S4U2Self + S4U2Proxy, `for client kbruser`).

## Cross-realm trust (A5)

The DC has a bidirectional MIT realm trust `KERBER.TEST` (`netdom
/twoway`, `ksetup /addkdc` → `10.10.44.154`). Isolated
`~/adlab/ad-krb5.conf` lists `KERBER.TEST` at `10.10.44.154:8888`
(rootless distrobox cannot bind host `:88`; TESTLABBY stays on
`aurora.testlabby.local`).

`scripts/ad-mit-trust-gate.sh` (twice): both directions, aes256:

- `kbruser@AD.KERBER.TEST` → `host/testhost.kerber.test@KERBER.TEST`
- `user@KERBER.TEST` → `host/svc.ad.kerber.test@AD.KERBER.TEST`

Windows TDO inbound/outbound AES keys differ by salt. The Rust KDC
issues `krbtgt/AD.KERBER.TEST` with the inbound key and decrypts
AD-issued referrals with the outbound key (`KRB5_TEST_INTERREALM_KEY`
/ `KRB5_TEST_INTERREALM_KEY_ACCEPT`). Referral TGTs carry a PAC with
store SID/RID (`scripts/samba-crossrealm-gate.sh`). The accepting TGS
verifies that PAC and copies LOGON_INFO; `kvno` is not that copy
proof. Secrets stay in `~/adlab/` (0600).
