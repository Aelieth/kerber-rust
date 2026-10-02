# scripts

The gates (`scripts/*-gate.sh`), the evidence runners and the tools they share. Gates run against real
MIT 1.22.2, Heimdal and Samba peers; [`docs/gates.md`](../docs/gates.md) lists what each one asserts and
[`docs/testing.md`](../docs/testing.md) how to run them.

## `lib/` — sourced by the gates and runners

| File | What it is |
|---|---|
| `lib/gate-common.sh` | The gate preamble: `log`, `die`, `unavailable`, cleanups, the one scratch default, the listener and log waits, `retry_until`, `shell_container`, `stock_mit_kdc`, `assert_no_error_log`. |
| `lib/provenance.sh` | Stamps every gate artefact with the tested tree; its `ERR` trap names the failing command. |
| `lib/kadmin-q.sh` | Every kadmin query a gate or a lib helper runs, but for the keyed container sites: `kadmin_q` / `kadmin_q_as`, the runners `mit_kadmin_local` / `mit_kadmin` / `rust_kadmin_local`, `kadmin_q_ok` (the verb's MIT success line, or the effect read back for a verb silent on success) and `kadmin_q_try` (best-effort cleanups). |
| `lib/kadmin-common.sh` | The kadmin gates' shared cells: the kadm5 probe builds, the RPCSEC_GSS and framing cells, the snapshot helpers. |
| `lib/kadmin-glob-cells.sh` | The alias and glob cells both kadmin legs run. |
| `lib/kpasswd-common.sh` | The raw kpasswd exchange and the pinned wire cells both kpasswd legs run. |
| `lib/proc-common.sh` | Stops a daemon inside the container by its comm name (`kill_comm`, `term_comm`). |
| `lib/client-diff-common.sh` | Shared helpers for the two client-differential gates. |
| `lib/prod-realm-common.sh` | Shared helpers for the gates over the `harness/prod` multi-host realm. |
| `lib/boot-shell.sh` | CI job preamble: one shared shell container with the gate bins. |
| `lib/boot-stock-mit.sh` | CI job preamble: one stock MIT KDC the later steps attach to. |
| `lib/build-bins.sh` | One cargo build of the bins the gates and prod jobs need; gates call `need_bins`, never cargo. |
| `lib/lab-realm.sh` | Refuses a host whose `/etc/krb5.conf` names a real realm (the local evidence runners). |
| `lib/settle.sh` | Captures a live settle: provenance, the command, its verbatim output. |
| `lib/unit-evidence.sh` | Stamped unit-test greens and parent reds. |
| `lib/test-hooks.sh` | `test_hooks_features`: the `test-hooks` cargo features a SHA defines, for `red-at-sha.sh` and `unit_red_at`. |
| `lib/unit-red-check.py` | Exits 0 only when every expected test failed. |
| `lib/run-peer-step.sh` | The peers workflow's wrapper: exit 2 (oracle unavailable) is not a job failure. |
| `lib/hygiene_inventory.py` | Writes a hygiene snapshot (counts, gate cells by reachability, shellcheck). |
| `lib/gate_unit_index.py` | Pairs the differential gate's status-word cells with their unit twins. |
| `lib/junit-annotate.py` | Turns nextest junit failures into GitHub annotations. |
| `lib/analyze-kdc-slo.py` | Aggregates KDC JSON logs: p99 latency, throughput, error rate, panics. |
| `lib/auth-gssapi-init-probe.py` | Sends a forged AUTH_GSSAPI init to a kadmind. |
| `lib/kdc-error-proxy.py` | UDP proxy printing each KRB-ERROR's code, e-text, client and e-data types. |
| `lib/kdc-padata-proxy.py` | UDP proxy printing the padata types of each KDC-REQ. |
| `lib/kdc-req-proxy.py` | UDP/TCP proxy printing the shape of each KDC-REQ. |
| `lib/kdc-rewrite-proxy.py` | UDP/TCP man-in-the-middle that rewrites KDC replies. |
| `lib/skew-preload.c` | An `LD_PRELOAD` that moves the clock three days ahead, for the skew cells. |
| `lib/openssl-seclevel0.cnf` | The OpenSSL 3 configuration the PKINIT gates load. |

## `oracle/` — MIT programs the gates build inside the container

| File | What it is |
|---|---|
| `oracle/gss-mit-client.c` | An MIT `libgssapi_krb5` initiator: AP-REQ plus a wrap token to the Rust acceptor (it can dump the AP-REQ for the replay cell). |
| `oracle/gss-mit-server.c` | An MIT `libgssapi_krb5` acceptor that prints the delegated name; the acceptor principal is optional. |
| `oracle/ccache-mit-remove.c` | MIT `krb5_cc_remove_cred` on a Rust-written ccache. |
| `oracle/kadm5-changepw-rpc.c` | An MIT libkadm5 client authenticating to `kadmin/changepw` (or a chosen service): the calls stock `kadmin` never makes. |
| `oracle/kadm5-integrity-rpc.c` | GET_PRINCS over RPCSEC_GSS with no protection, integrity, privacy or a tampered body. |
| `oracle/kadm5-rpc-probe.c` | Probes kadmind's RPCSEC_GSS / AUTH_GSSAPI reject machines: hand-framed calls after a real handshake. |
| `oracle/kpasswd-tgs-client.c` | MIT `krb5_change_password` / `krb5_set_password` with a `kadmin/changepw` ticket from the TGS. |
| `oracle/rd-safe-oracle.c` | MIT `krb5_rd_safe` over KRB-SAFE messages it builds and rewrites (canonical, non-canonical body, seq 2^31). |
| `oracle/t_vfy_increds.c` | MIT's own test program for `krb5_verify_init_creds`. |

`ccache-mit-addr-u2u.c` stays in `scripts/`: no gate builds it; it generated the committed
`tests/traces/ccache-mit-addr-u2u.bin` (a MIT `kinit -a` TGT plus a user-to-user cred).
