# scripts

The gates (`scripts/*-gate.sh`) and the tools they share. Gates run against real
MIT 1.22.2 and Samba peers; [`docs/gates.md`](../docs/gates.md) lists what each one asserts and
[`docs/testing.md`](../docs/testing.md) how to run them.

## `lib/` — sourced by the gates and runners

| File | What it is |
|---|---|
| `lib/gate-common.sh` | The gate preamble: `log`, `die`, `unavailable`, cleanups, the one scratch default, the listener and log waits, `retry_until`, `shell_container`, `stock_mit_kdc`, `assert_no_error_log`, `mit_oracle_cc` / `mit_oracle_brand` (an oracle built in the container and the `libkrb5` it loads). |
| `lib/provenance.sh` | Stamps every gate artefact with the tested tree; its `ERR` trap names the failing command. |
| `lib/kadmin-q.sh` | Every kadmin query a gate or a lib helper runs, but for the keyed container sites: `kadmin_q` / `kadmin_q_as`, the runners `mit_kadmin_local` / `mit_kadmin` / `rust_kadmin_local`, `kadmin_q_ok` (the verb's MIT success line, or the effect read back for a verb silent on success) and `kadmin_q_try` (best-effort cleanups). |
| `lib/kadmin-common.sh` | Cells the kadmin gates source: the kadm5 probe builds, the RPCSEC_GSS and framing cells, the snapshot helpers. |
| `lib/kadmin-glob-cells.sh` | The alias and glob cells the kadmin gates run. |
| `lib/kpasswd-common.sh` | The raw kpasswd exchange and the pinned wire cells both kpasswd legs run. |
| `lib/client-diff-common.sh` | Shared helpers for the two client-differential gates. |
| `lib/proc-common.sh` | Stops a daemon inside the container by its comm name (`kill_comm`, `term_comm`). |
| `lib/boot-shell.sh` | CI job preamble: one shared shell container with the gate bins. |
| `lib/boot-stock-mit.sh` | CI job preamble: one stock MIT KDC the later steps attach to. |
| `lib/build-bins.sh` | One cargo build of the bins the gates need; gates call `need_bins`, never cargo. |
| `lib/run-peer-step.sh` | The peers workflow's wrapper: exit 2 (oracle unavailable) is not a job failure. |
| `lib/junit-annotate.py` | Turns nextest junit failures into GitHub annotations. |
| `lib/analyze-kdc-slo.py` | Aggregates KDC JSON logs: p99 latency, throughput, error rate, panics. |
| `lib/bulk-dump.py` | Copies a kdb5_util dump and appends principal records so a kprop transfer spans more than one KRB-PRIV block. |
| `lib/auth-gssapi-init-probe.py` | Sends a forged AUTH_GSSAPI init to a kadmind. |
| `lib/kdc-error-proxy.py` | UDP proxy printing each KRB-ERROR's code, e-text, client and e-data types. |
| `lib/kdc-padata-proxy.py` | UDP proxy printing the padata types of each KDC-REQ. |
| `lib/kdc-req-proxy.py` | UDP/TCP proxy printing the shape of each KDC-REQ. |
| `lib/kdc-rewrite-proxy.py` | UDP/TCP man-in-the-middle that rewrites KDC replies. |
| `lib/otp-common.sh` | The OTP gates' shared cells: the realm's files, one login per client with its bytes captured, the byte and ccache checks, the KDC-log slices. |
| `lib/otp-radius-stub.py` | A standard-library RADIUS responder on a UNIX socket (Access-Accept for the codes it is given): the verdict source MIT's `otp` module asks. |
| `lib/otp-fast-shim.c` | An `LD_PRELOAD` observer: the plaintext of the FAST request, the FAST response and the OTP nonce passing through `krb5_c_decrypt` / `krb5_c_encrypt` in `krb5kdc` or `kinit`. |
| `lib/otp-fastdump.py` | Reads the shim's lines and prints the inner padata types, the PA-OTP-REQUEST and PA-OTP-CHALLENGE bytes (ciphertext and nonce masked) and the nonces. |
| `lib/otp-totp.py` | RFC 6238 TOTP from the standard library: the current code, a code that is none of the five nearest, and the RFC's own vectors. |
| `lib/skew-preload.c` | An `LD_PRELOAD` that moves the clock three days ahead, for the skew cells. |
| `lib/openssl-seclevel0.cnf` | The OpenSSL 3 configuration the PKINIT gates load. |

## `oracle/` — MIT programs the gates build inside the container

A gate builds each with `mit_oracle_cc`: `krb5-config`'s `--cflags` and `--libs`, whose rpath loads the
image's MIT 1.22.2 libraries (a plain `cc … -lkrb5` loads Debian's 1.20.1 `libkrb5`, which `build-essential`
pulls in through `libtirpc3`). Before an oracle's first use the gate prints the `libkrb5` it loads and that
library's `KRB5_BRAND`, and goes red unless it is `krb5-1.22.2-final` with every krb5 library beside it.

| File | What it is |
|---|---|
| `oracle/asn1-decode-oracle.c` | MIT `decode_krb5_*` over the `asn1-sweep` corpus: `OK` and the FNV-1a of MIT's re-encoding, or `ERR`. |
| `oracle/ccache-mit-remove.c` | MIT `krb5_cc_remove_cred` on a Rust-written ccache. |
| `oracle/gss-mit-client.c` | An MIT `libgssapi_krb5` initiator: AP-REQ plus a wrap token to the Rust acceptor (it can dump the AP-REQ for the replay cell). |
| `oracle/gss-mit-server.c` | An MIT `libgssapi_krb5` acceptor that prints the delegated name; the acceptor principal is optional. |
| `oracle/kadm5-changepw-rpc.c` | An MIT libkadm5 client authenticating to `kadmin/changepw` (or a chosen service): the calls stock `kadmin` never makes. |
| `oracle/kadm5-integrity-rpc.c` | GET_PRINCS over RPCSEC_GSS with no protection, integrity, privacy or a tampered body. |
| `oracle/kadm5-rpc-probe.c` | Probes kadmind's RPCSEC_GSS / AUTH_GSSAPI reject machines: hand-framed calls after a real handshake. |
| `oracle/kpasswd-tgs-client.c` | MIT `krb5_change_password` / `krb5_set_password` with a `kadmin/changepw` ticket from the TGS. |
| `oracle/rd-priv-oracle.c` | MIT `krb5_rd_req`, `krb5_rd_priv` and `krb5_rd_safe` over the `rd-sweep` cases: answers `0`, `asn1` or the krb5 code. Built with `-DKPASSWD_KDB`, `kpasswd` mode: kadmind's acceptor calls on the `rd-sweep kpasswd` frames: `0`, `req`, `priv` or `drop`; `kadmind` mode: kadmind's GSS acceptor calls (`krb5_rd_req` with no server, as `kadmin/admin`, as `kadmin/changepw`) on the `rd-sweep kadmind` AP-REQs: `0` or the code, for each. |
| `oracle/t_vfy_increds.c` | MIT's own test program for `krb5_verify_init_creds`. |

`ccache-mit-addr-u2u.c` stays in `scripts/`: no gate builds it; it generated the committed
`tests/traces/ccache-mit-addr-u2u.bin` (a MIT `kinit -a` TGT plus a user-to-user cred). Build it the same
way: `cc -o ccache-mit-addr-u2u ccache-mit-addr-u2u.c $(krb5-config --libs krb5)`.
