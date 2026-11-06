# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/bl.sh: BL (the KDC's TCP listen backlog) on the final tree, on the UPGRADE PATH: the Send-Q of the KDC's listeners on the stock MIT realm, then on the same realm after docs/install.md's
# "Upgrading an MIT realm" (the field suite's upgrade.sh asserts the row on a rust-field-p12 install; this is the MIT-realm-to-ours path). Documented deviation: docs/mit-deviations.md:19
# (ours 88=128 unless `[kdcdefaults] kdc_tcp_listen_backlog` is set; kadmind's kpasswd listeners stay at 5, its RPC listeners at 2).
# Source records: vm/lab.txt:55-65 (ours, key absent: tcp :88 128, :464 5, :749 2), :87-99 (the key `= 5`: :88 5), :119-124 (MIT: 5, 5, 2); vm-upgrade/run-*/upgrade/mit/record.txt:43
# `backlog: 464=5 749=2 88=5` and .../rust/record.txt:425 `backlog: 464=5 749=2 88=128` (the same observation in upgrade.sh:30-40 `listencheck`, which hold A runs on both legs).
# Cells (VM: kdc; no client is used): default (the listeners as the stage found them), key5 (`[kdcdefaults] kdc_tcp_listen_backlog = 5`, krb5kdc restarted: ours 128 -> 5, MIT 5 -> 5), key64
# (the key at 64: both stages 64: the key means the same thing), restore (kdc.conf back as found, krb5kdc restarted: the default again).
# Differences from the recorded leg (vm/, 2026-10-06 20:31Z, tree 8f27ed57): the burst timing (50 simultaneous kinits after a cpw; 199/250 stalled on MIT's 5, none on 128) is NOT replayed: it is a
# capacity observation whose cause is the Send-Q number, and the generator was lost (survey BL); the upgrade path is dist/install.sh's, not make install; the key64 cell is new (the record has `= 5` and
# `= -3` (container-only) only); the login cell (kinit, kvno, sshd GSSAPI) is not BL's and is not run.
. "$SCRIPTS/helpers/b2a-host.sh"

bl_prep() {
    local f
    for f in bl-kdc.sh b2a-lib.sh b2a-kdcconf.py b2a-host.sh; do [ -s "$SCRIPTS/helpers/$f" ] || { echo "bl: helpers/$f is missing" >&2; return 1; }; done
}
bl_push() { b2a_push_script bl-kdc.sh; }

bl_run() {   # bl_run STAGE SECTION: the section on the kdc, split per cell
    b2a_run_kdc "bl/$1-run-$2" bl-kdc.sh "$1" "$2" < /dev/null
    b2a_split "$OUT/bl/$1-run-$2.txt" "$OUT/bl" "$1"
}

# the wildcard set MIT's own daemons open (upgrade.sh's listen.sockets check): 88 udp/tcp, 464 udp/tcp and 749 tcp, on 0.0.0.0 and [::]
bl_sockets_rx() { printf '%s' '^sockets: tcp 0\.0\.0\.0:464 tcp 0\.0\.0\.0:749 tcp 0\.0\.0\.0:88 tcp \[::\]:464 tcp \[::\]:749 tcp \[::\]:88 udp 0\.0\.0\.0:464 udp 0\.0\.0\.0:88 udp \[::\]:464 udp \[::\]:88$'; }

bl_stage() {   # bl_stage mit|ours
    local st=$1 L=BL.$1 f b88
    if [ "$st" = mit ]; then b88=5; else b88=128; fi    # the default of this stage's KDC
    bl_run "$st" default
    f="$OUT/bl/$st-default.txt"
    expect "$L.default.key-absent" "$f" '^key: backlog_key_absent$'
    expect "$L.default.krb5kdc-active" "$f" '^krb5kdc: active$'
    expect "$L.default.sockets" "$f" "$(bl_sockets_rx)"
    expect "$L.default.backlog" "$f" "^backlog: 464=5 749=2 88=$b88\$"                      # record: vm/lab.txt:60-65 (ours), :119-124 (MIT); upgrade.sh:39
    bl_run "$st" key5
    f="$OUT/bl/$st-key5.txt"
    expect "$L.key5.restart-rc" "$OUT/bl/$st-run-key5.txt" '^RESTART_RC:0$'
    expect "$L.key5.key-set" "$f" '^key: [0-9]+:[[:space:]]*kdc_tcp_listen_backlog = 5$'
    expect "$L.key5.backlog" "$f" '^backlog: 464=5 749=2 88=5$'                              # record: vm/lab.txt:87-99 (ours: 128 -> 5)
    bl_run "$st" key64
    f="$OUT/bl/$st-key64.txt"
    expect "$L.key64.restart-rc" "$OUT/bl/$st-run-key64.txt" '^RESTART_RC:0$'
    expect "$L.key64.key-set" "$f" '^key: [0-9]+:[[:space:]]*kdc_tcp_listen_backlog = 64$'
    expect "$L.key64.backlog" "$f" '^backlog: 464=5 749=2 88=64$'
    bl_run "$st" restore
    f="$OUT/bl/$st-restore.txt"
    expect "$L.restore.restart-rc" "$OUT/bl/$st-run-restore.txt" '^RESTART_RC:0$'
    expect "$L.restore.key-absent" "$f" '^key: backlog_key_absent$'
    expect "$L.restore.sockets" "$f" "$(bl_sockets_rx)"
    expect "$L.restore.backlog" "$f" "^backlog: 464=5 749=2 88=$b88\$"
    return 0
}

bl_mit() { bl_stage mit; }
bl_ours() { bl_stage ours; }

bl_parity() {
    local c m o
    local cite="docs/mit-deviations.md:19"
    # the cells whose rows are the same in both stages: the key at 5 and at 64 (the key means the same), the socket set
    for c in key5 key64; do
        parity_eq "BL.parity.$c.backlog" <(grep '^backlog: ' "$OUT/bl/mit-$c.txt") <(grep '^backlog: ' "$OUT/bl/ours-$c.txt")
    done
    parity_eq BL.parity.default.sockets <(grep '^sockets: ' "$OUT/bl/mit-default.txt") <(grep '^sockets: ' "$OUT/bl/ours-default.txt")
    parity_eq BL.parity.default.port-464-749 <(grep '^backlog: ' "$OUT/bl/mit-default.txt" | sed -E 's/ 88=[0-9]+$//') <(grep '^backlog: ' "$OUT/bl/ours-default.txt" | sed -E 's/ 88=[0-9]+$//')
    # the documented deviation: the default of port 88 (MIT 5, ours 128); kadmind's kpasswd (5) and RPC (2) listeners are the same
    parity_dev BL.parity.default.port-88.capacity "$cite" "$OUT/bl/mit-default.txt" '^backlog: 464=5 749=2 88=5$' "$OUT/bl/ours-default.txt" '^backlog: 464=5 749=2 88=128$'
    # the controls: a doctored copy of ours differs; the deviation row fails when MIT's cell is doctored to ours' number
    parity_control BL.parity.key64.backlog <(grep '^backlog: ' "$OUT/bl/mit-key64.txt") <(grep '^backlog: ' "$OUT/bl/ours-key64.txt")
    m="$OUT/bl/control-mit-default.txt"; sed 's/88=5$/88=128/' "$OUT/bl/mit-default.txt" > "$m"
    o=$(grep -cE '^backlog: 464=5 749=2 88=5$' "$m" || true)
    if [ "${o:-0}" = 0 ]; then verdict BL.parity.default.port-88.capacity.control PASS "a doctored MIT cell (88=5 turned into 88=128) must not hold the deviation row's MIT fact" 0 "$o"
    else verdict BL.parity.default.port-88.capacity.control FAIL "a doctored MIT cell (88=5 turned into 88=128) must not hold the deviation row's MIT fact" 0 "$o"; fi
    return 0
}

bl_clean() {   # kdc.conf is put back in the stage (restore); once more, quietly
    vm kdc "sudo env VMCTL_D=$VMD python3 -I $VMD/b2a/b2a-kdcconf.py" > /dev/null 2>&1
    return 0
}
