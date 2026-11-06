#!/bin/bash
# bl-kdc.sh STAGE SECTION: BL's listener cells (the Send-Q of the KDC's TCP listeners) on the kdc VM, as root: `sudo bash bl-kdc.sh mit|ours default|key5|key64|restore`.
# Source: lab.txt:55-65 (ours default: 88=128, 464=5, 749=2), :87-99 (the key `[kdcdefaults] kdc_tcp_listen_backlog = 5`: 88=5), :119-124 (MIT: 5 5 2); the field suite's
# listencheck (harness/field/scenarios/upgrade.sh:30-40) is the same observation in the same form: `backlog: 464=5 749=2 88=N` and the wildcard socket set.
set -u
: "${1:?mit|ours}"; SECTION=${2:?section}
. "$(dirname "$0")/b2a-lib.sh"
SS="( sport = :88 or sport = :464 or sport = :749 )"
report() {   # report NAME: CELL NAME, the key line, the listeners, upgrade.sh's two summaries, CELL_END
    echo "CELL $1"
    echo "key: $(grep -n '^[[:space:]]*kdc_tcp_listen_backlog' "$B2A_KDCDIR/kdc.conf" 2> /dev/null || echo backlog_key_absent)"
    echo "krb5kdc: $(systemctl is-active krb5kdc 2>&1)"
    ss -H -lntu "$SS" | LC_ALL=C sort
    printf 'sockets: %s\n' "$(ss -H -lntu "$SS" | awk '{ print $1, $5 }' | LC_ALL=C sort | paste -sd' ' -)"
    printf 'backlog: %s\n' "$(ss -H -lntu "$SS" | awk '$1 == "tcp" { n = split($5, a, ":"); print a[n] "=" $4 }' | LC_ALL=C sort -u | paste -sd' ' -)"
    echo "CELL_END $1"
}
restart_kdc() {   # restart krb5kdc.service and wait until it listens on tcp :88 again
    local rc
    systemctl restart krb5kdc > /dev/null 2>&1; rc=$?
    for _ in $(seq 1 50); do ss -H -lnt 'sport = :88' 2> /dev/null | grep -q . && break; sleep 0.2; done
    echo "RESTART_RC:$rc"
}
case $SECTION in
default) report default ;;
key5)    b2a_conf defaults kdc_tcp_listen_backlog 5; restart_kdc; report key5 ;;
key64)   b2a_conf defaults kdc_tcp_listen_backlog 64; restart_kdc; report key64 ;;
restore) b2a_conf; restart_kdc; report restore ;;
*) echo "bl-kdc.sh: unknown section '$SECTION'" >&2; exit 2 ;;
esac
