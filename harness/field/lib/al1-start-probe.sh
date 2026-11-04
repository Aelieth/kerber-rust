#!/usr/bin/env bash
# al1-start-probe.sh <realm> <dict|port>: run /usr/sbin/kadmind -nofork once against a throwaway profile
# that injects one start-up failure, and print a structured record. Run as root on the kdc VM, against
# the realm the leg's upgrade left; it leaves nothing behind. Used by scenarios/kadmind-start.sh (cells
# A1b and A1c), MIT first then kerber-rust: the same binary path, whichever the leg installed.
#   dict  (A1b): dict_file is a symlink loop, so open() returns ELOOP (not ENOENT, which both skip) and
#                the password-dictionary load errors before the network, as MIT's kadm5_init does.
#   port  (A1c): kpasswd moves to a free port, so the only bind that can fail is the kadm5 program on
#                749, which the running kadmind service already holds.
# The record (one line each): conf: the injected line; rc=<kadmind exit>; the stdout and stderr blocks;
# stderr-abort / stderr-neterr: how many of each message reached stderr; pidfile: present|absent;
# kadmind-procs: the count still running (the service is one).
set -u
realm=${1:?realm} mode=${2:?mode: dict or port}
kadmind=/usr/sbin/kadmind
src=/var/kerberos/krb5kdc/kdc.conf
# The throwaway profile lives beside the real kdc.conf so its SELinux label (krb5kdc_conf_t) lets kadmind
# read it; /tmp would be denied in enforcing mode.
d=$(mktemp -d /var/kerberos/krb5kdc/al1-start.XXXXXX) || exit 2
trap 'rm -rf "$d"' EXIT
pid=$d/kadmind.pid
drop=
case $mode in
    dict)
        ln -s loop "$d/loop"            # a->a: open() fails ELOOP
        ins="        dict_file = $d/loop"
        drop=dict_file ;;               # drop the realm's own dict_file so only the loop is read
    port)
        ins="        kpasswd_port = 60749" ;;
    *) echo "mode must be dict or port" >&2; exit 2 ;;
esac
# Copy the realm's kdc.conf: drop any existing <drop> relation first (so the injected dict_file is the only
# one, whichever a duplicate the profile would prefer), then add the override just after the realm's opening
# brace. index(), so a realm name with dots needs no escaping; done guards the first realm block.
awk -v r="$realm" -v ins="$ins" -v drop="$drop" '
    drop != "" && $0 ~ ("^[[:space:]]*" drop "[[:space:]]*=") { next }
    { print }
    index($0,r)>0 && index($0,"{")>0 && !done { print ins; done=1 }
' "$src" > "$d/kdc.conf"
chcon --reference="$src" "$d/kdc.conf" 2>/dev/null || true
grep -nE '^[[:space:]]*(dict_file|kpasswd_port)[[:space:]]*=' "$d/kdc.conf" | sed 's/^/conf: /'
# Run kadmind in the foreground. It must fail fast; the 15 s cap is a safety net, not the expected path.
rc=0
KRB5_KDC_PROFILE=$d/kdc.conf timeout 15 "$kadmind" -nofork -P "$pid" > "$d/out" 2> "$d/err" || rc=$?
echo "rc=$rc"
echo "--- stdout"; cat "$d/out"
echo "--- stderr"; cat "$d/err"
echo "stderr-abort: $(grep -c 'while initializing, aborting' "$d/err" 2>/dev/null || echo 0)"
echo "stderr-neterr: $(grep -c 'Error setting up network' "$d/err" 2>/dev/null || echo 0)"
[ -e "$pid" ] && echo "pidfile: present" || echo "pidfile: absent"
echo "kadmind-procs: $(pgrep -xc kadmind 2>/dev/null || echo 0)"
