#!/bin/bash
# dn-vm.sh SUBCOMMAND [args]: the VM-side helper of the B2 modules DN and KL (b2-client; modules mod/dn.sh and mod/kl.sh; library helpers/dn-lib.sh; spec/dn.md, spec/kl.md). Pushed to $VMD/dn-vm.sh next to dn-stub.py ($VMD/dn/dn-stub.py);
# the subcommands marked (root) run under `sudo bash dn-vm.sh`. Nothing is installed; no system file is edited: the clients' resolver is private to one command (nsrun), and the DNS stub is a process this helper starts and stops.
#   facts                                the tools the cells rely on: python3, tcpdump, unshare, setpriv, mount, ss, ip, getent, sudo
#   kdcaddr BASECONF REALM               the first `kdc =` of REALM in BASECONF (the VM's own krb5.conf): KDC_HOST, KDC_IP (a name resolved with getent), KDC_PORT (default 88)
#   nsaddr DEST                          the address this VM uses towards DEST (ip route get): the address a DNS stub on this VM has to bind
#   sums                                 sha256 of /etc/resolv.conf and /etc/nsswitch.conf as they are (through a symlink), and who listens on port 53 (the cells prove the VM's resolver was not touched)
#   listen53 [ADDR]                      the listeners on port 53 (ss); LISTEN53_LINES N (all) and, with ADDR, LISTEN53_ON ADDR N (those bound to ADDR:53)
#   probe IP NAME TYPE [--tcp]           one query to IP:53 with dn-stub.py's probe: `<name> <TYPE> bytes=N an=N tc=<bool> rcode=N id=N`
#   dns-start NAME BIND ZONEFILE (root)  dn-stub.py serve on BIND:53 (udp and tcp) with ZONEFILE, query log $DN/dns-NAME.log, pid $DN/dns-NAME.pid; waits until it answers; prints DNS_STARTED
#   dns-stop NAME (root)                 stop it; prints DNS_STOPPED (the log stays); dns-log NAME [FROM]: the log on stdout (the lines after the first FROM); dns-logsize NAME: `DNS_LOG_LINES N`
#   nsrun --ns IP [--options STR] [--env K=V]... -- CMD ARGS... (root)
#                                        CMD in a private mount namespace in which /etc/resolv.conf is `nameserver IP` + `options STR` (default `timeout:2 attempts:2`) and /etc/nsswitch.conf is the VM's own with
#                                        `hosts: files dns`; the command runs as the sudo caller (SUDO_UID/SUDO_GID; as itself when there is none) with SSSD_KRB5_LOCATOR_DISABLE=1 (MIT's sssd locator plugin would skip DNS);
#                                        stdin, stdout and stderr are the caller's. The namespace and its two bind mounts go with the command: nothing on the VM changes.
# The paths are the Fedora VM's; VMCTL_D overrides the leg's directory for the rehearsals on the host (the same variable as vmctl.sh and b2c-vm.sh).
set -u
D=${VMCTL_D:-/var/tmp/otp3}
DN=$D/dn
W=$D/b2c
sub=${1:-}
[ $# -gt 0 ] && shift

mkwork() {   # the lab user's work directory (b2c-vm.sh makes it theirs whoever comes first)
    bash "$D/b2c-vm.sh" workcheck > /dev/null 2>&1
}

case $sub in
facts)
    for t in python3 tcpdump unshare setpriv mount ss ip getent; do printf '%s: %s\n' "$t" "$(command -v "$t" 2>&1)"; done
    echo "sudo: $(sudo -n true 2>&1 && echo ok)"
    echo "python3: $(python3 --version 2>&1)"
    ;;
kdcaddr)
    conf=${1:?base conf}; realm=${2:?realm}
    kdc=$(awk -v r="$realm" '
        /^[[:space:]]*\[/ { in_realms = ($0 ~ /^[[:space:]]*\[realms\][[:space:]]*$/); next }
        in_realms && $0 ~ "^[[:space:]]*" r "[[:space:]]*=[[:space:]]*\\{" { inblock = 1; next }
        inblock && /^[[:space:]]*\}/ { inblock = 0 }
        inblock && /^[[:space:]]*kdc[[:space:]]*=/ { sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]].*$/, ""); print; exit }' "$conf")
    [ -n "$kdc" ] || { echo "KDC_NOT_FOUND no kdc relation for $realm in $conf"; exit 1; }
    host=${kdc%%:*}; port=88
    case $kdc in *:*) port=${kdc##*:} ;; esac
    if printf '%s' "$host" | grep -qE '^[0-9]+(\.[0-9]+){3}$'; then ip=$host; else ip=$(getent ahostsv4 "$host" | awk 'NR == 1 { print $1 }'); fi
    echo "KDC_HOST=$host"
    echo "KDC_IP=${ip:-unresolved}"
    echo "KDC_PORT=$port"
    ;;
nsaddr)
    dest=${1:?dest}
    echo "NS_IP=$(ip -4 -o route get "$dest" 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n 1)"
    ;;
sums)
    echo "resolv.conf: $(sha256sum < /etc/resolv.conf | cut -d' ' -f1) $(readlink -f /etc/resolv.conf)"
    echo "nsswitch.conf: $(sha256sum < /etc/nsswitch.conf | cut -d' ' -f1) $(readlink -f /etc/nsswitch.conf)"
    echo "listeners-53: $( { ss -H -lun 'sport = :53'; ss -H -ltn 'sport = :53'; } 2>/dev/null | wc -l)"
    ;;
listen53)
    # every listener on port 53 as ss prints it, then LISTEN53_LINES N (all of them: the VM's own, e.g. systemd-resolved's stub on 127.0.0.53 and 127.0.0.54, are among them) and, when ADDR is given,
    # LISTEN53_ON ADDR N: how many are bound to ADDR:53 itself (the address the module's stub used: nothing of the module is left when it is 0)
    addr=${1:-}
    all=$( { ss -H -lun 'sport = :53'; ss -H -ltn 'sport = :53'; } 2>/dev/null )
    [ -n "$all" ] && printf '%s\n' "$all"
    echo "LISTEN53_LINES $(printf '%s' "$all" | grep -c .)"
    if [ -n "$addr" ]; then
        echo "LISTEN53_ON $addr $(printf '%s\n' "$all" | awk -v want="$addr:53" '$4 == want' | wc -l)"
    fi
    ;;
probe)
    ip=${1:?ip}; name=${2:?name}; type=${3:?type}; shift 3
    python3 -I "$DN/dn-stub.py" probe "$ip" "$name" "$type" "$@" 2>&1 || echo "PROBE_FAILED rc=$?"
    ;;
dns-start)
    name=${1:?name}; bind=${2:?bind}; zone=${3:?zone}
    mkdir -p "$DN"
    log=$DN/dns-$name.log; pidf=$DN/dns-$name.pid
    if [ -s "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null; then echo "DNS_ALREADY_RUNNING $name pid=$(cat "$pidf")"; exit 1; fi
    rm -f "$log" "$pidf"
    # a new session, stdin /dev/null; the pid is the stub's (exec after the echo)
    setsid nohup bash -c "echo \$\$ > \"\$1\"; shift; exec \"\$@\"" _ "$pidf" python3 -I "$DN/dn-stub.py" serve --bind "$bind" --zone "$zone" --log "$log" < /dev/null > "$DN/dns-$name.out" 2>&1 &
    t=0; first=$(awk '$1 == "SRV" || $1 == "A" { print $2; exit }' "$zone")
    until python3 -I "$DN/dn-stub.py" probe "$bind" "${first:-kdc.kerber.test}" SRV > /dev/null 2>&1 || python3 -I "$DN/dn-stub.py" probe "$bind" "${first:-kdc.kerber.test}" A > /dev/null 2>&1; do
        if [ "$t" -ge 50 ]; then echo "DNS_NOT_ANSWERING $name"; cat "$DN/dns-$name.out" 2>/dev/null; exit 1; fi
        sleep 0.1; t=$((t + 1))
    done
    echo "DNS_STARTED $name bind=$bind pid=$(cat "$pidf")"
    ;;
dns-stop)
    name=${1:?name}
    pidf=$DN/dns-$name.pid
    if [ -s "$pidf" ]; then
        pid=$(cat "$pidf")
        kill -TERM "$pid" 2>/dev/null
        t=0
        while kill -0 "$pid" 2>/dev/null; do
            [ "$t" -ge 30 ] && { kill -KILL "$pid" 2>/dev/null; echo "KILLED stub $pid"; break; }
            sleep 0.1; t=$((t + 1))
        done
        rm -f "$pidf"
    fi
    echo "DNS_STOPPED $name"
    ;;
dns-log)
    if [ -n "${2:-}" ]; then tail -n +$(($2 + 1)) "$DN/dns-${1:?name}.log" 2>/dev/null; else cat "$DN/dns-${1:?name}.log" 2>/dev/null; fi
    ;;
dns-logsize)
    echo "DNS_LOG_LINES $(wc -l < "$DN/dns-${1:?name}.log" 2>/dev/null || echo 0)"
    ;;
nsrun)
    ns=""; opts="timeout:2 attempts:2"; ENVS=()
    while [ $# -gt 0 ]; do
        case $1 in
            --ns) ns=$2; shift 2 ;;
            --options) opts=$2; shift 2 ;;
            --env) ENVS+=("$2"); shift 2 ;;
            --) shift; break ;;
            *) echo "dn-vm.sh nsrun: bad option $1" >&2; exit 2 ;;
        esac
    done
    [ -n "$ns" ] && [ $# -ge 1 ] || { echo "dn-vm.sh nsrun: --ns IP -- CMD" >&2; exit 2; }
    mkwork || { echo "dn-vm.sh nsrun: the work directory $W cannot be used" >&2; exit 1; }
    t=$(mktemp -d "$W/ns.XXXXXX") || exit 1
    chmod 755 "$t"
    printf 'nameserver %s\noptions %s\n' "$ns" "$opts" > "$t/resolv.conf"
    if grep -q '^hosts:' /etc/nsswitch.conf 2>/dev/null; then sed 's/^hosts:.*/hosts: files dns/' /etc/nsswitch.conf > "$t/nsswitch.conf"; else { cat /etc/nsswitch.conf 2>/dev/null; echo 'hosts: files dns'; } > "$t/nsswitch.conf"; fi
    chmod 644 "$t/resolv.conf" "$t/nsswitch.conf"
    chown "${SUDO_UID:-$(id -u)}:${SUDO_GID:-$(id -g)}" "$t" 2>/dev/null
    read -r -d '' NSRUN_SH <<'EOS' || true
        d=$1; shift
        mount --bind "$d/resolv.conf" /etc/resolv.conf && mount --bind "$d/nsswitch.conf" /etc/nsswitch.conf || { echo "dn-vm.sh nsrun: the bind mounts failed" >&2; exit 97; }
        if [ -n "${SUDO_UID:-}" ] && [ "$(id -u)" = 0 ]; then
            exec setpriv --reuid="$SUDO_UID" --regid="$SUDO_GID" --init-groups env SSSD_KRB5_LOCATOR_DISABLE=1 "$@"
        fi
        exec env SSSD_KRB5_LOCATOR_DISABLE=1 "$@"
EOS
    unshare -m --propagation private bash -c "$NSRUN_SH" nsrun "$t" ${ENVS[@]+"${ENVS[@]}"} "$@"
    rc=$?
    rm -rf "$t"
    exit $rc
    ;;
*)
    echo "dn-vm.sh: unknown subcommand '$sub'" >&2
    exit 2
    ;;
esac
