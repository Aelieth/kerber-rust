#!/bin/bash
# vmctl.sh SUBCOMMAND [args]: the OTP4 lab leg's helper on a lab VM, run as root (sudo bash vmctl.sh ...).
# Pushed to /var/tmp/otp3 by driver.sh (stdin, sha256 checked). Nothing is installed by it. Secrets come on stdin only.
#   facts                      the VM's non-secret facts
#   otpplugin                  MIT's otp plugin files (rpm -ql krb5-server | grep otp)
#   conf-otp-set               kdc.conf := the original kdc.conf (kept beside it as kdc.conf.otp3-orig) + the [otp] stanza on stdin
#                              (an empty stdin leaves the original: no [otp] at all); prints the diff
#   stub-start SOCK            start radius_stub.py on a UNIX socket; stdin: the one code it accepts
#   stub-stop                  stop the stub
#   mit-restart | svc-restart  systemctl restart krb5kdc (MIT's before the install, ours after it); waits for "commencing operation";
#                              prints the service state and the KDC log lines from BEFORE the restart (the old process's "shutting down" first)
#   svc-stop                   systemctl stop krb5kdc
#   addprinc                   addprinc +requires_preauth otpuser; stdin: the lab password
#   kadm                       kadmin.local -q "<stdin line>" (so that quoting never crosses ssh)
#   klog-size | klog-since N   the KDC log: its size, and the bytes after the first N
#   stublog-size | stublog-since N
#   avc-mark | avc SINCE       the VM's clock as HH:MM:SS; AVC / USER_AVC records since SINCE (ausearch -ts), or "no AVC"
#   embed-start                stop the service KDC, run the example embedder in the background as the realm's KDC
#   embed-restart              stop the embedder, run it again (a new process, kdc.conf read afresh); log lines from BEFORE the stop
#   embed-stop                 stop the embedder
#   kcell KINIT ARMOR|- CC SVC one kinit login of otpuser (KINIT is MIT's /usr/bin/kinit or ours under $D/ours), the stdin of this call is exactly what the
#                              kinit reads on its own stdin (zero bytes = end of file at the first prompt); stdout, stderr and the KRB5_TRACE file are three
#                              separate files, printed under fixed "== " headings with the exit status first; then, when a ccache was written, MIT's klist -C and
#                              klist -f -e, our klist -C, and MIT's kvno of SVC with it
#   clean                      shred the leg's secrets and print what is left
# The paths are the Fedora VM's; VMCTL_* override them for the rehearsals on the host (rehearse.sh, flowtest.sh).
set -u
D=${VMCTL_D:-/var/tmp/otp3}
KDCDIR=${VMCTL_KDCDIR:-/var/kerberos/krb5kdc}
KDCCONF=${VMCTL_KDCCONF:-$KDCDIR/kdc.conf}
KLOG=${VMCTL_KLOG:-/var/log/krb5kdc.log}
RUNDIR=${VMCTL_RUNDIR:-/run/krb5kdc}
PORT=${VMCTL_PORT:-88}
KT=${VMCTL_KT:-/etc/krb5.keytab}
KRB5CONF=${VMCTL_KRB5CONF:-/etc/krb5.conf}
KRB5CONFD=${VMCTL_KRB5CONFD:-/etc/krb5.conf.d}
sub=${1:-}
[ $# -gt 0 ] && shift

wait_for() {   # wait_for SECONDS FILE PATTERN
    local t=0
    until grep -q -- "$3" "$2" 2>/dev/null; do
        [ "$t" -ge "$1" ] && { echo "TIMEOUT waiting for '$3' in $2"; return 1; }
        sleep 1; t=$((t + 1))
    done
}

klog_bytes() { { wc -c < "$KLOG"; } 2>/dev/null || echo 0; }

# start_detached PIDFILE OUTFILE CMD...: a new session, stdin /dev/null, stdout and stderr to OUTFILE. The pid file holds the pid of the
# command itself (the shell writes its own pid, then execs): `$!` can name the setsid wrapper instead when setsid forks.
start_detached() {
    local pidf=$1 out=$2 t=0
    shift 2
    : > "$pidf"
    # shellcheck disable=SC2016  # the single-quoted script is the inner shell's
    setsid nohup bash -c 'echo $$ > "$1"; shift; exec "$@"' _ "$pidf" "$@" </dev/null >"$out" 2>&1 &
    until [ -s "$pidf" ]; do
        [ "$t" -ge 50 ] && return 1
        sleep 0.1; t=$((t + 1))
    done
}

# stop_pid PIDFILE [SECONDS]: TERM, wait for the exit, KILL (and say so) if it will not go
stop_pid() {
    local pidf=$1 max=${2:-10} pid t=0
    [ -s "$pidf" ] || return 0
    pid=$(cat "$pidf")
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null
        while kill -0 "$pid" 2>/dev/null; do
            if [ "$t" -ge $((max * 10)) ]; then
                kill -9 "$pid" 2>/dev/null
                echo "KILLED: pid $pid ignored TERM for $max s"
                break
            fi
            sleep 0.1; t=$((t + 1))
        done
    fi
    rm -f "$pidf"
}

# the embedder: its seeds file is $D/totp.seeds, its stderr line "krb5-otp-kdc: starting..." comes after "commencing operation"
embed_run() {
    : > "$D/embed.out"
    install -m 0600 /dev/null "$D/totp.state"
    start_detached "$D/embed.pid" "$D/embed.out" env KERBER_EXAMPLE_TOTP_SEEDS="$D/totp.seeds" KERBER_EXAMPLE_TOTP_ONLY=1 KERBER_EXAMPLE_TOTP_STATE="$D/totp.state" "$D/krb5-otp-kdc" || { echo "embedder: no pid"; return 1; }
    wait_for 15 "$D/embed.out" 'starting' || { cat "$D/embed.out"; return 1; }
    sleep 1
}
embed_report() {   # embed_report N: what a started embedder shows, then the log lines from byte N
    echo "embedder pid $(cat "$D/embed.pid")"
    ps -o pid,user,label,args -p "$(cat "$D/embed.pid")"
    ss -H -lntup "sport = :$PORT" | sed 's/users:.*pid=\([0-9]*\).*/pid=\1/'
    echo "== embed.out"; cat "$D/embed.out"
    echo
    echo "# KDC log lines added by this cell ($KLOG on kdc)"
    tail -c +$(($1 + 1)) "$KLOG" 2>/dev/null
}

restart_svc() {
    local n
    n=$(klog_bytes)
    systemctl restart krb5kdc
    for _ in $(seq 40); do
        tail -c +$((n + 1)) "$KLOG" 2>/dev/null | grep -q 'commencing operation' && break
        sleep 0.5
    done
    echo "krb5kdc.service: $(systemctl is-active krb5kdc)"
    echo
    echo "# KDC log lines added by this cell ($KLOG on kdc)"
    tail -c +$((n + 1)) "$KLOG" 2>/dev/null
}

case $sub in
facts)
    echo "== $(date -u +%FT%TZ) $(hostname -f)"
    cat /etc/fedora-release; uname -r; echo "selinux: $(getenforce 2>&1)"; python3 --version
    echo "== rpm"; rpm -q krb5-libs krb5-workstation krb5-server 2>&1
    echo "== kinit klist"; command -v kinit klist; rpm -qf "$(command -v kinit)" 2>&1
    echo "== /etc/krb5.conf"; cat "$KRB5CONF"
    for f in "$KRB5CONFD"/*; do [ -f "$f" ] && { echo "== $f"; cat "$f"; }; done
    echo "== /etc/krb5.keytab (principals only)"; klist -k "$KT" 2>&1
    echo "== chrony"; chronyc tracking 2>&1 | sed -n 's/^\(Reference ID\|Stratum\|System time\|Leap status\).*/&/p'
    if [ -f "$KDCCONF" ]; then
        echo "== $KDCCONF"; cat "$KDCCONF"
        echo "== systemd"; systemctl is-active krb5kdc kadmin 2>&1; systemctl cat krb5kdc 2>&1 | sed -n '1,40p'
        echo "== listen 88/464/749"; ss -H -lntu 'sport = :88 or sport = :464 or sport = :749'
        echo "== $KLOG"; ls -lZ "$KLOG" 2>&1
        echo "== $RUNDIR"; ls -ldZ "$RUNDIR" 2>&1
    fi
    ;;
otpplugin)
    echo "== rpm -ql krb5-server | grep otp"
    rpm -ql krb5-server 2>&1 | grep -i otp
    mapfile -t so < <(rpm -ql krb5-server 2>/dev/null | grep -i 'otp.*\.so')
    if [ "${#so[@]}" -gt 0 ]; then
        echo "== ls -lZ"
        ls -lZ "${so[@]}"
        echo "== rpm -qf"
        rpm -qf "${so[@]}" 2>&1
    else
        echo "no otp plugin file listed for krb5-server"
    fi
    ;;
conf-otp-set)
    STANZA=$(cat)
    if [ ! -e "$KDCCONF.otp3-orig" ]; then
        cp -p "$KDCCONF" "$KDCCONF.otp3-orig" || { echo "cannot keep the original kdc.conf"; exit 1; }
        echo "kept the original: $KDCCONF.otp3-orig sha256 $(sha256sum < "$KDCCONF.otp3-orig" | cut -d' ' -f1)"
    fi
    # in place (the same inode, so the file keeps its SELinux label and mode)
    {
        cat "$KDCCONF.otp3-orig"
        if [ -n "$STANZA" ]; then printf '\n%s\n' "$STANZA"; fi
    } > "$KDCCONF"
    echo "== diff -u kdc.conf.otp3-orig kdc.conf"
    diff -u "$KDCCONF.otp3-orig" "$KDCCONF"
    ls -lZ "$KDCCONF"
    ;;
stub-start)
    SOCK=${1:?socket}
    IFS= read -r CODE
    [ -n "$CODE" ] || { echo "no code on stdin"; exit 1; }
    mkdir -p "$(dirname "$SOCK")"
    : > "$D/stub.log"
    start_detached "$D/stub.pid" "$D/stub.out" python3 -I "$D/radius_stub.py" --unix "$SOCK" --accept "$CODE" --name mit-stub --log "$D/stub.log" --idle 3000 || { echo "stub: no pid"; exit 1; }
    wait_for 10 "$D/stub.log" 'listening on' || exit 1
    echo "stub pid $(cat "$D/stub.pid")"; ls -lZ "$SOCK"
    ps -o pid,user,label,args -p "$(cat "$D/stub.pid")"
    cat "$D/stub.log"
    ;;
stub-stop)
    stop_pid "$D/stub.pid" 5
    echo "stub stopped"
    ;;
mit-restart|svc-restart)
    restart_svc
    ;;
svc-stop)
    systemctl stop krb5kdc
    sleep 1
    echo "krb5kdc.service: $(systemctl is-active krb5kdc)"
    tail -n 3 "$KLOG" 2>/dev/null
    ;;
addprinc)
    IFS= read -r PW
    [ -n "$PW" ] || { echo "no password on stdin"; exit 1; }
    kadmin.local -q "addprinc -pw $PW +requires_preauth otpuser"
    ;;
kadm)
    IFS= read -r CMD
    kadmin.local -q "$CMD"
    ;;
klog-size)   klog_bytes ;;
klog-since)  tail -c +$((${1:?N} + 1)) "$KLOG" 2>/dev/null ;;
stublog-size)  { wc -c < "$D/stub.log"; } 2>/dev/null || echo 0 ;;
stublog-since) tail -c +$((${1:?N} + 1)) "$D/stub.log" 2>/dev/null ;;
avc-mark) date +%T ;;
avc)
    since=${1:?since}
    echo "auditd: $(systemctl is-active auditd 2>&1); selinux: $(getenforce 2>&1)"
    out=$(ausearch -m AVC,USER_AVC -ts "$since" 2>&1)
    if printf '%s' "$out" | grep -q 'type=AVC\|type=USER_AVC'; then printf '%s\n' "$out"; else echo "no AVC since $since ($(printf '%s' "$out" | head -1))"; fi
    ;;
embed-start)
    systemctl stop krb5kdc
    sleep 1
    echo "krb5kdc.service: $(systemctl is-active krb5kdc)"
    n=$(klog_bytes)
    embed_run || exit 1
    embed_report "$n"
    ;;
embed-restart)
    n=$(klog_bytes)
    stop_pid "$D/embed.pid" 10
    echo "previous embedder stopped"
    embed_run || exit 1
    embed_report "$n"
    ;;
embed-stop)
    stop_pid "$D/embed.pid" 10
    echo "embedder stopped"
    tail -n 3 "$KLOG" 2>/dev/null
    ;;
kcell)
    # kcell KINIT ARMOR|- CC SVC: see the header. The kinit runs as root (the armor ccache and the host keytab are root's); nothing of the stdin is printed.
    KIN=${1:?kinit}; ARM=${2:?armor or -}; CC=${3:?ccache}; SVC=${4:?service}
    IN=$(cat; printf x); IN=${IN%x}
    TD=$D/kcell.$$
    install -d -m 0700 "$TD"
    rm -f "$CC"
    TARG=()
    [ "$ARM" != - ] && TARG=(-T "$ARM")
    # shellcheck disable=SC2031  # the pipe's subshell is the point: the kinit reads the offered bytes and nothing else
    printf '%s' "$IN" | env KRB5_TRACE="$TD/trace" timeout 120 "$KIN" "${TARG[@]}" -c "$CC" otpuser > "$TD/stdout" 2> "$TD/stderr"
    rc=${PIPESTATUS[1]}
    echo "[rc=$rc]"
    echo "== stdin"
    echo "bytes offered: $(printf '%s' "$IN" | wc -c) (content not recorded)"
    echo "== stdout (od -c)"
    od -c "$TD/stdout"
    echo "stdout-bytes $(wc -c < "$TD/stdout")"
    echo "stdout-sha256 $(sha256sum < "$TD/stdout" | cut -d' ' -f1)"
    echo "stdout-lines $(wc -l < "$TD/stdout")"
    sed 's/^/stdout-line: /' "$TD/stdout"
    echo "== stderr"
    cat "$TD/stderr"
    echo "== trace"
    cat "$TD/trace" 2>/dev/null
    echo "== ccache"
    if [ -e "$CC" ]; then
        echo "ccache written"
        echo "== klist -C"
        klist -C -c "$CC" 2>&1
        echo "== klist -f -e"
        klist -f -e -c "$CC" 2>&1
        echo "== our klist -C"
        if [ -x "$D/ours/klist" ]; then "$D/ours/klist" -C -c "$CC" 2>&1; else echo "(no $D/ours/klist on this VM)"; fi
        echo "== kvno $SVC"
        kvno -c "$CC" "$SVC" 2>&1
        echo "[kvno rc=$?]"
    else
        echo "no ccache was written"
    fi
    rm -rf "$TD"
    ;;
clean)
    # the seed, the codes, the armor and login ccaches, the dump and the stub's files: shredded, then removed.
    for f in "$D"/totp.seeds "$D"/*.cc "$D"/*.keytab "$D"/stub.log "$D"/stub.out "$D"/accept "$KDCDIR"/mit-realm.dump "$KDCDIR"/mit-realm.dump.dump_ok; do
        [ -e "$f" ] && { shred -u "$f" 2>/dev/null || rm -f "$f"; echo "shredded $f"; }
    done
    rm -rf "$D"/kcell.*
    rm -f "$RUNDIR/otp3.sock"
    left=$(find "$D" "$KDCDIR" -maxdepth 1 \( -name '*.cc' -o -name 'totp.seeds' -o -name '*.keytab' -o -name 'mit-realm.dump*' -o -name 'accept' \) 2>/dev/null | grep -vc kadm5.keytab)
    echo "CLEAN_OK secret files left: $left"
    ;;
*)
    echo "vmctl.sh: unknown subcommand '$sub'" >&2
    exit 2
    ;;
esac
