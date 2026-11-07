#!/bin/bash
# b2c-vm.sh SUBCOMMAND [args]: the B2 client modules' (pg1 pg2 pg3 pl p6g p6l) helper on a lab VM. Pushed by the modules to $VMD/b2c-vm.sh (stdin, sha256 checked both sides).
# Nothing is installed by it. The password of a login arrives on stdin and is never printed. Runs as the ssh user (login, run) or as root (pcap-*, krb5conf-*, clean via sudo).
#   login [--conf F] [--cc PATH] [--mkdir DIR]... [--delay N] [--env K=V]... [--then 'CMD']... -- PROG ARGS...
#                              one login: PROG (kinit, MIT's or ours) with ARGS, stdin = exactly what the program reads (one password line, or none), KRB5_CONFIG=F, KRB5_TRACE=<tmp>;
#                              PATH is removed first (rm -rf, a FILE: or DIR: cache's path), each --mkdir DIR is made (0700); --delay N: the password reaches the program N seconds after it started; prints "[rc=N]", PROMPT=yes|no (the prompt "Password for " is on stdout), stdout bytes and sha256 and lines,
#                              stderr, the trace (cookies masked), whether PATH exists afterwards, then each --then command (sh -c, same environment) under "== then: CMD" with "[then-rc=N]"
#   run [--env K=V]... [--rm PATH]... [--timeout N] [--in-stdin] -- PROG ARGS...
#                              one command: "[rc=N]", "== stdout" (verbatim), "== stderr"; stdin is /dev/null unless --in-stdin
#   pcap-start NAME [FILTER]   tcpdump -i any --immediate-mode (as root; sudo bash b2c-vm.sh) into $D/b2c/pcap-NAME.pcap, filter default "port 88"; waits until it listens
#   pcap-stop NAME             stop it; prints the size in bytes and tcpdump's own statistics (`PCAP_STATS NAME captured=N received=N dropped=N`)
#   pcap-get NAME              the capture on stdout (binary); pcap-rm NAME deletes it
#   krb5conf-set TAG           /etc/krb5.conf := the original (kept as $D/b2c/krb5.conf.TAG) + the stanza on stdin, in place; prints the diff
#   krb5conf-restore TAG       /etc/krb5.conf := the kept original, in place (the same inode: label and mode stay); prints both sha256
#   facts                      the tools the modules rely on (tcpdump, python3, locale -a de_DE, sudo)
#   workcheck                  the pre-cell check of a module (b2c_work_ok): the work directory $D/b2c is there (made when missing) and THIS user can make a directory in it;
#                              prints "WORKDIR_OK dir user= owner= mode=" or "WORKDIR_NOT_WRITABLE dir" with the reason (stderr) and exits 1
#   clean                      remove $D/b2c (caches shredded)
# The work directory $D/b2c (mode 0700, the pcap files and the kept krb5.conf copies are in it too) belongs to the LAB USER, whichever call makes it first (mkwork below): the B2 hold of 2026-10-13 had it made by a
# `sudo bash b2c-vm.sh pcap-start` on the kdc, root's, and every later lab-user `run` there died in mktemp (58 P6L rows red).
# The paths are the Fedora VM's; VMCTL_D / VMCTL_KRB5CONF override them for the rehearsals on the host (the same variables as vmctl.sh).
set -u
D=${VMCTL_D:-/var/tmp/otp3}
W=$D/b2c
KRB5CONF=${VMCTL_KRB5CONF:-/etc/krb5.conf}
sub=${1:-}
[ $# -gt 0 ] && shift

mkwork() {   # $W exists (0700) and is OWNED BY THE LAB USER, and the calling user can make a directory in it; status 1 with the reason on stderr otherwise.
    # Under sudo (pcap-*, krb5conf-*, clean) the owner is SUDO_UID:SUDO_GID; as root any other way, the owner of the parent $D (the lab user's: the modules' push made it). A root-owned $W that an older copy of this
    # helper left behind is given back to the lab user by the next call that runs as root. The last step is the real thing, not a test(1) guess: a directory made and removed in $W.
    local u g t
    [ -d "$W" ] || install -d -m 0700 "$W" || { echo "b2c-vm.sh: cannot make $W" >&2; return 1; }
    if [ "$(id -u)" = 0 ]; then
        u=${SUDO_UID:-}; g=${SUDO_GID:-}
        case "$u:$g" in *[!0-9:]* | : | :* | *:) u=""; g="" ;; esac
        if [ -z "$u" ] || [ "$u" = 0 ]; then u=$(stat -c %u "$D" 2> /dev/null); g=$(stat -c %g "$D" 2> /dev/null); fi
        if [ -n "$u" ] && [ -n "$g" ] && [ "$u" != 0 ]; then chown "$u:$g" "$W" 2> /dev/null || echo "b2c-vm.sh: cannot give $W to $u:$g" >&2; fi
    fi
    if ! t=$(mktemp -d "$W/probe.XXXXXX" 2>&1); then
        echo "b2c-vm.sh: the work directory $W is not writable by $(id -un) (owner $(stat -c %U:%G "$W" 2> /dev/null), mode $(stat -c %a "$W" 2> /dev/null)): $t" >&2
        return 1
    fi
    rmdir "$t"
    return 0
}

case $sub in
login)
    CONF=""; CCP=""; ENVS=(); THENS=(); MKD=(); DELAY=0
    while [ $# -gt 0 ]; do
        case $1 in
            --conf) CONF=$2; shift 2 ;;
            --cc) CCP=$2; shift 2 ;;
            --mkdir) MKD+=("$2"); shift 2 ;;
            --delay) DELAY=$2; shift 2 ;;
            --env) ENVS+=("$2"); shift 2 ;;
            --then) THENS+=("$2"); shift 2 ;;
            --) shift; break ;;
            *) echo "b2c-vm.sh login: bad option $1" >&2; exit 2 ;;
        esac
    done
    [ $# -ge 1 ] || { echo "b2c-vm.sh login: no program" >&2; exit 2; }
    mkwork || exit 1
    TD=$(mktemp -d "$W/login.XXXXXX")
    IN=$(cat; printf x); IN=${IN%x}
    [ -n "$CCP" ] && rm -rf "$CCP"
    for d in "${MKD[@]+"${MKD[@]}"}"; do mkdir -p "$d" && chmod 0700 "$d"; done
    EA=(KRB5_TRACE="$TD/trace")
    [ -n "$CONF" ] && EA+=(KRB5_CONFIG="$CONF")
    [ ${#ENVS[@]} -gt 0 ] && EA+=("${ENVS[@]}")
    # --delay N: the program starts at once (it prints its prompt and blocks reading), the password arrives N seconds later
    { [ "$DELAY" -gt 0 ] && sleep "$DELAY"; printf '%s' "$IN"; } | env "${EA[@]}" timeout $((DELAY + 120)) "$@" > "$TD/stdout" 2> "$TD/stderr"
    rc=${PIPESTATUS[1]}
    echo "[rc=$rc]"
    if grep -q '^Password for ' "$TD/stdout"; then echo "PROMPT=yes"; else echo "PROMPT=no"; fi
    echo "stdin-bytes $(printf '%s' "$IN" | wc -c)"
    echo "== stdout"
    echo "stdout-bytes $(wc -c < "$TD/stdout")"
    echo "stdout-sha256 $(sha256sum < "$TD/stdout" | cut -d' ' -f1)"
    sed 's/^/stdout-line: /' "$TD/stdout"
    echo "== stderr"
    cat "$TD/stderr"
    echo "== trace"
    # the cookie is the KDC's opaque state, not part of any judgement: masked (the redact filter masks the key and timestamp values)
    sed -E 's/(Received cookie: ).*/\1<masked>/' "$TD/trace" 2>/dev/null
    echo "== ccache"
    if [ -n "$CCP" ]; then
        if [ -e "$CCP" ]; then echo "ccache written"; else echo "no ccache was written"; fi
    else
        echo "(no cache path given)"
    fi
    for c in "${THENS[@]+"${THENS[@]}"}"; do
        echo "== then: $c"
        env "${EA[@]}" sh -c "$c" 2>&1 < /dev/null
        echo "[then-rc=$?]"
    done
    rm -rf "$TD"
    ;;
run)
    ENVS=(); RMS=(); INS=0; TMO=120
    while [ $# -gt 0 ]; do
        case $1 in
            --env) ENVS+=("$2"); shift 2 ;;
            --rm) RMS+=("$2"); shift 2 ;;
            --timeout) TMO=$2; shift 2 ;;
            --in-stdin) INS=1; shift ;;
            --) shift; break ;;
            *) echo "b2c-vm.sh run: bad option $1" >&2; exit 2 ;;
        esac
    done
    [ $# -ge 1 ] || { echo "b2c-vm.sh run: no program" >&2; exit 2; }
    mkwork || exit 1
    TD=$(mktemp -d "$W/run.XXXXXX")
    for p in "${RMS[@]+"${RMS[@]}"}"; do rm -rf "$p"; done
    if [ "$INS" = 1 ]; then
        env ${ENVS[@]+"${ENVS[@]}"} timeout "$TMO" "$@" > "$TD/stdout" 2> "$TD/stderr"
    else
        env ${ENVS[@]+"${ENVS[@]}"} timeout "$TMO" "$@" > "$TD/stdout" 2> "$TD/stderr" < /dev/null
    fi
    rc=$?
    echo "[rc=$rc]"
    echo "== stdout"
    cat "$TD/stdout"
    echo "== stderr"
    cat "$TD/stderr"
    rm -rf "$TD"
    ;;
pcap-start)
    name=${1:?name}; filter=${2:-port 88}
    mkwork || exit 1
    f=$W/pcap-$name.pcap
    rm -f "$f" "$W/pcap-$name.pid" "$W/pcap-$name.log"
    # a new session, stdin /dev/null; -Z root: keep the capture file ours (tcpdump would otherwise drop to user tcpdump and not write under $W);
    # -s 65535 -B 16384: the snaplen is the whole of any packet a loopback or GRO segment can be (65535) and the kernel buffer 16 MiB. The first version had -s 0 (snaplen 262144): the kernel sizes its buffer slots by the snaplen, so
    # the default buffer held a few dozen packets and a burst that found tcpdump not scheduled for a few milliseconds was dropped by the kernel (the rehearsal of 2026-10-13 on a loaded host: three packets of one TCP exchange
    # missing from a PG3 capture, 'AS-REQ 7 where 8'; a test of 400 packets in bursts of 40 with busy CPUs: 438 of 800 dropped with -s 0, none with -s 9000, -s 65535 -B 16384 or -s 2048)
    # shellcheck disable=SC2086,SC2016  # the filter is words on purpose; the inner script is single-quoted for the inner shell
    setsid nohup bash -c 'echo $$ > "$1"; shift; exec "$@"' _ "$W/pcap-$name.pid" tcpdump -i any -n -s 65535 -B 16384 -U --immediate-mode -Z root -w "$f" $filter < /dev/null > "$W/pcap-$name.log" 2>&1 &
    t=0
    until grep -q 'listening on' "$W/pcap-$name.log" 2>/dev/null; do
        if [ "$t" -ge 100 ]; then echo "PCAP_NOT_LISTENING $name"; cat "$W/pcap-$name.log" 2>/dev/null; exit 1; fi
        sleep 0.1; t=$((t + 1))
    done
    echo "PCAP_STARTED $name"
    ;;
pcap-stop)
    name=${1:?name}
    pf=$W/pcap-$name.pid
    if [ -s "$pf" ]; then
        pid=$(cat "$pf")
        # the last segments reach the capture: --immediate-mode delivers a packet as it arrives (tcpdump's default waits up to a second for a block); wait until the file stops growing
        sleep 1
        a=-1; b=$(wc -c < "$W/pcap-$name.pcap" 2>/dev/null || echo 0); t=0
        while [ "$a" != "$b" ] && [ "$t" -lt 20 ]; do a=$b; sleep 0.3; b=$(wc -c < "$W/pcap-$name.pcap" 2>/dev/null || echo 0); t=$((t + 1)); done
        kill -TERM "$pid" 2>/dev/null
        t=0
        while kill -0 "$pid" 2>/dev/null; do
            [ "$t" -ge 50 ] && { kill -KILL "$pid" 2>/dev/null; echo "KILLED tcpdump $pid"; break; }
            sleep 0.1; t=$((t + 1))
        done
        rm -f "$pf"
    fi
    chmod 0644 "$W/pcap-$name.pcap" 2>/dev/null
    echo "PCAP_STOPPED $name bytes=$(wc -c < "$W/pcap-$name.pcap" 2>/dev/null || echo 0)"
    # tcpdump's own statistics (it prints them to stderr when it ends): a packet the kernel dropped is missing from the capture, and every count of messages in it is then short
    if grep -q 'packets captured' "$W/pcap-$name.log" 2>/dev/null; then
        awk '/packets captured/ { c = $1 } /packets received by filter/ { r = $1 } /packets dropped by kernel/ { d = $1 } END { printf "PCAP_STATS '"$name"' captured=%d received=%d dropped=%d\n", c, r, d }' "$W/pcap-$name.log"
    else
        echo "PCAP_STATS $name unknown (no statistics in tcpdump's log)"
    fi
    ;;
pcap-get)
    cat "$W/pcap-${1:?name}.pcap"
    ;;
pcap-rm)
    rm -f "$W/pcap-${1:?name}.pcap" "$W/pcap-${1:?name}.log"
    echo "PCAP_REMOVED $1"
    ;;
krb5conf-set)
    tag=${1:?tag}
    STANZA=$(cat)
    mkwork || exit 1
    keep=$W/krb5.conf.$tag
    [ -e "$keep" ] || cp -p "$KRB5CONF" "$keep" || { echo "cannot keep the original krb5.conf"; exit 1; }
    echo "kept the original: $keep sha256 $(sha256sum < "$keep" | cut -d' ' -f1)"
    # in place (the same inode, so the file keeps its SELinux label and mode)
    { cat "$keep"; if [ -n "$STANZA" ]; then printf '\n%s\n' "$STANZA"; fi; } > "$KRB5CONF"
    echo "== diff -u krb5.conf.$tag krb5.conf"
    diff -u "$keep" "$KRB5CONF"
    ls -lZ "$KRB5CONF"
    ;;
krb5conf-restore)
    tag=${1:?tag}
    keep=$W/krb5.conf.$tag
    [ -f "$keep" ] || { echo "no kept krb5.conf.$tag"; exit 1; }
    cat "$keep" > "$KRB5CONF" || exit 1
    echo "krb5.conf put back from $tag: kept sha256 $(sha256sum < "$keep" | cut -d' ' -f1), file sha256 $(sha256sum < "$KRB5CONF" | cut -d' ' -f1)"
    ;;
workcheck)
    if mkwork; then
        echo "WORKDIR_OK $W user=$(id -un) owner=$(stat -c %U "$W") mode=$(stat -c %a "$W")"
    else
        echo "WORKDIR_NOT_WRITABLE $W"
        exit 1
    fi
    ;;
facts)
    echo "tcpdump: $(command -v tcpdump 2>&1)"
    echo "python3: $(command -v python3 2>&1)"
    echo "sudo: $(sudo -n true 2>&1 && echo ok)"
    echo "locale-a: $(locale -a 2>/dev/null | grep -c -i '^de_DE')"
    echo "LANG=${LANG:-}"
    ;;
clean)
    if [ -d "$W" ]; then
        for pf in "$W"/pcap-*.pid; do   # a capture still running (a hook that stopped early)
            [ -s "$pf" ] && kill -TERM "$(cat "$pf")" 2>/dev/null
        done
        find "$W" -type f \( -name '*.cc' -o -name 'tkt*' -o -name 'primary' -o -name '*.pcap' \) -print0 2>/dev/null | while IFS= read -r -d '' f; do shred -u "$f" 2>/dev/null || rm -f "$f"; done
        rm -rf "$W"
    fi
    echo "B2C_CLEAN_OK $(find "$W" -type f 2>/dev/null | wc -l) files left"
    ;;
*)
    echo "b2c-vm.sh: unknown subcommand '$sub'" >&2
    exit 2
    ;;
esac
