#!/bin/bash
# kp-vm.sh SECTION [ARGS]: KP's client2-side steps (the replica), as root: `sudo bash kp-vm.sh SECTION ...`. (lab-agent; module mod/kp.sh; VM-LEG.md)
# Pushed by the module to $VMD/kp/ (0700) with the rpm and our two programs (ours-kpropd, ours-kdc). Everything the replica makes is under $VMD/kp/r (0700): the ACL, the stash, a kdc.conf profile and
# a krb5.conf per flavor (mit = MIT's kpropd/kdb5_util/krb5kdc from krb5-server, ours = the ship build), the received dump, the replica database, the daemons' logs. kpropd and the loader find the replica's
# database and stash through KRB5_KDC_PROFILE (both MIT's and ours read it), so /var/kerberos/krb5kdc, which the shell watches, is touched only by the rpm itself, and the rpm is removed before the module returns.
# Sections: init | stash-install (stdin) | profile FLAVOR | mit-install SRC | mit-remove | replica-reset FLAVOR | kpropd-start MODE | kpropd-stop FLAVOR | replica-report MODE |
#           kdc-start FLAVOR | e2e FLAVOR | kdc-stop FLAVOR | nft-on | nft-off | avc-mark | avc-check MARK | cleanup
# The paths are the Fedora VM's; KP_SBIN (where MIT's server programs are), KP_DBMOD_DIR (a [dbmodules] db_module_dir) and VMCTL_D / VMCTL_KT override them for the rehearsals on the host.
set -u
SECTION=${1:?section}; [ $# -gt 0 ] && shift
D=${VMCTL_D:-/var/tmp/otp3}
KPD=$D/kp
R=$KPD/r
KT=${VMCTL_KT:-/etc/krb5.keytab}
SBIN=${KP_SBIN:-/usr/sbin}
REALM=KERBER.TEST
E2EPORT=${KP_E2E_PORT:-8088}
RPMP=krb5-server

listening() {   # listening PORT SECONDS: a TCP listener on PORT (any address) within SECONDS
    local _
    for _ in $(seq 1 $(( $2 * 5 ))); do
        ss -H -lnt "sport = :$1" 2> /dev/null | grep -q . && return 0
        sleep 0.2
    done
    return 1
}
stop_pid() {   # stop_pid PIDFILE: the process the file names, TERM then KILL after 5 s; the file goes
    local f=$1 pid
    [ -s "$f" ] || return 0
    pid=$(cat "$f")
    if kill -0 "$pid" 2> /dev/null; then
        kill "$pid" 2> /dev/null
        for _ in $(seq 1 25); do kill -0 "$pid" 2> /dev/null || break; sleep 0.2; done
        kill -0 "$pid" 2> /dev/null && kill -9 "$pid" 2> /dev/null
    fi
    rm -f "$f"
}
flavor_of() { case $1 in mit|mit-*) echo mit ;; ours|ours-*) echo ours ;; *) echo "kp-vm.sh: unknown flavor/mode '$1'" >&2; exit 2 ;; esac; }
names_sha16() {   # names_sha16 FILE: a short hash of the sorted principal names of a dump text (the same words from MIT's dump and from ours: the records differ in form, the names do not)
    grep '^princ' "$1" 2> /dev/null | awk -F'\t' '{ print $7 }' | LC_ALL=C sort | sha256sum | cut -c1-16
}
count_in() {   # count_in FILE REGEX
    grep -c -- "$2" "$1" 2> /dev/null || true
}

case $SECTION in
init)
    install -d -m 0700 "$KPD" "$R" "$R/mit" "$R/ours"
    printf 'host/kdc.kerber.test@%s\n' "$REALM" > "$R/kpropd.acl"; chmod 600 "$R/kpropd.acl"
    echo "hostname: $(hostname) / $(hostname -f 2>&1)"
    echo "resolves kdc.kerber.test: $(getent hosts kdc.kerber.test | head -n 1)"
    echo "== klist -ke $(basename "$KT")"
    klist -ke "$KT" 2>&1 | sed -n '1,14p'
    echo "== kpropd.acl"; cat "$R/kpropd.acl"
    echo "SELinux: $(getenforce 2>&1)"
    echo "firewalld: $(systemctl is-active firewalld 2>&1)"
    echo "nft: $(command -v nft || echo none)"
    echo "listeners on 754 and $E2EPORT: $(ss -H -lnt "( sport = :754 or sport = :$E2EPORT )" 2> /dev/null | wc -l)"
    echo "krb5-server before: $(rpm -q $RPMP 2>&1 | head -n 1)"
    echo "INIT_OK"
    ;;
stash-install)   # stdin = the realm's stash, from the kdc through the host's pipe (never a file on the host)
    ( umask 077; cat > "$R/stash" ) && chmod 600 "$R/stash"
    echo "STASH_BYTES $(stat -c %s "$R/stash" 2>&1)"
    ;;
profile)   # profile FLAVOR: the replica's kdc.conf (profile) and krb5.conf for that flavor's daemons
    f=${1:?flavor}
    cat > "$R/$f/kdc.conf" <<EOF
[kdcdefaults]
    kdc_listen = 127.0.0.1:$E2EPORT
    kdc_tcp_listen = 127.0.0.1:$E2EPORT

[realms]
    $REALM = {
        database_name = $R/$f/principal
        key_stash_file = $R/stash
        master_key_type = aes256-cts-hmac-sha1-96
        max_life = 24h
        max_renewable_life = 7d
        default_principal_flags = +preauth
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    }
EOF
    {
        cat <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
    udp_preference_limit = 1
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
    $REALM = {
        kdc = 127.0.0.1:$E2EPORT
    }

[logging]
    kdc = FILE:$R/$f/kdc.log
    default = FILE:$R/$f/default.log
EOF
        [ -n "${KP_DBMOD_DIR:-}" ] && printf '\n[dbmodules]\n    db_module_dir = %s\n' "$KP_DBMOD_DIR"
    } > "$R/$f/krb5.conf"
    chmod 600 "$R/$f/kdc.conf" "$R/$f/krb5.conf"
    echo "== $f/kdc.conf"; cat "$R/$f/kdc.conf"
    echo "PROFILE_OK $f"
    ;;
mit-install)   # mit-install SRC: SRC is the pushed rpm (a path) or a package name-version-release; the dry run first (its transaction is the record), then the install
    src=${1:?rpm path or name-version-release}
    echo "== source"
    if [ -f "$src" ]; then
        ls -l "$src"; echo "sha256 $(sha256sum < "$src" | cut -d' ' -f1)"
        echo "== rpmkeys --checksig -v (this VM)"; rpmkeys --checksig -v "$src" 2>&1
    else
        echo "repository package $src"
    fi
    echo "== rpm -q before"; rpm -q $RPMP words 2>&1
    echo "== dnf -y install --assumeno"; dnf -y install --assumeno "$src" 2>&1; echo "DRYRUN_RC=$?"
    echo "== dnf -y install"; dnf -y install "$src" 2>&1; echo "INSTALL_RC=$?"
    echo "== rpm -q after"; rpm -q $RPMP krb5-libs krb5-pkinit words 2>&1
    echo "== sudo rpm -V $RPMP"; rpm -V $RPMP 2>&1; echo "rpm -V rc=$?"
    echo "== programs"; ls -l "$SBIN/kpropd" "$SBIN/kdb5_util" "$SBIN/kprop" "$SBIN/krb5kdc" 2>&1
    echo "== labels"; ls -Z "$SBIN/kpropd" 2>&1
    ;;
mit-remove)
    echo "== dnf -y remove"; dnf -y remove $RPMP 2>&1; echo "REMOVE_RC=$?"
    echo "== after"; rpm -q $RPMP words 2>&1
    ls -d /var/kerberos/krb5kdc 2>&1
    ;;
replica-reset)   # replica-reset FLAVOR: no replica database, no received dump (the next load makes the database)
    f=${1:?flavor}
    rm -f "$R/$f"/principal* "$R/$f/recv.dump" "$R/$f/replica.dump"
    echo "RESET $f: $(find "$R/$f" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' ')"
    ;;
kpropd-start)   # kpropd-start MODE: mit-transport (MIT, the loader is /bin/true) | mit-load | mit-noacl (MIT, the ACL file is missing) | ours | ours-noacl
    mode=${1:?mode}; fl=$(flavor_of "$mode")
    rm -f "$R/$fl/kpropd.log" "$R/$fl/kpropd.pid" "$R/$fl/kpropd.runner" "$R/$fl/recv.dump"
    acl=$R/kpropd.acl; case $mode in *-noacl) acl=$R/no-such.acl ;; esac
    case $mode in
        mit-transport)  set -- "$SBIN/kpropd" -S -d -a "$acl" -s "$KT" -P 754 -f "$R/mit/recv.dump" -p /bin/true ;;
        mit-load|mit-noacl) set -- "$SBIN/kpropd" -S -d -a "$acl" -s "$KT" -P 754 -f "$R/mit/recv.dump" -p "$SBIN/kdb5_util" ;;
        mit-load-pid) set -- "$SBIN/kpropd" -S -d -a "$acl" -s "$KT" -P 754 -f "$R/mit/recv.dump" -p "$SBIN/kdb5_util" --pid-file "$R/mit/kpropd.pid" ;;
        ours) set -- "$KPD/ours-kpropd" -S -d -a "$acl" -s "$KT" -P 754 -f "$R/ours/recv.dump" -p "$KPD/kdb5_util" --pid-file "$R/ours/kpropd.pid" ;;
        ours-noacl) set -- "$KPD/ours-kpropd" -r "$REALM" -s "$KT" -a "$acl" 0.0.0.0:754 ;;
        *) echo "kp-vm.sh: unknown kpropd mode '$mode'" >&2; exit 2 ;;
    esac
    echo "== command"; echo "KRB5_KDC_PROFILE=$R/$fl/kdc.conf $*" | sed "s#$R/#R/#g; s#$KPD/#KP/#g"
    KRB5_KDC_PROFILE=$R/$fl/kdc.conf setsid nohup "$@" > "$R/$fl/kpropd.log" 2>&1 < /dev/null &
    case $mode in
        mit-load-pid|ours)
            echo $! > "$R/$fl/kpropd.runner"
            if listening 754 20; then echo "LISTENING 754 pid $(cat "$R/$fl/kpropd.runner")"; else echo "NOT_LISTENING 754"; fi
            line=$(head -n 1 "$R/$fl/kpropd.pid" 2>/dev/null || true)
            echo "PIDFILE_LINE ${line:-ABSENT}"
            if [ -n "$line" ] && [ "$line" = "$(cat "$R/$fl/kpropd.runner")" ]; then echo PIDFILE_EQ_DAEMON yes; else echo PIDFILE_EQ_DAEMON no; fi
            ;;
        *)
            echo $! > "$R/$fl/kpropd.pid"
            if listening 754 20; then echo "LISTENING 754 pid $(cat "$R/$fl/kpropd.pid")"; else echo "NOT_LISTENING 754"; fi
            ;;
    esac
    ;;
kpropd-pid-fail)   # kpropd-pid-fail FLAVOR: --pid-file in a directory that is not there. Foreground..
    fl=$(flavor_of "${1:?flavor}")
    case $fl in
        mit) bin=$SBIN/kpropd; loader=$SBIN/kdb5_util ;;
        ours) bin=$KPD/ours-kpropd; loader=$KPD/kdb5_util ;;
    esac
    since=$(date '+%Y-%m-%d %H:%M:%S')
    set -- "$bin" -S -d -a "$R/kpropd.acl" -s "$KT" -P 754 -f "$R/$fl/recv.dump" -p "$loader" --pid-file /nonexistent/dir/kpropd.pid
    echo "== command"; echo "KRB5_KDC_PROFILE=$R/$fl/kdc.conf $*" | sed "s#$R/#R/#g; s#$KPD/#KP/#g"
    KRB5_KDC_PROFILE=$R/$fl/kdc.conf timeout 20 "$@" > "$R/$fl/pid-fail.out" 2>&1
    echo "PIDFAIL_RC=$?"
    echo "== kpropd out"; sed "s#$R/#R/#g; s#$KPD/#KP/#g" "$R/$fl/pid-fail.out" 2>&1
    echo "== journal"
    journalctl -t kpropd --no-pager --since "$since" 2>&1 | cut -c1-200
    ;;
kpropd-stop)   # kpropd-stop FLAVOR|MODE: the daemon ends; its log is the record
    fl=$(flavor_of "${1:?flavor}")
    sleep 1
    if [ -s "$R/$fl/kpropd.runner" ]; then stop_pid "$R/$fl/kpropd.runner"; rm -f "$R/$fl/kpropd.pid"; else stop_pid "$R/$fl/kpropd.pid"; fi
    echo "== kpropd log ($fl)"; sed "s#$R/#R/#g; s#$KPD/#KP/#g" "$R/$fl/kpropd.log" 2>&1
    echo "== listeners on 754 after"; ss -H -lnt 'sport = :754' | wc -l
    ;;
replica-report)   # replica-report MODE: what the replica holds after a kprop
    mode=${1:?mode}; fl=$(flavor_of "$mode")
    case $mode in
    mit-transport)
        f=$R/mit/recv.dump
        if [ -s "$f" ]; then
            echo "RECV_BYTES $(stat -c %s "$f")"; echo "RECV_SHA16 $(sha256sum < "$f" | cut -c1-16)"; echo "RECV_PRINCS $(count_in "$f" '^princ')"; echo "REPLICA_NAMES_SHA16 $(names_sha16 "$f")"
        else
            echo "RECV_BYTES 0"
        fi ;;
    mit-load)
        KRB5_KDC_PROFILE=$R/mit/kdc.conf "$SBIN/kdb5_util" dump "$R/mit/replica.dump" 2>&1 | head -n 3
        f=$R/mit/replica.dump
        echo "REPLICA_DUMP_BYTES $(stat -c %s "$f" 2>&1)"; echo "REPLICA_PRINCS $(count_in "$f" '^princ')"; echo "REPLICA_NAMES_SHA16 $(names_sha16 "$f")"
        printf 'REPLICA_HAS_HOSTKDC %s\nREPLICA_HAS_ALICE %s\nREPLICA_HAS_CLIENT2 %s\nREPLICA_HAS_BULK250 %s\n' "$(count_in "$f" '	host/kdc.kerber.test@')" "$(count_in "$f" '	alice@')" "$(count_in "$f" '	host/client2.kerber.test@')" "$(count_in "$f" '	bulk0250@')"
        find "$R/mit" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' '; echo
        shred -u "$f" 2> /dev/null; rm -f "$f.dump_ok" ;;
    ours)
        f=$R/ours/principal
        echo "REPLICA_DB_BYTES $(stat -c %s "$f" 2>&1)"; echo "REPLICA_DB_HEADER $(head -n 1 "$f" 2>&1)"; echo "REPLICA_PRINCS $(count_in "$f" '^princ')"; echo "REPLICA_NAMES_SHA16 $(names_sha16 "$f")"
        printf 'REPLICA_HAS_HOSTKDC %s\nREPLICA_HAS_ALICE %s\nREPLICA_HAS_CLIENT2 %s\nREPLICA_HAS_BULK250 %s\n' "$(count_in "$f" '	host/kdc.kerber.test@')" "$(count_in "$f" '	alice@')" "$(count_in "$f" '	host/client2.kerber.test@')" "$(count_in "$f" '	bulk0250@')"
        find "$R/ours" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort | tr '\n' ' '; echo ;;
    *) echo "kp-vm.sh: replica-report mit-transport|mit-load|ours" >&2; exit 2 ;;
    esac
    ;;
kdc-start)   # kdc-start FLAVOR: the replica's own KDC on 127.0.0.1:$E2EPORT, serving the database the load made
    fl=$(flavor_of "${1:?flavor}")
    rm -f "$R/$fl/kdc.pid" "$R/$fl/kdc.run" "$R/$fl/kdc.log" "$R/$fl/kdc.out"
    case $fl in mit) set -- "$SBIN/krb5kdc" -r "$REALM" -n -P "$R/mit/kdc.pid" ;; ours) set -- "$KPD/ours-kdc" -r "$REALM" -n -P "$R/ours/kdc.pid" ;; esac
    KRB5_KDC_PROFILE=$R/$fl/kdc.conf KRB5_CONFIG=$R/$fl/krb5.conf setsid nohup "$@" > "$R/$fl/kdc.out" 2>&1 < /dev/null &
    echo $! > "$R/$fl/kdc.run"
    if listening "$E2EPORT" 20; then echo "KDC_LISTENING $E2EPORT pid $(cat "$R/$fl/kdc.run")"; else echo "KDC_NOT_LISTENING $E2EPORT"; echo "== kdc.out"; cat "$R/$fl/kdc.out" 2>&1; fi
    ;;
e2e)   # e2e FLAVOR: the host's key, from the keytab, against the replica's KDC
    fl=$(flavor_of "${1:?flavor}")
    cc=$R/$fl/e2e.cc
    rm -f "$cc"
    KRB5_CONFIG=$R/$fl/krb5.conf KRB5CCNAME=FILE:$cc kinit -k -t "$KT" "host/client2.kerber.test@$REALM" < /dev/null 2>&1
    echo "[rc=$?]"
    echo "== klist"
    KRB5_CONFIG=$R/$fl/krb5.conf KRB5CCNAME=FILE:$cc klist 2>&1 | sed "s#$R/#R/#g"
    KRB5CCNAME=FILE:$cc kdestroy 2> /dev/null; rm -f "$cc"
    echo "== replica kdc log"; sed "s#$R/#R/#g" "$R/$fl/kdc.log" 2>&1
    ;;
kdc-stop)
    fl=$(flavor_of "${1:?flavor}")
    stop_pid "$R/$fl/kdc.run"
    rm -f "$R/$fl/kdc.pid"
    echo "== listeners on $E2EPORT after"; ss -H -lnt "sport = :$E2EPORT" | wc -l
    ;;
nft-on)   # a network-level refusal of 754: nft rejects the SYN with host-prohibited (an ICMP error, so the connect fails at once, not after the kernel's SYN retries)
    if ! command -v nft > /dev/null 2>&1; then echo "NFT_UNAVAILABLE"; exit 0; fi
    nft add table ip kpfilter && nft add chain ip kpfilter input '{ type filter hook input priority -10 ; policy accept ; }' && nft add rule ip kpfilter input tcp dport 754 reject with icmp type host-prohibited
    echo "NFT_ON_RC=$?"
    nft list table ip kpfilter 2>&1
    ;;
nft-off)
    if ! command -v nft > /dev/null 2>&1; then echo "NFT_UNAVAILABLE"; exit 0; fi
    nft delete table ip kpfilter 2>&1; echo "NFT_OFF_RC=$?"
    echo "ruleset lines: $(nft list ruleset 2>&1 | wc -l)"
    ;;
avc-mark) date +%T ;;
avc-check)   # avc-check MARK: the driver's form (avc_rows), on this VM
    mark=${1:?mark}
    getenforce
    d=$(ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts "$mark" 2>&1); r=$?
    [ "$r" = 1 ] || printf '%s\n' "$d"
    c=$(ausearch --input-logs -m USER_CMD -ts "$mark" 2> /dev/null | grep -c '^type=USER_CMD')
    printf 'denials: %s (ausearch rc=%s); USER_CMD control: %s records\n' "$(printf '%s\n' "$d" | tail -n 1)" "$r" "$c"
    while IFS= read -r l; do case $l in *kpropd* | *krb5kdc* | *kdb5_util*) printf '%s\n' "$l" ;; esac; done < <(ps -eZ 2> /dev/null)
    ;;
cleanup)   # best effort, quiet on success: every daemon of this module stopped, the rule gone, the secrets shredded, the rpm removed, the directory gone
    for fl in mit ours; do
        stop_pid "$R/$fl/kpropd.runner"; stop_pid "$R/$fl/kpropd.pid"; stop_pid "$R/$fl/kdc.run"
    done
    if command -v nft > /dev/null 2>&1; then nft delete table ip kpfilter > /dev/null 2>&1; fi
    if rpm -q $RPMP > /dev/null 2>&1; then dnf -y remove $RPMP > /dev/null 2>&1; echo "CLEANUP_REMOVED_RPM rc=$?"; fi
    shred -u "$R/stash" "$R"/*/principal* "$R"/*/recv.dump "$R"/*/replica.dump 2> /dev/null
    rm -rf "$R"
    echo "CLEANUP_LISTENERS $(ss -H -lnt "( sport = :754 or sport = :$E2EPORT )" 2> /dev/null | wc -l)"
    echo "CLEANUP_DONE"
    ;;
*) echo "kp-vm.sh: unknown section '$SECTION'" >&2; exit 2 ;;
esac
