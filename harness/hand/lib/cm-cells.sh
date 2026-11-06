#!/bin/bash
# CM guest script, copied to ~/field/cm-cells.sh on each VM by rp-cm.sh.
#   prep <tag>               client: stock packages, the local user, PAM, facts
#   kdc-setup <tag>...       kdc: MIT kadmin.local makes the CM principals
#   run <leg> <tag>          client: cells 1-8 under FILE: then KCM:, then cell 9
# kdc-setup and run read "name<TAB>password" lines on stdin into ~/field/sec,
# which is shredded on exit. Cell output goes to ~/field/out/<cache>/cell<n>.out
# and .rc; lines starting INFO_ are recorded but not graded.
set -u
set +x
umask 077
F=$HOME/field
OUT=$F/out
REALM=KERBER.TEST
UID8=20101
mkdir -p "$F"

to() {
    local f=$1
    shift
    "$@" > "$f" 2>&1
}
sec() { awk -F'\t' -v k="$1" '$1 == k { print $2; exit }' "$F/sec"; }
pw2() {
    local v
    v=$(sec "$1")
    printf '%s\n%s\n' "$v" "$v"
}
take_secrets() {
    cat > "$F/sec"
    trap 'shred -u "$F/sec" 2>/dev/null || rm -f "$F/sec"' EXIT
}
family() {
    local id
    id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
    case $id in
        fedora | rocky) echo rpm ;;
        debian | ubuntu) echo deb ;;
        *) echo "unknown-$id" ;;
    esac
}

prep() {
    local tag=$1 fam rc
    fam=$(family)
    echo "FAMILY:$fam"
    echo '==== os-release ===='
    cat /etc/os-release
    case $fam in
        rpm)
            to "$F/install.out" sudo dnf install -y krb5-workstation sssd sssd-krb5 sssd-proxy sssd-kcm sssd-tools authselect python3
            rc=$?
            ;;
        deb)
            to "$F/update.out" sudo DEBIAN_FRONTEND=noninteractive apt-get update -q
            to "$F/install.out" sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q krb5-user sssd-krb5 sssd-proxy sssd-kcm sssd-tools libpam-sss libnss-sss python3
            rc=$?
            ;;
        *) rc=2 ;;
    esac
    echo "INSTALL_RC:$rc"
    [ "$rc" = 0 ] || return 1
    echo '==== packages ===='
    if [ "$fam" = rpm ]; then
        rpm -q krb5-workstation krb5-libs sssd sssd-common sssd-krb5 sssd-proxy sssd-kcm sssd-tools util-linux python3
    else
        dpkg-query -W krb5-user libkrb5-3 sssd sssd-common sssd-krb5 sssd-proxy sssd-kcm sssd-tools libpam-sss util-linux python3
    fi
    echo "SU_VERSION:$(su --version 2>&1 | head -n 1)"
    if ! id "cmu-$tag" > /dev/null 2>&1; then
        sudo useradd -m -u "$UID8" -s /bin/bash "cmu-$tag" || return 1
    fi
    echo "LOCAL_USER:$(id "cmu-$tag")"
    if [ "$fam" = rpm ]; then
        to "$F/pam.out" sudo authselect select sssd --force || return 1
        echo "PAM:$(sudo authselect current | head -n 1)"
    else
        to "$F/pam.out" sudo DEBIAN_FRONTEND=noninteractive pam-auth-update --enable sss || return 1
        echo "PAM:$(grep -c pam_sss /etc/pam.d/common-auth) pam_sss lines in common-auth"
    fi
    echo "NSS:$(grep -E '^passwd:' /etc/nsswitch.conf)"
    if zgrep -qs tgt_renewal /usr/share/man/man8/sssd-kcm.8*; then
        echo "KCM_RENEWAL_DOC:man"
    elif grep -qx 'option = tgt_renewal' /usr/share/sssd/cfg_rules.ini 2> /dev/null; then
        echo "KCM_RENEWAL_DOC:cfg_rules"
    else
        echo "KCM_RENEWAL_DOC:none"
        return 1
    fi
    sudo systemctl enable --now sssd-kcm.socket > /dev/null 2>&1 || return 1
    echo "KCM_SOCKET:$(systemctl is-active sssd-kcm.socket)"
    cat > "$F/realm.conf" << 'CFG'
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false

[realms]
    KERBER.TEST = {
        kdc = kdc.kerber.test
        admin_server = kdc.kerber.test
        kpasswd_server = kdc.kerber.test
    }

[domain_realm]
    .kerber.test = KERBER.TEST
    kerber.test = KERBER.TEST
CFG
    echo '==== ccache default ===='
    (unset KRB5CCNAME KRB5_CONFIG; klist 2>&1 | head -n 1)
    echo "PREP_OK:$tag"
}

kdc_setup() {
    local t c n
    kq() { sudo kadmin.local -q "$1"; }
    mkdir -p "$F/cm-kt"
    {
    kq "addpol -maxfailure 3 -failurecountinterval 0 -lockoutduration 0 cmlock" < /dev/null
    kq "addprinc -randkey host/cm.kerber.test" < /dev/null
    for t in "$@"; do
        pw2 "pw-$t" | kq "addprinc +requires_preauth -maxrenewlife \"1 hour\" cm-$t"
        pw2 "kt-$t" | kq "addprinc +requires_preauth cm-$t-kt"
        kq "ktadd -k $F/cm-kt/$t.keytab -norandkey cm-$t-kt" < /dev/null
        for c in file kcm; do
            pw2 "chpw-$t-$c" | kq "addprinc +requires_preauth cm-$t-$c-chpw"
            pw2 "exp-$t-$c" | kq "addprinc +requires_preauth -expire 2020-01-01 cm-$t-$c-exp"
            pw2 "pwexp-$t-$c" | kq "addprinc +requires_preauth -pwexpire 2020-01-01 cm-$t-$c-pwexp"
            pw2 "lock-$t-$c" | kq "addprinc +requires_preauth -policy cmlock cm-$t-$c-lock"
        done
        pw2 "cmu-$t" | kq "addprinc +requires_preauth -maxlife \"4 minutes\" -maxrenewlife \"1 hour\" cmu-$t"
    done
    } > "$F/setup.out" 2>&1
    sudo chown -R "$(id -un)" "$F/cm-kt"
    # MIT: `kadmin_addprinc` (kadmin/cli/kadmin.c:1355)
    n=$(grep -o 'Principal "[^"]*" created\.' "$F/setup.out" | wc -l)
    echo "SETUP_CREATED:$n"
    echo '==== listprincs cm* ===='
    kq 'listprincs cm*' < /dev/null 2>&1 | grep -v '^Authenticating'
    echo '==== kvno service ===='
    kq 'listprincs host/cm.kerber.test' < /dev/null 2>&1 | grep -x "host/cm.kerber.test@$REALM"
    echo '==== getpol cmlock ===='
    kq 'getpol cmlock' < /dev/null 2>&1
    echo '==== getprinc krbtgt ===='
    kq "getprinc krbtgt/$REALM" < /dev/null 2>&1 | grep -E '^(Maximum|Attributes)'
    echo '==== kdc.conf lifetimes ===='
    sudo grep -E '^\s*max_(renewable_)?life' /var/kerberos/krb5kdc/kdc.conf
    echo "KEYTABS:$(find "$F/cm-kt" -name '*.keytab' -size +0 | wc -l)"
}

cellenv() {
    export KRB5_CONFIG=$F/realm.conf:/etc/krb5.conf
    case $1 in
        file) export KRB5CCNAME=FILE:$F/cm-file.cc ;;
        kcm) export KRB5CCNAME=KCM: ;;
    esac
}
fresh() { kdestroy -A > /dev/null 2>&1 || kdestroy > /dev/null 2>&1 || true; }
mark() { printf '\n%s:%s\n' "$1" "$2"; }
till_of() { sed -n 's/.*renew until \([^,]*\).*/\1/p' "$1" | head -n 1; }

c1() {
    local p=cm-$TAG rc
    fresh
    sec "pw-$TAG" | kinit "$p"
    rc=$?
    mark KINIT_RC "$rc"
    [ "$rc" = 0 ] || return "$rc"
    klist -e -f
}
c2() {
    local rc
    fresh
    kinit -k -t "$F/cm.keytab" "cm-$TAG-kt"
    rc=$?
    mark KINIT_KT_RC "$rc"
    [ "$rc" = 0 ] || return "$rc"
    klist -e -f
}
c3() {
    local p=cm-$TAG rc
    fresh
    sec "pw-$TAG" | kinit "$p"
    mark KINIT_RC "$?"
    kvno "host/cm.kerber.test@$REALM"
    rc=$?
    mark KVNO_RC "$rc"
    klist -e
    return "$rc"
}
c4() {
    local p=cm-$TAG rc a b
    fresh
    sec "pw-$TAG" | kinit -r 1h "$p"
    rc=$?
    mark KINIT_R_RC "$rc"
    [ "$rc" = 0 ] || return "$rc"
    klist -f | tee "$F/c4.a"
    kinit -R
    rc=$?
    mark KINIT_RENEW_RC "$rc"
    klist -f | tee "$F/c4.b"
    a=$(till_of "$F/c4.a")
    b=$(till_of "$F/c4.b")
    if [ -n "$a" ] && [ "$a" = "$b" ]; then mark RENEW_TILL_KEPT yes; else mark RENEW_TILL_KEPT no; fi
    return "$rc"
}
c5() {
    local p=cm-$TAG-$CACHE-chpw rc
    fresh
    sec "chpw-$TAG-$CACHE" | kinit "$p"
    rc=$?
    mark KINIT1_RC "$rc"
    [ "$rc" = 0 ] || return "$rc"
    { sec "chpw-$TAG-$CACHE"; pw2 "chpw2-$TAG-$CACHE"; } | kpasswd "$p"
    rc=$?
    mark KPASSWD_RC "$rc"
    [ "$rc" = 0 ] || return "$rc"
    kdestroy
    sec "chpw2-$TAG-$CACHE" | kinit "$p"
    rc=$?
    mark KINIT2_RC "$rc"
    klist -f
    return "$rc"
}
c6() {
    local rc
    fresh
    sec "exp-$TAG-$CACHE" | kinit "cm-$TAG-$CACHE-exp"
    mark KINIT_EXP_RC "$?"
    { sec "pwexp-$TAG-$CACHE"; pw2 "pwexp2-$TAG-$CACHE"; } | kinit "cm-$TAG-$CACHE-pwexp"
    rc=$?
    mark KINIT_PWEXP_RC "$rc"
    klist -f
    return "$rc"
}
c7() {
    local p=cm-$TAG-$CACHE-lock i rc
    fresh
    for i in 1 2 3; do
        sec "wrong-$TAG-$CACHE" | kinit "$p"
        mark "KINIT_WRONG_${i}_RC" "$?"
    done
    sec "lock-$TAG-$CACHE" | kinit "$p"
    mark KINIT_LOCKED_RC "$?"
    sec admin | kadmin -p admin/admin -q "modprinc -unlock $p"
    mark UNLOCK_RC "$?"
    sec "lock-$TAG-$CACHE" | kinit "$p"
    rc=$?
    mark KINIT_UNLOCKED_RC "$rc"
    klist -f
    return "$rc"
}

sssd_conf() {
    cat << EOF
[sssd]
services = nss, pam
domains = kerber

[domain/kerber]
id_provider = proxy
proxy_lib_name = files
auth_provider = krb5
access_provider = permit
min_id = 20100
max_id = 20199
cache_credentials = false
krb5_realm = $REALM
krb5_server = kdc.kerber.test
krb5_validate = false
krb5_store_password_if_offline = false
krb5_renewable_lifetime = 1h
krb5_renew_interval = 30
debug_level = 6
EOF
    if [ "$1" = kcm ]; then
        printf 'krb5_ccname_template = KCM:\n\n[kcm]\ntgt_renewal = true\ntgt_renewal_inherit = kerber\ndebug_level = 6\n'
    else
        printf 'krb5_ccname_template = FILE:/tmp/krb5cc_%%U\n'
    fi
}
user_klist() {
    if [ "$CACHE" = kcm ]; then
        sudo -u "cmu-$TAG" env LC_ALL=C KRB5CCNAME=KCM: klist -f
    else
        sudo env LC_ALL=C klist -f -c "FILE:/tmp/krb5cc_$UID8"
    fi
}
# Valid starting, then renew until, then flags, of the TGT in a klist -f.
tgt_of() {
    awk -v r="krbtgt/$REALM@$REALM" '
        $5 == r { s = $1 " " $2; e = $3 " " $4; t = 1; next }
        t && /renew until/ { u = $0; sub(/.*renew until /, "", u); sub(/,.*/, "", u) }
        t && /Flags:/ { f = $0; sub(/.*Flags: /, "", f); print s "|" e "|" u "|" f; exit }
    ' "$1"
}
# A pty capture as plain lines: terminal escapes (OSC, CSI) and carriage returns removed.
ptytext() {
    python3 -c 'import re, sys
t = open(sys.argv[1], "rb").read().decode("utf-8", "replace")
t = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", t)
t = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", t)
sys.stdout.write(t.replace("\r", ""))' "$1"
}
life_min() { echo $(( ($(date -d "$2" +%s) - $(date -d "$1" +%s) + 30) / 60 )); }
c8() {
    local u=cmu-$TAG pid i got=no renewed=no t0 now s0 e0 u0 f0 s1 e1 u1 f1 cur
    sssd_conf "$CACHE" | sudo tee /etc/sssd/sssd.conf > /dev/null
    sudo chmod 600 /etc/sssd/sssd.conf
    sudo systemctl stop sssd sssd-kcm.socket sssd-kcm.service > /dev/null 2>&1
    sudo find /var/lib/sss/db /var/lib/sss/mc /var/lib/sss/secrets -type f -delete 2> /dev/null
    sudo rm -f "/tmp/krb5cc_$UID8"
    to "$F/c8.check" sudo sssctl config-check
    mark SSSD_CONFIG_CHECK "$?"
    sudo systemctl start sssd-kcm.socket sssd
    mark SSSD_START_RC "$?"
    for i in $(seq 1 30); do
        getent -s sss passwd "$u" > /dev/null && { got=yes; break; }
        sleep 1
    done
    mark SSS_USER "$got"
    : > "$OUT/$CACHE/cell8.pty"
    (sec "$u" | python3 "$F/ptydrive.py" --secrets 1 --timeout 330 --rule 'Password:=0' \
        -- su --pty - "$u" -c "echo SU_OK; echo \"SU_CC=\${KRB5CCNAME%%:*}\"; sleep 300" \
        > "$OUT/$CACHE/cell8.pty" 2>&1) &
    pid=$!
    got=no
    for i in $(seq 1 60); do
        ptytext "$OUT/$CACHE/cell8.pty" > "$OUT/$CACHE/cell8.txt" 2> /dev/null
        grep -qx 'SU_OK' "$OUT/$CACHE/cell8.txt" && { got=yes; break; }
        sleep 1
    done
    mark LOGIN "$got"
    ptytext "$OUT/$CACHE/cell8.pty" > "$OUT/$CACHE/cell8.txt" 2> /dev/null
    mark SU_CC "$(sed -n 's/^SU_CC=\([A-Z]*\)$/\1/p' "$OUT/$CACHE/cell8.txt" | head -n 1)"
    t0=$(date +%s)
    user_klist > "$F/c8.0" 2>&1
    IFS='|' read -r s0 e0 u0 f0 <<< "$(tgt_of "$F/c8.0")"
    mark FLAGS_LOGIN "${f0:-none}"
    mark RENEWABLE "$([ -n "${u0:-}" ] && echo yes || echo no)"
    if [ -n "${s0:-}" ]; then mark LIFE_MIN_LOGIN "$(life_min "$s0" "$e0")"; fi
    s1=${s0:-} e1=${e0:-} u1=${u0:-} f1=${f0:-}
    for i in $(seq 1 23); do
        [ -n "${s0:-}" ] || break
        sleep 10
        user_klist > "$F/c8.n" 2>&1
        cur=$(tgt_of "$F/c8.n")
        IFS='|' read -r s1 e1 u1 f1 <<< "$cur"
        if [ -n "$s1" ] && [ "$s1" != "$s0" ]; then
            renewed=yes
            now=$(date +%s)
            mark INFO_RENEW_SECS "$((now - t0))"
            break
        fi
    done
    mark RENEWED "$renewed"
    mark FLAGS_RENEWED "${f1:-none}"
    if [ -n "${s1:-}" ]; then mark LIFE_MIN_RENEWED "$(life_min "$s1" "$e1")"; fi
    mark RENEW_TILL_KEPT "$([ -n "${u0:-}" ] && [ "${u0:-}" = "${u1:-}" ] && echo yes || echo no)"
    sudo pkill -KILL -u "$u" > /dev/null 2>&1
    wait "$pid" 2> /dev/null
    for i in krb5_child sssd_kerber sssd_kcm; do
        if sudo grep -qi renew "/var/log/sssd/$i.log" 2> /dev/null; then mark INFO_RENEW_LOG "$i"; fi
    done
    sudo systemctl stop sssd > /dev/null 2>&1
    [ "$renewed" = yes ]
}

c9() {
    local p=cm-$TAG rc
    sec admin | kadmin -p admin/admin -q "getprinc $p"
    mark GETPRINC_RC "$?"
    { sec admin; pw2 "k9-$TAG"; } | kadmin -p admin/admin -q "addprinc $p-k9"
    mark ADDPRINC_RC "$?"
    sec admin | kadmin -p admin/admin -q "listprincs $p*"
    mark LISTPRINCS_RC "$?"
    sec admin | kadmin -p admin/admin -q "delprinc -force $p-k9"
    mark DELPRINC_RC "$?"
    sec admin | kadmin -p admin/admin -q "listprincs $p*"
    rc=$?
    mark LISTPRINCS2_RC "$rc"
    return "$rc"
}

cell() {
    local n=$1 rc
    mkdir -p "$OUT/$CACHE"
    "c$n" > "$OUT/$CACHE/cell$n.out" 2>&1
    rc=$?
    echo "$rc" > "$OUT/$CACHE/cell$n.rc"
    echo "CELL_RC:$CACHE:$n:$rc"
}

run() {
    local n
    LEG=$1 TAG=$2
    rm -rf "$OUT"
    mkdir -p "$OUT"
    echo "RUN:$LEG:$TAG"
    for CACHE in file kcm; do
        (
            cellenv "$CACHE"
            for n in 1 2 3 4 5 6 7 8; do cell "$n"; done
        )
    done
    CACHE=k9
    (cellenv file && cell 9)
    echo "RUN_DONE:$LEG:$TAG"
}

mode=${1:-}
shift || true
case $mode in
    prep) prep "$@" ;;
    kdc-setup) take_secrets && kdc_setup "$@" ;;
    run) take_secrets && run "$@" ;;
    *) echo "usage: cm-cells.sh prep|kdc-setup|run ..." >&2; exit 2 ;;
esac
