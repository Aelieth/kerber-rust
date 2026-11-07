#!/usr/bin/env bash
# KI rig, BG-1 only: 10 mutual contexts, then 10 non-mutual MIT contexts, then 10 ours.
set -uo pipefail
OUT=${1:?outdir}
if [ -z "${IN_NS:-}" ]; then mkdir -p "$OUT"; exec unshare -Urnm env IN_NS=1 bash "$0" "$@"; fi
KDC=${KDC:?}
OURS=${OURS:?}
INIT=${INIT:?}
ACC=${ACC:?}
SUMMARY=${SUMMARY:?}
HOSTNAME_=testhost.kerber.test
ip link set lo up
printf "127.0.0.1 localhost %s\n" "$HOSTNAME_" > "$OUT/hosts"
mount --bind "$OUT/hosts" /etc/hosts
export KRB5_TEST_USER_PASSWORD=userpassword KRB5_TEST_ADMIN_PASSWORD=adminpassword KRB5_KDC_DB=$OUT/principal KRB5_KDC_STASH=$OUT/stash
$KDC --test-realm --export-keytab "$OUT/host.keytab" 127.0.0.1:88 > "$OUT/kdc.log" 2>&1 &
for _ in $(seq 1 50); do grep -q '^listening ' "$OUT/kdc.log" 2>/dev/null && break; sleep 0.2; done
mkconf() { cat > "$1" <<EOT
[libdefaults]
    default_realm = KERBER.TEST
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    dns_canonicalize_hostname = false
[realms]
    KERBER.TEST = {
        kdc = 127.0.0.1
    }
EOT
}
mkconf "$OUT/krb5.conf"
export KRB5_CONFIG=$OUT/krb5.conf
for who in mit ours; do printf '%s\n' "$KRB5_TEST_USER_PASSWORD" | KRB5CCNAME=FILE:$OUT/cc-$who /usr/bin/kinit user@KERBER.TEST > "$OUT/kinit-$who.out" 2>&1; echo "kinit $who rc $?" >> "$OUT/setup.txt"; done
{ echo "krb5-kdc: $KDC"; echo "krb5-gss-init: $OURS"; sha256sum "$KDC" "$OURS"; } >> "$OUT/setup.txt"
port=4440
phase() {
  local label=$1 runs=$2; shift 2
  port=$((port + 1))
  KRB5_KTNAME=FILE:$OUT/host.keytab KRB5RCACHETYPE=none KRB5_CONFIG=$OUT/krb5.conf $ACC "$label" "$port" "$OUT/$label" > "$OUT/$label.acceptor.txt" 2> "$OUT/$label.acceptor.err" &
  local apid=$!
  for _ in $(seq 1 50); do grep -q '^listening ' "$OUT/$label.acceptor.txt" 2>/dev/null && break; sleep 0.1; done
  : > "$OUT/$label.runs.txt"
  for i in $(seq 1 "$runs"); do
    ( PORT=$port; export PORT; "$@" ) > "$OUT/$label.init-$i.out" 2>&1
    echo "run $i rc $?" >> "$OUT/$label.runs.txt"
  done
  sleep 0.5; kill $apid 2>/dev/null; wait $apid 2>/dev/null
}
phase mit-default 10 env KRB5_CONFIG="$OUT/krb5.conf" bash -c 'KRB5CCNAME=FILE:'"$OUT"'/cc-mit '"$INIT"' '"$HOSTNAME_"' host 127.0.0.1 '\$PORT
phase mit-nomutual 10 env GSS_NOMUTUAL=1 KRB5_CONFIG="$OUT/krb5.conf" bash -c 'KRB5CCNAME=FILE:'"$OUT"'/cc-mit '"$INIT"' '"$HOSTNAME_"' host 127.0.0.1 '\$PORT
KRB5CCNAME=FILE:$OUT/cc-ours kvno "host/$HOSTNAME_" >> "$OUT/setup.txt" 2>&1
echo "kvno ours rc $?" >> "$OUT/setup.txt"
phase ours 10 bash -c "$OURS"' --ccache '"$OUT"'/cc-ours --host '"$HOSTNAME_"' --ip 127.0.0.1 --port '\$PORT
kill %1 2>/dev/null || true
python3 -I "$SUMMARY" "$OUT" | tee "$OUT/summary.txt"
