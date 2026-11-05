#!/bin/bash
# One cell: N=10, iprop on, 5 rounds, MIT first.
# Not a regrade. Does not reseed. Does not reset klldap.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
REC=$HAND_REC/$PHASEC_SHA/p18-diag
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
exec 9>&-
LAB=$WT/harness/field/lab.sh
lab() { bash "$LAB" "$@"; }
mkdir -p "$REC"
echo $$ > "$REC/driver.pid"
echo "REC:$REC"
echo "COMMIT:$PHASEC_SHA"
echo "TREE:$(git -C "$WT" rev-parse 'HEAD^{tree}')"
echo "DIAG_START $(TZ=America/Chicago date '+%H:%M:%S')"
lab ssh klldap -- "sudo -n test -f /srv/p18/seed/N10.dump && sudo -n test -f /srv/p18/kdc-iprop.conf && sudo -n test -x /var/tmp/p18/session.sh && sudo -n test -x /opt/p18-${PHASEC_SHA:0:12}/sbin/krb5kdc && echo SEEDS_OK"
echo "SEED_RC:$?"
lab ssh klldap -- "sudo -n PREFIX=/opt/p18-${PHASEC_SHA:0:12} bash -s" << 'EOS'
set -u
B=/srv/p18
off() { cp -a "$B/kdc-off.conf" "$B/kdc.conf"; }
on() { cp -a "$B/kdc-iprop.conf" "$B/kdc.conf"; }
run() {
    local leg="$1" n="$2" tag="$3" kenv="$4" trace="$5" script="$6"
    echo "BEGIN $tag"
    if ! bash "/var/tmp/p18/$script" "$leg" "$n" "$tag" 30 "$kenv" "$trace"; then
        echo "SESSION_RC:1 $tag"
        exit 2
    fi
    echo "SESSION_RC:0 $tag"
}
iprop_on() {
    on
    if ! cmp -s "$B/kdc.conf" "$B/kdc-iprop.conf"; then
        echo "IPROP_CONF_DIFF"
        exit 3
    fi
    echo "IPROP_CONF:match $(sha256sum "$B/kdc.conf" | awk '{print $1}')"
}
for i in 1 2 3 4 5; do
  for leg in "mit:/usr/sbin" "ours:$PREFIX/sbin"; do
    name=${leg%%:*}
    iprop_on
    run "$leg" 10 "p872d-N10-${name}-iprop-io-${i}" - io session.sh
    iprop_on
    run "$leg" 10 "p872d-N10-${name}-iprop-${i}" - none session.sh
  done
  echo "ROUND_DONE $i"
done
echo "DIAG_DONE"
EOS
echo "DIAG_RC:$?"
echo "==== pull ===="
lab ssh klldap -- "sudo -n bash -s" << 'EOS' > "$REC/out.tar"
cd /srv/p18/out
tar -cf - p872d-N10-*
EOS
echo "PULL_RC:$?"
echo "DIAG_END $(TZ=America/Chicago date '+%H:%M:%S')"
