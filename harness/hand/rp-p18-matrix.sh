#!/bin/bash
# The untraced p18 grade of the build under test. Does not reseed.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
REC=$HAND_REC/$PHASEC_SHA/p18
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
exec 9>&-
LAB=$WT/harness/field/lab.sh
lab() { bash "$LAB" "$@"; }
mkdir -p "$REC"
echo $$ > "$REC/driver.pid"
echo "REC:$REC"
echo "COMMIT:$PHASEC_SHA"
echo "TREE:$(git -C "$WT" rev-parse 'HEAD^{tree}')"
echo "MATRIX_START $(TZ=America/Chicago date '+%H:%M:%S')"
lab ssh klldap -- "sudo -n test -f /srv/p18/seed/N10.dump && sudo -n test -f /srv/p18/seed/N1000.dump && sudo -n test -f /srv/p18/seed/N5000.dump && sudo -n test -x /var/tmp/p18/session.sh && sudo -n test -x /var/tmp/p18/probe-session.sh && sudo -n test -x /opt/p18-${PHASEC_SHA:0:12}/sbin/krb5kdc && echo SEEDS_OK"
echo "SEED_RC:$?"
lab ssh klldap -- "sudo -n PREFIX=/opt/p18-${PHASEC_SHA:0:12} bash -s" << 'EOS'
set -u
B=/srv/p18
EAT=$(ls -1 /usr/lib64/libeatmydata.so* | head -1)
echo "EAT:$EAT"
test -f "$EAT" || { echo "no eatmydata"; exit 2; }
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
for rep in 1 2 3; do
  for n in 10 1000 5000; do
    for leg in "mit:/usr/sbin" "ours:$PREFIX/sbin"; do
      name=${leg%%:*}
      off
      run "$leg" "$n" "p872-N${n}-${name}-${rep}" - io session.sh
      on
      run "$leg" "$n" "p872-N${n}-${name}-iprop-${rep}" - none session.sh
      off
      run "$leg" "$n" "p872-N${n}-${name}-nofsync-${rep}" "LD_PRELOAD=$EAT" none session.sh
      off
      run "$leg" "$n" "p872-N${n}-${name}-probe-${rep}" - none probe-session.sh
    done
  done
  echo "REP_DONE $rep"
done
echo "MATRIX_DONE"
EOS
echo "MATRIX_RC:$?"
echo "==== pull ===="
lab ssh klldap -- "sudo -n PREFIX=/opt/p18-${PHASEC_SHA:0:12} bash -s" << 'EOS' > "$REC/out.tar"
cd /srv/p18/out
tar -cf - p872-N*
EOS
echo "PULL_RC:$?"
echo "MATRIX_END $(TZ=America/Chicago date '+%H:%M:%S')"
