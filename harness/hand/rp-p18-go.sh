#!/bin/bash
# Installs the build under test under /opt (docs/install.md), then the MIT-first iprop kadmind strace.
# Does not reseed /srv/p18. Leaves /usr/local and the older guest trees alone.
set -u
PHASEC_SHA=${1:?phasec sha}
HDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$HDIR/lib/env.sh"
require_env HAND_WT HAND_REC
WT=$HAND_WT
REC=$HAND_REC/$PHASEC_SHA/p18-go
bash "$HDIR/lib/ship-guard.sh" "$PHASEC_SHA" "$REC" || exit $?
exec 9>&-
LAB=$WT/harness/field/lab.sh
lab() { bash "$LAB" "$@"; }
mkdir -p "$REC"
echo $$ > "$REC/driver.pid"
echo "GO_START $(TZ=America/Chicago date '+%H:%M:%S')"
echo "COMMIT:$(git -C "$WT" rev-parse HEAD)"
echo "TREE:$(git -C "$WT" rev-parse 'HEAD^{tree}')"

lab ssh klldap -- 'sudo -n test -f /srv/p18/seed/N10.dump && sudo -n test -x /var/tmp/p18/session.sh && echo SEEDS_OK'
seed_rc=$?
echo "SEED_RC:$seed_rc"
if [ "$seed_rc" != 0 ]; then
    echo "GO_END $(TZ=America/Chicago date '+%H:%M:%S')"
    exit 1
fi

git -C "$WT" archive --format=tar --prefix="kerber-rust-${PHASEC_SHA:0:12}/" HEAD > "$REC/tree.tar"
echo "TAR_BYTES:$(wc -c < "$REC/tree.tar")"
SHORT=${PHASEC_SHA:0:12}
lab ssh klldap -- "rm -rf ~/kerber-rust-${SHORT} && tar -x -C ~" < "$REC/tree.tar"
echo "UPLOAD_RC:$?"

sed "s#\\\${PREFIX_DIR}#/opt/p18-${SHORT}#g" "$HDIR/p18-trace.sh" > "$REC/p18-trace.guest.sh"
cat > "$REC/p18-install.sh" << EOF
set -o pipefail
. "\$HOME/.cargo/env"
cd "\$HOME/kerber-rust-${SHORT}"
make build && sudo -n make install PREFIX=/opt/p18-${SHORT}
sudo -n sha256sum /opt/p18-${SHORT}/sbin/krb5kdc /opt/p18-${SHORT}/sbin/kadmind
EOF
lab ssh klldap -- "bash -s" < "$REC/p18-install.sh"
build_rc=$?
echo "BUILD_RC:$build_rc"
if [ "$build_rc" != 0 ]; then
    echo "GO_END $(TZ=America/Chicago date '+%H:%M:%S')"
    exit 1
fi
echo INSTALL_OK

lab ssh klldap -- 'cat > /var/tmp/p18-trace.sh && sudo -n chmod 755 /var/tmp/p18-trace.sh' < "$REC/p18-trace.guest.sh"
echo "UPLOAD_TRACE_RC:$?"

lab ssh klldap -- 'sudo -n bash /var/tmp/p18-trace.sh'
trace_rc=$?
echo "TRACE_RC:$trace_rc"

echo "==== pull ===="
lab ssh klldap -- 'sudo -n bash -s' << 'EOS' > "$REC/out.tar"
cd /srv/p18/out
tar -cf - p872-iprop-trace-mit p872-iprop-trace-ours
EOS
pull_rc=$?
echo "PULL_RC:$pull_rc"
echo "GO_END $(TZ=America/Chicago date '+%H:%M:%S')"
if [ "$trace_rc" != 0 ]; then
    exit "$trace_rc"
fi
exit "$pull_rc"
