#!/usr/bin/env bash
# Job preamble: one --entrypoint sleep shell + docker cp of gate bins.
# Subsequent steps set KERBER_SHELL. Job cleanup removes the container.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
. "$ROOT/scripts/lib/provenance.sh"
. "$ROOT/scripts/lib/gate-common.sh"
need_image
NAME="${KERBER_SHELL:-kerber-rust-shell}"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --hostname testhost.kerber.test --entrypoint sleep "$IMAGE" 7200 >/dev/null
docker exec "$NAME" sh -c '
    cp -a /etc/krb5.conf /etc/krb5.conf.kerber-stock
    cp -a /etc/krb5kdc/kdc.conf /etc/krb5kdc/kdc.conf.kerber-stock
'
DEST="${CARGO_TARGET_DIR:-$ROOT/target}/debug"
for b in krb5-kdc krb5-kadmind krb5-kdb krb5-kadmin-local krb5-kinit krb5-kvno \
    krb5-klist krb5-kdestroy krb5-ktutil krb5-kpasswd krb5-kprop krb5-kpropd \
    krb5-iprop-pull krb5-gss-accept krb5-gss-init krb5-forge-tgt krb5-pac-extract \
    krb5-kswitch krb5-vfy-increds; do
    if [ -x "$DEST/$b" ]; then
        docker cp "$DEST/$b" "$NAME":/tmp/"$b"
        docker exec "$NAME" chmod +x /tmp/"$b"
    fi
done
if [ -x "$DEST/examples/ccache-probe" ]; then
    docker cp "$DEST/examples/ccache-probe" "$NAME":/tmp/ccache-probe
    docker exec "$NAME" chmod +x /tmp/ccache-probe
fi
echo "KERBER_SHELL=$NAME" >>"${GITHUB_ENV:-/dev/null}"
log "boot.shell" "ok" ",\"name\":\"$NAME\""
