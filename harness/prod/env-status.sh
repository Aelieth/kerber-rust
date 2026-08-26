#!/usr/bin/env bash
# Status of the C1 prod realm: node IPs, listeners, live resource usage vs caps.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$HERE/limits.env"

NODES="$(docker ps --format '{{.Names}}' | grep -E '^kerber-rust-prod-' | sort || true)"
if [ -z "$NODES" ]; then
    echo "[env-status] no prod nodes running — start with ./harness/prod/env-up.sh"
    exit 0
fi

echo "=== nodes / IPs / listeners ==="
for n in $NODES; do
    ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$n" 2>/dev/null)"
    listen="$(docker exec "$n" sh -c 'command -v ss >/dev/null && ss -lntu 2>/dev/null | grep -E ":(88|749|754)\b" | awk "{print \$5}" | tr "\n" " "' 2>/dev/null)"
    printf '  %-30s %-15s %s\n' "$n" "$ip" "${listen:-（no 88/749/754 listener）}"
done

echo
echo "=== live resource usage vs caps (${KERBER_KDC_MEM}/${KERBER_KDC_CPUS}cpu per node) ==="
# shellcheck disable=SC2086
docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}' $NODES 2>/dev/null

echo
echo "=== host headroom ==="
free -h | awk 'NR==1||/Mem:/'
printf '  cores=%s  load=%s\n' "$(nproc)" "$(uptime | sed 's/.*load average: //')"

echo
echo "=== captured pcap on primary (if any) ==="
docker exec kerber-rust-prod-kdc1 sh -c 'ls -l /tmp/prod.pcap 2>/dev/null || echo "  (none yet)"' 2>/dev/null || echo "  (primary not up)"
