#!/usr/bin/env bash
# Documented MIT Kerberos 1.22.2 harness entry point.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required to run the MIT 1.22.2 KDC harness" >&2
    exit 1
fi

export CORRELATION_ID="${CORRELATION_ID:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}"

echo "{\"event\":\"harness.launch\",\"correlation_id\":\"${CORRELATION_ID}\",\"component\":\"harness\",\"outcome\":\"ok\"}"

IMAGE="kerber-rust-mit-kdc:1.22.2"
NAME="kerber-rust-mit-kdc"

docker build -f harness/Dockerfile -t "$IMAGE" "$ROOT"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" \
    -p 88:88/tcp -p 88:88/udp \
    -e "CORRELATION_ID=${CORRELATION_ID}" \
    "$IMAGE"

# Wait for the in-container kinit (logged as harness.kinit).
for _ in $(seq 1 90); do
    logs="$(docker logs "$NAME" 2>&1 || true)"
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"ok"'; then
        echo "$logs"
        echo "{\"event\":\"harness.verified\",\"correlation_id\":\"${CORRELATION_ID}\",\"component\":\"harness\",\"outcome\":\"ok\",\"principal\":\"user@KERBER.TEST\"}"
        exit 0
    fi
    if echo "$logs" | grep -q '"event":"harness.kinit".*"outcome":"error"'; then
        echo "$logs" >&2
        exit 1
    fi
    # Container died during startup.
    if ! docker ps -q --filter "name=^${NAME}$" | grep -q .; then
        echo "$logs" >&2
        echo "harness container exited" >&2
        exit 1
    fi
    sleep 2
done

echo "timed out waiting for MIT 1.22.2 kinit" >&2
docker logs "$NAME" >&2 || true
exit 1
