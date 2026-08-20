#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
docker rm -f kerber-rust-mit-kdc >/dev/null 2>&1 || true
