#!/usr/bin/env bash
# Retired Windows-DC one-shot. Cross-realm is samba-realtrust-gate.sh
# (two Samba DCs + samba-tool domain trust create). Does not claim a Windows DC.
exec "$(cd "$(dirname "$0")" && pwd)/samba-realtrust-gate.sh" "$@"
