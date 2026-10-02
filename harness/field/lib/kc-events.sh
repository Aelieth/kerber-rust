#!/usr/bin/env bash
# kc-events.sh <since, epoch seconds>: Keycloak's events of realm kerber.test since then, read-only through the admin
# API from the host (R5-MIT's kc-events.sh without its absolute paths). stdin is the master realm's keyadmin password
# (secrets/s2/keycloak-keyadmin.password); the bearer token goes through a pipe into curl's `-H @-`. Neither touches
# argv or disk. TLS is verified against the lab CA. Prints one line per event, oldest first (time, type, user,
# client, ipAddress, error), then one count line per kind:  count: LOGIN alice nextcloud 192.168.177.22 = 3
set -euo pipefail
SINCE=${1:?usage: kc-events.sh <since, epoch seconds>}
CA=${KERBER_LAB_HOME:-$HOME/kerber-lab}/secrets/ldap/lab-ca.crt
C=(curl -sS --max-time 20 --resolve services.kerber.test:443:192.168.177.11 --cacert "$CA")
tr -d '\n' \
    | "${C[@]}" -d grant_type=password -d client_id=admin-cli -d username=keyadmin --data-urlencode password@- \
        https://services.kerber.test/realms/master/protocol/openid-connect/token \
    | python3 -c 'import sys, json; print("Authorization: Bearer " + json.load(sys.stdin)["access_token"])' \
    | "${C[@]}" -H @- "https://services.kerber.test/admin/realms/kerber.test/events?max=500" \
    | SINCE=$SINCE python3 -c '
import collections, datetime, json, os, sys
since = int(os.environ["SINCE"]) * 1000
count = collections.Counter()
for e in sorted(json.load(sys.stdin), key=lambda e: e["time"]):
    if e["time"] < since:
        continue
    d = e.get("details") or {}
    kind = (e.get("type", "-"), d.get("username", "-"), e.get("clientId", "-"), e.get("ipAddress", "-"))
    count[kind] += 1
    t = datetime.datetime.fromtimestamp(e["time"] / 1000, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print("\t".join((t,) + kind + (e.get("error") or "-",)))
for kind, n in sorted(count.items()):
    print("count: %s = %d" % (" ".join(kind), n))
print("events since %s: %d" % (datetime.datetime.fromtimestamp(since / 1000, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), sum(count.values())))
'
