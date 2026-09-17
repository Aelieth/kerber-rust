# Isolation guard for the local evidence runners (checkpoint.sh, hygiene-snapshot.sh).
# They run only where the host default realm is the TESTLABBY.LOCAL lab stub (the
# lab container), never on a host whose /etc/krb5.conf names a production realm.
# KERBER_ALLOW_HOST_REALM=1 overrides; the caller records lab_realm_override in
# its stamp so the evidence says so. Source after `cd "$ROOT"`.
# shellcheck shell=bash

LAB_REALM="TESTLABBY.LOCAL"

# The value of the first `default_realm` line in /etc/krb5.conf, or empty.
host_default_realm() {
    /usr/bin/grep -m1 'default_realm' /etc/krb5.conf 2>/dev/null \
        | sed 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*$//'
}

# Exit 2 unless the host realm is the lab stub or the override is set.
require_lab_realm() {
    local realm
    realm="$(host_default_realm)"
    if [ "$realm" = "$LAB_REALM" ] || [ "${KERBER_ALLOW_HOST_REALM:-0}" = 1 ]; then
        return 0
    fi
    echo "$0: host default_realm is '${realm:-<none>}', not $LAB_REALM; run inside the lab environment," \
        "or set KERBER_ALLOW_HOST_REALM=1 (recorded in the stamp)" >&2
    exit 2
}

# "no" on the lab realm, "yes" when running under the override (call after require_lab_realm).
lab_realm_override() {
    local override=yes
    [ "$(host_default_realm)" != "$LAB_REALM" ] || override=no
    echo "$override"
}
