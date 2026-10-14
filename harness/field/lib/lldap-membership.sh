#!/bin/bash
# lldap-membership.sh: add or remove one lldap group membership; runs on `services`, any user (S1's
# deploy/membership.sh; scenarios/sssd-login.sh puts alice in lldap_disabled and takes her out again).
# The caller prepends ADMIN_PW, ACTION (add|remove), MUSER and MGROUP as shell assignments on stdin, e.g.
#   { printf 'ADMIN_PW=%q\nACTION=add\nMUSER=bob\nMGROUP=lldap_disabled\n' \
#       "$(cat ~/kerber-lab/secrets/ldap/lldap-admin.password)"; cat lldap-membership.sh; } |
#     harness/field/lab.sh ssh services -- 'bash -s'
set -euo pipefail
: "${ADMIN_PW:?}" "${ACTION:?}" "${MUSER:?}" "${MGROUP:?}"
URL=http://127.0.0.1:17170
TOKEN=$(ADMIN_PW="$ADMIN_PW" jq -nc '{username: "admin", password: env.ADMIN_PW}' |
    curl -sf -H 'Content-Type: application/json' --data @- "$URL/auth/simple/login" | jq -r .token)
gql() {
    local vars=${2:-'{}'}
    jq -nc --arg q "$1" --argjson v "$vars" '{query: $q, variables: $v}' |
        curl -sf -H 'Content-Type: application/json' \
            -H @<(printf 'Authorization: Bearer %s\n' "$TOKEN") --data @- "$URL/api/graphql" |
        jq -c 'if .errors then error("GraphQL: " + (.errors | map(.message) | join("; "))) else .data end'
}
gid=$(gql '{groups{id displayName}}' | jq -r --arg n "$MGROUP" '.groups[] | select(.displayName == $n) | .id')
[ -n "$gid" ] || { echo "no group $MGROUP"; exit 1; }
case $ACTION in
    add) mut=addUserToGroup ;;
    remove) mut=removeUserFromGroup ;;
    *) echo "ACTION must be add or remove"; exit 2 ;;
esac
gql "mutation(\$u: String!, \$g: Int!) { $mut(userId: \$u, groupId: \$g) { ok } }" \
    "$(jq -nc --arg u "$MUSER" --argjson g "$gid" '{u: $u, g: $g}')" >/dev/null
echo "$ACTION $MUSER <-> $MGROUP (group id $gid): ok"
gql "query(\$u: String!) { user(userId: \$u) { id groups { displayName } } }" "$(jq -nc --arg u "$MUSER" '{u: $u}')" |
    jq -r '"\(.user.id) is now in: \([.user.groups[].displayName] | join(", "))"'
