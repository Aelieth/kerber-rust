# harness/field/lib/leg.sh: a scenario's leg (--leg mit|rust) and the helpers the client and services scenarios
# share. Sourced after rec.sh and baseline.env, with LEG set (the scenario parses --leg).
# shellcheck shell=bash
#
# From baseline.env's MIT_* or RUST_* set: REALM, and `legset NAME...` (each NAME = the leg's SECRET_<NAME>, a file
# name under ~/kerber-lab/secrets, never a value). A missing name or file stops the scenario before any lab step.
#   resetvm <vm>...        each VM back to the leg's SNAPSHOT_<VM> (check reset.<vm>), then chrony (check sync.<vm>)
#   kdcis                  kdc runs the leg's KDC, which upgrade.sh left (check kdc.leg): MIT = krb5-server's own
#                          binaries and no kerber-rust install; rust = the install manifest as installed, and (check
#                          kdc.ref) its programs the ref's build (lib/install-check.sh against ~/kerber-rust-<sha12>)
#   servicesready          services' four units active, 2049 listening, Keycloak's realm answering (check
#                          services.ready; up to 5 min after a reset)
#   ktcheck <vm> <keytab> <name>   the keytab's newest kvno and enctypes = the KDC's getprinc (check keytab.<name>);
#                          services has no klist, so there it runs in the S2 probe image (label separation off,
#                          the file bind-mounted read-only, no relabel)
#   countlast <name> <ERE> <n>     graded like checklast, but exactly n lines of the last output must match
case ${LEG:-} in
    mit) LEGP=MIT ;;
    rust) LEGP=RUST ;;
    *) printf 'leg.sh: LEG must be mit or rust\n' >&2; exit 1 ;;
esac
_legv="${LEGP}_REALM"
REALM=${!_legv:-}
[ -n "$REALM" ] || { note "baseline.env sets no $_legv: the scenario cannot run"; exit 1; }

legset() {
    local n v
    for n in "$@"; do
        v="${LEGP}_SECRET_$n"
        if [ -z "${!v:-}" ] || [ ! -f "$SECRETS/${!v}" ]; then
            note "baseline.env sets no $v, or ~/kerber-lab/secrets has no such file: the scenario cannot run"
            exit 1
        fi
        printf -v "$n" '%s' "${!v}"
    done
}

resetvm() {
    local vm v
    for vm in "$@"; do
        v="${LEGP}_SNAPSHOT_${vm^^}"
        if [ -z "${!v:-}" ]; then
            _checkrow "reset.$vm" FAIL "baseline.env's $v" 1 "baseline.env sets no $v"
            return 1
        fi
        check "reset.$vm" rc host "$LABQ reset $vm ${!v}"
    done
    for vm in "$@"; do waitsync "$vm"; done
}

kdcis() {
    if [ "$LEG" = mit ]; then
        check kdc.leg '^kdc: MIT krb5-server-[0-9].*, binaries as packaged, no kerber-rust install$' run kdc \
            "systemctl is-active krb5kdc kadmin | paste -sd' ' -; sudo rpm -V krb5-server krb5-libs | grep -E ' /usr/(s?bin|lib64)/'; [ ! -e /usr/share/kerber-rust/install-manifest ] && ! sudo rpm -V krb5-server | grep -qE '^..5.* /usr/sbin/(krb5kdc|kadmind)\$' && echo \"kdc: MIT \$(rpm -q krb5-server), binaries as packaged, no kerber-rust install\""
    else
        check kdc.leg '^kdc: kerber-rust, [1-9][0-9]* files as installed$' run kdc \
            "systemctl is-active krb5kdc kadmin | paste -sd' ' -; sudo sha256sum -c --quiet /usr/share/kerber-rust/install-manifest && echo \"kdc: kerber-rust, \$(wc -l < /usr/share/kerber-rust/install-manifest) files as installed\""
        check kdc.ref '^programs: [1-9][0-9]* in the manifest, each identical to the build$' \
            runin kdc "lib/install-check.sh" "sh -s -- ~/kerber-rust-${FIELD_SHA:0:12}" < "$FIELD_LIB/install-check.sh"
    fi
}

servicesready() {
    check services.ready '^ready: lldap nfs-klldap-host keycloak keycloak-proxy active, 2049 listening, realm 200$' run services \
        "for i in \$(seq 1 60); do a=\$(systemctl is-active lldap nfs-klldap-host keycloak keycloak-proxy | grep -c '^active\$'); l=\$(sudo ss -Hltn 'sport = :2049' | grep -c .); c=\$(curl -sk -o /dev/null -w '%{http_code}' -m 5 --resolve services.kerber.test:443:127.0.0.1 https://services.kerber.test/realms/kerber.test/.well-known/openid-configuration); [ \"\$a\" = 4 ] && [ \"\$l\" -ge 1 ] && [ \"\$c\" = 200 ] && break; sleep 5; done; echo \"try \$i: \$a units active, \$l listeners on 2049, realm \$c\"; [ \"\$a\" = 4 ] && [ \"\$l\" -ge 1 ] && [ \"\$c\" = 200 ] && echo 'ready: lldap nfs-klldap-host keycloak keycloak-proxy active, 2049 listening, realm 200'"
}

ktcheck() {
    local vm=$1 kt=$2 name=$3 princs lister="sudo klist -k -e $2"
    if [ "$vm" = services ]; then
        lister="sudo podman run --rm --network none --security-opt label=disable -v $kt:/kt:ro localhost/s2-nfs-probe:f43 klist -k -e /kt"
    fi
    run "$vm" "sudo ls -laZ $kt; $lister"
    cp "$LAST_OUT" "$STATE/kt.$name"
    princs=$(awk '$1 ~ /^[0-9]+$/ && $2 ~ /@/ { print $2 }' "$STATE/kt.$name" | sort -u | paste -sd' ' -)
    run kdc "for p in $princs; do sudo kadmin.local -q \"getprinc \$p\" 2>&1 | grep -E '^(Principal|Key|get_principal)'; done"
    cp "$LAST_OUT" "$STATE/gp.$name"
    check "keytab.$name" '^keytab-vs-kdc: [0-9]+ principals?, all equal$' host \
        "python3 -B $(printf '%q' "$FIELD_LIB/kt-vs-kdc.py") $(printf '%q' "$STATE/kt.$name") $(printf '%q' "$STATE/gp.$name")"
}

countlast() {
    local n res=FAIL
    n=$(grep -cE -- "$2" "$LAST_OUT" || true)
    if [ "$LAST_RC" = 0 ] && [ "$n" = "$3" ]; then res=PASS; fi
    _checkrow "$1" "$res" "$3 lines: $2" "$LAST_RC" "$n lines match"
}
