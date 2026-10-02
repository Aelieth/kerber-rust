# harness/field/lib/leg.sh: a scenario's leg (--leg mit|rust) and the helpers the client and services scenarios
# share. Sourced after rec.sh and baseline.env, with LEG set (the scenario parses --leg).
# shellcheck shell=bash
#
# From baseline.env's MIT_* or RUST_* set: REALM.
#   resetvm <vm>...        each VM back to the leg's SNAPSHOT_<VM> (check reset.<vm>), then chrony (check sync.<vm>)
#   kdcis                  kdc runs the leg's KDC, which upgrade.sh left (check kdc.leg): MIT = krb5-server's own
#                          binaries and no kerber-rust install; rust = the install manifest as installed, and (check
#                          kdc.ref) its programs the ref's build (lib/install-check.sh against ~/kerber-rust-<sha12>)
case ${LEG:-} in
    mit) LEGP=MIT ;;
    rust) LEGP=RUST ;;
    *) printf 'leg.sh: LEG must be mit or rust\n' >&2; exit 1 ;;
esac
_legv="${LEGP}_REALM"
REALM=${!_legv:-}
[ -n "$REALM" ] || { note "baseline.env sets no $_legv: the scenario cannot run"; exit 1; }

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
