#!/usr/bin/env bash
# The test-hooks cargo features a tree defines, for a build or test run at another SHA.
# shellcheck shell=bash

# test_hooks_features REV [INJECT...]: `krb5-kdc/test-hooks,krb5-admin/test-hooks`, naming
# each crate whose Cargo.toml at REV defines the feature (a manifest among the INJECT files
# is read from $ROOT instead), or nothing for a tree from before the feature.
test_hooks_features() {
    local rev=$1 crate manifest text f
    local -a feats=()
    shift
    for crate in krb5-kdc krb5-admin; do
        manifest="crates/$crate/Cargo.toml"
        text="$(git -C "$ROOT" show "$rev:$manifest" 2>/dev/null || true)"
        for f in "$@"; do
            case "$f" in
                "$manifest" | "$ROOT/$manifest") text="$(cat "$ROOT/$manifest")" ;;
            esac
        done
        if grep -qE '^test-hooks[[:space:]]*=' <<<"$text"; then
            feats+=("$crate/test-hooks")
        fi
    done
    local IFS=,
    printf '%s' "${feats[*]}"
}
