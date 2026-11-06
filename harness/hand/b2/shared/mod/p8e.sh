# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/p8e.sh: P8E. EVIDENCE ONLY (evidence only: scratch-patched copy, not the package's script).
# Hold B's P8 field check (field-check.sh, run by driver.sh's p8_check on the ship build installed by install.md's upgrade) failed only at its line 165:
# `matchpathcon -V $D/principal $SIDE $DB.ulog $DB.ok $DB.kadm5.lock`. An MIT-upgraded realm without iprop has no principal.ulog, and neither did the MIT baseline: a stale assumption in the
# script, not a product fault. The head implementer's scratch copy fix-p8/field-check.sh (sha256 7713cae4..., field-check.patch beside it, field-check.orig.sh the original) checks
# principal.ulog only when it exists. This module runs that copy ONCE, in the ours stage, exactly as p8_check runs the original (kdc_script: the script on the kdc's sh, the realm's admin/admin
# password the first line of stdin, 900 s), with the same rows; only the script path differs. It is not a package leg, it proves nothing about P8's own script, and the row labels are P8E.*.
# Ours stage only (no _mit, no _parity: the field check needs the KDC the upgrade installed); it runs before p16ae's FIFO cell (module order, INTERFACE-CHANGES.md).
# Environment: P8E_CHECK (required: the fixed check script). No variable is assigned outside a function.
# After the check, whatever it returned (helpers/p8e-kdc.sh after, one more kdc call): the units krb5kdc and kadmin must be active and the check's scratch principal p8-lock, policy p8-lockpol and directory
# /root/p8-check gone. The check puts them back itself when it ends normally; when it stops early (its `stop` lines leave the daemons as they were then) this module names what it found in rows
# (P8E.ours.units-after-check, P8E.ours.leftovers: FAIL when the check left something) and then puts it back (P8E.ours.units-after-putback), so that p16ae and p6l start from the units and the realm they expect.

. "$SCRIPTS/helpers/b2a-host.sh"

p8e_script() { printf '%s' "${P8E_CHECK:?P8E_CHECK is not set}"; }   # the scratch copy P8E_CHECK names

p8e_prep() {   # the scratch copy is there and is the one the head implementer named; the copy, its patch and the original go into the record beside the rows
    local script d f
    for f in p8e-kdc.sh b2a-lib.sh b2a-kdcconf.py b2a-host.sh; do [ -s "$SCRIPTS/helpers/$f" ] || { echo "p8e: helpers/$f is missing" >&2; return 1; }; done
    script=$(p8e_script)
    [ -s "$script" ] || { echo "p8e: $script is missing or empty" >&2; return 1; }
    d=$(dirname "$script")
    mkdir -p "$OUT/p8e"
    {
        echo "# P8E: evidence only: scratch-patched copy, not the package's script"
        sha256sum "$script"
        for f in "$d/field-check.patch" "$d/field-check.orig.sh"; do [ -f "$f" ] && sha256sum "$f"; done
    } > "$OUT/p8e/inputs-sha256.txt"
    cp -p "$script" "$OUT/p8e/field-check.sh.ran"
    [ -f "$d/field-check.patch" ] && cp -p "$d/field-check.patch" "$OUT/p8e/field-check.patch"
    return 0
}

p8e_push() { b2a_push_script p8e-kdc.sh; }

p8e_ours() {   # the rows are p8_check's, under P8E.ours.*
    local f="$OUT/p8e/ours-field-check.txt"
    deadline
    note "P8E: the scratch-patched field-check.sh on the kdc (EVIDENCE ONLY, not the package's script)"
    kdc_script p8e/ours-field-check "$(p8e_script)" 900
    note "P8E rc=$KS_RC: $(tail -1 "$f")"
    verdict P8E.ours.rc "$([ "$KS_RC" = 0 ] && echo PASS || echo FAIL)" "ssh exit status" 0 "$KS_RC"
    expect P8E.ours.enforcing "$f" '^Enforcing$' 1
    expect P8E.ours.fourth-attempt-refused "$f" 'credentials have been revoked'
    expect P8E.ours.db-and-lockout-file-unchanged "$f" '^ok: database [0-9a-f]{64} and its age unchanged, principal\.lockout inode [0-9]+ unchanged$' 1
    expect P8E.ours.nothing-to-relabel "$f" '^ok: restorecon -n would relabel nothing$' 1
    expect P8E.ours.put-back "$f" '^ok: the principal, the policy and /root/p8-check are gone$' 1
    expect P8E.ours.no-avc "$f" '^ok: no AVC since the start$' 1
    expect P8E.ours.no-fail-line "$f" '^(FAIL|bad:)' 0
    expect P8E.ours.pass "$f" '^PASS$' 1
    # the line the scratch patch changed: which branch ran (recorded, not judged: with iprop off MIT keeps no principal.ulog either)
    info P8E.ours.ulog-branch "$f" 'ok: no principal\.ulog|matchpathcon -V .*principal\.ulog' "(neither branch's line is in the output)"
    p8e_aftermath
    return 0
}

p8e_aftermath() {   # whatever the check returned: the kdc's units and the realm as the next module expects them (the check ends normally with both done: a FAIL row here means it stopped early)
    local f="$OUT/p8e/ours-after.txt"
    cell p8e/ours-after kdc "sudo bash $VMD/b2a/p8e-kdc.sh after" none < /dev/null
    expect P8E.ours.units-after-check "$f" '^UNITS_BEFORE krb5kdc=active kadmin=active$' 1      # FAIL: the check left krb5kdc or kadmin down
    expect P8E.ours.leftovers "$f" '^LEFT ' 0                                                      # FAIL: the check left its principal, policy or directory
    expect P8E.ours.units-after-putback "$f" '^UNITS_AFTER krb5kdc=active kadmin=active$' 1
    expect P8E.ours.putback-failed "$f" '^(REMOVE_FAILED|START_FAILED|KADMIND_NOT_LISTENING)' 0
    return 0
}
