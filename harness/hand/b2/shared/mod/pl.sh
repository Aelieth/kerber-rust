# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/pl.sh: B2 module PL, the kinit cell (b2-client; spec: spec/pl.md). The GSS acceptor clockskew cell is NOT built (below).
# Record of the recorded leg (R). Landed b06d07d1 (tree d77d17f2); the proof hold 2026-10-08 00:19:52-00:22:02Z (R/r2/lab/{mit,rust,mit-rustkdc,rust-rustkdc}.out and .trace, R/r2/ship-build.txt).
# The cell, per stage (MIT = stock krb5-server 1.22.2-4.fc43, ours = after docs/install.md's upgrade) x client x program (MIT's kinit/klist/kvno, ours): a client krb5.conf with a [libdefaults] REALM NODE,
#   kinit alice@REALM  ->  a 1h ticket renewable for 2h, flags PRIA (proxiable, renewable, initial, pre-authenticated), addresses in the AS-REQ (noaddresses = false);
#   klist -f -a, kvno krbtgt/REALM  (R/r2/lab/mit.out:1-9; the commit message R/f-series/01.msg:1-14 says "a 1h ticket, a 2h renew, flags PRIA, and addresses present")
# Parity rule of the leg: rc, flags, lifetimes, request sizes, preauth lines, kvno line equal; documented row: klist prints the address numerically, MIT resolves it unless -n
#   (docs/mit-deviations.md:76; klist.c:878-880). At the tip the date format equals MIT's (P6l), so the klist outputs are equal apart from the address row.
# Differences from the recorded leg:
#   - the leg's krb5.conf is NOT recorded. Reconstructed from the commit message, the recorded outputs and the unit test pl_per_realm_keys_read_the_realm_then_the_top_level
#     (crates/krb5-config/src/tests.rs:1964-2015): the VM's own /etc/krb5.conf plus, first under [libdefaults], the realm node
#       KERBER.TEST = { forwardable = false  proxiable = true  ticket_lifetime = 1h  renew_lifetime = 2h  noaddresses = false  preferred_preauth_types = 2 }
#     (forwardable = false because the recorded flags have no F while the base has forwardable = true at the top level: the realm node must win; preferred_preauth_types = 2 because the recorded hint order
#     starts with PA-ENC-TIMESTAMP (2) and the ticket's pa_type is 2, R/r2/lab/mit.trace:11 and :27). The hint order is judged only as MIT = ours;
#   - the conf is a per-cell copy of the VM's krb5.conf (KRB5_CONFIG), /etc/krb5.conf is not edited; the upgrade is otp/install-ours.sh; both client VMs run the cell (the leg: client2);
#   - klist -f -a and klist -f -a -n (numeric) are both run, so the address row is separated from the rest; ours run as $VMD/ours/{kinit,klist,kvno};
#   - the first-request and later request sizes are compared MIT = ours within a stage (the later ones depend on the KDC's cookie: 439 against 438 bytes on the two KDCs in the record); the later ones are compared
#     after taking out the DER length of the encrypted timestamp's microseconds (b2c_sizes_norm: 1 byte below 128, 2 below 32768, else 3, so a request is 1 byte shorter in about 3 logins in 100; ADDED after the rehearsal of
#     2026-10-13 14:00Z, where MIT's login sent `Encrypted timestamp (for ....30208)` and 438 bytes against ours' 439: a 6% flake per row, 4 rows); and each place may differ by one byte (pl_sizes_close): the request's
#     random nonce is a DER INTEGER of 4 bytes, or 3 in 1 login in 256, and the reply echoes it (the rehearsal of 14:25Z: 437 against 438 with equal microseconds bands, the AS-REP 872 against 873).
# NOT BUILT: the GSS acceptor clockskew cell (R/lab/acc-*.log, init-*.log, proxy-*.log, gss-kinit.out): it needs krb5-gss-accept/-init, which are test-hooks-only (crates/krb5-gss/Cargo.toml:12-20) and not in the ship
#   build, an MIT-side acceptor (source lost) and a delay proxy (lost). The clockskew relation rests on the Rust units (crates/krb5-config/src/tests.rs, crates/krb5-admin/src/kadm5/tests/auth_gssapi.rs, auth_con/tests.rs).
# shellcheck source=/dev/null
declare -F b2c_init > /dev/null || . "$SCRIPTS/helpers/b2c-lib.sh"

pl_init() {   # the module's constants, assigned in a function (the shell's hygiene check refuses top-level assignments); idempotent
    [ -n "${PL_INIT_DONE:-}" ] && return 0
    PL_INIT_DONE=1
    b2c_init
    PL_NODE='forwardable=false,proxiable=true,ticket_lifetime=1h,renew_lifetime=2h,noaddresses=false,preferred_preauth_types=2'
    PL_ADDR_MASK='s/^([[:space:]]*Addresses: ).*/\1<addr>/'
}


pl_prep() { pl_init; b2c_prep_check; }
pl_push() { pl_init; b2c_push_vm client1 client2; }

# SOURCE RECORD: mit.out:1-9 and rust.out:1-9 (stock MIT KDC), mit-rustkdc.out / rust-rustkdc.out (the installed KDC); traces r2/lab/{mit,rust}.trace:3,11,17,18; commit message r2/f-series/01.msg:1-14
pl_cell() {   # pl_cell CLIENT PROG STAGE: kinit, klist -f -a, klist -f -a -n, kvno
    local c=$1 p=$2 st=$3 cc n f l
    cc="$VMD/b2c/pl-$st-$p.cc"; n="pl/$st-k-$p-$c"; f="$OUT/$n.txt"; l="PL.$st.k-$p-$c"
    alice_pw | b2c_login "$n" "$c" "$p" pl-k --cc "$cc" \
        --then "$(b2c_tool "$p" klist) -f -a -c FILE:$cc" \
        --then "$(b2c_tool "$p" klist) -f -a -n -c FILE:$cc" \
        --then "$(b2c_tool "$p" kvno) -c FILE:$cc krbtgt/$REALM@$REALM" \
        -- -c "FILE:$cc" "alice@$REALM"
    b2c_chk_login "$l" "$f" "$p"
    expect_under "$l.klist-rc" "$f" '^== then: .*klist -f -a -c' '^\[then-rc=0\]$'
    expect_under "$l.klist-principal" "$f" '^== then: .*klist -f -a -c' "^Default principal: alice@$RRX\$"
    expect_under "$l.klist-flags" "$f" '^== then: .*klist -f -a -c' ', Flags: PRIA$'
    expect_under "$l.klist-addresses-present" "$f" '^== then: .*klist -f -a -c' '^[[:space:]]*Addresses: .+'
    expect_under "$l.klist-n-rc" "$f" '^== then: .*klist -f -a -n -c' '^\[then-rc=0\]$'
    expect_under "$l.klist-n-numeric" "$f" '^== then: .*klist -f -a -n -c' '^[[:space:]]*Addresses: [0-9a-f.:, ]+$'
    expect_under "$l.kvno-rc" "$f" '^== then: .*kvno' '^\[then-rc=0\]$'
    expect_under "$l.kvno-line" "$f" '^== then: .*kvno' "^krbtgt/$RRX@$RRX: kvno = [0-9]+\$"
    pl_lifetimes "$l" "$f"
    info "$l.hint-list" "$f" 'Processing preauth types:'
    info "$l.request-sizes" "$f" 'Sending request \('
}

pl_when() { date -d "$1" +%s 2> /dev/null; }
pl_lifetimes() {   # pl_lifetimes LABEL FILE: 1h and 2h from the klist block's own dates
    local l=$1 f=$2 blk row sd ed rd s e r
    blk=$(b2c_then "$f" '^== then: .*klist -f -a -c')
    row=$(printf '%s\n' "$blk" | grep -m1 'krbtgt/')
    sd=$(printf '%s\n' "$row" | awk '{ print $1 " " $2 }'); ed=$(printf '%s\n' "$row" | awk '{ print $3 " " $4 }')
    rd=$(printf '%s\n' "$blk" | sed -n 's/^[[:space:]]*renew until \([0-9/.]* [0-9:]*\).*/\1/p' | head -n 1)
    s=$(pl_when "$sd"); e=$(pl_when "$ed"); r=$(pl_when "$rd")
    if [ -n "$s" ] && [ -n "$e" ] && [ -n "$r" ]; then
        same "$l.lifetime-3600" 3600 "$((e - s))" "ticket end - start (s)"
        same "$l.renew-7200" 7200 "$((r - s))" "renew until - start (s)"
    else
        verdict "$l.lifetime-3600" FAIL "dates of the ticket row and the renew row parse" parsed "start [$sd] end [$ed] renew [$rd]"
    fi
}

pl_stage() {   # pl_stage mit|ours
    local st=$1 c
    b2c_kdc_ready pl "$st" || return 0
    for c in "${CLIENTS[@]}"; do
        b2c_conf pl "$c" pl-k --libdefaults-realm-node "$REALM" "$PL_NODE" || { b2c_not_run "PL.$st.conf-$c" "no conf variant on $c"; return 0; }
    done
    b2c_each_cp pl_cell "$st"
    return 0
}
pl_mit() { pl_init; pl_stage mit; }
pl_ours() { pl_init; pl_stage ours; }

pl_block() { b2c_then "$1" "$2" | grep -v '^\[then-rc='; }   # a then block without its rc line

pl_address_row() {   # pl_address_row LABEL MITFILE OURSFILE: the documented klist address row (docs/mit-deviations.md:76)
    local l=$1 m a b
    m=$(pl_block "$2" '^== then: .*klist -f -a -c' | grep -m1 'Addresses: ' | sed 's/^[[:space:]]*Addresses: //')
    a=$(pl_block "$3" '^== then: .*klist -f -a -c' | grep -m1 'Addresses: ' | sed 's/^[[:space:]]*Addresses: //')
    b=$(printf '%s' "$m" | grep -cE '^[0-9a-f.:, ]+$')
    if [ -z "$m" ] || [ -z "$a" ]; then
        verdict "$l" FAIL "both klist outputs have an address row" present "MIT [$m] ours [$a]"
    elif [ "$b" = 0 ] && ! printf '%s' "$a" | grep -qE '[A-Za-z]'; then
        verdict "$l" PASS "documented deviation (docs/mit-deviations.md:76): MIT resolves the address to a name, ours prints it numerically" documented "documented" "MIT [$m] ours [$a]"
    elif [ "$m" = "$a" ]; then
        result "$l" INFO "documented deviation (docs/mit-deviations.md:76)" - 1 "the two rows are equal: [$m] ($([ "$b" != 0 ] && echo 'MIT could not resolve the address here, so both are numeric' || echo 'ours now resolves like MIT: the row is obsolete'))"
    else
        verdict "$l" FAIL "documented deviation (docs/mit-deviations.md:76): MIT a name (or equal numeric), ours numeric" documented "other" "MIT [$m] ours [$a]"
    fi
}

pl_sizes_close() {   # pl_sizes_close A B: the two lists of sizes (words) have the same length and differ by at most 1 byte in each place. A request carries a random 31-bit nonce, a DER INTEGER of 4 bytes, or 3 in 1 login in 256
    # (and the reply echoes it, one byte shorter too); a request one byte shorter is not a different request. The microseconds of the encrypted timestamp are taken out before (b2c_sizes_norm).
    local -a x y
    local i d
    read -ra x <<< "$1"; read -ra y <<< "$2"
    [ "${#x[@]}" = "${#y[@]}" ] && [ "${#x[@]}" -gt 0 ] || return 1
    for i in "${!x[@]}"; do
        d=$((x[i] - y[i]))
        [ "${d#-}" -le 1 ] || return 1
    done
    return 0
}
pl_sizes_row() {   # pl_sizes_row LABEL MITLIST OURSLIST TEXT: a row decided by pl_sizes_close; the columns carry both lists
    if pl_sizes_close "$2" "$3"; then verdict "$1" PASS "$4" "$2" "$3"; else verdict "$1" FAIL "$4" "$2" "$3"; fi
}

pl_parity() {
    pl_init
    local st c p m o d
    for st in mit ours; do
        for c in "${CLIENTS[@]}"; do
            m="$OUT/pl/$st-k-mit-$c.txt"; o="$OUT/pl/$st-k-ours-$c.txt"
            b2c_cmp "PL.parity.k-$st-$c" "$m" "$o" "$PL_ADDR_MASK"
            # the numeric address block (klist -a -n) is not masked: it equals MIT's byte for byte
            pl_block "$m" '^== then: .*klist -f -a -n -c' | sed -E -e 's/[0-9][0-9][.\/][0-9][0-9][.\/]([0-9]{4}|[0-9]{2}) [0-9:]{8}/<DATE>/g' -e 's#FILE:[^ ]*#FILE:<cache>#' > "$OUT/pl/norm/$st-$c.n.mit.txt"
            pl_block "$o" '^== then: .*klist -f -a -n -c' | sed -E -e 's/[0-9][0-9][.\/][0-9][0-9][.\/]([0-9]{4}|[0-9]{2}) [0-9:]{8}/<DATE>/g' -e 's#FILE:[^ ]*#FILE:<cache>#' > "$OUT/pl/norm/$st-$c.n.ours.txt"
            parity_eq "PL.parity.k-addr-numeric-$st-$c" "$OUT/pl/norm/$st-$c.n.mit.txt" "$OUT/pl/norm/$st-$c.n.ours.txt"
            pl_address_row "PL.parity.k-addr-row-$st-$c" "$m" "$o"
            pl_sizes_row "PL.parity.k-request-sizes-$st-$c" "$(b2c_sizes_norm "$m" | tr '\n' ' ')" "$(b2c_sizes_norm "$o" | tr '\n' ' ')" "request sizes in order (the timestamp's microseconds taken out: b2c_sizes_norm; each place within 1 byte: the nonce), MIT = ours within a stage"
        done
    done
    b2c_cmp_control "PL.parity.k-mit-${CLIENTS[0]}" "$PL_ADDR_MASK"
    for p in mit ours; do
        for c in "${CLIENTS[@]}"; do
            pl_sizes_row "PL.parity.k-first-size-xstage-$p-$c" "$(b2c_sizes "$OUT/pl/mit-k-$p-$c.txt" | head -n 1)" "$(b2c_sizes "$OUT/pl/ours-k-$p-$c.txt" | head -n 1)" "first request size (within 1 byte: the nonce), MIT stage = ours stage (the KDC does not enter)"
        done
    done
    # a control for the size rule: a size list with its last size 2 bytes longer must NOT count as close (the tolerance is 1), and one with 1 byte more must
    m=$(b2c_sizes_norm "$OUT/pl/mit-k-mit-${CLIENTS[0]}.txt" | tr '\n' ' ')
    d=$(printf '%s\n' "$m" | awk 'NF { $NF = $NF + 2 } 1')
    if [ -n "${m// /}" ] && ! pl_sizes_close "$m" "$d"; then verdict PL.parity.k-request-sizes.control PASS "a size list 2 bytes longer in its last place must differ" differ differ ""
    else verdict PL.parity.k-request-sizes.control FAIL "a size list 2 bytes longer in its last place must differ" differ same ""; fi
    return 0
}

pl_clean() { pl_init; b2c_clean_vms; return 0; }
