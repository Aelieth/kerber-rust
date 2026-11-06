# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/p6b.sh: B2 module P6b, the client-tool families no gate reaches (b2-client; spec: spec/p6b.md).
# Records of the recorded leg: {mit,rust}/client{1,2}-{mit,rust}-<cell>.txt (R, 80 transcripts), R/lab/rcs.txt (the rc lists), R/lab/wrapper.txt; the reports on past -s, kinit -I (the -U sentence) and on the whole series.
# Landed a16a7b5d (tree 4f0d3c51); the proof hold 2026-10-09 13:13:55-13:19:41Z. The leg's wrapper script is not saved: the cells below are rewritten from those outputs and reports.
# The cells, per stage (MIT = stock krb5-server 1.22.2-4.fc43, ours = after docs/install.md's upgrade), on client1 and client2, as the lab user (plain ssh), with MIT's tool (/usr/bin) and ours ($VMD/ours/<name>),
# alice's password on stdin where a prompt is expected (R = the record's cell name, rc as recorded):
#   kinit    `kinit -c FILE:<in> alice`                                 rc 0   the prompt only                                                                          (R kinit)
#   I        `kinit -c FILE:<out> -I FILE:<in> alice`                   rc 0   the prompt only                                                                          (R I)
#   IV       `KRB5CCNAME=FILE:<outv> kinit -V -I FILE:<in> alice`       rc 0   `Using default cache: <outv>` / `Using specified input cache: FILE:<in>` / `Using principal: alice@REALM` / prompt / `Authenticated to Kerberos v5`   (R IV)
#   Imiss    `kinit -c FILE:<out2> -I FILE:<no such cache> alice`       rc 0   the prompt only, no error line                                                          (R Imiss)
#   S        `kvno -c FILE:<in> -S host <own fqdn>`                     rc 0   `host/<fqdn>@REALM: kvno = N` (record: client1 2, client2 3)                              (R S)
#   U-krbtgt `kvno -c FILE:<in> -U alice krbtgt/REALM`                  rc 1   `Invalid argument client and server principal names must match`                           (R U-krbtgt)
#   U        `kvno -c FILE:<in> -U alice alice@REALM`                   rc 1   `KDC has no support for padata type while getting credentials for alice@REALM`           (R U)
#   kt       ktutil, stdin `rkt <keytab>` `list` `quit`                 rc 0   `rkt: Permission denied while reading keytab "<keytab>"` and the `slot KVNO Principal` header (the lab user cannot read root's keytab; MIT echoes the requests, ours does not: content lines only)   (R kt)
#   kp       kpasswd, stdin old new new                                 rc 0   the three prompts and `Password changed.`                                               (R kp)
#   past     client1: `kinit -s <1 hour ago> alice` then `klist -f`     rc 0   `Valid starting` = the call's second (a past start is clamped), `Flags: FRIA`            (R past)
#   future   client1: `kinit -s <1 hour ahead> alice` then `klist -f`   rc 0   `Valid starting` = the stamp, `Flags: FDdiRIA`                                             (R future)
# Parity rule of the leg: the rc lists equal on the two stages and the two tools, the outputs equal after masking the program name (the argv0 prefix `kvno:` / `krb5-kvno:`), the cache-name suffix and the stamps; ktutil by its content lines.
# Differences from the recorded leg:
#   - the ours stage is dist/install.sh's upgrade of the final ship build (otp/install-ours.sh), not a Rust snapshot with two binaries copied in; ours run as $VMD/ours/{kinit,klist,kvno,kdestroy,kpasswd,ktutil,kswitch}
#     (the names dist/install.sh install-clients gives them), so their error lines carry the bare name like MIT's (the leg ran them as /home/lab/p6b/krb5-*); the shell pushes the first five, this module pushes ktutil and kswitch
#     from the ship build's directory ($SHIP: the frozen set has no ktutil or kswitch), sha256 checked on both sides and listed in P6b/ship-extra-sha256.txt;
#   - the kpasswd cell changes four scratch principals p6bkp-c<1|2><m|r> (one per client and tool, made and deleted by helpers/p6b-kdc.sh), not alice: alice's key version number is part of the shell's realm row at the module
#     boundary and must not move; the leg reset alice with `kadmin.local cpw` between the tools;
#   - the service of the S cell is the client's own host principal, built from the shell's HOSTPRINC (`host/client1.kerber.test`, the leg's `host/$(hostname -f)`), asked as `-S host <fqdn>`;
#   - ktutil's keytab is $P6B_KT (default /etc/krb5.keytab); only a rehearsal sets it (the fake lab runs as one user, so it names a path under a root-only directory to get the same EACCES);
#   - the cells run one ssh each through b2c-vm.sh run (the leg: one ssh per client and stage); the -s cells use the client's own `date -u -d`.
# ADDED (not in the recorded leg; MIT is the oracle, ours must equal it): `kinit -S kadmin/changepw` (alternate service name), `-4` of kinit, klist and kdestroy (`Kerberos 4 is no longer supported`, rc 3), `klist -V`,
# `kdestroy -c` (rc 0, the cache gone), and kswitch in a DIR collection (alice and a scratch principal made by MIT's kinit for both tools, then `kswitch -p alice`, `-p p6bsw`, `-p nobody`; MIT's klist shows the result).
# Not VM cells (units and gates only): steps 01-03, 05-08, 10, 11, 16 of the series, FILE ccache versions 1-3 (docs/mit-deviations.md:18) and the DST row.
# shellcheck source=/dev/null
. "$SCRIPTS/helpers/b2a-host.sh"
declare -F b2c_init > /dev/null || . "$SCRIPTS/helpers/b2c-lib.sh"

p6b_init() {   # the module's constants, assigned in a function (the shell's hygiene check refuses top-level assignments); idempotent
    [ -n "${P6B_INIT_DONE:-}" ] && return 0
    P6B_INIT_DONE=1
    b2c_init
    P6B_PRINCS='p6bkp-c1m p6bkp-c1r p6bkp-c2m p6bkp-c2r p6bsw'
    P6B_MASK=('s#^(/[^ :]*/)?(krb5-)?(kinit|klist|kvno|kdestroy|kpasswd|kswitch|ktutil): #PROG: #'
              's#/b2c/p6b-(mit|ours)-(mit|ours)-#/b2c/p6b-STAGE-TOOL-#g'
              's/START:[0-9]{14}/START:<stamp>/'
              's#[0-9]{2}/[0-9]{2}/[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}#<TIME>#g'
              's/tkt[A-Za-z0-9]{6}/tktXXXXXX/g'
              's/p6bkp-c([12])[mr]/p6bkp-cN/g')
}

p6b_prep() {
    local f d p src="" sums
    p6b_init
    for f in p6b-kdc.sh p6b-vm.sh b2a-lib.sh b2a-kdcconf.py b2a-host.sh; do [ -s "$SCRIPTS/helpers/$f" ] || { echo "p6b: helpers/$f is missing" >&2; return 1; }; done
    b2c_prep_check || return 1
    # ktutil and kswitch are not in the frozen set: the first of these directories that has both
    for d in "${P6B_SHIP_EXTRA:-}" "${SHIP:-}"; do
        [ -n "$d" ] || continue
        [ -d "$d/release" ] && d=$d/release
        if [ -x "$d/krb5-ktutil" ] && [ -x "$d/krb5-kswitch" ]; then src=$d; break; fi
    done
    [ -n "$src" ] || { echo "p6b: no krb5-ktutil and krb5-kswitch in \$P6B_SHIP_EXTRA or \$SHIP" >&2; return 1; }
    mkdir -p "$W/ship/release"
    for p in krb5-ktutil krb5-kswitch; do cp -p "$src/$p" "$W/ship/release/$p" || return 1; done
    sums="$OUT/p6b/ship-extra-sha256.txt"
    {
        echo "# the two client programs of the ship build that the frozen set lacks, taken from $src; the VMs' copies are checked against these lines"
        ( cd "$W/ship/release" && sha256sum krb5-ktutil krb5-kswitch )
    } > "$sums"
    note "p6b: krb5-ktutil and krb5-kswitch from $src ($(grep -c '^[0-9a-f]\{64\}' "$sums") sha256 lines in p6b/ship-extra-sha256.txt)"
    return 0
}

p6b_push() {   # the two extra programs on both clients (push checks the sha256 on both sides), the kdc-side script, the client helper
    local c p n want got
    p6b_init
    b2a_push_script p6b-kdc.sh || return 1
    b2c_push_vm client1 client2 || return 1
    for c in "${CLIENTS[@]}"; do
        push "$c" "$SCRIPTS/helpers/p6b-vm.sh" "$VMD/p6b-vm.sh" 755 || return 1
        for p in krb5-ktutil krb5-kswitch; do
            push "$c" "$W/ship/release/$p" "$VMD/ours/${p#krb5-}" 755 || return 1
            n=${p#krb5-}
            want=$(awk -v p="$p" '$2 == p { print $1 }' "$OUT/p6b/ship-extra-sha256.txt")
            got=$(vm "$c" "sha256sum $VMD/ours/$n" 2>> "$LOG" < /dev/null | cut -d' ' -f1)
            verdict "P6B.push.$c.ours-$n-sha256" "$([ -n "$want" ] && [ "$want" = "$got" ] && echo PASS || echo FAIL)" "the VM's $VMD/ours/$n = the ship build's $p" "$want" "${got:-none}"
        done
    done
    return 0
}

p6b_f() { printf '%s/p6b/%s-%s-%s-%s.txt' "$OUT" "$1" "$2" "$3" "$4"; }   # p6b_f STAGE CELL TOOL CLIENT: the cell's transcript
p6b_cc() { printf '%s/b2c/p6b-%s-%s-%s' "$VMD" "$1" "$2" "$3"; }          # p6b_cc STAGE TOOL NAME: a cache path on the VM
p6b_fq() { local h=${HOSTPRINC[$1]#host/}; printf '%s' "${h%@*}"; }        # p6b_fq CLIENT: the client's own host name (the shell's HOSTPRINC)

p6b_only_prompt() {   # p6b_only_prompt LABEL FILE RC: the cell printed the password prompt and nothing else, and exited RC
    local l=$1 f=$2 rc=$3
    expect "$l.rc" "$f" "^\\[rc=$rc\\]\$"
    expect "$l.prompt" "$f" "^Password for alice@$RRX: ?\$"
    expect_under "$l.stdout-one-line" "$f" '^== stdout$' '.' 1
    expect_under "$l.stderr-empty" "$f" '^== stderr$' '.' 0
}
p6b_err_only() {   # p6b_err_only LABEL FILE RC RX: exit RC, one stderr line matching RX, nothing on stdout
    local l=$1 f=$2 rc=$3 rx=$4
    expect "$l.rc" "$f" "^\\[rc=$rc\\]\$"
    expect_under "$l.stderr-line" "$f" '^== stderr$' "$rx" 1
    expect_under "$l.stderr-one-line" "$f" '^== stderr$' '.' 1
    expect_under "$l.stdout-empty" "$f" '^== stdout$' '.' 0
}

p6b_cells() {   # p6b_cells STAGE CLIENT TOOL: every cell of one (client, tool) in one stage
    local st=$1 c=$2 t=$3 l f kin kls kvn kds kpw ktu ksw fq fqx kt ktx in out outv out2 svc past fut coll tl kprinc fam prog
    kin=$(b2c_tool "$t" kinit); kls=$(b2c_tool "$t" klist); kvn=$(b2c_tool "$t" kvno); kds=$(b2c_tool "$t" kdestroy)
    kpw=$(b2c_tool "$t" kpasswd); ktu=$(b2c_tool "$t" ktutil); ksw=$(b2c_tool "$t" kswitch)
    fq=$(p6b_fq "$c"); fqx=${fq//./\\.}
    kt=${P6B_KT:-/etc/krb5.keytab}; ktx=${kt//./\\.}
    in=$(p6b_cc "$st" "$t" in); out=$(p6b_cc "$st" "$t" out); outv=$(p6b_cc "$st" "$t" outv); out2=$(p6b_cc "$st" "$t" out2)
    svc=$(p6b_cc "$st" "$t" svc); past=$(p6b_cc "$st" "$t" past); fut=$(p6b_cc "$st" "$t" fut); coll=$(p6b_cc "$st" "$t" coll)
    if [ "$t" = mit ]; then tl=m; else tl=r; fi
    kprinc="p6bkp-c${c#client}$tl"
    # ---- kinit: the input cache; then -I, -V -I and -I with a missing cache
    l="P6B.$st.kinit-$t-$c"; f=$(p6b_f "$st" kinit "$t" "$c")
    alice_pw | b2c_run "p6b/$st-kinit-$t-$c" "$c" --in-stdin --rm "$in" -- "$kin" -c "FILE:$in" alice
    p6b_only_prompt "$l" "$f" 0
    l="P6B.$st.I-$t-$c"; f=$(p6b_f "$st" I "$t" "$c")
    alice_pw | b2c_run "p6b/$st-I-$t-$c" "$c" --in-stdin --rm "$out" -- "$kin" -c "FILE:$out" -I "FILE:$in" alice
    p6b_only_prompt "$l" "$f" 0
    l="P6B.$st.IV-$t-$c"; f=$(p6b_f "$st" IV "$t" "$c")
    alice_pw | b2c_run "p6b/$st-IV-$t-$c" "$c" --in-stdin --rm "$outv" --env "KRB5CCNAME=FILE:$outv" -- "$kin" -V -I "FILE:$in" alice
    expect "$l.rc" "$f" '^\[rc=0\]$'
    expect "$l.prompt" "$f" "^Password for alice@$RRX: ?\$"
    expect_under "$l.stdout-one-line" "$f" '^== stdout$' '.' 1                    # -V writes its lines to stderr (R IV: the four lines are the stderr of the cell), the prompt is the whole stdout
    expect_under "$l.default-cache" "$f" '^== stderr$' "^Using default cache: .*/p6b-$st-$t-outv\$"
    expect_under "$l.input-cache" "$f" '^== stderr$' "^Using specified input cache: FILE:.*/p6b-$st-$t-in\$"
    expect_under "$l.principal" "$f" '^== stderr$' "^Using principal: alice@$RRX\$"
    expect_under "$l.authenticated" "$f" '^== stderr$' '^Authenticated to Kerberos v5$'
    expect_under "$l.stderr-four-lines" "$f" '^== stderr$' '.' 4
    l="P6B.$st.Imiss-$t-$c"; f=$(p6b_f "$st" Imiss "$t" "$c")
    alice_pw | b2c_run "p6b/$st-Imiss-$t-$c" "$c" --in-stdin --rm "$out2" -- "$kin" -c "FILE:$out2" -I "FILE:$VMD/b2c/p6b-no-such-ccache" alice
    p6b_only_prompt "$l" "$f" 0
    # ---- kvno -S (the own host principal), -U twice
    l="P6B.$st.S-$t-$c"; f=$(p6b_f "$st" S "$t" "$c")
    b2c_run "p6b/$st-S-$t-$c" "$c" -- "$kvn" -c "FILE:$in" -S host "$fq" < /dev/null
    expect "$l.rc" "$f" '^\[rc=0\]$'
    expect "$l.line" "$f" "^host/$fqx@$RRX: kvno = [0-9]+\$"
    expect_under "$l.stderr-empty" "$f" '^== stderr$' '.' 0
    l="P6B.$st.U-krbtgt-$t-$c"; f=$(p6b_f "$st" U-krbtgt "$t" "$c")
    b2c_run "p6b/$st-U-krbtgt-$t-$c" "$c" -- "$kvn" -c "FILE:$in" -U alice "krbtgt/$REALM" < /dev/null
    p6b_err_only "$l" "$f" 1 '^([^ :]*/)?(krb5-)?kvno: Invalid argument client and server principal names must match$'
    l="P6B.$st.U-$t-$c"; f=$(p6b_f "$st" U "$t" "$c")
    b2c_run "p6b/$st-U-$t-$c" "$c" -- "$kvn" -c "FILE:$in" -U alice "alice@$REALM" < /dev/null
    p6b_err_only "$l" "$f" 1 "^([^ :]*/)?(krb5-)?kvno: KDC has no support for padata type while getting credentials for alice@$RRX\$"
    # ---- ktutil as the lab user: the keytab is root's
    l="P6B.$st.kt-$t-$c"; f=$(p6b_f "$st" kt "$t" "$c")
    printf 'rkt %s\nlist\nquit\n' "$kt" | b2c_run "p6b/$st-kt-$t-$c" "$c" --in-stdin -- "$ktu"
    expect "$l.rc" "$f" '^\[rc=0\]$'
    expect "$l.permission-denied" "$f" "^(ktutil:  )*rkt: Permission denied while reading keytab \"$ktx\"\$"
    expect "$l.header" "$f" '^(ktutil:  )*slot KVNO Principal$'
    expect "$l.rule" "$f" '^---- ---- -+$'
    expect "$l.no-entry" "$f" '^[[:space:]]*[0-9]+[[:space:]]+[0-9]+[[:space:]]+host/' 0
    # ---- kpasswd of a scratch principal (alice is not changed): the old password, the new one twice
    l="P6B.$st.kp-$t-$c"; f=$(p6b_f "$st" kp "$t" "$c")
    { b2_pw 1; b2_pw 2; b2_pw 2; } | cell "p6b/$st-kp-$t-$c" "$c" "bash $VMD/b2c-vm.sh run --in-stdin -- $kpw $kprinc" kdc+kadmin
    expect "$l.rc" "$f" '^\[rc=0\]$'
    expect "$l.prompt-old" "$f" "^Password for $kprinc@$RRX: ?\$"
    expect "$l.prompt-new" "$f" '^Enter new password: ?$'
    expect "$l.prompt-again" "$f" '^Enter it again: ?$'
    expect "$l.changed" "$f" '^Password changed\.$'
    expect_part "$l.log-chpw" "$f" kadmin "chpw request from [0-9a-f.:]+ for $kprinc@$RRX: success\$" 1
    # ---- ADDED: kinit -S, -4 of three tools, klist -V, kdestroy, kswitch
    l="P6B.$st.Skinit-$t-$c"; f=$(p6b_f "$st" Skinit "$t" "$c")
    alice_pw | b2c_run "p6b/$st-Skinit-$t-$c" "$c" --in-stdin --rm "$svc" -- bash "$VMD/p6b-vm.sh" skinit "$kin" "$kls" "$svc"
    expect "$l.rc" "$f" '^\[rc=0\]$'
    expect "$l.kinit-rc" "$f" '^\[kinit rc=0\]$'
    expect "$l.prompt" "$f" "^Password for alice@$RRX: ?\$"
    expect "$l.service-ticket" "$f" "kadmin/changepw@$RRX\$"
    expect "$l.klist-rc" "$f" '^\[klist rc=0\]$'
    for fam in kinit klist kdestroy; do
        l="P6B.$st.v4-$fam-$t-$c"; f=$(p6b_f "$st" "v4-$fam" "$t" "$c")
        case $fam in kinit) prog=$kin ;; klist) prog=$kls ;; kdestroy) prog=$kds ;; esac
        b2c_run "p6b/$st-v4-$fam-$t-$c" "$c" -- "$prog" -4 < /dev/null
        p6b_err_only "$l" "$f" 3 '^Kerberos 4 is no longer supported$'
    done
    l="P6B.$st.klistV-$t-$c"; f=$(p6b_f "$st" klistV "$t" "$c")
    b2c_run "p6b/$st-klistV-$t-$c" "$c" -- "$kls" -V < /dev/null
    expect "$l.rc" "$f" '^\[rc=0\]$'
    expect "$l.version" "$f" '^Kerberos 5 version 1\.22\.2$'
    expect_under "$l.stderr-empty" "$f" '^== stderr$' '.' 0
    l="P6B.$st.kdestroy-$t-$c"; f=$(p6b_f "$st" kdestroy "$t" "$c")
    b2c_run "p6b/$st-kdestroy-$t-$c" "$c" -- bash "$VMD/p6b-vm.sh" kdestroy "$kds" "$in" < /dev/null
    expect "$l.rc" "$f" '^\[rc=0\]$'
    expect "$l.kdestroy-rc" "$f" '^\[kdestroy rc=0\]$'
    expect "$l.cache-gone" "$f" '^CACHE_GONE$'
    expect_under "$l.stderr-empty" "$f" '^== stderr$' '.' 0
    l="P6B.$st.sw-$t-$c"; f=$(p6b_f "$st" sw "$t" "$c")
    { alice_pw; b2_pw 1; } | b2c_run "p6b/$st-sw-$t-$c" "$c" --in-stdin -- bash "$VMD/p6b-vm.sh" kswitch "$coll" "$(b2c_tool mit kinit)" "$ksw" "$(b2c_tool mit klist)"
    expect "$l.rc" "$f" '^\[rc=0\]$'
    expect "$l.kinit-alice" "$f" '^\[kinit alice rc=0\]$'
    expect "$l.kinit-p6bsw" "$f" '^\[kinit p6bsw rc=0\]$'
    expect_under "$l.list-alice" "$f" '^== klist -l$' "^alice@$RRX +DIR::.*/tkt[A-Za-z0-9]*\$"
    expect_under "$l.list-p6bsw" "$f" '^== klist -l$' "^p6bsw@$RRX +DIR::.*/tkt[A-Za-z0-9]*\$"
    expect_under "$l.switch-alice-rc" "$f" '^== kswitch -p alice$' '^\[kswitch rc=0\]$'
    expect_under "$l.switch-alice-primary" "$f" '^== kswitch -p alice$' "^Default principal: alice@$RRX\$"
    expect_under "$l.switch-p6bsw-rc" "$f" '^== kswitch -p p6bsw$' '^\[kswitch rc=0\]$'
    expect_under "$l.switch-p6bsw-primary" "$f" '^== kswitch -p p6bsw$' "^Default principal: p6bsw@$RRX\$"
    expect_under "$l.switch-nobody-rc" "$f" '^== kswitch -p nobody$' '^\[kswitch rc=1\]$'
    expect "$l.switch-nobody-text" "$f" '^([^ :]*/)?(krb5-)?kswitch: Matching credential not found while searching for ccache for nobody$'
    expect_under "$l.switch-nobody-primary" "$f" '^== kswitch -p nobody$' "^Default principal: p6bsw@$RRX\$"
    # ---- client1 only: kinit -s, a start an hour in the past (clamped to now) and an hour ahead (postdated)
    if [ "$c" = client1 ]; then
        l="P6B.$st.past-$t-$c"; f=$(p6b_f "$st" past "$t" "$c")
        alice_pw | b2c_run "p6b/$st-past-$t-$c" "$c" --in-stdin --rm "$past" -- bash "$VMD/p6b-vm.sh" start '1 hour ago' "$kin" "$kls" "$past"
        p6b_start_rows "$l" "$f" past
        l="P6B.$st.future-$t-$c"; f=$(p6b_f "$st" future "$t" "$c")
        alice_pw | b2c_run "p6b/$st-future-$t-$c" "$c" --in-stdin --rm "$fut" -- bash "$VMD/p6b-vm.sh" start '1 hour' "$kin" "$kls" "$fut"
        p6b_start_rows "$l" "$f" future
    fi
}

p6b_start_rows() {   # p6b_start_rows LABEL FILE past|future: the stamp, the ticket row's start, the flags
    local l=$1 f=$2 which=$3 s fmt k t e ok=0
    expect "$l.rc" "$f" '^\[rc=0\]$'
    expect "$l.kinit-rc" "$f" '^\[kinit rc=0\]$'
    expect "$l.klist-rc" "$f" '^\[klist rc=0\]$'
    expect "$l.prompt" "$f" "^Password for alice@$RRX: ?\$"
    s=$(sed -n 's/^START:\([0-9]\{14\}\)$/\1/p' "$f" | head -n 1)
    fmt=""
    [ -n "$s" ] && fmt="${s:4:2}/${s:6:2}/${s:0:4} ${s:8:2}:${s:10:2}:${s:12:2}"
    if [ "$which" = past ]; then
        expect "$l.flags" "$f" ', Flags: FRIA$'
        verdict "$l.start-clamped" "$([ -n "$fmt" ] && ! grep -q "^$fmt  " "$f" && echo PASS || echo FAIL)" "a past start is clamped: the ticket row does not start at the stamp $fmt" "not the stamp" "$(grep -m1 'krbtgt/' "$f" | cut -c1-40)"
    else
        expect "$l.flags" "$f" ', Flags: FDdiRIA$'
        # kinit hands libkrb5 the start as an OFFSET from its own `now`, and libkrb5 adds it to ITS now when it builds the request: when the second turns between the two reads the ticket starts one second after the stamp
        # (seen in the rehearsal of 2026-10-13, MIT's kinit against the ship KDC: stamp 15:10:54, ticket 15:10:55), so the row accepts the stamp and the two seconds after it
        if [ -n "$s" ]; then
            e=$(date -u -d "${s:0:4}-${s:4:2}-${s:6:2} ${s:8:2}:${s:10:2}:${s:12:2} UTC" +%s 2> /dev/null)
            for k in 0 1 2; do
                t=$(date -u -d "@$((e + k))" +'%m/%d/%Y %H:%M:%S' 2> /dev/null)
                [ -n "$t" ] && grep -q "^$t  " "$f" && ok=1
            done
        fi
        verdict "$l.start-is-stamp" "$([ "$ok" = 1 ] && echo PASS || echo FAIL)" "the ticket row starts at the stamp $fmt (or one or two seconds after it: libkrb5 adds the offset to its own clock)" "the stamp" "$(grep -m1 'krbtgt/' "$f" | cut -c1-40)"
    fi
}

p6b_stage() {   # p6b_stage mit|ours
    local st=$1 L=P6B.$1 c t ok=1 n
    b2c_kdc_ready p6b "$st" || return 0
    for c in "${CLIENTS[@]}"; do b2c_work_ok p6b "$st" "$c" || ok=0; done
    if [ "$ok" = 0 ]; then b2c_not_run "P6B.$st.cells" "a client's work directory cannot be used by the lab user (see the P6B.$st.workdir rows): no cell ran"; return 0; fi
    b2a_pw3 | b2a_run_kdc "p6b/$st-run-setup" p6b-kdc.sh "$st" setup
    b2a_split "$OUT/p6b/$st-run-setup.txt" "$OUT/p6b" "$st"
    for n in $P6B_PRINCS; do expect "$L.setup.$n-created" "$OUT/p6b/$st-add-$n.txt" "^Principal \"$n@$RRX\" created\\.\$"; done
    for c in "${CLIENTS[@]}"; do
        for t in mit ours; do deadline; p6b_cells "$st" "$c" "$t"; done
    done
    b2a_pw3 | b2a_run_kdc "p6b/$st-run-cleanup" p6b-kdc.sh "$st" cleanup
    b2a_split "$OUT/p6b/$st-run-cleanup.txt" "$OUT/p6b" "$st"
    for n in $P6B_PRINCS; do expect "$L.cleanup.$n-deleted" "$OUT/p6b/$st-del-$n.txt" "^Principal \"$n@$RRX\" deleted\\.\$"; done
    expect "$L.cleanup.p6bsw-gone" "$OUT/p6b/$st-getprinc-gone.txt" '^get_principal: Principal does not exist while retrieving "p6bsw@'"$RRX"'"\.$'
    return 0
}
p6b_mit() { p6b_init; p6b_stage mit; }
p6b_ours() { p6b_init; p6b_stage ours; }

p6b_kt_lines() {   # p6b_kt_lines FILE: ktutil's content lines of a cell (MIT echoes the requests through its prompt, ours does not: the prompts are cut off the front of a line)
    cell_body "$1" | sed -E 's/^(ktutil:  )+//' | grep -E '^(rkt: |slot KVNO Principal$|---- ---- )'
}
p6b_cmp() {   # p6b_cmp LABEL CELL STAGE-A TOOL-A STAGE-B TOOL-B CLIENT: the client parts of two cells, equal after the named masks
    local label=$1 k=$2 sa=$3 ta=$4 sb=$5 tb=$6 c=$7 d="$OUT/p6b/norm" fa fb
    mkdir -p "$d"
    fa=$(p6b_f "$sa" "$k" "$ta" "$c"); fb=$(p6b_f "$sb" "$k" "$tb" "$c")
    if [ "$k" = kt ]; then p6b_kt_lines "$fa" > "$d/$label.a.txt" 2> /dev/null; p6b_kt_lines "$fb" > "$d/$label.b.txt" 2> /dev/null
    else cell_body "$fa" > "$d/$label.a.txt" 2> /dev/null; cell_body "$fb" > "$d/$label.b.txt" 2> /dev/null; fi
    parity_eq "$label" "$d/$label.a.txt" "$d/$label.b.txt" "${P6B_MASK[@]}"
}

p6b_parity() {
    p6b_init
    local c k s t cells="kinit I IV Imiss S U-krbtgt U kt kp Skinit v4-kinit v4-klist v4-kdestroy klistV kdestroy sw"
    for c in "${CLIENTS[@]}"; do
        for k in $cells past future; do
            case $k in past | future) [ "$c" = client1 ] || continue ;; esac
            for s in mit ours; do p6b_cmp "P6B.parity.$k-prog-$s-$c" "$k" "$s" mit "$s" ours "$c"; done      # the programs differ, the KDC does not
            for t in mit ours; do p6b_cmp "P6B.parity.$k-xkdc-$t-$c" "$k" mit "$t" ours "$t" "$c"; done     # the KDC changes, the program does not
        done
    done
    # controls: a doctored copy differs; two different cells differ; the masks are needed (the unmasked comparison of a cell with the program name in it differs)
    parity_control P6B.parity.kinit-prog "$OUT/p6b/norm/P6B.parity.kinit-prog-mit-${CLIENTS[0]}.a.txt" "$OUT/p6b/norm/P6B.parity.kinit-prog-mit-${CLIENTS[0]}.b.txt" "${P6B_MASK[@]}"
    p6b_differ P6B.parity.control.kinit-vs-I "$(p6b_f mit kinit mit "${CLIENTS[0]}")" "$(p6b_f mit IV mit "${CLIENTS[0]}")"
    p6b_differ P6B.parity.control.U-vs-U-krbtgt "$(p6b_f mit U mit "${CLIENTS[0]}")" "$(p6b_f mit U-krbtgt mit "${CLIENTS[0]}")"
    # the argv0 mask maps the three forms of the program name (MIT's bare name, ours' krb5- name, a path) to one
    local u
    u=$(printf '%s\n' 'kvno: x' 'krb5-kvno: x' '/var/tmp/otp3/ours/kvno: x' '/usr/bin/kvno: x' | b2_norm /dev/stdin "${P6B_MASK[@]}" | sort -u | paste -sd'|' -)
    verdict P6B.parity.control.program-name-mask "$([ "$u" = 'PROG: x' ] && echo PASS || echo FAIL)" "the argv0 mask maps the program name in front of an error line to PROG" 'PROG: x' "$u"
    return 0
}
p6b_differ() {   # p6b_differ LABEL A B: the client parts of two different cells differ after the masks
    local label=$1 a=$2 b=$3 na nb
    na=$(cell_body "$a" 2> /dev/null | b2_norm /dev/stdin "${P6B_MASK[@]}"); nb=$(cell_body "$b" 2> /dev/null | b2_norm /dev/stdin "${P6B_MASK[@]}")
    if [ -n "$na" ] && [ "$na" != "$nb" ]; then verdict "$label" PASS "two different cells must differ" differ differ ""
    else verdict "$label" FAIL "two different cells must differ" differ same ""; fi
}

p6b_clean() {   # the caches are removed by their cells and the work directory goes; once more, quietly
    p6b_init
    b2c_clean_vms
    return 0
}
