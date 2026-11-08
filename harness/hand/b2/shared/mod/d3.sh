# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/d3.sh: B2-style module D3: what the FEDORA side does with des3-cbc-sha1, recorded in both stages ("d3-lite": cells 1 and 2 below), and, from the later leg on, what UPSTREAM MIT 1.22.2 with des3 and this tree's build
# do with the same keys, MIT stage first, on the lab VM mitd3 (cell 3, the block "cell 3: mitd3" below; spec/d3.md). (lab agent)
# Why it exists: B22 (des3 long-term keys work on upstream MIT, fail on ours: the des3 checksum used the AES derivation, and the keys our tools make lack DES parity) is proven against UPSTREAM MIT in the B22 implementer's
# container-oracle runner. The lab VMs' MIT is Fedora's krb5 1.22.2-4.fc43, which has NO des3-cbc-sha1 at all (krb5_c_valid_enctype is 0 for it, as for the three DES types), so it is not the reference for des3 and nothing here is a
# parity gate: the rows RECORD (INFO), and the controls (PASS/FAIL) say that the cells ran. After B22's fix ours will make des3 keys and use them where Fedora's MIT cannot; that is the documented difference these rows show.
# The two cells, per stage (MIT = the stock krb5-server on the kdc, ours = after docs/install.md's upgrade of the ship build):
#   1. kadmin  the lab realm's own kadmin.local on `addprinc -randkey -e des3-cbc-sha1:normal` and `addprinc -pw ... -e des3-cbc-sha1:normal`: Fedora's creates the principal with only the default AES keys (the -e entry is dropped, no
#              message); controls: `-e arcfour-hmac:normal` gives an arcfour key (-e works for a type the build has), a plain addprinc gives the default keys. And client2's MIT ktutil: `addent -e des3-cbc-sha1` says
#              "Bad encryption type", `-e aes256-cts-hmac-sha1-96` writes the entry. (ours: kadmin.local only; the clients stay MIT's.) Principals d3probe d3probepw d3rc4 d3aes, deleted at the stage's end.
#   2. db      a DB that carries des3 key_data made by upstream MIT (the fixture dir's d3-realm.dump; the realm D3.TEST with a des3+arcfour krbtgt, aesp, mixedp (aes256+des3+arcfour), desonly, desonlyp (des3 only),
#              rc4onlyp, three services svcaes, svcmix, svcdes and their keytabs) loaded into a PRIVATE realm on the kdc by the stage's kdb5_util (what it prints, whether the dump keeps the des3 key_data, getprinc), served by the stage's
#              krb5kdc on ADDR:8089 (the lab KDC on :88 is untouched; the private KDC logs into the lab's KDC log so that the shell's cells slice it). On client2, under a private krb5.conf (profile `lab`: the fleet's AES-sha1 lists;
#              profile `plain`: library defaults), with MIT's clients and ours: kinit of aesp (control), mixedp, desonly, desonlyp, rc4onlyp; kvno of svcaes, svcmix, svcdes with aesp's ticket; kinit -k -t of each service keytab.
#              Then `cpw -pw` on desonly (what a password change does to a des3-only principal), the private KDC restarted, and kinit desonly with the new password.
# Rows: D3.<stage>.<cell> INFO = "rc=; out=[...]; err=[...]; kdc=[the KDC log lines of the run, compacted]"; D3.<stage>.control.* PASS/FAIL (the cells ran: principals created, the arcfour and default controls, the dump loaded, the KDC listening,
# aesp's login works with each client and profile, desonly healed); D3.parity.<cell> INFO = same / differs between the stages (not a verdict), D3.parity.control = a doctored copy differs.
# Rehearsed in the fake lab (real MIT programs from the same rpm in the MIT stage; ours = KS's 7612269f build, and HF's 3a33f82d build): 158 PASS / 0 FAIL / 211 INFO each; with p15b and ks beside it (KS's tree) 1728 PASS / 4 FAIL / 233 INFO, the 4 being
# ks's E1 rows (finding B11). Known from the fake lab (real MIT binaries from the same rpm, KS's 7612269f as ours): the two KDCs and all four client/profile combinations agree on every cell but one: a TGS request for the
# des3-only service svcdes: Fedora's KDC says FINDING_SERVER_KEY "No matching key in entry having a permitted enctype" (kvno: "KDC returned error string: FINDING_SERVER_KEY"), ours (before B22's fix) PREAUTH_FAILED "protocol key length
# does not match etype" (kvno: "Preauthentication failed while getting credentials"). Differences from the first text: none; the secrets: the realm's passwords are throwaway literals of a throwaway realm (the fixture dir's d3-user.pw), the lab's are untouched.
# shellcheck source=/dev/null
. "$SCRIPTS/helpers/b2a-host.sh"
declare -F b2c_init > /dev/null || . "$SCRIPTS/helpers/b2c-lib.sh"

d3_init() {   # the module's constants, assigned in a function (the shell's hygiene check refuses top-level assignments); idempotent
    [ -n "${D3M_INIT_DONE:-}" ] && return 0
    D3M_INIT_DONE=1
    b2c_init
    D3M_FIX=${HAND_FIXTURE_DIR:?HAND_FIXTURE_DIR is not set}   # the D3.TEST fixtures, outside the tree (d3-fixtures.sha256)
    D3M_CLIENT=client2
    D3M_ADDR=${D3_ADDR:-${FIELD_LAB_NET:?FIELD_LAB_NET is not set in field.env}.10}   # the kdc VM's lab address, where the private KDC listens (a knob for the rehearsal: 127.0.0.1)
    D3M_PORT=8089
    D3M_REALM=D3.TEST
    D3M_PROFILES='lab plain'
    D3M_USERS='aesp mixedp desonly desonlyp rc4onlyp'
    D3M_SVCS='svcaes svcmix svcdes'
    D3M_PROBES='d3probe d3probepw d3rc4 d3aes'
}

d3_prep() {
    local f
    d3_init
    for f in d3-kdc.sh b2a-lib.sh b2a-kdcconf.py b2a-host.sh d3-mitd3.sh; do [ -s "$SCRIPTS/helpers/$f" ] || { echo "d3: helpers/$f is missing" >&2; return 1; }; done
    for f in d3-realm.dump d3-realm.stash d3-svcdes.keytab d3-svcmix.keytab d3-svcaes.keytab d3-user.pw d3-old.dump d3-old.stash d3-old-svc.keytab d3-old-mix.keytab d3-old-aes.keytab d3-old-rnd.keytab d3-old-user.pw; do [ -s "$D3M_FIX/$f" ] || { echo "d3: $D3M_FIX/$f is missing" >&2; return 1; }; done
    b2c_prep_check || return 1
    return 0
}

d3_push() {   # the kdc-side script and b2c-vm.sh on client2; the realm's files are pushed per stage (the stage's cleanup shreds them)
    d3_init
    b2a_push_script d3-kdc.sh || return 1
    b2c_push_vm client2 || return 1
    d3m_probe
    return 0
}

d3_kdc() {   # d3_kdc STAGE NAME SECTION [ARGS...]: a section of d3-kdc.sh on the kdc as root (the three throwaway passwords on stdin); transcript $OUT/d3/STAGE-run-NAME.txt (with the lab KDC log delta), its CELL blocks split into $OUT/d3/STAGE-<cell>.txt
    local st=$1 name=$2 sec=$3
    shift 3
    b2a_pw3 | cell "d3/$st-run-$name" kdc "sudo bash $VMD/b2a/d3-kdc.sh $st $sec $*" kdc
    b2a_split "$OUT/d3/$st-run-$name.txt" "$OUT/d3" "$st"
}

d3_conf() {   # d3_conf PROFILE: the client's krb5.conf for the private realm, pushed to client2 as $VMD/b2c/d3-PROFILE.conf
    local pf=$1 f
    mkdir -p "$TMPDIR"
    f="$TMPDIR/d3-$pf.conf"
    {
        printf '[libdefaults]\n    default_realm = %s\n    dns_lookup_realm = false\n    dns_lookup_kdc = false\n    rdns = false\n' "$D3M_REALM"
        if [ "$pf" = lab ]; then
            printf '    udp_preference_limit = 1\n    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96\n'
        fi
        printf '\n[realms]\n    %s = {\n        kdc = %s:%s\n    }\n' "$D3M_REALM" "$D3M_ADDR" "$D3M_PORT"
    } > "$f"
    push "$D3M_CLIENT" "$f" "$VMD/b2c/d3-$pf.conf" 644
    rm -f "$f"
}

d3_keys() {   # d3_keys FILE: the key list of a getprinc transcript, "N keys: type type ..." ("no getprinc" when it has none)
    local n
    n=$(sed -n 's/^Number of keys: //p' "$1" 2> /dev/null | head -n 1)
    if [ -z "$n" ]; then printf 'no getprinc output'; return 0; fi
    printf '%s keys: %s' "$n" "$(sed -n 's/^Key: vno [0-9]*, //p' "$1" | paste -sd' ' -)"
}

d3_sum() {   # d3_sum STAGE NAME: a run's outcome in one line (the exit status, stdout, stderr, the lab KDC log lines the run added, compacted) -> $OUT/d3/STAGE-NAME.sum and an INFO row D3.STAGE.NAME
    local st=$1 nm=$2 f="$OUT/d3/$1-$2.txt" rc out err kdc
    rc=$(sed -n 's/^\[rc=\([0-9]*\)\]$/\1/p' "$f" 2> /dev/null | head -n 1)
    out=$(sed -n '/^== stdout$/,/^== stderr$/p' "$f" 2> /dev/null | sed '1d;$d' | grep -v '^Password for ' | tr '\n\t' '| ' | sed 's/|$//')
    err=$(sed -n '/^== stderr$/,/^# end of cell output$/p' "$f" 2> /dev/null | sed '1d;$d' | tr '\n\t' '| ' | sed 's/|$//')
    kdc=$(sed -n '/^# KDC log lines added/,$p' "$f" 2> /dev/null | grep -E '(AS|TGS)_REQ|verify failure' \
        | sed -E 's/^[A-Z][a-z]{2} [ 0-9]{2} [0-9:]{8} [^ ]+ //; s/krb5kdc\[[0-9]+\]\((info|Error)\): //; s/ \([0-9]+ etypes \{[^}]*\}\) [^ ]+: / /; s/authtime [0-9]+,? *//' | tr '\n\t' '| ' | sed 's/|$//')
    printf 'rc=%s; out=[%s]; err=[%s]; kdc=[%s]\n' "$rc" "$out" "$err" "$kdc" > "$OUT/d3/$st-$nm.sum"
    result "D3.$st.$nm" INFO "-" - "$(cut -c1-700 "$OUT/d3/$st-$nm.sum")" ""
}

d3_run() {   # d3_run STAGE NAME CLIENT PROFILE CCPATH PROG ARGS...: one command on client2 under the private conf (stdin: the caller's), then its INFO row; the lab KDC log delta is part of the transcript
    local st=$1 nm=$2 c=$3 pf=$4 cc=$5 prog=$6 conf
    shift 6
    conf="$VMD/b2c/d3-$pf.conf"
    deadline
    cell "d3/$st-$nm" "$D3M_CLIENT" "bash $VMD/b2c-vm.sh run --in-stdin --env KRB5_CONFIG=$conf --env KRB5CCNAME=FILE:$cc -- $(b2c_q "$prog" "$@")" kdc
    d3_sum "$st" "$nm"
}

d3_user_pw() { cat "$D3M_FIX/d3-user.pw"; }

d3_kadmin() {   # d3_kadmin STAGE: cell 1, the lab realm's kadmin.local and client2's ktutil
    local st=$1 L=D3.$1 p
    d3_kdc "$st" kadmin kadmin
    for p in randkey:d3probe pw:d3probepw rc4:d3rc4 default:d3aes; do
        expect "$L.control.kadmin-created-${p%%:*}" "$OUT/d3/$st-add-${p%%:*}.txt" "^Principal \"${p##*:}@$RRX\" created\\.\$"
    done
    result "$L.kadmin.des3-randkey" INFO "-" - "addprinc -randkey -e des3-cbc-sha1:normal -> $(d3_keys "$OUT/d3/$st-get-randkey.txt")" ""
    result "$L.kadmin.des3-pw" INFO "-" - "addprinc -pw ... -e des3-cbc-sha1:normal -> $(d3_keys "$OUT/d3/$st-get-pw.txt")" ""
    result "$L.kadmin.arcfour-control" INFO "-" - "addprinc -randkey -e arcfour-hmac:normal -> $(d3_keys "$OUT/d3/$st-get-rc4.txt")" ""
    result "$L.kadmin.default-control" INFO "-" - "addprinc -randkey -> $(d3_keys "$OUT/d3/$st-get-default.txt")" ""
    expect "$L.control.kadmin-arcfour-has-an-arcfour-key" "$OUT/d3/$st-get-rc4.txt" '^Key: vno [0-9]+, (DEPRECATED:)?arcfour-hmac$'
    expect "$L.control.kadmin-default-has-aes-keys" "$OUT/d3/$st-get-default.txt" '^Key: vno [0-9]+, aes256-cts-hmac-sha1-96$'
    # client2's ktutil (MIT's in both stages): des3 refused or taken, an AES control
    printf 'addent -password -p d3kt@%s -k 1 -e des3-cbc-sha1\nwkt %s/d3/kt-des3.kt\nquit\n' "$D3M_REALM" "$VMD" | b2c_run "d3/$st-ktutil-des3" "$D3M_CLIENT" --in-stdin -- /usr/bin/ktutil
    b2c_run "d3/$st-klist-des3" "$D3M_CLIENT" -- /usr/bin/klist -ke "$VMD/d3/kt-des3.kt" < /dev/null
    { printf 'addent -password -p d3kt@%s -k 1 -e aes256-cts-hmac-sha1-96\n' "$D3M_REALM"; d3_user_pw; printf 'wkt %s/d3/kt-aes.kt\nquit\n' "$VMD"; } | b2c_run "d3/$st-ktutil-aes" "$D3M_CLIENT" --in-stdin -- /usr/bin/ktutil
    b2c_run "d3/$st-klist-aes" "$D3M_CLIENT" -- /usr/bin/klist -ke "$VMD/d3/kt-aes.kt" < /dev/null
    result "$L.ktutil.des3" INFO "-" - "ktutil addent -e des3-cbc-sha1 -> $(grep -E '^addent:' "$OUT/d3/$st-ktutil-des3.txt" | head -n 1 | tr '\n' '|'); keytab afterwards: $(grep -E 'not found|^\[rc=' "$OUT/d3/$st-klist-des3.txt" | head -n 2 | tr '\n' ' ' | cut -c1-140)" ""
    expect "$L.control.ktutil-aes-wrote-the-entry" "$OUT/d3/$st-klist-aes.txt" "^[[:space:]]*1 d3kt@$D3M_REALM \\(aes256-cts-hmac-sha1-96\\)"
    vm "$D3M_CLIENT" "rm -f $VMD/d3/kt-des3.kt $VMD/d3/kt-aes.kt" > /dev/null 2>&1 < /dev/null
}

d3_db() {   # d3_db STAGE: cell 2, the des3-keyed DB in a private realm
    local st=$1 L=D3.$1 c pf u s cc
    d3_kdc "$st" init init "$D3M_ADDR"
    expect "$L.control.private-realm-initialised" "$OUT/d3/$st-run-init.txt" '^INIT_OK '
    d3_kdc "$st" load load
    result "$L.db.load" INFO "-" - "kdb5_util load of the upstream dump: $(grep -E '^LOAD_RC:' "$OUT/d3/$st-run-load.txt" | head -n 1); its output: [$(sed -n '/^CELL load$/,/^CELL_END load$/p' "$OUT/d3/$st-run-load.txt" | grep -v -e '^CELL' -e '^LOAD_RC' | tr '\n' '|')]" ""
    result "$L.db.dump-after-load" INFO "-" - "$(grep -E '^PRINCS_ORIGINAL' "$OUT/d3/$st-dump-after-load.txt" | head -n 1); original $(grep -E '^KEYS_PER_PRINCIPAL_ORIGINAL' "$OUT/d3/$st-dump-after-load.txt" | cut -c35-); after $(grep -E '^KEYS_PER_PRINCIPAL_AFTER' "$OUT/d3/$st-dump-after-load.txt" | cut -c35-)" ""
    expect "$L.control.dump-loaded" "$OUT/d3/$st-run-load.txt" '^LOAD_RC:0$'
    for u in krbtgt_D3.TEST desonly desonlyp mixedp aesp rc4onlyp host_svcdes.d3.test host_svcmix.d3.test host_svcaes.d3.test; do
        result "$L.db.getprinc-$u" INFO "-" - "$(d3_keys "$OUT/d3/$st-getprinc-$u.txt")" ""
    done
    if ! grep -q '^LOAD_RC:0$' "$OUT/d3/$st-run-load.txt" 2> /dev/null; then
        b2c_not_run "$L.db.cells" "the dump did not load (see $L.control.dump-loaded): the private KDC and its cells did not run"
        return 0
    fi
    d3_kdc "$st" start start
    expect "$L.control.private-kdc-listening" "$OUT/d3/$st-run-start.txt" '^KDC_LISTENING '
    if ! grep -q '^KDC_LISTENING ' "$OUT/d3/$st-run-start.txt" 2> /dev/null; then
        b2c_not_run "$L.db.cells" "the private KDC is not listening (see $L.control.private-kdc-listening): its cells did not run"
        return 0
    fi
    for pf in $D3M_PROFILES; do d3_conf "$pf" || { b2c_not_run "$L.db.conf-$pf" "no $pf conf on client2"; return 0; }; done
    for pf in $D3M_PROFILES; do
        for c in mit ours; do
            cc="$VMD/b2c/d3-$st-$pf-$c"
            for u in $D3M_USERS; do
                d3_user_pw | d3_run "$st" "as-$u-$c-$pf" "$c" "$pf" "$cc-$u.cc" "$(b2c_tool "$c" kinit)" "$u"
            done
            expect "$L.control.aesp-login-$c-$pf" "$OUT/d3/$st-as-aesp-$c-$pf.txt" '^\[rc=0\]$'
            expect_part "$L.control.aesp-kdc-issue-$c-$pf" "$OUT/d3/$st-as-aesp-$c-$pf.txt" kdc ': ISSUE: ' 1
            for s in $D3M_SVCS; do
                d3_run "$st" "tgs-$s-$c-$pf" "$c" "$pf" "$cc-aesp.cc" "$(b2c_tool "$c" kvno)" "host/$s.d3.test" < /dev/null
            done
            for s in $D3M_SVCS; do
                d3_run "$st" "kt-$s-$c-$pf" "$c" "$pf" "$cc-kt-$s.cc" "$(b2c_tool "$c" kinit)" -k -t "$VMD/d3/$s.keytab" "host/$s.d3.test" < /dev/null
            done
        done
    done
    # a password change on the des3-only principal, the private KDC restarted, then a login with the new password
    d3_kdc "$st" heal heal
    d3_kdc "$st" stop stop-before-heal-login
    d3_kdc "$st" start start-again
    result "$L.db.heal" INFO "-" - "cpw -pw on desonly: $(d3_keys "$OUT/d3/$st-heal-getprinc.txt")" ""
    for c in mit ours; do
        b2_pw 2 | d3_run "$st" "heal-login-$c-lab" "$c" lab "$VMD/b2c/d3-$st-heal-$c.cc" "$(b2c_tool "$c" kinit)" desonly
    done
    expect "$L.control.heal-changed-the-password" "$OUT/d3/$st-heal-cpw.txt" '^Password for "desonly@D3\.TEST" changed\.$'
    expect "$L.control.healed-login-mit" "$OUT/d3/$st-heal-login-mit-lab.txt" '^\[rc=0\]$'
    expect "$L.control.healed-login-ours" "$OUT/d3/$st-heal-login-ours-lab.txt" '^\[rc=0\]$'
    d3_kdc "$st" stop stop
}

d3_stage() {   # d3_stage mit|ours
    local st=$1 L=D3.$1 f s
    d3_init
    b2c_kdc_ready d3 "$st" || return 0
    b2c_work_ok d3 "$st" "$D3M_CLIENT" || { b2c_not_run "$L.cells" "client2's work directory cannot be used by the lab user (see $L.workdir.$D3M_CLIENT): no cell ran"; return 0; }
    vm "$D3M_CLIENT" "install -d -m 0700 $VMD/d3" > /dev/null 2>&1 < /dev/null
    d3_kadmin "$st"
    # the private realm: its files pushed for this stage (the cleanup shreds them)
    push kdc "$D3M_FIX/d3-realm.dump" "$VMD/d3/d3-realm.dump" 600 || { b2c_not_run "$L.db" "the dump could not be pushed"; return 0; }
    push kdc "$D3M_FIX/d3-realm.stash" "$VMD/d3/d3-realm.stash" 600 || { b2c_not_run "$L.db" "the stash could not be pushed"; return 0; }
    for s in $D3M_SVCS; do push "$D3M_CLIENT" "$D3M_FIX/d3-$s.keytab" "$VMD/d3/$s.keytab" 600 || { b2c_not_run "$L.db" "the $s keytab could not be pushed"; return 0; }; done
    d3_db "$st"
    # undo: the private KDC, the files, the lab-realm probes
    d3_kdc "$st" cleanup cleanup
    for f in d3probe d3probepw d3rc4 d3aes; do expect "$L.cleanup.$f-deleted" "$OUT/d3/$st-del-$f.txt" "^Principal \"$f@$RRX\" deleted\\.\$"; done
    expect "$L.cleanup.private-dir-gone" "$OUT/d3/$st-run-cleanup.txt" '^PRIVATE_DIR_GONE: yes$'
    expect "$L.cleanup.port-free" "$OUT/d3/$st-run-cleanup.txt" '^LISTENERS_ON_PORT_AFTER: 0$'
    vm "$D3M_CLIENT" "rm -f $VMD/b2c/d3-lab.conf $VMD/b2c/d3-plain.conf; rm -rf $VMD/d3" > /dev/null 2>&1 < /dev/null
    return 0
}

# ================================================================ cell 3: mitd3, upstream MIT 1.22.2 with des3 (the grown d3 module)
# mitd3 is the lab's sixth VM: upstream MIT krb5 built from the release tarball under /opt/mit-1.22.2, nothing of Fedora's krb5-server, a permanent realm D3.TEST (empty) at the VM's snapshot `mit-d3` (the provisioning record is kept with the leg).
# Per stage the VM is reverted to that snapshot: the MIT stage makes the realm's principals with MIT's own kadmin.local (set A: krbtgt with a des3 key, desonly, desonlyp, mixedp, aesp, the
# services svcdes, svcmix, svcaes with keytabs; dump), then set B (nd-*, the same kinds) and serves them with MIT's krb5kdc; the ours stage loads MIT's dump of set A with the ship's krb5-kdb (docs/install.md's upgrade), makes set B
# with OUR kadmin.local and serves the DB with OUR krb5-kdc. The same client cells run in both stages with MIT's clients (/opt/mit-1.22.2/bin) and ours (the ship's krb5-kinit, krb5-kvno, krb5-klist):
#   AS      kinit of each user under the profiles def des3 aesdes3 encts (the KDC at its default permissions: phase D) and wdef wdes3 waesdes3 wencts (allow_weak_crypto, allow_des3, allow_rc4 in the KDC's and the client's krb5.conf:
#           phase W), then klist -e;  TGS  an AES TGT, then kvno of each service: default, -e aes256-cts-hmac-sha1-96, -e des3-cbc-sha1, -e arcfour-hmac, -e camellia256-cts-cmac, then klist -e;
#   KT      kinit -k -t of each service keytab (D: def; W: wdef, wdes3), klist -e;  KVK  kvno -k KEYTAB (MIT decrypts the service ticket with the keytab);
#   SESS    (W) a TGT whose session key is des3 (desonly under wdes3, wd3: only a des3 key can be answered with a des3 session key), then kvno of each service: a des3 session key our KDC issues, used by the client;  GSS  (W) MIT's sample initiator against MIT's sample acceptor on the service ticket the
#           KDC issued (wdef: aesp's TGT, an AES session key; wd3: desonly's TGT and des3 session keys), the acceptor with the service keytab;  KEYPARITY  the octets of even parity in each des3 key of the keytabs (MIT's klist -k -K -e; 0 for a valid key; no key is printed).
#   OURSRE  (ours stage, set B) our `krb5-kdb dump` of the realm loaded by UPSTREAM's `kdb5_util load` into a scratch DB and served by upstream's krb5kdc: the set-B cells again, stage tag oursre (the migration back).
#   B25     (both stages) a realm made by an OLD build (HF's tip, before B22: the fixture dir's d3-old.dump + d3-old.stash): its random des3 keys have even-parity octets, MIT refuses them ("DES key has bad
#           parity": KDC_RETURN_ENC_PADATA in the AS, HANDLE_AUTHDATA in the TGS), and the build after B22's re-cut must refuse them as MIT does. Loaded by the stage's own loader, served by the stage's KDC on its own port.
# Rows: D3M.<stage>.control.* PASS/FAIL (the stage did what the container runner measured on upstream MIT), D3M.parity.<run> PASS/FAIL (the run's normalised summary in the MIT stage equals the ours stage's,
# same client, same names), D3M.parity-re.<run> (MIT stage against oursre, set B), D3M.<stage>.<what> INFO for the facts. A run's summary is its exit statuses, its stdout and stderr lines and the KDC log lines it added,
# masked as D3M.parity.masks says; the transcripts (raw) are $OUT/d3/m3-<stage>-<run>.txt. The unfixed build (HF's tip) must be RED in the des3 rows and green in the AES controls.
# The module needs the lab.sh of this tree to know mitd3 and the VM to have the snapshot mit-d3: else one NOT-RUN row (D3M.cells) and cell 3 does not run (d3-lite does).

d3m_init() {   # the cell-3 constants (assigned here: the shell's hygiene check refuses top-level assignments); idempotent
    local k
    [ -n "${D3MM_INIT_DONE:-}" ] && return 0
    D3MM_INIT_DONE=1
    d3_init
    D3MM_VM=mitd3
    D3MM_REST=mit-d3                                  # the snapshot that carries the permanent realm D3.TEST, empty
    D3MM_D=$VMD/d3m                                   # the leg's directory on mitd3
    D3MM_H=$D3MM_D/d3-mitd3.sh
    D3MM_ADDR=${D3_MITD3_ADDR:-${FIELD_LAB_NET:?FIELD_LAB_NET is not set in field.env}.31}
    D3MM_KPORT=${D3_MITD3_KPORT:-88}
    D3MM_OLDPORT=${D3_MITD3_OLDPORT:-8091}
    D3MM_GSSPORT=${D3_MITD3_GSSPORT:-4455}
    D3MM_BASEPORT=${D3_MITD3_BASEPORT:-8092}
    D3MM_BASESHIP=${D3_BASESHIP:-}   # the UNFIXED build's programs: its KDC issues the session key of bad parity of the wire cell (P6)
    D3MM_PROGS='krb5-kdc krb5-kdb krb5-kadmin-local krb5-kinit krb5-kvno krb5-klist'
    D3MM_HOSTD=$TMPDIR/d3m                            # on the host: the dump and the keytabs pulled from mitd3 for the ours stage (0700, shredded in d3_clean)
    D3MM_ENV="VMCTL_D=$VMD D3_ADDR=$D3MM_ADDR D3_KPORT=$D3MM_KPORT D3_OLDPORT=$D3MM_OLDPORT D3_GSSPORT=$D3MM_GSSPORT D3_BASEPORT=$D3MM_BASEPORT"
    for k in D3_MITROOT D3_LDPATH D3_DBMOD_DIR D3_LABUSER; do
        [ -n "${!k:-}" ] && D3MM_ENV="$D3MM_ENV $k=${!k}"
    done
    D3MM_USERS_A='desonly desonlyp mixedp aesp'
    D3MM_USERS_B='nd-desonly nd-desonlyp nd-mixedp'
    D3MM_SVCS_A='svcdes svcmix svcaes'
    D3MM_SVCS_B='nd-svcdes nd-svcmix'
    return 0
}

d3m_probe() {   # (d3_push) mitd3 is in lab.sh's table, shut off, with the snapshot mit-d3: $OUT/d3/m3-ready; else one NOT-RUN row
    local line snaps
    d3m_init
    mkdir -p "$OUT/d3"
    line=$(timeout 120 "$LAB" status 2>> "$LOG" < /dev/null | awk -v name="$D3MM_VM" '$1 == name')
    snaps=${line##* }
    if [ -z "$line" ]; then b2c_not_run D3M.cells "$D3MM_VM is not in the lab.sh of this tree (lab.sh status lists no such VM): cell 3 did not run"; return 0; fi
    case $line in *" absent "*) b2c_not_run D3M.cells "$D3MM_VM does not exist (lab.sh up $D3MM_VM): cell 3 did not run"; return 0 ;; esac
    case $line in *"shut off"*) ;; *) b2c_not_run D3M.cells "$D3MM_VM is not shut off before the leg ($line): cell 3 did not run"; return 0 ;; esac
    case ",$snaps," in *",$D3MM_REST,"*) ;; *) b2c_not_run D3M.cells "$D3MM_VM has no snapshot '$D3MM_REST' (it has: $snaps): cell 3 did not run"; return 0 ;; esac
    : > "$OUT/d3/m3-ready"
    result D3M.cells.ready INFO "-" - "$D3MM_VM is there with the snapshot $D3MM_REST: $(printf '%s' "$line" | tr -s ' ')" ""
    return 0
}

d3m_sec() {   # d3m_sec STAGE NAME ROOT|USER SECTION [ARGS...]: a section of the helper on mitd3 (ROOT: under sudo), stdin the caller's; transcript $OUT/d3/m3-STAGE-NAME.txt
    local st=$1 nm=$2 who=$3 sec=$4 pre=""
    shift 4
    [ "$who" = ROOT ] && pre="sudo"
    deadline
    cell "d3/m3-$st-$nm" "$D3MM_VM" "$pre env $D3MM_ENV bash $D3MM_H ${st%re} $sec $(b2c_q "$@")" none
}

d3m_norm() {   # d3m_norm: a tagged transcript (R1 0 / O1 line / E1 line / K line) on stdin, the masks applied, on stdout. The masks are listed in d3m_masks.
    sed -E \
        -e 's/[[:space:]]+$//' \
        -e 's/\t/ /g' \
        -e '/^[OE][0-9]+ *$/d' \
        -e '/^[OE][0-9]+ ([0-9a-f]{16,})$/d' \
        -e '/^[OE][0-9]+ Valid starting/d' \
        -e 's/^(O[0-9]+) Ticket cache: .*/\1 Ticket cache: CC/' \
        -e 's/\(filename: [^)]*\)/(filename: CC)/g' \
        -e 's/^(O[0-9]+) [0-9]{2}\/[0-9]{2}\/[0-9]{4} [0-9:]{8} +[0-9]{2}\/[0-9]{2}\/[0-9]{4} [0-9:]{8} +/\1 /' \
        -e 's/^(O[0-9]+) +renew until [0-9\/]+ [0-9:]+, /\1 /' \
        -e 's/(token \(size=)[0-9]+/\1N/' \
        -e 's/lifetime [0-9]+/lifetime N/' \
        -e 's/^([OE][0-9]+) krb5-(kinit|kvno|klist)[A-Za-z0-9-]*:/\1 \2:/' \
        -e '/^K /{/(AS|TGS)_REQ|verify failure/!d;/TGS_REQ : handle_authdata/d}' \
        -e 's/^K [A-Z][a-z]{2} [ 0-9]{2} [0-9:]{8} [^ ]+ /K /' \
        -e 's/^K krb5(-)?kdc\[[0-9]+\]\((info|Error)\): /K /' \
        -e 's/^K (.*)authtime [0-9]+,? */K \1/' \
        -e 's/^K (.*\}\)) [0-9a-fA-F.:]+: /K \1 /' \
        -e 's/  +/ /g'
}
d3m_masks() { printf '%s' "trailing blanks, empty lines, hex-only lines (the acceptor's PAC dump), klist's header and times (the Etype fields and the principals are kept), the cache name, token sizes and lifetimes, the KDC log's date, host, process and authtime, the client address, the handle_authdata debug line, the program name of an error line (krb5-kinit: for kinit:, so that the clients can be compared), the cache file name in an error"; }

d3m_sum() {   # d3m_sum STAGE NAME: the normalised one-line summary of a run's transcript -> $OUT/d3/m3-STAGE-NAME.sum
    local st=$1 nm=$2 f="$OUT/d3/m3-$1-$2.txt"
    awk '
        /^# end of cell output/ { exit }
        /^# / && sect == "" { next }
        /^== cmd [0-9]+: / { n++; sect = "cmd"; next }
        /^\[rc=[0-9]+\]$/ { printf "R%d %s\n", n, substr($0, 5, length($0) - 5); next }
        /^\[skipped\]$/ { printf "R%d -\n", n; next }
        /^== stdout$/ { sect = "out"; next }
        /^== stderr$/ { sect = "err"; next }
        /^== kdc log$/ { sect = "kdc"; next }
        sect == "out" { printf "O%d %s\n", n, $0; next }
        sect == "err" { printf "E%d %s\n", n, $0; next }
        sect == "kdc" { printf "K %s\n", $0; next }
    ' "$f" 2> /dev/null | d3m_norm | awk '
        /^R[0-9]+ / { r = r (r == "" ? "" : ",") $2; next }
        /^O[0-9]+ / { o = o (o == "" ? "" : " | ") substr($0, 2); next }
        /^E[0-9]+ / { e = e (e == "" ? "" : " | ") substr($0, 2); next }
        /^K / { k = k (k == "" ? "" : " | ") substr($0, 3); next }
        END { printf "rc=%s; out=[%s]; err=[%s]; kdc=[%s]\n", r, o, e, k }
    ' > "$OUT/d3/m3-$st-$nm.sum"
}

d3m_run() {   # d3m_run STAGE NAME PROFILE [CCFROM=PATH] [TRACE] KT -- CMD...: one chain on mitd3. CCFROM copies that ccache onto this cell's ccache first. TRACE sets KRB5_TRACE to a pathname (MIT opens the value as a file). The helper counts "No credentials found with supported encryption types" in that file and then deletes it.
    local st=$1 nm=$2 pf=$3 ke="" ccfrom="" trace="" kt
    shift 3
    if [ "${1:-}" != "${1#CCFROM=}" ]; then ccfrom=$1; shift; fi
    if [ "${1:-}" = TRACE ]; then trace="KRB5_TRACE=$D3MM_D/trace-$st-$nm"; shift; fi
    kt=${1:-}; shift
    [ "${1:-}" = -- ] && shift
    [ "$kt" != - ] && ke="KRB5_KTNAME=FILE:$D3MM_D/kt/$kt.keytab"
    deadline
    cell "d3/m3-$st-$nm" "$D3MM_VM" "env $D3MM_ENV bash $D3MM_H ${st%re} run auto KRB5_CONFIG=$D3MM_D/conf/$pf.conf KRB5CCNAME=FILE:$D3MM_D/cc/$st-$nm $ke $ccfrom $trace -- $(b2c_q "$@")" none
    d3m_sum "$st" "$nm"
}

d3m_pull() {   # d3m_pull REMOTE LOCAL: a file from mitd3 to the host (0600), sha256 checked on both sides
    local want got
    vm "$D3MM_VM" "cat $1" > "$2" 2>> "$LOG" < /dev/null || return 1
    chmod 600 "$2"
    want=$(vm "$D3MM_VM" "sha256sum $1" 2>> "$LOG" < /dev/null | cut -d' ' -f1)
    got=$(sha256sum "$2" | cut -d' ' -f1)
    [ -n "$want" ] && [ "$want" = "$got" ] || { note "PULL_SHA_MISMATCH $D3MM_VM:$1 want=$want got=$got"; return 1; }
    note "pulled $D3MM_VM:$1 sha256=${got:0:16}"
}

d3m_prepare() {   # d3m_prepare STAGE: the helper, the ship's programs (both stages: ours' clients are used in both), the directories; the conf profiles
    local st=$1 f
    push "$D3MM_VM" "$SCRIPTS/helpers/d3-mitd3.sh" "$D3MM_H" 755 || return 1
    for f in $D3MM_PROGS; do push "$D3MM_VM" "$SHIP/$f" "$D3MM_D/ship/$f" 755 || return 1; done
    vm "$D3MM_VM" "install -d -m 0755 $D3MM_D/cc $D3MM_D/kt $D3MM_D/old" > /dev/null 2>&1 < /dev/null
    vm "$D3MM_VM" "cd $D3MM_D/ship && sha256sum $D3MM_PROGS" > "$OUT/d3/m3-$st-ship-on-vm.sha256" 2>> "$LOG" < /dev/null
    ( cd "$SHIP" && read -ra progs <<< "$D3MM_PROGS" && sha256sum "${progs[@]}" ) > "$OUT/d3/m3-$st-ship-on-host.sha256" 2>> "$LOG"
    if cmp -s "$OUT/d3/m3-$st-ship-on-host.sha256" "$OUT/d3/m3-$st-ship-on-vm.sha256"; then
        verdict "D3M.$st.control.ship-on-mitd3-is-the-ship" PASS "the six programs on mitd3 equal the ship's (sha256)" equal equal "$(cut -c1-12 "$OUT/d3/m3-$st-ship-on-vm.sha256" | paste -sd' ' -)"
    else
        verdict "D3M.$st.control.ship-on-mitd3-is-the-ship" FAIL "the six programs on mitd3 equal the ship's (sha256)" equal differ "see m3-$st-ship-on-host.sha256 and m3-$st-ship-on-vm.sha256"
        return 1
    fi
    d3m_sec "$st" conf ROOT conf < /dev/null
    d3m_sec "$st" facts ROOT facts < /dev/null
    return 0
}

d3m_facts() {   # d3m_facts STAGE: the VM's identity as controls
    local st=$1 L=D3M.$1
    expect "$L.control.brand-release" "$OUT/d3/m3-$st-facts.txt" '^krb5-config --version: Kerberos 5 release 1\.22\.2$'
    expect "$L.control.brand-klist" "$OUT/d3/m3-$st-facts.txt" '^klist -V: Kerberos 5 version 1\.22\.2 $'
    expect "$L.control.build-prefix" "$OUT/d3/m3-$st-facts.txt" '^krb5-config --prefix: /opt/mit-1\.22\.2$'
    expect "$L.control.no-fedora-krb5-server" "$OUT/d3/m3-$st-facts.txt" '^krb5-server installed: package krb5-server is not installed$'
    result "$L.facts.runpath" INFO "-" - "$(grep -E '^RUNPATH of kinit:' "$OUT/d3/m3-$st-facts.txt" | head -n 1)" ""
    result "$L.facts.selinux" INFO "-" - "$(grep -E '^getenforce:' "$OUT/d3/m3-$st-facts.txt" | head -n 1)" ""
    result "$L.facts.programs" INFO "-" - "$(grep -E '^[0-9a-f]{64} ' "$OUT/d3/m3-$st-facts.txt" | sed -E 's#^([0-9a-f]{16})[0-9a-f]* .*/#\1 #' | paste -sd';' -)" ""
}

d3m_getprinc() {   # d3m_getprinc STAGE [SECTION]: the key lists of both sets (INFO) and the des3 keys as controls; SECTION getprinc-re: upstream's kadmin.local on the DB it loaded from our dump
    local st=$1 L=D3M.$1 p f sec=${2:-getprinc}
    d3m_sec "$st" run-getprinc ROOT "$sec" < /dev/null
    b2a_split "$OUT/d3/m3-$st-run-getprinc.txt" "$OUT/d3" "m3-$st"
    for p in krbtgt_D3.TEST desonly desonlyp mixedp aesp host_svcdes.d3.test host_svcmix.d3.test host_svcaes.d3.test nd-desonly nd-desonlyp nd-mixedp host_nd-svcdes.d3.test host_nd-svcmix.d3.test; do
        f="$OUT/d3/m3-$st-getprinc-$p.txt"
        result "$L.getprinc.$p" INFO "-" - "$(d3_keys "$f")" ""
    done
    for p in desonly desonlyp host_svcdes.d3.test nd-desonly nd-desonlyp host_nd-svcdes.d3.test; do
        expect "$L.control.getprinc-$p-has-des3" "$OUT/d3/m3-$st-getprinc-$p.txt" '^Key: vno [0-9]+, DEPRECATED:des3-cbc-sha1$'
    done
    for p in mixedp host_svcmix.d3.test nd-mixedp host_nd-svcmix.d3.test; do
        expect "$L.control.getprinc-$p-has-aes-des3-arcfour" "$OUT/d3/m3-$st-getprinc-$p.txt" '^Key: vno [0-9]+, (aes256-cts-hmac-sha1-96|DEPRECATED:des3-cbc-sha1|DEPRECATED:arcfour-hmac)$' 3
    done
    expect "$L.control.getprinc-krbtgt-has-des3" "$OUT/d3/m3-$st-getprinc-krbtgt_D3.TEST.txt" '^Key: vno [0-9]+, DEPRECATED:des3-cbc-sha1$'
}

d3m_keyparity() {   # d3m_keyparity STAGE NAME KEYTAB...: the even-parity octets of each des3 key, as a control row (0 everywhere) and an INFO row of the counts
    local st=$1 nm=$2 L=D3M.$1 f="$OUT/d3/m3-$1-keyparity-$2.txt"
    shift 2
    d3m_sec "$st" "keyparity-$nm" USER keyparity "$@" < /dev/null
    result "$L.keyparity.$nm" INFO "-" - "$(grep -E '^KEYPARITY ' "$f" | sed -E 's/^KEYPARITY //' | paste -sd';' -)" ""
    verdict "$L.control.keyparity-$nm-all-odd" "$([ "$(grep -c -E '^KEYPARITY .* octets=24 even=0$' "$f")" -ge 1 ] && ! grep -q -E '^KEYPARITY .* even=[1-9]' "$f" && echo PASS || echo FAIL)" \
        "every des3 key of the keytab(s) has odd parity on all 24 octets (MIT's rule)" 0 "$(grep -c -E '^KEYPARITY .* even=[1-9]' "$f")"
}

d3m_kdc() {   # d3m_kdc STAGE start|stop [MODE...]: the stage's KDC on mitd3 (modes: weak, mitre, old)
    local st=$1 act=$2
    shift 2
    d3m_sec "$st" "kdc-$act${1:+-$1}${2:+-$2}" ROOT "kdc-$act" "$@" < /dev/null
    if [ "$act" = start ]; then
        expect "D3M.$st.control.kdc-listening${1:+-$1}${2:+-$2}" "$OUT/d3/m3-$st-kdc-start${1:+-$1}${2:+-$2}.txt" '^KDC_LISTENING '
        grep -q '^KDC_LISTENING ' "$OUT/d3/m3-$st-kdc-start${1:+-$1}${2:+-$2}.txt" 2> /dev/null
    fi
}

d3m_phase() {   # d3m_phase STAGE PH SETS: one phase of the client cells; PH D (the KDC at its default permissions) or W (weak crypto allowed); SETS ab (set A and set B) or b (set B only)
    local st=$1 ph=$2 sets=$3 cl pf us sv op tg
    local asa asb kta ktb tgt
    if [ "$ph" = D ]; then
        asa='def des3 aesdes3 encts'; asb='def aesdes3'; kta='def'; ktb='def'; tgt=def
    else
        asa='wdef wdes3 waesdes3 wencts'; asb='wdef wdes3'; kta='wdef wdes3'; ktb='wdef wdes3'; tgt=wdef
    fi
    for cl in mit ours; do
        # AS: a password login of each user under each profile, then the cache
        for us in $([ "$sets" = ab ] && echo "$D3MM_USERS_A") $D3MM_USERS_B; do
            for pf in $(case $us in nd-*) echo "$asb" ;; *) echo "$asa" ;; esac); do
                b2_pw 1 | d3m_run "$st" "$ph-as-$us-$pf-$cl" "$pf" - -- "$cl:kinit" "$us" -- "$cl:klist" -e
            done
        done
        # TGS: an AES TGT, then each service under each etype request
        for sv in $([ "$sets" = ab ] && echo "$D3MM_SVCS_A") $D3MM_SVCS_B; do
            for op in default aes des3 rc4 cam; do
                case $sv in nd-*) case $op in rc4|cam) continue ;; esac ;; esac
                case $op in default) tg="" ;; aes) tg="-e aes256-cts-hmac-sha1-96" ;; des3) tg="-e des3-cbc-sha1" ;; rc4) tg="-e arcfour-hmac" ;; cam) tg="-e camellia256-cts-cmac" ;; esac
                # shellcheck disable=SC2086  # $tg is empty or the two words -e ENCTYPE
                b2_pw 1 | d3m_run "$st" "$ph-tgs-$sv-$op-$cl" "$tgt" - -- "$cl:kinit" aesp -- "$cl:kvno" $tg "host/$sv.d3.test" -- "$cl:klist" -e
            done
        done
        # KT: the service keytab as the key of a login; KVK: the keytab verifying the service ticket
        for sv in $([ "$sets" = ab ] && echo "$D3MM_SVCS_A") $D3MM_SVCS_B; do
            for pf in $(case $sv in nd-*) echo "$ktb" ;; *) echo "$kta" ;; esac); do
                d3m_run "$st" "$ph-kt-$sv-$pf-$cl" "$pf" - -- "$cl:kinit" -k -t "$D3MM_D/kt/$sv.keytab" "host/$sv.d3.test" -- "$cl:klist" -e < /dev/null
            done
            b2_pw 1 | d3m_run "$st" "$ph-kvk-$sv-$cl" "$tgt" - -- "$cl:kinit" aesp -- "$cl:kvno" -k "$D3MM_D/kt/$sv.keytab" "host/$sv.d3.test"
        done
        # SESS (W): a TGT with a des3 session key, then the service tickets
        if [ "$ph" = W ]; then
            for sv in $([ "$sets" = ab ] && echo "$D3MM_SVCS_A") $D3MM_SVCS_B; do
                for pf in wdes3 wd3; do
                    b2_pw 1 | d3m_run "$st" "W-sess-$sv-$pf-$cl" "$pf" - -- "$cl:kinit" desonly -- "$cl:kvno" "host/$sv.d3.test" -- "$cl:klist" -e
                done
            done
        fi
    done
    [ "$ph" = W ] && [ "$sets" = ab ] && d3m_clientside "$st"
    # GSS (W, MIT's initiator and acceptor on the VM): the service ticket the KDC issues, an AES session key (wdef) and a des3 one (wd3)
    if [ "$ph" = W ]; then
        for sv in $([ "$sets" = ab ] && echo "$D3MM_SVCS_A") $D3MM_SVCS_B; do
            b2_pw 1 | d3m_run "$st" "W-gss-$sv-wdef" wdef "$sv" -- mit:kinit aesp -- "gss:host@$sv.d3.test"
            b2_pw 1 | d3m_run "$st" "W-gss-$sv-wd3" wd3 "$sv" -- mit:kinit desonly -- "gss:host@$sv.d3.test"
        done
    fi
    return 0
}

d3m_old() {   # d3m_old STAGE: B25 and the facet-iii cells P1 to P4 of VM-LEG.md: the realm an OLD build made, in the stage's own loader and KDC, phases D (default permissions) and W (weak crypto allowed)
    local st=$1 L=D3M.$1 f
    for f in d3-old.dump:old/old.dump d3-old.stash:old/stash d3-old-svc.keytab:kt/oldsvc.keytab d3-old-mix.keytab:kt/oldmix.keytab d3-old-aes.keytab:kt/oldaes.keytab d3-old-rnd.keytab:kt/oldrnd.keytab; do
        push "$D3MM_VM" "$D3M_FIX/${f%%:*}" "$D3MM_D/${f##*:}" 600 || { b2c_not_run "$L.old" "${f%%:*} could not be pushed"; return 0; }
    done
    d3m_sec "$st" old-init ROOT old-init < /dev/null
    d3m_sec "$st" run-old-load ROOT old-load < /dev/null
    b2a_split "$OUT/d3/m3-$st-run-old-load.txt" "$OUT/d3" "m3-$st"
    expect "$L.control.old-loaded" "$OUT/d3/m3-$st-old-load.txt" '^LOAD_RC:0$'
    for f in krbtgt_D3.TEST olduser olddes host_oldsvc.d3.test host_oldmix.d3.test host_oldaes.d3.test oldrnd oldrndp; do
        [ -f "$OUT/d3/m3-$st-old-getprinc-$f.txt" ] && result "$L.old.getprinc.$f" INFO "-" - "$(d3_keys "$OUT/d3/m3-$st-old-getprinc-$f.txt")" ""
    done
    d3m_keyparity_old "$st"
    if d3m_kdc "$st" start old; then
        d3m_old_phase "$st" D
        d3m_kdc "$st" stop < /dev/null
    else
        b2c_not_run "$L.old.cells.D" "the old realm's KDC is not listening: no cell of phase D ran"
    fi
    if d3m_kdc "$st" start old weak; then
        d3m_old_phase "$st" W
        d3m_kdc "$st" stop < /dev/null
    else
        b2c_not_run "$L.old.cells.W" "the old realm's weak KDC is not listening: no cell of phase W ran"
    fi
    d3m_old_controls "$st"
    return 0
}

d3m_old_phase() {   # d3m_old_phase STAGE PH: the cells on the old build's realm; P1 a password login of a des3-only user whose stored key is bad, P1b its keytab, P2 the same with preauth, P3a a good des3 key, P3b a ticket for a service whose key is bad,
    # P3c the controls, P4a/P4b a principal with a good AES key and a bad des3 key (P4a: AES chosen, P4b: des3 chosen: the profile that offers only des3)
    local st=$1 ph=$2 cl pf pfs f
    if [ "$ph" = D ]; then pfs='old oldd'; else pfs='wold woldd woldd3'; fi
    for cl in mit ours; do
        for pf in $pfs; do
            if [ "$pf" != woldd3 ]; then
                cat "$D3M_FIX/d3-old-user.pw" | d3m_run "$st" "$ph-old-as-olduser-$pf-$cl" "$pf" - -- "$cl:kinit" olduser -- "$cl:klist" -e
                for f in oldaes oldsvc oldmix; do
                    cat "$D3M_FIX/d3-old-user.pw" | d3m_run "$st" "$ph-old-tgs-$f-$pf-$cl" "$pf" - -- "$cl:kinit" olduser -- "$cl:kvno" "host/$f.d3.test" -- "$cl:klist" -e
                done
                d3m_run "$st" "$ph-old-kt-oldaes-$pf-$cl" "$pf" - -- "$cl:kinit" -k -t "$D3MM_D/kt/oldaes.keytab" host/oldaes.d3.test -- "$cl:klist" -e < /dev/null
            fi
            cat "$D3M_FIX/d3-old-user.pw" | d3m_run "$st" "$ph-old-as-olddes-$pf-$cl" "$pf" - -- "$cl:kinit" olddes -- "$cl:klist" -e
            d3m_run "$st" "$ph-old-kt-oldsvc-$pf-$cl" "$pf" - -- "$cl:kinit" -k -t "$D3MM_D/kt/oldsvc.keytab" host/oldsvc.d3.test -- "$cl:klist" -e < /dev/null
            d3m_run "$st" "$ph-old-kt-oldmix-$pf-$cl" "$pf" - -- "$cl:kinit" -k -t "$D3MM_D/kt/oldmix.keytab" host/oldmix.d3.test -- "$cl:klist" -e < /dev/null
            d3m_run "$st" "$ph-old-kt-oldrnd-$pf-$cl" "$pf" - -- "$cl:kinit" -k -t "$D3MM_D/kt/oldrnd.keytab" oldrnd -- "$cl:klist" -e < /dev/null
            printf 'anypass\n' | d3m_run "$st" "$ph-old-pw-oldrnd-$pf-$cl" "$pf" - -- "$cl:kinit" oldrnd -- "$cl:klist" -e
            printf 'anypass\n' | d3m_run "$st" "$ph-old-pw-oldrndp-$pf-$cl" "$pf" - -- "$cl:kinit" oldrndp -- "$cl:klist" -e
            printf 'anypass\n' | d3m_run "$st" "$ph-old-pw-oldmix-$pf-$cl" "$pf" - -- "$cl:kinit" host/oldmix.d3.test -- "$cl:klist" -e
        done
    done
    return 0
}

d3m_clientside() {   # d3m_clientside STAGE: P5 and P7, the client side (phase W, the stage's KDC with weak crypto allowed): a keytab whose des3 key has ONE octet of even parity (the parity bit of octet 3 flipped on the VM), plain and under FAST armor, and the wire
    # control P6c; the clients are compared with each other (D3M.client.*): MIT's refusal against ours
    local st=$1 L=D3M.$1 cl f ok
    for f in bpk bpkp; do d3m_sec "$st" "flipkt-$f" USER flipkt "$D3MM_D/kt/$f.keytab" "$D3MM_D/kt/$f-bad.keytab" < /dev/null; done
    result "$L.clientside.flipped-keytabs" INFO "-" - "$(grep -h '^FLIPKT' "$OUT/d3/m3-$st-flipkt-bpk.txt" "$OUT/d3/m3-$st-flipkt-bpkp.txt" | sed 's/^FLIPKT //' | paste -sd';' -)" ""
    ok=$(cat "$OUT/d3/m3-$st-flipkt-bpk.txt" "$OUT/d3/m3-$st-flipkt-bpkp.txt" | grep -c -E 'before 0, after 1$')
    verdict "$L.control.flipped-keytabs-have-one-even-octet" "$([ "$ok" = 2 ] && echo PASS || echo FAIL)" "each flipped des3 keytab key has exactly one even-parity octet (the good one has none)" 2 "$ok"
    b2_pw 1 | d3m_run "$st" "W-cs-armor" wdef - -- mit:kinit -c "FILE:$D3MM_D/cc/armor" okpw
    for cl in mit ours; do
        d3m_run "$st" "W-cs-p5a-bpk-bad-$cl" wdes3 - -- "$cl:kinit" -k -t "$D3MM_D/kt/bpk-bad.keytab" bpk < /dev/null
        d3m_run "$st" "W-cs-p5b-bpkp-bad-$cl" wdes3 - -- "$cl:kinit" -k -t "$D3MM_D/kt/bpkp-bad.keytab" bpkp < /dev/null
        d3m_run "$st" "W-cs-p5c-bpk-good-$cl" wdes3 - -- "$cl:kinit" -k -t "$D3MM_D/kt/bpk.keytab" bpk -- "$cl:klist" -e < /dev/null
        d3m_run "$st" "W-cs-p7a-fast-bpk-bad-$cl" wdes3 - -- "$cl:kinit" -T "FILE:$D3MM_D/cc/armor" -k -t "$D3MM_D/kt/bpk-bad.keytab" bpk < /dev/null
        d3m_run "$st" "W-cs-p7b-fast-bpkp-bad-$cl" wdes3 - -- "$cl:kinit" -T "FILE:$D3MM_D/cc/armor" -k -t "$D3MM_D/kt/bpkp-bad.keytab" bpkp < /dev/null
        d3m_run "$st" "W-cs-p7c-fast-bpkp-good-$cl" wdes3 - -- "$cl:kinit" -T "FILE:$D3MM_D/cc/armor" -k -t "$D3MM_D/kt/bpkp.keytab" bpkp -- "$cl:klist" -e < /dev/null
        b2_pw 1 | d3m_run "$st" "W-cs-p6c-wire-good-$cl" wmixed - -- mit:kinit okpw -- "$cl:kvno" host/svcmix.d3.test
    done
    # (1). MIT kinit under aes128-only ticket enctypes, then each kvno under aes256-only TGS enctypes.
    b2_pw 1 | d3m_run "$st" "W-cs-a4-tkt128" tkt128 - -- mit:kinit okpw -- mit:klist -e
    expect "$L.a4.tkt128.rc" "$OUT/d3/m3-$st-W-cs-a4-tkt128.txt" '^\[rc=0\]$'
    expect "$L.a4.tkt128.skey" "$OUT/d3/m3-$st-W-cs-a4-tkt128.txt" 'Etype \(skey, tkt\): aes128-cts-hmac-sha1-96,'
    for cl in mit ours; do
        d3m_run "$st" "W-cs-a4-tgs256-$cl" tgs256 "CCFROM=$D3MM_D/cc/$st-W-cs-a4-tkt128" - -- "$cl:kvno" host/svcaes.d3.test
        expect "$L.a4.tgs256-$cl.rc" "$OUT/d3/m3-$st-W-cs-a4-tgs256-$cl.txt" '^\[rc=1\]$'
        expect "$L.a4.tgs256-$cl.message" "$OUT/d3/m3-$st-W-cs-a4-tgs256-$cl.txt" 'No credentials found with supported encryption types'
        expect_under "$L.a4.tgs256-$cl.no-tgs" "$OUT/d3/m3-$st-W-cs-a4-tgs256-$cl.txt" '^== kdc log$' ' TGS_REQ ' 0
    done
    # A list that parses empty stops before any request. The phrase is graded without the program name.
    for cl in mit ours; do
        b2_pw 1 | d3m_run "$st" "W-cs-a4-tktnosuch-$cl" tktnosuch - -- "$cl:kinit" okpw
        expect "$L.a4.tktnosuch-$cl.rc" "$OUT/d3/m3-$st-W-cs-a4-tktnosuch-$cl.txt" '^\[rc=1\]$'
        expect "$L.a4.tktnosuch-$cl.message" "$OUT/d3/m3-$st-W-cs-a4-tktnosuch-$cl.txt" 'No supported encryption types \(config file error\?\)'
        expect "$L.a4.tktnosuch-$cl.suffix" "$OUT/d3/m3-$st-W-cs-a4-tktnosuch-$cl.txt" 'while getting initial credentials'
        expect "$L.a4.tktnosuch-$cl.no-prompt" "$OUT/d3/m3-$st-W-cs-a4-tktnosuch-$cl.txt" 'Password for ' 0
        expect_under "$L.a4.tktnosuch-$cl.no-as" "$OUT/d3/m3-$st-W-cs-a4-tktnosuch-$cl.txt" '^== kdc log$' ' AS_REQ ' 0
        expect_under "$L.a4.tktnosuch-$cl.no-tgs" "$OUT/d3/m3-$st-W-cs-a4-tktnosuch-$cl.txt" '^== kdc log$' ' TGS_REQ ' 0
        d3m_run "$st" "W-cs-a4-tgsnosuch-$cl" tgsnosuch "CCFROM=$D3MM_D/cc/$st-W-cs-a4-tkt128" - -- "$cl:kvno" host/svcaes.d3.test
        expect "$L.a4.tgsnosuch-$cl.rc" "$OUT/d3/m3-$st-W-cs-a4-tgsnosuch-$cl.txt" '^\[rc=1\]$'
        expect "$L.a4.tgsnosuch-$cl.message" "$OUT/d3/m3-$st-W-cs-a4-tgsnosuch-$cl.txt" 'No supported encryption types \(config file error\?\)'
        expect "$L.a4.tgsnosuch-$cl.suffix" "$OUT/d3/m3-$st-W-cs-a4-tgsnosuch-$cl.txt" 'while getting credentials for host/svcaes\.d3\.test'
        expect_under "$L.a4.tgsnosuch-$cl.no-as" "$OUT/d3/m3-$st-W-cs-a4-tgsnosuch-$cl.txt" '^== kdc log$' ' AS_REQ ' 0
        expect_under "$L.a4.tgsnosuch-$cl.no-tgs" "$OUT/d3/m3-$st-W-cs-a4-tgsnosuch-$cl.txt" '^== kdc log$' ' TGS_REQ ' 0
    done
    # noweak: client profile has no allow_weak_crypto. The stage KDC is still the weak one.
    for cl in mit ours; do
        b2_pw 1 | d3m_run "$st" "W-cs-p6c-wire-good-noweak-$cl" mixed - -- mit:kinit okpw -- "$cl:kvno" host/svcmix.d3.test
        expect "$L.b3.noweak-$cl.rc" "$OUT/d3/m3-$st-W-cs-p6c-wire-good-noweak-$cl.txt" '^\[rc=0\]$'
        expect "$L.b3.noweak-$cl.kvno" "$OUT/d3/m3-$st-W-cs-p6c-wire-good-noweak-$cl.txt" 'kvno = 2$'
    done
    # A des3 service ticket, then the same cache under an AES-only TGS list. The trace file is counted and deleted.
    b2_pw 1 | d3m_run "$st" "W-cs-fam-svc" tgsdes3 - -- mit:kinit okpw -- mit:kvno host/svcmix.d3.test -- mit:klist -e
    expect "$L.b3.fam-svc.rc" "$OUT/d3/m3-$st-W-cs-fam-svc.txt" '^\[rc=0\]$'
    expect "$L.b3.fam-svc.tgt" "$OUT/d3/m3-$st-W-cs-fam-svc.txt" 'Etype \(skey, tkt\): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha384-192'
    expect "$L.b3.fam-svc.skey" "$OUT/d3/m3-$st-W-cs-fam-svc.txt" 'Etype \(skey, tkt\): DEPRECATED:des3-cbc-sha1, aes256-cts-hmac-sha1-96'
    for cl in mit ours; do
        d3m_run "$st" "W-cs-fam-aes-$cl" tgs256 "CCFROM=$D3MM_D/cc/$st-W-cs-fam-svc" TRACE - -- "$cl:kvno" host/svcmix.d3.test
        expect "$L.b3.fam-aes-$cl.rc" "$OUT/d3/m3-$st-W-cs-fam-aes-$cl.txt" '^\[rc=0\]$'
        expect "$L.b3.fam-aes-$cl.not-ktype" "$OUT/d3/m3-$st-W-cs-fam-aes-$cl.txt" '^TRACE_NOT_KTYPE [1-9][0-9]*$'
        expect_under "$L.b3.fam-aes-$cl.tgs" "$OUT/d3/m3-$st-W-cs-fam-aes-$cl.txt" '^== kdc log$' 'TGS_REQ \(1 etypes \{aes256-cts-hmac-sha1-96\(18\)\}\).*rep=aes256-cts-hmac-sha1-96\(18\)'
    done
    # kinit -R on the des3-session TGT, under an AES-only TGS list.
    b2_pw 1 | d3m_run "$st" "W-cs-fam-r-tgt" wmixed - -- mit:kinit okpw -- mit:klist -e
    expect "$L.b3.fam-r-tgt.rc" "$OUT/d3/m3-$st-W-cs-fam-r-tgt.txt" '^\[rc=0\]$'
    expect "$L.b3.fam-r-tgt.skey" "$OUT/d3/m3-$st-W-cs-fam-r-tgt.txt" 'Etype \(skey, tkt\): DEPRECATED:des3-cbc-sha1,'
    for cl in mit ours; do
        d3m_run "$st" "W-cs-fam-r-$cl" tgs256 "CCFROM=$D3MM_D/cc/$st-W-cs-fam-r-tgt" - -- "$cl:kinit" -R
        expect "$L.b3.fam-r-$cl.rc" "$OUT/d3/m3-$st-W-cs-fam-r-$cl.txt" '^\[rc=1\]$'
        expect "$L.b3.fam-r-$cl.message" "$OUT/d3/m3-$st-W-cs-fam-r-$cl.txt" 'No credentials found with supported encryption types'
        expect_under "$L.b3.fam-r-$cl.no-as" "$OUT/d3/m3-$st-W-cs-fam-r-$cl.txt" '^== kdc log$' ' AS_REQ ' 0
        expect_under "$L.b3.fam-r-$cl.no-tgs" "$OUT/d3/m3-$st-W-cs-fam-r-$cl.txt" '^== kdc log$' ' TGS_REQ ' 0
    done
    # Two local TGTs. MIT's kvno -e stores a second krbtgt with a des3 session key. Each client then asks for host/svcaes, and the TGS reply key is the session key of the TGT the client ranked first.
    b2_pw 1 | d3m_run "$st" "W-cs-rank-tgt" wdef - -- mit:kinit okpw -- mit:kvno -e des3-cbc-sha1 krbtgt/D3.TEST -- mit:klist -e
    expect "$L.b3.rank-tgt.rc" "$OUT/d3/m3-$st-W-cs-rank-tgt.txt" '^\[rc=0\]$'
    expect "$L.b3.rank-tgt.des3" "$OUT/d3/m3-$st-W-cs-rank-tgt.txt" 'Etype \(skey, tkt\): DEPRECATED:des3-cbc-sha1, aes256-cts-hmac-sha384-192'
    for cl in mit ours; do
        d3m_run "$st" "W-cs-rank-aesfirst-$cl" rank-aesfirst "CCFROM=$D3MM_D/cc/$st-W-cs-rank-tgt" - -- "$cl:kvno" host/svcaes.d3.test
        expect "$L.b3.rank-aesfirst-$cl.rc" "$OUT/d3/m3-$st-W-cs-rank-aesfirst-$cl.txt" '^\[rc=0\]$'
        expect "$L.b3.rank-aesfirst-$cl.kvno" "$OUT/d3/m3-$st-W-cs-rank-aesfirst-$cl.txt" 'kvno = 2$'
        expect_under "$L.b3.rank-aesfirst-$cl.rep" "$OUT/d3/m3-$st-W-cs-rank-aesfirst-$cl.txt" '^== kdc log$' 'TGS_REQ \(2 etypes \{aes256-cts-hmac-sha1-96\(18\), DEPRECATED:des3-cbc-sha1\(16\)\}\).*rep=aes256-cts-hmac-sha1-96\(18\)'
        d3m_run "$st" "W-cs-rank-desfirst-$cl" rank-desfirst "CCFROM=$D3MM_D/cc/$st-W-cs-rank-tgt" - -- "$cl:kvno" host/svcaes.d3.test
        expect "$L.b3.rank-desfirst-$cl.rc" "$OUT/d3/m3-$st-W-cs-rank-desfirst-$cl.txt" '^\[rc=0\]$'
        expect "$L.b3.rank-desfirst-$cl.kvno" "$OUT/d3/m3-$st-W-cs-rank-desfirst-$cl.txt" 'kvno = 2$'
        expect_under "$L.b3.rank-desfirst-$cl.rep" "$OUT/d3/m3-$st-W-cs-rank-desfirst-$cl.txt" '^== kdc log$' 'TGS_REQ \(2 etypes \{DEPRECATED:des3-cbc-sha1\(16\), aes256-cts-hmac-sha1-96\(18\)\}\).*rep=DEPRECATED:des3-cbc-sha1\(16\)'
    done
    # Short-life TGT. No clock skew. kinit -l 30s, then sleep 35. If the KDC floors the life, these rows fail and that is the block.
    b2_pw 1 | d3m_run "$st" "W-cs-exp-tgt" wdef - -- mit:kinit -l 30s okpw -- mit:klist -e -- sleep 35
    expect "$L.b3.exp-tgt.rc" "$OUT/d3/m3-$st-W-cs-exp-tgt.txt" '^\[rc=0\]$'
    result "$L.b3.exp-tgt.issued" INFO "-" - "$(grep -E 'krbtgt/D3\.TEST@D3\.TEST' "$OUT/d3/m3-$st-W-cs-exp-tgt.txt" | head -n 1)" ""
    for cl in mit ours; do
        d3m_run "$st" "W-cs-exp-kvno-$cl" wdef "CCFROM=$D3MM_D/cc/$st-W-cs-exp-tgt" - -- "$cl:kvno" host/svcaes.d3.test
        expect "$L.b3.exp-kvno-$cl.rc" "$OUT/d3/m3-$st-W-cs-exp-kvno-$cl.txt" '^\[rc=1\]$'
        expect "$L.b3.exp-kvno-$cl.message" "$OUT/d3/m3-$st-W-cs-exp-kvno-$cl.txt" 'Ticket expired'
        expect_under "$L.b3.exp-kvno-$cl.no-tgs" "$OUT/d3/m3-$st-W-cs-exp-kvno-$cl.txt" '^== kdc log$' ' TGS_REQ ' 0
        b2_pw 1 | d3m_run "$st" "W-cs-exp-armor-$cl" wdef - -- "$cl:kinit" -T "FILE:$D3MM_D/cc/$st-W-cs-exp-tgt" okpw
        expect "$L.b3.exp-armor-$cl.rc" "$OUT/d3/m3-$st-W-cs-exp-armor-$cl.txt" '^\[rc=1\]$'
        expect "$L.b3.exp-armor-$cl.message" "$OUT/d3/m3-$st-W-cs-exp-armor-$cl.txt" 'Ticket expired'
        expect_under "$L.b3.exp-armor-$cl.no-as" "$OUT/d3/m3-$st-W-cs-exp-armor-$cl.txt" '^== kdc log$' ' AS_REQ ' 0
    done
    return 0
}

d3m_wire() {   # d3m_wire: P6 (ours stage): the UNFIXED build's KDC issues okpw a TGT whose des3 session key has bad parity, then each client asks for a service ticket: MIT's kvno refuses it before any TGS-REQ, ours must too (D3M.client.*)
    local st=ours L=D3M.wire cl f
    if [ -z "$D3MM_BASESHIP" ] || [ ! -x "$D3MM_BASESHIP/krb5-kdc" ] || [ ! -x "$D3MM_BASESHIP/krb5-kdb" ]; then b2c_not_run "$L.cells" "no unfixed build at $D3MM_BASESHIP (D3_BASESHIP): the wire cell P6 did not run"; return 0; fi
    for f in krb5-kdc krb5-kdb; do push "$D3MM_VM" "$D3MM_BASESHIP/$f" "$D3MM_D/shipbase/$f" 755 || { b2c_not_run "$L.cells" "$f of the unfixed build could not be pushed"; return 0; }; done
    d3m_sec "$st" run-base-load ROOT base-load < /dev/null
    b2a_split "$OUT/d3/m3-$st-run-base-load.txt" "$OUT/d3" "m3-$st"
    expect "$L.control.unfixed-build-loaded-the-dump" "$OUT/d3/m3-$st-base-load.txt" '^LOAD_RC:0$'
    result "$L.facts.unfixed-programs" INFO "-" - "$(grep -E '^BASE_PROGRAMS:' "$OUT/d3/m3-$st-run-base-load.txt" | head -n 1)" ""
    if d3m_kdc "$st" start base weak; then
        for cl in mit ours; do
            b2_pw 1 | d3m_run "$st" "W-cs-p6-wire-bad-$cl" wmixedb - -- mit:kinit okpw -- "$cl:kvno" host/svcmix.d3.test
        done
        d3m_kdc "$st" stop < /dev/null
        expect "$L.control.p6-bad-session-key-refused-by-mits-kvno" "$OUT/d3/m3-$st-W-cs-p6-wire-bad-mit.txt" '^kvno: DES key has bad parity while getting credentials for host/svcmix\.d3\.test@D3\.TEST$'
        expect_under "$L.control.p6-no-tgs-request-was-sent" "$OUT/d3/m3-$st-W-cs-p6-wire-bad-mit.txt" '^== kdc log$' ' TGS_REQ ' 0
    else
        b2c_not_run "$L.cells" "the unfixed build's KDC is not listening: the wire cell P6 did not run"
    fi
    return 0
}

d3m_old_controls() {   # d3m_old_controls STAGE: what upstream MIT does with the old build's keys (the container runner's settle/parity, measured on mitd3's MIT in the MIT stage), asserted in the stage that ran the cells
    local st=$1 L=D3M.$1 p="$OUT/d3/m3-$1" ph pf
    expect "$L.control.old-user-login" "$p-D-old-as-olduser-oldd-mit.txt" '^\[rc=0\]$'
    expect "$L.control.old-des3-password-key-login" "$p-D-old-as-olddes-oldd-mit.txt" '^\[rc=0\]$'
    expect "$L.control.old-aes-service-ticket" "$p-D-old-tgs-oldaes-oldd-mit.txt" '^\[rc=0\]$'
    expect "$L.control.old-mixed-keytab-login" "$p-D-old-kt-oldmix-oldd-mit.txt" '^\[rc=0\]$'
    for ph in D W; do
        pf=oldd; [ $ph = W ] && pf=woldd
        # P1, P1b: the stored key of a des3-only user is bad
        expect "$L.control.$ph-p1-password-login-bad-stored-key" "$p-$ph-old-pw-oldrnd-$pf-mit.txt" '^kinit: Generic error \(see e-text\) while getting initial credentials$'
        expect_under "$L.control.$ph-p1-kdc-refuses" "$p-$ph-old-pw-oldrnd-$pf-mit.txt" '^== kdc log$' ' AS_REQ .*: KDC_RETURN_ENC_PADATA: oldrnd@D3\.TEST for krbtgt/D3\.TEST@D3\.TEST, DES key has bad parity$' 1
        expect "$L.control.$ph-p1b-keytab-login-bad-stored-key" "$p-$ph-old-kt-oldrnd-$pf-mit.txt" '^kinit: Generic error \(see e-text\) while getting initial credentials$'
        expect_under "$L.control.$ph-p1b-kdc-refuses" "$p-$ph-old-kt-oldrnd-$pf-mit.txt" '^== kdc log$' ' AS_REQ .*: KDC_RETURN_ENC_PADATA: oldrnd@D3\.TEST for krbtgt/D3\.TEST@D3\.TEST, DES key has bad parity$' 1
        expect_under "$L.control.$ph-b25-service-keytab-refused-in-the-as" "$p-$ph-old-kt-oldsvc-$pf-mit.txt" '^== kdc log$' ' AS_REQ .*: KDC_RETURN_ENC_PADATA: host/oldsvc\.d3\.test@D3\.TEST for krbtgt/D3\.TEST@D3\.TEST, DES key has bad parity$' 1
        # P2: with preauth the encrypted timestamp cannot be decrypted by the bad key: the walk goes on to the next key and ends as for a wrong password
        expect "$L.control.$ph-p2-preauth-bad-stored-key-is-password-incorrect" "$p-$ph-old-pw-oldrndp-$pf-mit.txt" '^kinit: Password incorrect while getting initial credentials$'
        expect_under "$L.control.$ph-p2-kdc-verify-failure" "$p-$ph-old-pw-oldrndp-$pf-mit.txt" '^== kdc log$' 'preauth \(encrypted_timestamp\) verify failure: Preauthentication failed$' 1
        # P3b: the service key is bad
        expect "$L.control.$ph-p3b-bad-service-key-refused-in-the-tgs" "$p-$ph-old-tgs-oldsvc-$pf-mit.txt" '^kvno: KDC returned error string: HANDLE_AUTHDATA while getting credentials for host/oldsvc\.d3\.test@D3\.TEST$'
        expect_under "$L.control.$ph-p3b-kdc-logs-it" "$p-$ph-old-tgs-oldsvc-$pf-mit.txt" '^== kdc log$' ' TGS_REQ .*: HANDLE_AUTHDATA: .*olduser@D3\.TEST for host/oldsvc\.d3\.test@D3\.TEST, DES key has bad parity$' 2
        # P4a: a principal with a good AES key and a bad des3 key, AES chosen: a wrong password, no refusal
        expect "$L.control.$ph-p4a-mixed-aes-chosen-password-incorrect" "$p-$ph-old-pw-oldmix-$pf-mit.txt" '^kinit: Password incorrect while getting initial credentials$'
    done
    # P4b: the same principal, des3 chosen (W): the KDC refuses its bad des3 key
    expect "$L.control.W-p4b-mixed-des3-chosen-refused" "$p-W-old-pw-oldmix-woldd3-mit.txt" '^kinit: Generic error \(see e-text\) while getting initial credentials$'
    expect_under "$L.control.W-p4b-kdc-refuses" "$p-W-old-pw-oldmix-woldd3-mit.txt" '^== kdc log$' ' AS_REQ .*: KDC_RETURN_ENC_PADATA: host/oldmix\.d3\.test@D3\.TEST for krbtgt/D3\.TEST@D3\.TEST, DES key has bad parity$' 1
}

d3m_keyparity_old() {   # d3m_keyparity_old STAGE: the old build's des3 keys really have even-parity octets (else the B25 cells test nothing)
    local st=$1 L=D3M.$1 f="$OUT/d3/m3-$1-keyparity-old.txt"
    d3m_sec "$st" keyparity-old USER keyparity "$D3MM_D/kt/oldsvc.keytab" "$D3MM_D/kt/oldmix.keytab" "$D3MM_D/kt/oldrnd.keytab" < /dev/null
    result "$L.keyparity.old" INFO "-" - "$(grep -E '^KEYPARITY ' "$f" | sed -E 's/^KEYPARITY //' | paste -sd';' -)" ""
    verdict "$L.control.old-keys-have-even-parity-octets" "$([ "$(grep -c -E '^KEYPARITY .* even=[1-9][0-9]*$' "$f")" = 3 ] && echo PASS || echo FAIL)" \
        "each of the three old-build des3 keys has at least one even-parity octet" 3 "$(grep -c -E '^KEYPARITY .* even=[1-9][0-9]*$' "$f")"
}

d3m_controls() {   # d3m_controls STAGE: what the container runner measured on upstream MIT (settle/after: D = defaults, W = weak crypto allowed), asserted in the stage that ran the cells
    local st=$1 L=D3M.$1 p
    p="$OUT/d3/m3-$st"
    expect "$L.control.as-desonly-def-issues" "$p-D-as-desonly-def-mit.txt" '^\[rc=0\]$'
    expect_under "$L.control.as-desonly-def-reply-key-des3" "$p-D-as-desonly-def-mit.txt" '^== kdc log$' ' ISSUE: .*etypes \{rep=DEPRECATED:des3-cbc-sha1\(16\), tkt=aes256-cts-hmac-sha384-192\(20\), ses=aes256-cts-hmac-sha1-96\(18\)\}, desonly@D3\.TEST for krbtgt/D3\.TEST@D3\.TEST$' 1
    expect "$L.control.as-desonly-des3-refused" "$p-D-as-desonly-des3-mit.txt" '^kinit: KDC has no support for encryption type while getting initial credentials$'
    expect "$L.control.as-desonlyp-def-issues" "$p-D-as-desonlyp-def-mit.txt" '^\[rc=0\]$'
    expect_under "$L.control.as-desonlyp-def-preauth-then-des3-reply" "$p-D-as-desonlyp-def-mit.txt" '^== kdc log$' ' ISSUE: .*rep=DEPRECATED:des3-cbc-sha1\(16\)' 1
    expect "$L.control.as-mixedp-def-issues" "$p-D-as-mixedp-def-mit.txt" '^\[rc=0\]$'
    expect "$L.control.as-aesp-def-issues" "$p-D-as-aesp-def-mit.txt" '^\[rc=0\]$'
    expect "$L.control.tgs-svcdes-default-des3-ticket" "$p-D-tgs-svcdes-default-mit.txt" 'Etype \(skey, tkt\): aes256-cts-hmac-sha1-96, DEPRECATED:des3-cbc-sha1 $'
    expect "$L.control.tgs-svcdes-des3-refused-by-default" "$p-D-tgs-svcdes-des3-mit.txt" '^kvno: KDC has no support for encryption type while getting credentials for host/svcdes\.d3\.test@D3\.TEST$'
    expect "$L.control.tgs-svcmix-default-aes-ticket" "$p-D-tgs-svcmix-default-mit.txt" 'Etype \(skey, tkt\): aes256-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96 $'
    expect "$L.control.tgs-svcaes-default-issues" "$p-D-tgs-svcaes-default-mit.txt" '^\[rc=0\]$'
    expect "$L.control.kt-svcdes-login" "$p-D-kt-svcdes-def-mit.txt" '^\[rc=0\]$'
    expect_under "$L.control.kt-svcdes-reply-key-des3" "$p-D-kt-svcdes-def-mit.txt" '^== kdc log$' ' ISSUE: .*rep=DEPRECATED:des3-cbc-sha1\(16\)' 1
    expect "$L.control.kt-svcmix-login" "$p-D-kt-svcmix-def-mit.txt" '^\[rc=0\]$'
    expect "$L.control.kvk-svcdes-keytab-entry-valid" "$p-D-kvk-svcdes-mit.txt" '^host/svcdes\.d3\.test@D3\.TEST: kvno = [0-9]+, keytab entry valid$'
    expect "$L.control.w-as-desonly-des3-session" "$p-W-as-desonly-wdes3-mit.txt" 'Etype \(skey, tkt\): DEPRECATED:des3-cbc-sha1, aes256-cts-hmac-sha384-192 $'
    expect "$L.control.w-tgs-svcdes-des3-des3" "$p-W-tgs-svcdes-des3-mit.txt" 'Etype \(skey, tkt\): DEPRECATED:des3-cbc-sha1, DEPRECATED:des3-cbc-sha1 $'
    expect "$L.control.w-sess-svcmix-des3-session-aes-ticket" "$p-W-sess-svcmix-wd3-mit.txt" 'Etype \(skey, tkt\): DEPRECATED:des3-cbc-sha1, aes256-cts-hmac-sha1-96 $'
    expect "$L.control.w-gss-svcdes-des3-session" "$p-W-gss-svcdes-wd3.txt" '^Signature verified\.$'
    expect "$L.control.w-gss-svcmix-aes-session" "$p-W-gss-svcmix-wdef.txt" '^Signature verified\.$'
    # facet iii, the client side (P5, P7) and the wire control (P6c): MIT's client refuses a des3 key of bad parity in the keytab, the KDC (key good) sees only the first request
    expect "$L.control.p5a-bad-keytab-key-refused-by-the-client" "$p-W-cs-p5a-bpk-bad-mit.txt" '^kinit: DES key has bad parity while getting initial credentials$'
    expect "$L.control.p5b-bad-keytab-key-refused-with-preauth" "$p-W-cs-p5b-bpkp-bad-mit.txt" '^kinit: Pre-authentication failed: DES key has bad parity while getting initial credentials$'
    expect_under "$L.control.p5b-kdc-saw-only-needed-preauth" "$p-W-cs-p5b-bpkp-bad-mit.txt" '^== kdc log$' ' AS_REQ .*: NEEDED_PREAUTH: bpkp@D3\.TEST for krbtgt/D3\.TEST@D3\.TEST, Additional pre-authentication required$' 1
    expect_under "$L.control.p5b-kdc-issued-nothing" "$p-W-cs-p5b-bpkp-bad-mit.txt" '^== kdc log$' ' ISSUE: ' 0
    expect "$L.control.p5c-good-keytab-key-logs-in" "$p-W-cs-p5c-bpk-good-mit.txt" '^\[rc=0\]$'
    expect "$L.control.p7a-fast-bad-keytab-key-refused" "$p-W-cs-p7a-fast-bpk-bad-mit.txt" '^kinit: DES key has bad parity while getting initial credentials$'
    expect "$L.control.p7b-fast-bad-keytab-key-refused-with-preauth" "$p-W-cs-p7b-fast-bpkp-bad-mit.txt" '^kinit: Pre-authentication failed: DES key has bad parity while getting initial credentials$'
    expect "$L.control.p7c-fast-good-keytab-key-logs-in" "$p-W-cs-p7c-fast-bpkp-good-mit.txt" '^\[rc=0\]$'
    expect "$L.control.p6c-wire-good-session-key-service-ticket" "$p-W-cs-p6c-wire-good-mit.txt" '^host/svcmix\.d3\.test@D3\.TEST: kvno = [0-9]+$'
}

d3m_stage() {   # d3m_stage mit|ours: cell 3 of one stage; the VM goes back to the snapshot first and is shut off afterwards
    local st=$1 L=D3M.$1 f
    d3m_init
    [ -f "$OUT/d3/m3-ready" ] || return 0
    mkdir -p "$OUT/d3" "$D3MM_HOSTD"; chmod 700 "$D3MM_HOSTD"
    : > "$OUT/d3/mitd3-touched"
    if [ "$st" = ours ] && [ ! -s "$D3MM_HOSTD/mit.dump" ]; then b2c_not_run "$L.cells" "the MIT stage left no dump of set A (see D3M.mit.*): the ours stage of cell 3 did not run"; return 0; fi
    lab reset "$D3MM_VM" "$D3MM_REST" || { b2c_not_run "$L.cells" "lab.sh reset $D3MM_VM $D3MM_REST failed: cell 3 did not run in this stage"; return 0; }
    d3m_prepare "$st" || { b2c_not_run "$L.cells" "the helper or the programs could not be pushed to $D3MM_VM"; d3m_down; return 0; }
    d3m_facts "$st"
    if [ "$st" = mit ]; then
        b2a_pw3 | d3m_sec "$st" setup-a ROOT mit-setup-a
        expect "$L.control.set-a-made" "$OUT/d3/m3-$st-setup-a.txt" '^Principal "aesp@D3\.TEST" created\.$'
        d3m_sec "$st" dump ROOT dump < /dev/null
        expect "$L.control.dump-of-set-a" "$OUT/d3/m3-$st-dump.txt" '^DUMP_RC:0$'
        d3m_pull "$D3MM_D/mit.dump" "$D3MM_HOSTD/mit.dump" || { b2c_not_run "$L.cells" "the dump could not be pulled"; d3m_down; return 0; }
        for f in svcdes svcmix svcaes bpk bpkp; do d3m_pull "$D3MM_D/kt/$f.keytab" "$D3MM_HOSTD/$f.keytab" || { b2c_not_run "$L.cells" "the keytab $f could not be pulled"; d3m_down; return 0; }; done
        b2a_pw3 | d3m_sec "$st" setup-b ROOT mit-setup-b
        expect "$L.control.set-b-made" "$OUT/d3/m3-$st-setup-b.txt" '^Principal "nd-mixedp@D3\.TEST" created\.$'
    else
        push "$D3MM_VM" "$D3MM_HOSTD/mit.dump" "$D3MM_D/mit.dump" 600 || { b2c_not_run "$L.cells" "the dump could not be pushed"; d3m_down; return 0; }
        for f in svcdes svcmix svcaes bpk bpkp; do push "$D3MM_VM" "$D3MM_HOSTD/$f.keytab" "$D3MM_D/kt/$f.keytab" 600 || { b2c_not_run "$L.cells" "the keytab $f could not be pushed"; d3m_down; return 0; }; done
        d3m_sec "$st" run-load ROOT ours-load < /dev/null
        b2a_split "$OUT/d3/m3-$st-run-load.txt" "$OUT/d3" "m3-$st"
        expect "$L.control.load-of-mits-dump" "$OUT/d3/m3-$st-load.txt" '^LOAD_RC:0$'
        grep -q '^LOAD_RC:0$' "$OUT/d3/m3-$st-load.txt" 2> /dev/null || { b2c_not_run "$L.cells" "the dump did not load: no cell ran"; d3m_down; return 0; }
        b2a_pw3 | d3m_sec "$st" setup-b ROOT ours-setup
        expect "$L.control.set-b-made" "$OUT/d3/m3-$st-setup-b.txt" '^Entry for principal host/nd-svcmix\.d3\.test with kvno [0-9]+, encryption type des3-cbc-sha1 added to keytab '
    fi
    d3m_getprinc "$st"
    d3m_keyparity "$st" set-a "$D3MM_D/kt/svcdes.keytab" "$D3MM_D/kt/svcmix.keytab" "$D3MM_D/kt/svcaes.keytab"
    d3m_keyparity "$st" set-b "$D3MM_D/kt/nd-svcdes.keytab" "$D3MM_D/kt/nd-svcmix.keytab"
    # phase D: the KDC at its default permissions; phase W: weak crypto allowed
    if d3m_kdc "$st" start; then
        d3m_phase "$st" D ab
        d3m_kdc "$st" stop
    else
        b2c_not_run "$L.cells.D" "the KDC is not listening: no cell of phase D ran"
    fi
    if d3m_kdc "$st" start weak; then
        d3m_phase "$st" W ab
        d3m_kdc "$st" stop
    else
        b2c_not_run "$L.cells.W" "the weak KDC is not listening: no cell of phase W ran"
    fi
    d3m_controls "$st"
    # the migration back (ours stage): our dump, loaded by upstream's kdb5_util into a scratch DB and served by upstream's krb5kdc
    if [ "$st" = ours ]; then d3m_reload; fi
    d3m_old "$st"
    [ "$st" = ours ] && d3m_wire
    d3m_sec "$st" avc ROOT avc < /dev/null
    result "D3M.$st.avc" INFO "-" - "$(grep -E '^(getenforce|AVC_DENIALS_SINCE_BOOT):' "$OUT/d3/m3-$st-avc.txt" | paste -sd';' -); $(grep -E '^ +[0-9]+ ' "$OUT/d3/m3-$st-avc.txt" | head -n 3 | tr -s ' ' | paste -sd'|' -)" "SELinux on mitd3 (not judged: the shell's AVC rows are the kdc VM's)"
    d3m_sec "$st" clean ROOT clean < /dev/null
    d3m_down
    return 0
}

d3m_reload() {   # (ours stage) OURSRE: our dump of the realm into upstream's kdb5_util and krb5kdc, the set-B cells with MIT's clients and ours
    local st=ours L=D3M.oursre
    d3m_sec "$st" ours-dump ROOT ours-dump < /dev/null
    expect "$L.control.ours-dump" "$OUT/d3/m3-$st-ours-dump.txt" '^DUMP_RC:0$'
    d3m_sec "$st" mit-reload ROOT mit-reload < /dev/null
    expect "$L.control.upstream-loaded-our-dump" "$OUT/d3/m3-$st-mit-reload.txt" '^LOAD_RC:0$'
    grep -q '^LOAD_RC:0$' "$OUT/d3/m3-$st-mit-reload.txt" 2> /dev/null || { b2c_not_run "$L.cells" "upstream's kdb5_util did not load our dump: no cell ran"; return 0; }
    d3m_getprinc oursre getprinc-re
    if d3m_kdc oursre start mitre; then
        d3m_phase oursre D b
        d3m_kdc oursre stop
    else
        b2c_not_run "$L.cells.D" "upstream's KDC on our dump is not listening: no cell of phase D ran"
    fi
    if d3m_kdc oursre start mitre weak; then
        d3m_phase oursre W b
        d3m_kdc oursre stop
    else
        b2c_not_run "$L.cells.W" "upstream's weak KDC on our dump is not listening: no cell of phase W ran"
    fi
}

d3m_down() {   # the VM shut off (the next stage reverts it again; d3_clean leaves it at its snapshot)
    lab down "$D3MM_VM" || note "D3M: lab.sh down $D3MM_VM rc=$?"
}

d3m_parity() {   # d3m_parity: the MIT stage against the ours stage (and against oursre for set B), per run name: the normalised summaries equal; the unfixed build is red in the des3 runs
    local f nm a b same=0 diff=0 miss=0 sa sb
    d3m_init
    [ -f "$OUT/d3/m3-ready" ] || return 0
    if ! ls "$OUT"/d3/m3-mit-*.sum > /dev/null 2>&1 || ! ls "$OUT"/d3/m3-ours-*.sum > /dev/null 2>&1; then
        b2c_not_run D3M.parity "a stage of cell 3 left no run summaries (see D3M.cells): no comparison"
        return 0
    fi
    result D3M.parity.masks INFO "-" - "$(d3m_masks)" "the masks of every parity row of cell 3"
    for f in "$OUT"/d3/m3-mit-*.sum; do
        nm=$(basename "$f" .sum); nm=${nm#m3-mit-}
        if [ ! -f "$OUT/d3/m3-ours-$nm.sum" ]; then miss=$((miss + 1)); verdict "D3M.parity.$nm" FAIL "MIT stage = ours stage" equal missing "no run $nm in the ours stage"; continue; fi
        a=$(cat "$f"); b=$(cat "$OUT/d3/m3-ours-$nm.sum")
        if [ "$a" = "$b" ]; then
            same=$((same + 1)); verdict "D3M.parity.$nm" PASS "MIT stage = ours stage" equal equal "same: $(printf '%s' "$a" | cut -c1-600)"
        else
            diff=$((diff + 1)); verdict "D3M.parity.$nm" FAIL "MIT stage = ours stage" equal differ "MIT: $(printf '%s' "$a" | cut -c1-900)  ||  ours: $(printf '%s' "$b" | cut -c1-900)"
        fi
    done
    result D3M.parity.summary INFO "-" - "$same runs equal, $diff differ, $miss missing in the ours stage" "(not counting oursre)"
    same=0; diff=0; miss=0
    for f in "$OUT"/d3/m3-oursre-*.sum; do
        [ -f "$f" ] || continue
        nm=$(basename "$f" .sum); nm=${nm#m3-oursre-}
        sa="$OUT/d3/m3-mit-$nm.sum"
        [ -f "$sa" ] || { miss=$((miss + 1)); continue; }
        a=$(cat "$sa"); b=$(cat "$f")
        if [ "$a" = "$b" ]; then
            same=$((same + 1)); verdict "D3M.parity-re.$nm" PASS "MIT stage = upstream KDC on our dump" equal equal "same: $(printf '%s' "$a" | cut -c1-600)"
        else
            diff=$((diff + 1)); verdict "D3M.parity-re.$nm" FAIL "MIT stage = upstream KDC on our dump" equal differ "MIT stage: $(printf '%s' "$a" | cut -c1-900)  ||  oursre: $(printf '%s' "$b" | cut -c1-900)"
        fi
    done
    result D3M.parity-re.summary INFO "-" - "$same runs equal, $diff differ, $miss without a MIT-stage run" "upstream's kdb5_util and krb5kdc on the dump our krb5-kdb wrote"
    # the clients against each other, within each stage, on the client-side cells (P5, P6, P7 and their controls): MIT's refusal against ours; rc, stdout and stderr (the KDC's lines differ by the clients' etype lists)
    local stg
    for stg in mit ours; do
        for f in "$OUT/d3/m3-$stg-"*-cs-*-mit.sum; do
            [ -f "$f" ] || continue
            nm=$(basename "$f" .sum); nm=${nm#"m3-$stg-"}; nm=${nm%-mit}
            sb="$OUT/d3/m3-$stg-$nm-ours.sum"
            if [ ! -f "$sb" ]; then verdict "D3M.client.$stg.$nm" FAIL "MIT's client = ours" equal missing "no run of ours' client"; continue; fi
            a=$(cat "$f"); b=$(cat "$sb"); a=${a%%; kdc=*}; b=${b%%; kdc=*}   # the exit statuses and the words only: the two clients ask with different etype lists (docs/mit-deviations.md line 20)
            if [ "$a" = "$b" ]; then verdict "D3M.client.$stg.$nm" PASS "MIT's client = ours (rc, stdout, stderr)" equal equal "same: $(printf '%s' "$a" | cut -c1-600)"
            else verdict "D3M.client.$stg.$nm" FAIL "MIT's client = ours (rc, stdout, stderr)" equal differ "MIT's client: $(printf '%s' "$a" | cut -c1-900)  ||  ours: $(printf '%s' "$b" | cut -c1-900)"; fi
        done
    done
    # keys and key lists
    for f in "$OUT"/d3/m3-mit-getprinc-*.txt; do
        [ -f "$f" ] || continue
        nm=$(basename "$f" .txt); nm=${nm#m3-mit-}
        [ -f "$OUT/d3/m3-ours-$nm.txt" ] || continue
        a=$(d3_keys "$f"); b=$(d3_keys "$OUT/d3/m3-ours-$nm.txt")
        if [ "$a" = "$b" ]; then verdict "D3M.parity.$nm" PASS "key list MIT = ours" equal equal "same: $a"; else verdict "D3M.parity.$nm" FAIL "key list MIT = ours" equal differ "MIT: $a  ||  ours: $b"; fi
    done
    # a control that the comparison can tell two runs apart
    if [ -s "$OUT/d3/m3-mit-D-as-aesp-def-mit.sum" ] && [ -s "$OUT/d3/m3-ours-D-as-aesp-def-mit.sum" ]; then
        parity_control D3M.parity.aesp "$OUT/d3/m3-mit-D-as-aesp-def-mit.sum" "$OUT/d3/m3-ours-D-as-aesp-def-mit.sum"
    else
        b2c_not_run D3M.parity.aesp "the control runs are missing"
    fi
    return 0
}

d3m_clean() {   # (d3_clean) the VM back at its snapshot and shut off, the host-side copies shredded; only when cell 3 touched the VM
    d3m_init
    shred -u "$D3MM_HOSTD"/* 2> /dev/null
    rm -rf "$D3MM_HOSTD"
    [ -f "$OUT/d3/mitd3-touched" ] || return 0
    lab reset "$D3MM_VM" "$D3MM_REST" || note "D3M: lab.sh reset $D3MM_VM $D3MM_REST rc=$?"
    lab down "$D3MM_VM" || note "D3M: lab.sh down $D3MM_VM rc=$?"
    rm -f "$OUT/d3/mitd3-touched"
    return 0
}

d3_mit() { d3_init; d3_stage mit; d3m_stage mit; }
d3_ours() { d3_init; d3_stage ours; d3m_stage ours; }

d3_parity() {   # not a verdict: for every run both stages made, "same" or "differs" (INFO), and a control that the comparison can tell two runs apart
    local f nm a b same=0 diff=0
    d3_init
    for f in "$OUT"/d3/mit-*.sum; do
        [ -f "$f" ] || continue
        nm=$(basename "$f" .sum); nm=${nm#mit-}
        [ -f "$OUT/d3/ours-$nm.sum" ] || continue
        a=$(cat "$f"); b=$(cat "$OUT/d3/ours-$nm.sum")
        if [ "$a" = "$b" ]; then
            same=$((same + 1)); result "D3.parity.$nm" INFO "-" - "same: $a" ""
        else
            diff=$((diff + 1)); result "D3.parity.$nm" INFO "-" - "differs: MIT: $a  ||  ours: $b" ""
        fi
    done
    result D3.parity.summary INFO "-" - "$same runs the same in both stages, $diff differ" "not a verdict: Fedora's MIT is not the reference for des3"
    if [ -s "$OUT/d3/mit-as-aesp-mit-lab.sum" ] && [ -s "$OUT/d3/ours-as-aesp-mit-lab.sum" ]; then
        parity_control D3.parity.aesp "$OUT/d3/mit-as-aesp-mit-lab.sum" "$OUT/d3/ours-as-aesp-mit-lab.sum"
    else
        b2c_not_run D3.parity.aesp "the aesp control run is missing in a stage"
    fi
    d3m_parity
    return 0
}

d3_clean() {   # the private KDC, the files and the probes once more, quietly (the reset undoes them in any case)
    d3_init
    vm kdc "sudo env D3_PORT=$D3M_PORT bash $VMD/b2a/d3-kdc.sh mit cleanup" > /dev/null 2>&1 < <(b2a_pw3)
    vm "$D3M_CLIENT" "rm -rf $VMD/d3; rm -f $VMD/b2c/d3-lab.conf $VMD/b2c/d3-plain.conf" > /dev/null 2>&1 < /dev/null
    b2c_clean_vms
    d3m_clean
    return 0
}
