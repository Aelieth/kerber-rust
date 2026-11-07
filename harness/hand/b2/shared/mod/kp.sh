# shellcheck shell=bash disable=SC2154,SC2034  # sourced by driver-b2.sh, which sets and reads these
# mod/kp.sh: B2-style module KP, the VM leg of the KP series (kprop -f as MIT's kprop: its ticket from the KDC, the file kdb5_util dump wrote, the dump size as MIT encodes it, a dump of several KRB-PRIV blocks, the keytab
# AS ending at the key that opens the reply), MIT first (lab-agent; cells: VM-LEG.md, cells 1-4 and the failure table, built to the head implementer's order of 2026-10-13).
# Not a package of the B2 survey: it runs beside the B2 modules in one hold (B2_EXTRA=kp until the shell's order names it).
# The shape (two stages): the kdc is the primary, client2 the replica running kpropd. MIT stage = stock krb5-server on the kdc: MIT's kprop and kdb5_util dump. Ours stage = after docs/install.md's upgrade: our kprop and
# our kdb5_util dump. The replica's kpropd is one of two programs in either stage: MIT's, from the Fedora-signed krb5-server-1.22.2-4.fc43 rpm (installed on client2 for the cells that need it and removed after them, so that
# the shell's rows after the stage find client2's config as it was), or ours, the ship build's krb5-kpropd. So the four cells of VM-LEG.md are:
#   cell 1  MIT stage,  MIT kprop -> MIT kpropd     (rows KP.mit.tm*, KP.mit.lm*)       cell 2  MIT stage,  MIT kprop -> our kpropd    (rows KP.mit.lo*)
#   cell 3  ours stage, our kprop -> MIT kpropd     (rows KP.ours.tm*, KP.ours.lm*)     cell 4  ours stage, our kprop -> our kpropd    (rows KP.ours.lo*)
# Per cell: dump A (the realm's own dump, one block) and dump B (A and 250 more principals, helpers/kp-bulk-dump.py = KP's scripts/lib/bulk-dump.py, byte for byte; several blocks of 32768 bytes; the multi-block case
# is commit 02's proof). tm = MIT kpropd with the loader /bin/true (transport only: the received file against the sent one), lm = MIT kpropd with kdb5_util load (the replica's database against the primary's),
# lo = our kpropd (the replica's database, which our kpropd writes as the dump text, against the sent file). e2m / e2o = the end-to-end cell: the replica's own KDC (MIT's krb5kdc, or ours) serves the database the
# load made, and `kinit -k -t /etc/krb5.keytab host/client2.kerber.test` against it works (the replica's key in the keytab is the primary's key).
# The failure table of VM-LEG.md, MIT's kprop first and ours in the ours stage, the texts compared MIT = ours: no ACL (noacl: kpropd refuses after the AP-REP), the port refused (refused: nothing listens) and the port
# rejected by the network (reject: an nft rule, host-prohibited), a replica name the KDC does not know (nohost), no key for the client in -s (nokey), no keytab file at all (nokeytab), a stale key (stale-nopre, and
# stale-pre with +requires_preauth, the lab realm's default flag), a dump newer than its .dump_ok (toonew), no .dump_ok (nodumpok).
# What the rows assert: kprop's rc and its words (stdout, stderr and the KRB5_TRACE file kept apart), the "N bytes sent." lines (one per KRB-PRIV block of up to 32768 bytes, the last the file's size), the one-NUL .last_prop
# (0600), exactly one ISSUE line for host/kdc -> host/client2 in the KDC's log, the trace's events; MIT's kpropd's own log (the connection, recvauth, the authenticated client, the transfer, the load) or ours (ready since ec0b2d6a, and with -d MIT's load lines; kprop ok is gone since 0178dd7e);
# the replica's content (the received file's short hash against the sent one; the loaded database's principals against the primary's, and alice, host/client2, host/kdc, bulk0250 in it); the end-to-end kinit.
# Parity (L6): MIT's kprop against ours to the same kpropd, per cell, after a NAMED mask (the byte counts of the dump, the trace's times, sequence numbers, hashes and sizes, and the transport's own lines: UDP and TCP
# attempts and the datagram or stream the answer came on, which the row KP.<st>.transport.no-udp-error judges by itself), kpropd's log in the same way, the KDC log's AS result sequence; the failure cells by rc, stdout
# and stderr (the no-ACL cell by rc and the class of the message: kpropd refuses after the AP-REP, and whether kprop's write or its read meets the closed connection is a race that MIT's kprop loses either way). The AS retry of MIT's krb5_get_init_creds_keytab after a failure (commit 04's named limit) is an INFO row, not a judgement.
# Differences from VM-LEG.md:
#   - the module runs inside the B2 shell (L1 resets and the Fedora identity rule, install.md's upgrade, the state rows, the restore), not as a separate driver;
#   - MIT's kpropd for client2 comes from the exact rpm the head implementer named (krb5-server-1.22.2-4.fc43, Fedora-signed; rpmkeys --checksig on the host and on the VM; sha256 pinned), installed with dnf from the
#     local file: the only package dnf adds is `words` (krb5-server requires it; dnf takes it from the Fedora repository, and `dnf remove` takes both away); the rows judge the transaction and the identity of the
#     daemon (the ELF package note of /usr/sbin/kpropd, rpm -V config files only, rpm -q the exact version); KP_RPM names another path, and with no file at all the exact package name-version-release is installed from
#     the repository (the same rows);
#   - kpropd and the loader find the replica's database and stash through KRB5_KDC_PROFILE (a private kdc.conf under $VMD/kp/r), not /var/kerberos/krb5kdc, which the rpm owns and the shell watches; the stash is the
#     primary's, from the kdc to client2 through the host's pipe (never a file on the host); the replica's own KDC listens on 127.0.0.1:8088;
#   - the kdc's keytab for kprop is made by ktadd of host/kdc.kerber.test (the lab realm has none; deleted at the end of the stage, like the decoy principal of the "no key" cell);
#   - the "rejected by the network" cell is an nft rule that rejects with host-prohibited (the connect fails at once; a DROP would wait out the kernel's SYN retries for two minutes) and runs only when nft is there;
#   - no firewalld on the VMs (firewall-cmd is not installed): no --add-port; the AVC rows of client2 are the module's own (the shell judges the kdc's);
#   - kprop runs with the KRB5_TRACE file of its own (a trace sent to /dev/stderr shares the file with the error message and overwrites it).
# Not built: VM-LEG.md's empty dump (it says not to run it); the one-block dump of its cells is dump A.
# shellcheck source=/dev/null
. "$SCRIPTS/helpers/b2a-host.sh"

kp_init() {   # the module's constants, assigned in a function (the shell's hygiene check refuses top-level assignments); idempotent
    [ -n "${KP_INIT_DONE:-}" ] && return 0
    KP_INIT_DONE=1
    declare -gA KP_F=()
    KP_REPLICA=client2.kerber.test
    KP_KDIR=$VMD/kp
    KP_P=$VMD/kp/p
    KP_KEYTAB=$VMD/kp/p/kdc.keytab
    KP_NEVR=krb5-server-1.22.2-4.fc43
    KP_RPM_FILE=${KP_RPM:-}
    KP_RPM_SHA=${KP_RPM_SHA256:-fca11e840218f2b2dad5c279b667a1ee6185424f2e109bfd511abeadc57985c3}
    KP_MODE=local
    KP_CELLS="tmA tmB lmA lmB loA loB"
    KP_FAILS="noacl refused reject nohost nokey nokeytab stale-nopre stale-pre toonew nodumpok"
    # kpropd refuses the connection after the AP-REP; kprop then meets the closed connection in its write of the first block (a loopback, a fast peer: "Broken pipe ...") or, having written the whole dump, in its read
    # of the answer (a network: "Software caused connection abort ..."); MIT's kprop did the first in the fake lab and the second on the VMs, ours the first on the VMs: a race, not a difference
    KP_NOACL_RX='^kprop: (Broken pipe while sending database block starting at 0|Software caused connection abort while reading response from server|Connection reset by peer while (sending database block starting at 0|reading response from server))$'
    # the NAMED mask of the success cells' parity: what differs between two runs of the same program, or between MIT's kprop and ours with equal meaning
    declare -ga KP_MASK=(
        '/^== which$/,/^== stdout$/{/^== stdout$/!d}'
        '/^[0-9]+ bytes sent\.$/d'
        's/^\[[0-9]+\] [0-9]+\.[0-9]+: //'
        's/seqnum [0-9]+/seqnum N/g'
        's/time [0-9]+\.[0-9]+,/time T,/'
        's#(aes(128|256)-[a-z0-9-]+)/[0-9A-F]{4}\b#\1/XXXX#g'
        's/\([0-9]+ bytes\)/(N bytes)/g'
        '/^(Sending initial UDP request|Sending retry UDP request|UDP error sending|Initiating TCP connection|Sending TCP request|Terminating TCP connection) /d'
        's/^Received answer \(N bytes\) from (dgram|stream) .*/Received answer (N bytes) from KDC/'
        's/^Received cookie: .*/Received cookie: C/'
        's/(SPAKE (challenge received with group [0-9]+, pubkey|key generated with pubkey|algorithm result:|final transcript hash:)) [0-9A-F]+/\1 H/'
        's#FILE:[^ ]*/kdc\.keytab#FILE:KEYTAB#'
        's#(/[^ :]*/)?kprop: #kprop: #'
    )
}

kp_prep() {   # host, before the lock
    local f
    kp_init
    for f in kp-kdc.sh kp-vm.sh kp-bulk-dump.py b2a-lib.sh b2a-kdcconf.py b2a-host.sh; do [ -s "$SCRIPTS/helpers/$f" ] || { echo "kp: helpers/$f is missing" >&2; return 1; }; done
    if [ -s "$KP_RPM_FILE" ]; then
        command -v rpmkeys > /dev/null || { echo "kp: rpmkeys is missing on the host" >&2; return 1; }
        KP_MODE=local
    else
        KP_MODE=repo
        echo "kp: no rpm (KP_RPM=${KP_RPM_FILE:-unset}): the replica installs $KP_NEVR from the repository (the exact version is checked)" >&2
    fi
    return 0
}

kp_push() {   # L2: the host's check of the rpm, the helpers on both VMs, the rpm and our two programs on client2
    local rpm_name=""
    kp_init
    mkdir -p "$OUT/kp"
    if [ "$KP_MODE" = local ]; then
        {
            echo "# rpmkeys --checksig -v on the host, $(now)"
            echo "# $KP_RPM_FILE"
            sha256sum "$KP_RPM_FILE"
            rpmkeys --checksig -v "$KP_RPM_FILE" 2>&1; echo "[rc=$?]"
        } 2>&1 | redact > "$OUT/kp/rpm-checksig-host.txt"
        cat "$OUT/kp/rpm-checksig-host.txt" >> "$LOG"
        expect KP.push.rpm-sha256 "$OUT/kp/rpm-checksig-host.txt" "^$KP_RPM_SHA  "
        expect KP.push.rpm-signature-host "$OUT/kp/rpm-checksig-host.txt" 'key fingerprint: c6e7f081cf80e13146676e88829b606631645531: OK'
        expect KP.push.rpm-digests-host "$OUT/kp/rpm-checksig-host.txt" '^ +(Header|Payload) SHA256 digest: OK$' 2
        expect KP.push.rpm-checksig-rc "$OUT/kp/rpm-checksig-host.txt" '^\[rc=0\]$'
        rpm_name=$(basename "$KP_RPM_FILE")
    fi
    b2a_push_script kp-kdc.sh kp-bulk-dump.py || return 1
    push client2 "$SCRIPTS/helpers/kp-vm.sh" "$KP_KDIR/kp-vm.sh" 755 || return 1
    if [ "$KP_MODE" = local ]; then push client2 "$KP_RPM_FILE" "$KP_KDIR/$rpm_name" 644 || return 1; fi
    push client2 "$W/ship/release/krb5-kpropd" "$KP_KDIR/ours-kpropd" 755 || return 1
    push client2 "$W/ship/release/krb5-kdb" "$KP_KDIR/kdb5_util" 755 || return 1
    push client2 "$W/ship/release/krb5-kdc" "$KP_KDIR/ours-kdc" 755 || return 1
    return 0
}

# ---------------------------------------------------------------- the pieces
kp_kdcx() {   # kp_kdcx STAGE NAME SECTION: a section of kp-kdc.sh on the kdc; its CELL blocks are split into $OUT/kp/STAGE-<cell>.txt
    local st=$1 name=$2 section=$3
    cell "kp/$st-run-$name" kdc "sudo bash $VMD/b2a/kp-kdc.sh $st $section" kdc+kadmin < /dev/null
    b2a_split "$OUT/kp/$st-run-$name.txt" "$OUT/kp" "$st"
}
kp_vmx() {   # kp_vmx STAGE NAME ARGS...: kp-vm.sh ARGS on client2 as a cell without a KDC log part: $OUT/kp/STAGE-NAME.txt
    local st=$1 name=$2; shift 2
    cell "kp/$st-$name" client2 "sudo bash $KP_KDIR/kp-vm.sh $*; echo \"[rc=\$?]\"" none < /dev/null
}
kp_kprop() {   # kp_kprop STAGE CELL DUMPFILE [KEYTAB [REPLICA]]: one kprop run on the kdc: its streams, the trace, the .last_prop it left, and the KDC log lines it added
    local st=$1 name=$2 dump=$3 keytab=${4:-$KP_KEYTAB} replica=${5:-$KP_REPLICA}
    cell "kp/$st-$name" kdc "sudo bash $VMD/b2a/kp-kdc.sh $st run -- kprop -d -s $keytab -f $KP_P/$dump $replica; echo \"[end rc=\$?]\"" kdc < /dev/null
}
kp_fact() {   # kp_fact STAGE FILE KEY: the value of "KEY value" in a record file (first line)
    sed -n "s/^$3 //p" "$OUT/kp/$1-$2.txt" 2> /dev/null | head -n 1
}
kp_section() {   # kp_section FILE HEADER-RX: the lines under the first header that matches, up to the next "==" / "# " / "[" line (not for the trace: its lines begin with "[")
    RX="$2" awk 'f && /^(==|# |\[)/ { exit } f { print } $0 ~ ENVIRON["RX"] { f = 1 }' "$1" 2> /dev/null
}
kp_as_seq() {   # kp_as_seq FILE: the results of the AS_REQ lines for host/kdc in the KDC part of a cell, in order ("NEEDED_PREAUTH ISSUE")
    sed -n '/^# KDC log lines added/,/^# kadmind log lines/p' "$1" 2> /dev/null | grep -E 'AS_REQ .* host/kdc\.kerber\.test@' | sed -nE 's/.*AS_REQ \(.*\) [^ ]+: ([A-Z_]+): .*/\1/p' | paste -sd' ' -
}

kp_sent_rows() {   # kp_sent_rows LABEL FILE BLOCKS BYTES: the "N bytes sent." lines of kprop -d: one per KRB-PRIV block of up to 32768 bytes, the last the file's size
    local label=$1 file=$2 blocks=$3 bytes=$4 got
    got=$(kp_section "$file" '^== stdout$' | awk '/^[0-9]+ bytes sent\.$/ { n++; last = $1 } END { print n + 0, last + 0 }')
    same "$label.bytes-sent" "$blocks $bytes" "$got" "the bytes-sent lines: count and last = ceil(size/32768) and the dump's size"
}

kp_ok_rows() {   # kp_ok_rows STAGE CELL DUMP: the rows every successful kprop run shares
    local st=$1 name=$2 dump=$3 L=KP.$1.$2 f="$OUT/kp/$1-$2.txt" blocks bytes nerr
    blocks=${KP_F[$st.$dump.blocks]:-0}; bytes=${KP_F[$st.$dump.bytes]:-0}
    expect "$L.kprop.rc" "$f" '^\[rc=0\]$'
    expect "$L.kprop.end-rc" "$f" '^\[end rc=0\]$'
    expect_under "$L.kprop.succeeded" "$f" '^== stdout$' "^Database propagation to ${KP_REPLICA//./\\.}: SUCCEEDED\$" 1
    kp_sent_rows "$L.kprop" "$f" "$blocks" "$bytes"
    nerr=$(kp_section "$f" '^== stderr$' | grep -c . || true)
    same "$L.kprop.stderr-empty" 0 "${nerr:-0}" "stderr lines of a successful run"
    expect_under "$L.kprop.last-prop" "$f" '^== last_prop$' '^size_mode 1 600$' 1
    expect_under "$L.kprop.last-prop-nul" "$f" '^== last_prop$' '^bytes 00$' 1
    expect_part "$L.kprop.kdc-issue" "$f" kdc "AS_REQ .*: ISSUE: .*host/kdc\\.kerber\\.test@$RRX for host/client2\\.kerber\\.test@$RRX" 1
    expect_under "$L.kprop.trace-start" "$f" '^== trace$' "Getting initial credentials for host/kdc\\.kerber\\.test@$RRX" 1
    expect_under "$L.kprop.trace-service" "$f" '^== trace$' 'Setting initial creds service to host/client2\.kerber\.test' 1
    expect_under "$L.kprop.trace-keytab" "$f" '^== trace$' "Retrieving host/kdc\\.kerber\\.test@$RRX from FILE:.*kdc\\.keytab \\(vno 0, enctype aes256-cts\\) with result: 0/Success" 1
    expect_under "$L.kprop.trace-authenticator" "$f" '^== trace$' 'Creating authenticator for .*, seqnum [0-9]+, subkey \(null\)' 1
    expect_under "$L.kprop.trace-ap-rep" "$f" '^== trace$' 'Read AP-REP' 1
    expect_part "$L.kprop.no-secret" "$f" client '<REDACTED:' 0
}

kp_fail_rows() {   # kp_fail_rows STAGE CELL STDERR-RX: kprop failed with rc 1 and a message that matches, nothing propagated
    local st=$1 name=$2 rx=$3 L=KP.$1.$2 f="$OUT/kp/$1-$2.txt"
    expect "$L.kprop.rc" "$f" '^\[rc=1\]$'
    expect_under "$L.kprop.message" "$f" '^== stderr$' "$rx" 1
    expect_under "$L.kprop.not-succeeded" "$f" '^== stdout$' 'SUCCEEDED' 0
    expect_under "$L.kprop.no-last-prop" "$f" '^== last_prop$' '^absent$' 1
    expect_part "$L.kprop.no-secret" "$f" client '<REDACTED:' 0
    result "$L.kprop.as-results" INFO "the AS_REQ results for host/kdc in the KDC's log (MIT's keytab AS may repeat after a failure: commit 04's named limit)" - 0 "$(kp_as_seq "$f")"
}

kp_mit_log_rows() {   # kp_mit_log_rows LABEL FILE: MIT's kpropd -d, one connection
    local L=$1 f=$2
    expect_under "$L.kpropd.connection" "$f" '^== kpropd log' '^Connection from ' 1
    expect_under "$L.kpropd.recvauth" "$f" '^== kpropd log' "^krb5_recvauth\\(.*kprop5_01, host/client2\\.kerber\\.test@$RRX" 1
    expect_under "$L.kpropd.client" "$f" '^== kpropd log' "^authenticated client: host/kdc\\.kerber\\.test@$RRX \\(etype == aes(128|256)-cts-hmac-sha1-96\\)\$" 1
    expect_under "$L.kpropd.transfer-started" "$f" '^== kpropd log' '^Full propagation transfer started\.$' 1
    expect_under "$L.kpropd.transfer-finished" "$f" '^== kpropd log' '^Full propagation transfer finished\.$' 1
    expect_under "$L.kpropd.loader" "$f" '^== kpropd log' '^calling kdb5_util to load database$' 1
    expect_under "$L.kpropd.load-done" "$f" '^== kpropd log' '^Database load process for full propagation completed\.$' 1
}
kp_ours_log_rows() {   # kp_ours_log_rows LABEL FILE: our kpropd -d. Start line is ready (ec0b2d6a). kprop ok is gone since 0178dd7e.
    local L=$1 f=$2
    expect_under "$L.kpropd.log-listening" "$f" '^== kpropd log' '^ready$' 1
    expect_under "$L.kpropd.connection" "$f" '^== kpropd log' '^Connection from ' 1
    expect_under "$L.kpropd.recvauth" "$f" '^== kpropd log' "^krb5_recvauth\\(.*kprop5_01, host/client2\\.kerber\\.test@$RRX" 1
    expect_under "$L.kpropd.client" "$f" '^== kpropd log' "^authenticated client: host/kdc\\.kerber\\.test@$RRX \\(etype == aes(128|256)-cts-hmac-sha1-96\\)\$" 1
    expect_under "$L.kpropd.transfer-started" "$f" '^== kpropd log' '^Full propagation transfer started\.$' 1
    expect_under "$L.kpropd.transfer-finished" "$f" '^== kpropd log' '^Full propagation transfer finished\.$' 1
    expect_under "$L.kpropd.loader" "$f" '^== kpropd log' '^calling kdb5_util to load database$' 1
    expect_under "$L.kpropd.load-pid" "$f" '^== kpropd log' '^Load PID is [0-9]+$' 1
    expect_under "$L.kpropd.load-done" "$f" '^== kpropd log' '^Database load process for full propagation completed\.$' 1
}

kp_listening_row() {   # kp_listening_row LABEL FILE
    expect "$1.kpropd.listening" "$2" '^LISTENING 754 pid [0-9]+$'
}

kp_counts_rows() {   # kp_counts_rows LABEL STAGE REPORTCELL DUMP: the replica's principals against the primary's dump
    local L=$1 st=$2 rc=$3 d=$4 want_bulk=0
    [ "$d" = B ] && want_bulk=1
    same "$L.replica-princs" "${KP_F[$st.$d.princs]:-?}" "$(kp_fact "$st" "$rc" REPLICA_PRINCS)" "principals in the replica's database = in the dump sent"
    same "$L.replica-names" "${KP_F[$st.$d.names]:-?}" "$(kp_fact "$st" "$rc" REPLICA_NAMES_SHA16)" "the sorted principal names of the replica = of the dump sent (a short hash)"
    same "$L.replica-has-hostkdc" 1 "$(kp_fact "$st" "$rc" REPLICA_HAS_HOSTKDC)" "host/kdc.kerber.test is in the replica"
    same "$L.replica-has-alice" 1 "$(kp_fact "$st" "$rc" REPLICA_HAS_ALICE)" "alice is in the replica"
    same "$L.replica-has-client2" 1 "$(kp_fact "$st" "$rc" REPLICA_HAS_CLIENT2)" "host/client2.kerber.test is in the replica"
    same "$L.replica-has-bulk250" "$want_bulk" "$(kp_fact "$st" "$rc" REPLICA_HAS_BULK250)" "bulk0250 is in the replica exactly when the dump was B"
}

# ---------------------------------------------------------------- the cells
kp_cell_tm() {   # kp_cell_tm STAGE DUMP(A|B): MIT's kpropd with the loader /bin/true: what it received against what was sent
    local st=$1 d=$2 name=tm$2 L=KP.$1.tm$2
    kp_vmx "$st" "$name-start" kpropd-start mit-transport
    kp_listening_row "$L" "$OUT/kp/$st-$name-start.txt"
    kp_kprop "$st" "$name" "dump$d"
    kp_vmx "$st" "$name-kpropd" kpropd-stop mit
    kp_vmx "$st" "$name-report" replica-report mit-transport
    kp_ok_rows "$st" "$name" "$d"
    kp_mit_log_rows "$L" "$OUT/kp/$st-$name-kpropd.txt"
    same "$L.received-bytes" "${KP_F[$st.$d.bytes]:-?}" "$(kp_fact "$st" "$name-report" RECV_BYTES)" "the file kpropd received is as long as the dump sent"
    same "$L.received-hash" "${KP_F[$st.$d.sha16]:-?}" "$(kp_fact "$st" "$name-report" RECV_SHA16)" "the file kpropd received has the dump's short hash"
    same "$L.received-princs" "${KP_F[$st.$d.princs]:-?}" "$(kp_fact "$st" "$name-report" RECV_PRINCS)" "principal records in the received file = in the dump"
    same "$L.received-names" "${KP_F[$st.$d.names]:-?}" "$(kp_fact "$st" "$name-report" REPLICA_NAMES_SHA16)" "the sorted principal names of the received file = of the dump sent"
}
kp_pidfile_rows() {   # kp_pidfile_rows LABEL FILE: --pid-file's one line is the daemon pid
    expect "$1.pidfile.line" "$2" '^PIDFILE_LINE [0-9]+$'
    expect "$1.pidfile.eq-daemon" "$2" '^PIDFILE_EQ_DAEMON yes$'
}
kp_pid_fail() {   # kp_pid_fail STAGE FLAVOR: missing directory. rc 1 and MIT's journal line.
    local st=$1 fl=$2 L=KP.$1 f="$OUT/kp/$1-pid-fail-$2.txt"
    kp_vmx "$st" "pid-fail-$fl" kpropd-pid-fail "$fl"
    expect "$L.$fl.pid-fail.rc" "$f" '^PIDFAIL_RC=1$'
    expect_under "$L.$fl.pid-fail.journal" "$f" '^== journal$' 'Could not write pid file /nonexistent/dir/kpropd.pid' 1
}
kp_cell_lm() {   # kp_cell_lm STAGE DUMP: MIT's kpropd loading with kdb5_util. Dump A also passes --pid-file.
    local st=$1 d=$2 name=lm$2 L=KP.$1.lm$2 mode=mit-load
    [ "$d" = A ] && mode=mit-load-pid
    kp_vmx "$st" "$name-start" kpropd-start "$mode"
    kp_listening_row "$L" "$OUT/kp/$st-$name-start.txt"
    [ "$d" = A ] && kp_pidfile_rows "$L" "$OUT/kp/$st-$name-start.txt"
    kp_kprop "$st" "$name" "dump$d"
    kp_vmx "$st" "$name-kpropd" kpropd-stop mit
    kp_vmx "$st" "$name-report" replica-report mit-load
    kp_ok_rows "$st" "$name" "$d"
    kp_mit_log_rows "$L" "$OUT/kp/$st-$name-kpropd.txt"
    kp_counts_rows "$L" "$st" "$name-report" "$d"
}
kp_cell_lo() {   # kp_cell_lo STAGE DUMP: our kpropd: the database it wrote against the dump
    local st=$1 d=$2 name=lo$2 L=KP.$1.lo$2
    kp_vmx "$st" "$name-start" kpropd-start ours
    kp_listening_row "$L" "$OUT/kp/$st-$name-start.txt"
    kp_pidfile_rows "$L" "$OUT/kp/$st-$name-start.txt"
    kp_kprop "$st" "$name" "dump$d"
    kp_vmx "$st" "$name-kpropd" kpropd-stop ours
    kp_vmx "$st" "$name-report" replica-report ours
    kp_ok_rows "$st" "$name" "$d"
    kp_ours_log_rows "$L" "$OUT/kp/$st-$name-kpropd.txt"
    same "$L.replica-header" "kdb5_util load_dump version 7" "$(kp_fact "$st" "$name-report" REPLICA_DB_HEADER)" "our kpropd writes the database as dump text (its records are its own form: the names are compared, not the bytes)"
    kp_counts_rows "$L" "$st" "$name-report" "$d"
}
kp_e2e() {   # kp_e2e STAGE FLAVOR(mit|ours) CELL(e2m|e2o): the replica's own KDC serves what was propagated; the host key kinits against it
    local st=$1 fl=$2 name=$3 L=KP.$1.$3
    kp_vmx "$st" "$name-start" kdc-start "$fl"
    expect "$L.kdc-up" "$OUT/kp/$st-$name-start.txt" '^KDC_LISTENING 8088 pid [0-9]+$'
    kp_vmx "$st" "$name" e2e "$fl"
    kp_vmx "$st" "$name-stop" kdc-stop "$fl"
    expect "$L.kinit-rc" "$OUT/kp/$st-$name.txt" '^\[rc=0\]$'
    expect_under "$L.klist-principal" "$OUT/kp/$st-$name.txt" '^== klist$' "^Default principal: host/client2\\.kerber\\.test@$RRX\$" 1
    expect_under "$L.klist-tgt" "$OUT/kp/$st-$name.txt" '^== klist$' " krbtgt/$RRX@$RRX\$" 1
    expect_under "$L.replica-kdc-issue" "$OUT/kp/$st-$name.txt" '^== replica kdc log' "AS_REQ .*: ISSUE: .*host/client2\\.kerber\\.test@$RRX for krbtgt/$RRX@$RRX" 1
    expect "$L.kdc-down" "$OUT/kp/$st-$name-stop.txt" '^0$'
}

kp_identity_rows() {   # kp_identity_rows STAGE: the identity of the MIT kpropd the rpm installed on client2, and the install itself
    local st=$1 L=KP.$1.identity f="$OUT/kp/$1-mit-install.txt" idf="$OUT/kp/$1-identity.txt" nrx
    {
        echo "# identity rule applied to the daemon of the rpm on client2: the ELF package note of /usr/sbin/kpropd names krb5 1.22.2-<rel>.fc43, rpm -V lists config files only, rpm -q the exact version"
        echo "== readelf -n /usr/sbin/kpropd (.note.package)"
        vm client2 "$(note_cmd /usr/sbin/kpropd)" 2>&1
    } 2>&1 < /dev/null | redact > "$idf"
    cat "$idf" >> "$LOG"
    nrx='Packaging Metadata: \{"type":"rpm","name":"krb5","version":"'"$PKG_VERSION_RX"'"'
    expect_under "$L.package-note-kpropd" "$idf" '^== readelf -n ' "$nrx"
    expect "$L.install-rc" "$f" '^INSTALL_RC=0$'
    expect "$L.rpm-q" "$f" "^$KP_NEVR\\.x86_64\$"
    expect_rpmv_config_only "$L.rpmV-config-only" "$f" no
    expect_under "$L.transaction-installing" "$f" '^== dnf -y install --assumeno$' '^ krb5-server x86_64 1\.22\.2-4\.fc43 (@commandline|updates|fedora) ' 1
    expect_under "$L.transaction-dependencies" "$f" '^== dnf -y install --assumeno$' '^ words +noarch ' 1
    expect_under "$L.transaction-only-these" "$f" '^== dnf -y install --assumeno$' '^ Installing: +2 packages$' 1
    expect_under "$L.transaction-nothing-else" "$f" '^== dnf -y install --assumeno$' '^(Upgrading|Replacing|Removing|Downgrading|Reinstalling):' 0
    if [ "$KP_MODE" = local ]; then
        expect_under "$L.checksig-vm" "$f" '^== rpmkeys --checksig -v' 'key fingerprint: c6e7f081cf80e13146676e88829b606631645531: OK' 1
        expect_under "$L.checksig-vm-digests" "$f" '^== rpmkeys --checksig -v' '^ +(Header|Payload) SHA256 digest: OK$' 2
        expect "$L.source-sha256" "$f" "^sha256 $KP_RPM_SHA\$"
    fi
}

kp_phase_mit() {   # kp_phase_mit STAGE: MIT's kpropd on client2 (the rpm installed for the phase and removed after it)
    local st=$1 L=KP.$1 src d f="$OUT/kp/$1-mit-install.txt"
    if [ "$KP_MODE" = local ]; then src="$KP_KDIR/$(basename "$KP_RPM_FILE")"; else src=$KP_NEVR; fi
    kp_vmx "$st" mit-install mit-install "$src"
    kp_identity_rows "$st"
    if ! grep -q '^INSTALL_RC=0$' "$f" 2> /dev/null; then
        result "$L.mit-kpropd" INFO "NOT-RUN: MIT's kpropd (the rpm) is not installed on client2 (see $L.identity.install-rc): the cells with MIT's kpropd did not run" - 0 "NOT-RUN"
        return 0
    fi
    for d in A B; do deadline; kp_cell_tm "$st" "$d"; done
    kp_vmx "$st" replica-reset-mit replica-reset mit
    for d in A B; do deadline; kp_cell_lm "$st" "$d"; done
    deadline; kp_e2e "$st" mit e2m
    deadline; kp_cells_mit_up "$st"
    deadline; kp_pid_fail "$st" mit
    kp_vmx "$st" mit-remove mit-remove
    f="$OUT/kp/$st-mit-remove.txt"
    expect "$L.remove.rc" "$f" '^REMOVE_RC=0$'
    expect_under "$L.remove.gone" "$f" '^== after$' '^package krb5-server is not installed$' 1
    expect_under "$L.remove.words-gone" "$f" '^== after$' '^package words is not installed$' 1
    expect_under "$L.remove.dir-gone" "$f" '^== after$' "^ls: cannot access '/var/kerberos/krb5kdc': No such file or directory\$" 1
}
kp_cells_mit_up() {   # kp_cells_mit_up STAGE: the failure cells that need MIT's kpropd listening: no ACL, and the network refusing
    local st=$1 L=KP.$1 f
    kp_vmx "$st" noacl-start kpropd-start mit-noacl
    kp_listening_row "$L.noacl" "$OUT/kp/$st-noacl-start.txt"
    kp_kprop "$st" noacl dumpA
    kp_vmx "$st" noacl-kpropd kpropd-stop mit
    kp_fail_rows "$st" noacl "$KP_NOACL_RX"
    expect_under "$L.noacl.kpropd-rejected" "$OUT/kp/$st-noacl-kpropd.txt" '^== kpropd log' "^Rejected connection from unauthorized principal host/kdc\\.kerber\\.test@$RRX\$" 1
    kp_vmx "$st" reject-start kpropd-start mit-transport
    kp_vmx "$st" reject-on nft-on
    f="$OUT/kp/$st-reject-on.txt"
    if grep -q '^NFT_UNAVAILABLE$' "$f"; then
        result "$L.reject" INFO "NOT-RUN: nft is not on client2" - 0 "NOT-RUN"
        kp_vmx "$st" reject-kpropd kpropd-stop mit
        return 0
    fi
    expect "$L.reject.nft-on" "$f" '^NFT_ON_RC=0$'
    kp_kprop "$st" reject dumpA
    kp_vmx "$st" reject-off nft-off
    kp_vmx "$st" reject-kpropd kpropd-stop mit
    expect "$L.reject.nft-off" "$OUT/kp/$st-reject-off.txt" '^NFT_OFF_RC=0$'
    expect "$L.reject.nft-gone" "$OUT/kp/$st-reject-off.txt" '^ruleset lines: 0$'
    kp_fail_rows "$st" reject '^kprop: No route to host while connecting to server$'
}

kp_phase_ours() {   # kp_phase_ours STAGE: our kpropd on client2
    local st=$1 d
    kp_vmx "$st" replica-reset-ours replica-reset ours
    for d in A B; do deadline; kp_cell_lo "$st" "$d"; done
    deadline; kp_e2e "$st" ours e2o
    deadline; kp_pid_fail "$st" ours
}

kp_cells_plain() {   # kp_cells_plain STAGE: the failure cells that need no kpropd (none is listening)
    local st=$1 L=KP.$1
    deadline; kp_kprop "$st" refused dumpA
    kp_fail_rows "$st" refused '^kprop: Connection refused while connecting to server$'
    kp_kprop "$st" nohost dumpA "$KP_KEYTAB" nohost.kerber.test
    kp_fail_rows "$st" nohost '^kprop: Server not found in Kerberos database while getting initial credentials$'
    kp_kprop "$st" nokey dumpA "$KP_P/other.keytab"
    kp_fail_rows "$st" nokey '^kprop: Key table entry not found while getting initial credentials$'
    kp_kprop "$st" nokeytab dumpA "$KP_P/no-such.keytab"
    kp_fail_rows "$st" nokeytab '^kprop: .* while getting initial credentials$'
    kp_kprop "$st" stale-pre dumpA "$KP_P/stale.keytab"
    kp_fail_rows "$st" stale-pre '^kprop: Preauthentication failed while getting initial credentials$'
    kp_kdcx "$st" preauth-off preauth-off
    kp_kprop "$st" stale-nopre dumpA "$KP_P/stale.keytab"
    kp_kdcx "$st" preauth-on preauth-on
    kp_fail_rows "$st" stale-nopre '^kprop: Decrypt integrity check failed while getting initial credentials$'
    expect "$L.stale.preauth-flag-off" "$OUT/kp/$st-preauth-off.txt" "^Principal \"host/kdc\\.kerber\\.test@$RRX\" modified\\.\$"
    expect "$L.stale.preauth-flag-on" "$OUT/kp/$st-preauth-on.txt" "^Principal \"host/kdc\\.kerber\\.test@$RRX\" modified\\.\$"
    kp_kdcx "$st" touch-new touch-new
    kp_kprop "$st" toonew dumpC
    kp_fail_rows "$st" toonew "^kprop: '.*/dumpC' more recent than '.*/dumpC\\.dump_ok'\\.\$"
    kp_kprop "$st" nodumpok dumpD
    kp_fail_rows "$st" nodumpok '^kprop: No such file or directory while trying to stat .*/dumpD\.dump_ok$'
    kp_cell_kinit_nokeytab "$st"
}

kp_cell_kinit_nokeytab() {   # kp_cell_kinit_nokeytab STAGE: `kinit -k -t FILE-THAT-IS-NOT-THERE host/client2` on client2 with MIT's kinit and with ours, against a principal that requires preauthentication: the shared keytab path (the head's question on KP.parity.nokeytab)
    local st=$1 L=KP.$1 t kin nm f
    for t in mit ours; do
        kin=kinit; [ "$t" = ours ] && kin=$VMD/ours/kinit
        nm="nokeytab-kinit-$t"; f="$OUT/kp/$st-$nm.txt"
        cell "kp/$st-$nm" client2 "KRB5CCNAME=FILE:$KP_KDIR/nokeytab-$t.cc $kin -k -t $KP_KDIR/no-such.keytab host/client2.kerber.test@$REALM < /dev/null 2>&1; echo \"[rc=\$?]\"; rm -f $KP_KDIR/nokeytab-$t.cc" kdc
        expect "$L.$nm.rc" "$f" '^\[rc=1\]$'
        expect "$L.$nm.message" "$f" '^(/[^ :]*/)?(krb5-)?kinit: .* while getting initial credentials$'
        expect_part "$L.$nm.no-secret" "$f" client '<REDACTED:' 0
    done
    parity_eq "$L.nokeytab-kinit.mit-eq-ours" <(cell_body "$OUT/kp/$st-nokeytab-kinit-mit.txt" | sed -E 's#^(/[^ :]*/)?(krb5-)?kinit: #kinit: #') <(cell_body "$OUT/kp/$st-nokeytab-kinit-ours.txt" | sed -E 's#^(/[^ :]*/)?(krb5-)?kinit: #kinit: #') '/^# /d'
}

kp_stage() {   # kp_stage mit|ours
    local st=$1 L=KP.$1 mark d f n
    kp_init
    mkdir -p "$OUT/kp"
    mark=$(vm client2 "sudo bash $KP_KDIR/kp-vm.sh avc-mark" 2>> "$LOG" < /dev/null | tr -d '[:space:]')
    # the primary: principals, keytabs, dumps
    kp_kdcx "$st" setup setup
    expect "$L.setup.kdc-principal" "$OUT/kp/$st-add-1.txt" "^Principal \"host/kdc\\.kerber\\.test@$RRX\" created\\.\$"
    expect "$L.setup.decoy-principal" "$OUT/kp/$st-add-2.txt" "^Principal \"kpdecoy/kdc\\.kerber\\.test@$RRX\" created\\.\$"
    info "$L.setup.principal-flags" "$OUT/kp/$st-getprinc-kdc.txt" '^Attributes: ' "(no Attributes line)"
    expect_under "$L.setup.kdc-keytab" "$OUT/kp/$st-keytabs.txt" '^== klist -ke kdc\.keytab$' "^ +3 host/kdc\\.kerber\\.test@$RRX \\(aes256-cts-hmac-sha1-96\\)" 1
    expect_under "$L.setup.stale-keytab" "$OUT/kp/$st-keytabs.txt" '^== klist -ke stale\.keytab$' "^ +2 host/kdc\\.kerber\\.test@$RRX \\(aes256-cts-hmac-sha1-96\\)" 1
    expect_under "$L.setup.other-keytab" "$OUT/kp/$st-keytabs.txt" '^== klist -ke other\.keytab$' "kpdecoy/kdc\\.kerber\\.test@$RRX" 2
    expect_under "$L.setup.other-keytab-no-host-key" "$OUT/kp/$st-keytabs.txt" '^== klist -ke other\.keytab$' 'host/kdc' 0
    kp_kdcx "$st" dump dump
    for d in A B; do
        KP_F[$st.$d.bytes]=$(kp_fact "$st" dump-facts DUMP_${d}_BYTES); KP_F[$st.$d.blocks]=$(kp_fact "$st" dump-facts DUMP_${d}_BLOCKS)
        KP_F[$st.$d.princs]=$(kp_fact "$st" dump-facts DUMP_${d}_PRINCS); KP_F[$st.$d.sha16]=$(kp_fact "$st" dump-facts DUMP_${d}_SHA16); KP_F[$st.$d.names]=$(kp_fact "$st" dump-facts DUMP_${d}_NAMES_SHA16)
        same "$L.dump-$d.header" "kdb5_util load_dump version 7" "$(kp_fact "$st" dump-facts DUMP_${d}_HEADER)" "the first line of dump $d"
        verdict "$L.dump-$d.size" "$([ "${KP_F[$st.$d.bytes]:-0}" -gt 0 ] 2> /dev/null && echo PASS || echo FAIL)" "dump $d is there" "> 0" "${KP_F[$st.$d.bytes]:-0}"
        same "$L.dump-$d.has-hostkdc" 1 "$(kp_fact "$st" dump-facts DUMP_${d}_HAS_HOSTKDC)" "host/kdc.kerber.test is in dump $d"
        same "$L.dump-$d.has-alice" 1 "$(kp_fact "$st" dump-facts DUMP_${d}_HAS_ALICE)" "alice is in dump $d"
    done
    same "$L.dump-A.one-block" 1 "${KP_F[$st.A.blocks]:-0}" "dump A fits one KRB-PRIV block of 32768 bytes"
    n=${KP_F[$st.B.blocks]:-0}
    verdict "$L.dump-B.several-blocks" "$([ "$n" -ge 2 ] 2> /dev/null && echo PASS || echo FAIL)" "dump B spans several KRB-PRIV blocks (the multi-block case of KP's commit 02)" ">= 2" "$n"
    same "$L.dump-B.bulk" 1 "$(kp_fact "$st" dump-facts DUMP_B_HAS_BULK250)" "dump B holds bulk0250 (250 principals more than A)"
    # the replica: directory, ACL, stash (from the kdc through the host's pipe), profiles
    kp_vmx "$st" init init
    expect "$L.replica.init" "$OUT/kp/$st-init.txt" '^INIT_OK$'
    expect "$L.replica.keytab-host-key" "$OUT/kp/$st-init.txt" "host/client2\\.kerber\\.test@$RRX \\(aes256-cts-hmac-sha1-96\\)"
    vm kdc "sudo bash $VMD/b2a/kp-kdc.sh $st stash-cat" 2>> "$LOG" < /dev/null | vm client2 "sudo bash $KP_KDIR/kp-vm.sh stash-install" 2>&1 | redact > "$OUT/kp/$st-stash.txt"
    cat "$OUT/kp/$st-stash.txt" >> "$LOG"
    expect "$L.replica.stash" "$OUT/kp/$st-stash.txt" '^STASH_BYTES [1-9][0-9]*$'
    kp_vmx "$st" profile-mit profile mit
    kp_vmx "$st" profile-ours profile ours
    expect "$L.replica.profile-mit" "$OUT/kp/$st-profile-mit.txt" '^PROFILE_OK mit$'
    expect "$L.replica.profile-ours" "$OUT/kp/$st-profile-ours.txt" '^PROFILE_OK ours$'
    # the cells
    kp_phase_mit "$st"
    kp_phase_ours "$st"
    kp_cells_plain "$st"
    kp_transport_rows "$st"
    kp_controls "$st"
    # undo
    kp_vmx "$st" cleanup cleanup
    expect "$L.cleanup.client2" "$OUT/kp/$st-cleanup.txt" '^CLEANUP_DONE$'
    expect "$L.cleanup.no-listener" "$OUT/kp/$st-cleanup.txt" '^CLEANUP_LISTENERS 0$'
    kp_kdcx "$st" cleanup cleanup
    expect "$L.cleanup.kdc-principal-deleted" "$OUT/kp/$st-del-1.txt" "^Principal \"host/kdc\\.kerber\\.test@$RRX\" deleted\\.\$"
    expect "$L.cleanup.decoy-deleted" "$OUT/kp/$st-del-2.txt" "^Principal \"kpdecoy/kdc\\.kerber\\.test@$RRX\" deleted\\.\$"
    expect "$L.cleanup.kdc-principal-gone" "$OUT/kp/$st-getprinc-gone.txt" '^get_principal: Principal does not exist while retrieving "host/kdc\.kerber\.test@'"$RRX"'"\.$'
    expect "$L.cleanup.kdc-files-gone" "$OUT/kp/$st-left.txt" '^KP_LEFT 0$'
    # SELinux on client2 over the module's window
    cell "kp/$st-avc-client2" client2 "sudo bash $KP_KDIR/kp-vm.sh avc-check $mark" none < /dev/null
    expect "$L.avc-client2.enforcing" "$OUT/kp/$st-avc-client2.txt" '^Enforcing$' 1
    expect "$L.avc-client2.no-denial" "$OUT/kp/$st-avc-client2.txt" '^denials: <no matches> \(ausearch rc=1\); USER_CMD control: [1-9][0-9]* records$' 1
    info "$L.avc-client2.daemon-domains" "$OUT/kp/$st-avc-client2.txt" 'kpropd|krb5kdc|kdb5_util' "(no daemon of the module was running at the end: expected)"
    return 0
}

kp_transport_rows() {   # kp_transport_rows STAGE: the transport lines of the traces of the successful runs, named once (the parity rows compare the protocol after a mask that leaves these out)
    local st=$1 L=KP.$1.transport f n=0 first="" c
    for f in "$OUT"/kp/"$st"-{tmA,tmB,lmA,lmB,loA,loB}.txt; do
        [ -s "$f" ] || continue
        c=$(grep -c ' UDP error sending ' "$f" || true); n=$((n + ${c:-0}))
        [ -n "$first" ] || first=$(grep -m 1 -E ' Sending initial UDP request to ' "$f" | sed -E 's/^\[[0-9]+\] [0-9.]+: //')
    done
    verdict "$L.no-udp-error" "$([ "$n" = 0 ] && echo PASS || echo FAIL)" "UDP errors in the traces of the successful kprop runs (MIT's kprop reaches the KDC over UDP; ours, to an IPv6 address, got 97/Address family not supported and went to TCP)" 0 "$n"
    result "$L.first-udp-request" INFO "the first UDP request of the first successful run's trace (the kdc's own name resolves to its link-local IPv6 address on the lab VM)" - 0 "${first:-none}"
}

kp_controls() {   # kp_controls STAGE: the controls that make the rows above able to fail
    local st=$1 L=KP.$1.control a b
    a=$(sed -n '/^== stdout$/,/^== stderr$/p' "$OUT/kp/$st-tmA.txt" 2> /dev/null | grep -c '^[0-9]* bytes sent\.$' || true)
    b=$(sed -n '/^== stdout$/,/^== stderr$/p' "$OUT/kp/$st-tmB.txt" 2> /dev/null | grep -c '^[0-9]* bytes sent\.$' || true)
    verdict "$L.B-sends-more-blocks" "$([ "${a:-0}" -ge 1 ] && [ "${b:-0}" -gt "${a:-0}" ] && echo PASS || echo FAIL)" "dump B is sent in more KRB-PRIV blocks than dump A (kprop -d prints the running total after each)" "B > A >= 1" "A=${a:-0} B=${b:-0}"
    verdict "$L.hash-compare-can-fail" "$([ -n "${KP_F[$st.A.sha16]:-}" ] && [ "${KP_F[$st.A.sha16]:-}" != "${KP_F[$st.B.sha16]:-}" ] && echo PASS || echo FAIL)" "the short hashes of dump A and dump B differ, so the received-hash row would be red for the wrong file" differ "A=${KP_F[$st.A.sha16]:-} B=${KP_F[$st.B.sha16]:-}"
}

kp_mit() { kp_init; kp_stage mit; }
kp_ours() { kp_init; kp_stage ours; }

kp_body() {   # kp_body FILE: the client part of a cell without the KDC log
    cell_body "$1" 2> /dev/null
}
kp_nolog_body() {   # kp_nolog_body FILE: the client part of a failed run without the trace (MIT's keytab AS may repeat after a failure: commit 04's named limit)
    cell_body "$1" 2> /dev/null | sed '/^== trace$/,/^== last_prop$/{/^== last_prop$/!d}'
}

kp_parity() {
    local cell m o d="$OUT/kp" L=KP.parity
    kp_init
    for cell in $KP_CELLS; do
        m="$d/mit-$cell.txt"; o="$d/ours-$cell.txt"
        if [ ! -s "$m" ] || [ ! -s "$o" ]; then result "$L.$cell" INFO "NOT-RUN: a stage of this cell did not run (MIT's kpropd or the stage)" - 0 "NOT-RUN"; continue; fi
        kp_body "$m" > "$d/mit-$cell.body"; kp_body "$o" > "$d/ours-$cell.body"
        parity_eq "$L.$cell" "$d/mit-$cell.body" "$d/ours-$cell.body" "${KP_MASK[@]}"
        cell_body "$d/mit-$cell-kpropd.txt" > "$d/mit-$cell-kpropd.body" 2> /dev/null; cell_body "$d/ours-$cell-kpropd.txt" > "$d/ours-$cell-kpropd.body" 2> /dev/null
        parity_eq "$L.$cell.kpropd" "$d/mit-$cell-kpropd.body" "$d/ours-$cell-kpropd.body" 's/Load PID is [0-9]+/Load PID is N/'
        same "$L.$cell.as-results" "$(kp_as_seq "$m")" "$(kp_as_seq "$o")" "the AS_REQ results for host/kdc in the KDC's log, MIT's kprop and ours"
    done
    for cell in e2m e2o; do
        m="$d/mit-$cell.txt"; o="$d/ours-$cell.txt"
        if [ ! -s "$m" ] || [ ! -s "$o" ]; then result "$L.$cell" INFO "NOT-RUN: a stage of this cell did not run" - 0 "NOT-RUN"; continue; fi
        cell_body "$m" | sed '/^== replica kdc log/,$d' > "$d/mit-$cell.body"; cell_body "$o" | sed '/^== replica kdc log/,$d' > "$d/ours-$cell.body"
        parity_eq "$L.$cell" "$d/mit-$cell.body" "$d/ours-$cell.body" 's#^[0-9/]+ [0-9:]+ +[0-9/]+ [0-9:]+ #TIMES #' 's#FILE:[^ ]*/e2e\.cc#FILE:CC#'
    done
    for cell in $KP_FAILS; do
        m="$d/mit-$cell.txt"; o="$d/ours-$cell.txt"
        if [ ! -s "$m" ] || [ ! -s "$o" ]; then result "$L.$cell" INFO "NOT-RUN: a stage of this cell did not run" - 0 "NOT-RUN"; continue; fi
        kp_nolog_body "$m" > "$d/mit-$cell.body"; kp_nolog_body "$o" > "$d/ours-$cell.body"
        if [ "$cell" = noacl ]; then   # rc and the class of the message, not the words of a race
            local mm mo rm_ ro
            mm=$(kp_section "$d/mit-$cell.txt" '^== stderr$' | grep -cE "$KP_NOACL_RX" || true); mo=$(kp_section "$d/ours-$cell.txt" '^== stderr$' | grep -cE "$KP_NOACL_RX" || true)
            rm_=$(sed -n 's/^\[rc=\([0-9]*\)\]$/\1/p' "$d/mit-$cell.txt" | head -n 1); ro=$(sed -n 's/^\[rc=\([0-9]*\)\]$/\1/p' "$d/ours-$cell.txt" | head -n 1)
            verdict "$L.$cell" "$([ "$rm_" = 1 ] && [ "$ro" = 1 ] && [ "${mm:-0}" = 1 ] && [ "${mo:-0}" = 1 ] && echo PASS || echo FAIL)" "rc 1 and a message of the closed-connection class from MIT's kprop and from ours" "1 1" "rc ${rm_:-?}/${ro:-?}, message ${mm:-0}/${mo:-0}"
            result "$L.$cell.texts" INFO "the messages: MIT's kprop | ours" - 0 "$(kp_section "$d/mit-$cell.txt" '^== stderr$' | head -n 1) | $(kp_section "$d/ours-$cell.txt" '^== stderr$' | head -n 1)"
        else
            parity_eq "$L.$cell" "$d/mit-$cell.body" "$d/ours-$cell.body" "${KP_MASK[@]}"
        fi
        result "$L.$cell.as-results" INFO "the AS_REQ results for host/kdc in the KDC's log: MIT's kprop | ours (MIT may repeat the keytab AS after a failure: commit 04's named limit; VM-LEG.md 4)" - 0 "$(kp_as_seq "$m") | $(kp_as_seq "$o")"
    done
    # controls: a doctored copy differs; two different cells differ
    if [ -s "$d/mit-lmA.body" ] && [ -s "$d/ours-lmA.body" ]; then
        parity_control "$L.lmA" "$d/mit-lmA.body" "$d/ours-lmA.body" "${KP_MASK[@]}"
        if ! cmp -s <(b2_norm "$d/mit-lmA.body" "${KP_MASK[@]}") <(b2_norm "$d/mit-nohost.body" "${KP_MASK[@]}"); then verdict "$L.control.success-vs-failure" PASS "a successful run and a failed one must differ" differ differ ""
        else verdict "$L.control.success-vs-failure" FAIL "a successful run and a failed one must differ" differ same ""; fi
    fi
    return 0
}

kp_clean() {   # L7, before the shred: the daemons, the nft table, the rpm and the replica's files on client2; the keytabs and dumps on the kdc (the reset undoes the rest)
    kp_init
    vm client2 "sudo bash $KP_KDIR/kp-vm.sh cleanup" > /dev/null 2>&1 < /dev/null
    vm kdc "sudo bash $VMD/b2a/kp-kdc.sh ours cleanup" > /dev/null 2>&1 < /dev/null
    return 0
}
