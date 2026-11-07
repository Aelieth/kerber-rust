#!/usr/bin/env bash
# r3.sh --stage mit|ours: R3 (sshd GSSAPI from client1 to client2, short name and FQDN, delegation, refusals) on the lab,
# the R3-only RE-RUN of hold C's cell of the 1.1 full pass: the same commands and the same expectations; the one change is that the helpers countlast, tktcheck and tgtline
# are now defined (lib/cellfns.sh), so the five rows hold C never ran (r3.3.tgt, r3.4b.kdc-one-tgs, r3.4d.three-logins, r3.4d.acceptor-decrypts, r3.6.no-kdc-line) run. The commands are the ones of the proven hand records
# (for MIT and for kerber-rust: record.txt sections 0-10), run the same way, with these named differences:
#   - alice logs in on client1 headless, with pamtester through SSSD on a pty (harness/field/scenarios/sssd-login.sh,
#     R2 PROOF 2b), not at SDDM: the host route rule allows lab.sh only, and the SDDM/Konsole driving of the hand
#     records is direct virsh. The cache is the same (FILE:/tmp/krb5cc_10001 from pam_sss); the Konsole variant (R3 5b) is not run.
#   - client2 starts from f4-mit (the kit-joined baseline), so the harness exception, the group admins, the parked RA drop-in
#     and the kit's --sshd are done here, as R3-MIT's section 1 did, and undone at the end (sshd_config restored from a copy),
#     so that RA1 finds the sshd it needs and both stages start from the same client2.
# Needs: the lab lock held by the caller; kdc/services/client1/client2 up on f4-mit; the KDC under test running (MIT's, or the
# ship build after docs/install.md's upgrade); alice's password in ~/kerber-lab/secrets (the realm's, MIT_SECRET_ALICE).
# Environment (set by hc.sh): STAGE REC_DIR TMPDIR LAB HCIN HCSRC CELLFNS TREE SHIPNOTE. Output: $REC_DIR/record.txt and checks.tsv.
set -uo pipefail
STAGE=""
while [ $# -gt 0 ]; do
    case $1 in
        --stage) STAGE=$2; shift 2 ;;
        *) echo "usage: r3.sh --stage mit|ours" >&2; exit 2 ;;
    esac
done
case $STAGE in mit | ours) ;; *) echo "r3.sh: --stage mit|ours" >&2; exit 2 ;; esac
: "${REC_DIR:?}" "${TMPDIR:?}" "${LAB:?}" "${HCIN:?}" "${HCSRC:?}" "${CELLFNS:?}"
: "${FIELD_LAB_NET:?FIELD_LAB_NET is not set in field.env}" "${FIELD_KIT_DIR:?FIELD_KIT_DIR is not set in field.env}"
NET=$FIELD_LAB_NET; NETRX=${NET//./\\.}
kit_setup=("$FIELD_KIT_DIR"/*-remote-setup.sh)
[ "${#kit_setup[@]}" = 1 ] && [ -f "${kit_setup[0]}" ] || { echo "r3.sh: FIELD_KIT_DIR holds no single *-remote-setup.sh" >&2; exit 2; }
KN=$(basename "${kit_setup[0]}" -remote-setup.sh)
export LAB
# shellcheck source=/dev/null
. "$HCSRC/harness/field/lib/rec.sh"
# shellcheck source=/dev/null
. "$CELLFNS"   # countlast, tktcheck, tgtline: leg.sh's, copied; hold C's cell called them without any definition

R=KERBER\\.TEST
ALICE=mit-realm.alice.password
HV=/var/tmp/hand3
OPTS='-o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -o PasswordAuthentication=no -o PubkeyAuthentication=no -o KbdInteractiveAuthentication=no -o GSSAPIAuthentication=yes -o PreferredAuthentications=gssapi-with-mic'
OPTS_NK='-o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -o PubkeyAuthentication=no -o KbdInteractiveAuthentication=no -o GSSAPIAuthentication=yes -o PreferredAuthentications=gssapi-with-mic'
E2='\(2 etypes \{aes256-cts-hmac-sha1-96\(18\), aes128-cts-hmac-sha1-96\(17\)\}\)'
ISSUE_ETYPES='etypes \{rep=aes256-cts-hmac-sha1-96\(18\), tkt=aes256-cts-hmac-sha1-96\(18\), ses=aes256-cts-hmac-sha1-96\(18\)\}'
CAPS=${STATE:?}/caps
mkdir -p "$CAPS" "$REC_DIR/pcap" "$REC_DIR/logs"

note "R3 ($STAGE stage), the R3-only RE-RUN of the 1.1 full pass: tree $TREE; $SHIPNOTE"
note "KDC under test: $( [ "$STAGE" = mit ] && echo "Fedora MIT krb5-server 1.22.2-4.fc43 (f4-mit, as packaged)" || echo "kerber-rust, the ship build installed by docs/install.md 'Upgrading an MIT realm' from the f4-mit realm" )"

# ---------------------------------------------------------------- captures (streamed over ssh into the state dir: SELinux refuses tcpdump writing a file on client1, R2-MIT)
scapstart() {   # scapstart NAME VM IFACE FILTER
    local name=$1 vm=$2 iface=$3 filter=$4
    setsid -w nohup "$LAB" ssh "$vm" -- "sudo tcpdump -i $iface -U -s 0 -w - $(printf '%q' "$filter")" > "$CAPS/$name.raw.pcap" 2> "$CAPS/cap.$name.err" < /dev/null &
    echo $! > "$CAPS/cap.$name.pid"
    sleep 2
    note "capture $name started: lab@$vm tcpdump -i $iface $filter"
}
scapstop() {   # scapstop NAME VM
    local name=$1 vm=$2
    "$LAB" ssh "$vm" -- 'sudo pkill -INT -x tcpdump; true' < /dev/null > /dev/null 2>&1
    for _ in $(seq 1 15); do kill -0 "$(cat "$CAPS/cap.$name.pid")" 2> /dev/null || break; sleep 1; done
    note "capture $name stopped: $(grep -E 'packets (captured|received)' "$CAPS/cap.$name.err" | tr '\n' ' ')"
}
scapkeep() {   # scapkeep NAME TITLE: the kept copy without AS exchanges (lib/pcap-keep.sh) and its tshark decode (R3's pcapdecode.sh)
    local name=$1 title=$2
    check "pcap.$name" rc host "bash $(printf '%q' "$FIELD_LIB/pcap-keep.sh") $(printf '%q' "$CAPS/$name.raw.pcap") $(printf '%q' "$REC_DIR/pcap/$name.pcap") && head -n 1 $(printf '%q' "$REC_DIR/pcap/$name.pcap.txt")"
    host "bash $(printf '%q' "$HCIN/pcapdecode.sh") $(printf '%q' "$REC_DIR/pcap/$name.pcap") $(printf '%q' "$title"); wc -l $(printf '%q' "$REC_DIR/pcap/$name.pcap.txt")"
    rm -f "$CAPS/$name.raw.pcap"
}

# ---------------------------------------------------------------- 0. the machines as found
section "0. client2 and client1 as found (R3-MIT section 0 / R3 section 0b), the sshd state saved for the restore at the end"
T0=$(date -u '+%Y-%m-%d %H:%M:%S')
note "stage clock on the host: $T0 UTC"
run client2 "date -u; grep -E '^(VERSION|VARIANT_ID)=' /etc/os-release; rpm -q openssh-server openssh-clients krb5-libs krb5-workstation; getenforce; getent passwd alice bob kbruser lab; id alice; id bob; getent group admins || echo '(no group admins)'; sudo klist -k -e /etc/krb5.keytab; sudo ls -la /etc/ssh/sshd_config.d/ /var/opt/kit 2>&1 | head -30"
check r3.0.client2.keytab '^ +3 host/client2\.kerber\.test@KERBER\.TEST \(aes256-cts-hmac-sha1-96\)' run client2 "sudo klist -k -e /etc/krb5.keytab"
checklast r3.0.client2.keytab-short '^ +2 host/client2@KERBER\.TEST \(aes256-cts-hmac-sha1-96\)'
check r3.0.client2.stubs '^uid=10001\(alice\) gid=10001\(alice\)' run client2 "id alice; id bob"
check r3.0.save-sshd '^saved: ' run client2 "install -d -m 0700 $HV && sudo install -d -m 0700 $HV/r3-save && sudo rm -f $HV/r3-save/admins-existed && { getent group admins > /dev/null && sudo touch $HV/r3-save/admins-existed; true; } && sudo rm -rf $HV/r3-save/sshd_config $HV/r3-save/sshd_config.d && sudo cp -a /etc/ssh/sshd_config $HV/r3-save/sshd_config && sudo cp -a /etc/ssh/sshd_config.d $HV/r3-save/sshd_config.d && sudo sh -c 'sha256sum /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*' | tee $HV/r3-save.sha256 | sed 's/^/before: /' && echo \"saved: \$(sudo ls $HV/r3-save/sshd_config.d | wc -l) drop-ins and sshd_config\""
check r3.0.client1.pam '^pamtester: /' run client1 "rpm -q sssd sssd-krb5 pamtester krb5-workstation | sed 's/^/rpm: /'; command -v pamtester | sed 's/^/pamtester: /'; id alice | sed 's/^/id: /'; systemctl is-active sssd | sed 's/^/sssd: /'; sudo klist -c FILE:/tmp/krb5cc_0 2>&1 | head -4; ls /tmp | grep krb5cc || true; echo 'pamtester ready'"
checklast r3.0.client1.alice '^id: uid=10001\(alice\)'
checklast r3.0.client1.sssd '^sssd: active$'
check r3.0.stage-pt '^staged$' hostin "lib/ptydrive.py" "$LABQ ssh client1 -- 'install -d -m 0700 ~/field && cat > ~/field/ptydrive.py && chmod 0700 ~/field/ptydrive.py && echo staged'" < "$FIELD_LIB/ptydrive.py"

# ---------------------------------------------------------------- 1. client2's sshd: the kit's own server half
section "1. client2's sshd: the $KN kit's own server half ($KN-remote-setup.sh --sshd), with what the lab needs around it, as R3-MIT section 1"
note "1a. the harness exception first (R3-MIT's block): the kit's drop-in turns public keys off and allows only group admins; lab.sh reaches client2 as user lab with a key from the host bridge $NET.1. A Match block at the very end of sshd_config keeps that one door."
check r3.1a.match-block '^sshd -t ok$' run client2 'printf "%s\n" "" "# kerber-lab harness (full pass hold C, R3): the lab'"'"'s own management login only." "# The '"$KN"' kit'"'"'s 49-'"$KN"'.conf turns public keys off and allows group admins only;" "# harness/field/lab.sh reaches this VM as lab, with a key, from the host bridge '"$NET"'.1." "Match User lab Address '"$NET"'.1" "	PubkeyAuthentication yes" "	AllowGroups lab wheel" | sudo tee -a /etc/ssh/sshd_config >/dev/null && sudo tail -n 7 /etc/ssh/sshd_config && sudo sshd -t && echo "sshd -t ok" && sudo sha256sum /etc/ssh/sshd_config'
note "1b. the fleet's AllowGroups admins is an LDAP group; client2 has no SSSD (alice and bob are R4's local stubs), so a local group admins with both stands in for it (R3-MIT)"
check r3.1b.admins '^admins:x:[0-9]+:alice,bob$|^admins:x:[0-9]+:bob,alice$' run client2 'getent group admins >/dev/null || sudo groupadd admins; sudo usermod -aG admins alice && sudo usermod -aG admins bob && getent group admins && id alice && id bob'
note "1c. RA's GSSAPI drop-in (the kit's three lines, same values) is parked out of sshd_config.d so that the kit's own file is the only source of these settings (R3-MIT)"
check r3.1c.park 'parked-ok' run client2 'if [ -e /etc/ssh/sshd_config.d/49-kerber-ra-gssapi.conf ]; then sudo mkdir -p /etc/ssh/kerber-lab-parked && sudo mv /etc/ssh/sshd_config.d/49-kerber-ra-gssapi.conf /etc/ssh/kerber-lab-parked/ && echo "moved the RA drop-in"; else echo "(no RA drop-in on this client2)"; fi; sudo ls -la /etc/ssh/sshd_config.d/; echo parked-ok'
note "1d. the kit's lab copy (R3-MIT's kit/, byte for byte; the three SSO site values in lib/$KN-common.sh are the lab's, kit/twin.diff) at /var/opt/kit on client2, then the kit's own entry point: sudo ./$KN-remote-setup.sh --sshd (ssh, no TTY)"
check r3.1d.kit-sha '^1fdb19a8be463ce8e7c47a0aa1f01f540e0ca3927aec8ca0ff2485f33262fbac  '"$KN"'-remote-setup\.sh$' runin client2 "tar of kit/{$KN-remote-setup.sh,lib/*.sh}" "sudo mkdir -p /var/opt/kit && sudo tar -C /var/opt/kit --no-same-owner -xf - && sudo chmod 0755 /var/opt/kit/$KN-remote-setup.sh && cd /var/opt/kit && sha256sum $KN-remote-setup.sh lib/*.sh" < <(tar -C "$FIELD_KIT_DIR" -cf - "$KN-remote-setup.sh" "lib/$KN-apps.sh" "lib/$KN-browsers.sh" "lib/$KN-common.sh")
checklast r3.1d.kit-common '^c4754529f4eadde7765d59f2b44e76d35d03e0b367715152779ed528ec306a7a  lib/'"$KN"'-common\.sh$'
kdcmark kit
run client2 'cd /var/opt/kit && sudo ./'"$KN"'-remote-setup.sh --sshd; echo "kit exit status: $?"'
checklast r3.1d.kit-conf '^\[OK\] /etc/ssh/sshd_config\.d/49-'"$KN"'\.conf \(GSSAPI only, AllowGroups admins, no password/pubkey/root\) — sshd -t clean$'
checklast r3.1d.kit-running '^\[OK\] sshd\.service is running$'
checklast r3.1d.kit-port '^\[OK\] listening on port 22$'
checklast r3.1d.kit-keytab '^\[OK\] host/client2\.kerber\.test is in /etc/krb5\.keytab — GSSAPI can answer$'
checklast r3.1d.kit-validate-fqdn '^\[FAIL\] GSSAPI ssh REFUSED as client2\.kerber\.test — remote access does not work by that name$'
checklast r3.1d.kit-validate-short '^\[FAIL\] GSSAPI ssh REFUSED as client2 — remote access does not work by that name$'
checklast r3.1d.kit-exit '^kit exit status: 1$'
note "R3-MIT kit finding 1, reproduced on both stages: --sshd run with sudo validates as root, who is not in admins and has PermitRootLogin no, so its trailing validate reports FAIL and exits 1 on a healthy machine"
kdcsince kit "$NETRX\\.22"
checklast r3.1d.kit-kdc-pair "ISSUE: authtime [0-9]+, $ISSUE_ETYPES, host/client2\\.kerber\\.test@$R for host/client2(\\.kerber\\.test)?@$R\$"
check r3.1e.sha-49 '^c5ce290bf2ed52321c4c6d955e91dff254c0423e14206e3855ce694cd243ce97  /etc/ssh/sshd_config\.d/49-'"$KN"'\.conf$' run client2 'sudo sha256sum /etc/ssh/sshd_config.d/49-'"$KN"'.conf; sudo grep -v "^#" /etc/ssh/sshd_config.d/49-'"$KN"'.conf | grep -v "^\s*$"; systemctl is-active sshd; systemctl is-enabled sshd'
check r3.1e.sshd-T '^allowgroups admins$' run client2 'sudo sshd -T | grep -E "^(gssapi|kerberos|pubkeyauth|passwordauth|kbdinteractive|allowgroups|allowusers|usepam|loglevel|permitrootlogin|authenticationmethods|maxauthtries|x11forwarding|allowtcpforwarding|allowagentforwarding|logingracetime|maxsessions|clientalive)" | sort'
checklast r3.1e.gssapi '^gssapiauthentication yes$'
checklast r3.1e.cleanup '^gssapicleanupcredentials yes$'
checklast r3.1e.strict '^gssapistrictacceptorcheck no$'
checklast r3.1e.keyex '^gssapikeyexchange no$'
checklast r3.1e.nopubkey '^pubkeyauthentication no$'
checklast r3.1e.nopass '^passwordauthentication no$'
checklast r3.1e.noroot '^permitrootlogin no$'
checklast r3.1e.kuserok '^kerberosusekuserok yes$'
check r3.1e.door '^pubkeyauthentication yes$' run client2 'echo "== -C user=lab,addr='"$NET"'.1,host=host"; sudo sshd -T -C user=lab,addr='"$NET"'.1,host=host | grep -E "^(pubkeyauthentication|allowgroups|gssapiauthentication)"; echo "== -C user=alice,addr='"$NET"'.21,host=client1.kerber.test"; sudo sshd -T -C user=alice,addr='"$NET"'.21,host=client1.kerber.test | grep -E "^(pubkeyauthentication|allowgroups|gssapiauthentication)"'
check r3.1e.harness-login '^harness login ok$' host "$LABQ ssh client2 -- 'echo harness login ok; id -un'"

section "2. Test-only instrumentation on client2 (removed at the end), as R3-MIT: sshd LogLevel VERBOSE (a single refused attempt is logged) and KRB5_TRACE for sshd (the acceptor's own view of which keytab entry decrypts the ticket)"
check r3.2.instrument '^loglevel VERBOSE$' run client2 "printf '%s\n' '# R3 (full pass) test-only (removed at the end): log refused attempts too' 'LogLevel VERBOSE' | sudo install -m 0600 -o root -g root /dev/stdin /etc/ssh/sshd_config.d/30-r3-loglevel.conf && sudo mkdir -p /etc/systemd/system/sshd.service.d && printf '%s\n' '# R3 (full pass) test-only (removed at the end)' '[Service]' 'Environment=KRB5_TRACE=/var/tmp/r3-sshd-krb5.trace' | sudo tee /etc/systemd/system/sshd.service.d/r3-krb5trace.conf >/dev/null && sudo systemctl daemon-reload && sudo sshd -t && sudo systemctl restart sshd && systemctl is-active sshd && sudo sshd -T | grep -E '^loglevel' && systemctl show sshd -p Environment"
checklast r3.2.trace-env '^Environment=.*KRB5_TRACE=/var/tmp/r3-sshd-krb5\.trace'
check r3.2.harness-login-after '^harness login ok after restart$' host "$LABQ ssh client2 -- 'echo harness login ok after restart'"

# ---------------------------------------------------------------- 3. alice's login on client1
section "3. alice logs in on client1 through SSSD (pam_sss -> krb5_child -> the KDC), headless on a pty: FILE:/tmp/krb5cc_10001 (sssd-login PROOF 2b; the hand records used SDDM)"
PT=\$HOME/field/ptydrive.py
PAM="$PT --secrets 1 --timeout 60 --rule Password:=0 -- sudo pamtester -v login alice"
# SSSD must be online (an offline SSSD would answer from its cached password and issue no ticket): restart it, destroy any old cache
run client1 "sudo -u alice -H kdestroy -c FILE:/tmp/krb5cc_10001 2>/dev/null; sudo rm -f /tmp/krb5cc_10001; sudo systemctl restart sssd; for i in \$(seq 1 30); do id alice > /dev/null 2>&1 && break; sleep 2; done; id alice; systemctl is-active sssd; d=\$(sudo sssctl domain-list 2>/dev/null | grep -v -x implicit_files | head -1); echo \"sssd domain: \${d:-unknown}\"; for i in \$(seq 1 30); do sudo sssctl domain-status \"\$d\" -o 2>/dev/null | grep -q 'Online status: Online' && break; sleep 2; done; sudo sssctl domain-status \"\$d\" -o 2>&1 | head -4"
kdcmark login
check r3.3.login '^pamtester: sucessfully opened a session$' runin client1 "alice's password ($ALICE)" "$PAM authenticate open_session; echo \"pamtester rc=\$?\"" < <(once "$ALICE")
checklast r3.3.login-auth '^pamtester: successfully authenticated$'
checklast r3.3.login-rc '^pamtester rc=0$'
check r3.3.cache '^-rw-------\. 1 alice alice [a-z_]+:object_r:user_tmp_t:s0 [0-9]+ .* /tmp/krb5cc_10001$' run client1 "sudo ls -lZ --time-style=full-iso /tmp/krb5cc_10001; sudo klist -f -e -c FILE:/tmp/krb5cc_10001; sudo journalctl --since -3min --no-pager -o short-iso | grep -E 'pam_sss\\(login' | tail -n 3"
observelast r3.3.cache-bytes 'user_tmp_t:s0 [0-9]+'
checklast r3.3.pam_sss 'pam_sss\(login:auth\): authentication success; .*user=alice$'
tktcheck r3.3.tgt '^krbtgt/' ': 86(399|400) s life, 60(4799|4800) s renewable, flags FRIA$'
kdcsince login "$NETRX\\.21: .*alice@$R"
checklast r3.3.kdc-preauth "AS_REQ $E2 $NETRX\\.21: NEEDED_PREAUTH: alice@$R for krbtgt/$R@$R, Additional pre-authentication required\$"
checklast r3.3.kdc-issue "AS_REQ $E2 $NETRX\\.21: ISSUE: authtime [0-9]+, $ISSUE_ETYPES, alice@$R for krbtgt/$R@$R\$"

# ---------------------------------------------------------------- captures
note "captures (R3-MIT's filters; a host filter keeps every IP fragment; kdc: this run's two clients, ports 88/464/749 plus every non-first fragment)"
scapstart p1-client1 client1 enp1s0 'host '"$NET"'.10 or (host '"$NET"'.22 and port 22)'
scapstart p1-client2 client2 enp1s0 'host '"$NET"'.10 or (host '"$NET"'.21 and port 22)'
scapstart p1-kdc kdc any '(host '"$NET"'.21 or host '"$NET"'.22) and ((port 88 or port 464 or port 749) or (ip[6:2] & 0x1fff != 0))'

# ---------------------------------------------------------------- 4. Proof 1
section "4. Proof 1: ssh with gssapi-with-mic only (BatchMode; publickey, password and keyboard-interactive off; the kit's own client options from tools/fleet-status.sh plus PreferredAuthentications), as alice from client1, to the FQDN and to the short name; client-side KRB5_TRACE in a file alice owns"
run client1 "sudo rm -f /var/home/alice/.ssh/known_hosts /var/tmp/r3-*.trace; true"
run client2 'sudo truncate -s 0 /var/tmp/r3-sshd-krb5.trace 2>/dev/null; sudo ls -laZ /var/tmp/r3-sshd-krb5.trace 2>&1'
kdcmark t1
check r3.4a.fqdn-auth '^Authenticated to client2\.kerber\.test \(\['"$NETRX"'\.22\]:22\) using "gssapi-with-mic"\.$' run client1 "sudo rm -f /var/tmp/r3-ssh-fqdn.trace; sudo -u alice -H env KRB5_TRACE=/var/tmp/r3-ssh-fqdn.trace ssh -v $OPTS client2.kerber.test \"echo REMOTE: \\\$(id) on \\\$(hostname); echo REMOTE KRB5CCNAME=\\\${KRB5CCNAME:-unset}\" 2>&1 | grep -E \"^REMOTE|Authentications that can continue|Next authentication method|Authenticated to|Delegating|Permission denied|Connecting to|Server host key|Local version|Remote protocol|Warning: Permanently\"; echo \"ssh rc=\${PIPESTATUS[0]}\"; echo \"--- client trace (KRB5_TRACE of ssh as alice):\"; sudo cat /var/tmp/r3-ssh-fqdn.trace | sed -E \"s/^\\[[0-9]+\\] [0-9.]+: //\""
checklast r3.4a.fqdn-methods '^debug1: Authentications that can continue: gssapi-keyex,gssapi-with-mic$'
checklast r3.4a.fqdn-remote '^REMOTE: uid=10001\(alice\) gid=10001\(alice\) groups=10001\(alice\),[0-9]+\(admins\) .* on client2\.kerber\.test$'
checklast r3.4a.fqdn-ccname '^REMOTE KRB5CCNAME=unset$'
checklast r3.4a.fqdn-rc '^ssh rc=0$'
checklast r3.4a.trace-asks-fqdn-key "^Requesting tickets for host/client2\\.kerber\\.test@$R, referrals on\$"
checklast r3.4a.trace-tgs-ok '^TGS request result: 0/Success$'
checklast r3.4a.trace-fast "^Encoding request body and padata into FAST request\$"
observelast r3.4a.trace-tgs-req-bytes '^Sending request \([0-9]+ bytes\) to KERBER.TEST' 1
observelast r3.4a.trace-tgs-rep-bytes 'Received answer \([0-9]+ bytes\) from stream' 1
checklast r3.4a.trace-tcp '^Initiating TCP connection to stream '"$NETRX"'\.10:88$'
run client1 "sudo rm -f /var/tmp/r3-ssh-fqdn2.trace; sudo -u alice -H env KRB5_TRACE=/var/tmp/r3-ssh-fqdn2.trace ssh -v $OPTS client2.kerber.test \"echo REMOTE: \\\$(id -un) on \\\$(hostname)\" 2>&1 | grep -E \"^REMOTE|Authentications that can continue|Next authentication method|Authenticated to|Permission denied\"; echo \"ssh rc=\${PIPESTATUS[0]}\"; echo \"--- client trace (KRB5_TRACE of ssh as alice):\"; sudo cat /var/tmp/r3-ssh-fqdn2.trace | sed -E \"s/^\\[[0-9]+\\] [0-9.]+: //\""
checklast r3.4a.fqdn2-auth '^Authenticated to client2\.kerber\.test \(\['"$NETRX"'\.22\]:22\) using "gssapi-with-mic"\.$'
checklast r3.4a.fqdn2-cached "^Retrieving alice@$R -> host/client2\\.kerber\\.test@$R from FILE:/tmp/krb5cc_10001 with result: 0/Success\$"
check r3.4b.short-auth '^Authenticated to client2 \(\['"$NETRX"'\.22\]:22\) using "gssapi-with-mic"\.$' run client1 "sudo rm -f /var/tmp/r3-ssh-short.trace; sudo -u alice -H env KRB5_TRACE=/var/tmp/r3-ssh-short.trace ssh -v $OPTS client2 \"echo REMOTE: \\\$(id -un) on \\\$(hostname)\" 2>&1 | grep -E \"^REMOTE|Connecting to|Authentications that can continue|Next authentication method|Authenticated to|Permission denied|Warning: Permanently\"; echo \"ssh rc=\${PIPESTATUS[0]}\"; echo \"--- client trace (KRB5_TRACE of ssh as alice):\"; sudo cat /var/tmp/r3-ssh-short.trace | sed -E \"s/^\\[[0-9]+\\] [0-9.]+: //\"; echo \"--- her cache now, and the ticket kvno from the cache (kvno uses the cached ticket):\"; sudo klist -f -e -c FILE:/tmp/krb5cc_10001 | tail -n +4; sudo -u alice -H kvno host/client2.kerber.test"
checklast r3.4b.short-rc '^ssh rc=0$'
checklast r3.4b.short-asks-fqdn "^Getting credentials alice@$R -> host/client2\\.kerber\\.test@$R using ccache FILE:/tmp/krb5cc_10001\$"
checklast r3.4b.kvno3 "^host/client2\\.kerber\\.test@$R: kvno = 3\$"
checklast r3.4b.ticket-flags '^\s+renew until [0-9/]+ [0-9:]+, Flags: FRAT$'
kdcsince t1 "$NETRX\\.2[12]"
countlast r3.4b.kdc-one-tgs "TGS_REQ .* $NETRX\\.21: ISSUE: .* alice@$R for host/client2\\.kerber\\.test@$R\$" 1
checklast r3.4b.kdc-tgs-line "TGS_REQ $E2 $NETRX\\.21: ISSUE: authtime [0-9]+, $ISSUE_ETYPES, alice@$R for host/client2\\.kerber\\.test@$R\$"

section "4b. The acceptor's side (client2): sshd's journal and sshd-session's KRB5_TRACE"
check r3.4d.sshd-journal '^.* Accepted gssapi-with-mic for alice from '"$NETRX"'\.21 port [0-9]+ ssh2: alice@KERBER\.TEST$' run client2 "sudo journalctl -u sshd --since \"$T0\" --no-pager -o short-iso-precise | grep -v 'from $NET.1 ' | grep -v 'for lab from\\|user lab\\|lab(uid=1000)'"
checklast r3.4d.postponed '^.* Postponed gssapi-with-mic for alice from '"$NETRX"'\.21 port [0-9]+ ssh2 \[preauth\]$'
checklast r3.4d.authorized '^.* Authorized to alice, krb5 principal alice@KERBER\.TEST \(ssh_gssapi_krb5_cmdok\)$'
countlast r3.4d.three-logins '^.* Accepted gssapi-with-mic for alice from '"$NETRX"'\.21 port [0-9]+ ssh2: alice@KERBER\.TEST$' 3
check r3.4d.acceptor-trace '^Decrypted AP-REQ with server principal host/client2\.kerber\.test@KERBER\.TEST: aes256-cts' run client2 "sudo ls -laZ /var/tmp/r3-sshd-krb5.trace; sudo wc -l /var/tmp/r3-sshd-krb5.trace; sudo sed -E \"s/^\\[[0-9]+\\] [0-9.]+: //\" /var/tmp/r3-sshd-krb5.trace | grep -v -E \"^(Retrieving|Sending|Received|Resolving|Initiating|Terminating)\" | head -40"
countlast r3.4d.acceptor-decrypts '^Decrypted AP-REQ with server principal host/client2\.kerber\.test@KERBER\.TEST: aes256-cts' 3
observelast r3.4d.acceptor-trace-size '^[0-9]+ /var/tmp/r3-sshd-krb5.trace$'

section "4c. Test-only variation: the short name with Fedora's stock name settings (dns_canonicalize_hostname = fallback, qualify_shortname = \"\"), so that the short host/client2 key is exercised too"
kdcmark t1c
run client1 "sed 's/^\\[libdefaults\\]\$/[libdefaults]\\n    dns_canonicalize_hostname = fallback\\n    qualify_shortname = \"\"/' /etc/krb5.conf | sudo install -m 0644 /dev/stdin /var/tmp/r3-krb5-stocknames.conf && head -4 /var/tmp/r3-krb5-stocknames.conf && sudo rm -f /var/tmp/r3-ssh-short-stock.trace && sudo -u alice -H env KRB5_CONFIG=/var/tmp/r3-krb5-stocknames.conf KRB5_TRACE=/var/tmp/r3-ssh-short-stock.trace ssh -v $OPTS client2 \"echo REMOTE: \\\$(id -un) on \\\$(hostname)\" 2>&1 | grep -E \"^REMOTE|Authenticated to|Permission denied\"; echo \"ssh rc=\${PIPESTATUS[0]}\"; echo \"--- client trace:\"; sudo sed -E \"s/^\\[[0-9]+\\] [0-9.]+: //\" /var/tmp/r3-ssh-short-stock.trace | grep -E \"ccselect|Getting credentials|Requesting tickets|TGS request result|Received creds|Retrieving alice@KERBER.TEST -> host|Creating authenticator|Sending request|Received answer|Initiating\" | head -16; sudo -u alice -H env KRB5_CONFIG=/var/tmp/r3-krb5-stocknames.conf kvno host/client2"
checklast r3.4c.stock-auth '^Authenticated to client2 \(\['"$NETRX"'\.22\]:22\) using "gssapi-with-mic"\.$'
checklast r3.4c.stock-asks-short "^Requesting tickets for host/client2@$R, referrals on\$"
checklast r3.4c.stock-kvno2 "^host/client2@$R: kvno = 2\$"
check r3.4c.stock-acceptor '^Decrypted AP-REQ with server principal host/client2@KERBER\.TEST: aes256-cts' run client2 'sudo sed -E "s/^\[[0-9]+\] [0-9.]+: //" /var/tmp/r3-sshd-krb5.trace | grep -E "Decrypted AP-REQ|AP-REQ ticket" | tail -n 2'
kdcsince t1c "$NETRX\\.2[12]"
checklast r3.4c.stock-kdc-line "TGS_REQ $E2 $NETRX\\.21: ISSUE: authtime [0-9]+, $ISSUE_ETYPES, alice@$R for host/client2@$R\$"

# ---------------------------------------------------------------- 5. Proof 2: delegation
section "5. Proof 2: delegation (ssh -K = GSSAPIDelegateCredentials yes; the kit sets no ssh client options, Fedora's default is no delegation): alice's forwarded TGT on client2"
kdcmark t2
check r3.5.deleg 'Delegating credentials$' run client1 "sudo rm -f /var/tmp/r3-ssh-deleg.trace; sudo -u alice -H env KRB5_TRACE=/var/tmp/r3-ssh-deleg.trace ssh -v -K $OPTS client2.kerber.test \"echo REMOTE KRB5CCNAME=\\\${KRB5CCNAME:-unset}; klist -f -e; ls -laZ /tmp | grep krb5cc; ls -la /run/user/10001 2>/dev/null | head -5\" 2>&1 | grep -E \"Delegating|Authenticated to|^REMOTE|Ticket cache|Default principal|krbtgt|renew until|Etype|krb5cc|ssh rc\"; echo \"ssh rc=\${PIPESTATUS[0]}\"; echo \"--- client trace (forwarding):\"; sudo sed -E \"s/^\\[[0-9]+\\] [0-9.]+: //\" /var/tmp/r3-ssh-deleg.trace | grep -E \"Getting credentials|Retrieving alice@KERBER.TEST -> krbtgt|etypes requested|Sending request|Received answer|Creating authenticator\""
checklast r3.5.authenticated '^Authenticated to client2\.kerber\.test \(\['"$NETRX"'\.22\]:22\) using "gssapi-with-mic"\.$'
checklast r3.5.ccname '^REMOTE KRB5CCNAME=unset$'
checklast r3.5.far-cache '^Ticket cache: FILE:/tmp/krb5cc_10001$'
checklast r3.5.far-flags '^\s+renew until [0-9/]+ [0-9:]+, Flags: FfRAT$'
checklast r3.5.one-etype '^etypes requested in TGS request: aes256-cts$'
checklast r3.5.far-file '^-rw-------\. +1 alice +alice .* krb5cc_10001$'
observelast r3.5.far-cache-bytes ' [0-9]+ [A-Z][a-z]{2} +[0-9]+ [0-9:]+ krb5cc_10001'
kdcsince t2 "$NETRX\\.2[12]"
checklast r3.5.kdc-forwarded "TGS_REQ \\(1 etypes \\{aes256-cts-hmac-sha1-96\\(18\\)\\}\\) $NETRX\\.21: ISSUE: authtime [0-9]+, $ISSUE_ETYPES, alice@$R for krbtgt/$R@$R\$"
check r3.5.cleanup-gone '^\(no /tmp/krb5cc_10001 on client2 after the session closed' run client2 'sudo ls -la /tmp | grep krb5cc_10001 || echo "(no /tmp/krb5cc_10001 on client2 after the session closed: GSSAPICleanupCredentials yes)"; sudo journalctl -u sshd --since "-40s" --no-pager -o short-iso-precise | grep -E "alice|gssapi"'
checklast r3.5.far-accepted '^.* Accepted gssapi-with-mic for alice from '"$NETRX"'\.21 port [0-9]+ ssh2: alice@KERBER\.TEST$'
note "5b (Konsole, an interactive ssh -K in alice's Plasma session) is not run: it needs SDDM and a desktop driven by direct virsh, which the host route rule forbids; the non-interactive ssh -K above is the same GSSAPI delegation"

# ---------------------------------------------------------------- 6. Proof 3: refusals
section "6. Proof 3: refusals (gssapi-with-mic only, BatchMode), with sshd at LogLevel VERBOSE (test-only) so that a single refused attempt is logged"
kdcmark t3
note "6a. a ticketless user: bob (a directory user on client1 with no login, so no /tmp/krb5cc_10002) as bob@client2.kerber.test"
check r3.6a.noticket '^No Kerberos credentials available \(default cache: FILE:/tmp/krb5cc_10002\)$' run client1 "sudo rm -f /tmp/krb5cc_10002; sudo ls -la /tmp/krb5cc_10002 2>&1; sudo -u bob -H env KRB5_TRACE=/dev/null ssh -v $OPTS_NK bob@client2.kerber.test true 2>&1 | grep -E \"Authentications that can continue|Next authentication|No Kerberos credentials|Unspecified GSS|No credentials|Permission denied|Authenticated|ticket|cache\"; echo \"ssh rc=\${PIPESTATUS[0]}\""
checklast r3.6a.denied '^bob@client2\.kerber\.test: Permission denied \(gssapi-keyex,gssapi-with-mic\)\.$'
checklast r3.6a.rc '^ssh rc=255$'
note "6b. a principal not mapped to the local account: alice (alice@KERBER.TEST, a valid ticket) as bob@client2.kerber.test (bob is in admins, so AllowGroups lets the attempt through; no ~bob/.k5login, auth_to_local maps alice@KERBER.TEST to alice)"
check r3.6b.no-k5login '^ls: cannot access ./home/bob/\.k5login.: No such file or directory$' run client2 'sudo ls -la /home/bob/.k5login 2>&1; true'
check r3.6b.denied '^bob@client2\.kerber\.test: Permission denied \(gssapi-keyex,gssapi-with-mic\)\.$' run client1 "sudo -u alice -H ssh -v $OPTS_NK bob@client2.kerber.test true 2>&1 | grep -E \"Authentications that can continue|Next authentication|Unspecified GSS|Permission denied|Authenticated|Delegating\"; echo \"ssh rc=\${PIPESTATUS[0]}\""
checklast r3.6b.rc '^ssh rc=255$'
note "6c. the kit's AllowGroups admins: alice as lab@client2.kerber.test from client1 (lab is not in admins; the harness exception covers only $NET.1)"
check r3.6c.denied '^lab@client2\.kerber\.test: Permission denied \(gssapi-keyex,gssapi-with-mic\)\.$' run client1 "sudo -u alice -H ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o PasswordAuthentication=no -o PubkeyAuthentication=no -o KbdInteractiveAuthentication=no -o GSSAPIAuthentication=yes -o PreferredAuthentications=gssapi-with-mic lab@client2.kerber.test true; echo \"ssh rc=\$?\""
checklast r3.6c.rc '^ssh rc=255$'
check r3.6.sshd-lines '^.* Connection closed by authenticating user bob '"$NETRX"'\.21 port [0-9]+ \[preauth\]$' run client2 "sudo journalctl -u sshd --since \"-90s\" --no-pager -o short-iso-precise | grep -v -E 'from $NET.1 |Accepted key ED25519|lab\\(uid=1000\\)|User child is on pid|SHA1 in signatures'"
checklast r3.6.srclimit '^.* srclimit_penalise: ipv4: new '"$NETRX"'\.21/32 deferred penalty of 1 seconds for penalty: connections without attempting authentication$'
checklast r3.6.postponed-bob '^.* Postponed gssapi-with-mic for bob from '"$NETRX"'\.21 port [0-9]+ ssh2 \[preauth\]$'
checklast r3.6.failed-bob '^.* Failed gssapi-with-mic for bob from '"$NETRX"'\.21 port [0-9]+ ssh2$'
checklast r3.6.allowgroups '^.* User lab from '"$NETRX"'\.21 not allowed because none of user.s groups are listed in AllowGroups$'
checklast r3.6.invalid-lab '^.* Connection closed by invalid user lab '"$NETRX"'\.21 port [0-9]+ \[preauth\]$'
kdcsince t3 "$NETRX\\.2[12]"
countlast r3.6.no-kdc-line "(alice|bob)@$R" 0
check r3.6.acceptor-total '^6$' run client2 'sudo grep -c "Decrypted AP-REQ" /var/tmp/r3-sshd-krb5.trace'
note "the acceptor decrypted 6 AP-REQs for 6 GSSAPI logins in the whole stage (FQDN, FQDN again, short name, short name with the stock name settings, -K, alice as bob); R3-MIT's 7 included the Konsole -K login (skipped here); the user lab is refused by AllowGroups before any GSS context. The acceptor never talks to the KDC"

# ---------------------------------------------------------------- captures stop
section "captures: stop, keep without AS exchanges, decode"
scapstop p1-client1 client1
scapstop p1-client2 client2
scapstop p1-kdc kdc
scapkeep p1-client1 "R3 $STAGE: client1 enp1s0, host kdc or (host client2 and port 22)"
scapkeep p1-client2 "R3 $STAGE: client2 enp1s0, host kdc or (host client1 and port 22)"
scapkeep p1-kdc "R3 $STAGE: kdc -i any, both clients, 88/464/749 plus every non-first IP fragment"
host "for n in p1-client1 p1-client2 p1-kdc; do f=$(printf '%q' "$REC_DIR")/pcap/\$n.pcap; echo \"\$n ip-fragments: \$(tshark -r \$f -Y 'ip.flags.mf == 1 || ip.frag_offset > 0' 2>/dev/null | wc -l) kerberos-frames: \$(tshark -r \$f -Y kerberos 2>/dev/null | wc -l)\"; done; f=$(printf '%q' "$REC_DIR")/pcap/p1-kdc.pcap; echo \"kdc TGS-REQ over TCP: \$(tshark -r \$f -Y 'kerberos.msg_type == 12 && tcp' 2>/dev/null | wc -l)\"; echo \"kdc TGS-REQ over UDP: \$(tshark -r \$f -Y 'kerberos.msg_type == 12 && udp' 2>/dev/null | wc -l)\""
checklast r3.cap.client1-no-fragments '^p1-client1 ip-fragments: 0 kerberos-frames: [1-9]'
checklast r3.cap.client2-no-fragments '^p1-client2 ip-fragments: 0 kerberos-frames: '
checklast r3.cap.kdc-no-fragments '^p1-kdc ip-fragments: 0 kerberos-frames: [1-9]'
checklast r3.cap.kdc-tgs-tcp '^kdc TGS-REQ over TCP: [1-9]'
observelast r3.cap.kdc-tgs-udp 'kdc TGS-REQ over UDP: [0-9]+'

# ---------------------------------------------------------------- 6b. logs and SELinux
section "6b. The traces and logs into the record (read-only), then SELinux on both clients (ausearch --input-logs, with a positive control)"
host "for t in r3-ssh-fqdn r3-ssh-fqdn2 r3-ssh-short r3-ssh-short-stock r3-ssh-deleg; do $LABQ ssh client1 -- sudo cat /var/tmp/\$t.trace < /dev/null | python3 -B $(printf '%q' "$FIELD_LIB/redact.py") | sed -E 's/(encrypted )[0-9A-Fa-f]{16,}/\\1<redacted>/g' > $(printf '%q' "$REC_DIR")/logs/client1-alice-ssh.\$t.krb5-trace.txt; done; $LABQ ssh client2 -- sudo cat /var/tmp/r3-sshd-krb5.trace < /dev/null | python3 -B $(printf '%q' "$FIELD_LIB/redact.py") > $(printf '%q' "$REC_DIR")/logs/client2-sshd-session.krb5-trace.txt; $LABQ ssh client2 -- sudo journalctl -u sshd --since \"'$T0'\" --no-pager -o short-iso-precise < /dev/null | python3 -B $(printf '%q' "$FIELD_LIB/redact.py") > $(printf '%q' "$REC_DIR")/logs/client2-sshd.journal.txt; wc -l $(printf '%q' "$REC_DIR")/logs/*"
read -r -d '' AVC_CLIENT2_AVC <<-'EOS' || true
	echo "== AVC / USER_AVC / SELINUX_ERR since boot:"; sudo ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts boot 2>&1 | tail -n 5; echo "AVC rc=${PIPESTATUS[0]}"; echo "== positive control, USER_LOGIN since boot (sshd logins):"; sudo ausearch --input-logs -m USER_LOGIN -ts boot 2>/dev/null | grep -c "type=USER_LOGIN"; getenforce
EOS
check r3.6b.client2-avc '^AVC rc=1$|^AVC rc=0$' run client2 "$AVC_CLIENT2_AVC"
checklast r3.6b.client2-enforcing '^Enforcing$'
read -r -d '' AVC_CLIENT2_AVC_LIST <<-'EOS' || true
	n=$(sudo ausearch --input-logs -m AVC -ts boot 2>/dev/null | grep -c "^type=AVC"); echo "$n AVC records since boot (client2)"; sudo ausearch --input-logs -m AVC -ts boot 2>/dev/null | grep -E "^type=AVC" | sed -E "s/msg=audit\(([0-9]+)\.[0-9]+:[0-9]+\)/t=\1/; s/ ino=[0-9]+//; s/ pid=[0-9]+//" | awk "{ \$2=\"\"; print }" | sort | uniq -c | head -20; echo "== permissive? sshd_session_t:"; sudo semanage permissive -l 2>/dev/null | grep -E "sshd|Builtin|Custom"; rpm -q selinux-policy-targeted
EOS
check r3.6b.client2-avc-list 'AVC records' run client2 "$AVC_CLIENT2_AVC_LIST"
observelast r3.6b.client2-avc-count '^[0-9]+ AVC records since boot'
read -r -d '' AVC_CLIENT1_AVC <<-'EOS' || true
	echo "== AVC / USER_AVC / SELINUX_ERR since boot:"; sudo ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts boot 2>&1 | tail -n 5; echo "AVC rc=${PIPESTATUS[0]}"; echo "== positive control, USER_START since boot:"; sudo ausearch --input-logs -m USER_START -ts boot 2>/dev/null | grep -c "type=USER_START"; getenforce
EOS
check r3.6b.client1-avc '^AVC rc=1$|^AVC rc=0$' run client1 "$AVC_CLIENT1_AVC"
checklast r3.6b.client1-enforcing '^Enforcing$'
read -r -d '' AVC_CLIENT1_AVC_LIST <<-'EOS' || true
	n=$(sudo ausearch --input-logs -m AVC -ts boot 2>/dev/null | grep -c "^type=AVC"); echo "$n AVC records since boot (client1)"; sudo ausearch --input-logs -m AVC -ts boot 2>/dev/null | grep -E "^type=AVC" | sed -E "s/msg=audit\(([0-9]+)\.[0-9]+:[0-9]+\)/t=\1/; s/ ino=[0-9]+//; s/ pid=[0-9]+//" | awk "{ \$2=\"\"; print }" | sort | uniq -c | head -20
EOS
check r3.6b.client1-avc-list 'AVC records' run client1 "$AVC_CLIENT1_AVC_LIST"
observelast r3.6b.client1-avc-count '^[0-9]+ AVC records since boot'

# ---------------------------------------------------------------- 7. undo the test-only changes and the stage's sshd changes
section "7. Undo: the test-only instrumentation, the kit's sshd drop-in, the harness exception, the group admins and the parked RA drop-in (client2's sshd back to the f4-mit state, so that RA1 finds it), alice's cache and the traces on client1"
run client1 "sudo rm -f /var/tmp/r3-ssh-fqdn.trace /var/tmp/r3-ssh-fqdn2.trace /var/tmp/r3-ssh-short.trace /var/tmp/r3-ssh-short-stock.trace /var/tmp/r3-ssh-deleg.trace /var/tmp/r3-krb5-stocknames.conf; ls /var/tmp | grep r3- || echo '(no r3 files left in /var/tmp on client1)'; sudo -u alice -H kdestroy -c FILE:/tmp/krb5cc_10001 2>&1; sudo rm -f /var/home/alice/.ssh/known_hosts; ls /tmp | grep krb5cc || true"
check r3.7.restore-sshd '^restored-ok$' run client2 "test -d $HV/r3-save/sshd_config.d && test -f $HV/r3-save/sshd_config && sudo rm -f /etc/systemd/system/sshd.service.d/r3-krb5trace.conf /var/tmp/r3-sshd-krb5.trace && sudo rmdir /etc/systemd/system/sshd.service.d 2>/dev/null; sudo systemctl daemon-reload; sudo rm -rf /etc/ssh/sshd_config.d && sudo cp -a $HV/r3-save/sshd_config.d /etc/ssh/sshd_config.d && sudo cp -a $HV/r3-save/sshd_config /etc/ssh/sshd_config && sudo rm -rf /etc/ssh/kerber-lab-parked && { [ -e $HV/r3-save/admins-existed ] || sudo groupdel admins; }; sudo sshd -t && sudo systemctl restart sshd && systemctl is-active sshd && sudo sh -c 'sha256sum /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*' > $HV/r3-after.sha256 && diff $HV/r3-save.sha256 $HV/r3-after.sha256 && echo restored-ok"
check r3.7.harness-login '^harness login ok$' host "$LABQ ssh client2 -- 'echo harness login ok; id -un'"
check r3.7.gssapi-back '^gssapiauthentication yes$' run client2 'sudo sshd -T | grep -E "^(gssapiauthentication|allowgroups|permitrootlogin|pubkeyauthentication|loglevel)"; getent group admins || echo "(no group admins)"; systemctl show sshd -p Environment'
run client2 "sudo find /var/lib/gssproxy/clients -mindepth 1 -delete 2>/dev/null; ls /var/tmp | grep r3- || echo '(no r3 files in /var/tmp on client2)'; ls /tmp | grep krb5cc || echo '(no caches on client2)'"
run client1 "sudo rm -rf ~/field; true"

finish
