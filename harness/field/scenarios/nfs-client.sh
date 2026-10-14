#!/usr/bin/env bash
# harness/field/scenarios/nfs-client.sh --leg mit|rust: client2's NFS and SPNEGO legs against the leg's KDC, as
# upgrade.sh left it on kdc (hand records f-R4-mit + f-R5-mit, MIT; f-R4 + f-R5, rust). client2's baseline is the
# kit-configured Fedora client, already joined: the kit's lab copy, rpc.gssd + gssproxy, the automounts, local alice and
# bob with the directory's numbers.
#   R4 PROOF 1: root's first touch mounts /media and /data (krb5i) and /users (krb5p) by the machine credential; root
#     is squashed, with R4's error texts. PROOF 2: alice (kinit into the kit's FILE:/tmp/krb5cc_10001) writes and reads
#     her krb5p home and the krb5i shares; 10001 on both sides. PROOF 2b: ticketless bob is refused with R4's texts.
#   R5: the kit's check_spnego (the VM's own copy) without and with a ticket, the two requests by hand, Keycloak's
#     LOGIN events from client2.
#   The KDC's lines for client2; no SELinux denial on client2 but the kit's known id_resolver one (R4 kit finding 2).
# Not here: R4 PROOF 3 (ticket expiry, a clock window), the wire decodes, client1's legs (GUI). Recorded, not graded
# (nfs-client.expect): alice's AS preauth types and AS-REP size. Run by run.sh (REC_DIR, TMPDIR, FIELD_SHA).
# vms: client2 services kdc
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: nfs-client.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_SHA:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
# shellcheck source=../baseline.env
. "$HERE/../baseline.env"
# shellcheck source=../lib/leg.sh
. "$FIELD_LIB/leg.sh"
legset ALICE
T0=$(date +%s)
TAG=f4$LEG
R=${REALM//./\\.}
I3='etypes \{rep=aes256-cts-hmac-sha1-96\(18\), tkt=aes256-cts-hmac-sha1-96\(18\), ses=aes256-cts-hmac-sha1-96\(18\)\}'
E2='\(2 etypes \{aes256-cts-hmac-sha1-96\(18\), aes128-cts-hmac-sha1-96\(17\)\}\) 192\.168\.177\.22: ISSUE: authtime [0-9]+, '
URL='https://services.kerber.test/realms/kerber.test/protocol/openid-connect/auth?client_id=nextcloud&response_type=code&scope=openid&redirect_uri=https%3A%2F%2Fnextcloud.kerber.test%2Fapps%2Fuser_oidc%2Fcode'
CURL="curl -sS --connect-timeout 5 --max-time 15"
AL="sudo -u alice -H" BO="sudo -u bob -H"
cleanup() {
    timeout -k 5 60 "$LAB" ssh client2 -- 'sudo -u alice -H kdestroy 2> /dev/null; sudo rm -rf /home/alice/field; sudo systemctl stop "field-pcap-*" 2> /dev/null; sudo rm -f /var/tmp/field-*.pcap; sudo umount -a -t nfs4 2> /dev/null; true' < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

section "nfs-client --leg $LEG: client2's R4 (NFS 4.2 krb5i / krb5p) and R5 (Keycloak SPNEGO) legs against the $LEG KDC"
section "1. kdc as upgrade.sh left it; services and client2 at the leg's baseline; client2 as the kit boots it"
kdcis
resetvm services client2
servicesready
WSTART=$(limited "$LAB" ssh client2 -- 'date "+%m/%d/%Y %H:%M:%S"' < /dev/null)
note "window start on client2's clock, local time (ausearch -ts): ${WSTART:-<none: the SELinux check fails>}"
check kit.copy '^851d8565d52fa453b2adc6f49b8faaa06d3aab271121d4098e818a9172bd2833  /var/opt/kit/network/klldap-client-setup\.sh$' run client2 \
    "sha256sum /var/opt/kit/network/klldap-client-setup.sh /var/opt/kit/check_spnego.lab.sh; id alice; id bob; rpm -q krb5-workstation nfs-utils gssproxy; grep -E 'default_ccache_name|udp_preference_limit' /etc/krb5.conf"
checklast kit.check_spnego '^90e8642680b8f7fd89e913bc5f081f7e012180b87ba750a24188a758d3c4bf2e  /var/opt/kit/check_spnego\.lab\.sh$'
checklast stub.alice '^uid=10001\(alice\) gid=10001\(alice\)'
check boot.running '^running$' run client2 "systemctl is-system-running; systemctl list-units --all --no-legend 'mnt-*.automount'; ls /run/klldap/home-present; sudo klist -c FILE:/tmp/krb5cc_0; sudo journalctl -b --no-pager -o cat -u klldap-nfs-machine-creds | tail -n 4"
countlast boot.automounts 'mnt-(users|media|data)\.automount +loaded active +waiting' 3
checklast boot.prime.tgt "^Default principal: host/client2\\.kerber\\.test@$R\$"
checklast boot.prime.kvno "nfs/services\\.kerber\\.test@$R: kvno = 2\$"
checklast boot.revive 'klldap-nfs-revive: 3 nfs automount\(s\), none failed$'

section "2. R4 PROOF 1: root touches the automount points; the machine credential mounts them; root is squashed"
kdcmark r4
W0=$(date +%s)
capstart client2 r4 'host 192.168.177.10 or host 192.168.177.11'
check root.media '^ls /mnt/media rc=0$' run client2 "sudo ls -la /mnt/media > /dev/null; echo \"ls /mnt/media rc=\$?\"; sudo ls -la /mnt/data; echo \"ls /mnt/data rc=\$?\"; findmnt -t nfs4 -o TARGET,SOURCE,FSTYPE,OPTIONS; grep -E '^device services|sec:' /proc/self/mountstats"
checklast root.data '^ls /mnt/data rc=0$'
checklast root.krb5i '^/mnt/media +services\.kerber\.test:/media +nfs4 +.*vers=4\.2,.*sec=krb5i'
checklast root.flavor.krb5i 'flavor=6,pseudoflavor=390004$'
S=$(date -u +%Y%m%dT%H%M%SZ)
X=r4-$TAG-root-client2-$S
check root.fleet '^cat rc=0$' run client2 "sudo cat /mnt/data/fleet/README.txt; echo \"cat rc=\$?\"; sudo touch /mnt/data/$X; sudo sh -c 'echo R4 root write > /mnt/data/scratch/$X.txt'; sudo sh -c 'echo R4 root write > /mnt/media/$X.txt'; sudo stat -c '%n uid=%u gid=%g' /mnt/media/$X.txt; sudo chown 10001 /mnt/media/$X.txt; sudo ls -la /mnt/users; echo \"ls /mnt/users rc=\$?\"; sudo ls -la /mnt/users/alice; sudo touch /mnt/users/alice/$X; findmnt -o TARGET,OPTIONS /mnt/users; grep -E 'sec:' /proc/self/mountstats; true"
checklast root.data.denied "^touch: cannot touch '/mnt/data/$X': Permission denied\$"
checklast root.scratch.denied "^sh: line 1: /mnt/data/scratch/$X\\.txt: Permission denied\$"
checklast root.media.denied "^sh: line 1: /mnt/media/$X\\.txt: Permission denied\$"
checklast root.media.anon "^/mnt/media/$X\\.txt uid=4294967294 gid=4294967294\$"
checklast root.chown.denied "^chown: changing ownership of '/mnt/media/$X\\.txt': Operation not permitted\$"
checklast root.users '^ls /mnt/users rc=0$'
checklast root.alice.denied "^ls: cannot open directory '/mnt/users/alice': Permission denied\$"
checklast root.krb5p '^/mnt/users +.*sec=krb5p'
checklast root.flavor.krb5p 'flavor=6,pseudoflavor=390005$'

section "3. R4 PROOF 2: alice's kinit into the kit's FILE cache; her krb5p home and the krb5i shares; the server's owners"
check alice.kinit '^kinit rc=0$' runin client2 "alice's password ($ALICE)" "$AL sh -c 'mkdir -p ~/field && KRB5_TRACE=\$HOME/field/kinit.trace kinit alice; rc=\$?; cat ~/field/kinit.trace; rm -f ~/field/kinit.trace; echo kinit rc=\$rc'; $AL klist -fe; sudo ls -laZ /tmp/krb5cc_10001" < <(once "$ALICE")
observelast obs.as.preauth 'Processing preauth types: .*'
observelast obs.as.rep.bytes 'Received answer \([0-9]+ bytes\)' 2
checklast alice.ccache '^-rw-------\. 1 alice alice [a-z_]+:object_r:user_tmp_t:s0 [0-9]+ .* /tmp/krb5cc_10001$'
tktcheck alice.tgt '^krbtgt/' ': 86(399|400) s life, 60(4799|4800) s renewable, flags FRIA$'
S2=$(date -u +%Y%m%dT%H%M%SZ)
H=r4-$TAG-krb5p-client2-$S2.txt I=alice-r4-$TAG-krb5i-client2-$S2.txt
check alice.home '^ls rc=0$' run client2 "$AL ls -la /mnt/users/alice > /dev/null; echo \"ls rc=\$?\"; $AL sh -c 'echo R4 krb5p write by alice $S2 > /mnt/users/alice/$H'; echo \"write rc=\$?\"; $AL cat /mnt/users/alice/$H; echo \"read rc=\$?\"; $AL stat -c '%n uid=%u(%U) gid=%g(%G)' /mnt/users/alice/$H; $AL ls -ln /mnt/users/alice/$H; $AL sh -c 'echo R4 krb5i write by alice $S2 > /mnt/media/$I'; echo \"write /media rc=\$?\"; $AL sh -c 'echo R4 krb5i write by alice $S2 > /mnt/data/scratch/$I'; echo \"write /data/scratch rc=\$?\"; $AL touch /mnt/data/alice-r4-$TAG-$S2; $AL ls /mnt/users/bob; $AL kvno nfs/services.kerber.test; $AL klist -f; true"
checklast alice.write '^write rc=0$'
checklast alice.read '^read rc=0$'
checklast alice.owner "/mnt/users/alice/$H uid=10001\\(alice\\) gid=10001\\(alice\\)\$"
checklast alice.owner.numeric "^-rw-r--r--\\. 1 10001 10001 [0-9]+ .*/mnt/users/alice/$H\$"
checklast alice.write.media '^write /media rc=0$'
checklast alice.write.scratch '^write /data/scratch rc=0$'
checklast alice.data.denied "^touch: cannot touch '/mnt/data/alice-r4-$TAG-$S2': Permission denied\$"
checklast alice.bob.denied "^ls: cannot open directory '/mnt/users/bob': Permission denied\$"
checklast alice.nfs.kvno "^nfs/services\\.kerber\\.test@$R: kvno = 2\$"
tktcheck alice.nfs.ticket '^nfs/services\.kerber\.test@' 'flags FRAT$'
check alice.server '^on the server: 3 of 3 owned 10001:10001$' run services \
    "F='/var/data/nvme-raid/users/alice/$H /var/data/nvme-raid/media/$I /var/data/nvme-raid/data/scratch/$I'; sudo stat -c '%u:%g %a size=%s %n' \$F; echo \"on the server: \$(sudo stat -c '%u:%g' \$F | grep -c '^10001:10001\$') of 3 owned 10001:10001\""

section "4. R4 PROOF 2b: bob holds no ticket: every access is refused"
check bob.noticket '^klist: No credentials cache found' run client2 "$BO klist 2>&1; for c in 'ls /mnt/users' 'ls /mnt/media' 'stat /mnt/data' 'cat /mnt/data/fleet/README.txt' 'touch /mnt/media/bob-r4-$TAG-x'; do echo \"--- bob: \$c\"; $BO \$c 2>&1; done; $BO bash -c 'cd /mnt/users/bob' 2>&1; true"
checklast bob.users.stale "^ls: cannot open directory '/mnt/users': Stale file handle\$"
checklast bob.media.denied "^ls: cannot access '/mnt/media': Permission denied\$"
checklast bob.stat.denied "^stat: cannot statx '/mnt/data': Permission denied\$"
checklast bob.cat.denied '^cat: /mnt/data/fleet/README\.txt: Permission denied$'
checklast bob.touch.denied "^touch: cannot touch '/mnt/media/bob-r4-$TAG-x': Permission denied\$"
checklast bob.cd.denied '^bash: line 1: cd: /mnt/users/bob: Permission denied$'

section "5. R5: the kit's check_spnego as alice, without a ticket and with one; the two requests by hand"
check r5.noticket '^check_spnego rc=0$' run client2 "$AL kdestroy; $AL klist 2>&1; $AL bash /var/opt/kit/check_spnego.lab.sh 2>&1; echo '--- plain:'; $AL $CURL -D - -o /dev/null '$URL' | tr -d '\r' | grep -i -E '^HTTP/|^www-authenticate'; echo '--- negotiate, no ticket:'; $AL $CURL --negotiate -u : -o /dev/null -w '%{http_code}\n' '$URL'"
checklast r5.skipped '^ +no Kerberos TGT — SPNEGO handshake skipped$'
checklast r5.401 '^HTTP/1\.1 401 Unauthorized$'
checklast r5.challenge '^[Ww][Ww][Ww]-[Aa]uthenticate: Negotiate$'
checklast r5.negotiate.noticket '^401$'
check r5.ok '^\[OK\] SPNEGO handshake: Keycloak accepted the ticket and issued an OIDC code$' runin client2 "alice's password ($ALICE)" "$AL kinit alice > /dev/null; echo \"kinit rc=\$?\"; $AL bash /var/opt/kit/check_spnego.lab.sh 2>&1; echo '--- negotiate:'; $AL $CURL --negotiate -u : -D - -o /dev/null -w 'check_spnego view: %{http_code} %{redirect_url}\n' '$URL' | tr -d '\r' | grep -i -E '^HTTP/|^www-authenticate|^location|^check_spnego'; $AL klist -f" < <(once "$ALICE")
checklast r5.rc '^check_spnego rc=0$'
checklast r5.302 '^HTTP/1\.1 302 Found$'
checklast r5.code '^[Ll]ocation: https://nextcloud\.kerber\.test/apps/user_oidc/code\?.*code=<REDACTED:oidc-code>$'
checklast r5.mutual '^[Ww][Ww][Ww]-[Aa]uthenticate: Negotiate <REDACTED:[a-z-]+>$'
tktcheck r5.http.ticket '^HTTP/services\.kerber\.test@' 'flags FRAT$'
check r5.events '^count: LOGIN alice nextcloud 192\.168\.177\.22 = [1-9][0-9]*$' hostin "Keycloak's keyadmin password ($LAB_SECRET_KEYCLOAK_ADMIN)" \
    "bash $(printf '%q' "$FIELD_LIB/kc-events.sh") $W0" < "$SECRETS/$LAB_SECRET_KEYCLOAK_ADMIN"
capstop client2 r4

section "6. the KDC's lines for client2; SELinux on client2 over the window"
kdcsince r4 '192\.168\.177\.22'
checklast log.as.machine "AS_REQ $E2$I3, host/client2\\.kerber\\.test@$R for krbtgt/$R@$R\$"
checklast log.as.alice "AS_REQ $E2$I3, alice@$R for krbtgt/$R@$R\$"
checklast log.tgs.nfs.alice "TGS_REQ $E2$I3, alice@$R for nfs/services\\.kerber\\.test@$R\$"
checklast log.tgs.http.alice "TGS_REQ $E2$I3, alice@$R for HTTP/services\\.kerber\\.test@$R\$"
check selinux.client2 '^denials but the kit id_resolver helper: 0$' run client2 "getenforce; d=\$(sudo ausearch --input-logs -m AVC,USER_AVC,SELINUX_ERR -ts $WSTART 2> /dev/null | grep -E '^type=(AVC|USER_AVC|SELINUX_ERR)'); printf '%s\n' \"\$d\" | cut -c1-300; echo \"denials but the kit id_resolver helper: \$(printf '%s\n' \"\$d\" | grep . | grep -vc 'comm=\"nfsidmap-client\"')\"; echo \"USER_CMD control: \$(sudo ausearch --input-logs -m USER_CMD -ts $WSTART 2> /dev/null | grep -c '^type=USER_CMD') records\""
checklast selinux.enforcing '^Enforcing$'
checklast selinux.control '^USER_CMD control: [1-9][0-9]* records$'
MIN=$(( ($(date +%s) - T0) / 60 + 2 ))
host "COLLECT_MINUTES=$MIN $LABQ collect client2 $(printf '%q' "$REC_DIR/collect") /etc/krb5.conf /etc/gssproxy/99-network-fs-clients.conf /etc/nfs.conf.d /etc/idmapd.conf /etc/fstab /etc/systemd/system/rpc-gssd.service.d"
if [ -f "$REC_DIR/collect/client2/journal.txt" ]; then _redact < "$REC_DIR/collect/client2/journal.txt" > "$STATE/j" && mv "$STATE/j" "$REC_DIR/collect/client2/journal.txt"; fi
finish
