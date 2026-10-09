#!/usr/bin/env bash
# harness/field/scenarios/services.sh --leg mit|rust: S2's two server proofs on the services VM against the leg's KDC,
# as upgrade.sh left it on kdc (hand records f-S2-services, MIT, and f-S2-rust). From throwaway probe containers on
# services (their own network namespace: a separate client host as far as the servers can tell):
#   (A) NFS-Ganesha (lib/nfs-probe.sh): alice mounts /users sec=krb5p, /media and /data sec=krb5i, writes and reads;
#       her files are 10001:10001 on the client and on the server's disk; root (host/services, the machine
#       credential) reads /data/fleet and is squashed in alice's home; ticketless bob is refused;
#   (B) Keycloak (lib/spnego-probe.sh): the kit's check_spnego (lib/check_spnego.lab.sh): 401 + Negotiate, then 302
#       with code= and a mutual token; Keycloak's LOGIN events.
# Also graded: services' three keytabs equal the KDC's keys; the KDC's ISSUE lines for nfs/ and HTTP/. Recorded, not
# graded: the probes' TGS transport and PREAUTH_REQUIRED padata (services.expect). Not checked here: S2's decode of
# the RPCSEC_GSS INIT replies and call counts (no full pcap decoding). Run by run.sh (REC_DIR, TMPDIR, FIELD_SHA).
# vms: services kdc
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-} ${2:-}" in
    "--leg mit" | "--leg rust") LEG=$2 ;;
    *) echo "usage: services.sh --leg mit|rust" >&2; exit 1 ;;
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
PODMAN="sudo podman run --rm -i"
cleanup() {
    timeout -k 5 60 "$LAB" ssh services -- 'sudo podman rm -f s2-nfs-probe s2-spnego-probe > /dev/null 2>&1; sudo systemctl stop "field-pcap-*" 2>/dev/null; sudo rm -f /var/tmp/field-*.pcap; true' < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# probein nfs|spnego: a probe's stdin: its secrets and inputs as shell assignments, then the probe itself.
probein() {
    printf 'ALICE_PW=%q\n' "$(< "$SECRETS/$ALICE")"
    if [ "$1" = nfs ]; then
        printf 'TAG=%q\n' "$TAG"
        cat "$FIELD_LIB/nfs-probe.sh"
    else
        printf 'LAB_CA_PEM=%q\nCHECK_SH=%q\n' "$(< "$SECRETS/$LAB_CA")" "$(< "$FIELD_LIB/check_spnego.lab.sh")"
        cat "$FIELD_LIB/spnego-probe.sh"
    fi
}

section "services --leg $LEG: S2's proofs (A) NFS and (B) Keycloak SPNEGO, from probe containers on services, against the $LEG KDC"
section "1. kdc as upgrade.sh left it; services at the leg's baseline, serving; its keytabs against the KDC"
kdcis
resetvm services
servicesready
check probe.kit.check_spnego '^90e8642680b8f7fd89e913bc5f081f7e012180b87ba750a24188a758d3c4bf2e  -$' host \
    "tail -n +2 $(printf '%q' "$FIELD_LIB/check_spnego.lab.sh") | sha256sum"
ktcheck services /var/data/nvme-raid/AppData/nfs-klldap-host/keytab/krb5.keytab nfs
ktcheck services /var/lib/keycloak/keytab/keycloak-http.keytab http
ktcheck services /var/lib/s2-probe/krb5.keytab probe
run services "sudo podman images --format '{{.Repository}}:{{.Tag}} {{.Digest}}' | grep -E 's2-nfs-probe|nfs-klldap-host|keycloak|nginx|lldap'; sudo podman ps --format '{{.Names}} {{.Status}}'"

section "2. (A) NFS: S2's probe, privileged, as host/services (root) and alice (uid 10001), bob without a ticket"
kdcmark s2
W0=$(date +%s)
capstart services s2 '(port 88) or (ip[6:2] & 0x1fff != 0)'
check nfs.probe '^PROBE STAMP=[0-9]{8}T[0-9]{6}Z$' hostin "alice's password ($ALICE), the file prefix, then lib/nfs-probe.sh" \
    "$LABQ ssh services -- '$PODMAN --privileged --name s2-nfs-probe --hostname services.kerber.test --add-host services.kerber.test:192.168.177.11 -v /var/lib/s2-probe/krb5.keytab:/etc/krb5.keytab:ro localhost/s2-nfs-probe:f43 bash -s'" < <(probein nfs)
checklast nfs.kinit.host '^kinit -k rc=0$'
checklast nfs.kinit.alice '^kinit alice rc=0$'
checklast nfs.mount.users '^mount /users krb5p rc=0$'
checklast nfs.mount.media '^mount /media krb5i rc=0$'
checklast nfs.mount.data '^mount /data krb5i rc=0$'
checklast nfs.krb5p '^services\.kerber\.test:/users /mnt/users nfs4 .*sec=krb5p'
checklast nfs.krb5i '^services\.kerber\.test:/media /mnt/media nfs4 .*sec=krb5i'
checklast nfs.alice.write.krb5p '^write rc=0$'
checklast nfs.alice.write.media '^write /media rc=0$'
checklast nfs.alice.write.scratch '^write /data/scratch rc=0$'
countlast nfs.alice.read '^read rc=0$' 3
checklast nfs.alice.owner.krb5p "^/mnt/users/alice/$TAG-s2-krb5p-[0-9TZ]+\\.txt uid=10001 gid=10001 "
checklast nfs.alice.owner.media "^/mnt/media/$TAG-alice-s2-krb5i-[0-9TZ]+\\.txt uid=10001 gid=10001 "
checklast nfs.alice.ticket "Ticket server: nfs/services\\.kerber\\.test@$R\$"
checklast nfs.root.fleet '^root read /data/fleet rc=0$'
checklast nfs.root.squashed "^touch: cannot touch '/mnt/users/alice/root-was-here': Permission denied$"
checklast nfs.bob.refused "^ls: cannot access '/mnt/media': Permission denied$"
checklast nfs.umount '^umount rc=0$'
STAMP=$(sed -n 's/^PROBE STAMP=//p' "$LAST_OUT" | head -n 1)
F="/var/data/nvme-raid/users/alice/$TAG-s2-krb5p-$STAMP.txt /var/data/nvme-raid/media/$TAG-alice-s2-krb5i-$STAMP.txt /var/data/nvme-raid/data/scratch/$TAG-alice-s2-krb5i-$STAMP.txt"
check nfs.server.owner '^on the server: 3 of 3 owned 10001:10001$' run services \
    "sudo stat -c '%u:%g %a size=%s %n' $F; echo \"on the server: \$(sudo stat -c '%u:%g' $F | grep -c '^10001:10001\$') of 3 owned 10001:10001\""

section "3. (B) Keycloak: S2's probe (own netns, the lab CA trusted) runs the kit's check_spnego as alice, then the two requests by hand"
check spnego.probe '^check_spnego rc=0$' hostin "alice's password ($ALICE), the lab CA (public), lib/check_spnego.lab.sh, then lib/spnego-probe.sh" \
    "$LABQ ssh services -- '$PODMAN --name s2-spnego-probe localhost/s2-nfs-probe:f43 bash -s'" < <(probein spnego)
checklast spnego.kinit '^kinit rc=0$'
checklast spnego.ok '^\[OK\] SPNEGO handshake: Keycloak accepted the ticket and issued an OIDC code$'
checklast spnego.401 '^HTTP/1\.1 401 Unauthorized'
checklast spnego.challenge '^[Ww][Ww][Ww]-[Aa]uthenticate: Negotiate$'
checklast spnego.302 '^HTTP/1\.1 302 Found'
checklast spnego.code '^[Ll]ocation: https://nextcloud\.kerber\.test/apps/user_oidc/code\?.*code=<REDACTED:oidc-code>'
checklast spnego.mutual '^[Ww][Ww][Ww]-[Aa]uthenticate: Negotiate <REDACTED:[a-z-]+>$'
checklast spnego.ticket "Ticket server: HTTP/services\\.kerber\\.test@$R\$"
capstop services s2

section "4. the KDC's lines for the probes (from services' address), Keycloak's events, what the capture shows"
kdcsince s2 '192\.168\.177\.11'
checklast log.tgs.nfs.host "TGS_REQ \\([0-9]+ etypes \\{[^}]*\\}\\) 192\\.168\\.177\\.11: ISSUE: authtime [0-9]+, $I3, host/services\\.kerber\\.test@$R for nfs/services\\.kerber\\.test@$R\$"
checklast log.tgs.nfs.alice "TGS_REQ \\([0-9]+ etypes \\{[^}]*\\}\\) 192\\.168\\.177\\.11: ISSUE: authtime [0-9]+, $I3, alice@$R for nfs/services\\.kerber\\.test@$R\$"
checklast log.tgs.http.alice "TGS_REQ \\([0-9]+ etypes \\{[^}]*\\}\\) 192\\.168\\.177\\.11: ISSUE: authtime [0-9]+, $I3, alice@$R for HTTP/services\\.kerber\\.test@$R\$"
check kc.events '^count: LOGIN alice nextcloud [0-9.]+ = [1-9][0-9]*$' hostin "Keycloak's keyadmin password ($LAB_SECRET_KEYCLOAK_ADMIN)" \
    "bash $(printf '%q' "$FIELD_LIB/kc-events.sh") $W0" < "$SECRETS/$LAB_SECRET_KEYCLOAK_ADMIN"
P=$(printf '%q' "$REC_DIR/pcap/s2.pcap")
observe obs.tgs.transport 'TGS-REQ over [a-z ]+' host "printf 'TGS-REQ over %s\n' \"\$(tshark -r $P -Y 'kerberos.msg_type == 12' -T fields -e frame.protocols 2>/dev/null | grep -oE ':(udp|tcp):' | tr -d : | LC_ALL=C sort -u | paste -sd' ' -)\""
observe obs.preauth.padata 'PREAUTH_REQUIRED padata [0-9,]+' host "printf 'PREAUTH_REQUIRED padata %s\n' \"\$(tshark -r $P -Y 'kerberos.error_code == 25' -T fields -e kerberos.padata_type 2>/dev/null | LC_ALL=C sort -u | paste -sd' ' -)\""

section "5. evidence: Ganesha's and Keycloak's own logs for the window, services' journal and deployed public files"
run services "sudo podman exec nfs-klldap-host sh -c 'tail -n 30 /var/log/ganesha.log' | cut -c1-300; sudo podman logs --since $W0 keycloak 2>&1 | tail -n 20 | cut -c1-300"
MIN=$(( ($(date +%s) - T0) / 60 + 2 ))
host "COLLECT_MINUTES=$MIN $LABQ collect services $(printf '%q' "$REC_DIR/collect") /etc/containers/systemd /etc/keycloak/krb5.conf /etc/keycloak-proxy/conf.d"
if [ -f "$REC_DIR/collect/services/journal.txt" ]; then _redact < "$REC_DIR/collect/services/journal.txt" > "$STATE/j" && mv "$STATE/j" "$REC_DIR/collect/services/journal.txt"; fi
finish
