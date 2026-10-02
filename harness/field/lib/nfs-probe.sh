#!/bin/bash
# nfs-probe.sh — runs INSIDE the throwaway privileged probe container on `services`
# (S2's probe; scenarios/services.sh). stdin carries `ALICE_PW=<value>` (from
# ~/kerber-lab/secrets, never on argv) and `TAG=<prefix of the test files>`, followed by
# this script. The client side is configured exactly as the satomlin kit's
# satomlin-ldap-setup-v5.sh configures a fleet client (§6 configure_rpc_gssd,
# prime_nfs_creds, the idmapd.conf block), with the kit's host/realm values swapped:
# KDC kerber.test, NFS_SERVER services.kerber.test, REALM KERBER.TEST.
#   machine credential: host/services.kerber.test (keytab bind-mounted at /etc/krb5.keytab)
#   user:               alice@KERBER.TEST, uid 10001 (a local passwd stub here; SSSD on a client)
set -u
SERVER=services.kerber.test
REALM=KERBER.TEST
TAG=${TAG:-probe}
step() { printf '\n--- %s\n' "$*"; }

step "probe container"
echo "hostname=$(cat /proc/sys/kernel/hostname)"; grep PRETTY_NAME /etc/os-release; uname -r
# The probe IS services in its client role, so its own name must not resolve to itself
# (podman's /etc/hosts entry and glibc's myhostname both answer with the probe's address);
# the run passes --add-host services.kerber.test:192.168.177.11, the name's DNS answer.
getent ahostsv4 "$SERVER" | head -1; getent ahostsv4 kdc.kerber.test | head -1
rpm -q nfs-utils gssproxy krb5-workstation | tr '\n' ' '; echo
ip -4 -o addr show scope global | awk '{print $2, $4}'

step "client config (the kit's files, lab values)"
cat > /etc/krb5.conf <<EOF
[libdefaults]
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    dns_canonicalize_hostname = fallback
    qualify_shortname = ""
    default_realm = $REALM
    default_ccache_name = FILE:/tmp/krb5cc_%{uid}

[realms]
$REALM = {
    kdc = kdc.kerber.test
    admin_server = kdc.kerber.test
    kpasswd_server = kdc.kerber.test
}

[domain_realm]
.kerber.test = $REALM
kerber.test = $REALM
EOF
mkdir -p /etc/nfs.conf.d /etc/gssproxy /var/lib/gssproxy/clients
printf '[gssd]\nuse-machine-creds=0\n' > /etc/nfs.conf.d/nfs-klldap.conf
cat > /etc/idmapd.conf <<EOF
[General]
Domain = $REALM
Local-Realms = $REALM
[Mapping]
Nobody-User = nobody
Nobody-Group = nobody
[Translation]
Method = nsswitch
GSS-Methods = nsswitch
EOF
cat > /etc/gssproxy/99-network-fs-clients.conf <<'EOG'
[service/network-fs-clients]
  mechs = krb5
  cred_store = keytab:/etc/krb5.keytab
  cred_store = ccache:FILE:/tmp/krb5cc_%U
  cred_store = ccache:FILE:/var/lib/gssproxy/clients/krb5cc_%U
  cred_store = ccache:KEYRING:persistent:%U
  cred_store = client_keytab:/var/lib/gssproxy/clients/%U.keytab
  cred_usage = initiate
  allow_any_uid = yes
  trusted = yes
  euid = 0
  min_lifetime = 60
EOG
sed -i '/^\[service\/network-fs-clients\]/,/^$/d' /etc/gssproxy/gssproxy.conf 2>/dev/null || true
cat /etc/nfs.conf.d/nfs-klldap.conf
klist -k -t /etc/krb5.keytab

step "rpc_pipefs + gssproxy + rpc.gssd (GSS_USE_PROXY=yes, the kit's -d list) + rpc.idmapd"
mkdir -p /var/lib/nfs/rpc_pipefs
mountpoint -q /var/lib/nfs/rpc_pipefs || mount -t rpc_pipefs rpc_pipefs /var/lib/nfs/rpc_pipefs
gssproxy -i -d >/var/log/gssproxy.log 2>&1 &
GSSPROXY_PID=$!
sleep 1
GSS_USE_PROXY=yes rpc.gssd -f -v -d /tmp:/var/tmp:/run/user:/var/lib/gssproxy/clients >/var/log/rpc.gssd.log 2>&1 &
GSSD_PID=$!
rpc.idmapd -f >/var/log/rpc.idmapd.log 2>&1 &
IDMAPD_PID=$!
sleep 2
pgrep -a -f 'gssproxy|rpc\.(gssd|idmapd)'

step "machine credential prime (the kit's prime_nfs_creds: host/ -> /tmp/krb5cc_0 -> gssproxy clients/)"
env KRB5CCNAME=FILE:/tmp/krb5cc_0 kinit -k -t /etc/krb5.keytab "host/${SERVER}@${REALM}"; echo "kinit -k rc=$?"
install -o root -g root -m 600 /tmp/krb5cc_0 /var/lib/gssproxy/clients/krb5cc_0
klist -c FILE:/tmp/krb5cc_0

step "alice: local passwd stub uid 10001 (SSSD supplies it on a joined client), kinit with the realm's password on stdin"
useradd -u 10001 -U -M -d /nonexistent -s /sbin/nologin alice
useradd -u 10002 -U -M -d /nonexistent -s /sbin/nologin bob
id alice; id bob
printf '%s\n' "$ALICE_PW" | runuser -u alice -- env KRB5CCNAME=FILE:/tmp/krb5cc_10001 kinit "alice@${REALM}" >/dev/null; echo "kinit alice rc=$?"
unset ALICE_PW
runuser -u alice -- klist -c FILE:/tmp/krb5cc_10001

step "mounts: /users sec=krb5p, /media and /data sec=krb5i (vers=4.2)"
mkdir -p /mnt/users /mnt/media /mnt/data
timeout 90 mount -t nfs4 -o vers=4.2,sec=krb5p "${SERVER}:/users" /mnt/users; echo "mount /users krb5p rc=$?"
timeout 90 mount -t nfs4 -o vers=4.2,sec=krb5i "${SERVER}:/media" /mnt/media; echo "mount /media krb5i rc=$?"
timeout 90 mount -t nfs4 -o vers=4.2,sec=krb5i "${SERVER}:/data" /mnt/data; echo "mount /data krb5i rc=$?"
grep ' nfs4 ' /proc/mounts
nfsstat -m 2>/dev/null

stamp=$(date -u +%Y%m%dT%H%M%SZ)
step "as alice (uid 10001, her own TGT): write, read back, stat — krb5p on /users/alice"
runuser -u alice -- sh -c "echo 'S2 krb5p write by alice $stamp' > /mnt/users/alice/$TAG-s2-krb5p-$stamp.txt" ; echo "write rc=$?"
runuser -u alice -- cat "/mnt/users/alice/$TAG-s2-krb5p-$stamp.txt"; echo "read rc=$?"
runuser -u alice -- stat -c '%n uid=%u gid=%g mode=%A' "/mnt/users/alice/$TAG-s2-krb5p-$stamp.txt"

step "as alice: krb5i on /media and /data/scratch"
runuser -u alice -- sh -c "echo 'S2 krb5i write by alice $stamp' > /mnt/media/$TAG-alice-s2-krb5i-$stamp.txt"; echo "write /media rc=$?"
runuser -u alice -- cat "/mnt/media/$TAG-alice-s2-krb5i-$stamp.txt"; echo "read rc=$?"
runuser -u alice -- stat -c '%n uid=%u gid=%g mode=%A' "/mnt/media/$TAG-alice-s2-krb5i-$stamp.txt"
runuser -u alice -- sh -c "echo 'S2 krb5i write by alice $stamp' > /mnt/data/scratch/$TAG-alice-s2-krb5i-$stamp.txt"; echo "write /data/scratch rc=$?"
runuser -u alice -- cat "/mnt/data/scratch/$TAG-alice-s2-krb5i-$stamp.txt"; echo "read rc=$?"
runuser -u alice -- klist -c FILE:/tmp/krb5cc_10001 | grep -E 'nfs/|krbtgt/'

step "root (machine credential host/, squashed): read /data/fleet; may NOT write into alice's 0700 home"
cat /mnt/data/fleet/README.txt; echo "root read /data/fleet rc=$?"
touch /mnt/users/alice/root-was-here 2>&1; echo "root write into /users/alice rc=$? (expect non-zero)"

step "bob (uid 10002) holds NO ticket: access must be refused"
runuser -u bob -- ls /mnt/media 2>&1 | head -3; echo "bob ls /media rc=${PIPESTATUS[0]} (expect non-zero)"

step "unmount, stop daemons"
umount /mnt/users /mnt/media /mnt/data; echo "umount rc=$?"
kill "$GSSD_PID" "$IDMAPD_PID" "$GSSPROXY_PID" 2>/dev/null
sleep 1
step "rpc.gssd log (tail)"; tail -40 /var/log/rpc.gssd.log
step "gssproxy log (tail)"; tail -15 /var/log/gssproxy.log
echo "PROBE STAMP=$stamp"
