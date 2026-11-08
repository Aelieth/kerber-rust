#!/bin/sh
# session.sh: a normal MIT kadmin session (the VM's krb5-workstation) against the realm's kadmind, as admin/admin; run on a client VM.
#   { cat ~/kerber-lab/secrets/mit-realm.admin-admin.password; cat session.sh; } | lab.sh ssh clientN -- 'IFS= read -r ADMIN_PW; export ADMIN_PW; exec sh -s PROBE'
# The password is stdin's first line, never on a command line; the principal $1 is made and deleted here and nothing else is touched.
REALM=KERBER.TEST
P=${1:?probe principal}
K() { printf '%s\n' "$ADMIN_PW" | kadmin -r "$REALM" -p "admin/admin@$REALM" -q "$1" 2>&1; }
say() { printf '==== %s\n' "$*"; }
say "kadmin version: $(rpm -q krb5-workstation)"
say "getprinc kadmin/admin"; K 'getprinc kadmin/admin'
say "addprinc -randkey $P"; K "addprinc -randkey $P"
say "getprinc $P"; K "getprinc $P"
say "modprinc -maxlife -maxrenewlife +requires_preauth $P"; K "modprinc -maxlife \"2 hours\" -maxrenewlife \"1 day\" +requires_preauth $P"
say "getprinc $P"; K "getprinc $P"
say "cpw -randkey $P"; K "cpw -randkey $P"
say "getprinc $P"; K "getprinc $P"
say "listprincs $P"; K "listprincs $P"
say "getprivs"; K 'getprivs'
say "delprinc -force $P"; K "delprinc -force $P"
say "getprinc $P (deleted)"; K "getprinc $P"
say "wrong password"; printf 'not-the-password\n' | kadmin -r "$REALM" -p "admin/admin@$REALM" -q 'getprinc kadmin/admin' 2>&1
echo "SESSION_DONE"
