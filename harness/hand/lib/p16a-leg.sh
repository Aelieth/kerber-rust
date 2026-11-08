#!/bin/sh
# P16a field leg: on the lab kdc, a dictionary word is refused by kadmin.local and by kadmind
# (through MIT's kadmin) with the dictionary refusal, on whichever KDC the kdc VM runs (MIT or ours).
# admin/admin's password is stdin's first line, never on a command line:
#   { cat ~/kerber-lab/secrets/<realm>.admin-admin.password; cat leg.sh; } |
#     harness/field/lab.sh ssh kdc -- 'IFS= read -r ADMIN_PW; export ADMIN_PW; exec sh -s'
# What it adds (a two-word dictionary file, its dict_file line, a policy on bob) it removes, then restarts
# kadmin. The last line is PASS or FAIL.
set -u
REALM=KERBER.TEST; CONF=/var/kerberos/krb5kdc/kdc.conf; DICT=/var/kerberos/krb5kdc/p16a-field.dict
say() { printf '== %s\n' "$*"; }
say "kdc: $(rpm -q krb5-server 2>/dev/null || echo 'krb5-server not installed (kerber-rust)'); $(command -v kadmind)"
sudo grep -q 'p16a-field.dict' "$CONF" && { echo "FAIL: a dict_file line from an earlier run is still there"; exit 1; }
printf 'zebra\napple\n' | sudo tee "$DICT" >/dev/null; sudo chmod 0644 "$DICT"; sudo restorecon "$DICT" 2>/dev/null
sudo sed -i "/^[[:space:]]*${REALM}[[:space:]]*=[[:space:]]*{/a\\        dict_file = $DICT" "$CONF"
sudo grep -n 'dict_file' "$CONF"
sudo kadmin.local -r "$REALM" -q "addpol p16adict" </dev/null
sudo kadmin.local -r "$REALM" -q "modprinc -policy p16adict bob" </dev/null
sudo systemctl restart kadmin; sleep 2; systemctl is-active kadmin
say "kadmin.local cpw -pw <dictionary word> bob"
LOCAL=$(sudo kadmin.local -r "$REALM" -q "cpw -pw zebra bob" </dev/null 2>&1); echo "$LOCAL"
say "MIT kadmin (to kadmind) cpw -pw <dictionary word> bob"
REMOTE=$(printf '%s\n' "$ADMIN_PW" | kadmin -r "$REALM" -p "admin/admin@$REALM" -q "cpw -pw zebra bob" 2>&1); echo "$REMOTE"
say "undo"
sudo kadmin.local -r "$REALM" -q "modprinc -clearpolicy bob" </dev/null
sudo kadmin.local -r "$REALM" -q "delpol -force p16adict" </dev/null
sudo sed -i '/p16a-field.dict/d' "$CONF"; sudo rm -f "$DICT"; sudo systemctl restart kadmin; sleep 2; systemctl is-active kadmin
sudo grep -c 'p16a-field.dict' "$CONF"
ok=1
echo "$LOCAL" | grep -q 'Password is in the password dictionary' || { echo "kadmin.local did not refuse with the dictionary text"; ok=0; }
echo "$REMOTE" | grep -q 'Password is in the password dictionary' || { echo "kadmind did not refuse with the dictionary text"; ok=0; }
[ $ok = 1 ] && echo PASS || echo FAIL
