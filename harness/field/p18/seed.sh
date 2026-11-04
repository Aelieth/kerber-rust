#!/bin/bash
# P18 seed.sh (klldap, root, `sudo bash -s`): one scratch realm P18.TEST made by MIT 1.22.2
# (Fedora's kdb5_util / kadmin.local), dumped at N = 10, 100, 1000 and 5000 principals.
# Both legs load these same dumps with their own kdb5_util and the same stash, so each N is the
# same realm, keys included, on both sides.
#  - The master password and the fillers' passwords are drawn here per run (python secrets) and
#    go straight into the pipe; they are never written to a file, printed or recorded.
#  - admin/admin's key goes to /srv/p18/seed/admin.keytab (the kadmin client's keytab for every
#    session); it is the same key in every dump.
#  - Fillers alternate host/fNNNNN.p18.test (-randkey) and fNNNNN (-pw), one aes256 key each.
set -euo pipefail
B=/srv/p18
export KRB5_CONFIG=$B/krb5.conf KRB5_KDC_PROFILE=$B/kdc.conf
D=$B/run/kdc
rm -rf "$D" "$B"/seed/*
mkdir -p "$D" "$B/seed"
cp $B/kadm5.acl "$D/kadm5.acl"
python3 -c 'import secrets; p = secrets.token_urlsafe(24); print(p); print(p)' \
    | /usr/bin/kdb5_util -r P18.TEST create -s > "$B/tmp/seed-create.out" 2>&1
grep -v -i 'password' "$B/tmp/seed-create.out" || true
/usr/bin/kadmin.local -r P18.TEST -q 'addprinc -randkey admin/admin' 2>&1 | grep -v '^Authenticating' || true
/usr/bin/kadmin.local -r P18.TEST -q "ktadd -k $B/seed/admin.keytab admin/admin" 2>&1 | grep -v '^Authenticating' || true
cp "$D/.k5.P18.TEST" "$B/seed/stash"
chmod 0600 "$B/seed/stash" "$B/seed/admin.keytab"
count() { /usr/bin/kadmin.local -r P18.TEST -q listprincs 2>/dev/null | grep -c '@P18.TEST$'; }
have=$(count)
echo "base realm: $have principals: $(/usr/bin/kadmin.local -r P18.TEST -q listprincs 2>/dev/null | grep '@P18.TEST$' | paste -sd' ')"
next=0
for N in 10 100 1000 5000; do
    want=$((N - have))
    t0=$(date +%s.%N)
    python3 - "$next" "$want" <<'EOF' | /usr/bin/kadmin.local -r P18.TEST > "$B/tmp/seed-fill.out" 2>&1
import secrets, sys
start, n = int(sys.argv[1]), int(sys.argv[2])
for i in range(start, start + n):
    if i % 2 == 0:
        print(f"addprinc -randkey host/f{i:05d}.p18.test")
    else:
        print(f"addprinc -pw {secrets.token_urlsafe(18)} f{i:05d}")
EOF
    t1=$(date +%s.%N)
    created=$(grep -c 'created\.$' "$B/tmp/seed-fill.out" || true)
    next=$((next + want)); have=$(count)
    /usr/bin/kdb5_util -r P18.TEST dump "$B/seed/N$N.dump"
    printf 'N=%s: +%s created by kadmin.local in %s s (%s ms each); listprincs %s; dump %s B, %s princ lines, sha256 %s\n' \
        "$N" "$created" "$(awk -v a="$t0" -v b="$t1" 'BEGIN { printf "%.1f", b - a }')" \
        "$(awk -v a="$t0" -v b="$t1" -v n="$want" 'BEGIN { printf "%.1f", n ? (b - a) * 1000 / n : 0 }')" \
        "$have" "$(stat -c %s "$B/seed/N$N.dump")" "$(grep -c '^princ' "$B/seed/N$N.dump")" \
        "$(sha256sum < "$B/seed/N$N.dump" | cut -c1-16)"
done
rm -f "$B/tmp/seed-fill.out" "$B/tmp/seed-create.out"
head -1 "$B/seed/N10.dump"
ls -la "$B/seed"
