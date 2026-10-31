#!/usr/bin/env bash
# harness/field/lib/acl-variant.sh: the svc/setup ACL-settle helper, promoted from f-L2-rust's record copy.
# Sourced by a scenario after rec.sh / baseline.env / leg.sh, with the globals R (the realm), DOMAIN and
# KDC_HOST set, and the leg's svc/setup keytab already staged on client2 at ~/field/svc-setup.keytab.
#
# acl_variant <letters> <tag>: write kadm5.acl giving svc/setup <letters> on host/* and nfs/*, restart
# kadmind, then run the kit's svc/setup add + ktadd on host/<tag> and nfs/<tag> from client2 and check the
# outcome the letters dictate. The ACL letters: a = add (create), c = change-password (randkey), i = get
# (the new kvno); ktadd needs both c and i. The refusal texts are MIT's, settled live and reproduced by ours;
# F4d's compare.py grades the two legs against each other, so both legs run the same variants.
acl_variant() {
    local L=$1 T=$2 p pf ere
    section "acl.$L: svc/setup '$L' on host/* and nfs/* (target $T)"
    check "acl.$L.kadmin" '^active$' runin kdc "kadm5.acl $L" \
        "sudo tee /var/kerberos/krb5kdc/kadm5.acl >/dev/null && sudo systemctl restart kadmin && systemctl is-active kadmin" \
        <<< "$(printf 'admin/admin@%s\t*\nsvc/setup@%s\t%s\thost/*@%s\nsvc/setup@%s\t%s\tnfs/*@%s\n' "$R" "$R" "$L" "$R" "$R" "$L" "$R")"
    local K="kadmin -p svc/setup@$R -k -t \$HOME/field/svc-setup.keytab -s $KDC_HOST"
    for p in host nfs; do
        pf="$p/$T.$DOMAIN@$R"
        # addprinc: succeeds iff the letters carry 'a', else the "add" refusal.
        if [[ $L == *a* ]]; then ere="Principal \"$p/$T\\.$DOMAIN@$R\" created\\."
        else ere="add_principal: Operation requires \`\`add'' privilege while creating \"$p/$T\\.$DOMAIN@$R\"\\."; fi
        check "acl.$L.$p.addprinc" "$ere" run client2 "$K -q 'addprinc -randkey $pf' 2>&1"
        # ktadd: needs c (randkey) and i (get) once the principal exists; with no 'a' it never got created.
        if [[ $L != *a* ]]; then ere="kadmin: Principal $p/$T\\.$DOMAIN@$R does not exist\\."
        elif [[ $L == *c* && $L == *i* ]]; then ere="Entry for principal $p/$T\\.$DOMAIN@$R with kvno 2, .*added to keytab"
        elif [[ $L != *c* ]]; then ere="Operation requires \`\`change-password'' privilege while changing $p/$T\\.$DOMAIN@$R's key"
        else ere="Operation requires \`\`get'' privilege while changing $p/$T\\.$DOMAIN@$R's key"; fi
        check "acl.$L.$p.ktadd" "$ere" run client2 "rm -f \$HOME/field/$p-$T.keytab; $K -q \"ktadd -k \$HOME/field/$p-$T.keytab $pf\" 2>&1"
    done
}
