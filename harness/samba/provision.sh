#!/bin/sh
# Build-time provisioning of the Samba AD DC (realm AD.KERBER.TEST).
# Runs offline against the local sam.ldb — no samba daemon needed here.
# Baseline steps (provision + accounts + SPN) are must-pass; the AES-only and
# delegation refinements are logged-best-effort (A2/A4 tune them further).
set -eu

: "${SAMBA_REALM:?realm required}"
: "${SAMBA_DOMAIN:?domain required}"
: "${SAMBA_ADMIN_PASSWORD:?admin pw required}"
: "${SAMBA_KBRUSER_PASSWORD:?kbruser pw required}"
: "${SAMBA_KBRSVC_PASSWORD:?kbrsvc pw required}"

HOST_SHORT=dc1
SVC_SPN="host/svc.ad.kerber.test"
SAM_LDB=/var/lib/samba/private/sam.ldb

# Base DN from the realm: AD.KERBER.TEST -> DC=ad,DC=kerber,DC=test
BASE_DN="DC=$(echo "$SAMBA_REALM" | tr 'A-Z.' 'a-z ' | sed 's/ /,DC=/g')"

echo "[provision] realm=$SAMBA_REALM domain=$SAMBA_DOMAIN host=$HOST_SHORT base=$BASE_DN"

# A stock Ubuntu smb.conf blocks a clean AD DC provision.
rm -f /etc/samba/smb.conf

echo "[provision] samba-tool domain provision (function level 2016)"
# --function-level raises the domain/forest FL; the DC's own FL is governed by the
# `ad dc functional level` smb.conf parameter (Samba >= 4.19) — set both to 2016
# or provision refuses (DC FL 2008_R2 < domain FL 2016).
# posix:eadb redirects NT ACL / extended-attribute storage into a tdb instead of
# native security.* xattrs, which need CAP_SYS_ADMIN that `docker build` lacks
# (otherwise sysvol ACLs fail NT_STATUS_ACCESS_DENIED). It persists into the
# generated smb.conf, so runtime samba uses the same store.
samba-tool domain provision \
    --realm="$SAMBA_REALM" \
    --domain="$SAMBA_DOMAIN" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --host-name="$HOST_SHORT" \
    --function-level=2016 \
    --option="ad dc functional level = 2016" \
    --option="posix:eadb = /var/lib/samba/private/eadb.tdb" \
    --adminpass="$SAMBA_ADMIN_PASSWORD"

# Write an explicit container /etc/krb5.conf pointing at the local KDC. Samba's
# generated krb5.conf uses dns_lookup_kdc=true (SRV), which fails inside the
# container unless resolv.conf points at Samba's internal DNS — so pin
# kdc=127.0.0.1 to make in-container kinit/kvno work directly. (The gate writes
# its own equivalent profile, so it does not depend on this.)
cat > /etc/krb5.conf <<KRB5EOF
[libdefaults]
    default_realm = $SAMBA_REALM
    dns_lookup_realm = false
    dns_lookup_kdc = false
    rdns = false
[realms]
    $SAMBA_REALM = {
        kdc = 127.0.0.1
        kpasswd_server = 127.0.0.1
    }
KRB5EOF

echo "[provision] create test accounts"
samba-tool user create kbruser "$SAMBA_KBRUSER_PASSWORD"
samba-tool user create kbrsvc  "$SAMBA_KBRSVC_PASSWORD"

echo "[provision] register SPN $SVC_SPN on kbrsvc"
samba-tool spn add "$SVC_SPN" kbrsvc

# AES-only (0x18 = 24) to match the hardened Windows lab. Logged-best-effort.
echo "[provision] set msDS-SupportedEncryptionTypes=24 (AES-only)"
for u in kbruser kbrsvc; do
    printf 'dn: CN=%s,CN=Users,%s\nchangetype: modify\nreplace: msDS-SupportedEncryptionTypes\nmsDS-SupportedEncryptionTypes: 24\n' \
        "$u" "$BASE_DN" > "/tmp/enc-$u.ldif"
    if ldbmodify -H "$SAM_LDB" "/tmp/enc-$u.ldif"; then
        echo "[provision]   enctypes set for $u"
    else
        echo "[provision]   WARNING: enctype set failed for $u (non-fatal for A3 baseline)" >&2
    fi
done

# Constrained delegation for the S4U work (A4). Logged-best-effort.
echo "[provision] enable protocol transition + allowed-to-delegate on kbrsvc"
samba-tool delegation for-any-protocol kbrsvc on \
    && echo "[provision]   protocol transition on" \
    || echo "[provision]   WARNING: for-any-protocol failed (non-fatal for A3 baseline)" >&2
samba-tool delegation add-service kbrsvc "$SVC_SPN" \
    && echo "[provision]   allowed-to-delegate-to $SVC_SPN" \
    || echo "[provision]   WARNING: add-service failed (non-fatal for A3 baseline)" >&2

echo "[provision] verify accounts exist offline"
ldbsearch -H "$SAM_LDB" -b "$BASE_DN" "(|(sAMAccountName=kbruser)(sAMAccountName=kbrsvc))" sAMAccountName objectSid \
    | grep -E 'sAMAccountName|objectSid' || true

echo "[provision] domain object SID (for the record):"
ldbsearch -H "$SAM_LDB" -b "$BASE_DN" -s base objectSid | grep -i objectSid || true

echo "[provision] done"
