#!/bin/bash
# spnego-probe.sh — runs INSIDE a throwaway probe container on `services` (podman's default
# bridge, its own netns: a separate client host as far as Keycloak can tell). Field runner S2.
# stdin carries a preamble from the host: ALICE_PW (the realm's password), LAB_CA_PEM (the lab CA,
# public) and CHECK_SH (the satomlin kit's helper block + check_spnego, verbatim from
# lib/satomlin-common.sh, preceded by the four SSO constants with the lab's values), then this.
set -u
step() { printf '\n--- %s\n' "$*"; }
URL='https://services.kerber.test/realms/kerber.test/protocol/openid-connect/auth?client_id=nextcloud&response_type=code&scope=openid&redirect_uri=https%3A%2F%2Fnextcloud.kerber.test%2Fapps%2Fuser_oidc%2Fcode'
scrub() {  # never let a code, a cookie value or a token out of the container
    tr -d '\r' | sed -E 's/(code=)[A-Za-z0-9._-]+/\1<REDACTED:oidc-code>/g;
        s/^([<>]? ?[Ss]et-[Cc]ookie: *[^=]+=)[^;]*/\1<REDACTED:cookie>/;
        s/^([<>]? ?[Cc]ookie: *).*/\1<REDACTED:cookie>/;
        s/([Nn]egotiate) [A-Za-z0-9+\/=]{16,}/\1 <REDACTED:spnego-token>/g'
}

step "probe container"
echo "hostname=$(cat /proc/sys/kernel/hostname)"; ip -4 -o addr show scope global | awk '{print $2, $4}'
getent ahostsv4 services.kerber.test | head -1
curl -V | grep -i '^Features' | tr ' ' '\n' | grep -i -E 'GSS-API|SPNEGO|Kerberos' | tr '\n' ' '; echo

step "trust the lab CA system-wide (what a kit client does; check_spnego never uses -k)"
printf '%s\n' "$LAB_CA_PEM" > /etc/pki/ca-trust/source/anchors/kerber-lab-ca.crt
update-ca-trust && trust list --filter=ca-anchors | grep -B1 -A2 'kerber-lab' | grep -E 'label|type' | head -2

step "client krb5.conf (the kit's: FILE ccache, rdns off)"
cat > /etc/krb5.conf <<'EOF'
[libdefaults]
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    dns_canonicalize_hostname = fallback
    qualify_shortname = ""
    default_realm = KERBER.TEST
    default_ccache_name = FILE:/tmp/krb5cc_%{uid}

[realms]
KERBER.TEST = {
    kdc = kdc.kerber.test
    admin_server = kdc.kerber.test
    kpasswd_server = kdc.kerber.test
}

[domain_realm]
.kerber.test = KERBER.TEST
kerber.test = KERBER.TEST
EOF

step "alice (uid 10001) logs in: kinit with the realm's password on stdin"
useradd -u 10001 -U -m -s /bin/bash alice
printf '%s\n' "$ALICE_PW" | runuser -u alice -- kinit alice@KERBER.TEST >/dev/null; echo "kinit rc=$?"
unset ALICE_PW
runuser -u alice -- klist

step "the kit's check_spnego, verbatim; constants: SSO_AUTH_HOST/SSO_REALM/SSO_PROBE_CLIENT/SSO_PROBE_REDIRECT"
printf '%s\n' "$CHECK_SH" > /tmp/check.sh; chmod 0755 /tmp/check.sh
grep -E '^SSO_' /tmp/check.sh
runuser -u alice -- bash /tmp/check.sh 2>&1 | sed 's/\x1b\[[0-9;]*m//g'

step "the same two requests by hand, headers only (scrubbed in the container)"
echo "# 1. plain (no ticket offered):"
runuser -u alice -- curl -sS --connect-timeout 5 --max-time 15 -D - -o /dev/null "$URL" | scrub | grep -i -E '^HTTP/|^www-authenticate'
echo "# 2. --negotiate -u : (alice's ticket for HTTP/services.kerber.test):"
runuser -u alice -- curl -sS --connect-timeout 5 --max-time 15 --negotiate -u : -D - -o /dev/null "$URL" | scrub | grep -i -E '^HTTP/|^www-authenticate|^location|^set-cookie'
echo "# 2 again, curl -v (TLS verification and the Authorization header):"
runuser -u alice -- curl -v -sS --connect-timeout 5 --max-time 15 --negotiate -u : -o /dev/null "$URL" 2>&1 | scrub \
    | grep -E '^\* (SSL certificate verify|Server certificate|  subject|  issuer|Connected to)|^> (GET|Host|Authorization)|^< (HTTP|www-authenticate|location)' | cut -c1-220

step "alice's cache after: the HTTP/ service ticket"
runuser -u alice -- klist
