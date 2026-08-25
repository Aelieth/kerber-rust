# Samba 4 AD Domain Controller — live AD.KERBER.TEST oracle (Track A / A3).
# The domain is provisioned at BUILD time so the domain SID is stable and baked
# into the image (reproducible; recorded once). The entrypoint only starts samba
# in the foreground. Coordinates + accounts: docs/samba-lab.md.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Throwaway test creds for a synthetic, ephemeral DC (like the MIT harness's
# masterpassword/userpassword). Overridable at build; canonical values are in the
# gitignored working/samba-lab-accounts.md.
ARG SAMBA_REALM=AD.KERBER.TEST
ARG SAMBA_DOMAIN=ADKERBER
ARG SAMBA_ADMIN_PASSWORD=Samba-Admin-Kerber-2026!
ARG SAMBA_KBRUSER_PASSWORD=Kbruser-P@ss-2026!
ARG SAMBA_KBRSVC_PASSWORD=Kbrsvc-P@ss-2026!
ENV SAMBA_REALM=${SAMBA_REALM}

# AD DC runtime + provisioning tools. krb5-user gives kinit/kvno/klist for the gate.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        samba \
        samba-ad-provision \
        samba-dsdb-modules \
        samba-vfs-modules \
        smbclient \
        winbind \
        krb5-user \
        ldb-tools \
        python3-samba \
        iproute2 \
        dnsutils \
        procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY harness/samba/provision.sh /usr/local/bin/samba-provision.sh
COPY harness/samba/entrypoint.sh /usr/local/bin/samba-entrypoint.sh
RUN chmod +x /usr/local/bin/samba-provision.sh /usr/local/bin/samba-entrypoint.sh

# Provision the domain + accounts at build time (fails the build loudly on error).
RUN SAMBA_REALM="${SAMBA_REALM}" \
    SAMBA_DOMAIN="${SAMBA_DOMAIN}" \
    SAMBA_ADMIN_PASSWORD="${SAMBA_ADMIN_PASSWORD}" \
    SAMBA_KBRUSER_PASSWORD="${SAMBA_KBRUSER_PASSWORD}" \
    SAMBA_KBRSVC_PASSWORD="${SAMBA_KBRSVC_PASSWORD}" \
    /usr/local/bin/samba-provision.sh

# L2 PAC signatures: samba.tests.krb5.kcrypto (not in python3-samba).
RUN apt-get update \
    && apt-get install -y --no-install-recommends samba-testsuite python3-cryptography \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 53 88/tcp 88/udp 389 464/tcp 464/udp 636 3268

# Samba KDC listening on UDP 88 is the readiness signal the gate also polls.
HEALTHCHECK --interval=5s --timeout=3s --retries=40 --start-period=30s \
    CMD ss -lun 2>/dev/null | grep -q ':88 ' || exit 1

ENTRYPOINT ["/usr/local/bin/samba-entrypoint.sh"]
