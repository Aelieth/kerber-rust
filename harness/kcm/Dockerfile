# Digest-pinned Fedora sssd-kcm oracle. Default is F43 (R10).
ARG FEDORA_DIGEST=sha256:96b2a05f8ce3111e10c236abe8055b01500880d95ee7c2f92fa30847fdbb667b
FROM registry.fedoraproject.org/fedora@${FEDORA_DIGEST}

RUN dnf -y install sssd-kcm krb5-workstation python3 \
    && dnf clean all \
    && mkdir -p /var/lib/sss/secrets /var/log/sssd /var/lib/sss/db /etc/sssd

COPY harness/kcm/sssd.conf /etc/sssd/sssd.conf
COPY harness/kcm/entrypoint.sh /usr/local/bin/kcm-entrypoint.sh
COPY harness/kcm/probe-opcodes.py /usr/local/bin/kcm-probe-opcodes.py
RUN chmod 600 /etc/sssd/sssd.conf \
    && chmod +x /usr/local/bin/kcm-entrypoint.sh /usr/local/bin/kcm-probe-opcodes.py

ENV KCM_SOCKET=/run/.heim_org.h5l.kcm-socket
ENTRYPOINT ["/usr/local/bin/kcm-entrypoint.sh"]
