# Heimdal 7.8 secondary oracle (Debian bookworm apt). No krb5-user:
# that package's kinit/klist collide with Heimdal binary names.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    HEIMDAL_REALM=KERBER.TEST \
    KRB5_CONFIG=/etc/krb5.conf

RUN echo "krb5-config krb5-config/default_realm string KERBER.TEST" | debconf-set-selections \
    && echo "heimdal-kdc heimdal-kdc/realm string KERBER.TEST" | debconf-set-selections \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        heimdal-kdc \
        heimdal-clients \
        heimdal-servers \
        ca-certificates \
        iproute2 \
        python3 \
        procps \
    && rm -rf /var/lib/apt/lists/* \
    && if dpkg -l krb5-user 2>/dev/null | grep -q '^ii'; then \
           echo "ERROR: krb5-user must not be installed" >&2; \
           exit 1; \
       fi

COPY harness/heimdal/krb5.conf /etc/krb5.conf
COPY harness/heimdal/kdc.conf /etc/heimdal-kdc/kdc.conf
COPY harness/heimdal/provision.sh /usr/local/bin/heimdal-provision.sh
COPY harness/heimdal/entrypoint.sh /usr/local/bin/heimdal-entrypoint.sh
RUN chmod +x /usr/local/bin/heimdal-provision.sh /usr/local/bin/heimdal-entrypoint.sh \
    && /usr/local/bin/heimdal-provision.sh

EXPOSE 88/tcp 88/udp

HEALTHCHECK --interval=5s --timeout=3s --retries=20 --start-period=15s \
    CMD python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),2)"

ENTRYPOINT ["/usr/local/bin/heimdal-entrypoint.sh"]
