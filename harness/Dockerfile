# MIT Kerberos 1.22.2 reference KDC. Version is pinned; do not float.
FROM debian:bookworm-slim

ARG KRB5_VERSION=1.22.2
ARG KRB5_SHA256=3243ffbc8ea4d4ac22ddc7dd2a1dc54c57874c40648b60ff97009763554eaf13
ARG KRB5_URL=https://web.mit.edu/kerberos/dist/krb5/1.22/krb5-1.22.2.tar.gz

ENV DEBIAN_FRONTEND=noninteractive \
    KRB5_CONFIG=/etc/krb5.conf \
    KRB5_KDC_PROFILE=/etc/krb5kdc/kdc.conf \
    KRB5_VERSION=${KRB5_VERSION}

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        bison \
        byacc \
        ca-certificates \
        libssl-dev \
        wget \
        python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/build
RUN wget -O krb5.tar.gz "${KRB5_URL}" \
    && echo "${KRB5_SHA256}  krb5.tar.gz" | sha256sum -c - \
    && tar -xzf krb5.tar.gz \
    && cd krb5-${KRB5_VERSION}/src \
    && ./configure \
        --prefix=/usr \
        --sysconfdir=/etc \
        --localstatedir=/var \
        --with-crypto-impl=builtin \
        --without-system-verto \
        --disable-nls \
    && make -j"$(nproc)" \
    && make install \
    && plugin="$(find /usr -name pkinit.so 2>/dev/null | head -1)" \
    && if [ -z "$plugin" ]; then \
           echo "ERROR: MIT PKINIT preauth plugin (pkinit.so) was not built; OpenSSL/libssl-dev must be present at configure time" >&2; \
           exit 1; \
       fi \
    && echo "MIT PKINIT plugin present: $plugin" \
    && cd / \
    && rm -rf /tmp/build

RUN mkdir -p /var/lib/krb5kdc /etc/krb5kdc /var/kerberos/krb5kdc

COPY harness/krb5.conf /etc/krb5.conf
COPY harness/kdc.conf /etc/krb5kdc/kdc.conf
COPY harness/kadm5.acl /var/kerberos/krb5kdc/kadm5.acl
COPY harness/entrypoint.sh /usr/local/bin/harness-entrypoint.sh
RUN chmod +x /usr/local/bin/harness-entrypoint.sh

EXPOSE 88/tcp 88/udp

HEALTHCHECK --interval=5s --timeout=3s --retries=20 --start-period=15s \
    CMD python3 -c "import socket;s=socket.create_connection(('127.0.0.1',88),2)"

ENTRYPOINT ["/usr/local/bin/harness-entrypoint.sh"]
