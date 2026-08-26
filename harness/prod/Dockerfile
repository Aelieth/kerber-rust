# C1 multi-host prod-realm node image.
#
# Layers packet-capture + net tooling onto the MIT 1.22.2 reference image so a
# node can run a Rust KDC/kpropd (docker cp'd in at run time) AND capture its own
# real NIC traffic on eth0 (tcpdump) + dissect Kerberos (tshark) in-container.
# Kept separate from harness/Dockerfile so the 15 other gates + CI keep the lean
# base image; this builds in seconds (one apt layer on the cached base).
ARG BASE_IMAGE=kerber-rust-mit-kdc:1.22.2
FROM ${BASE_IMAGE}

# tshark is non-interactive; do not offer the setuid dumpcap prompt (we capture
# as root inside the container).
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        tcpdump \
        tshark \
        iproute2 \
        procps \
    && rm -rf /var/lib/apt/lists/*

# No new entrypoint: nodes are launched with --entrypoint sleep and driven by
# docker exec, exactly like the existing MIT-image gates.
