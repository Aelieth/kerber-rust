#!/bin/bash
# pcapdecode.sh <file.pcap> <title>: the tshark decode kept beside each capture
# (<file.pcap>.txt). R3-MIT's decoder (pcapdecode.sh) unchanged, plus
# section 1b (R3 kerber-rust): each Kerberos message's transport, sizes and IP
# fragmentation, and client2 in the hosts line. Sections print only what the
# capture holds:
#   1. Kerberos messages to/from the KDC (msg-type, names, padata, etypes, error)
#   2. RPCSEC_GSS context establishment on NFS (INIT calls with the AP-REQ, the
#      server's replies), then DATA calls per context handle and service level,
#      DESTROYs, and any non-SUCCESS reply
#   3. NFSv4 names visible on the wire (krb5i is integrity only; krb5p is sealed)
#   4. TLS ClientHellos (SNI) to services:443 (R5)
#   5. SSH on port 22 (R3): banners, KEXINIT algorithm lists (gss-* kex offered?),
#      the clear-text message codes before NEWKEYS; userauth itself is encrypted
# Captures come from client1's lab NIC (enp1s0); they carry no secret in clear
# (krb5p is sealed, TLS is encrypted; Kerberos ciphertext only).
set -euo pipefail
export TZ=UTC
f=$1
title=$2
: "${FIELD_LAB_NET:?FIELD_LAB_NET is not set in field.env}"
NET=$FIELD_LAB_NET
out="$f.txt"
first=$(tshark -r "$f" -c 1 -T fields -e frame.time_epoch 2>/dev/null || true)
T() { tshark -r "$f" "$@" 2>/dev/null || true; }
# tfix: 2026-10-01T23:40:01.123456789Z -> 23:40:01.123456
tfix() { sed -E 's/\|[0-9]{4}-[0-9]{2}-[0-9]{2}T([0-9:]{8}\.[0-9]{6})[0-9]*Z/|\1/'; }
{
    printf '# tshark decode of %s: %s. %s\n' "$(basename "$f")" "$title" "$(tshark --version | head -1)"
    [ -n "$first" ] && printf '# t=0 is %s\n' "$(date -u -d "@${first%%.*}" +%FT%TZ)"
    printf '# hosts: client1 %s.21, client2 %s.22, kdc %s.10, services %s.11\n' "$NET" "$NET" "$NET" "$NET"

    printf '\n## 1. Kerberos (frame | time UTC | src | dst | msg_type 10=AS-REQ 11=AS-REP 12=TGS-REQ 13=TGS-REP 14=AP-REQ 15=AP-REP 30=ERROR | crealm | cname | sname | padata | kdc-options fwd,renewable,renew,canon | till | etypes | error | e-text | kvnos (ticket enc-part, then reply enc-part) | forwarded option)\n'
    T -Y 'kerberos.msg_type && (ip.addr == '"$NET"'.10)' -T fields -E separator='|' -E occurrence=a -E aggregator=, \
        -e frame.number -e frame.time_utc -e ip.src -e ip.dst -e kerberos.msg_type -e kerberos.crealm -e kerberos.CNameString \
        -e kerberos.SNameString -e kerberos.padata_type -e kerberos.KDCOptions.forwardable -e kerberos.KDCOptions.renewable \
        -e kerberos.KDCOptions.renew -e kerberos.KDCOptions.canonicalize -e kerberos.till -e kerberos.etype \
        -e kerberos.error_code -e kerberos.e_text -e kerberos.kvno -e kerberos.KDCOptions.forwarded | tfix

    printf '\n## 1b. Kerberos transport and sizes (frame | time UTC | src | dst | ip.proto 6=TCP 17=UDP | ip.len of the last frame | TCP record-mark length (the whole Kerberos message over TCP) | UDP length | msg_type | sname)\n'
    T -Y 'kerberos.msg_type && (ip.addr == '"$NET"'.10)' -T fields -E separator='|' -E occurrence=f \
        -e frame.number -e frame.time_utc -e ip.src -e ip.dst -e ip.proto -e ip.len -e kerberos.rm.length -e udp.length \
        -e kerberos.msg_type -e kerberos.SNameString | tfix
    printf '# IP fragments in this capture (more-fragments set or offset > 0): %s\n' "$(T -Y 'ip.flags.mf == 1 || ip.frag_offset > 0' | wc -l)"

    n_gss=$(T -Y 'rpc.auth.flavor == 6' | wc -l)
    if [ "$n_gss" -gt 0 ]; then
        printf '\n## 2. RPCSEC_GSS on NFS (%s frames with flavor 6)\n' "$n_gss"
        printf '# INIT / CONTINUE_INIT calls (gss proc 1/2): frame | time UTC | src | dst | xid | gss proc | gss service | AP-REQ sname | ticket etype, authenticator etype\n'
        T -Y 'rpc.msgtyp == 0 && rpc.authgss.procedure in {1, 2}' -T fields -E separator='|' -E occurrence=a -E aggregator=, \
            -e frame.number -e frame.time_utc -e ip.src -e ip.dst -e rpc.xid -e rpc.authgss.procedure -e rpc.authgss.service \
            -e kerberos.SNameString -e kerberos.etype | tfix
        printf '# replies to them: frame | reply to frame | reply_stat (0=MSG_ACCEPTED) | accept_stat (0=SUCCESS) | gss_major (0=GSS_S_COMPLETE) | gss_minor | seq window | context handle (len)\n'
        T -Y 'rpc.msgtyp == 1 && rpc.authgss.major' -T fields -E separator='|' -E occurrence=a -E aggregator=, \
            -e frame.number -e rpc.repframe -e rpc.replystat -e rpc.state_accept -e rpc.authgss.major -e rpc.authgss.minor \
            -e rpc.authgss.window -e rpc.authgss.context -e rpc.authgss.context.length
        printf '# DATA calls per context handle and service level (1=none 2=integrity/krb5i 3=privacy/krb5p): count | handle | service\n'
        T -Y 'rpc.msgtyp == 0 && rpc.auth.flavor == 6 && rpc.authgss.procedure == 0' -T fields -E separator=' ' \
            -e rpc.authgss.context -e rpc.authgss.service | sort | uniq -c | sed 's/^/  /'
        printf '# first and last DATA call of each context handle: handle | first frame time | last frame time\n'
        T -Y 'rpc.msgtyp == 0 && rpc.auth.flavor == 6 && rpc.authgss.procedure == 0' -T fields -E separator='|' \
            -e rpc.authgss.context -e frame.time_epoch | awk -F'|' '{ if (!($1 in a)) a[$1]=$2; b[$1]=$2 } END { for (h in a) { printf "  %s | %s | %s\n", h, strftime("%H:%M:%S", a[h], 1), strftime("%H:%M:%S", b[h], 1) } }' | sort -t'|' -k2
        printf '# DESTROY calls (gss proc 3): frame | time UTC | handle\n'
        T -Y 'rpc.msgtyp == 0 && rpc.authgss.procedure == 3' -T fields -E separator='|' -e frame.number -e frame.time_utc -e rpc.authgss.context | tfix
        printf '# replies that are not MSG_ACCEPTED/SUCCESS (RPC level): frame | reply_stat | accept_stat | reject (auth_stat)\n'
        T -Y 'rpc.msgtyp == 1 && (rpc.replystat != 0 || rpc.state_accept != 0)' -T fields -E separator='|' -e frame.number -e rpc.replystat -e rpc.state_accept -e rpc.state_auth
        printf '# NFSv4 compound replies with a non-OK status: frame | time UTC | opcodes | status\n'
        T -Y 'nfs.nfsstat4 != 0 && rpc.msgtyp == 1' -T fields -E separator='|' -E occurrence=a -E aggregator=, -e frame.number -e frame.time_utc -e nfs.opcode -e nfs.nfsstat4 | tfix | head -40

        printf '\n## 3. NFSv4 names visible on the wire (integrity-level frames decode; privacy-level frames are sealed)\n'
        printf '# frame | gss service | names (LOOKUP / OPEN / CREATE / REMOVE components)\n'
        T -Y 'rpc.msgtyp == 0 && rpc.authgss.service == 2 && (nfs.pathname.component || nfs.name)' -T fields -E separator='|' -E occurrence=a -E aggregator=, \
            -e frame.number -e rpc.authgss.service -e nfs.pathname.component -e nfs.name | head -60
        printf '# privacy-level calls in which any NFS name decodes: %s\n' "$(T -Y 'rpc.msgtyp == 0 && rpc.authgss.service == 3 && (nfs.pathname.component || nfs.name)' | wc -l)"
    fi

    n_tls=$(T -Y 'tls.handshake.type == 1' | wc -l)
    if [ "$n_tls" -gt 0 ]; then
        printf '\n## 4. TLS ClientHellos (frame | time UTC | src | dst:port | SNI)\n'
        T -Y 'tls.handshake.type == 1' -T fields -E separator='|' -e frame.number -e frame.time_utc -e ip.src -e ip.dst -e tcp.dstport -e tls.handshake.extensions_server_name | tfix
        printf '# TLS versions negotiated (ServerHello supported_version): %s\n' "$(T -Y 'tls.handshake.type == 2' -T fields -e tls.handshake.extensions.supported_version | sort | uniq -c | tr '\n' ' ')"
    fi

    n_ssh=$(T -Y 'ssh' | wc -l)
    if [ "$n_ssh" -gt 0 ]; then
        printf '\n## 5. SSH (port 22): per connection, the clear-text part (frame | time UTC | src:port | dst:port | banner | message codes 20 KEXINIT 21 NEWKEYS 30/31 KEX_ECDH_INIT/REPLY)\n'
        T -Y 'ssh.protocol || ssh.message_code' -T fields -E separator='|' -E occurrence=a -E aggregator=, \
            -e frame.number -e frame.time_utc -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e ssh.protocol -e ssh.message_code | tfix
        printf '# KEXINIT kex_algorithms offered (first KEXINIT of each side; a gss-* entry would mean GSSAPI key exchange):\n'
        T -Y 'ssh.kex_algorithms' -T fields -E separator='|' -e frame.number -e ip.src -e ssh.kex_algorithms | awk -F'|' '!seen[$2]++' | cut -c1-400
        printf '# TCP connections to port 22 (one per ssh run): count %s\n' "$(T -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == 22' | wc -l)"
    fi

    printf '\n## TCP/UDP conversations in this capture\n'
    T -q -z conv,tcp -z conv,udp | sed -n '/====/,$p'
} > "$out"
printf '%s: %s frames, decode in %s (%s lines)\n' "$(basename "$f")" "$(tshark -r "$f" 2>/dev/null | wc -l)" "$(basename "$out")" "$(wc -l < "$out")"
