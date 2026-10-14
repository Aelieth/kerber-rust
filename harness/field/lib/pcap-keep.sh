#!/usr/bin/env bash
# pcap-keep.sh <raw.pcap> <out.pcap>: copy a capture into a record without any AS exchange.
# An AS-REQ's PA-ENC-TIMESTAMP and an AS-REP's enc-part are offline-guessable password material, so every TCP
# stream that carries an AS-REQ or AS-REP is dropped, and every UDP one with its IP fragments (IPv4 and IPv6).
# Other fragmented datagrams (such as a large UDP TGS-REQ) are kept. The copy is checked to hold no AS message.
# Writes <out.pcap> and <out.pcap>.txt (one line per Kerberos / SPNEGO message, tshark fields). The raw capture
# is the caller's to delete.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: pcap-keep.sh <raw.pcap> <out.pcap>" >&2; exit 1; }
in=$1 out=$2
AS='kerberos.msg_type == 10 || kerberos.msg_type == 11'
packets() { capinfos -c -M "$1" | awk '/Number of packets/ { print $NF }'; }
streams=$(tshark -r "$in" -Y "tcp && ($AS)" -T fields -e tcp.stream 2>/dev/null | sort -un | paste -sd, -)
frames=$(tshark -r "$in" -Y "udp && ($AS)" -T fields -E aggregator=' ' -e frame.number -e ip.fragment \
    -e ipv6.fragment 2>/dev/null | tr -s ' \t\n' '\n' | { grep -v '^$' || true; } | sort -un | paste -sd, -)
filter='frame'
[ -n "$streams" ] && filter="$filter && not (tcp.stream in {${streams}})"
[ -n "$frames" ] && filter="$filter && not (frame.number in {${frames}})"
tshark -r "$in" -Y "$filter" -w "$out" 2>/dev/null
left=$(tshark -r "$out" -Y "$AS" 2>/dev/null | wc -l)
if [ "$left" -ne 0 ]; then
    rm -f "$out"
    echo "pcap-keep.sh: $left AS message(s) left in the copy; removed it" >&2
    exit 1
fi
kept=$(packets "$out")
{
    echo "# $(basename "$out"): $kept packets kept, $(( $(packets "$in") - kept )) dropped (AS exchanges: tcp streams {${streams}}, UDP AS frames + fragments {${frames}}); 0 AS messages left"
    echo "# frame|time|src|dst|msg_type|realm|sname|ticket kvno(s)|etypes|error_code|e_text|padata types|krb5 cname|info"
    tshark -r "$out" -Y 'kerberos || spnego || gss-api || http.authorization || http.www_authenticate || ssh.message_code' \
        -T fields -E separator='|' -e frame.number -e frame.time_utc -e ip.src -e ip.dst -e kerberos.msg_type \
        -e kerberos.realm -e kerberos.SNameString -e kerberos.kvno -e kerberos.etype -e kerberos.error_code \
        -e kerberos.e_text -e kerberos.padata_type -e kerberos.CNameString -e _ws.col.Info 2>/dev/null
} > "$out.txt"
