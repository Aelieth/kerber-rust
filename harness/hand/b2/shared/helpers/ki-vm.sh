#!/bin/bash
# ki-vm.sh SUB: KI's client-side steps on client2, as root (`sudo bash ki-vm.sh setup|down|up|expect|teardown|facts`). (lab-agent; module mod/ki.sh; VM-LEG.md "Setup on client2")
#   setup      kidum0: a dummy interface, UP, 192.0.2.77/24, 198.51.100.77/24 and 2001:db8:7::77/64 (nodad); kidum1: a dummy interface that stays DOWN, 203.0.113.77/24. A veth pair when the dummy module is missing.
#              Anything left from an earlier run is removed first. Prints SETUP_OK and `ip -o addr`.
#   down / up  kidum0 DOWN (its addresses stay configured but the interface is not UP, so none is sent; the kernel drops its IPv6 addresses) / UP again with the IPv6 address put back.
#   expect     EXPECT_ADDRS <a,b,c>: what MIT's krb5_os_localaddr sends: the addresses of the interfaces that are UP, IPv4 (less 127.0.0.1) then IPv6 (less ::1 and fe80::/10), each family in interface
#              order, repeats dropped (getifaddrs order, kinit.c:674-683, localaddr.c:415-481 as the VM-LEG cites them); and the interfaces' states.
#   teardown   both interfaces deleted. TEARDOWN_OK.
#   facts      what the cells rely on: ip, tcpdump, python3, the dummy module, the global IPv6 addresses of this VM.
# No secret passes through this file. The interfaces are gone at the snapshot reset in any case.
set -u
V4A=192.0.2.77/24 V4B=198.51.100.77/24 V6=2001:db8:7::77/64 V4D=203.0.113.77/24
mkif() {   # mkif NAME: a dummy interface, else a veth pair
    ip link add "$1" type dummy 2> /dev/null || ip link add "$1" type veth peer name "${1}p" || return 1
}
case ${1:-} in
setup)
    ip link del kidum0 2> /dev/null; ip link del kidum1 2> /dev/null
    mkif kidum0 || { echo "SETUP_FAILED kidum0"; exit 1; }
    ip link set kidum0 up || exit 1
    ip addr add "$V4A" dev kidum0 || exit 1
    ip addr add "$V4B" dev kidum0 || exit 1
    ip -6 addr add "$V6" dev kidum0 nodad || echo "SETUP_V6_FAILED (IPv6 disabled on this VM?): the cells run without the IPv6 address"
    mkif kidum1 || { echo "SETUP_FAILED kidum1"; exit 1; }
    ip addr add "$V4D" dev kidum1 || exit 1
    echo "SETUP_OK"
    ip -o addr
    ;;
down)
    ip link set kidum0 down || exit 1
    echo "DOWN_OK"
    ;;
up)
    ip link set kidum0 up || exit 1
    ip -6 addr show dev kidum0 2> /dev/null | grep -q '2001:db8:7::77' || ip -6 addr add "$V6" dev kidum0 nodad || echo "UP_V6_FAILED"
    echo "UP_OK"
    ;;
expect)
    {
        ip -o -4 addr show up | awk '{ split($4, a, "/"); if (a[1] != "127.0.0.1") print a[1] }'
        ip -o -6 addr show up | awk '{ split($4, a, "/"); ip = a[1]; if (ip == "::1" || tolower(ip) ~ /^fe[89ab][0-9a-f]:/) next; print ip }'
    } | awk '!seen[$0]++' | paste -sd, - | sed 's/^/EXPECT_ADDRS /'
    echo "IFACES $(ip -o link | awk '{ gsub(":", "", $2); s = "DOWN"; if ($0 ~ /<[^>]*[<,]UP[,>]/) s = "UP"; printf "%s=%s ", $2, s }')"
    ;;
teardown)
    ip link del kidum0 2> /dev/null; ip link del kidum1 2> /dev/null
    echo "TEARDOWN_OK"
    ip -o link | grep -c kidum | sed 's/^/KIDUM_LEFT /'
    ;;
facts)
    echo "ip: $(ip -V 2>&1 | head -n 1)"
    echo "tcpdump: $(command -v tcpdump 2>&1)"
    echo "python3: $(command -v python3 2>&1)"
    echo "dummy: $( { modinfo dummy > /dev/null 2>&1 && echo module-known; } || echo no-modinfo; grep -c '^dummy' /proc/modules 2> /dev/null | sed 's/^/loaded=/')"
    echo "global_ipv6: $(ip -o -6 addr show scope global | awk '{ print $2 ":" $4 }' | paste -sd' ' -)"
    ;;
*)
    echo "ki-vm.sh: unknown subcommand '${1:-}'" >&2; exit 2 ;;
esac
