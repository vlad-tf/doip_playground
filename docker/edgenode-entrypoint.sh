#!/bin/sh
# EdgeNode startup shim: make the config's interface names match whatever
# Docker actually assigned, so the IPv6 connect to the Echo ECU uses the real
# backend interface regardless of eth0/eth1 ordering.
set -e

SRC=/app/config.yaml
DST=/tmp/config.yaml

# Backend interface = the one carrying a GLOBAL-scope IPv6 address.
# /proc/net/if_inet6 columns: addr ifindex prefixlen scope flags devname
# scope "00" == global; "20" == link-local (fe80); "10" == host (lo).
ECU_IF=$(awk '$4=="00" && $6!="lo" {print $6; exit}' /proc/net/if_inet6)
: "${ECU_IF:=eth1}"

# Tester interface = the remaining non-loopback interface (IPv4 frontend).
TESTER_IF=eth0
for d in /sys/class/net/*; do
    n=$(basename "$d")
    [ "$n" = lo ] && continue
    [ "$n" = "$ECU_IF" ] && continue
    TESTER_IF=$n
    break
done

echo "edgenode-entrypoint: detected tester_interface=$TESTER_IF ecu_interface=$ECU_IF"

# config.yaml is mounted read-only, so patch a writable copy in /tmp.
cp "$SRC" "$DST"
sed -i \
    -e "s|^\( *tester_interface:\).*|\1 \"$TESTER_IF\"|" \
    -e "s|\( *ecu_interface:\).*|\1 \"$ECU_IF\"|" \
    "$DST"

exec python3 main.py --config "$DST" --log-level "${LOG_LEVEL:-INFO}"
