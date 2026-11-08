#!/usr/bin/env bash
#
# Four-namespace lab on one Linux machine (no VMs needed):
#
#   PC1 ---- Device1 ======== Device2 ---- PC2
#   10.0.1.2  .1   10.0.2.1   10.0.2.2  .1   10.0.3.2
#       net A (10.0.1.0/24)  net B (10.0.2.0/24)  net C (10.0.3.0/24)
#
# Usage (root):  scripts/lab.sh up [PORT] | down | status | exec NS cmd...
#   PORT  optional: only protect flows to/from this PC2-side TCP port
#
set -euo pipefail

PC1=sic-pc1; D1=sic-d1; D2=sic-d2; PC2=sic-pc2
PC1_IP=10.0.1.2; D1_A=10.0.1.1; D1_B=10.0.2.1; D2_B=10.0.2.2; D2_C=10.0.3.1; PC2_IP=10.0.3.2
QUEUE=0

ns() { local n=$1; shift; ip netns exec "$n" "$@"; }

offloads_off() {   # behave like a plain NIC: real checksums, no GRO/GSO/TSO
    local n=$1 dev=$2
    ns "$n" ethtool -K "$dev" tso off gso off gro off lro off tx off rx off \
        >/dev/null 2>&1 || ns "$n" ethtool -K "$dev" tso off gso off gro off >/dev/null 2>&1 || true
}

link() {  # link NS_A DEV_A IP_A NS_B DEV_B IP_B
    ip link add "$2" netns "$1" type veth peer name "$5" netns "$4"
    ns "$1" ip addr add "$3/24" dev "$2"; ns "$4" ip addr add "$6/24" dev "$5"
    ns "$1" ip link set "$2" up;          ns "$4" ip link set "$5" up
    offloads_off "$1" "$2"; offloads_off "$4" "$5"
}

lab_down() {
    for n in $PC1 $D1 $D2 $PC2; do ip netns del "$n" 2>/dev/null || true; done
}

lab_up() {
    local port=${1:-0}
    lab_down
    for n in $PC1 $D1 $D2 $PC2; do ip netns add "$n"; ns "$n" ip link set lo up; done

    link $PC1 veth-pc1 $PC1_IP  $D1 veth-d1a $D1_A
    link $D1  veth-d1b $D1_B    $D2 veth-d2b $D2_B
    link $D2  veth-d2c $D2_C    $PC2 veth-pc2 $PC2_IP

    # Routing: PC1 -> Device1 -> Device2 -> PC2 (original IP headers are kept,
    # the protected packet is simply routed to the peer device).
    ns $PC1 ip route add default via $D1_A
    ns $PC2 ip route add default via $D2_C
    ns $D1  ip route add 10.0.3.0/24 via $D2_B
    ns $D2  ip route add 10.0.1.0/24 via $D1_B
    for d in $D1 $D2; do
        ns $d sysctl -qw net.ipv4.ip_forward=1
        ns $d sysctl -qw net.ipv4.conf.all.rp_filter=0
        ns $d sysctl -qw net.ipv4.conf.default.rp_filter=0
        install_rules $d "$port"
    done
}

# NFQUEUE rules for the devices.  Without a listener (device not yet running /
# handshake not finished) the kernel drops these packets: fail closed.
install_rules() {
    local d=$1 port=${2:-0} dp="" sp=""
    [ "$port" != 0 ] && { dp="--dport $port"; sp="--sport $port"; }
    # Optional: keep conntrack out of the way (it would otherwise see the
    # longer, protected segments on the inter-device link).
    ns "$d" iptables -t raw -A PREROUTING -p tcp -s $PC1_IP -d $PC2_IP $dp -j CT --notrack 2>/dev/null || true
    ns "$d" iptables -t raw -A PREROUTING -p tcp -s $PC2_IP -d $PC1_IP $sp -j CT --notrack 2>/dev/null || true
    ns "$d" iptables -A FORWARD -p tcp -s $PC1_IP -d $PC2_IP $dp -j NFQUEUE --queue-num $QUEUE
    ns "$d" iptables -A FORWARD -p tcp -s $PC2_IP -d $PC1_IP $sp -j NFQUEUE --queue-num $QUEUE
}

case "${1:-}" in
    up)     lab_up "${2:-0}"; echo "lab up: PC1=$PC1_IP Device1=$D1_A/$D1_B Device2=$D2_B/$D2_C PC2=$PC2_IP" ;;
    down)   lab_down; echo "lab removed" ;;
    status) ip netns list ;;
    exec)   shift; n=$1; shift; exec ip netns exec "$n" "$@" ;;   # exec: keep the PID of the command
    *)      echo "usage: $0 up [PORT] | down | status | exec NS cmd..."; exit 1 ;;
esac
