#!/bin/bash
#
#
#   ns-client                        ns-proxy                       ns-server
#   ┌────────┐                      ┌──────────┐                    ┌────────┐
#   │ veth-c │◄──── veth pair ─────►│ veth-p0  │                    │        │
#   │10.0.0.1│                      │ (no IP)  │                    │        │
#   └────────┘                      │          │                    │        │
#                                   │ veth-p1  │◄─── veth pair ────►│ veth-s │
#                                   │ (no IP)  │                    │10.0.0.2│
#                                   └──────────┘                    └────────┘

set -euo pipefail

CLIENT_NS=ns-client
PROXY_NS=ns-proxy
SERVER_NS=ns-server

CLIENT_IF=veth-c
PROXY_CLIENT_IF=veth-p0
PROXY_SERVER_IF=veth-p1
SERVER_IF=veth-s

CLIENT_IP=10.0.0.1
SERVER_IP=10.0.0.2
PREFIX=24

die() { echo "error: $*" >&2; exit 1; }

ns_exists() {
    ip netns list | awk '{print $1}' | grep -qx "$1"
}

cleanup() {
    echo "=== cleanup ==="
    for ns in "$CLIENT_NS" "$PROXY_NS" "$SERVER_NS"; do
        if ns_exists "$ns"; then
            sudo ip netns del "$ns" || true
        fi
    done
}

setup_namespaces() {
    echo "=== create namespaces ==="
    for ns in "$CLIENT_NS" "$PROXY_NS" "$SERVER_NS"; do
        if ! ns_exists "$ns"; then
            sudo ip netns add "$ns"
        else
            echo "  $ns already exists, skipping"
        fi
    done
}

setup_veth() {
    echo "=== create veth pairs ==="

    # client <-> proxy
    if ! sudo ip netns exec "$CLIENT_NS" ip link show "$CLIENT_IF" &>/dev/null; then
        sudo ip link add "$CLIENT_IF" type veth peer name "$PROXY_CLIENT_IF"
        sudo ip link set "$CLIENT_IF"       netns "$CLIENT_NS"
        sudo ip link set "$PROXY_CLIENT_IF" netns "$PROXY_NS"
    else
        echo "  $CLIENT_IF already exists"
    fi

    # proxy <-> server
    if ! sudo ip netns exec "$SERVER_NS" ip link show "$SERVER_IF" &>/dev/null; then
        sudo ip link add "$PROXY_SERVER_IF" type veth peer name "$SERVER_IF"
        sudo ip link set "$PROXY_SERVER_IF" netns "$PROXY_NS"
        sudo ip link set "$SERVER_IF"       netns "$SERVER_NS"
    else
        echo "  $SERVER_IF already exists"
    fi
}

configure_client() {
    echo "=== configure $CLIENT_NS ==="

    sudo ip netns exec "$CLIENT_NS" ip addr flush dev "$CLIENT_IF"
    sudo ip netns exec "$CLIENT_NS" ip neigh flush all
    sudo ip netns exec "$CLIENT_NS" ip route flush default 2>/dev/null || true

    sudo ip netns exec "$CLIENT_NS" ip link set lo up
    sudo ip netns exec "$CLIENT_NS" ip link set "$CLIENT_IF" up
    sudo ip netns exec "$CLIENT_NS" ip addr add "${CLIENT_IP}/${PREFIX}" dev "$CLIENT_IF"

    sudo ip netns exec "$CLIENT_NS" \
        sysctl -qw net.ipv6.conf."$CLIENT_IF".disable_ipv6=1
}

configure_server() {
    echo "=== configure $SERVER_NS ==="

    sudo ip netns exec "$SERVER_NS" ip addr flush dev "$SERVER_IF"
    sudo ip netns exec "$SERVER_NS" ip neigh flush all
    sudo ip netns exec "$SERVER_NS" ip route flush default 2>/dev/null || true

    sudo ip netns exec "$SERVER_NS" ip link set lo up
    sudo ip netns exec "$SERVER_NS" ip link set "$SERVER_IF" up
    sudo ip netns exec "$SERVER_NS" ip addr add "${SERVER_IP}/${PREFIX}" dev "$SERVER_IF"

    sudo ip netns exec "$SERVER_NS" \
        sysctl -qw net.ipv6.conf."$SERVER_IF".disable_ipv6=1
}

configure_proxy() {
    echo "=== configure $PROXY_NS ==="

    sudo ip netns exec "$PROXY_NS" ip addr flush dev "$PROXY_CLIENT_IF"
    sudo ip netns exec "$PROXY_NS" ip addr flush dev "$PROXY_SERVER_IF"
    sudo ip netns exec "$PROXY_NS" ip neigh flush all

    sudo ip netns exec "$PROXY_NS" ip link set lo up
    sudo ip netns exec "$PROXY_NS" ip link set "$PROXY_CLIENT_IF" up
    sudo ip netns exec "$PROXY_NS" ip link set "$PROXY_SERVER_IF" up

    sudo ip netns exec "$PROXY_NS" \
        sysctl -qw net.ipv4.ip_forward=0

    sudo ip netns exec "$PROXY_NS" \
        sysctl -qw net.ipv4.conf.all.rp_filter=0
    sudo ip netns exec "$PROXY_NS" \
        sysctl -qw net.ipv4.conf.default.rp_filter=0
    sudo ip netns exec "$PROXY_NS" \
        sysctl -qw net.ipv4.conf."$PROXY_CLIENT_IF".rp_filter=0
    sudo ip netns exec "$PROXY_NS" \
        sysctl -qw net.ipv4.conf."$PROXY_SERVER_IF".rp_filter=0

    sudo ip netns exec "$PROXY_NS" \
        sysctl -qw net.ipv4.conf.all.arp_ignore=8
    sudo ip netns exec "$PROXY_NS" \
        sysctl -qw net.ipv4.conf."$PROXY_CLIENT_IF".arp_ignore=8
    sudo ip netns exec "$PROXY_NS" \
        sysctl -qw net.ipv4.conf."$PROXY_SERVER_IF".arp_ignore=8

    sudo ip netns exec "$PROXY_NS" \
        sysctl -qw net.ipv4.conf."$PROXY_CLIENT_IF".proxy_arp=0
    sudo ip netns exec "$PROXY_NS" \
        sysctl -qw net.ipv4.conf."$PROXY_SERVER_IF".proxy_arp=0

    sudo ip netns exec "$PROXY_NS" \
        sysctl -qw net.ipv6.conf."$PROXY_CLIENT_IF".disable_ipv6=1
    sudo ip netns exec "$PROXY_NS" \
        sysctl -qw net.ipv6.conf."$PROXY_SERVER_IF".disable_ipv6=1
}

show_state() {
    echo "=== state ==="
    for ns in "$CLIENT_NS" "$PROXY_NS" "$SERVER_NS"; do
        echo "--- $ns ---"
        sudo ip netns exec "$ns" ip -br addr show
        echo
    done

    echo "--- $PROXY_NS sysctl ---"
    for key in \
        net.ipv4.ip_forward \
        net.ipv4.conf.all.rp_filter \
        net.ipv4.conf.all.arp_ignore \
        net.ipv4.conf."$PROXY_CLIENT_IF".rp_filter \
        net.ipv4.conf."$PROXY_SERVER_IF".rp_filter \
        net.ipv4.conf."$PROXY_CLIENT_IF".arp_ignore \
        net.ipv4.conf."$PROXY_SERVER_IF".arp_ignore
    do
        printf "  %s = " "$key"
        sudo ip netns exec "$PROXY_NS" sysctl -n "$key"
    done
    echo
}

case "${1:-setup}" in
    setup)
        setup_namespaces
        setup_veth
        configure_client
        configure_server
        configure_proxy
        show_state
        echo "=== done ==="
        echo
        echo "next:"
        echo "  sudo ip netns exec $PROXY_NS ./your_app --config ... --driver ..."
        echo
        echo "test:"
        echo "  sudo ip netns exec $CLIENT_NS ping $SERVER_IP"
        ;;
    cleanup)
        cleanup
        ;;
    state)
        show_state
        ;;
    *)
        echo "usage: $0 {setup|cleanup|state}"
        exit 1
        ;;
esac