#!/bin/bash

ip netns exec ns-client ip link set lo up
ip netns exec ns-client ip addr add 10.0.0.1/24 dev veth-c
ip netns exec ns-client ip link set veth-c up
ip netns exec ns-client ip route add default via 10.0.0.254

ip netns exec ns-proxy ip link set lo up
ip netns exec ns-proxy ip addr add 10.0.0.254/24 dev veth-cp
ip netns exec ns-proxy ip link set veth-cp up
ip netns exec ns-proxy ip addr add 10.0.1.254/24 dev veth-ps
ip netns exec ns-proxy ip link set veth-ps up

ip netns exec ns-server ip link set lo up
ip netns exec ns-server ip addr add 10.0.1.1/24 dev veth-s
ip netns exec ns-server ip link set veth-s up
ip netns exec ns-server ip route add default via 10.0.1.254

# No forwarding and reverse path filtering
ip netns exec ns-proxy sysctl -w net.ipv4.ip_forward=0
ip netns exec ns-proxy sysctl -w net.ipv4.conf.all.rp_filter=0
ip netns exec ns-proxy sysctl -w net.ipv4.conf.veth-cp.rp_filter=0
ip netns exec ns-proxy sysctl -w net.ipv4.conf.veth-ps.rp_filter=0
