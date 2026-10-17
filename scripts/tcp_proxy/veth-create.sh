#!/bin/bash

ip netns del ns-client 2>/dev/null
ip netns del ns-proxy  2>/dev/null
ip netns del ns-server 2>/dev/null

ip netns add ns-client
ip netns add ns-proxy
ip netns add ns-server

ip link add veth-c  type veth peer name veth-cp
ip link set veth-c  netns ns-client
ip link set veth-cp netns ns-proxy

ip link add veth-s  type veth peer name veth-ps
ip link set veth-s  netns ns-server
ip link set veth-ps netns ns-proxy
