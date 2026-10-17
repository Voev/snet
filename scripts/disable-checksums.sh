#!/bin/bash
sudo ip netns exec ns-client ethtool -K veth-c tx off rx off sg off tso off gso off gro off txvlan off rxvlan off

sudo ip netns exec ns-server ethtool -K veth-s tx off rx off sg off tso off gso off gro off txvlan off rxvlan off

sudo ip netns exec ns-proxy ethtool -K veth-p0 tx off rx off sg off tso off gso off gro off txvlan off rxvlan off
sudo ip netns exec ns-proxy ethtool -K veth-p1 tx off rx off sg off tso off gso off gro off txvlan off rxvlan off
